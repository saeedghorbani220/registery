<?php
/**
 * LegacyApply.php — reviewed decisions and atomic merge for staged legacy data.
 *
 * Safety model:
 *   * analysis never writes live rows (LegacyImport.php);
 *   * every detected conflict/invalid row needs an explicit admin decision;
 *   * one apply holds tenant_state FOR UPDATE and commits all accepted rows in
 *     one database transaction;
 *   * the online dataset's source_installation_id is never replaced once set;
 *   * ledger source sequence numbers are never trusted on a live dataset — a
 *     new sequence is allocated while the customer row is locked;
 *   * merge is conservative: existing non-empty online values win, while old
 *     data may fill empty fields. There is no silent legacy-over-online write.
 */

declare(strict_types=1);

final class LegacyApply
{
    private const ORDER = [
        'periods', 'customers', 'owners', 'identities', 'crm_devices',
        'customer_transactions', 'settings',
    ];

    /** @param array<string, mixed> $cfg */
    public function __construct(
        private readonly Database $db,
        private readonly Sync $sync,
        private readonly Log $log,
        private readonly array $cfg
    ) {
    }

    /**
     * Record or replace one administrator decision for a staged row.
     *
     * @param array<string, mixed> $body
     * @return array<string, mixed>
     */
    public function decide(Principal $user, array $body, string $requestId,
                           string $ip): array
    {
        $this->requireAdmin($user);
        $jobId = $body['job_id'] ?? null;
        $recordId = $body['record_id'] ?? null;
        $resolution = $body['resolution'] ?? null;
        $targetId = $body['target_id'] ?? null;
        if (!is_string($jobId) || !Ids::isUuid($jobId)
            || !is_string($recordId) || !Ids::isUuid($recordId)
            || !is_string($resolution)
            || !in_array($resolution, ['create','merge','skip','reject'], true)) {
            throw new ApiException(400, Codes::BAD_PAYLOAD,
                'job_id, record_id and a valid resolution are required');
        }

        $job = $this->job($user->tenantId, $jobId);
        if (in_array((string) $job['status'], ['applying','applied','cancelled'], true)) {
            throw new ApiException(409, Codes::VERSION_CONFLICT,
                'this migration job no longer accepts review changes');
        }
        $record = $this->db->queryOne(
            'SELECT id,entity,action,target_id FROM legacy_import_records '
            . 'WHERE id = ? AND job_id = ? AND tenant_id = ?',
            [$recordId, $jobId, $user->tenantId]
        );
        if ($record === null) {
            throw new ApiException(404, Codes::NOT_FOUND,
                'staged migration record was not found');
        }
        $entity = (string) $record['entity'];
        $detected = (string) $record['action'];
        if ($detected === 'invalid' && $resolution !== 'reject') {
            throw new ApiException(409, Codes::VALIDATION_FAILED,
                'an invalid staged row can only be rejected');
        }
        if ($entity === 'customer_transactions' && $resolution === 'merge') {
            throw new ApiException(409, Codes::VALIDATION_FAILED,
                'financial rows cannot be merged in place');
        }
        if ($entity === 'settings' && $resolution === 'create'
            && $this->db->queryValue(
                'SELECT id FROM settings WHERE tenant_id = ? AND deleted_at IS NULL LIMIT 1',
                [$user->tenantId]
            ) !== null) {
            throw new ApiException(409, Codes::VERSION_CONFLICT,
                'settings already exist; choose merge, skip or reject');
        }

        if (in_array($resolution, ['merge','skip'], true)) {
            if ($targetId === null || $targetId === '') {
                $targetId = $record['target_id'];
            }
            if (!is_string($targetId) || !Ids::isUuid($targetId)) {
                throw new ApiException(400, Codes::BAD_PAYLOAD,
                    'merge and skip decisions require a target UUID');
            }
            $this->requireTarget($user->tenantId, $entity, $targetId);
        } else {
            $targetId = null;
        }

        $now = gmdate('Y-m-d H:i:s');
        $this->db->transaction(function (Database $tx) use (
            $user, $jobId, $recordId, $resolution, $targetId, $now
        ): void {
            $tx->execute(
                'INSERT INTO legacy_import_decisions '
                . '(id,tenant_id,job_id,record_id,resolution,target_id,'
                . 'decided_by,decided_at) VALUES (?,?,?,?,?,?,?,?) '
                . 'ON DUPLICATE KEY UPDATE resolution=VALUES(resolution), '
                . 'target_id=VALUES(target_id), decided_by=VALUES(decided_by), '
                . 'decided_at=VALUES(decided_at)',
                [
                    Ids::v4(), $user->tenantId, $jobId, $recordId,
                    $resolution, $targetId, $user->userId, $now,
                ]
            );
            $unresolved = (int) ($tx->queryValue(
                'SELECT COUNT(*) FROM legacy_import_records r '
                . 'LEFT JOIN legacy_import_decisions d '
                . 'ON d.job_id=r.job_id AND d.record_id=r.id '
                . 'WHERE r.job_id=? AND r.tenant_id=? '
                . "AND r.action IN ('pending','conflict','invalid') "
                . 'AND d.id IS NULL',
                [$jobId, $user->tenantId]
            ) ?? 0);
            $tx->execute(
                'UPDATE legacy_import_jobs SET status=?,updated_at=? '
                . 'WHERE id=? AND tenant_id=?',
                [$unresolved === 0 ? 'ready' : 'review', $now,
                 $jobId, $user->tenantId]
            );
        });

        $this->log->audit($this->db, [
            'tenant_id' => $user->tenantId,
            'action' => 'legacy_import.decision',
            'actor_type' => 'user',
            'actor_user_id' => $user->userId,
            'entity' => 'tenant_state',
            'entity_id' => $user->tenantId,
            'request_id' => $requestId,
            'ip' => $ip,
            'outcome' => 'ok',
            'metadata' => [
                'job_id' => $jobId,
                'record_id' => $recordId,
                'resolution' => $resolution,
            ],
        ]);
        return $this->review($user, $jobId);
    }

    /**
     * Return the staged review with decisions overlaid; PII is returned only
     * to this authenticated admin response and never copied to logs.
     *
     * @return array<string, mixed>
     */
    public function review(Principal $user, string $jobId): array
    {
        $this->requireAdmin($user);
        if (!Ids::isUuid($jobId)) {
            throw new ApiException(400, Codes::BAD_PAYLOAD, 'job_id must be a UUID');
        }
        $job = $this->job($user->tenantId, $jobId);
        $rows = $this->db->query(
            'SELECT r.id,r.entity,r.source_key,r.action,r.target_id,r.record_json,'
            . 'r.issues_json,d.resolution,d.target_id AS decision_target_id '
            . 'FROM legacy_import_records r '
            . 'LEFT JOIN legacy_import_decisions d '
            . 'ON d.job_id=r.job_id AND d.record_id=r.id '
            . 'WHERE r.job_id=? AND r.tenant_id=? '
            . 'ORDER BY FIELD(r.entity,\'periods\',\'customers\',\'owners\','
            . '\'identities\',\'crm_devices\',\'customer_transactions\','
            . '\'settings\'),r.source_key',
            [$jobId, $user->tenantId]
        );
        $records = [];
        $counts = [
            'create'=>0,'merge'=>0,'skip'=>0,'reject'=>0,
            'conflict'=>0,'invalid'=>0,'pending'=>0,
        ];
        $unresolved = 0;
        foreach ($rows as $row) {
            $detected = (string) $row['action'];
            $decision = $row['resolution'] === null ? null : (string) $row['resolution'];
            $effective = $decision ?? $detected;
            if (isset($counts[$effective])) {
                $counts[$effective]++;
            }
            if ($decision === null && in_array($detected,
                ['pending','conflict','invalid'], true)) {
                $unresolved++;
            }
            $decoded = json_decode((string) $row['record_json'], true);
            $issues = $row['issues_json'] === null ? []
                : json_decode((string) $row['issues_json'], true);
            $records[] = [
                'id' => (string) $row['id'],
                'entity' => (string) $row['entity'],
                'source_key' => (string) $row['source_key'],
                'detected_action' => $detected,
                'decision' => $decision,
                'effective_action' => $effective,
                'target_id' => $row['decision_target_id'] !== null
                    ? (string) $row['decision_target_id']
                    : ($row['target_id'] === null ? null : (string) $row['target_id']),
                'record' => is_array($decoded) ? $decoded : [],
                'issues' => is_array($issues) ? $issues : [],
            ];
        }
        return [
            'job' => [
                'id' => (string) $job['id'],
                'status' => (string) $job['status'],
                'source_sha256' => (string) $job['source_sha256'],
                'source_version' => (string) $job['source_version'],
                'record_count' => (int) $job['record_count'],
                'applied_at' => $job['applied_at'] === null ? null
                    : Schema::toWireTimestamp((string) $job['applied_at']),
                'error_code' => (string) $job['error_code'],
            ],
            'counts' => $counts,
            'unresolved' => $unresolved,
            'records' => $records,
        ];
    }

    /**
     * Apply every accepted staged record in one transaction.
     *
     * @return array<string, mixed>
     */
    public function apply(Principal $user, string $jobId, string $requestId,
                          string $ip): array
    {
        $this->requireAdmin($user);
        if (!Ids::isUuid($jobId)) {
            throw new ApiException(400, Codes::BAD_PAYLOAD, 'job_id must be a UUID');
        }
        $this->ensureTenantState($user->tenantId);

        $result = $this->db->transaction(function (Database $tx) use (
            $user, $jobId, $requestId
        ): array {
            $job = $tx->queryOne(
                'SELECT * FROM legacy_import_jobs WHERE id=? AND tenant_id=? FOR UPDATE',
                [$jobId, $user->tenantId]
            );
            if ($job === null) {
                throw new ApiException(404, Codes::NOT_FOUND,
                    'legacy import job was not found');
            }
            if (($job['status'] ?? '') === 'applied') {
                $cursor = $tx->queryValue(
                    'SELECT MAX(seq) FROM change_log WHERE tenant_id=?',
                    [$user->tenantId]
                );
                return [
                    'job_id' => $jobId, 'status' => 'applied',
                    'cursor' => $cursor === null ? 0 : (int) $cursor,
                    'replayed' => true,
                ];
            }
            if (($job['status'] ?? '') !== 'ready') {
                throw new ApiException(409, Codes::VERSION_CONFLICT,
                    'legacy import job still requires review');
            }
            $unresolved = (int) ($tx->queryValue(
                'SELECT COUNT(*) FROM legacy_import_records r '
                . 'LEFT JOIN legacy_import_decisions d '
                . 'ON d.job_id=r.job_id AND d.record_id=r.id '
                . 'WHERE r.job_id=? AND r.tenant_id=? '
                . "AND r.action IN ('pending','conflict','invalid') "
                . 'AND d.id IS NULL',
                [$jobId, $user->tenantId]
            ) ?? 0);
            if ($unresolved !== 0) {
                throw new ApiException(409, Codes::VERSION_CONFLICT,
                    'legacy import job has unresolved rows');
            }

            $state = $tx->queryOne(
                'SELECT * FROM tenant_state WHERE tenant_id=? FOR UPDATE',
                [$user->tenantId]
            );
            if ($state === null) {
                throw new ApiException(500, Codes::CONFIG_INVALID,
                    'tenant state row is missing');
            }
            $datasetSource = $state['source_installation_id'] ?? null;
            if (!is_string($datasetSource) || !Ids::isUuid($datasetSource)) {
                if ($this->businessRows($tx, $user->tenantId) !== 0) {
                    throw new ApiException(409, Codes::VERSION_CONFLICT,
                        'live data has no stable dataset authority');
                }
                $datasetSource = (string) $job['source_installation_id'];
                if (!Ids::isUuid($datasetSource)) {
                    throw new ApiException(500, Codes::CONFIG_INVALID,
                        'migration job has no source installation identity');
                }
                $tx->execute(
                    'UPDATE tenant_state SET source_installation_id=?, '
                    . 'dataset_epoch=?,bootstrap_status=?,updated_at=? '
                    . 'WHERE tenant_id=?',
                    [
                        $datasetSource,
                        max(1, (int) $state['dataset_epoch'] + 1),
                        'done', gmdate('Y-m-d H:i:s'), $user->tenantId,
                    ]
                );
            }

            $tx->execute(
                'UPDATE legacy_import_jobs SET status=?,updated_at=? '
                . 'WHERE id=? AND tenant_id=?',
                ['applying', gmdate('Y-m-d H:i:s'), $jobId, $user->tenantId]
            );

            $staged = $tx->query(
                'SELECT r.*,d.resolution,d.target_id AS decision_target_id '
                . 'FROM legacy_import_records r '
                . 'LEFT JOIN legacy_import_decisions d '
                . 'ON d.job_id=r.job_id AND d.record_id=r.id '
                . 'WHERE r.job_id=? AND r.tenant_id=?',
                [$jobId, $user->tenantId]
            );
            $byEntity = [];
            foreach ($staged as $row) {
                $byEntity[(string) $row['entity']][] = $row;
            }

            /** @var array<string, string> $sourceMap */
            $sourceMap = [];
            $counts = ['created'=>0,'merged'=>0,'skipped'=>0,'rejected'=>0];
            $now = gmdate('Y-m-d H:i:s');
            foreach (self::ORDER as $entity) {
                foreach ($byEntity[$entity] ?? [] as $row) {
                    $record = json_decode((string) $row['record_json'], true);
                    if (!is_array($record)) {
                        throw new ApiException(409, Codes::VALIDATION_FAILED,
                            'staged record is no longer valid JSON');
                    }
                    $detected = (string) $row['action'];
                    $resolution = $row['resolution'] === null
                        ? $detected : (string) $row['resolution'];
                    $target = $row['decision_target_id'] !== null
                        ? (string) $row['decision_target_id']
                        : ($row['target_id'] === null ? null : (string) $row['target_id']);
                    $sourceKey = (string) $row['source_key'];

                    if ($resolution === 'reject') {
                        $counts['rejected']++;
                        continue;
                    }
                    if ($resolution === 'skip') {
                        if ($target === null || !Ids::isUuid($target)) {
                            throw new ApiException(409, Codes::VERSION_CONFLICT,
                                'skip decision lost its target');
                        }
                        if ($entity !== 'customer_transactions' && $entity !== 'settings') {
                            $sourceMap[$this->mapKey($entity, $sourceKey)] = $target;
                        }
                        $counts['skipped']++;
                        continue;
                    }
                    if ($entity === 'customer_transactions') {
                        if ($resolution !== 'create') {
                            throw new ApiException(409, Codes::VALIDATION_FAILED,
                                'financial staged rows may only be created, skipped or rejected');
                        }
                        $uuid = $this->createTransaction(
                            $tx, $user, $jobId, $datasetSource, $record,
                            $sourceMap, $requestId, $now
                        );
                        $tx->execute(
                            'UPDATE legacy_import_records SET target_id=?,updated_at=? '
                            . 'WHERE id=?', [$uuid, $now, $row['id']]
                        );
                        $counts['created']++;
                        continue;
                    }

                    if ($resolution === 'create') {
                        $uuid = $this->createRecord(
                            $tx, $user, $jobId, $datasetSource, $entity,
                            $sourceKey, $record, $sourceMap, $requestId, $now
                        );
                        if ($entity !== 'settings') {
                            $sourceMap[$this->mapKey($entity, $sourceKey)] = $uuid;
                        }
                        $tx->execute(
                            'UPDATE legacy_import_records SET target_id=?,updated_at=? '
                            . 'WHERE id=?', [$uuid, $now, $row['id']]
                        );
                        $counts['created']++;
                        continue;
                    }
                    if ($resolution === 'merge') {
                        if ($target === null || !Ids::isUuid($target)) {
                            throw new ApiException(409, Codes::VERSION_CONFLICT,
                                'merge decision lost its target');
                        }
                        $this->mergeRecord(
                            $tx, $user, $jobId, $entity, $target, $record,
                            $sourceMap, $requestId, $now
                        );
                        if ($entity !== 'settings') {
                            $sourceMap[$this->mapKey($entity, $sourceKey)] = $target;
                        }
                        $counts['merged']++;
                        continue;
                    }
                    throw new ApiException(409, Codes::VERSION_CONFLICT,
                        'staged row has no applicable resolution');
                }
            }

            $cursor = $tx->queryValue(
                'SELECT MAX(seq) FROM change_log WHERE tenant_id=?',
                [$user->tenantId]
            );
            $tx->execute(
                'UPDATE legacy_import_jobs SET status=?,applied_at=?,updated_at=?,error_code=? '
                . 'WHERE id=? AND tenant_id=?',
                ['applied', $now, $now, '', $jobId, $user->tenantId]
            );
            return [
                'job_id' => $jobId,
                'status' => 'applied',
                'cursor' => $cursor === null ? 0 : (int) $cursor,
                'counts' => $counts,
                'replayed' => false,
            ];
        });

        $this->log->line([
            'request_id' => $requestId,
            'action' => 'legacy_import.apply',
            'outcome' => 'ok',
            'tenant_id' => $user->tenantId,
        ]);
        $this->log->audit($this->db, [
            'tenant_id' => $user->tenantId,
            'action' => 'legacy_import.apply',
            'actor_type' => 'user',
            'actor_user_id' => $user->userId,
            'entity' => 'tenant_state',
            'entity_id' => $user->tenantId,
            'request_id' => $requestId,
            'ip' => $ip,
            'outcome' => 'ok',
            'metadata' => [
                'job_id' => $jobId,
                'created' => (int) (($result['counts']['created'] ?? 0)),
                'merged' => (int) (($result['counts']['merged'] ?? 0)),
                'skipped' => (int) (($result['counts']['skipped'] ?? 0)),
                'rejected' => (int) (($result['counts']['rejected'] ?? 0)),
            ],
        ]);
        return $result;
    }

    /** @return array<string,mixed> */
    private function job(string $tenantId, string $jobId): array
    {
        $row = $this->db->queryOne(
            'SELECT * FROM legacy_import_jobs WHERE id=? AND tenant_id=?',
            [$jobId, $tenantId]
        );
        if ($row === null) {
            throw new ApiException(404, Codes::NOT_FOUND,
                'legacy import job was not found');
        }
        return $row;
    }

    private function requireAdmin(Principal $user): void
    {
        if (!$user->isUser()) {
            throw new ApiException(401, Codes::AUTH_REQUIRED,
                'legacy migration requires a user session');
        }
        Roles::requireImport($user->role);
    }

    private function requireTarget(string $tenantId, string $entity,
                                   string $targetId): void
    {
        $table = Schema::tableForEntity($entity);
        if ($table === null) {
            throw new ApiException(400, Codes::VALIDATION_FAILED,
                'staged entity is outside the sync schema');
        }
        $found = $this->db->queryValue(
            'SELECT id FROM ' . $this->db->table($table)
            . ' WHERE id=? AND tenant_id=? AND deleted_at IS NULL',
            [$targetId, $tenantId]
        );
        if ($found === null) {
            throw new ApiException(404, Codes::NOT_FOUND,
                'selected merge target was not found');
        }
    }

    private function ensureTenantState(string $tenantId): void
    {
        if ($this->db->queryValue(
            'SELECT tenant_id FROM tenant_state WHERE tenant_id=?', [$tenantId]
        ) !== null) {
            return;
        }
        $now = gmdate('Y-m-d H:i:s');
        try {
            $this->db->execute(
                'INSERT INTO tenant_state '
                . '(tenant_id,bootstrap_status,dataset_epoch,created_at,updated_at) '
                . 'VALUES (?,?,?,?,?)',
                [$tenantId, 'pending', 0, $now, $now]
            );
        } catch (PDOException $error) {
            $info = $error->errorInfo ?? null;
            if (!is_array($info) || (int) ($info[1] ?? 0) !== 1062) {
                throw $error;
            }
        }
    }

    private function businessRows(Database $tx, string $tenantId): int
    {
        $parts = [];
        $params = [];
        foreach (Schema::entities() as $table) {
            $parts[] = '(SELECT COUNT(*) FROM ' . $tx->table($table)
                . ' WHERE tenant_id=?)';
            $params[] = $tenantId;
        }
        return (int) ($tx->queryValue('SELECT ' . implode(' + ', $parts), $params) ?? 0);
    }

    /** @param array<string,mixed> $record @param array<string,string> $sourceMap */
    private function createRecord(Database $tx, Principal $user, string $jobId,
                                  string $datasetSource, string $entity,
                                  string $sourceKey, array $record,
                                  array $sourceMap, string $requestId,
                                  string $now): string
    {
        $table = Schema::tableForEntity($entity);
        if ($table === null || $entity === 'customer_transactions') {
            throw new ApiException(400, Codes::VALIDATION_FAILED,
                'staged entity cannot be created by this path');
        }
        $legacyId = $entity === 'settings' ? Ids::SETTINGS_LEGACY_ID
            : $this->availableLegacyId($tx, $table, $user->tenantId, $sourceKey);
        $uuid = Ids::uuid5($datasetSource, $entity, $legacyId);
        $wire = $this->mapReferences(
            $tx, $user->tenantId, $entity, $record, $sourceMap
        );
        if (!Ids::isSynthetic($entity)) {
            $wire['id'] = $legacyId;
        }
        $row = $this->sync->recordToRow(
            $entity, $table, $uuid, $user->tenantId, $wire, $requestId, $this->log
        );
        $tx->insert($table, $row);
        $this->change($tx, $user, $jobId, $entity, $uuid, 1, $now);
        return $uuid;
    }

    /** @param array<string,mixed> $record @param array<string,string> $sourceMap */
    private function mergeRecord(Database $tx, Principal $user, string $jobId,
                                 string $entity, string $targetId, array $record,
                                 array $sourceMap, string $requestId,
                                 string $now): void
    {
        if ($entity === 'customer_transactions') {
            throw new ApiException(409, Codes::VALIDATION_FAILED,
                'financial rows cannot be merged in place');
        }
        $table = Schema::tableForEntity($entity);
        if ($table === null) {
            throw new ApiException(400, Codes::VALIDATION_FAILED,
                'staged entity is outside the sync schema');
        }
        $live = $tx->queryOne(
            'SELECT * FROM ' . $tx->table($table)
            . ' WHERE id=? AND tenant_id=? AND deleted_at IS NULL FOR UPDATE',
            [$targetId, $user->tenantId]
        );
        if ($live === null) {
            throw new ApiException(409, Codes::VERSION_CONFLICT,
                'merge target changed after review');
        }
        $base = $this->sync->rowToRecord($table, $live);
        if (!Ids::isSynthetic($entity)
            && (!isset($base['id']) || !is_string($base['id']) || $base['id'] === '')) {
            throw new ApiException(409, Codes::VERSION_CONFLICT,
                'merge target has no client-compatible legacy identity');
        }
        $mapped = $this->mapReferences(
            $tx, $user->tenantId, $entity, $record, $sourceMap
        );
        unset($mapped['id']);
        foreach ($mapped as $key => $value) {
            if (!array_key_exists($key, $base) || $this->blank($base[$key])) {
                $base[$key] = $value;
            }
        }
        $candidate = $this->sync->recordToRow(
            $entity, $table, $targetId, $user->tenantId, $base,
            $requestId, $this->log
        );
        $nextVersion = (int) $live['row_version'] + 1;
        $updates = ['row_version' => $nextVersion,
                    'updated_at' => gmdate('Y-m-d\TH:i:s+00:00')];
        foreach (Schema::businessColumns($table) as $column) {
            if (array_key_exists($column, $candidate)) {
                $updates[$column] = $candidate[$column];
            }
        }
        $tx->update($table, $updates, 'id=? AND tenant_id=?',
            [$targetId, $user->tenantId]);
        $this->change($tx, $user, $jobId, $entity, $targetId,
            $nextVersion, $now);
    }

    /** @param array<string,mixed> $record @param array<string,string> $sourceMap */
    private function createTransaction(Database $tx, Principal $user,
                                       string $jobId, string $datasetSource,
                                       array $record, array $sourceMap,
                                       string $requestId, string $now): string
    {
        $sourceCustomer = $record['customer_id'] ?? null;
        if (!is_string($sourceCustomer) || $sourceCustomer === '') {
            throw new ApiException(409, Codes::VALIDATION_FAILED,
                'financial row lost its customer reference');
        }
        $customerId = $this->resolveReference(
            $tx, $user->tenantId, 'customers', $sourceCustomer, $sourceMap
        );
        if ($customerId === null) {
            throw new ApiException(409, Codes::VERSION_CONFLICT,
                'financial customer was rejected or no longer exists');
        }
        $customer = $tx->queryOne(
            'SELECT id,legacy_id FROM customers '
            . 'WHERE id=? AND tenant_id=? AND deleted_at IS NULL FOR UPDATE',
            [$customerId, $user->tenantId]
        );
        if ($customer === null || !is_string($customer['legacy_id'])
            || $customer['legacy_id'] === '') {
            throw new ApiException(409, Codes::VERSION_CONFLICT,
                'financial customer has no stable client identity');
        }
        $nextSeq = (int) ($tx->queryValue(
            'SELECT MAX(seq) FROM customer_transactions '
            . 'WHERE tenant_id=? AND customer_id=? AND deleted_at IS NULL',
            [$user->tenantId, $customerId]
        ) ?? -1) + 1;
        $legacyId = Ids::transactionLegacyId((string) $customer['legacy_id'], $nextSeq);
        $uuid = Ids::uuid5($datasetSource, 'customer_transactions', $legacyId);
        $wire = $record;
        $wire['seq'] = $nextSeq;
        $wire['customer_id'] = $customerId;
        $sourceDevice = $record['device_id'] ?? '';
        $wire['device_id'] = is_string($sourceDevice) && $sourceDevice !== ''
            ? $this->resolveReference(
                $tx, $user->tenantId, 'crm_devices', $sourceDevice, $sourceMap
            ) : null;
        if (is_string($sourceDevice) && $sourceDevice !== ''
            && $wire['device_id'] === null) {
            throw new ApiException(409, Codes::VERSION_CONFLICT,
                'financial device reference was rejected or no longer exists');
        }
        $row = $this->sync->recordToRow(
            'customer_transactions', 'customer_transactions', $uuid,
            $user->tenantId, $wire, $requestId, $this->log
        );
        $tx->insert('customer_transactions', $row);
        $this->change($tx, $user, $jobId, 'customer_transactions',
            $uuid, 1, $now);
        return $uuid;
    }

    /** @param array<string,mixed> $record @param array<string,string> $sourceMap @return array<string,mixed> */
    private function mapReferences(Database $tx, string $tenantId, string $entity,
                                   array $record, array $sourceMap): array
    {
        $refs = [
            'crm_devices' => [
                'customer_id'=>'customers','owner_id'=>'owners','period_id'=>'periods',
            ],
            'settings' => ['current_period_id'=>'periods'],
        ];
        foreach ($refs[$entity] ?? [] as $field => $targetEntity) {
            $source = $record[$field] ?? '';
            if ($source === null || $source === '') {
                $record[$field] = null;
                continue;
            }
            if (!is_string($source)) {
                throw new ApiException(409, Codes::VALIDATION_FAILED,
                    'staged reference has an invalid type');
            }
            $resolved = $this->resolveReference(
                $tx, $tenantId, $targetEntity, $source, $sourceMap
            );
            if ($resolved === null) {
                throw new ApiException(409, Codes::VERSION_CONFLICT,
                    'a reviewed staged reference no longer resolves');
            }
            $record[$field] = $resolved;
        }
        return $record;
    }

    /** @param array<string,string> $sourceMap */
    private function resolveReference(Database $tx, string $tenantId,
                                      string $entity, string $sourceId,
                                      array $sourceMap): ?string
    {
        $key = $this->mapKey($entity, $sourceId);
        if (isset($sourceMap[$key])) {
            return $sourceMap[$key];
        }
        $table = Schema::tableForEntity($entity);
        if ($table === null) {
            return null;
        }
        $value = $tx->queryValue(
            'SELECT id FROM ' . $tx->table($table)
            . ' WHERE tenant_id=? AND legacy_id=? AND deleted_at IS NULL LIMIT 1',
            [$tenantId, $sourceId]
        );
        return is_string($value) && Ids::isUuid($value) ? $value : null;
    }

    private function availableLegacyId(Database $tx, string $table,
                                       string $tenantId, string $preferred): string
    {
        if ($preferred !== '' && strlen($preferred) <= 64
            && $tx->queryValue(
                'SELECT id FROM ' . $tx->table($table)
                . ' WHERE tenant_id=? AND legacy_id=? LIMIT 1',
                [$tenantId, $preferred]
            ) === null) {
            return $preferred;
        }
        for ($attempt = 0; $attempt < 32; $attempt++) {
            $candidate = substr(str_replace('-', '', Ids::v4()), 0, 8);
            if ($tx->queryValue(
                'SELECT id FROM ' . $tx->table($table)
                . ' WHERE tenant_id=? AND legacy_id=? LIMIT 1',
                [$tenantId, $candidate]
            ) === null) {
                return $candidate;
            }
        }
        throw new ApiException(500, Codes::SERVER_ERROR,
            'could not allocate a legacy-compatible row identity');
    }

    private function change(Database $tx, Principal $user, string $jobId,
                            string $entity, string $id, int $version,
                            string $now): void
    {
        $tx->insert('change_log', [
            'tenant_id' => $user->tenantId,
            'entity' => $entity,
            'id' => $id,
            'row_version' => $version,
            'action' => 'upsert',
            'actor_type' => 'user',
            'actor_user_id' => $user->userId,
            'actor_device_id' => null,
            'operation_id' => $jobId,
            'changed_at' => $now,
        ]);
    }

    private function mapKey(string $entity, string $sourceId): string
    {
        return $entity . "\0" . $sourceId;
    }

    private function blank(mixed $value): bool
    {
        return $value === null || $value === '' || $value === [];
    }
}
