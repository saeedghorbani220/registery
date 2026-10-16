<?php
/**
 * LegacyImport.php — safe staging and preview for pre-server CRM databases.
 *
 * This is intentionally separate from Import.php. Bootstrap import owns the
 * empty-dataset, exactly-once path; LegacyImport owns merging old local stores
 * into an already-live server dataset. Analysis never writes a business table.
 * It stores only normalized staging rows plus metadata, so an operator can
 * review every ambiguous match before a later atomic apply.
 */

declare(strict_types=1);

final class LegacyImport
{
    private const MAX_SUPPORTED_VERSION = '1.13.1';

    /** @var array<string, string> */
    private const TABLES = [
        'customers' => 'customers',
        'owners' => 'owners',
        'identities' => 'identities',
        'crm_devices' => 'crm_devices',
        'periods' => 'periods',
        'customer_transactions' => 'customer_transactions',
        'settings' => 'settings',
    ];

    /** @var list<string> */
    private const SETTINGS_ALLOWLIST = [
        'business_name', 'business_phone', 'watch_interval_hours',
        'scheduler_enabled', 'auto_advance_default',
        'telegram_report_full_data', 'registry_fee_amount',
        'registration_chat_id', 'report_chat_id', 'sound_enabled',
        'current_period_id', 'links',
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
     * Analyze one exact uploaded legacy JSON document and stage a dry-run.
     *
     * Body shape:
     *   {source_text: "{...}", filename?: "crm_store.json",
     *    source_version?: "1.13.1"}
     *
     * The raw file is never stored. source_sha256 fingerprints the exact bytes
     * supplied by the browser and makes re-upload idempotent.
     *
     * @param array<string, mixed> $body
     * @return array<string, mixed>
     */
    public function analyze(Principal $user, array $body, string $requestId,
                            string $ip): array
    {
        $this->requireAdminUser($user);
        $sourceText = $body['source_text'] ?? null;
        if (!is_string($sourceText) || trim($sourceText) === '') {
            throw new ApiException(400, Codes::BAD_PAYLOAD,
                'source_text must contain the legacy JSON document');
        }
        $limit = (int) ($this->cfg['limits']['max_import_body_bytes'] ?? 16777216);
        if ($limit < 1024) {
            $limit = 16777216;
        }
        if (strlen($sourceText) > $limit) {
            throw new ApiException(413, Codes::PAYLOAD_TOO_LARGE,
                'legacy database exceeds the configured import size');
        }

        try {
            $source = json_decode($sourceText, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException $error) {
            unset($error);
            throw new ApiException(400, Codes::VALIDATION_FAILED,
                'legacy database is not valid JSON');
        }
        if (!is_array($source) || array_is_list($source)) {
            throw new ApiException(400, Codes::VALIDATION_FAILED,
                'legacy database root must be a JSON object');
        }

        $version = $this->sourceVersion($body, $source);
        if ($this->isNewerVersion($version)) {
            throw new ApiException(400, Codes::VALIDATION_FAILED,
                'this migration path only accepts version 1.13.1 or older');
        }

        $tenantId = $user->tenantId;
        $sha = hash('sha256', $sourceText);
        $existing = $this->db->queryOne(
            'SELECT id FROM legacy_import_jobs '
            . 'WHERE tenant_id = ? AND source_sha256 = ? LIMIT 1',
            [$tenantId, $sha]
        );
        if ($existing !== null) {
            return $this->preview($user, (string) $existing['id']);
        }

        $rows = $this->normalize($source);
        $this->markBrokenReferences($tenantId, $rows);
        foreach ($rows as &$row) {
            if ($row['issues'] !== []) {
                $row['action'] = 'invalid';
                $row['target_id'] = null;
                continue;
            }
            [$action, $target] = $this->classify(
                $tenantId, (string) $row['entity'], $row['record']
            );
            $row['action'] = $action;
            $row['target_id'] = $target;
        }
        unset($row);

        $jobId = Ids::v4();
        $sourceInstallationId = Ids::v4(); // provenance only; never rewrites dataset authority
        $filename = $this->safeFilename($body['filename'] ?? '');
        $now = gmdate('Y-m-d H:i:s');
        $counts = $this->counts($rows);
        $status = (($counts['conflict'] ?? 0) > 0
            || ($counts['invalid'] ?? 0) > 0) ? 'review' : 'ready';

        try {
            $this->db->transaction(function (Database $tx) use (
                $jobId, $tenantId, $sha, $version, $sourceInstallationId,
                $filename, $user, $now, $rows, $status
            ): void {
                $duplicate = $tx->queryOne(
                    'SELECT id FROM legacy_import_jobs '
                    . 'WHERE tenant_id = ? AND source_sha256 = ? FOR UPDATE',
                    [$tenantId, $sha]
                );
                if ($duplicate !== null) {
                    // A concurrent identical upload won. The unique index is
                    // the final guard; throwing rolls this no-op transaction back.
                    throw new LegacyImportDuplicate((string) $duplicate['id']);
                }

                $tx->execute(
                    'INSERT INTO legacy_import_jobs '
                    . '(id,tenant_id,source_sha256,source_version,'
                    . 'source_installation_id,original_filename,status,'
                    . 'record_count,created_by,created_at,updated_at,error_code) '
                    . 'VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',
                    [
                        $jobId, $tenantId, $sha, $version,
                        $sourceInstallationId, $filename, 'analyzing',
                        count($rows), $user->userId, $now, $now, '',
                    ]
                );

                foreach ($rows as $row) {
                    $recordJson = $this->canonical($row['record']);
                    $issuesJson = $row['issues'] === [] ? null
                        : $this->canonical($row['issues']);
                    $tx->execute(
                        'INSERT INTO legacy_import_records '
                        . '(id,tenant_id,job_id,entity,source_key,source_hash,'
                        . 'action,target_id,record_json,issues_json,created_at,updated_at) '
                        . 'VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',
                        [
                            Ids::v4(), $tenantId, $jobId, $row['entity'],
                            $row['source_key'], hash('sha256', $recordJson),
                            $row['action'], $row['target_id'], $recordJson,
                            $issuesJson, $now, $now,
                        ]
                    );
                }
                $tx->execute(
                    'UPDATE legacy_import_jobs SET status = ?, updated_at = ? '
                    . 'WHERE id = ? AND tenant_id = ?',
                    [$status, $now, $jobId, $tenantId]
                );
            });
        } catch (LegacyImportDuplicate $duplicate) {
            return $this->preview($user, $duplicate->jobId);
        }

        $this->log->line([
            'request_id' => $requestId,
            'action' => 'legacy_import.analyze',
            'outcome' => 'ok',
            'tenant_id' => $tenantId,
            'count' => count($rows),
        ]);
        $this->log->audit($this->db, [
            'tenant_id' => $tenantId,
            'action' => 'legacy_import.analyze',
            'actor_type' => 'user',
            'actor_user_id' => $user->userId,
            'entity' => 'tenant_state',
            'entity_id' => $tenantId,
            'request_id' => $requestId,
            'ip' => $ip,
            'outcome' => 'ok',
            'metadata' => [
                'job_id' => $jobId,
                'rows' => count($rows),
                'source_sha256' => $sha,
                'status' => $status,
            ],
        ]);
        return $this->preview($user, $jobId);
    }

    /** @return array<string, mixed> */
    public function preview(Principal $user, string $jobId): array
    {
        $this->requireAdminUser($user);
        if (!Ids::isUuid($jobId)) {
            throw new ApiException(400, Codes::BAD_PAYLOAD,
                'job_id must be a UUID');
        }
        $job = $this->db->queryOne(
            'SELECT id,source_sha256,source_version,status,record_count,'
            . 'created_at,updated_at,applied_at,error_code '
            . 'FROM legacy_import_jobs WHERE id = ? AND tenant_id = ?',
            [$jobId, $user->tenantId]
        );
        if ($job === null) {
            throw new ApiException(404, Codes::NOT_FOUND,
                'legacy import job was not found');
        }
        $staged = $this->db->query(
            'SELECT id,entity,source_key,action,target_id,record_json,issues_json '
            . 'FROM legacy_import_records WHERE job_id = ? AND tenant_id = ? '
            . 'ORDER BY FIELD(entity,\'periods\',\'customers\',\'owners\','
            . '\'identities\',\'crm_devices\',\'customer_transactions\','
            . '\'settings\'), source_key',
            [$jobId, $user->tenantId]
        );
        $records = [];
        foreach ($staged as $row) {
            $record = json_decode((string) $row['record_json'], true);
            $issues = $row['issues_json'] === null ? []
                : json_decode((string) $row['issues_json'], true);
            $records[] = [
                'id' => (string) $row['id'],
                'entity' => (string) $row['entity'],
                'source_key' => (string) $row['source_key'],
                'action' => (string) $row['action'],
                'target_id' => $row['target_id'] === null
                    ? null : (string) $row['target_id'],
                'record' => is_array($record) ? $record : [],
                'issues' => is_array($issues) ? $issues : [],
            ];
        }
        return [
            'job' => [
                'id' => (string) $job['id'],
                'source_sha256' => (string) $job['source_sha256'],
                'source_version' => (string) $job['source_version'],
                'status' => (string) $job['status'],
                'record_count' => (int) $job['record_count'],
                'created_at' => Schema::toWireTimestamp((string) $job['created_at']),
                'updated_at' => Schema::toWireTimestamp((string) $job['updated_at']),
                'applied_at' => $job['applied_at'] === null ? null
                    : Schema::toWireTimestamp((string) $job['applied_at']),
                'error_code' => (string) $job['error_code'],
            ],
            'counts' => $this->counts($records),
            'records' => $records,
        ];
    }

    private function requireAdminUser(Principal $user): void
    {
        if (!$user->isUser()) {
            throw new ApiException(401, Codes::AUTH_REQUIRED,
                'legacy migration requires a user session');
        }
        Roles::requireImport($user->role);
    }

    /** @param array<string, mixed> $body @param array<string, mixed> $source */
    private function sourceVersion(array $body, array $source): string
    {
        $value = $body['source_version'] ?? ($source['version'] ?? ($source['app_version'] ?? ''));
        if (!is_string($value)) {
            return '';
        }
        return substr(trim($value), 0, 32);
    }

    private function isNewerVersion(string $version): bool
    {
        if ($version === '') {
            return false;
        }
        if (preg_match('/^v?(\d+\.\d+\.\d+)(?:[-+].*)?$/i', $version, $m) !== 1) {
            return false; // old stores often had no formal version marker
        }
        return version_compare($m[1], self::MAX_SUPPORTED_VERSION, '>');
    }

    private function safeFilename(mixed $value): string
    {
        if (!is_string($value) || $value === '') {
            return '';
        }
        $name = basename(str_replace('\\', '/', $value));
        $name = preg_replace('/[^A-Za-z0-9._ -]/u', '_', $name) ?? '';
        return substr($name, 0, 255);
    }

    /**
     * Convert a legacy store into current staged business records.
     *
     * @param array<string, mixed> $source
     * @return list<array{entity:string,source_key:string,record:array<string,mixed>,issues:list<array{code:string,field:string}>,action:string,target_id:?string}>
     */
    private function normalize(array $source): array
    {
        $rows = [];
        $customers = $this->listOf($source, 'customers');
        foreach ($customers as $index => $raw) {
            $issues = [];
            $id = $this->sourceId($raw, 'id', $issues);
            $record = [
                'id' => $id,
                'full_name' => $this->text($raw, 'full_name', 80, $issues, true),
                'address' => $this->text($raw, 'address', 300, $issues),
                'mobile' => $this->text($raw, 'mobile', 11, $issues),
                'telegram_id' => $this->text($raw, 'telegram_id', 64, $issues),
                'instagram_id' => $this->text($raw, 'instagram_id', 64, $issues),
                'notes' => $this->text($raw, 'notes', 500, $issues),
                'created' => $this->wireTime($raw['created'] ?? null, 'created', $issues),
                'updated' => $this->wireTime($raw['updated'] ?? null, 'updated', $issues),
            ];
            $rows[] = $this->stage('customers', $id !== '' ? $id : 'row-' . $index,
                $record, $issues);

            $transactions = isset($raw['transactions']) && is_array($raw['transactions'])
                && array_is_list($raw['transactions']) ? $raw['transactions'] : [];
            foreach ($transactions as $seq => $txRaw) {
                $txIssues = [];
                if (!is_array($txRaw) || array_is_list($txRaw)) {
                    $txRaw = [];
                    $this->issue($txIssues, 'TYPE_INVALID', 'transaction');
                }
                $amount = $this->integer($txRaw, 'amount', $txIssues, true);
                $recordTx = [
                    'seq' => $seq,
                    'customer_id' => $id,
                    'at' => $this->wireTime($txRaw['at'] ?? null, 'at', $txIssues, true),
                    'amount' => $amount,
                    'note' => $this->text($txRaw, 'note', 1000, $txIssues),
                    'kind' => $this->text($txRaw, 'kind', 32, $txIssues),
                    'image' => $this->text($txRaw, 'image', 64, $txIssues),
                    'device_id' => $this->text($txRaw, 'device_id', 64, $txIssues),
                    'voided_at' => $this->wireTime($txRaw['voided_at'] ?? null, 'voided_at', $txIssues),
                    'void_reason' => $this->text($txRaw, 'void_reason', 1000, $txIssues),
                ];
                if ($id === '') {
                    $this->issue($txIssues, 'REFERENCE_MISSING', 'customer_id');
                }
                $rows[] = $this->stage('customer_transactions',
                    ($id !== '' ? $id : 'customer-' . $index) . '/' . $seq,
                    $recordTx, $txIssues);
            }
        }

        foreach ($this->listOf($source, 'owners') as $index => $raw) {
            $issues = [];
            $id = $this->sourceId($raw, 'id', $issues);
            $record = [
                'id' => $id,
                'first_name' => $this->text($raw, 'first_name', 120, $issues, true),
                'last_name' => $this->text($raw, 'last_name', 120, $issues, true),
                'national' => $this->text($raw, 'national', 10, $issues, true),
                'birth' => $this->text($raw, 'birth', 10, $issues, true),
                'mobile' => $this->text($raw, 'mobile', 11, $issues, true),
                'card_no' => $this->text($raw, 'card_no', 16, $issues),
                'passport' => strtoupper($this->text($raw, 'passport', 20, $issues)),
                'created' => $this->wireTime($raw['created'] ?? null, 'created', $issues),
                'updated' => $this->wireTime($raw['updated'] ?? null, 'updated', $issues),
            ];
            $rows[] = $this->stage('owners', $id !== '' ? $id : 'row-' . $index,
                $record, $issues);
        }

        foreach ($this->listOf($source, 'identities') as $index => $raw) {
            $issues = [];
            $id = $this->sourceId($raw, 'id', $issues);
            $record = [
                'id' => $id,
                'label' => $this->text($raw, 'label', 80, $issues),
                'national' => $this->text($raw, 'national', 10, $issues, true),
                'birth' => $this->text($raw, 'birth', 10, $issues, true),
                'mobile' => $this->text($raw, 'mobile', 11, $issues, true),
                'created' => $this->wireTime($raw['created'] ?? null, 'created', $issues),
                'updated' => $this->wireTime($raw['updated'] ?? null, 'updated', $issues),
            ];
            $rows[] = $this->stage('identities', $id !== '' ? $id : 'row-' . $index,
                $record, $issues);
        }

        foreach ($this->listOf($source, 'devices') as $index => $raw) {
            $issues = [];
            $id = $this->sourceId($raw, 'id', $issues);
            $record = [
                'id' => $id,
                'name' => $this->text($raw, 'name', 40, $issues, true),
                'serial1' => $this->text($raw, 'serial1', 15, $issues, true),
                'serial2' => $this->text($raw, 'serial2', 15, $issues),
                'customer_id' => $this->text($raw, 'customer_id', 64, $issues),
                'owner_id' => $this->text($raw, 'owner_id', 64, $issues),
                'stage' => $this->textDefault($raw, 'stage', 'new', 16, $issues),
                'auto_advance' => $this->boolean($raw, 'auto_advance', false, $issues),
                'profile_id' => $this->text($raw, 'profile_id', 64, $issues),
                'handed_at' => $this->wireTime($raw['handed_at'] ?? null, 'handed_at', $issues),
                'registered_at' => $this->wireTime($raw['registered_at'] ?? null, 'registered_at', $issues),
                'payment_confirmed_at' => $this->wireTime($raw['payment_confirmed_at'] ?? null, 'payment_confirmed_at', $issues),
                'code_delivered_at' => $this->wireTime($raw['code_delivered_at'] ?? null, 'code_delivered_at', $issues),
                'done_at' => $this->wireTime($raw['done_at'] ?? null, 'done_at', $issues),
                'last_inquiry_at' => $this->wireTime($raw['last_inquiry_at'] ?? null, 'last_inquiry_at', $issues),
                'notes' => $this->text($raw, 'notes', 500, $issues),
                'advance_attempts' => $this->integerDefault($raw, 'advance_attempts', 0, $issues),
                'period_id' => $this->text($raw, 'period_id', 64, $issues),
                'created' => $this->wireTime($raw['created'] ?? null, 'created', $issues),
                'updated' => $this->wireTime($raw['updated'] ?? null, 'updated', $issues),
                'skipped_stages' => $this->stringList($raw, 'skipped_stages', $issues),
                'closed_at' => $this->wireTime($raw['closed_at'] ?? null, 'closed_at', $issues),
                'closed_reason' => $this->text($raw, 'closed_reason', 1000, $issues),
                'periodic_opt_out' => $this->boolean($raw, 'periodic_opt_out', false, $issues),
                'payment_started_at' => $this->wireTime($raw['payment_started_at'] ?? null, 'payment_started_at', $issues),
            ];
            $rows[] = $this->stage('crm_devices', $id !== '' ? $id : 'row-' . $index,
                $record, $issues);
        }

        foreach ($this->listOf($source, 'periods') as $index => $raw) {
            $issues = [];
            $id = $this->sourceId($raw, 'id', $issues);
            $record = [
                'id' => $id,
                'number' => $this->integer($raw, 'number', $issues, true),
                'label' => $this->text($raw, 'label', 120, $issues),
                'opened_at' => $this->wireTime($raw['opened_at'] ?? null, 'opened_at', $issues, true),
                'opened_by' => $this->textDefault($raw, 'opened_by', 'system', 64, $issues),
                'closed_at' => $this->wireTime($raw['closed_at'] ?? null, 'closed_at', $issues),
                'closed_by' => $this->text($raw, 'closed_by', 64, $issues),
                'closed_reason' => $this->text($raw, 'closed_reason', 1000, $issues),
            ];
            $rows[] = $this->stage('periods', $id !== '' ? $id : 'row-' . $index,
                $record, $issues);
        }

        if (isset($source['settings']) && is_array($source['settings'])
            && !array_is_list($source['settings'])) {
            $record = [];
            $issues = [];
            foreach (self::SETTINGS_ALLOWLIST as $key) {
                if (!array_key_exists($key, $source['settings'])) {
                    continue;
                }
                $record[$key] = $source['settings'][$key];
            }
            // database_mode is intentionally absent from the server allowlist.
            $rows[] = $this->stage('settings', Ids::SETTINGS_LEGACY_ID,
                $record, $issues);
        }
        return $rows;
    }

    /** @return list<array<string,mixed>> */
    private function listOf(array $source, string $key): array
    {
        $value = $source[$key] ?? [];
        if (!is_array($value) || !array_is_list($value)) {
            throw new ApiException(400, Codes::VALIDATION_FAILED,
                'legacy collection has an invalid shape');
        }
        $out = [];
        foreach ($value as $record) {
            if (!is_array($record) || array_is_list($record)) {
                throw new ApiException(400, Codes::VALIDATION_FAILED,
                    'legacy collection entries must be JSON objects');
            }
            $out[] = $record;
        }
        return $out;
    }

    /** @param list<array{code:string,field:string}> $issues */
    private function sourceId(array $raw, string $field, array &$issues): string
    {
        $value = $raw[$field] ?? null;
        if (!is_string($value) || trim($value) === '' || strlen(trim($value)) > 64) {
            $this->issue($issues, 'FIELD_REQUIRED', $field);
            return '';
        }
        return trim($value);
    }

    /** @param list<array{code:string,field:string}> $issues */
    private function text(array $raw, string $field, int $max, array &$issues,
                          bool $required = false): string
    {
        $value = $raw[$field] ?? '';
        if ($value === null) {
            $value = '';
        }
        if (!is_string($value)) {
            $this->issue($issues, 'TYPE_INVALID', $field);
            return '';
        }
        $value = trim($value);
        if ($required && $value === '') {
            $this->issue($issues, 'FIELD_REQUIRED', $field);
        }
        if (strlen($value) > $max) {
            $this->issue($issues, 'FIELD_TOO_LONG', $field);
            $value = substr($value, 0, $max);
        }
        return $value;
    }

    /** @param list<array{code:string,field:string}> $issues */
    private function textDefault(array $raw, string $field, string $default,
                                 int $max, array &$issues): string
    {
        if (!array_key_exists($field, $raw) || $raw[$field] === '' || $raw[$field] === null) {
            return $default;
        }
        return $this->text($raw, $field, $max, $issues);
    }

    /** @param list<array{code:string,field:string}> $issues */
    private function integer(array $raw, string $field, array &$issues,
                             bool $required = false): int
    {
        if (!array_key_exists($field, $raw)) {
            if ($required) {
                $this->issue($issues, 'FIELD_REQUIRED', $field);
            }
            return 0;
        }
        $value = $raw[$field];
        if (is_int($value)) {
            return $value;
        }
        if (is_string($value) && preg_match('/^-?\d+$/', $value) === 1) {
            return (int) $value;
        }
        $this->issue($issues, 'TYPE_INVALID', $field);
        return 0;
    }

    /** @param list<array{code:string,field:string}> $issues */
    private function integerDefault(array $raw, string $field, int $default,
                                    array &$issues): int
    {
        return array_key_exists($field, $raw)
            ? $this->integer($raw, $field, $issues) : $default;
    }

    /** @param list<array{code:string,field:string}> $issues */
    private function boolean(array $raw, string $field, bool $default,
                             array &$issues): bool
    {
        if (!array_key_exists($field, $raw)) {
            return $default;
        }
        $value = $raw[$field];
        if (is_bool($value)) {
            return $value;
        }
        if ($value === 0 || $value === 1 || $value === '0' || $value === '1') {
            return (bool) ((int) $value);
        }
        $this->issue($issues, 'TYPE_INVALID', $field);
        return $default;
    }

    /** @param list<array{code:string,field:string}> $issues @return list<string> */
    private function stringList(array $raw, string $field, array &$issues): array
    {
        if (!array_key_exists($field, $raw) || $raw[$field] === null) {
            return [];
        }
        if (!is_array($raw[$field]) || !array_is_list($raw[$field])) {
            $this->issue($issues, 'TYPE_INVALID', $field);
            return [];
        }
        $out = [];
        foreach ($raw[$field] as $value) {
            if (!is_string($value) || strlen($value) > 32) {
                $this->issue($issues, 'TYPE_INVALID', $field);
                continue;
            }
            $out[] = $value;
        }
        return $out;
    }

    /** @param list<array{code:string,field:string}> $issues */
    private function wireTime(mixed $value, string $field, array &$issues,
                              bool $required = false): ?string
    {
        if ($value === null || $value === '') {
            if ($required) {
                $this->issue($issues, 'FIELD_REQUIRED', $field);
            }
            return null;
        }
        if (!is_string($value)) {
            $this->issue($issues, 'TYPE_INVALID', $field);
            return null;
        }
        try {
            if (preg_match('/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/', $value) === 1) {
                $dt = new DateTimeImmutable($value, new DateTimeZone('+03:30'));
            } else {
                $dt = new DateTimeImmutable($value);
                if ($dt->getOffset() === 0 && !str_contains($value, '+')
                    && !str_ends_with(strtoupper($value), 'Z')) {
                    $this->issue($issues, 'TIMEZONE_MISSING', $field);
                    return null;
                }
            }
            return $dt->setTimezone(new DateTimeZone('UTC'))
                ->format('Y-m-d\TH:i:s+00:00');
        } catch (Exception $error) {
            unset($error);
            $this->issue($issues, 'TIME_INVALID', $field);
            return null;
        }
    }

    /** @param list<array{code:string,field:string}> $issues */
    private function issue(array &$issues, string $code, string $field): void
    {
        foreach ($issues as $existing) {
            if (($existing['code'] ?? '') === $code
                && ($existing['field'] ?? '') === $field) {
                return;
            }
        }
        $issues[] = ['code' => $code, 'field' => $field];
    }

    /** @param array<string,mixed> $record @param list<array{code:string,field:string}> $issues */
    private function stage(string $entity, string $sourceKey, array $record,
                           array $issues): array
    {
        return [
            'entity' => $entity,
            'source_key' => substr($sourceKey, 0, 128),
            'record' => $record,
            'issues' => $issues,
            'action' => 'pending',
            'target_id' => null,
        ];
    }

    /** @param list<array<string,mixed>> $rows */
    private function markBrokenReferences(string $tenantId, array &$rows): void
    {
        $source = [
            'customers' => [], 'owners' => [], 'periods' => [], 'crm_devices' => [],
        ];
        foreach ($rows as $row) {
            $entity = (string) $row['entity'];
            if (isset($source[$entity])) {
                $id = $row['record']['id'] ?? '';
                if (is_string($id) && $id !== '') {
                    $source[$entity][$id] = true;
                }
            }
        }

        $refs = [
            'crm_devices' => [
                'customer_id' => 'customers', 'owner_id' => 'owners',
                'period_id' => 'periods',
            ],
            'customer_transactions' => [
                'customer_id' => 'customers', 'device_id' => 'crm_devices',
            ],
            'settings' => ['current_period_id' => 'periods'],
        ];
        foreach ($rows as &$row) {
            $entity = (string) $row['entity'];
            foreach ($refs[$entity] ?? [] as $field => $targetEntity) {
                $value = $row['record'][$field] ?? '';
                if ($value === null || $value === '') {
                    if ($entity === 'customer_transactions' && $field === 'customer_id') {
                        $this->issue($row['issues'], 'REFERENCE_MISSING', $field);
                    }
                    continue;
                }
                if (!is_string($value)) {
                    $this->issue($row['issues'], 'TYPE_INVALID', $field);
                    continue;
                }
                if (isset($source[$targetEntity][$value])) {
                    continue;
                }
                $table = self::TABLES[$targetEntity];
                $found = $this->db->queryValue(
                    'SELECT id FROM ' . $table
                    . ' WHERE tenant_id = ? AND legacy_id = ? '
                    . 'AND deleted_at IS NULL LIMIT 1',
                    [$tenantId, $value]
                );
                if ($found === null) {
                    $this->issue($row['issues'], 'ORPHAN_REFERENCE', $field);
                }
            }
        }
        unset($row);
    }

    /** @param array<string,mixed> $record @return array{0:string,1:?string} */
    private function classify(string $tenantId, string $entity, array $record): array
    {
        if ($entity === 'settings') {
            $row = $this->db->queryOne(
                'SELECT id FROM settings WHERE tenant_id = ? AND deleted_at IS NULL LIMIT 1',
                [$tenantId]
            );
            return $row === null ? ['create', null] : ['conflict', (string) $row['id']];
        }
        if ($entity === 'customer_transactions') {
            // Source sequence numbers are not authoritative in an already-live
            // ledger. Apply will allocate a new server sequence. Never guess
            // duplicate money from amount/date alone: two equal receipts can be real.
            return ['create', null];
        }

        $table = self::TABLES[$entity] ?? null;
        if ($table === null) {
            return ['invalid', null];
        }
        $legacyId = $record['id'] ?? '';
        if (is_string($legacyId) && $legacyId !== '') {
            $sameId = $this->db->queryOne(
                'SELECT * FROM ' . $table
                . ' WHERE tenant_id = ? AND legacy_id = ? '
                . 'AND deleted_at IS NULL LIMIT 1',
                [$tenantId, $legacyId]
            );
            if ($sameId !== null) {
                return $this->sameBusiness($entity, $record, $sameId)
                    ? ['skip', (string) $sameId['id']]
                    : ['conflict', (string) $sameId['id']];
            }
        }

        $candidates = $this->naturalCandidates($tenantId, $entity, $record);
        if (count($candidates) === 0) {
            return ['create', null];
        }
        if (count($candidates) > 1) {
            return ['conflict', null];
        }
        $candidate = $candidates[0];
        return $this->sameBusiness($entity, $record, $candidate)
            ? ['skip', (string) $candidate['id']]
            : ['conflict', (string) $candidate['id']];
    }

    /** @param array<string,mixed> $record @return list<array<string,mixed>> */
    private function naturalCandidates(string $tenantId, string $entity,
                                       array $record): array
    {
        if ($entity === 'customers') {
            $mobile = $record['mobile'] ?? '';
            if (!is_string($mobile) || $mobile === '') {
                return [];
            }
            return $this->db->query(
                'SELECT * FROM customers WHERE tenant_id = ? AND mobile = ? '
                . 'AND deleted_at IS NULL LIMIT 3', [$tenantId, $mobile]
            );
        }
        if ($entity === 'owners' || $entity === 'identities') {
            $national = $record['national'] ?? '';
            if (!is_string($national) || $national === '') {
                return [];
            }
            $table = self::TABLES[$entity];
            return $this->db->query(
                'SELECT * FROM ' . $table . ' WHERE tenant_id = ? AND national = ? '
                . 'AND deleted_at IS NULL LIMIT 3', [$tenantId, $national]
            );
        }
        if ($entity === 'crm_devices') {
            $serial = $record['serial1'] ?? '';
            if (!is_string($serial) || $serial === '') {
                return [];
            }
            return $this->db->query(
                'SELECT * FROM crm_devices WHERE tenant_id = ? AND serial1 = ? '
                . 'AND deleted_at IS NULL LIMIT 3', [$tenantId, $serial]
            );
        }
        if ($entity === 'periods') {
            $number = $record['number'] ?? null;
            if (!is_int($number)) {
                return [];
            }
            return $this->db->query(
                'SELECT * FROM periods WHERE tenant_id = ? AND number = ? '
                . 'AND deleted_at IS NULL LIMIT 3', [$tenantId, $number]
            );
        }
        return [];
    }

    /** @param array<string,mixed> $record @param array<string,mixed> $live */
    private function sameBusiness(string $entity, array $record, array $live): bool
    {
        $fields = match ($entity) {
            'customers' => ['full_name','address','mobile','telegram_id','instagram_id','notes'],
            'owners' => ['first_name','last_name','national','birth','mobile','card_no','passport'],
            'identities' => ['label','national','birth','mobile'],
            'crm_devices' => ['name','serial1','serial2','stage','notes'],
            'periods' => ['number','label','opened_by','closed_by','closed_reason'],
            default => [],
        };
        if ($fields === []) {
            return false;
        }
        foreach ($fields as $field) {
            $a = $record[$field] ?? null;
            $b = $live[$field] ?? null;
            if (is_bool($a)) {
                $a = $a ? 1 : 0;
            }
            if (is_int($a)) {
                $b = (int) $b;
            } elseif ($a !== null) {
                $b = (string) ($b ?? '');
            }
            if ($a !== $b) {
                return false;
            }
        }
        return true;
    }

    /** @param list<array<string,mixed>> $rows @return array<string,int> */
    private function counts(array $rows): array
    {
        $out = [
            'pending' => 0, 'create' => 0, 'merge' => 0, 'skip' => 0,
            'conflict' => 0, 'invalid' => 0,
        ];
        foreach ($rows as $row) {
            $action = (string) ($row['action'] ?? 'pending');
            if (isset($out[$action])) {
                $out[$action]++;
            }
        }
        return $out;
    }

    private function canonical(mixed $value): string
    {
        $sort = static function (mixed $node) use (&$sort): mixed {
            if (!is_array($node)) {
                return $node;
            }
            if (array_is_list($node)) {
                return array_map($sort, $node);
            }
            ksort($node);
            foreach ($node as $key => $item) {
                $node[$key] = $sort($item);
            }
            return $node;
        };
        $encoded = json_encode($sort($value),
            JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if (!is_string($encoded)) {
            throw new ApiException(400, Codes::VALIDATION_FAILED,
                'legacy data cannot be encoded safely');
        }
        return $encoded;
    }
}

/** Internal control flow for two identical uploads racing each other. */
final class LegacyImportDuplicate extends RuntimeException
{
    public function __construct(public readonly string $jobId)
    {
        parent::__construct('duplicate legacy import job');
    }
}
