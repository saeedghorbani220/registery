<?php
/**
 * LegacyVerify.php — PII-free reconciliation for an applied legacy migration.
 *
 * The apply transaction persists aggregate before/after snapshots. This class
 * compares those immutable snapshots with reviewed staging decisions and also
 * checks every accepted staged target against the current live row. Responses
 * contain counts, amounts, stage histograms and issue codes only — never names,
 * phone numbers, national ids, addresses, notes or raw staged JSON.
 */

declare(strict_types=1);

final class LegacyVerify
{
    private const ENTITIES = [
        'customers', 'owners', 'identities', 'crm_devices',
        'periods', 'customer_transactions', 'settings',
    ];

    /** @param array<string,mixed> $cfg */
    public function __construct(
        private readonly Database $db,
        private readonly Log $log,
        private readonly array $cfg
    ) {
    }

    /** @return array<string,mixed> */
    public static function captureSnapshot(Database $db, string $tenantId): array
    {
        $counts = [];
        foreach (self::ENTITIES as $entity) {
            $table = Schema::tableForEntity($entity);
            if ($table === null) {
                throw new RuntimeException('verification entity has no table');
            }
            $counts[$entity] = (int) ($db->queryValue(
                'SELECT COUNT(*) FROM ' . $db->table($table)
                . ' WHERE tenant_id=? AND deleted_at IS NULL',
                [$tenantId]
            ) ?? 0);
        }

        $ledger = $db->queryOne(
            'SELECT COUNT(*) AS row_count,COALESCE(SUM(amount),0) AS gross_amount,'
            . 'COALESCE(SUM(CASE WHEN voided_at IS NULL THEN amount ELSE 0 END),0) '
            . 'AS effective_amount,COALESCE(SUM(CASE WHEN voided_at IS NOT NULL '
            . 'THEN 1 ELSE 0 END),0) AS voided_count FROM customer_transactions '
            . 'WHERE tenant_id=? AND deleted_at IS NULL',
            [$tenantId]
        ) ?? [];

        $stages = [];
        foreach ($db->query(
            'SELECT stage,COUNT(*) AS n FROM crm_devices '
            . 'WHERE tenant_id=? AND deleted_at IS NULL GROUP BY stage ORDER BY stage',
            [$tenantId]
        ) as $row) {
            $stages[(string) $row['stage']] = (int) $row['n'];
        }

        $links = $db->queryOne(
            'SELECT '
            . 'COALESCE(SUM(CASE WHEN d.customer_id IS NOT NULL THEN 1 ELSE 0 END),0) AS device_customer_links,'
            . 'COALESCE(SUM(CASE WHEN d.owner_id IS NOT NULL THEN 1 ELSE 0 END),0) AS device_owner_links,'
            . 'COALESCE(SUM(CASE WHEN d.period_id IS NOT NULL THEN 1 ELSE 0 END),0) AS device_period_links,'
            . 'COALESCE(SUM(CASE WHEN d.customer_id IS NOT NULL AND (c.id IS NULL OR c.deleted_at IS NOT NULL) THEN 1 ELSE 0 END),0) AS invalid_customer_links,'
            . 'COALESCE(SUM(CASE WHEN d.owner_id IS NOT NULL AND (o.id IS NULL OR o.deleted_at IS NOT NULL) THEN 1 ELSE 0 END),0) AS invalid_owner_links,'
            . 'COALESCE(SUM(CASE WHEN d.period_id IS NOT NULL AND (p.id IS NULL OR p.deleted_at IS NOT NULL) THEN 1 ELSE 0 END),0) AS invalid_period_links '
            . 'FROM crm_devices d LEFT JOIN customers c ON c.id=d.customer_id AND c.tenant_id=d.tenant_id '
            . 'LEFT JOIN owners o ON o.id=d.owner_id AND o.tenant_id=d.tenant_id '
            . 'LEFT JOIN periods p ON p.id=d.period_id AND p.tenant_id=d.tenant_id '
            . 'WHERE d.tenant_id=? AND d.deleted_at IS NULL',
            [$tenantId]
        ) ?? [];
        $invalidTxCustomer = (int) ($db->queryValue(
            'SELECT COUNT(*) FROM customer_transactions t LEFT JOIN customers c '
            . 'ON c.id=t.customer_id AND c.tenant_id=t.tenant_id '
            . 'WHERE t.tenant_id=? AND t.deleted_at IS NULL '
            . 'AND (c.id IS NULL OR c.deleted_at IS NOT NULL)',
            [$tenantId]
        ) ?? 0);

        return [
            'counts' => $counts,
            'ledger' => [
                'row_count' => (int) ($ledger['row_count'] ?? 0),
                'gross_amount' => (int) ($ledger['gross_amount'] ?? 0),
                'effective_amount' => (int) ($ledger['effective_amount'] ?? 0),
                'voided_count' => (int) ($ledger['voided_count'] ?? 0),
            ],
            'stages' => $stages,
            'links' => [
                'device_customer_links' => (int) ($links['device_customer_links'] ?? 0),
                'device_owner_links' => (int) ($links['device_owner_links'] ?? 0),
                'device_period_links' => (int) ($links['device_period_links'] ?? 0),
                'invalid_customer_links' => (int) ($links['invalid_customer_links'] ?? 0),
                'invalid_owner_links' => (int) ($links['invalid_owner_links'] ?? 0),
                'invalid_period_links' => (int) ($links['invalid_period_links'] ?? 0),
                'invalid_transaction_customer_links' => $invalidTxCustomer,
            ],
        ];
    }

    /** @param array<string,mixed> $before @param array<string,mixed> $after */
    public static function storeSnapshots(Database $db, string $tenantId,
                                          string $jobId, array $before,
                                          array $after, string $capturedAt): void
    {
        $beforeJson = json_encode($before, JSON_UNESCAPED_SLASHES);
        $afterJson = json_encode($after, JSON_UNESCAPED_SLASHES);
        if (!is_string($beforeJson) || !is_string($afterJson)) {
            throw new RuntimeException('verification snapshot could not be encoded');
        }
        $db->execute(
            'INSERT INTO legacy_import_verifications '
            . '(job_id,tenant_id,before_json,after_json,captured_at) '
            . 'VALUES (?,?,?,?,?)',
            [$jobId, $tenantId, $beforeJson, $afterJson, $capturedAt]
        );
    }

    /** @return array<string,mixed> */
    public function report(Principal $user, string $jobId): array
    {
        $this->requireAdmin($user);
        if (!Ids::isUuid($jobId)) {
            throw new ApiException(400, Codes::BAD_PAYLOAD, 'job_id must be a UUID');
        }
        $job = $this->db->queryOne(
            'SELECT id,status,applied_at FROM legacy_import_jobs '
            . 'WHERE id=? AND tenant_id=?', [$jobId, $user->tenantId]
        );
        if ($job === null) {
            throw new ApiException(404, Codes::NOT_FOUND,
                'legacy import job was not found');
        }
        if ((string) $job['status'] !== 'applied') {
            throw new ApiException(409, Codes::VERSION_CONFLICT,
                'verification requires an applied migration job');
        }
        $saved = $this->db->queryOne(
            'SELECT before_json,after_json,captured_at FROM legacy_import_verifications '
            . 'WHERE job_id=? AND tenant_id=?', [$jobId, $user->tenantId]
        );
        if ($saved === null) {
            throw new ApiException(409, Codes::VALIDATION_FAILED,
                'migration has no transactional verification snapshot');
        }
        $before = json_decode((string) $saved['before_json'], true);
        $after = json_decode((string) $saved['after_json'], true);
        if (!is_array($before) || !is_array($after)) {
            throw new ApiException(500, Codes::SERVER_ERROR,
                'verification snapshot is not valid JSON');
        }

        $rows = $this->db->query(
            'SELECT r.entity,r.source_key,r.action,r.target_id,r.record_json,'
            . 'd.resolution,d.target_id AS decision_target_id '
            . 'FROM legacy_import_records r LEFT JOIN legacy_import_decisions d '
            . 'ON d.job_id=r.job_id AND d.record_id=r.id '
            . 'WHERE r.job_id=? AND r.tenant_id=?', [$jobId, $user->tenantId]
        );

        $sourceMap = [];
        $effectiveRows = [];
        $actions = [];
        $created = array_fill_keys(self::ENTITIES, 0);
        $expectedStages = [];
        $financial = [
            'source_amount' => 0,
            'rejected_amount' => 0,
            'created_gross_amount' => 0,
            'created_effective_amount' => 0,
            'mapped_live_amount' => 0,
            'duplicate_target_amount' => 0,
        ];
        foreach ($rows as $row) {
            $entity = (string) $row['entity'];
            $detected = (string) $row['action'];
            $resolution = $row['resolution'] === null
                ? $detected : (string) $row['resolution'];
            $target = $row['decision_target_id'] !== null
                ? (string) $row['decision_target_id']
                : ($row['target_id'] === null ? null : (string) $row['target_id']);
            $record = json_decode((string) $row['record_json'], true);
            if (!is_array($record)) {
                $record = [];
            }
            $actions[$entity][$resolution] = ($actions[$entity][$resolution] ?? 0) + 1;
            if ($entity === 'customer_transactions') {
                $amount = (int) ($record['amount'] ?? 0);
                $financial['source_amount'] += $amount;
                if ($resolution === 'reject') {
                    $financial['rejected_amount'] += $amount;
                } elseif ($resolution === 'create') {
                    $financial['created_gross_amount'] += $amount;
                    if (($record['voided_at'] ?? null) === null) {
                        $financial['created_effective_amount'] += $amount;
                    }
                }
            }
            if ($resolution === 'reject') {
                continue;
            }
            if ($resolution === 'create' && isset($created[$entity])) {
                $created[$entity]++;
                if ($entity === 'crm_devices') {
                    $stage = (string) ($record['stage'] ?? 'new');
                    $expectedStages[$stage] = ($expectedStages[$stage] ?? 0) + 1;
                }
            }
            if (is_string($target) && Ids::isUuid($target)
                && $entity !== 'customer_transactions' && $entity !== 'settings') {
                $sourceMap[$entity . '/' . (string) $row['source_key']] = $target;
            }
            $effectiveRows[] = [
                'entity' => $entity,
                'source_key' => (string) $row['source_key'],
                'resolution' => $resolution,
                'target_id' => $target,
                'record' => $record,
            ];
        }

        $issues = [];
        $issueCounts = [];
        $targetSeen = [];
        $checked = 0;
        $matched = 0;
        foreach ($effectiveRows as $row) {
            $entity = $row['entity'];
            $target = $row['target_id'];
            if (!is_string($target) || !Ids::isUuid($target)) {
                $this->issue($issues, $issueCounts, 'MISSING_TARGET', $entity);
                continue;
            }
            $live = $this->liveRow($user->tenantId, $entity, $target);
            $checked++;
            if ($live === null) {
                $this->issue($issues, $issueCounts, 'TARGET_NOT_LIVE', $entity);
                continue;
            }
            $rowOk = true;
            if ($entity === 'customer_transactions') {
                $expectedAmount = (int) ($row['record']['amount'] ?? 0);
                if ((int) $live['amount'] !== $expectedAmount) {
                    $this->issue($issues, $issueCounts, 'TRANSACTION_AMOUNT_MISMATCH', $entity);
                    $rowOk = false;
                }
                $sourceCustomer = (string) ($row['record']['customer_id'] ?? '');
                $expectedCustomer = $sourceMap['customers/' . $sourceCustomer] ?? null;
                if (!is_string($expectedCustomer) || $expectedCustomer !== (string) $live['customer_id']) {
                    $this->issue($issues, $issueCounts, 'TRANSACTION_CUSTOMER_MISMATCH', $entity);
                    $rowOk = false;
                }
                $sourceVoided = ($row['record']['voided_at'] ?? null) !== null;
                $liveVoided = $live['voided_at'] !== null;
                if ($sourceVoided !== $liveVoided) {
                    $this->issue($issues, $issueCounts, 'TRANSACTION_VOID_MISMATCH', $entity);
                    $rowOk = false;
                }
                if (isset($targetSeen[$entity][$target])) {
                    $financial['duplicate_target_amount'] += $expectedAmount;
                } else {
                    $financial['mapped_live_amount'] += (int) $live['amount'];
                }
            } elseif ($entity === 'crm_devices') {
                if ((string) $live['stage'] !== (string) ($row['record']['stage'] ?? 'new')) {
                    $this->issue($issues, $issueCounts, 'DEVICE_STAGE_MISMATCH', $entity);
                    $rowOk = false;
                }
                foreach ([
                    'customer_id' => 'customers',
                    'owner_id' => 'owners',
                    'period_id' => 'periods',
                ] as $field => $parentEntity) {
                    $sourceParent = (string) ($row['record'][$field] ?? '');
                    $expectedParent = $sourceParent === '' ? null
                        : ($sourceMap[$parentEntity . '/' . $sourceParent] ?? null);
                    $actualParent = $live[$field] === null ? null : (string) $live[$field];
                    if ($expectedParent !== $actualParent) {
                        $this->issue($issues, $issueCounts, 'DEVICE_LINK_MISMATCH', $entity);
                        $rowOk = false;
                    }
                }
            }
            if (isset($targetSeen[$entity][$target])) {
                $this->issue($issues, $issueCounts, 'DUPLICATE_TARGET_MAPPING', $entity);
            }
            $targetSeen[$entity][$target] = true;
            if ($rowOk) {
                $matched++;
            }
        }

        $countChecks = [];
        foreach (self::ENTITIES as $entity) {
            $beforeCount = (int) ($before['counts'][$entity] ?? 0);
            $afterCount = (int) ($after['counts'][$entity] ?? 0);
            $delta = $afterCount - $beforeCount;
            $expected = (int) ($created[$entity] ?? 0);
            $countChecks[$entity] = [
                'before' => $beforeCount,
                'created' => $expected,
                'after' => $afterCount,
                'delta_matches' => $delta === $expected,
            ];
            if ($delta !== $expected) {
                $this->issue($issues, $issueCounts, 'COUNT_DELTA_MISMATCH', $entity);
            }
        }

        $grossDelta = (int) ($after['ledger']['gross_amount'] ?? 0)
            - (int) ($before['ledger']['gross_amount'] ?? 0);
        $effectiveDelta = (int) ($after['ledger']['effective_amount'] ?? 0)
            - (int) ($before['ledger']['effective_amount'] ?? 0);
        $financial['gross_delta'] = $grossDelta;
        $financial['effective_delta'] = $effectiveDelta;
        $financial['gross_delta_matches'] = $grossDelta === $financial['created_gross_amount'];
        $financial['effective_delta_matches'] = $effectiveDelta === $financial['created_effective_amount'];
        $financial['source_after_review_amount'] =
            $financial['source_amount'] - $financial['rejected_amount'];
        $financial['represented_amount'] =
            $financial['mapped_live_amount'] + $financial['duplicate_target_amount'];
        if (!$financial['gross_delta_matches'] || !$financial['effective_delta_matches']) {
            $this->issue($issues, $issueCounts, 'LEDGER_DELTA_MISMATCH', 'customer_transactions');
        }

        $stageChecks = [];
        $allStages = array_unique(array_merge(
            array_keys($before['stages'] ?? []),
            array_keys($after['stages'] ?? []),
            array_keys($expectedStages)
        ));
        sort($allStages);
        foreach ($allStages as $stage) {
            $b = (int) ($before['stages'][$stage] ?? 0);
            $a = (int) ($after['stages'][$stage] ?? 0);
            $expected = (int) ($expectedStages[$stage] ?? 0);
            $ok = ($a - $b) === $expected;
            $stageChecks[$stage] = ['before'=>$b,'created'=>$expected,'after'=>$a,'delta_matches'=>$ok];
            if (!$ok) {
                $this->issue($issues, $issueCounts, 'STAGE_DELTA_MISMATCH', 'crm_devices');
            }
        }

        $invalidBefore = $this->invalidLinkTotal($before['links'] ?? []);
        $invalidAfter = $this->invalidLinkTotal($after['links'] ?? []);
        $links = [
            'before' => $before['links'] ?? [],
            'after' => $after['links'] ?? [],
            'invalid_before' => $invalidBefore,
            'invalid_after' => $invalidAfter,
            'no_new_invalid_links' => $invalidAfter <= $invalidBefore,
        ];
        if (!$links['no_new_invalid_links']) {
            $this->issue($issues, $issueCounts, 'INVALID_LINKS_INCREASED', 'crm_devices');
        }

        return [
            'job_id' => $jobId,
            'status' => 'applied',
            'captured_at' => Schema::toWireTimestamp((string) $saved['captured_at']),
            'passed' => count($issues) === 0,
            'actions' => $actions,
            'counts' => $countChecks,
            'financial' => $financial,
            'stages' => $stageChecks,
            'links' => $links,
            'row_checks' => [
                'checked' => $checked,
                'matched' => $matched,
                'mismatched' => max(0, $checked - $matched),
            ],
            'issues' => $issueCounts,
        ];
    }

    /** @return array<string,mixed>|null */
    private function liveRow(string $tenantId, string $entity, string $targetId): ?array
    {
        $table = Schema::tableForEntity($entity);
        if ($table === null) {
            return null;
        }
        $fields = 'id';
        if ($entity === 'customer_transactions') {
            $fields = 'id,customer_id,amount,voided_at';
        } elseif ($entity === 'crm_devices') {
            $fields = 'id,customer_id,owner_id,period_id,stage';
        }
        return $this->db->queryOne(
            'SELECT ' . $fields . ' FROM ' . $this->db->table($table)
            . ' WHERE id=? AND tenant_id=? AND deleted_at IS NULL',
            [$targetId, $tenantId]
        );
    }

    /** @param array<string,int> $counts @param list<string> $issues */
    private function issue(array &$issues, array &$counts, string $code,
                           string $entity): void
    {
        $key = $code . ':' . $entity;
        if (!isset($counts[$key])) {
            $counts[$key] = 0;
        }
        $counts[$key]++;
        $issues[] = $key;
    }

    /** @param array<string,mixed> $links */
    private function invalidLinkTotal(array $links): int
    {
        return (int) ($links['invalid_customer_links'] ?? 0)
            + (int) ($links['invalid_owner_links'] ?? 0)
            + (int) ($links['invalid_period_links'] ?? 0)
            + (int) ($links['invalid_transaction_customer_links'] ?? 0);
    }

    private function requireAdmin(Principal $user): void
    {
        if (!$user->isUser()) {
            throw new ApiException(401, Codes::AUTH_REQUIRED,
                'legacy migration verification requires a user session');
        }
        Roles::requireImport($user->role);
    }
}
