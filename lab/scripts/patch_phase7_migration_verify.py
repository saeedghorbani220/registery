#!/usr/bin/env python3
"""One-shot Phase 7 patch: persist PII-free migration snapshots and verify reconciliation."""
from __future__ import annotations

import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[2]

MIGRATION = r'''-- ===========================================================================
-- 004_legacy_import_verification.sql
--
-- Persist PII-free before/after summaries for one reviewed legacy migration.
-- The raw source and row-level customer data stay in the existing staging
-- tables; this table stores only aggregate counts, sums, stages and link-health
-- metrics captured inside the same transaction as apply.
-- ===========================================================================

SET NAMES utf8mb4;
SET time_zone = '+00:00';

CREATE TABLE legacy_import_verifications (
  job_id       CHAR(36)    NOT NULL,
  tenant_id    CHAR(36)    NOT NULL,
  before_json  MEDIUMTEXT  NOT NULL,
  after_json   MEDIUMTEXT  NOT NULL,
  captured_at  DATETIME    NOT NULL,
  PRIMARY KEY (job_id),
  KEY ix_legacy_verify_tenant (tenant_id, captured_at),
  CONSTRAINT fk_legacy_verify_job
    FOREIGN KEY (job_id) REFERENCES legacy_import_jobs (id),
  CONSTRAINT fk_legacy_verify_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
  CHECK (json_valid(before_json)),
  CHECK (json_valid(after_json))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
'''

VERIFY = r'''<?php
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
'''


def write_new(path: str, content: str) -> None:
    target = ROOT / path
    if target.exists():
        raise RuntimeError(f"refusing to overwrite {path}")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8", newline="\n")


def replace_once(path: str, old: str, new: str, label: str) -> None:
    target = ROOT / path
    text = target.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one match, found {count}")
    target.write_text(text.replace(old, new, 1), encoding="utf-8", newline="\n")


def patch_apply() -> None:
    path = "host/src/LegacyApply.php"
    replace_once(path,
'''            $tx->execute(
                'UPDATE legacy_import_jobs SET status=?,updated_at=? '
                . 'WHERE id=? AND tenant_id=?',
                ['applying', gmdate('Y-m-d H:i:s'), $jobId, $user->tenantId]
            );

            $staged = $tx->query(
''',
'''            $tx->execute(
                'UPDATE legacy_import_jobs SET status=?,updated_at=? '
                . 'WHERE id=? AND tenant_id=?',
                ['applying', gmdate('Y-m-d H:i:s'), $jobId, $user->tenantId]
            );
            $verificationBefore = LegacyVerify::captureSnapshot($tx, $user->tenantId);

            $staged = $tx->query(
''', "capture before")
    replace_once(path,
'''            $cursor = $tx->queryValue(
                'SELECT MAX(seq) FROM change_log WHERE tenant_id=?',
                [$user->tenantId]
            );
            $tx->execute(
''',
'''            $verificationAfter = LegacyVerify::captureSnapshot($tx, $user->tenantId);
            LegacyVerify::storeSnapshots(
                $tx, $user->tenantId, $jobId,
                $verificationBefore, $verificationAfter, $now
            );
            $cursor = $tx->queryValue(
                'SELECT MAX(seq) FROM change_log WHERE tenant_id=?',
                [$user->tenantId]
            );
            $tx->execute(
''', "capture after")


def patch_index() -> None:
    path = "host/public/index.php"
    replace_once(path,
"""    'LegacyImport', 'LegacyApply',
""",
"""    'LegacyImport', 'LegacyVerify', 'LegacyApply',
""", "include verify")
    replace_once(path,
"""        '/legacy-import/apply' => ['POST'],
        '/bootstrap/import' => ['POST'],
""",
"""        '/legacy-import/apply' => ['POST'],
        '/legacy-import/verify' => ['GET'],
        '/bootstrap/import' => ['POST'],
""", "verify route table")
    replace_once(path,
"""    $legacyImport = new LegacyImport($db, $sync, $log, $config);
    $legacyApply = new LegacyApply($db, $sync, $log, $config);
    $ip = $request->remoteAddr;
""",
"""    $legacyImport = new LegacyImport($db, $sync, $log, $config);
    $legacyVerify = new LegacyVerify($db, $log, $config);
    $legacyApply = new LegacyApply($db, $sync, $log, $config);
    $ip = $request->remoteAddr;
""", "verify service")
    replace_once(path,
"""        case '/bootstrap/import':
""",
"""        case '/legacy-import/verify':
            $user = requireUser($auth, $request);
            requireLegacyImportEnabled($config);
            $jobId = stringQuery($request, 'job_id');
            $payload = $legacyVerify->report($user, $jobId);
            $statusCode = 200;
            $errorCode = '';
            Response::ok($payload);
            break;

        case '/bootstrap/import':
""", "verify switch")


def patch_test() -> None:
    path = "lab/tests/test_server_crm_v2_legacy_apply.py"
    replace_once(path,
'''    "003_server_crm_v2_device_auth.sql",
)
''',
'''    "003_server_crm_v2_device_auth.sql",
    "004_legacy_import_verification.sql",
)
''', "test migration")
    replace_once(path,
'''        required = ("Schema", "Database", "Http", "Ids", "Log", "Tokens", "Roles", "RateLimit", "Auth", "Sync", "LegacyImport", "LegacyApply")
''',
'''        required = ("Schema", "Database", "Http", "Ids", "Log", "Tokens", "Roles", "RateLimit", "Auth", "Sync", "LegacyImport", "LegacyVerify", "LegacyApply")
''', "test requires")
    replace_once(path,
'''            "$import=new LegacyImport($db,$sync,$log,['limits'=>['max_import_body_bytes'=>16777216]]); $apply=new LegacyApply($db,$sync,$log,[]);",
''',
'''            "$import=new LegacyImport($db,$sync,$log,['limits'=>['max_import_body_bytes'=>16777216]]); $verify=new LegacyVerify($db,$log,[]); $apply=new LegacyApply($db,$sync,$log,[]);",
''', "test service")
    replace_once(path,
'''            "$action=$argv[1]; try { if($action==='analyze'){$body=['source_text'=>file_get_contents($argv[2]),'filename'=>basename($argv[2]),'source_version'=>'1.13.1'];$r=$import->analyze($p,$body,Ids::v4(),'127.0.0.1');} elseif($action==='apply'){$r=$apply->apply($p,$argv[2],Ids::v4(),'127.0.0.1');} elseif($action==='decide'){$body=['job_id'=>$argv[2],'record_id'=>$argv[3],'resolution'=>$argv[4]];if(isset($argv[5])&&$argv[5]!==''){$body['target_id']=$argv[5];}$r=$apply->decide($p,$body,Ids::v4(),'127.0.0.1');} elseif($action==='review'){$r=$apply->review($p,$argv[2]);} else {throw new RuntimeException('bad action');} echo json_encode(['ok'=>true,'result'=>$r],JSON_UNESCAPED_UNICODE); } catch(ApiException $e){echo json_encode(['ok'=>false,'status'=>$e->status,'code'=>$e->errorCode]);exit(2);} catch(Throwable $e){echo json_encode(['ok'=>false,'status'=>500,'code'=>'SERVER_ERROR']);exit(3);}",
''',
'''            "$action=$argv[1]; try { if($action==='analyze'){$body=['source_text'=>file_get_contents($argv[2]),'filename'=>basename($argv[2]),'source_version'=>'1.13.1'];$r=$import->analyze($p,$body,Ids::v4(),'127.0.0.1');} elseif($action==='apply'){$r=$apply->apply($p,$argv[2],Ids::v4(),'127.0.0.1');} elseif($action==='verify'){$r=$verify->report($p,$argv[2]);} elseif($action==='decide'){$body=['job_id'=>$argv[2],'record_id'=>$argv[3],'resolution'=>$argv[4]];if(isset($argv[5])&&$argv[5]!==''){$body['target_id']=$argv[5];}$r=$apply->decide($p,$body,Ids::v4(),'127.0.0.1');} elseif($action==='review'){$r=$apply->review($p,$argv[2]);} else {throw new RuntimeException('bad action');} echo json_encode(['ok'=>true,'result'=>$r],JSON_UNESCAPED_UNICODE); } catch(ApiException $e){echo json_encode(['ok'=>false,'status'=>$e->status,'code'=>$e->errorCode]);exit(2);} catch(Throwable $e){echo json_encode(['ok'=>false,'status'=>500,'code'=>'SERVER_ERROR']);exit(3);}",
''', "test verify action")
    replace_once(path,
'''        self._sql("DELETE FROM legacy_import_decisions; DELETE FROM legacy_import_records; DELETE FROM legacy_import_jobs; DELETE FROM audit_events WHERE action LIKE 'legacy_import.%';")
''',
'''        self._sql("DELETE FROM legacy_import_verifications; DELETE FROM legacy_import_decisions; DELETE FROM legacy_import_records; DELETE FROM legacy_import_jobs; DELETE FROM audit_events WHERE action LIKE 'legacy_import.%';")
''', "test cleanup")
    replace_once(path,
'''        self.assertEqual(self.scalar("SELECT status FROM legacy_import_jobs WHERE id='%s';" % job), "applied")

        code, replay = self._call("apply", job)
''',
'''        self.assertEqual(self.scalar("SELECT status FROM legacy_import_jobs WHERE id='%s';" % job), "applied")
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM legacy_import_verifications WHERE job_id='%s';" % job), "1")
        code, verified = self._call("verify", job)
        self.assertEqual(code, 0, verified)
        report = verified["result"]
        self.assertTrue(report["passed"], report)
        self.assertEqual(report["counts"]["customers"], {"before": 0, "created": 1, "after": 1, "delta_matches": True})
        self.assertEqual(report["counts"]["customer_transactions"], {"before": 0, "created": 1, "after": 1, "delta_matches": True})
        self.assertEqual(report["financial"]["created_gross_amount"], 1200)
        self.assertEqual(report["financial"]["gross_delta"], 1200)
        self.assertTrue(report["financial"]["gross_delta_matches"])
        self.assertEqual(report["row_checks"]["mismatched"], 0)

        code, replay = self._call("apply", job)
''', "verification assertions")
    replace_once(path,
'''    def test_existing_customer_mapping_allocates_next_server_ledger_sequence(self):
''',
'''    def test_verification_detects_live_financial_tampering_without_exposing_pii(self):
        staged = self._analyze(self.store())
        job = staged["job"]["id"]
        code, applied = self._call("apply", job)
        self.assertEqual(code, 0, applied)
        self._sql("UPDATE customer_transactions SET amount=999 WHERE tenant_id='%s';" % self.tenant)
        code, verified = self._call("verify", job)
        self.assertEqual(code, 0, verified)
        report = verified["result"]
        self.assertFalse(report["passed"])
        self.assertEqual(report["issues"].get("TRANSACTION_AMOUNT_MISMATCH:customer_transactions"), 1)
        serialized = json.dumps(report, ensure_ascii=False)
        for pii in ("Legacy Customer", "09120000001", "Old address", "receipt"):
            self.assertNotIn(pii, serialized)

    def test_existing_customer_mapping_allocates_next_server_ledger_sequence(self):
''', "tamper test")


def main() -> None:
    write_new("host/migrations/004_legacy_import_verification.sql", MIGRATION)
    write_new("host/src/LegacyVerify.php", VERIFY)
    patch_apply()
    patch_index()
    patch_test()
    print("phase7 migration verification patch applied")


if __name__ == "__main__":
    main()
