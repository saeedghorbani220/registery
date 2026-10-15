#!/usr/bin/env python3
"""One-shot Phase 8 patch: complete backup dump + real restore verification."""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BACKUP = ROOT / "host" / "bin" / "backup-to-telegram.php"
TEST = ROOT / "lab" / "tests" / "test_server_crm_v2_backup_restore.py"

HELPER = r'''
/**
 * Build the exact SQL/gzip payload used by production backup delivery.
 *
 * Tables and triggers are discovered from the live database rather than from
 * Schema::tables(): forward migrations add operational tables and triggers
 * that are intentionally outside the synced-entity allowlist.
 *
 * @return array<string, mixed>
 */
function build_database_backup_dump(Database $db, string $dbName): array
{
    $pdo = $db->pdo();
    $nowUtc = gmdate('Y-m-d H:i:s');
    $dateSlug = gmdate('Ymd_His');

    $tableStmt = $pdo->query(
        "SELECT TABLE_NAME FROM information_schema.TABLES "
        . "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_TYPE = 'BASE TABLE' "
        . "ORDER BY TABLE_NAME"
    );
    $tables = $tableStmt->fetchAll(\PDO::FETCH_COLUMN);
    if (!is_array($tables) || $tables === []) {
        throw new \RuntimeException('No base tables are visible for database backup');
    }

    $sqlParts = [];
    $sqlParts[] = "-- ============================================================";
    $sqlParts[] = "-- IRICA Cloud CRM Database Backup";
    $sqlParts[] = "-- Date (UTC): " . $nowUtc;
    $sqlParts[] = "-- Database: " . $dbName;
    $sqlParts[] = "-- ============================================================";
    $sqlParts[] = "";
    $sqlParts[] = "SET FOREIGN_KEY_CHECKS = 0;";
    $sqlParts[] = "SET SQL_MODE = 'NO_AUTO_VALUE_ON_ZERO';";
    $sqlParts[] = "SET NAMES utf8mb4;";
    $sqlParts[] = "";

    $totalRows = 0;
    $dumpedTables = 0;
    foreach ($tables as $table) {
        if (!is_string($table) || preg_match('/^[A-Za-z0-9_]+$/D', $table) !== 1) {
            throw new \RuntimeException('Unsafe database table identifier in backup');
        }
        $quotedTable = '`' . $table . '`';
        $sqlParts[] = "-- ------------------------------------------------------------";
        $sqlParts[] = "-- Table structure for `{$table}`";
        $sqlParts[] = "-- ------------------------------------------------------------";
        $sqlParts[] = "DROP TABLE IF EXISTS {$quotedTable};";

        $createStmt = $pdo->query("SHOW CREATE TABLE {$quotedTable}");
        $createRow = $createStmt->fetch(\PDO::FETCH_NUM);
        if (!$createRow || !isset($createRow[1]) || !is_string($createRow[1])) {
            throw new \RuntimeException('Unable to read a table definition for backup');
        }
        $sqlParts[] = $createRow[1] . ";";
        $sqlParts[] = "";

        $dataStmt = $pdo->query("SELECT * FROM {$quotedTable}");
        $rows = $dataStmt->fetchAll(\PDO::FETCH_ASSOC);
        $rowCount = count($rows);
        $totalRows += $rowCount;
        $dumpedTables++;
        if ($rowCount === 0) {
            continue;
        }
        $sqlParts[] = "-- Data for table `{$table}` ({$rowCount} rows)";
        $cols = array_keys($rows[0]);
        foreach ($cols as $col) {
            if (!is_string($col) || preg_match('/^[A-Za-z0-9_]+$/D', $col) !== 1) {
                throw new \RuntimeException('Unsafe database column identifier in backup');
            }
        }
        $colsList = implode(', ', array_map(
            static fn (string $col): string => '`' . $col . '`', $cols
        ));
        foreach (array_chunk($rows, 100) as $chunk) {
            $valSets = [];
            foreach ($chunk as $row) {
                $escapedVals = [];
                foreach ($cols as $col) {
                    $val = $row[$col];
                    if ($val === null) {
                        $escapedVals[] = 'NULL';
                    } elseif (is_int($val) || is_float($val)) {
                        $escapedVals[] = (string) $val;
                    } else {
                        $escapedVals[] = $pdo->quote((string) $val);
                    }
                }
                $valSets[] = '(' . implode(', ', $escapedVals) . ')';
            }
            $sqlParts[] = "INSERT INTO {$quotedTable} ({$colsList}) VALUES\n  "
                . implode(",\n  ", $valSets) . ";";
        }
        $sqlParts[] = "";
    }

    $triggerStmt = $pdo->query(
        "SELECT TRIGGER_NAME, EVENT_MANIPULATION, EVENT_OBJECT_TABLE, "
        . "ACTION_TIMING, ACTION_STATEMENT FROM information_schema.TRIGGERS "
        . "WHERE TRIGGER_SCHEMA = DATABASE() ORDER BY TRIGGER_NAME"
    );
    $triggers = $triggerStmt->fetchAll(\PDO::FETCH_ASSOC);
    $dumpedTriggers = 0;
    if ($triggers !== []) {
        $sqlParts[] = "-- ------------------------------------------------------------";
        $sqlParts[] = "-- Triggers";
        $sqlParts[] = "-- ------------------------------------------------------------";
        $sqlParts[] = 'DELIMITER $$';
        foreach ($triggers as $trigger) {
            $name = $trigger['TRIGGER_NAME'] ?? null;
            $event = strtoupper((string) ($trigger['EVENT_MANIPULATION'] ?? ''));
            $table = $trigger['EVENT_OBJECT_TABLE'] ?? null;
            $timing = strtoupper((string) ($trigger['ACTION_TIMING'] ?? ''));
            $statement = $trigger['ACTION_STATEMENT'] ?? null;
            if (!is_string($name) || !is_string($table)
                || preg_match('/^[A-Za-z0-9_]+$/D', $name) !== 1
                || preg_match('/^[A-Za-z0-9_]+$/D', $table) !== 1
                || !in_array($event, ['INSERT', 'UPDATE', 'DELETE'], true)
                || !in_array($timing, ['BEFORE', 'AFTER'], true)
                || !is_string($statement) || trim($statement) === ''
                || str_contains($statement, '$$')) {
                throw new \RuntimeException('Unsafe trigger definition in backup');
            }
            $sqlParts[] = "DROP TRIGGER IF EXISTS `{$name}`$$";
            $sqlParts[] = "CREATE TRIGGER `{$name}` {$timing} {$event} "
                . "ON `{$table}` FOR EACH ROW {$statement}$$";
            $dumpedTriggers++;
        }
        $sqlParts[] = 'DELIMITER ;';
        $sqlParts[] = "";
    }

    $sqlParts[] = "SET FOREIGN_KEY_CHECKS = 1;";
    $sqlParts[] = "-- Backup completed successfully at " . gmdate('Y-m-d H:i:s') . " UTC.";
    $fullSql = implode("\n", $sqlParts);
    $gzippedSql = gzencode($fullSql, 9);
    if ($gzippedSql === false) {
        throw new \RuntimeException('Failed to gzip database dump');
    }
    return [
        'sql' => $fullSql,
        'gzipped_sql' => $gzippedSql,
        'timestamp' => $nowUtc,
        'date_slug' => $dateSlug,
        'tables_dumped' => $dumpedTables,
        'triggers_dumped' => $dumpedTriggers,
        'total_rows' => $totalRows,
        'uncompressed_bytes' => strlen($fullSql),
        'compressed_bytes' => strlen($gzippedSql),
        'sha256' => hash('sha256', $gzippedSql),
    ];
}

'''

CALL_BLOCK = r'''    $dbName = $config['db']['dbname'] ?? 'irica_cloud';
    $dumpDb = $db;
    $migrationConfig = $config['db_migrate'] ?? null;
    if (is_array($migrationConfig) && !empty($migrationConfig['user'])
        && !empty($migrationConfig['password'])) {
        // The normal app account is deliberately DML-only. Trigger metadata
        // may require migration-level metadata privileges, so use the existing
        // privileged connection for the controlled read-only dump when present.
        $dumpDb = Database::fromConfig($migrationConfig);
    }
    $dump = build_database_backup_dump($dumpDb, (string) $dbName);
    $pdo = $db->pdo();
    $nowUtc = (string) $dump['timestamp'];
    $dateSlug = (string) $dump['date_slug'];
    $totalRows = (int) $dump['total_rows'];
    $dumpedTables = (int) $dump['tables_dumped'];
    $dumpedTriggers = (int) $dump['triggers_dumped'];
    $uncompressedBytes = (int) $dump['uncompressed_bytes'];
    $gzippedSql = (string) $dump['gzipped_sql'];
    $compressedBytes = (int) $dump['compressed_bytes'];
    $sha256 = (string) $dump['sha256'];

'''

TEST_CONTENT = r'''# -*- coding: utf-8 -*-
"""Round-trip verification for the production host backup generator."""
import json
import os
import shutil
import subprocess
import tempfile
import unittest
import uuid

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
HOST = os.path.join(ROOT, "host")
MIGRATIONS = [
    os.path.join(HOST, "migrations", name) for name in (
        "001_initial.sql",
        "002_server_crm_v2_foundation.sql",
        "003_server_crm_v2_device_auth.sql",
        "004_legacy_import_verification.sql",
    )
]
BACKUP = os.path.join(HOST, "bin", "backup-to-telegram.php")


class BackupRestoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mysql = os.environ.get("IRICA_MARIADB") or shutil.which("mariadb") or shutil.which("mysql")
        cls.php = os.environ.get("IRICA_PHP") or shutil.which("php")
        cls.password = os.environ.get("IRICA_DB_ROOT_PASSWORD")
        cls.host = os.environ.get("IRICA_DB_HOST", "127.0.0.1")
        cls.port = os.environ.get("IRICA_DB_PORT", "3307")
        if not cls.mysql or not cls.php or not cls.password:
            raise unittest.SkipTest("MariaDB/PHP test service is not configured")
        cls.source = "irica_backup_src_%s" % uuid.uuid4().hex[:10]
        cls.restore = "irica_backup_dst_%s" % uuid.uuid4().hex[:10]
        cls.tenant = str(uuid.uuid4())
        cls.user = str(uuid.uuid4())
        cls.customer = str(uuid.uuid4())
        cls.job = str(uuid.uuid4())
        for db in (cls.source, cls.restore):
            cls._sql("CREATE DATABASE `%s` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;" % db, database=None)
        for migration in MIGRATIONS:
            with open(migration, encoding="utf-8") as handle:
                cls._sql(handle.read(), database=cls.source)
        cls._seed()

    @classmethod
    def tearDownClass(cls):
        if getattr(cls, "mysql", None):
            for db in (getattr(cls, "source", ""), getattr(cls, "restore", "")):
                if db:
                    cls._sql("DROP DATABASE IF EXISTS `%s`;" % db, database=None, check=False)

    @classmethod
    def _command(cls, database=None):
        cmd = [cls.mysql, "-h", cls.host, "-P", str(cls.port), "-u", "root",
               "--protocol=TCP", "--default-character-set=utf8mb4", "--batch", "--skip-column-names"]
        if "mariadb" in os.path.basename(cls.mysql).lower():
            cmd.append("--ssl=FALSE")
        if database:
            cmd.append(database)
        return cmd

    @classmethod
    def _env(cls):
        env = dict(os.environ)
        env["MYSQL_PWD"] = cls.password
        return env

    @classmethod
    def _sql(cls, sql, database=None, check=True):
        run = subprocess.run(cls._command(database), input=sql, capture_output=True,
                             text=True, encoding="utf-8", errors="replace",
                             env=cls._env(), timeout=180)
        if check and run.returncode != 0:
            raise AssertionError("SQL failed (exit %d): %s" % (run.returncode, (run.stderr or "")[:1600]))
        return run.stdout or ""

    @classmethod
    def _scalar(cls, sql, database):
        text = cls._sql(sql, database=database).strip()
        return text.splitlines()[-1] if text else ""

    @classmethod
    def _seed(cls):
        now = "2026-10-15 18:00:00"
        tx = str(uuid.uuid4())
        verification = json.dumps({"counts": {"customers": 1}}, separators=(",", ":"))
        sql = "\n".join([
            "INSERT INTO tenants(id,slug,name,status,created_at,updated_at) VALUES ('%s','backup-test','Backup Test','active','%s','%s');" % (cls.tenant, now, now),
            "INSERT INTO users(id,tenant_id,username,password_hash,display_name,must_change_password,status,token_version,row_version,created_at,updated_at) VALUES ('%s','%s','backup-user','not-a-secret-hash','',0,'active',1,1,'%s','%s');" % (cls.user, cls.tenant, now, now),
            "INSERT INTO customers(id,tenant_id,legacy_id,row_version,created_at,updated_at,full_name,address,mobile,telegram_id,instagram_id,notes) VALUES ('%s','%s','cust-backup',1,'%s','%s','Backup Customer','','','','','');" % (cls.customer, cls.tenant, now, now),
            "INSERT INTO customer_transactions(id,tenant_id,legacy_id,row_version,created_at,updated_at,seq,customer_id,amount,note,kind,image,void_reason) VALUES ('%s','%s','cust-backup/0',1,'%s','%s',0,'%s',4321,'seed','receipt','','');" % (tx, cls.tenant, now, now, cls.customer),
            "INSERT INTO legacy_import_jobs(id,tenant_id,source_sha256,source_version,status,record_count,created_by,created_at,updated_at,error_code) VALUES ('%s','%s','%s','1.13.1','applied',1,'%s','%s','%s','');" % (cls.job, cls.tenant, 'a'*64, cls.user, now, now),
            "INSERT INTO legacy_import_verifications(job_id,tenant_id,before_json,after_json,captured_at) VALUES ('%s','%s','%s','%s','%s');" % (cls.job, cls.tenant, verification.replace("'", "''"), verification.replace("'", "''"), now),
        ])
        cls._sql(sql, database=cls.source)

    def _build_dump(self):
        directory = tempfile.mkdtemp(prefix="irica_backup_probe_")
        self.addCleanup(shutil.rmtree, directory, True)
        out = os.path.join(directory, "backup.sql")
        probe = os.path.join(directory, "probe.php")
        script = """<?php
declare(strict_types=1);
require_once %s;
$cfg=['host'=>getenv('IRICA_DB_HOST'),'port'=>(int)getenv('IRICA_DB_PORT'),
      'dbname'=>getenv('IRICA_BACKUP_SOURCE'),'user'=>'root',
      'password'=>getenv('IRICA_DB_ROOT_PASSWORD')];
$db=Database::fromConfig($cfg);
$dump=build_database_backup_dump($db,getenv('IRICA_BACKUP_SOURCE'));
file_put_contents(getenv('IRICA_BACKUP_SQL'),$dump['sql']);
echo json_encode(['tables'=>$dump['tables_dumped'],'triggers'=>$dump['triggers_dumped'],
                  'rows'=>$dump['total_rows'],'sha256'=>$dump['sha256']]);
""" % json.dumps(BACKUP.replace("\\", "/"))
        with open(probe, "w", encoding="utf-8") as handle:
            handle.write(script)
        env = dict(os.environ)
        env.update({"IRICA_DB_ROOT_PASSWORD": self.password,
                    "IRICA_DB_HOST": self.host, "IRICA_DB_PORT": str(self.port),
                    "IRICA_BACKUP_SOURCE": self.source, "IRICA_BACKUP_SQL": out})
        run = subprocess.run([self.php, probe], capture_output=True, text=True,
                             encoding="utf-8", errors="replace", env=env, timeout=120)
        if run.returncode != 0:
            raise AssertionError("backup generator failed: %s" % (run.stderr or "")[:1600])
        meta = json.loads((run.stdout or "").strip().splitlines()[-1])
        with open(out, encoding="utf-8") as handle:
            return meta, handle.read()

    def test_production_dump_round_trips_all_tables_data_and_trigger(self):
        meta, sql = self._build_dump()
        source_tables = int(self._scalar(
            "SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_TYPE='BASE TABLE';",
            self.source))
        source_triggers = int(self._scalar(
            "SELECT COUNT(*) FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA=DATABASE();",
            self.source))
        self.assertEqual(meta["tables"], source_tables)
        self.assertEqual(meta["triggers"], source_triggers)
        self.assertGreaterEqual(source_tables, 23)
        self.assertEqual(source_triggers, 1)
        self.assertIn("legacy_import_verifications", sql)
        self.assertIn("trg_sync_devices_owner_default", sql)

        self._sql(sql, database=self.restore)
        restored_tables = int(self._scalar(
            "SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_TYPE='BASE TABLE';",
            self.restore))
        restored_triggers = int(self._scalar(
            "SELECT COUNT(*) FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA=DATABASE();",
            self.restore))
        self.assertEqual(restored_tables, source_tables)
        self.assertEqual(restored_triggers, source_triggers)
        self.assertEqual(self._scalar("SELECT COUNT(*) FROM legacy_import_jobs;", self.restore), "1")
        self.assertEqual(self._scalar("SELECT COUNT(*) FROM legacy_import_verifications;", self.restore), "1")
        self.assertEqual(self._scalar("SELECT SUM(amount) FROM customer_transactions;", self.restore), "4321")
        self.assertEqual(self._scalar("SELECT full_name FROM customers WHERE legacy_id='cust-backup';", self.restore), "Backup Customer")

        device = str(uuid.uuid4())
        now = "2026-10-15 19:00:00"
        self._sql(
            "INSERT INTO sync_devices(id,tenant_id,name,status,token_version,created_at,updated_at,enrolled_by,row_version) "
            "VALUES ('%s','%s','restored-device','active',1,'%s','%s','%s',1);" %
            (device, self.tenant, now, now, self.user),
            database=self.restore)
        self.assertEqual(self._scalar(
            "SELECT owner_user_id FROM sync_devices WHERE id='%s';" % device,
            self.restore), self.user)


if __name__ == "__main__":
    unittest.main()
'''


def main() -> None:
    text = BACKUP.read_text(encoding="utf-8")
    if "function build_database_backup_dump" in text:
        raise RuntimeError("backup dump helper already exists")
    marker = "/**\n * Perform full MySQL database dump and deliver via Telegram."
    if text.count(marker) != 1:
        raise RuntimeError("backup helper insertion anchor drifted")
    text = text.replace(marker, HELPER + marker)
    start_marker = "    $pdo = $db->pdo();\n    $nowUtc = gmdate('Y-m-d H:i:s');"
    end_marker = "    // Save temporary file\n"
    start = text.find(start_marker, text.find("function run_database_backup"))
    end = text.find(end_marker, start)
    if start < 0 or end < 0:
        raise RuntimeError("backup generation block anchors drifted")
    text = text[:start] + CALL_BLOCK + text[end:]
    text = text.replace(
        "        'tables_dumped' => $dumpedTables,\n        'total_rows' => $totalRows,",
        "        'tables_dumped' => $dumpedTables,\n        'triggers_dumped' => $dumpedTriggers,\n        'total_rows' => $totalRows,",
        1,
    )
    BACKUP.write_text(text, encoding="utf-8", newline="\n")
    if TEST.exists():
        raise RuntimeError("backup restore test already exists")
    TEST.write_text(TEST_CONTENT, encoding="utf-8", newline="\n")
    print("phase8 backup restore patch applied")


if __name__ == "__main__":
    main()
