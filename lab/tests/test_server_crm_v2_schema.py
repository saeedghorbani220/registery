# -*- coding: utf-8 -*-
"""Server CRM v2 foundation migration tests.

The migration is intentionally additive. These tests protect the rollout
contract before higher-level auth/import APIs start depending on it:

* migration 001 is never rewritten or replaced by the v2 schema;
* migration 002 contains no destructive DROP operations;
* device ownership is explicit and independent from `enrolled_by`;
* edit presence is advisory/expiring rather than a business-row lock;
* legacy import uses job + normalized staging + explicit admin decisions;
* exact source-file re-upload is idempotent per tenant by SHA-256;
* staging JSON validity is enforced by SQL.

When a MariaDB/MySQL test service is available, the module also applies 001 and
002 to a fresh database and verifies the resulting columns/tables/indexes.
No production data or credentials are used.
"""
import os
import re
import shutil
import subprocess
import sys
import unittest
import uuid

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
MIGRATIONS = os.path.join(ROOT, "host", "migrations")
INITIAL = os.path.join(MIGRATIONS, "001_initial.sql")
FOUNDATION = os.path.join(MIGRATIONS, "002_server_crm_v2_foundation.sql")


def read(path):
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


class FoundationStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.initial = read(INITIAL)
        cls.sql = read(FOUNDATION)

    def test_foundation_is_separate_forward_migration(self):
        self.assertTrue(os.path.isfile(INITIAL))
        self.assertTrue(os.path.isfile(FOUNDATION))
        self.assertNotRegex(self.sql, r"(?im)^\s*DROP\s+")
        self.assertNotRegex(self.sql, r"(?im)^\s*TRUNCATE\s+")

    def test_device_owner_is_explicit_and_backfilled(self):
        self.assertIn("ADD COLUMN owner_user_id CHAR(36) NULL", self.sql)
        self.assertIn("FOREIGN KEY (owner_user_id) REFERENCES users (id)", self.sql)
        self.assertRegex(
            self.sql,
            r"UPDATE\s+sync_devices\s+SET\s+owner_user_id\s*=\s*enrolled_by",
        )

    def test_presence_is_advisory_and_expiring(self):
        self.assertIn("CREATE TABLE record_presence", self.sql)
        for column in ("lease_id", "heartbeat_at", "expires_at", "sync_device_id"):
            self.assertIn(column, self.sql)
        self.assertNotIn("locked_at", self.sql.lower())
        self.assertNotIn("lock_owner", self.sql.lower())

    def test_legacy_import_has_staging_and_explicit_decisions(self):
        for table in (
            "legacy_import_jobs", "legacy_import_records", "legacy_import_decisions"
        ):
            self.assertIn("CREATE TABLE " + table, self.sql)
        self.assertIn(
            "UNIQUE KEY uq_legacy_import_source (tenant_id, source_sha256)",
            self.sql,
        )
        self.assertIn("CHECK (json_valid(record_json))", self.sql)
        self.assertIn("CHECK (issues_json IS NULL OR json_valid(issues_json))", self.sql)
        self.assertRegex(
            self.sql,
            r"(?s)resolution\s+VARCHAR\(24\).*?'create'.*?'merge'.*?'skip'.*?'reject'",
        )

    def test_import_job_error_is_code_not_free_text(self):
        self.assertIn("error_code             VARCHAR(40)", self.sql)
        self.assertNotRegex(self.sql, r"(?i)error_(message|detail|trace)")


class FoundationDatabaseTests(unittest.TestCase):
    """Apply both migrations when CI provides a disposable MariaDB service."""

    @classmethod
    def setUpClass(cls):
        cls.mysql = os.environ.get("IRICA_MARIADB") or shutil.which("mariadb") or shutil.which("mysql")
        cls.password = os.environ.get("IRICA_DB_ROOT_PASSWORD")
        cls.host = os.environ.get("IRICA_DB_HOST", "127.0.0.1")
        cls.port = os.environ.get("IRICA_DB_PORT", "3307")
        if not cls.mysql or not cls.password:
            raise unittest.SkipTest("MariaDB test service is not configured")
        cls.db = "irica_v2_%s" % uuid.uuid4().hex[:12]
        cls._run("CREATE DATABASE `%s` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;" % cls.db, database=None)
        try:
            cls._run(read(INITIAL), database=cls.db)
            cls._run(read(FOUNDATION), database=cls.db)
        except Exception:
            cls._run("DROP DATABASE IF EXISTS `%s`;" % cls.db, database=None, check=False)
            raise

    @classmethod
    def tearDownClass(cls):
        if getattr(cls, "mysql", None) and getattr(cls, "db", None):
            cls._run("DROP DATABASE IF EXISTS `%s`;" % cls.db, database=None, check=False)

    @classmethod
    def _run(cls, sql, database=None, check=True):
        command = [
            cls.mysql, "-h", cls.host, "-P", str(cls.port), "-u", "root",
            "--protocol=TCP", "--default-character-set=utf8mb4", "--batch",
            "--skip-column-names",
        ]
        # MariaDB accepts --ssl=FALSE; MySQL clients may not. Use it only for
        # the MariaDB executable, matching the repository's existing tests.
        if "mariadb" in os.path.basename(cls.mysql).lower():
            command.append("--ssl=FALSE")
        if database:
            command.append(database)
        env = dict(os.environ)
        env["MYSQL_PWD"] = cls.password
        process = subprocess.run(
            command, input=sql, capture_output=True, text=True,
            encoding="utf-8", errors="replace", env=env, timeout=120,
        )
        if check and process.returncode != 0:
            raise AssertionError(
                "migration SQL failed with exit %d: %s" %
                (process.returncode, (process.stderr or "")[:1000])
            )
        return process.stdout or ""

    def scalar(self, sql):
        return self._run(sql, database=self.db).strip().splitlines()[-1]

    def test_new_tables_exist(self):
        count = self.scalar(
            "SELECT COUNT(*) FROM information_schema.TABLES "
            "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME IN "
            "('record_presence','legacy_import_jobs','legacy_import_records',"
            "'legacy_import_decisions');"
        )
        self.assertEqual(count, "4")

    def test_device_owner_column_and_fk_exist(self):
        column = self.scalar(
            "SELECT COUNT(*) FROM information_schema.COLUMNS "
            "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='sync_devices' "
            "AND COLUMN_NAME='owner_user_id';"
        )
        fk = self.scalar(
            "SELECT COUNT(*) FROM information_schema.KEY_COLUMN_USAGE "
            "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='sync_devices' "
            "AND COLUMN_NAME='owner_user_id' AND REFERENCED_TABLE_NAME='users';"
        )
        self.assertEqual(column, "1")
        self.assertEqual(fk, "1")

    def test_import_source_hash_is_unique_per_tenant(self):
        unique_index = self.scalar(
            "SELECT COUNT(*) FROM information_schema.STATISTICS "
            "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='legacy_import_jobs' "
            "AND INDEX_NAME='uq_legacy_import_source' AND NON_UNIQUE=0;"
        )
        self.assertEqual(unique_index, "2")  # two columns in the composite key


if __name__ == "__main__":
    unittest.main()
