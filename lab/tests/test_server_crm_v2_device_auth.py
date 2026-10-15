# -*- coding: utf-8 -*-
"""Server CRM v2 device ownership and revocation tests.

This module exercises the new device lifecycle against a disposable real
MariaDB schema and the real PHP service class. It deliberately avoids the
HTTP test harness so service-container networking cannot weaken the production
localhost-only database account model.

Coverage:
* migration 003 is additive and defaults owner_user_id before INSERT;
* one ordinary user can enrol two independent desktop credential families;
* revoking one desktop leaves the other active;
* revoking all desktops for the user invalidates the remaining machine;
* a non-admin cannot probe another user's device (404, not 403);
* an admin can revoke another user's device;
* device status, token_version and refresh-session revocation change together.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import uuid

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
HOST = os.path.join(ROOT, "host")
MIGRATIONS = os.path.join(HOST, "migrations")
MIGRATION_FILES = (
    "001_initial.sql",
    "002_server_crm_v2_foundation.sql",
    "003_server_crm_v2_device_auth.sql",
)


def read(path):
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


class DeviceAuthStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sql = read(os.path.join(MIGRATIONS, MIGRATION_FILES[-1]))
        cls.roles = read(os.path.join(HOST, "src", "Roles.php"))
        cls.index = read(os.path.join(HOST, "public", "index.php"))
        cls.devices = read(os.path.join(HOST, "src", "Devices.php"))

    def test_migration_is_forward_only_and_defaults_owner(self):
        self.assertNotRegex(self.sql, r"(?im)^\s*DROP\s+")
        self.assertNotRegex(self.sql, r"(?im)^\s*TRUNCATE\s+")
        self.assertIn("BEFORE INSERT ON sync_devices", self.sql)
        self.assertIn(
            "SET NEW.owner_user_id = COALESCE(NEW.owner_user_id, NEW.enrolled_by)",
            self.sql,
        )

    def test_admin_enroll_and_self_enroll_are_distinct_capabilities(self):
        self.assertIn("function canEnroll", self.roles)
        self.assertIn("return $role === self::ADMIN", self.roles)
        self.assertIn("function canSelfEnroll", self.roles)
        self.assertIn("return self::isKnown($role)", self.roles)
        self.assertIn("function requireSelfEnroll", self.roles)

    def test_device_routes_are_explicit(self):
        for route in (
            "/sync-devices/self-enroll",
            "/sync-devices/revoke",
            "/sync-devices/revoke-all",
        ):
            self.assertIn("'" + route + "' => ['POST']", self.index)
        self.assertIn("new Devices($db, $log, $config)", self.index)

    def test_revocation_is_transactional_and_kills_refresh_sessions(self):
        self.assertIn("$this->db->transaction", self.devices)
        self.assertIn("token_version = token_version + 1", self.devices)
        self.assertIn("UPDATE auth_sessions SET revoked_at", self.devices)
        self.assertIn("FOR UPDATE", self.devices)
        self.assertIn("throw new ApiException(404, Codes::NOT_FOUND", self.devices)


class DeviceAuthMariaDbTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mysql = (
            os.environ.get("IRICA_MARIADB")
            or shutil.which("mariadb")
            or shutil.which("mysql")
        )
        cls.php = os.environ.get("IRICA_PHP") or shutil.which("php")
        cls.password = os.environ.get("IRICA_DB_ROOT_PASSWORD")
        cls.host = os.environ.get("IRICA_DB_HOST", "127.0.0.1")
        cls.port = os.environ.get("IRICA_DB_PORT", "3307")
        if not cls.mysql or not cls.php or not cls.password:
            raise unittest.SkipTest("MariaDB/PHP test service is not configured")

        cls.db = "irica_device_%s" % uuid.uuid4().hex[:12]
        cls.tenant = str(uuid.uuid4())
        cls.admin = str(uuid.uuid4())
        cls.user_a = str(uuid.uuid4())
        cls.user_b = str(uuid.uuid4())
        cls._run_sql(
            "CREATE DATABASE `%s` CHARACTER SET utf8mb4 "
            "COLLATE utf8mb4_unicode_ci;" % cls.db,
            database=None,
        )
        try:
            for filename in MIGRATION_FILES:
                cls._run_sql(read(os.path.join(MIGRATIONS, filename)))
            cls._seed_users()
        except Exception:
            cls._run_sql(
                "DROP DATABASE IF EXISTS `%s`;" % cls.db,
                database=None,
                check=False,
            )
            raise

    @classmethod
    def tearDownClass(cls):
        if getattr(cls, "mysql", None) and getattr(cls, "db", None):
            cls._run_sql(
                "DROP DATABASE IF EXISTS `%s`;" % cls.db,
                database=None,
                check=False,
            )

    @classmethod
    def _run_sql(cls, sql, database=None, check=True):
        command = [
            cls.mysql,
            "-h", cls.host,
            "-P", str(cls.port),
            "-u", "root",
            "--protocol=TCP",
            "--default-character-set=utf8mb4",
            "--batch",
            "--skip-column-names",
        ]
        if "mariadb" in os.path.basename(cls.mysql).lower():
            command.append("--ssl=FALSE")
        if database is not None:
            command.append(database)
        elif getattr(cls, "db", None):
            command.append(cls.db)
        env = dict(os.environ)
        env["MYSQL_PWD"] = cls.password
        process = subprocess.run(
            command,
            input=sql,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
            timeout=180,
        )
        if check and process.returncode != 0:
            raise AssertionError(
                "SQL failed with exit %d: %s"
                % (process.returncode, (process.stderr or "")[:1200])
            )
        return process.stdout or ""

    @classmethod
    def _seed_users(cls):
        now = "2026-10-15 16:00:00"
        users = (
            (cls.admin, "admin-v2", "admin"),
            (cls.user_a, "user-a-v2", "user"),
            (cls.user_b, "user-b-v2", "user"),
        )
        statements = [
            "INSERT INTO tenants (id, slug, name, status, created_at, updated_at) "
            "VALUES ('%s', 'device-auth-v2', 'Device Auth Test', 'active', '%s', '%s');"
            % (cls.tenant, now, now)
        ]
        for user_id, username, role in users:
            statements.append(
                "INSERT INTO users (id, tenant_id, username, password_hash, "
                "display_name, must_change_password, status, token_version, "
                "row_version, created_at, updated_at) VALUES "
                "('%s', '%s', '%s', 'test-hash-not-a-credential', '', 0, "
                "'active', 1, 1, '%s', '%s');"
                % (user_id, cls.tenant, username, now, now)
            )
            statements.append(
                "INSERT INTO memberships (id, tenant_id, user_id, role, created_at, updated_at) "
                "VALUES ('%s', '%s', '%s', '%s', '%s', '%s');"
                % (str(uuid.uuid4()), cls.tenant, user_id, role, now, now)
            )
        cls._run_sql("\n".join(statements))

    def _run_php_scenario(self):
        directory = tempfile.mkdtemp(prefix="irica_device_auth_php_")
        self.addCleanup(shutil.rmtree, directory, True)
        script = os.path.join(directory, "probe.php")
        requires = [
            "Schema", "Database", "Http", "Ids", "Log", "Tokens", "Roles",
            "RateLimit", "Auth", "Devices",
        ]
        lines = ["<?php", "declare(strict_types=1);"]
        for name in requires:
            path = os.path.join(HOST, "src", name + ".php").replace("\\", "/")
            lines.append("require_once %s;" % json.dumps(path))
        lines.extend([
            "$cfg = [",
            "  'host' => getenv('IRICA_DB_HOST') ?: '127.0.0.1',",
            "  'port' => (int) (getenv('IRICA_DB_PORT') ?: '3307'),",
            "  'dbname' => getenv('IRICA_DEVICE_TEST_DB'),",
            "  'user' => 'root',",
            "  'password' => getenv('IRICA_DB_ROOT_PASSWORD'),",
            "];",
            "$db = Database::fromConfig($cfg);",
            "$log = new Log(null);",
            "$service = new Devices($db, $log, [",
            "  'refresh' => [",
            "    'device_idle_seconds' => 3600,",
            "    'device_absolute_seconds' => 7200,",
            "  ],",
            "]);",
            "$tenant = getenv('IRICA_DEVICE_TEST_TENANT');",
            "$adminId = getenv('IRICA_DEVICE_TEST_ADMIN');",
            "$userA = getenv('IRICA_DEVICE_TEST_USER_A');",
            "$userB = getenv('IRICA_DEVICE_TEST_USER_B');",
            "$admin = new Principal(Tokens::KIND_USER, $adminId, $tenant,",
            "  Roles::ADMIN, $adminId, '', Ids::v4(), 1);",
            "$a = new Principal(Tokens::KIND_USER, $userA, $tenant,",
            "  Roles::USER, $userA, '', Ids::v4(), 1);",
            "$b = new Principal(Tokens::KIND_USER, $userB, $tenant,",
            "  Roles::USER, $userB, '', Ids::v4(), 1);",
            "$d1 = $service->selfEnroll($a, ['name' => 'workstation-a1'], Ids::v4(), '127.0.0.1');",
            "$d2 = $service->selfEnroll($a, ['name' => 'workstation-a2'], Ids::v4(), '127.0.0.1');",
            "$dOther = $service->selfEnroll($b, ['name' => 'workstation-b1'], Ids::v4(), '127.0.0.1');",
            "$owner1 = $db->queryValue('SELECT owner_user_id FROM sync_devices WHERE id = ?', [$d1['sync_device_id']]);",
            "$owner2 = $db->queryValue('SELECT owner_user_id FROM sync_devices WHERE id = ?', [$d2['sync_device_id']]);",
            "$session1Before = (int) $db->queryValue('SELECT COUNT(*) FROM auth_sessions WHERE sync_device_id = ? AND revoked_at IS NULL', [$d1['sync_device_id']]);",
            "$one = $service->revoke($a, $d1['sync_device_id'], Ids::v4(), '127.0.0.1');",
            "$row1 = $db->queryOne('SELECT status, token_version FROM sync_devices WHERE id = ?', [$d1['sync_device_id']]);",
            "$row2Before = $db->queryOne('SELECT status, token_version FROM sync_devices WHERE id = ?', [$d2['sync_device_id']]);",
            "$session1After = (int) $db->queryValue('SELECT COUNT(*) FROM auth_sessions WHERE sync_device_id = ? AND revoked_at IS NULL', [$d1['sync_device_id']]);",
            "$foreignStatus = null; $foreignCode = null;",
            "try {",
            "  $service->revoke($a, $dOther['sync_device_id'], Ids::v4(), '127.0.0.1');",
            "} catch (ApiException $e) {",
            "  $foreignStatus = $e->status; $foreignCode = $e->errorCode;",
            "}",
            "$adminOther = $service->revoke($admin, $dOther['sync_device_id'], Ids::v4(), '127.0.0.1');",
            "$all = $service->revokeAll($a, null, Ids::v4(), '127.0.0.1');",
            "$row2After = $db->queryOne('SELECT status, token_version FROM sync_devices WHERE id = ?', [$d2['sync_device_id']]);",
            "$session2After = (int) $db->queryValue('SELECT COUNT(*) FROM auth_sessions WHERE sync_device_id = ? AND revoked_at IS NULL', [$d2['sync_device_id']]);",
            "echo json_encode([",
            "  'different_ids' => $d1['sync_device_id'] !== $d2['sync_device_id'],",
            "  'owner1' => $owner1, 'owner2' => $owner2,",
            "  'session1_before' => $session1Before,",
            "  'revoke_one' => $one, 'row1' => $row1,",
            "  'row2_before' => $row2Before, 'session1_after' => $session1After,",
            "  'foreign_status' => $foreignStatus, 'foreign_code' => $foreignCode,",
            "  'admin_other' => $adminOther, 'revoke_all' => $all,",
            "  'row2_after' => $row2After, 'session2_after' => $session2After,",
            "]);",
        ])
        with open(script, "w", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")
        env = dict(os.environ)
        env.update({
            "IRICA_DB_ROOT_PASSWORD": self.password,
            "IRICA_DB_HOST": self.host,
            "IRICA_DB_PORT": str(self.port),
            "IRICA_DEVICE_TEST_DB": self.db,
            "IRICA_DEVICE_TEST_TENANT": self.tenant,
            "IRICA_DEVICE_TEST_ADMIN": self.admin,
            "IRICA_DEVICE_TEST_USER_A": self.user_a,
            "IRICA_DEVICE_TEST_USER_B": self.user_b,
        })
        process = subprocess.run(
            [self.php, script],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
            cwd=ROOT,
            timeout=120,
        )
        if process.returncode != 0:
            raise AssertionError(
                "PHP device-auth scenario failed (exit %d): %s"
                % (process.returncode, (process.stderr or "")[:1600])
            )
        try:
            return json.loads((process.stdout or "").strip().splitlines()[-1])
        except (ValueError, IndexError) as exc:
            raise AssertionError(
                "PHP device-auth scenario did not return JSON: %s / %s"
                % (exc, (process.stdout or "")[:800])
            )

    def test_two_devices_revoke_one_then_revoke_all(self):
        result = self._run_php_scenario()
        self.assertIs(result["different_ids"], True)
        self.assertEqual(result["owner1"], self.user_a)
        self.assertEqual(result["owner2"], self.user_a)
        self.assertEqual(result["session1_before"], 1)

        self.assertIs(result["revoke_one"]["revoked"], True)
        self.assertIs(result["revoke_one"]["changed"], True)
        self.assertEqual(result["row1"]["status"], "revoked")
        self.assertEqual(int(result["row1"]["token_version"]), 2)
        self.assertEqual(result["session1_after"], 0)

        self.assertEqual(result["row2_before"]["status"], "active")
        self.assertEqual(int(result["row2_before"]["token_version"]), 1)
        self.assertEqual(result["foreign_status"], 404)
        self.assertEqual(result["foreign_code"], "NOT_FOUND")
        self.assertIs(result["admin_other"]["revoked"], True)

        self.assertEqual(result["revoke_all"]["matched_devices"], 2)
        self.assertEqual(result["revoke_all"]["revoked_devices"], 1)
        self.assertEqual(result["row2_after"]["status"], "revoked")
        self.assertEqual(int(result["row2_after"]["token_version"]), 2)
        self.assertEqual(result["session2_after"], 0)


if __name__ == "__main__":
    unittest.main()
