# -*- coding: utf-8 -*-
"""Real MariaDB/PHP coverage for server CRM v2 device ownership."""
import json
import os
import shutil
import subprocess
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

    def test_contract_is_additive_and_explicit(self):
        self.assertNotRegex(self.sql, r"(?im)^\s*(DROP|TRUNCATE)\s+")
        self.assertIn("BEFORE INSERT ON sync_devices", self.sql)
        self.assertIn(
            "SET NEW.owner_user_id = COALESCE(NEW.owner_user_id, NEW.enrolled_by)",
            self.sql,
        )
        self.assertIn("function canSelfEnroll", self.roles)
        self.assertIn("function requireSelfEnroll", self.roles)
        for route in (
            "/sync-devices/self-enroll",
            "/sync-devices/revoke",
            "/sync-devices/revoke-all",
        ):
            self.assertIn("'" + route + "' => ['POST']", self.index)
        for marker in (
            "$this->db->transaction",
            "token_version + 1",
            "UPDATE auth_sessions SET revoked_at",
            "FOR UPDATE",
        ):
            self.assertIn(marker, self.devices)


class DeviceAuthMariaDbTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mysql = os.environ.get("IRICA_MARIADB") or shutil.which("mariadb") or shutil.which("mysql")
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
        cls._sql("CREATE DATABASE `%s` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;" % cls.db, select_db=False)
        try:
            for filename in MIGRATION_FILES:
                cls._sql(read(os.path.join(MIGRATIONS, filename)))
            cls._seed()
        except Exception:
            cls._sql("DROP DATABASE IF EXISTS `%s`;" % cls.db, select_db=False, check=False)
            raise

    @classmethod
    def tearDownClass(cls):
        if getattr(cls, "mysql", None) and getattr(cls, "db", None):
            cls._sql("DROP DATABASE IF EXISTS `%s`;" % cls.db, select_db=False, check=False)

    @classmethod
    def _sql(cls, sql, *, select_db=True, check=True):
        cmd = [
            cls.mysql, "-h", cls.host, "-P", str(cls.port), "-u", "root",
            "--protocol=TCP", "--default-character-set=utf8mb4", "--batch",
            "--skip-column-names",
        ]
        if "mariadb" in os.path.basename(cls.mysql).lower():
            cmd.append("--ssl=FALSE")
        if select_db:
            cmd.append(cls.db)
        env = dict(os.environ)
        env["MYSQL_PWD"] = cls.password
        run = subprocess.run(
            cmd, input=sql, capture_output=True, text=True, encoding="utf-8",
            errors="replace", env=env, timeout=180,
        )
        if check and run.returncode != 0:
            raise AssertionError("SQL failed (exit %d): %s" % (run.returncode, (run.stderr or "")[:1200]))
        return run.stdout or ""

    @classmethod
    def _seed(cls):
        now = "2026-10-15 16:00:00"
        sql = [
            "INSERT INTO tenants (id, slug, name, status, created_at, updated_at) VALUES ('%s','device-auth-v2','Device Auth Test','active','%s','%s');"
            % (cls.tenant, now, now)
        ]
        for user_id, username, role in (
            (cls.admin, "admin-v2", "admin"),
            (cls.user_a, "user-a-v2", "user"),
            (cls.user_b, "user-b-v2", "user"),
        ):
            sql.append(
                "INSERT INTO users (id,tenant_id,username,password_hash,display_name,must_change_password,status,token_version,row_version,created_at,updated_at) "
                "VALUES ('%s','%s','%s','test-hash-not-a-credential','',0,'active',1,1,'%s','%s');"
                % (user_id, cls.tenant, username, now, now)
            )
            sql.append(
                "INSERT INTO memberships (id,tenant_id,user_id,role,created_at,updated_at) VALUES ('%s','%s','%s','%s','%s','%s');"
                % (str(uuid.uuid4()), cls.tenant, user_id, role, now, now)
            )
        cls._sql("\n".join(sql))

    def _scenario(self):
        directory = tempfile.mkdtemp(prefix="irica_device_auth_php_")
        self.addCleanup(shutil.rmtree, directory, True)
        path = os.path.join(directory, "probe.php")
        source = ["<?php", "declare(strict_types=1);"]
        for name in ("Schema", "Database", "Http", "Ids", "Log", "Tokens", "Roles", "RateLimit", "Auth", "Devices"):
            source.append("require_once %s;" % json.dumps(os.path.join(HOST, "src", name + ".php").replace("\\", "/")))
        source.extend([
            "$db=Database::fromConfig(['host'=>getenv('IRICA_DB_HOST'),'port'=>(int)getenv('IRICA_DB_PORT'),'dbname'=>getenv('IRICA_DEVICE_TEST_DB'),'user'=>'root','password'=>getenv('IRICA_DB_ROOT_PASSWORD')]);",
            "$svc=new Devices($db,new Log(null),['refresh'=>['device_idle_seconds'=>3600,'device_absolute_seconds'=>7200]]);",
            "$t=getenv('IRICA_DEVICE_TEST_TENANT'); $aid=getenv('IRICA_DEVICE_TEST_ADMIN'); $ua=getenv('IRICA_DEVICE_TEST_USER_A'); $ub=getenv('IRICA_DEVICE_TEST_USER_B');",
            "$admin=new Principal(Tokens::KIND_USER,$aid,$t,Roles::ADMIN,$aid,'',Ids::v4(),1);",
            "$a=new Principal(Tokens::KIND_USER,$ua,$t,Roles::USER,$ua,'',Ids::v4(),1);",
            "$b=new Principal(Tokens::KIND_USER,$ub,$t,Roles::USER,$ub,'',Ids::v4(),1);",
            "$d1=$svc->selfEnroll($a,['name'=>'a1'],Ids::v4(),'127.0.0.1'); $d2=$svc->selfEnroll($a,['name'=>'a2'],Ids::v4(),'127.0.0.1'); $dx=$svc->selfEnroll($b,['name'=>'b1'],Ids::v4(),'127.0.0.1');",
            "$owner1=$db->queryValue('SELECT owner_user_id FROM sync_devices WHERE id = ?',[$d1['sync_device_id']]); $owner2=$db->queryValue('SELECT owner_user_id FROM sync_devices WHERE id = ?',[$d2['sync_device_id']]);",
            "$s1b=(int)$db->queryValue('SELECT COUNT(*) FROM auth_sessions WHERE sync_device_id = ? AND revoked_at IS NULL',[$d1['sync_device_id']]);",
            "$one=$svc->revoke($a,$d1['sync_device_id'],Ids::v4(),'127.0.0.1'); $r1=$db->queryOne('SELECT status,token_version FROM sync_devices WHERE id = ?',[$d1['sync_device_id']]); $r2b=$db->queryOne('SELECT status,token_version FROM sync_devices WHERE id = ?',[$d2['sync_device_id']]); $s1a=(int)$db->queryValue('SELECT COUNT(*) FROM auth_sessions WHERE sync_device_id = ? AND revoked_at IS NULL',[$d1['sync_device_id']]);",
            "$fs=null; $fc=null; try{$svc->revoke($a,$dx['sync_device_id'],Ids::v4(),'127.0.0.1');}catch(ApiException $e){$fs=$e->status;$fc=$e->errorCode;}",
            "$adminOther=$svc->revoke($admin,$dx['sync_device_id'],Ids::v4(),'127.0.0.1'); $all=$svc->revokeAll($a,null,Ids::v4(),'127.0.0.1'); $r2a=$db->queryOne('SELECT status,token_version FROM sync_devices WHERE id = ?',[$d2['sync_device_id']]); $s2a=(int)$db->queryValue('SELECT COUNT(*) FROM auth_sessions WHERE sync_device_id = ? AND revoked_at IS NULL',[$d2['sync_device_id']]);",
            "echo json_encode(['different_ids'=>$d1['sync_device_id']!==$d2['sync_device_id'],'owner1'=>$owner1,'owner2'=>$owner2,'s1b'=>$s1b,'one'=>$one,'r1'=>$r1,'r2b'=>$r2b,'s1a'=>$s1a,'fs'=>$fs,'fc'=>$fc,'adminOther'=>$adminOther,'all'=>$all,'r2a'=>$r2a,'s2a'=>$s2a]);",
        ])
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("\n".join(source) + "\n")
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
        run = subprocess.run([self.php, path], capture_output=True, text=True, encoding="utf-8", errors="replace", env=env, cwd=ROOT, timeout=120)
        if run.returncode != 0:
            raise AssertionError("PHP scenario failed (exit %d): %s" % (run.returncode, (run.stderr or "")[:1600]))
        return json.loads((run.stdout or "").strip().splitlines()[-1])

    def test_two_devices_revoke_one_then_all(self):
        r = self._scenario()
        self.assertTrue(r["different_ids"])
        self.assertEqual((r["owner1"], r["owner2"]), (self.user_a, self.user_a))
        self.assertEqual(r["s1b"], 1)
        self.assertTrue(r["one"]["changed"])
        self.assertEqual((r["r1"]["status"], int(r["r1"]["token_version"]), r["s1a"]), ("revoked", 2, 0))
        self.assertEqual((r["r2b"]["status"], int(r["r2b"]["token_version"])), ("active", 1))
        self.assertEqual((r["fs"], r["fc"]), (404, "NOT_FOUND"))
        self.assertTrue(r["adminOther"]["changed"])
        self.assertEqual((r["all"]["matched_devices"], r["all"]["revoked_devices"]), (2, 1))
        self.assertEqual((r["r2a"]["status"], int(r["r2a"]["token_version"]), r["s2a"]), ("revoked", 2, 0))


if __name__ == "__main__":
    unittest.main()
