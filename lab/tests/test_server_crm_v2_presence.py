# -*- coding: utf-8 -*-
"""Real DB verification for advisory record presence (Phase 4)."""
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
MIGRATION_FILES = ("001_initial.sql", "002_server_crm_v2_foundation.sql",
                   "003_server_crm_v2_device_auth.sql")


def read(path):
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


class PresenceStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = read(os.path.join(HOST, "src", "Presence.php"))
        cls.index = read(os.path.join(HOST, "public", "index.php"))
        cls.client = read(os.path.join(ROOT, "cloud_sync", "client.py"))

    def test_presence_is_advisory_not_a_write_lock(self):
        self.assertIn("Multiple devices may heartbeat", self.source)
        self.assertIn("ON DUPLICATE KEY UPDATE", self.source)
        self.assertNotIn("FOR UPDATE", self.source)
        self.assertNotIn("GET_LOCK", self.source)
        self.assertIn("'advisory' => true", self.source)

    def test_routes_and_client_require_acting_user(self):
        self.assertIn("'/presence/heartbeat' => ['POST']", self.index)
        self.assertIn("'/presence/close' => ['POST']", self.index)
        self.assertIn("$auth->actingUser($request)", self.index)
        self.assertIn('"/presence/heartbeat"', self.client)
        self.assertIn('"/presence/close"', self.client)
        self.assertIn("acting=True", self.client)


class PresenceDatabaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mysql = os.environ.get("IRICA_MARIADB") or shutil.which("mariadb") or shutil.which("mysql")
        cls.php = os.environ.get("IRICA_PHP") or shutil.which("php")
        cls.password = os.environ.get("IRICA_DB_ROOT_PASSWORD")
        cls.host = os.environ.get("IRICA_DB_HOST", "127.0.0.1")
        cls.port = os.environ.get("IRICA_DB_PORT", "3307")
        if not cls.mysql or not cls.php or not cls.password:
            raise unittest.SkipTest("MariaDB/PHP test service is not configured")
        cls.db = "irica_presence_%s" % uuid.uuid4().hex[:12]
        cls.tenant = str(uuid.uuid4())
        cls.user1, cls.user2 = str(uuid.uuid4()), str(uuid.uuid4())
        cls.dev1, cls.dev2 = str(uuid.uuid4()), str(uuid.uuid4())
        cls._sql("CREATE DATABASE `%s` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;" % cls.db, select_db=False)
        try:
            for filename in MIGRATION_FILES:
                cls._sql(read(os.path.join(MIGRATIONS, filename)))
            cls._seed()
            cls.script_dir = tempfile.mkdtemp(prefix="irica_presence_php_")
            cls.script = os.path.join(cls.script_dir, "presence.php")
            cls._write_script()
        except Exception:
            cls._sql("DROP DATABASE IF EXISTS `%s`;" % cls.db, select_db=False, check=False)
            raise

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(getattr(cls, "script_dir", ""), ignore_errors=True)
        if getattr(cls, "mysql", None) and getattr(cls, "db", None):
            cls._sql("DROP DATABASE IF EXISTS `%s`;" % cls.db, select_db=False, check=False)

    @classmethod
    def _sql(cls, sql, *, select_db=True, check=True):
        cmd = [cls.mysql, "-h", cls.host, "-P", str(cls.port), "-u", "root",
               "--protocol=TCP", "--default-character-set=utf8mb4", "--batch",
               "--skip-column-names"]
        if "mariadb" in os.path.basename(cls.mysql).lower():
            cmd.append("--ssl=FALSE")
        if select_db:
            cmd.append(cls.db)
        env = dict(os.environ); env["MYSQL_PWD"] = cls.password
        run = subprocess.run(cmd, input=sql, capture_output=True, text=True,
                             encoding="utf-8", errors="replace", env=env, timeout=180)
        if check and run.returncode != 0:
            raise AssertionError("SQL failed: %s" % (run.stderr or "")[:1800])
        return run.stdout or ""

    @classmethod
    def scalar(cls, sql):
        lines = cls._sql(sql).strip().splitlines()
        return lines[-1] if lines else ""

    @classmethod
    def _seed(cls):
        now = "2026-10-16 09:00:00"
        rows = [
            "INSERT INTO tenants (id,slug,name,status,created_at,updated_at) VALUES ('%s','presence-v2','Presence Test','active','%s','%s');" % (cls.tenant, now, now),
        ]
        for idx, user in enumerate((cls.user1, cls.user2), 1):
            rows.append("INSERT INTO users (id,tenant_id,username,password_hash,display_name,must_change_password,status,token_version,row_version,created_at,updated_at) VALUES ('%s','%s','presence-user-%d','test-hash','Operator %d',0,'active',1,1,'%s','%s');" % (user, cls.tenant, idx, idx, now, now))
            rows.append("INSERT INTO memberships (id,tenant_id,user_id,role,created_at,updated_at) VALUES ('%s','%s','%s','user','%s','%s');" % (str(uuid.uuid4()), cls.tenant, user, now, now))
        for dev, user, name in ((cls.dev1, cls.user1, "PC 1"), (cls.dev2, cls.user2, "PC 2")):
            rows.append("INSERT INTO sync_devices (id,tenant_id,name,status,token_version,enrolled_by,owner_user_id,row_version,created_at,updated_at) VALUES ('%s','%s','%s','active',1,'%s','%s',1,'%s','%s');" % (dev, cls.tenant, name, user, user, now, now))
        cls._sql("\n".join(rows))

    @classmethod
    def _write_script(cls):
        required = ("Schema", "Database", "Http", "Ids", "Log", "Tokens", "Roles", "RateLimit", "Auth", "Presence")
        lines = ["<?php", "declare(strict_types=1);"]
        for name in required:
            lines.append("require_once %s;" % json.dumps(os.path.join(HOST, "src", name + ".php").replace("\\", "/")))
        lines.extend([
            "$db=Database::fromConfig(['host'=>getenv('IRICA_DB_HOST'),'port'=>(int)getenv('IRICA_DB_PORT'),'dbname'=>getenv('IRICA_PRESENCE_DB'),'user'=>'root','password'=>getenv('IRICA_DB_ROOT_PASSWORD')]);",
            "$svc=new Presence($db,new Log(null));",
            "$tenant=getenv('IRICA_PRESENCE_TENANT'); $dev=$argv[2]; $user=$argv[3];",
            "$dp=new Principal(Tokens::KIND_DEVICE,$dev,$tenant,Roles::USER,$user,$dev,Ids::v4(),1);",
            "$up=new Principal(Tokens::KIND_USER,$user,$tenant,Roles::USER,$user,'',Ids::v4(),1);",
            "try{if($argv[1]==='heartbeat'){$out=$svc->heartbeat($dp,$up,['entity'=>'crm_devices','entity_id'=>$argv[4]],Ids::v4());}else{$out=$svc->close($dp,$up,['lease_id'=>$argv[4]],Ids::v4());}echo json_encode(['ok'=>true,'result'=>$out]);}catch(ApiException $e){echo json_encode(['ok'=>false,'status'=>$e->status,'code'=>$e->errorCode]);exit(2);}",
        ])
        with open(cls.script, "w", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")

    def _call(self, action, dev, user, value):
        env = dict(os.environ)
        env.update({"IRICA_DB_ROOT_PASSWORD": self.password,
                    "IRICA_DB_HOST": self.host, "IRICA_DB_PORT": str(self.port),
                    "IRICA_PRESENCE_DB": self.db, "IRICA_PRESENCE_TENANT": self.tenant})
        run = subprocess.run([self.php, self.script, action, dev, user, value],
                             capture_output=True, text=True, encoding="utf-8",
                             errors="replace", env=env, cwd=ROOT, timeout=120)
        payload = json.loads((run.stdout or "").strip().splitlines()[-1])
        return run.returncode, payload

    def test_two_devices_can_be_present_on_same_record_without_locking(self):
        record = str(uuid.uuid4())
        code, first = self._call("heartbeat", self.dev1, self.user1, record)
        self.assertEqual(code, 0); self.assertTrue(first["ok"])
        self.assertEqual(first["result"]["peers"], [])
        lease1 = first["result"]["lease_id"]
        code, second = self._call("heartbeat", self.dev2, self.user2, record)
        self.assertEqual(code, 0); self.assertTrue(second["ok"])
        self.assertEqual(len(second["result"]["peers"]), 1)
        self.assertEqual(second["result"]["peers"][0]["sync_device_id"], self.dev1)
        code, again = self._call("heartbeat", self.dev1, self.user1, record)
        self.assertEqual(code, 0)
        self.assertEqual(again["result"]["lease_id"], lease1)
        self.assertEqual(len(again["result"]["peers"]), 1)
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM record_presence WHERE entity_id='%s';" % record), "2")

    def test_close_is_scoped_and_idempotent(self):
        record = str(uuid.uuid4())
        _, one = self._call("heartbeat", self.dev1, self.user1, record)
        _, two = self._call("heartbeat", self.dev2, self.user2, record)
        lease1 = one["result"]["lease_id"]
        code, closed = self._call("close", self.dev1, self.user1, lease1)
        self.assertEqual(code, 0); self.assertTrue(closed["result"]["closed"])
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM record_presence WHERE entity_id='%s';" % record), "1")
        _, closed_again = self._call("close", self.dev1, self.user1, lease1)
        self.assertFalse(closed_again["result"]["closed"])
        # The second device's lease was never touched.
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM record_presence WHERE lease_id='%s';" % two["result"]["lease_id"]), "1")

    def test_expired_presence_is_purged_by_next_heartbeat(self):
        record = str(uuid.uuid4())
        self._call("heartbeat", self.dev1, self.user1, record)
        self._sql("UPDATE record_presence SET expires_at='2000-01-01 00:00:00' WHERE entity_id='%s' AND sync_device_id='%s';" % (record, self.dev1))
        _, second = self._call("heartbeat", self.dev2, self.user2, record)
        peers = second["result"]["peers"]
        self.assertEqual(peers, [])
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM record_presence WHERE entity_id='%s';" % record), "1")


if __name__ == "__main__":
    unittest.main()
