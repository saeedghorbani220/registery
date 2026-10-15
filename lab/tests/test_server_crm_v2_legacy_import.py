# -*- coding: utf-8 -*-
"""Real MariaDB coverage for staged legacy CRM migration analysis."""
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


class LegacyImportStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = read(os.path.join(HOST, "src", "LegacyImport.php"))

    def test_analysis_is_staging_only_and_does_not_use_bootstrap_import(self):
        self.assertIn("legacy_import_jobs", self.source)
        self.assertIn("legacy_import_records", self.source)
        self.assertIn("Roles::requireImport", self.source)
        self.assertIn("hash('sha256', $sourceText)", self.source)
        self.assertNotIn("new Import", self.source)
        self.assertNotIn("INSERT INTO customers ", self.source)
        self.assertNotIn("INSERT INTO crm_devices ", self.source)
        self.assertNotIn("INSERT INTO customer_transactions ", self.source)

    def test_sensitive_source_is_not_written_to_logs(self):
        log_slice = self.source[self.source.index("legacy_import.analyze"):]
        self.assertNotIn("sourceText", log_slice)
        self.assertNotIn("record_json' =>", log_slice)
        self.assertIn("source_sha256", log_slice)


class LegacyImportMariaDbTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mysql = os.environ.get("IRICA_MARIADB") or shutil.which("mariadb") or shutil.which("mysql")
        cls.php = os.environ.get("IRICA_PHP") or shutil.which("php")
        cls.password = os.environ.get("IRICA_DB_ROOT_PASSWORD")
        cls.host = os.environ.get("IRICA_DB_HOST", "127.0.0.1")
        cls.port = os.environ.get("IRICA_DB_PORT", "3307")
        if not cls.mysql or not cls.php or not cls.password:
            raise unittest.SkipTest("MariaDB/PHP test service is not configured")

        cls.db = "irica_legacy_%s" % uuid.uuid4().hex[:12]
        cls.tenant = str(uuid.uuid4())
        cls.user = str(uuid.uuid4())
        cls._sql("CREATE DATABASE `%s` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;" % cls.db, select_db=False)
        try:
            for filename in MIGRATION_FILES:
                cls._sql(read(os.path.join(MIGRATIONS, filename)))
            cls._seed()
            cls.tmp = tempfile.mkdtemp(prefix="irica_legacy_php_")
            cls.script = os.path.join(cls.tmp, "analyze.php")
            cls._write_script()
        except Exception:
            cls._sql("DROP DATABASE IF EXISTS `%s`;" % cls.db, select_db=False, check=False)
            raise

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(getattr(cls, "tmp", ""), ignore_errors=True)
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
            raise AssertionError("SQL failed (exit %d): %s" % (run.returncode, (run.stderr or "")[:1800]))
        return run.stdout or ""

    @classmethod
    def scalar(cls, sql):
        lines = cls._sql(sql).strip().splitlines()
        return lines[-1] if lines else ""

    @classmethod
    def _seed(cls):
        now = "2026-10-15 17:00:00"
        membership = str(uuid.uuid4())
        source_installation = str(uuid.uuid4())
        cls._sql("\n".join([
            "INSERT INTO tenants (id,slug,name,status,created_at,updated_at) VALUES ('%s','legacy-v2','Legacy Test','active','%s','%s');" % (cls.tenant, now, now),
            "INSERT INTO users (id,tenant_id,username,password_hash,display_name,must_change_password,status,token_version,row_version,created_at,updated_at) VALUES ('%s','%s','legacy-admin','test-hash-not-a-credential','',0,'active',1,1,'%s','%s');" % (cls.user, cls.tenant, now, now),
            "INSERT INTO memberships (id,tenant_id,user_id,role,created_at,updated_at) VALUES ('%s','%s','%s','admin','%s','%s');" % (membership, cls.tenant, cls.user, now, now),
            "INSERT INTO tenant_state (tenant_id,dataset_epoch,bootstrap_status,source_installation_id,created_at,updated_at) VALUES ('%s',1,'done','%s','%s','%s');" % (cls.tenant, source_installation, now, now),
        ]))

    @classmethod
    def _write_script(cls):
        required = ("Schema", "Database", "Http", "Ids", "Log", "Tokens", "Roles", "RateLimit", "Auth", "Sync", "LegacyImport")
        lines = ["<?php", "declare(strict_types=1);"]
        for name in required:
            lines.append("require_once %s;" % json.dumps(os.path.join(HOST, "src", name + ".php").replace("\\", "/")))
        lines.extend([
            "$db=Database::fromConfig(['host'=>getenv('IRICA_DB_HOST'),'port'=>(int)getenv('IRICA_DB_PORT'),'dbname'=>getenv('IRICA_LEGACY_DB'),'user'=>'root','password'=>getenv('IRICA_DB_ROOT_PASSWORD')]);",
            "$sync=new Sync($db,new Log(null),[]);",
            "$svc=new LegacyImport($db,$sync,new Log(null),['limits'=>['max_import_body_bytes'=>16777216]]);",
            "$tenant=getenv('IRICA_LEGACY_TENANT'); $user=getenv('IRICA_LEGACY_USER');",
            "$principal=new Principal(Tokens::KIND_USER,$user,$tenant,Roles::ADMIN,$user,'',Ids::v4(),1);",
            "$body=['source_text'=>file_get_contents($argv[1]),'filename'=>basename($argv[1])]; if(isset($argv[2])&&$argv[2]!==''){$body['source_version']=$argv[2];}",
            "try{$result=$svc->analyze($principal,$body,Ids::v4(),'127.0.0.1');echo json_encode(['ok'=>true,'result'=>$result],JSON_UNESCAPED_UNICODE);}catch(ApiException $e){echo json_encode(['ok'=>false,'status'=>$e->status,'code'=>$e->errorCode]);exit(2);}",
        ])
        with open(cls.script, "w", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")

    def setUp(self):
        self._sql("DELETE FROM legacy_import_decisions; DELETE FROM legacy_import_records; DELETE FROM legacy_import_jobs; DELETE FROM audit_events WHERE action='legacy_import.analyze';")
        self._sql("DELETE FROM customer_transactions; DELETE FROM crm_devices; DELETE FROM owners; DELETE FROM identities; DELETE FROM periods; DELETE FROM settings; DELETE FROM customers;")

    def _run(self, store, version="1.13.1"):
        fd, path = tempfile.mkstemp(prefix="crm_store_", suffix=".json", dir=self.tmp)
        os.close(fd)
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(store, handle, ensure_ascii=False, separators=(",", ":"))
        env = dict(os.environ)
        env.update({
            "IRICA_DB_ROOT_PASSWORD": self.password,
            "IRICA_DB_HOST": self.host,
            "IRICA_DB_PORT": str(self.port),
            "IRICA_LEGACY_DB": self.db,
            "IRICA_LEGACY_TENANT": self.tenant,
            "IRICA_LEGACY_USER": self.user,
        })
        run = subprocess.run(
            [self.php, self.script, path, version], capture_output=True, text=True,
            encoding="utf-8", errors="replace", env=env, cwd=ROOT, timeout=120,
        )
        payload = json.loads((run.stdout or "").strip().splitlines()[-1])
        return run.returncode, payload, path

    @staticmethod
    def base_store():
        return {
            "customers": [{
                "id": "cust0001", "full_name": "Legacy Customer",
                "mobile": "09120000001", "address": "Old address", "notes": "",
                "created": "2026-01-01 12:00:00",
                "transactions": [{
                    "at": "2026-01-02 12:00:00", "amount": 1200,
                    "note": "receipt", "kind": "receipt", "image": "",
                    "device_id": "dev00001",
                }],
            }],
            "owners": [{
                "id": "own00001", "first_name": "Ali", "last_name": "Test",
                "national": "0013547209", "birth": "1370/01/01",
                "mobile": "09120000002", "card_no": "", "passport": "",
            }],
            "identities": [{
                "id": "ident001", "label": "Pool", "national": "0013547209",
                "birth": "1370/01/01", "mobile": "09120000003",
            }],
            "devices": [{
                "id": "dev00001", "name": "Phone", "serial1": "123456789012345",
                "serial2": "", "customer_id": "cust0001", "owner_id": "own00001",
                "stage": "new", "period_id": "",
            }],
            "periods": [],
            "settings": {"business_name": "Legacy Shop", "database_mode": "local"},
        }

    def test_valid_store_is_staged_without_touching_business_tables(self):
        code, payload, _path = self._run(self.base_store())
        self.assertEqual(code, 0, payload)
        self.assertTrue(payload["ok"])
        result = payload["result"]
        self.assertEqual(result["job"]["status"], "ready")
        self.assertEqual(result["job"]["record_count"], 6)
        self.assertEqual(result["counts"]["create"], 6)
        self.assertEqual(result["counts"]["invalid"], 0)
        self.assertEqual(result["counts"]["conflict"], 0)
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM customers;"), "0")
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM customer_transactions;"), "0")
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM legacy_import_records;"), "6")
        # local-only settings never cross the staging boundary
        settings = next(r for r in result["records"] if r["entity"] == "settings")
        self.assertNotIn("database_mode", settings["record"])

    def test_same_exact_file_is_idempotent(self):
        store = self.base_store()
        code, first, path = self._run(store)
        self.assertEqual(code, 0, first)
        # Reuse exact bytes, not merely an equivalent Python object.
        env = dict(os.environ)
        env.update({
            "IRICA_DB_ROOT_PASSWORD": self.password,
            "IRICA_DB_HOST": self.host,
            "IRICA_DB_PORT": str(self.port),
            "IRICA_LEGACY_DB": self.db,
            "IRICA_LEGACY_TENANT": self.tenant,
            "IRICA_LEGACY_USER": self.user,
        })
        run = subprocess.run([self.php, self.script, path, "1.13.1"], capture_output=True,
                             text=True, encoding="utf-8", errors="replace", env=env,
                             cwd=ROOT, timeout=120)
        second = json.loads((run.stdout or "").strip().splitlines()[-1])
        self.assertEqual(run.returncode, 0, second)
        self.assertEqual(first["result"]["job"]["id"], second["result"]["job"]["id"])
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM legacy_import_jobs;"), "1")
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM legacy_import_records;"), "6")

    def test_exact_live_customer_is_skipped_and_different_same_mobile_conflicts(self):
        now = "2026-10-15 17:00:00"
        target = str(uuid.uuid4())
        self._sql(
            "INSERT INTO customers (id,tenant_id,legacy_id,row_version,created_at,updated_at,full_name,address,mobile,telegram_id,instagram_id,notes) "
            "VALUES ('%s','%s','server-customer',1,'%s','%s','Legacy Customer','Old address','09120000001','','','');" %
            (target, self.tenant, now, now)
        )
        store = self.base_store()
        # Avoid unrelated invalid tx device reference by preserving its source device.
        code, exact, _path = self._run(store)
        self.assertEqual(code, 0, exact)
        customer = next(r for r in exact["result"]["records"] if r["entity"] == "customers")
        self.assertEqual(customer["action"], "skip")
        self.assertEqual(customer["target_id"], target)

        self.setUp()
        self._sql(
            "INSERT INTO customers (id,tenant_id,legacy_id,row_version,created_at,updated_at,full_name,address,mobile,telegram_id,instagram_id,notes) "
            "VALUES ('%s','%s','server-customer',1,'%s','%s','Different Name','Old address','09120000001','','','');" %
            (target, self.tenant, now, now)
        )
        code, conflict, _path = self._run(store)
        self.assertEqual(code, 0, conflict)
        customer = next(r for r in conflict["result"]["records"] if r["entity"] == "customers")
        self.assertEqual(customer["action"], "conflict")
        self.assertEqual(conflict["result"]["job"]["status"], "review")

    def test_orphan_reference_is_invalid_and_newer_version_is_refused(self):
        store = self.base_store()
        store["devices"][0]["customer_id"] = "missing-customer"
        code, payload, _path = self._run(store)
        self.assertEqual(code, 0, payload)
        device = next(r for r in payload["result"]["records"] if r["entity"] == "crm_devices")
        self.assertEqual(device["action"], "invalid")
        self.assertTrue(any(i["code"] == "ORPHAN_REFERENCE" and i["field"] == "customer_id" for i in device["issues"]))
        self.assertEqual(payload["result"]["job"]["status"], "review")

        self.setUp()
        code, rejected, _path = self._run(self.base_store(), "1.14.0")
        self.assertNotEqual(code, 0)
        self.assertEqual((rejected["status"], rejected["code"]), (400, "VALIDATION_FAILED"))
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM legacy_import_jobs;"), "0")


if __name__ == "__main__":
    unittest.main()
