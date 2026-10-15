# -*- coding: utf-8 -*-
"""Real MariaDB concurrency tests for atomic ledger void + reversal."""
import json
import os
import shutil
import subprocess
import tempfile
import unittest
import uuid
from concurrent.futures import ThreadPoolExecutor

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


class FinanceVoidStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = read(os.path.join(HOST, "src", "Finance.php"))

    def test_void_is_atomic_idempotent_and_preserves_accounting_predicate(self):
        self.assertIn("public function void", self.source)
        self.assertIn("FOR UPDATE", self.source)
        self.assertIn("paired registry fee row is still active", self.source)
        self.assertIn("'kind' => 'void'", self.source)
        self.assertIn("'voided_at' => Schema::toWireTimestamp($now)", self.source)
        self.assertIn("foreach ([", self.source)
        self.assertIn("'action' => 'finance.void'", self.source)


class FinanceVoidMariaDbTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mysql = os.environ.get("IRICA_MARIADB") or shutil.which("mariadb") or shutil.which("mysql")
        cls.php = os.environ.get("IRICA_PHP") or shutil.which("php")
        cls.password = os.environ.get("IRICA_DB_ROOT_PASSWORD")
        cls.host = os.environ.get("IRICA_DB_HOST", "127.0.0.1")
        cls.port = os.environ.get("IRICA_DB_PORT", "3307")
        if not cls.mysql or not cls.php or not cls.password:
            raise unittest.SkipTest("MariaDB/PHP test service is not configured")
        cls.db = "irica_void_%s" % uuid.uuid4().hex[:12]
        cls.tenant = str(uuid.uuid4())
        cls.user = str(uuid.uuid4())
        cls.customer = str(uuid.uuid4())
        cls.source_installation = str(uuid.uuid4())
        cls._sql("CREATE DATABASE `%s` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;" % cls.db, select_db=False)
        try:
            for filename in MIGRATION_FILES:
                cls._sql(read(os.path.join(MIGRATIONS, filename)))
            cls._seed()
            cls.script_dir = tempfile.mkdtemp(prefix="irica_void_php_")
            cls.script = os.path.join(cls.script_dir, "finance.php")
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
        env = dict(os.environ)
        env["MYSQL_PWD"] = cls.password
        run = subprocess.run(cmd, input=sql, capture_output=True, text=True,
                             encoding="utf-8", errors="replace", env=env, timeout=180)
        if check and run.returncode != 0:
            raise AssertionError("SQL failed (exit %d): %s" % (run.returncode, (run.stderr or "")[:1600]))
        return run.stdout or ""

    @classmethod
    def scalar(cls, sql):
        out = cls._sql(sql).strip().splitlines()
        return out[-1] if out else ""

    @classmethod
    def _seed(cls):
        now = "2026-10-15 17:00:00"
        membership = str(uuid.uuid4())
        cls._sql("\n".join([
            "INSERT INTO tenants (id,slug,name,status,created_at,updated_at) VALUES ('%s','void-v2','Void Test','active','%s','%s');" % (cls.tenant, now, now),
            "INSERT INTO users (id,tenant_id,username,password_hash,display_name,must_change_password,status,token_version,row_version,created_at,updated_at) VALUES ('%s','%s','void-user','test-hash-not-a-credential','',0,'active',1,1,'%s','%s');" % (cls.user, cls.tenant, now, now),
            "INSERT INTO memberships (id,tenant_id,user_id,role,created_at,updated_at) VALUES ('%s','%s','%s','user','%s','%s');" % (membership, cls.tenant, cls.user, now, now),
            "INSERT INTO tenant_state (tenant_id,dataset_epoch,bootstrap_status,source_installation_id,created_at,updated_at) VALUES ('%s',1,'done','%s','%s','%s');" % (cls.tenant, cls.source_installation, now, now),
            "INSERT INTO customers (id,tenant_id,legacy_id,row_version,created_at,updated_at,full_name) VALUES ('%s','%s','cust-void',1,'%s','%s','Void Customer');" % (cls.customer, cls.tenant, now, now),
        ]))

    @classmethod
    def _write_script(cls):
        names = ("Schema", "Database", "Http", "Ids", "Log", "Tokens", "Roles", "RateLimit", "Auth", "Finance")
        lines = ["<?php", "declare(strict_types=1);"]
        for name in names:
            lines.append("require_once %s;" % json.dumps(os.path.join(HOST, "src", name + ".php").replace("\\", "/")))
        lines.extend([
            "$db=Database::fromConfig(['host'=>getenv('IRICA_DB_HOST'),'port'=>(int)getenv('IRICA_DB_PORT'),'dbname'=>getenv('IRICA_VOID_DB'),'user'=>'root','password'=>getenv('IRICA_DB_ROOT_PASSWORD')]);",
            "$svc=new Finance($db,new Log(null),['idempotency_retention_days'=>30]);",
            "$tenant=getenv('IRICA_VOID_TENANT'); $user=getenv('IRICA_VOID_USER');",
            "$principal=new Principal(Tokens::KIND_USER,$user,$tenant,Roles::USER,$user,'',Ids::v4(),1);",
            "$ctx=['device'=>null,'user'=>$principal,'role'=>Roles::USER];",
            "try{if($argv[1]==='append'){$body=['operation_id'=>$argv[2],'customer_id'=>getenv('IRICA_VOID_CUSTOMER'),'amount'=>(int)$argv[3],'note'=>'seed','kind'=>'receipt','image'=>'','device_id'=>null];$result=$svc->append($body,$ctx,Ids::v4());}else{$body=['operation_id'=>$argv[2],'transaction_id'=>$argv[3],'reason'=>$argv[4] ?? ''];$result=$svc->void($body,$ctx,Ids::v4());}echo json_encode(['ok'=>true,'result'=>$result]);}catch(ApiException $e){echo json_encode(['ok'=>false,'status'=>$e->status,'code'=>$e->errorCode]);exit(2);}",
        ])
        with open(cls.script, "w", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")

    def _run(self, args):
        env = dict(os.environ)
        env.update({
            "IRICA_DB_ROOT_PASSWORD": self.password,
            "IRICA_DB_HOST": self.host,
            "IRICA_DB_PORT": str(self.port),
            "IRICA_VOID_DB": self.db,
            "IRICA_VOID_TENANT": self.tenant,
            "IRICA_VOID_USER": self.user,
            "IRICA_VOID_CUSTOMER": self.customer,
        })
        run = subprocess.run([self.php, self.script] + list(args), capture_output=True,
                             text=True, encoding="utf-8", errors="replace",
                             env=env, cwd=ROOT, timeout=120)
        payload = json.loads((run.stdout or "").strip().splitlines()[-1])
        return run.returncode, payload

    def _append(self, amount):
        op = str(uuid.uuid4())
        code, payload = self._run(["append", op, str(amount)])
        self.assertEqual(code, 0)
        return payload["result"]["transaction"]

    def _void(self, operation_id, transaction_id, reason="operator correction"):
        return self._run(["void", operation_id, transaction_id, reason])

    def test_void_and_retry_create_exactly_one_inactive_pair(self):
        original = self._append(1250)
        op = str(uuid.uuid4())
        code, first = self._void(op, original["id"])
        self.assertEqual(code, 0)
        code, replay = self._void(op, original["id"])
        self.assertEqual(code, 0)
        self.assertEqual(first["result"], replay["result"])

        result = first["result"]
        reversal = result["reversal"]
        self.assertEqual(result["original"]["id"], original["id"])
        self.assertEqual(reversal["record"]["amount"], -1250)
        self.assertEqual(reversal["record"]["kind"], "void")
        self.assertNotEqual(reversal["id"], op)
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM change_log WHERE operation_id='%s';" % op), "2")
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM customer_transactions WHERE id='%s' AND voided_at IS NOT NULL;" % original["id"]), "1")
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM customer_transactions WHERE id='%s' AND kind='void';" % reversal["id"]), "1")
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM customer_transactions WHERE customer_id='%s' AND voided_at IS NULL AND kind <> 'void' AND id IN ('%s','%s');" % (self.customer, original["id"], reversal["id"])), "0")

    def test_two_different_void_operations_cannot_double_reverse(self):
        original = self._append(900)
        before = int(self.scalar("SELECT COUNT(*) FROM customer_transactions WHERE customer_id='%s';" % self.customer))
        operations = [str(uuid.uuid4()), str(uuid.uuid4())]
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda op: self._void(op, original["id"], "race"), operations))
        successes = [payload for code, payload in results if code == 0]
        failures = [payload for code, payload in results if code != 0]
        self.assertEqual(len(successes), 1)
        self.assertEqual(len(failures), 1)
        self.assertEqual((failures[0]["status"], failures[0]["code"]), (409, "VERSION_CONFLICT"))
        after = int(self.scalar("SELECT COUNT(*) FROM customer_transactions WHERE customer_id='%s';" % self.customer))
        self.assertEqual(after, before + 1)

    def test_reason_is_required_before_any_financial_write(self):
        original = self._append(400)
        op = str(uuid.uuid4())
        code, payload = self._void(op, original["id"], "")
        self.assertNotEqual(code, 0)
        self.assertEqual((payload["status"], payload["code"]), (400, "VALIDATION_FAILED"))
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM change_log WHERE operation_id='%s';" % op), "0")
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM customer_transactions WHERE id='%s' AND voided_at IS NOT NULL;" % original["id"]), "0")

    def test_reversal_cannot_be_voided_again(self):
        original = self._append(200)
        op = str(uuid.uuid4())
        code, payload = self._void(op, original["id"])
        self.assertEqual(code, 0)
        reversal_id = payload["result"]["reversal"]["id"]
        code, second = self._void(str(uuid.uuid4()), reversal_id)
        self.assertNotEqual(code, 0)
        self.assertEqual((second["status"], second["code"]), (409, "VERSION_CONFLICT"))


if __name__ == "__main__":
    unittest.main()
