# -*- coding: utf-8 -*-
"""Real MariaDB concurrency coverage for the server-authoritative ledger."""
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


class FinanceStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = read(os.path.join(HOST, "src", "Finance.php"))

    def test_append_contract_is_transactional_and_integer_only(self):
        self.assertIn("$this->db->transaction", self.source)
        self.assertIn("FOR UPDATE", self.source)
        self.assertIn("MAX(seq)", self.source)
        self.assertIn("is_bool($amount) || !is_int($amount)", self.source)
        self.assertIn("ON DUPLICATE KEY UPDATE operation_id = operation_id", self.source)
        self.assertIn("IDEMPOTENCY_MISMATCH", self.source)
        self.assertNotIn("floatval", self.source)
        self.assertNotIn("(float)", self.source)


class FinanceMariaDbTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mysql = os.environ.get("IRICA_MARIADB") or shutil.which("mariadb") or shutil.which("mysql")
        cls.php = os.environ.get("IRICA_PHP") or shutil.which("php")
        cls.password = os.environ.get("IRICA_DB_ROOT_PASSWORD")
        cls.host = os.environ.get("IRICA_DB_HOST", "127.0.0.1")
        cls.port = os.environ.get("IRICA_DB_PORT", "3307")
        if not cls.mysql or not cls.php or not cls.password:
            raise unittest.SkipTest("MariaDB/PHP test service is not configured")

        cls.db = "irica_finance_%s" % uuid.uuid4().hex[:12]
        cls.tenant = str(uuid.uuid4())
        cls.user = str(uuid.uuid4())
        cls.customer = str(uuid.uuid4())
        cls._sql("CREATE DATABASE `%s` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;" % cls.db, select_db=False)
        try:
            for filename in MIGRATION_FILES:
                cls._sql(read(os.path.join(MIGRATIONS, filename)))
            cls._seed()
            cls.script_dir = tempfile.mkdtemp(prefix="irica_finance_php_")
            cls.script = os.path.join(cls.script_dir, "append.php")
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
            raise AssertionError("SQL failed (exit %d): %s" % (run.returncode, (run.stderr or "")[:1600]))
        return run.stdout or ""

    @classmethod
    def scalar(cls, sql):
        out = cls._sql(sql).strip().splitlines()
        return out[-1] if out else ""

    @classmethod
    def _seed(cls):
        now = "2026-10-15 16:30:00"
        membership = str(uuid.uuid4())
        sql = "\n".join([
            "INSERT INTO tenants (id,slug,name,status,created_at,updated_at) VALUES ('%s','finance-v2','Finance Test','active','%s','%s');" % (cls.tenant, now, now),
            "INSERT INTO users (id,tenant_id,username,password_hash,display_name,must_change_password,status,token_version,row_version,created_at,updated_at) VALUES ('%s','%s','finance-user','test-hash-not-a-credential','',0,'active',1,1,'%s','%s');" % (cls.user, cls.tenant, now, now),
            "INSERT INTO memberships (id,tenant_id,user_id,role,created_at,updated_at) VALUES ('%s','%s','%s','user','%s','%s');" % (membership, cls.tenant, cls.user, now, now),
            "INSERT INTO customers (id,tenant_id,legacy_id,row_version,created_at,updated_at,full_name) VALUES ('%s','%s','cust-finance',1,'%s','%s','Finance Customer');" % (cls.customer, cls.tenant, now, now),
        ])
        cls._sql(sql)

    @classmethod
    def _write_script(cls):
        required = ("Schema", "Database", "Http", "Ids", "Log", "Tokens", "Roles", "RateLimit", "Auth", "Finance")
        lines = ["<?php", "declare(strict_types=1);"]
        for name in required:
            lines.append("require_once %s;" % json.dumps(os.path.join(HOST, "src", name + ".php").replace("\\", "/")))
        lines.extend([
            "$db=Database::fromConfig(['host'=>getenv('IRICA_DB_HOST'),'port'=>(int)getenv('IRICA_DB_PORT'),'dbname'=>getenv('IRICA_FINANCE_DB'),'user'=>'root','password'=>getenv('IRICA_DB_ROOT_PASSWORD')]);",
            "$svc=new Finance($db,new Log(null),['idempotency_retention_days'=>30]);",
            "$tenant=getenv('IRICA_FINANCE_TENANT'); $user=getenv('IRICA_FINANCE_USER');",
            "$principal=new Principal(Tokens::KIND_USER,$user,$tenant,Roles::USER,$user,'',Ids::v4(),1);",
            "$body=['operation_id'=>$argv[1],'customer_id'=>getenv('IRICA_FINANCE_CUSTOMER'),'amount'=>(int)$argv[2],'note'=>$argv[3] ?? '','kind'=>'receipt','image'=>'','device_id'=>null];",
            "try{$result=$svc->append($body,['device'=>null,'user'=>$principal,'role'=>Roles::USER],Ids::v4());echo json_encode(['ok'=>true,'result'=>$result]);}catch(ApiException $e){echo json_encode(['ok'=>false,'status'=>$e->status,'code'=>$e->errorCode]);exit(2);}",
        ])
        with open(cls.script, "w", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")

    def _append(self, operation_id, amount, note=""):
        env = dict(os.environ)
        env.update({
            "IRICA_DB_ROOT_PASSWORD": self.password,
            "IRICA_DB_HOST": self.host,
            "IRICA_DB_PORT": str(self.port),
            "IRICA_FINANCE_DB": self.db,
            "IRICA_FINANCE_TENANT": self.tenant,
            "IRICA_FINANCE_USER": self.user,
            "IRICA_FINANCE_CUSTOMER": self.customer,
        })
        run = subprocess.run(
            [self.php, self.script, operation_id, str(amount), note],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            env=env, cwd=ROOT, timeout=120,
        )
        payload = json.loads((run.stdout or "").strip().splitlines()[-1])
        return run.returncode, payload

    def test_concurrent_appends_preserve_every_entry_and_allocate_unique_seq(self):
        operations = [(str(uuid.uuid4()), 1000 + i, "parallel-%d" % i) for i in range(8)]
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda args: self._append(*args), operations))
        self.assertTrue(all(code == 0 and payload["ok"] for code, payload in results))

        rows = self._sql(
            "SELECT seq,amount,note FROM customer_transactions WHERE tenant_id='%s' AND customer_id='%s' ORDER BY seq;" % (self.tenant, self.customer)
        ).strip().splitlines()
        parsed = [(int(line.split("\t")[0]), int(line.split("\t")[1]), line.split("\t")[2]) for line in rows]
        self.assertEqual([seq for seq, _amount, _note in parsed], list(range(8)))
        self.assertEqual(sorted(amount for _seq, amount, _note in parsed), list(range(1000, 1008)))
        self.assertEqual(len({note for _seq, _amount, note in parsed}), 8)
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM change_log WHERE tenant_id='%s' AND entity='customer_transactions';" % self.tenant), "8")

    def test_concurrent_retry_of_same_operation_books_once(self):
        op = str(uuid.uuid4())
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _n: self._append(op, 777, "retry-once"), range(2)))
        self.assertTrue(all(code == 0 and payload["ok"] for code, payload in results))
        ids = [payload["result"]["transaction"]["id"] for _code, payload in results]
        seqs = [payload["result"]["transaction"]["record"]["seq"] for _code, payload in results]
        self.assertEqual(ids, [op, op])
        self.assertEqual(seqs[0], seqs[1])
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM customer_transactions WHERE id='%s';" % op), "1")
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM change_log WHERE operation_id='%s';" % op), "1")

    def test_reusing_operation_id_with_different_money_is_rejected(self):
        op = str(uuid.uuid4())
        code, first = self._append(op, 300, "same-op")
        self.assertEqual(code, 0)
        self.assertTrue(first["ok"])
        code, second = self._append(op, 301, "same-op")
        self.assertNotEqual(code, 0)
        self.assertEqual((second["status"], second["code"]), (409, "IDEMPOTENCY_MISMATCH"))
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM customer_transactions WHERE id='%s';" % op), "1")
        self.assertEqual(self.scalar("SELECT amount FROM customer_transactions WHERE id='%s';" % op), "300")

    def test_non_integer_amount_is_rejected_without_a_row(self):
        # The service itself receives the invalid value through a tiny direct
        # PHP probe because the normal append helper intentionally casts CLI
        # input to int before calling the service.
        source = read(self.script)
        source = source.replace("'amount'=>(int)$argv[2]", "'amount'=>1.25")
        path = os.path.join(self.script_dir, "bad-amount.php")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(source)
        env = dict(os.environ)
        env.update({
            "IRICA_DB_ROOT_PASSWORD": self.password,
            "IRICA_DB_HOST": self.host,
            "IRICA_DB_PORT": str(self.port),
            "IRICA_FINANCE_DB": self.db,
            "IRICA_FINANCE_TENANT": self.tenant,
            "IRICA_FINANCE_USER": self.user,
            "IRICA_FINANCE_CUSTOMER": self.customer,
        })
        op = str(uuid.uuid4())
        run = subprocess.run([self.php, path, op, "1", "float"], capture_output=True, text=True, encoding="utf-8", errors="replace", env=env, cwd=ROOT, timeout=120)
        payload = json.loads((run.stdout or "").strip().splitlines()[-1])
        self.assertEqual((payload["status"], payload["code"]), (400, "VALIDATION_FAILED"))
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM customer_transactions WHERE id='%s';" % op), "0")


if __name__ == "__main__":
    unittest.main()
