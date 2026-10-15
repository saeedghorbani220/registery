# -*- coding: utf-8 -*-
"""Real MariaDB tests for reviewed, atomic legacy migration apply."""
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
    "004_legacy_import_verification.sql",
)


def read(path):
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


class LegacyApplyStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = read(os.path.join(HOST, "src", "LegacyApply.php"))

    def test_apply_locks_authority_and_financial_customer(self):
        self.assertIn("tenant_state WHERE tenant_id=? FOR UPDATE", self.source)
        self.assertIn("SELECT id,legacy_id FROM customers", self.source)
        self.assertIn("WHERE id=? AND tenant_id=? AND deleted_at IS NULL FOR UPDATE", self.source)
        self.assertIn("MAX(seq)", self.source)
        self.assertIn("Ids::transactionLegacyId", self.source)
        self.assertIn("Ids::uuid5", self.source)

    def test_merge_preserves_non_empty_online_values(self):
        self.assertIn("$this->blank($base[$key])", self.source)
        self.assertNotIn("DELETE FROM customers", self.source)
        self.assertNotIn("source_installation_id=?", self.source.split("if (!is_string($datasetSource)", 1)[0])


class LegacyApplyMariaDbTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mysql = os.environ.get("IRICA_MARIADB") or shutil.which("mariadb") or shutil.which("mysql")
        cls.php = os.environ.get("IRICA_PHP") or shutil.which("php")
        cls.password = os.environ.get("IRICA_DB_ROOT_PASSWORD")
        cls.host = os.environ.get("IRICA_DB_HOST", "127.0.0.1")
        cls.port = os.environ.get("IRICA_DB_PORT", "3307")
        if not cls.mysql or not cls.php or not cls.password:
            raise unittest.SkipTest("MariaDB/PHP test service is not configured")
        cls.db = "irica_legacy_apply_%s" % uuid.uuid4().hex[:10]
        cls.tenant = str(uuid.uuid4())
        cls.user = str(uuid.uuid4())
        cls.dataset_source = str(uuid.uuid4())
        cls._sql("CREATE DATABASE `%s` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;" % cls.db, select_db=False)
        try:
            for filename in MIGRATION_FILES:
                cls._sql(read(os.path.join(MIGRATIONS, filename)))
            cls._seed()
            cls.tmp = tempfile.mkdtemp(prefix="irica_legacy_apply_php_")
            cls.script = os.path.join(cls.tmp, "legacy.php")
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
            raise AssertionError("SQL failed (exit %d): %s" % (run.returncode, (run.stderr or "")[:1800]))
        return run.stdout or ""

    @classmethod
    def scalar(cls, sql):
        lines = cls._sql(sql).strip().splitlines()
        return lines[-1] if lines else ""

    @classmethod
    def _seed(cls):
        now = "2026-10-15 17:20:00"
        membership = str(uuid.uuid4())
        cls._sql("\n".join([
            "INSERT INTO tenants (id,slug,name,status,created_at,updated_at) VALUES ('%s','legacy-apply','Legacy Apply','active','%s','%s');" % (cls.tenant, now, now),
            "INSERT INTO users (id,tenant_id,username,password_hash,display_name,must_change_password,status,token_version,row_version,created_at,updated_at) VALUES ('%s','%s','legacy-admin','test-hash-not-a-credential','',0,'active',1,1,'%s','%s');" % (cls.user, cls.tenant, now, now),
            "INSERT INTO memberships (id,tenant_id,user_id,role,created_at,updated_at) VALUES ('%s','%s','%s','admin','%s','%s');" % (membership, cls.tenant, cls.user, now, now),
            "INSERT INTO tenant_state (tenant_id,dataset_epoch,bootstrap_status,source_installation_id,created_at,updated_at) VALUES ('%s',1,'done','%s','%s','%s');" % (cls.tenant, cls.dataset_source, now, now),
        ]))

    @classmethod
    def _write_script(cls):
        required = ("Schema", "Database", "Http", "Ids", "Log", "Tokens", "Roles", "RateLimit", "Auth", "Sync", "LegacyImport", "LegacyVerify", "LegacyApply")
        lines = ["<?php", "declare(strict_types=1);"]
        for name in required:
            lines.append("require_once %s;" % json.dumps(os.path.join(HOST, "src", name + ".php").replace("\\", "/")))
        lines.extend([
            "$db=Database::fromConfig(['host'=>getenv('IRICA_DB_HOST'),'port'=>(int)getenv('IRICA_DB_PORT'),'dbname'=>getenv('IRICA_LEGACY_DB'),'user'=>'root','password'=>getenv('IRICA_DB_ROOT_PASSWORD')]);",
            "$log=new Log(null); $sync=new Sync($db,$log,[]);",
            "$import=new LegacyImport($db,$sync,$log,['limits'=>['max_import_body_bytes'=>16777216]]); $verify=new LegacyVerify($db,$log,[]); $apply=new LegacyApply($db,$sync,$log,[]);",
            "$tenant=getenv('IRICA_LEGACY_TENANT'); $user=getenv('IRICA_LEGACY_USER'); $p=new Principal(Tokens::KIND_USER,$user,$tenant,Roles::ADMIN,$user,'',Ids::v4(),1);",
            "$action=$argv[1]; try { if($action==='analyze'){$body=['source_text'=>file_get_contents($argv[2]),'filename'=>basename($argv[2]),'source_version'=>'1.13.1'];$r=$import->analyze($p,$body,Ids::v4(),'127.0.0.1');} elseif($action==='apply'){$r=$apply->apply($p,$argv[2],Ids::v4(),'127.0.0.1');} elseif($action==='verify'){$r=$verify->report($p,$argv[2]);} elseif($action==='decide'){$body=['job_id'=>$argv[2],'record_id'=>$argv[3],'resolution'=>$argv[4]];if(isset($argv[5])&&$argv[5]!==''){$body['target_id']=$argv[5];}$r=$apply->decide($p,$body,Ids::v4(),'127.0.0.1');} elseif($action==='review'){$r=$apply->review($p,$argv[2]);} else {throw new RuntimeException('bad action');} echo json_encode(['ok'=>true,'result'=>$r],JSON_UNESCAPED_UNICODE); } catch(ApiException $e){echo json_encode(['ok'=>false,'status'=>$e->status,'code'=>$e->errorCode]);exit(2);} catch(Throwable $e){echo json_encode(['ok'=>false,'status'=>500,'code'=>'SERVER_ERROR']);exit(3);}",
        ])
        with open(cls.script, "w", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")

    def setUp(self):
        self._sql("DELETE FROM legacy_import_verifications; DELETE FROM legacy_import_decisions; DELETE FROM legacy_import_records; DELETE FROM legacy_import_jobs; DELETE FROM audit_events WHERE action LIKE 'legacy_import.%';")
        self._sql("DELETE FROM change_log; DELETE FROM customer_transactions; DELETE FROM crm_devices; DELETE FROM owners; DELETE FROM identities; DELETE FROM settings; DELETE FROM periods; DELETE FROM customers;")
        self._sql("UPDATE tenant_state SET dataset_epoch=1,bootstrap_status='done',source_installation_id='%s',last_import_id=NULL,last_import_hash=NULL;" % self.dataset_source)

    @staticmethod
    def store(note=""):
        return {
            "customers": [{
                "id": "cust0001", "full_name": "Legacy Customer",
                "address": "Old address", "mobile": "09120000001",
                "notes": note, "created": "2026-01-01 12:00:00",
                "transactions": [{"at": "2026-01-02 12:00:00", "amount": 1200,
                                  "note": "receipt", "kind": "receipt",
                                  "image": "", "device_id": ""}],
            }],
            "owners": [], "identities": [], "devices": [], "periods": [],
        }


    @staticmethod
    def rich_store():
        return {
            "customers": [
                {
                    "id": "cust1001", "full_name": "Legacy One",
                    "address": "Address One", "mobile": "09120001001",
                    "notes": "first", "created": "2026-01-01 08:00:00",
                    "transactions": [
                        {"at": "2026-01-03 10:00:00", "amount": 5000,
                         "note": "received", "kind": "receipt", "image": "",
                         "device_id": "devdone1"},
                        {"at": "2026-01-04 10:00:00", "amount": -1200,
                         "note": "debt", "kind": "debt", "image": "",
                         "device_id": "devprob1"},
                    ],
                },
                {
                    "id": "cust1002", "full_name": "Legacy Two",
                    "address": "Address Two", "mobile": "09120001002",
                    "notes": "second", "created": "2026-02-01 08:00:00",
                    "transactions": [
                        {"at": "2026-02-03 11:00:00", "amount": 2500,
                         "note": "received", "kind": "receipt", "image": "",
                         "device_id": "devclose1"},
                        {"at": "2026-02-04 11:00:00", "amount": -500,
                         "note": "debt", "kind": "debt", "image": "",
                         "device_id": "devclose1"},
                    ],
                },
            ],
            "owners": [
                {"id": "owner001", "first_name": "Owner", "last_name": "One",
                 "national": "0012345678", "birth": "1370/01/02",
                 "mobile": "09121111001", "card_no": "",
                 "passport": "A10001", "created": "2026-01-01 09:00:00"},
                {"id": "owner002", "first_name": "Owner", "last_name": "Two",
                 "national": "0012345679", "birth": "1371/02/03",
                 "mobile": "09121111002", "card_no": "",
                 "passport": "A10002", "created": "2026-02-01 09:00:00"},
            ],
            "identities": [
                {"id": "ident001", "label": "Pool One", "national": "0022345678",
                 "birth": "1372/03/04", "mobile": "09122222001",
                 "created": "2026-01-01 09:30:00"},
                {"id": "ident002", "label": "Pool Two", "national": "0022345679",
                 "birth": "1373/04/05", "mobile": "09122222002",
                 "created": "2026-02-01 09:30:00"},
            ],
            "periods": [
                {"id": "period01", "number": 1, "label": "First",
                 "opened_at": "2026-01-01 07:00:00", "opened_by": "legacy"},
                {"id": "period02", "number": 2, "label": "Second",
                 "opened_at": "2026-02-01 07:00:00", "opened_by": "legacy",
                 "closed_at": "2026-02-28 19:00:00", "closed_by": "legacy",
                 "closed_reason": "month end"},
            ],
            "devices": [
                {"id": "devdone1", "name": "Done Phone",
                 "serial1": "350000000000001", "serial2": "",
                 "customer_id": "cust1001", "owner_id": "owner001",
                 "period_id": "period01", "stage": "done", "auto_advance": False,
                 "done_at": "2026-01-20 12:00:00", "notes": "done case",
                 "created": "2026-01-02 08:00:00"},
                {"id": "devclose1", "name": "Closed Phone",
                 "serial1": "350000000000002", "serial2": "",
                 "customer_id": "cust1002", "owner_id": "owner002",
                 "period_id": "period02", "stage": "closed", "auto_advance": False,
                 "closed_at": "2026-02-20 12:00:00", "closed_reason": "cancelled",
                 "notes": "closed case", "created": "2026-02-02 08:00:00"},
                {"id": "devprob1", "name": "Problem Phone",
                 "serial1": "350000000000003", "serial2": "",
                 "customer_id": "cust1001", "owner_id": "",
                 "period_id": "period01", "stage": "problem", "auto_advance": False,
                 "notes": "problem case", "created": "2026-01-05 08:00:00"},
            ],
            "settings": {
                "business_name": "Migrated Business",
                "registry_fee_amount": 123456,
                "current_period_id": "period02",
            },
        }

    def _file(self, store):
        fd, path = tempfile.mkstemp(prefix="legacy_apply_", suffix=".json", dir=self.tmp)
        os.close(fd)
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(store, handle, ensure_ascii=False, separators=(",", ":"))
        return path

    def _call(self, *args):
        env = dict(os.environ)
        env.update({"IRICA_DB_ROOT_PASSWORD": self.password,
                    "IRICA_DB_HOST": self.host, "IRICA_DB_PORT": str(self.port),
                    "IRICA_LEGACY_DB": self.db, "IRICA_LEGACY_TENANT": self.tenant,
                    "IRICA_LEGACY_USER": self.user})
        run = subprocess.run([self.php, self.script, *args], capture_output=True,
                             text=True, encoding="utf-8", errors="replace", env=env,
                             cwd=ROOT, timeout=120)
        payload = json.loads((run.stdout or "").strip().splitlines()[-1])
        return run.returncode, payload

    def _analyze(self, store):
        code, payload = self._call("analyze", self._file(store))
        self.assertEqual(code, 0, payload)
        return payload["result"]


    def test_rich_dataset_reconciles_counts_links_stages_and_financial_sums(self):
        source = self.rich_store()
        source_tx_count = sum(len(c.get("transactions") or [])
                              for c in source["customers"])
        source_sum = sum(tx["amount"] for c in source["customers"]
                         for tx in c.get("transactions") or [])

        staged = self._analyze(source)
        unresolved = [r for r in staged["records"] if r.get("action") in ("pending", "conflict", "invalid")]
        self.assertEqual(unresolved, [])
        job = staged["job"]["id"]
        code, applied = self._call("apply", job)
        self.assertEqual(code, 0, applied)
        self.assertFalse(applied["result"]["replayed"])
        self.assertEqual(applied["result"]["counts"]["created"], 16)

        expected_counts = {
            "customers": 2,
            "owners": 2,
            "identities": 2,
            "crm_devices": 3,
            "periods": 2,
            "customer_transactions": source_tx_count,
            "settings": 1,
        }
        for table, expected in expected_counts.items():
            actual = self.scalar(
                "SELECT COUNT(*) FROM %s WHERE tenant_id='%s' AND deleted_at IS NULL;"
                % (table, self.tenant))
            self.assertEqual(actual, str(expected), table)

        balances = self._sql(
            "SELECT c.legacy_id,COALESCE(SUM(t.amount),0) "
            "FROM customers c LEFT JOIN customer_transactions t "
            "ON t.customer_id=c.id AND t.tenant_id=c.tenant_id "
            "AND t.deleted_at IS NULL WHERE c.tenant_id='%s' "
            "AND c.deleted_at IS NULL GROUP BY c.id,c.legacy_id "
            "ORDER BY c.legacy_id;" % self.tenant
        ).strip().splitlines()
        self.assertEqual(balances, ["cust1001\t3800", "cust1002\t2000"])
        self.assertEqual(
            self.scalar("SELECT COALESCE(SUM(amount),0) FROM customer_transactions "
                        "WHERE tenant_id='%s' AND deleted_at IS NULL;" % self.tenant),
            str(source_sum))

        stage_counts = self._sql(
            "SELECT stage,COUNT(*) FROM crm_devices WHERE tenant_id='%s' "
            "AND deleted_at IS NULL GROUP BY stage ORDER BY stage;" % self.tenant
        ).strip().splitlines()
        self.assertEqual(stage_counts, ["closed\t1", "done\t1", "problem\t1"])

        links = self._sql(
            "SELECT d.legacy_id,c.legacy_id,COALESCE(o.legacy_id,''),"
            "p.legacy_id,d.stage FROM crm_devices d "
            "JOIN customers c ON c.id=d.customer_id "
            "LEFT JOIN owners o ON o.id=d.owner_id "
            "JOIN periods p ON p.id=d.period_id "
            "WHERE d.tenant_id='%s' AND d.deleted_at IS NULL "
            "ORDER BY d.legacy_id;" % self.tenant
        ).strip().splitlines()
        self.assertEqual(links, [
            "devclose1\tcust1002\towner002\tperiod02\tclosed",
            "devdone1\tcust1001\towner001\tperiod01\tdone",
            "devprob1\tcust1001\t\tperiod01\tproblem",
        ])

        tx_links = self._sql(
            "SELECT c.legacy_id,t.seq,COALESCE(d.legacy_id,''),t.amount "
            "FROM customer_transactions t JOIN customers c ON c.id=t.customer_id "
            "LEFT JOIN crm_devices d ON d.id=t.device_id "
            "WHERE t.tenant_id='%s' AND t.deleted_at IS NULL "
            "ORDER BY c.legacy_id,t.seq;" % self.tenant
        ).strip().splitlines()
        self.assertEqual(tx_links, [
            "cust1001\t0\tdevdone1\t5000",
            "cust1001\t1\tdevprob1\t-1200",
            "cust1002\t0\tdevclose1\t2500",
            "cust1002\t1\tdevclose1\t-500",
        ])

        current_period = self.scalar(
            "SELECT p.legacy_id FROM settings s JOIN periods p "
            "ON p.id=s.current_period_id WHERE s.tenant_id='%s' "
            "AND s.deleted_at IS NULL;" % self.tenant)
        self.assertEqual(current_period, "period02")
        self.assertEqual(self.scalar(
            "SELECT business_name FROM settings WHERE tenant_id='%s';" % self.tenant),
            "Migrated Business")

        change_count = self.scalar(
            "SELECT COUNT(*) FROM change_log WHERE tenant_id='%s' AND operation_id='%s';"
            % (self.tenant, job))
        self.assertEqual(change_count, "16")

        code, replay = self._call("apply", job)
        self.assertEqual(code, 0, replay)
        self.assertTrue(replay["result"]["replayed"])
        for table, expected in expected_counts.items():
            self.assertEqual(self.scalar(
                "SELECT COUNT(*) FROM %s WHERE tenant_id='%s' AND deleted_at IS NULL;"
                % (table, self.tenant)), str(expected), table)
        self.assertEqual(self.scalar(
            "SELECT COALESCE(SUM(amount),0) FROM customer_transactions "
            "WHERE tenant_id='%s' AND deleted_at IS NULL;" % self.tenant),
            str(source_sum))
        self.assertEqual(self.scalar(
            "SELECT COUNT(*) FROM change_log WHERE tenant_id='%s' AND operation_id='%s';"
            % (self.tenant, job)), "16")

    def test_clean_apply_uses_dataset_uuid_mapping_and_replays_without_duplicates(self):
        staged = self._analyze(self.store())
        job = staged["job"]["id"]
        code, applied = self._call("apply", job)
        self.assertEqual(code, 0, applied)
        self.assertEqual(applied["result"]["counts"]["created"], 2)
        expected_customer = str(uuid.uuid5(uuid.NAMESPACE_URL,
            "%s/customers/cust0001" % self.dataset_source))
        expected_tx = str(uuid.uuid5(uuid.NAMESPACE_URL,
            "%s/customer_transactions/cust0001/0" % self.dataset_source))
        self.assertEqual(self.scalar("SELECT id FROM customers WHERE legacy_id='cust0001';"), expected_customer)
        self.assertEqual(self.scalar("SELECT id FROM customer_transactions WHERE customer_id='%s';" % expected_customer), expected_tx)
        self.assertEqual(self.scalar("SELECT seq FROM customer_transactions WHERE id='%s';" % expected_tx), "0")
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM change_log WHERE operation_id='%s';" % job), "2")
        self.assertEqual(self.scalar("SELECT status FROM legacy_import_jobs WHERE id='%s';" % job), "applied")
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
        self.assertEqual(code, 0, replay)
        self.assertTrue(replay["result"]["replayed"])
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM customers;"), "1")
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM customer_transactions;"), "1")
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM change_log;"), "2")

    def test_verification_detects_live_financial_tampering_without_exposing_pii(self):
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
        now = "2026-10-15 17:20:00"
        customer = str(uuid.uuid4())
        first_tx = str(uuid.uuid4())
        self._sql("\n".join([
            "INSERT INTO customers (id,tenant_id,legacy_id,row_version,created_at,updated_at,full_name,address,mobile,telegram_id,instagram_id,notes) VALUES ('%s','%s','servercust',1,'%s','%s','Legacy Customer','Old address','09120000001','','','');" % (customer, self.tenant, now, now),
            "INSERT INTO customer_transactions (id,tenant_id,legacy_id,row_version,created_at,updated_at,seq,customer_id,at,amount,note,kind,image,void_reason) VALUES ('%s','%s','servercust/0',1,'%s','%s',0,'%s','%s',500,'existing','receipt','','');" % (first_tx, self.tenant, now, now, customer, now),
        ]))
        staged = self._analyze(self.store())
        customer_stage = next(r for r in staged["records"] if r["entity"] == "customers")
        self.assertEqual(customer_stage["action"], "skip")
        job = staged["job"]["id"]
        code, applied = self._call("apply", job)
        self.assertEqual(code, 0, applied)
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM customers;"), "1")
        self.assertEqual(self.scalar("SELECT GROUP_CONCAT(seq ORDER BY seq) FROM customer_transactions WHERE customer_id='%s';" % customer), "0,1")
        expected = str(uuid.uuid5(uuid.NAMESPACE_URL,
            "%s/customer_transactions/servercust/1" % self.dataset_source))
        self.assertEqual(self.scalar("SELECT id FROM customer_transactions WHERE customer_id='%s' AND seq=1;" % customer), expected)

    def test_conflict_requires_decision_and_merge_only_fills_blank_online_fields(self):
        now = "2026-10-15 17:20:00"
        customer = str(uuid.uuid4())
        self._sql(
            "INSERT INTO customers (id,tenant_id,legacy_id,row_version,created_at,updated_at,full_name,address,mobile,telegram_id,instagram_id,notes) VALUES ('%s','%s','servercust',1,'%s','%s','Online Name','','09120000001','','','');" %
            (customer, self.tenant, now, now)
        )
        staged = self._analyze(self.store(note="legacy-note"))
        row = next(r for r in staged["records"] if r["entity"] == "customers")
        self.assertEqual(row["action"], "conflict")
        job = staged["job"]["id"]
        code, blocked = self._call("apply", job)
        self.assertNotEqual(code, 0)
        self.assertEqual((blocked["status"], blocked["code"]), (409, "VERSION_CONFLICT"))
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM customer_transactions;"), "0")

        code, decision = self._call("decide", job, row["id"], "merge", customer)
        self.assertEqual(code, 0, decision)
        self.assertEqual(decision["result"]["job"]["status"], "ready")
        code, applied = self._call("apply", job)
        self.assertEqual(code, 0, applied)
        values = self._sql("SELECT full_name,address,notes,row_version FROM customers WHERE id='%s';" % customer).strip().split("\t")
        self.assertEqual(values, ["Online Name", "Old address", "legacy-note", "2"])
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM customer_transactions WHERE customer_id='%s';" % customer), "1")

    def test_rejected_parent_blocks_child_reference_fallback(self):
        now = "2026-10-15 17:20:00"
        customer = str(uuid.uuid4())
        self._sql(
            "INSERT INTO customers (id,tenant_id,legacy_id,row_version,created_at,updated_at,full_name,address,mobile,telegram_id,instagram_id,notes) "
            "VALUES ('%s','%s','cust0001',1,'%s','%s','Online Name','Server address','09120000001','','','');" %
            (customer, self.tenant, now, now)
        )
        staged = self._analyze(self.store())
        parent = next(r for r in staged["records"] if r["entity"] == "customers")
        self.assertEqual(parent["action"], "conflict")
        job = staged["job"]["id"]

        code, decision = self._call("decide", job, parent["id"], "reject")
        self.assertEqual(code, 0, decision)
        self.assertEqual(decision["result"]["job"]["status"], "ready")

        code, failed = self._call("apply", job)
        self.assertNotEqual(code, 0)
        self.assertEqual((failed["status"], failed["code"]), (409, "VERSION_CONFLICT"))
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM customers;"), "1")
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM customer_transactions;"), "0")
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM change_log;"), "0")
        self.assertEqual(self.scalar("SELECT status FROM legacy_import_jobs WHERE id='%s';" % job), "ready")

    def test_late_validation_failure_rolls_back_earlier_business_writes(self):
        store = self.store()
        store["settings"] = {"watch_interval_hours": 999}
        staged = self._analyze(store)
        self.assertEqual(staged["job"]["status"], "ready")
        job = staged["job"]["id"]
        code, failed = self._call("apply", job)
        self.assertNotEqual(code, 0, failed)
        self.assertIn(failed["code"], ("VALIDATION_FAILED", "SERVER_ERROR"))
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM customers;"), "0")
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM customer_transactions;"), "0")
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM settings;"), "0")
        self.assertEqual(self.scalar("SELECT status FROM legacy_import_jobs WHERE id='%s';" % job), "ready")
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM change_log;"), "0")


if __name__ == "__main__":
    unittest.main()
