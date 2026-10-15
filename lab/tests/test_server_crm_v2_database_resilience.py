# -*- coding: utf-8 -*-
"""Real-MariaDB resilience checks for Database.transaction()."""
import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest
import uuid

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
HOST = os.path.join(ROOT, "host")
DATABASE_PHP = os.path.join(HOST, "src", "Database.php")
SCHEMA_PHP = os.path.join(HOST, "src", "Schema.php")


class DatabaseResilienceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mysql = os.environ.get("IRICA_MARIADB") or shutil.which("mariadb") or shutil.which("mysql")
        cls.php = os.environ.get("IRICA_PHP") or shutil.which("php")
        cls.password = os.environ.get("IRICA_DB_ROOT_PASSWORD")
        cls.host = os.environ.get("IRICA_DB_HOST", "127.0.0.1")
        cls.port = os.environ.get("IRICA_DB_PORT", "3307")
        if not cls.mysql or not cls.php or not cls.password:
            raise unittest.SkipTest("MariaDB/PHP test service is not configured")
        cls.db = "irica_retry_%s" % uuid.uuid4().hex[:12]
        cls._sql("CREATE DATABASE `%s` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;" % cls.db, select_db=False)
        cls._sql("CREATE TABLE retry_probe (id INT PRIMARY KEY, value INT NOT NULL) ENGINE=InnoDB; INSERT INTO retry_probe VALUES (1,0);")

    @classmethod
    def tearDownClass(cls):
        if getattr(cls, "db", None):
            cls._sql("DROP DATABASE IF EXISTS `%s`;" % cls.db, select_db=False, check=False)

    @classmethod
    def _command(cls, *, select_db=True):
        cmd = [cls.mysql, "-h", cls.host, "-P", str(cls.port), "-u", "root",
               "--protocol=TCP", "--default-character-set=utf8mb4", "--batch", "--skip-column-names"]
        if "mariadb" in os.path.basename(cls.mysql).lower():
            cmd.append("--ssl=FALSE")
        if select_db:
            cmd.append(cls.db)
        return cmd

    @classmethod
    def _env(cls):
        env = dict(os.environ)
        env["MYSQL_PWD"] = cls.password
        return env

    @classmethod
    def _sql(cls, sql, *, select_db=True, check=True):
        run = subprocess.run(cls._command(select_db=select_db), input=sql,
                             capture_output=True, text=True, encoding="utf-8",
                             errors="replace", env=cls._env(), timeout=40)
        if check and run.returncode != 0:
            raise AssertionError("SQL failed (exit %d): %s" % (run.returncode, (run.stderr or "")[:1000]))
        return run.stdout or ""

    def test_retry_contract_is_bounded_and_covers_deadlock_and_lock_timeout(self):
        text = open(DATABASE_PHP, encoding="utf-8").read()
        self.assertIn("1213 => true", text)
        self.assertIn("1205 => true", text)
        self.assertIn("'40001' => true", text)
        self.assertIn("transactionAttempts", text)
        self.assertIn("if (!$this->isRetryable($error) || $attempt === $attempts)", text)

    def test_lock_wait_timeout_rolls_back_then_retries_successfully(self):
        self._sql("UPDATE retry_probe SET value=0 WHERE id=1;")
        locker_sql = (
            "START TRANSACTION; "
            "UPDATE retry_probe SET value=value+10 WHERE id=1; "
            "SELECT SLEEP(7); COMMIT;"
        )
        locker = subprocess.Popen(self._command(), stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  text=True, encoding="utf-8", errors="replace",
                                  env=self._env())
        self.addCleanup(lambda: locker.poll() is None and locker.kill())
        assert locker.stdin is not None
        locker.stdin.write(locker_sql)
        locker.stdin.close()
        time.sleep(0.7)  # the UPDATE above owns the row lock before PHP starts

        directory = tempfile.mkdtemp(prefix="irica_retry_php_")
        self.addCleanup(shutil.rmtree, directory, True)
        probe = os.path.join(directory, "probe.php")
        source = """<?php
declare(strict_types=1);
require_once %s;
require_once %s;
$db=Database::fromConfig([
 'host'=>getenv('IRICA_DB_HOST'),'port'=>(int)getenv('IRICA_DB_PORT'),
 'dbname'=>getenv('IRICA_RETRY_DB'),'user'=>'root',
 'password'=>getenv('IRICA_DB_ROOT_PASSWORD'),
 'transaction_attempts'=>3,'backoff_base_us'=>10000]);
$attempts=0;
$started=microtime(true);
$result=$db->transaction(function(Database $tx) use (&$attempts): int {
    $attempts++;
    $tx->execute('UPDATE retry_probe SET value=value+1 WHERE id=1');
    return $attempts;
});
$value=(int)$db->queryValue('SELECT value FROM retry_probe WHERE id=1');
echo json_encode(['attempts'=>$attempts,'result'=>$result,'value'=>$value,
                  'elapsed'=>microtime(true)-$started]);
""" % (json.dumps(SCHEMA_PHP.replace("\\", "/")),
         json.dumps(DATABASE_PHP.replace("\\", "/")))
        with open(probe, "w", encoding="utf-8") as handle:
            handle.write(source)
        env = self._env()
        env.update({"IRICA_RETRY_DB": self.db,
                    "IRICA_DB_HOST": self.host,
                    "IRICA_DB_PORT": str(self.port)})
        run = subprocess.run([self.php, probe], capture_output=True, text=True,
                             encoding="utf-8", errors="replace", env=env,
                             timeout=25)
        locker.wait(timeout=12)
        if run.returncode != 0:
            raise AssertionError("PHP retry probe failed: %s" % (run.stderr or "")[:1200])
        payload = json.loads((run.stdout or "").strip().splitlines()[-1])
        self.assertGreaterEqual(int(payload["attempts"]), 2)
        self.assertEqual(int(payload["result"]), int(payload["attempts"]))
        self.assertEqual(int(payload["value"]), 11)
        self.assertGreater(float(payload["elapsed"]), 4.0)
        self.assertLess(float(payload["elapsed"]), 15.0)


if __name__ == "__main__":
    unittest.main()
