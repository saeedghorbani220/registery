#!/usr/bin/env python3
"""One-shot guarded patch: authoritative ledger ids follow project uuid5 mapping."""
from __future__ import annotations

import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[2]


def replace_once(path: pathlib.Path, old: str, new: str, label: str) -> None:
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one match, found {count}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def main() -> None:
    finance = ROOT / "host" / "src" / "Finance.php"
    old = '''            $legacyId = Ids::transactionLegacyId($customerLegacy, $nextSeq);\n            $transactionId = $operationId;\n\n            $tx->insert('customer_transactions', [\n'''
    new = '''            $legacyId = Ids::transactionLegacyId($customerLegacy, $nextSeq);\n            $sourceInstallationId = $tx->queryValue(\n                'SELECT source_installation_id FROM tenant_state '\n                . 'WHERE tenant_id = ?',\n                [$tenantId]\n            );\n            if (!is_string($sourceInstallationId)\n                || !Ids::isUuid($sourceInstallationId)) {\n                throw new ApiException(409, Codes::VERSION_CONFLICT,\n                    'dataset authority has no source installation identity');\n            }\n            // Keep the row id compatible with mapper._minted_id(). The\n            // operation id is only the idempotency key; the record id remains\n            // uuid5(source installation, customer legacy id / server seq).\n            $transactionId = Ids::uuid5(\n                $sourceInstallationId, 'customer_transactions', $legacyId\n            );\n\n            $tx->insert('customer_transactions', [\n'''
    replace_once(finance, old, new, "finance transaction identity")

    tests = ROOT / "lab" / "tests" / "test_server_crm_v2_finance.py"
    old = '''        ids = [payload["result"]["transaction"]["id"] for _code, payload in results]\n        seqs = [payload["result"]["transaction"]["record"]["seq"] for _code, payload in results]\n        self.assertEqual(ids, [op, op])\n        self.assertEqual(seqs[0], seqs[1])\n        self.assertEqual(self.scalar("SELECT COUNT(*) FROM customer_transactions WHERE id='%s';" % op), "1")\n        self.assertEqual(self.scalar("SELECT COUNT(*) FROM change_log WHERE operation_id='%s';" % op), "1")\n'''
    new = '''        ids = [payload["result"]["transaction"]["id"] for _code, payload in results]\n        seqs = [payload["result"]["transaction"]["record"]["seq"] for _code, payload in results]\n        self.assertEqual(ids[0], ids[1])\n        self.assertNotEqual(ids[0], op)\n        self.assertRegex(ids[0], r"^[0-9a-f-]{36}$")\n        self.assertEqual(seqs[0], seqs[1])\n        self.assertEqual(self.scalar("SELECT COUNT(*) FROM customer_transactions WHERE id='%s';" % ids[0]), "1")\n        self.assertEqual(self.scalar("SELECT COUNT(*) FROM change_log WHERE operation_id='%s';" % op), "1")\n'''
    replace_once(tests, old, new, "finance retry identity test")

    old = '''        code, second = self._append(op, 301, "same-op")\n        self.assertNotEqual(code, 0)\n        self.assertEqual((second["status"], second["code"]), (409, "IDEMPOTENCY_MISMATCH"))\n        self.assertEqual(self.scalar("SELECT COUNT(*) FROM customer_transactions WHERE id='%s';" % op), "1")\n        self.assertEqual(self.scalar("SELECT amount FROM customer_transactions WHERE id='%s';" % op), "300")\n'''
    new = '''        tx_id = first["result"]["transaction"]["id"]\n        code, second = self._append(op, 301, "same-op")\n        self.assertNotEqual(code, 0)\n        self.assertEqual((second["status"], second["code"]), (409, "IDEMPOTENCY_MISMATCH"))\n        self.assertEqual(self.scalar("SELECT COUNT(*) FROM customer_transactions WHERE id='%s';" % tx_id), "1")\n        self.assertEqual(self.scalar("SELECT amount FROM customer_transactions WHERE id='%s';" % tx_id), "300")\n'''
    replace_once(tests, old, new, "finance mismatch row identity test")

    old = '''        self.assertEqual((payload["status"], payload["code"]), (400, "VALIDATION_FAILED"))\n        self.assertEqual(self.scalar("SELECT COUNT(*) FROM customer_transactions WHERE id='%s';" % op), "0")\n'''
    new = '''        self.assertEqual((payload["status"], payload["code"]), (400, "VALIDATION_FAILED"))\n        self.assertEqual(self.scalar("SELECT COUNT(*) FROM change_log WHERE operation_id='%s';" % op), "0")\n'''
    replace_once(tests, old, new, "finance invalid amount assertion")

    old = '''        self.assertIn("IDEMPOTENCY_MISMATCH", self.source)\n        self.assertNotIn("floatval", self.source)\n'''
    new = '''        self.assertIn("IDEMPOTENCY_MISMATCH", self.source)\n        self.assertIn("Ids::uuid5", self.source)\n        self.assertIn("source_installation_id FROM tenant_state", self.source)\n        self.assertNotIn("floatval", self.source)\n'''
    replace_once(tests, old, new, "finance static identity assertions")

    # The MariaDB fixture now needs the same source installation identity that
    # a successfully imported tenant has in production.
    old = '''        cls.customer = str(uuid.uuid4())\n        cls._sql("CREATE DATABASE `%s` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;" % cls.db, select_db=False)\n'''
    new = '''        cls.customer = str(uuid.uuid4())\n        cls.source_installation = str(uuid.uuid4())\n        cls._sql("CREATE DATABASE `%s` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;" % cls.db, select_db=False)\n'''
    replace_once(tests, old, new, "finance fixture source id")

    old = '''            "INSERT INTO memberships (id,tenant_id,user_id,role,created_at,updated_at) VALUES ('%s','%s','%s','user','%s','%s');" % (membership, cls.tenant, cls.user, now, now),\n            "INSERT INTO customers (id,tenant_id,legacy_id,row_version,created_at,updated_at,full_name) VALUES ('%s','%s','cust-finance',1,'%s','%s','Finance Customer');" % (cls.customer, cls.tenant, now, now),\n'''
    new = '''            "INSERT INTO memberships (id,tenant_id,user_id,role,created_at,updated_at) VALUES ('%s','%s','%s','user','%s','%s');" % (membership, cls.tenant, cls.user, now, now),\n            "INSERT INTO tenant_state (tenant_id,dataset_epoch,bootstrap_status,source_installation_id,created_at,updated_at) VALUES ('%s',1,'done','%s','%s','%s');" % (cls.tenant, cls.source_installation, now, now),\n            "INSERT INTO customers (id,tenant_id,legacy_id,row_version,created_at,updated_at,full_name) VALUES ('%s','%s','cust-finance',1,'%s','%s','Finance Customer');" % (cls.customer, cls.tenant, now, now),\n'''
    replace_once(tests, old, new, "finance fixture tenant state")
    print("finance authoritative identity patch applied")


if __name__ == "__main__":
    main()
