#!/usr/bin/env python3
"""One-shot guarded patch for explicit reject reference blocking."""
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
    apply = ROOT / "host" / "src" / "LegacyApply.php"
    old = """                    if ($resolution === 'reject') {\n                        $counts['rejected']++;\n                        continue;\n                    }\n"""
    new = """                    if ($resolution === 'reject') {\n                        // An explicit parent rejection is stronger than a\n                        // missing mapping. Record a blocked sentinel so a child\n                        // cannot fall through to an unrelated live row that\n                        // happens to reuse the same legacy id.\n                        if ($entity !== 'customer_transactions'\n                            && $entity !== 'settings') {\n                            $sourceMap[$this->mapKey($entity, $sourceKey)] = '';\n                        }\n                        $counts['rejected']++;\n                        continue;\n                    }\n"""
    replace_once(apply, old, new, "reject sentinel")

    old = """        $key = $this->mapKey($entity, $sourceId);\n        if (isset($sourceMap[$key])) {\n            return $sourceMap[$key];\n        }\n"""
    new = """        $key = $this->mapKey($entity, $sourceId);\n        if (array_key_exists($key, $sourceMap)) {\n            $mapped = $sourceMap[$key];\n            return is_string($mapped) && Ids::isUuid($mapped) ? $mapped : null;\n        }\n"""
    replace_once(apply, old, new, "reference sentinel resolution")

    tests = ROOT / "lab" / "tests" / "test_server_crm_v2_legacy_apply.py"
    old = '        self.assertIn("customers WHERE id=? AND tenant_id=? AND deleted_at IS NULL FOR UPDATE", self.source)\n'
    new = ('        self.assertIn("SELECT id,legacy_id FROM customers", self.source)\n'
           '        self.assertIn("WHERE id=? AND tenant_id=? AND deleted_at IS NULL FOR UPDATE", self.source)\n')
    replace_once(tests, old, new, "lock assertion")

    anchor = """    def test_late_validation_failure_rolls_back_earlier_business_writes(self):\n"""
    method = r'''    def test_rejected_parent_blocks_child_reference_fallback(self):
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

'''
    replace_once(tests, anchor, method + anchor, "reject fallback regression")
    print("legacy apply reject guard patch applied")


if __name__ == "__main__":
    main()
