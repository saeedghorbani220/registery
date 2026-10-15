#!/usr/bin/env python3
"""One-shot Phase 7 patch: add rich real-MariaDB migration reconciliation coverage."""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TEST = ROOT / "lab" / "tests" / "test_server_crm_v2_legacy_apply.py"

RICH_STORE = r'''
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

'''

TEST_METHOD = r'''
    def test_rich_dataset_reconciles_counts_links_stages_and_financial_sums(self):
        source = self.rich_store()
        source_tx_count = sum(len(c.get("transactions") or [])
                              for c in source["customers"])
        source_sum = sum(tx["amount"] for c in source["customers"]
                         for tx in c.get("transactions") or [])

        staged = self._analyze(source)
        self.assertEqual(staged["unresolved"], 0)
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

'''


def main() -> None:
    text = TEST.read_text(encoding="utf-8")
    if "def rich_store():" in text or "test_rich_dataset_reconciles_counts_links_stages_and_financial_sums" in text:
        raise RuntimeError("Phase 7 reconciliation coverage already exists")
    marker = "    def _file(self, store):\n"
    if text.count(marker) != 1:
        raise RuntimeError("rich-store insertion marker drifted")
    text = text.replace(marker, RICH_STORE + marker)
    marker2 = "    def test_clean_apply_uses_dataset_uuid_mapping_and_replays_without_duplicates(self):\n"
    if text.count(marker2) != 1:
        raise RuntimeError("reconciliation test insertion marker drifted")
    text = text.replace(marker2, TEST_METHOD + marker2)
    TEST.write_text(text, encoding="utf-8", newline="\n")
    print("phase7 migration reconciliation test patch applied")


if __name__ == "__main__":
    main()
