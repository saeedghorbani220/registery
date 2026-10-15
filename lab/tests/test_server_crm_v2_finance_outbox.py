# -*- coding: utf-8 -*-
"""Outbox routing contract for server-authoritative financial appends."""
import os
import tempfile
import types
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

from cloud_sync.outbox import Outbox, OutboxWorker


class FakeClient:
    def __init__(self):
        self.events = []
        self.cursor = 100

    def push(self, operations):
        self.events.append(("generic", [op["operation_id"] for op in operations]))
        self.cursor += 1
        return types.SimpleNamespace(
            applied=[op["operation_id"] for op in operations],
            conflicts=[], cursor=self.cursor)

    def append_ledger_transaction(self, customer_id, amount, **kwargs):
        self.events.append(("finance", customer_id, amount, dict(kwargs)))
        self.cursor += 1
        return {
            "transaction": {
                "id": "11111111-1111-5111-8111-111111111111",
                "record": {"seq": 7},
            },
            "cursor": self.cursor,
        }


def finance_op(customer="22222222-2222-5222-8222-222222222222", amount=500):
    return {
        "kind": "upsert",
        "entity": "customer_transactions",
        "id": "33333333-3333-5333-8333-333333333333",
        "base_version": 0,
        "transport": "finance_append",
        "record": {
            "customer_id": customer,
            "amount": amount,
            "note": "receipt",
            "kind": "receipt",
            "image": "",
            "device_id": None,
        },
    }


def generic_op(identifier):
    return {
        "kind": "upsert", "entity": "customers", "id": identifier,
        "base_version": 0, "record": {"full_name": identifier},
    }


class FinanceOutboxTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="irica_finance_outbox_")
        self.addCleanup(self.tmp.cleanup)
        self.outbox = Outbox(path=os.path.join(self.tmp.name, "outbox.jsonl"))
        self.client = FakeClient()
        self.worker = OutboxWorker(self.outbox, self.client)

    def test_finance_append_reuses_outbox_operation_id_and_is_settled(self):
        operation_id = self.outbox.enqueue(finance_op())
        outcome = self.worker.run_once()
        self.assertEqual(outcome.applied, 1)
        self.assertEqual(self.outbox.pending_count, 0)
        event = self.client.events[0]
        self.assertEqual(event[0], "finance")
        self.assertEqual(event[2], 500)
        self.assertEqual(event[3]["operation_id"], operation_id)
        self.assertEqual(event[3]["note"], "receipt")

    def test_generic_prefix_is_sent_before_following_finance_append(self):
        first_id = self.outbox.enqueue(generic_op("cust-a"))
        finance_id = self.outbox.enqueue(finance_op())
        third_id = self.outbox.enqueue(generic_op("cust-b"))

        first = self.worker.run_once()
        self.assertEqual(first.applied, 1)
        self.assertEqual(self.client.events, [("generic", [first_id])])
        self.assertIsNotNone(self.outbox.get(finance_id))
        self.assertIsNotNone(self.outbox.get(third_id))

        second = self.worker.run_once()
        self.assertEqual(second.applied, 1)
        self.assertEqual(self.client.events[1][0], "finance")
        self.assertEqual(self.client.events[1][3]["operation_id"], finance_id)
        self.assertIsNotNone(self.outbox.get(third_id))

        third = self.worker.run_once()
        self.assertEqual(third.applied, 1)
        self.assertEqual(self.client.events[2], ("generic", [third_id]))
        self.assertEqual(self.outbox.pending_count, 0)

    def test_only_explicit_transport_marker_uses_finance(self):
        operation = finance_op()
        operation.pop("transport")
        operation_id = self.outbox.enqueue(operation)
        self.worker.run_once()
        self.assertEqual(self.client.events, [("generic", [operation_id])])


class PanelFinanceTagTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(os.path.join(ROOT, "panel.py"), "r", encoding="utf-8") as handle:
            cls.panel = handle.read()

    def test_only_new_transaction_enqueue_is_tagged_for_finance(self):
        self.assertIn(
            'def _cloud_enqueue_mutation(entity, legacy_id, record=None, kind="upsert", transport=None):',
            self.panel,
        )
        self.assertIn('op["transport"] = str(transport)', self.panel)
        self.assertEqual(self.panel.count('transport="finance_append"'), 1)
        marker = self.panel.index('transport="finance_append"')
        void_marker = self.panel.index('elif action == "void_tx"', marker)
        self.assertLess(marker, void_marker)
        void_window = self.panel[void_marker:void_marker + 900]
        self.assertNotIn('transport="finance_append"', void_window)


if __name__ == "__main__":
    unittest.main()
