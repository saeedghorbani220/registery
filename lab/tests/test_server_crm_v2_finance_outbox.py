# -*- coding: utf-8 -*-
"""Outbox routing contract for server-authoritative financial writes."""
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

    def void_ledger_transaction(self, transaction_id, reason, **kwargs):
        self.events.append(("void", transaction_id, reason, dict(kwargs)))
        self.cursor += 2
        return {
            "original": {"id": transaction_id, "row_version": 2},
            "reversal": {
                "id": "44444444-4444-5444-8444-444444444444",
                "row_version": 1,
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


def finance_void_op(reason="operator correction"):
    return {
        "kind": "upsert",
        "entity": "customer_transactions",
        "id": "55555555-5555-5555-8555-555555555555",
        "base_version": 1,
        "transport": "finance_void",
        "record": {
            "seq": 2,
            "customer_id": "22222222-2222-5222-8222-222222222222",
            "amount": 700,
            "note": "old",
            "kind": "receipt",
            "image": "",
            "device_id": None,
            "voided_at": "2026-10-15T17:00:00+00:00",
            "void_reason": reason,
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

    def test_finance_void_reuses_outbox_operation_id_and_is_settled(self):
        operation_id = self.outbox.enqueue(finance_void_op())
        outcome = self.worker.run_once()
        self.assertEqual(outcome.applied, 1)
        self.assertEqual(self.outbox.pending_count, 0)
        event = self.client.events[0]
        self.assertEqual(event[0], "void")
        self.assertEqual(event[1], "55555555-5555-5555-8555-555555555555")
        self.assertEqual(event[2], "operator correction")
        self.assertEqual(event[3]["operation_id"], operation_id)

    def test_finance_void_isolated_between_generic_batches(self):
        first_id = self.outbox.enqueue(generic_op("cust-before-void"))
        void_id = self.outbox.enqueue(finance_void_op())
        third_id = self.outbox.enqueue(generic_op("cust-after-void"))
        self.worker.run_once()
        self.assertEqual(self.client.events[0], ("generic", [first_id]))
        self.worker.run_once()
        self.assertEqual(self.client.events[1][0], "void")
        self.assertEqual(self.client.events[1][3]["operation_id"], void_id)
        self.worker.run_once()
        self.assertEqual(self.client.events[2], ("generic", [third_id]))

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

    def test_new_and_void_transactions_have_distinct_finance_transports(self):
        self.assertIn(
            'def _cloud_enqueue_mutation(entity, legacy_id, record=None, kind="upsert", transport=None):',
            self.panel,
        )
        self.assertIn('op["transport"] = str(transport)', self.panel)
        self.assertEqual(self.panel.count('transport="finance_append"'), 1)
        self.assertEqual(self.panel.count('transport="finance_void"'), 1)
        append_marker = self.panel.index('transport="finance_append"')
        void_action = self.panel.index('elif action == "void_tx"', append_marker)
        void_marker = self.panel.index('transport="finance_void"', void_action)
        self.assertLess(append_marker, void_action)
        self.assertLess(void_action, void_marker)
        self.assertNotIn('transport="finance_append"',
                         self.panel[void_action:void_action + 1000])


if __name__ == "__main__":
    unittest.main()
