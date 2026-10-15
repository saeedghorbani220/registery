#!/usr/bin/env python3
"""One-shot guarded patch routing new ledger appends through Finance."""
from __future__ import annotations

import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[2]


def replace_once(path: pathlib.Path, old: str, new: str, label: str) -> None:
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one match, found {count}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def patch_outbox() -> None:
    path = ROOT / "cloud_sync" / "outbox.py"
    text = path.read_text(encoding="utf-8")

    old = '''#: A generous line size; anything larger is corrupt, not a real operation.\n_MAX_LINE_BYTES = 4 * 1024 * 1024\n'''
    new = '''#: A generous line size; anything larger is corrupt, not a real operation.\n_MAX_LINE_BYTES = 4 * 1024 * 1024\n\n#: Transport marker for a *new* customer ledger append. Updates/voids keep\n#: using generic CAS; only creation needs server-side sequence serialization.\n_FINANCE_APPEND_TRANSPORT = "finance_append"\n'''
    if text.count(old) != 1:
        raise RuntimeError("outbox transport constant anchor changed")
    text = text.replace(old, new, 1)

    old = '''        batch = ready[:max_batch or self.max_batch]\n        outcome = BatchOutcome(attempted=True, batch_size=len(batch))\n        failure = None\n        try:\n            result = self.client.push([e.operation for e in batch])\n'''
    new = '''        batch = self._transport_batch(ready, max_batch or self.max_batch)\n        outcome = BatchOutcome(attempted=True, batch_size=len(batch))\n        failure = None\n        try:\n            result = self._push_batch(batch)\n'''
    if text.count(old) != 1:
        raise RuntimeError("outbox run_once batch anchor changed")
    text = text.replace(old, new, 1)

    anchor = '''    # -- the terminal-event helpers ------------------------------------\n    def _finish(self, outcome):\n'''
    methods = '''    # -- transport routing ----------------------------------------------\n    @staticmethod\n    def _is_finance_append(entry):\n        operation = getattr(entry, "operation", None)\n        return (isinstance(operation, dict)\n                and operation.get("transport") == _FINANCE_APPEND_TRANSPORT)\n\n    def _transport_batch(self, ready, limit):\n        """Preserve queue order while isolating serialized finance appends.\n\n        If finance is at the head, send exactly that entry. Otherwise send the\n        contiguous generic prefix and stop before the first finance append.\n        This guarantees a newly-created customer reaches the host before its\n        first ledger entry without degrading unrelated generic batching.\n        """\n        bounded = ready[:limit]\n        if not bounded:\n            return []\n        if self._is_finance_append(bounded[0]):\n            return [bounded[0]]\n        prefix = []\n        for entry in bounded:\n            if self._is_finance_append(entry):\n                break\n            prefix.append(entry)\n        return prefix\n\n    def _push_batch(self, batch):\n        if len(batch) == 1 and self._is_finance_append(batch[0]):\n            return self._push_finance_append(batch[0])\n        return self.client.push([entry.operation for entry in batch])\n\n    def _push_finance_append(self, entry):\n        operation = entry.operation\n        if operation.get("kind") != "upsert" \\\n                or operation.get("entity") != "customer_transactions":\n            raise BadResponseError(code=SERVER_ERROR)\n        record = operation.get("record")\n        if not isinstance(record, dict):\n            raise BadResponseError(code=SERVER_ERROR)\n        customer_id = record.get("customer_id")\n        amount = record.get("amount")\n        if not isinstance(customer_id, str) or not customer_id \\\n                or isinstance(amount, bool) or not isinstance(amount, int):\n            raise BadResponseError(code=SERVER_ERROR)\n        note = record.get("note", "")\n        kind = record.get("kind", "")\n        image = record.get("image", "")\n        device_id = record.get("device_id")\n        if not all(isinstance(value, str) for value in (note, kind, image)):\n            raise BadResponseError(code=SERVER_ERROR)\n        if device_id == "":\n            device_id = None\n        if device_id is not None and not isinstance(device_id, str):\n            raise BadResponseError(code=SERVER_ERROR)\n\n        payload = self.client.append_ledger_transaction(\n            customer_id, amount, note=note, kind=kind, image=image,\n            device_id=device_id, operation_id=entry.operation_id)\n        transaction = payload.get("transaction") if isinstance(payload, dict) else None\n        cursor = payload.get("cursor") if isinstance(payload, dict) else None\n        if not isinstance(transaction, dict) \\\n                or not isinstance(transaction.get("id"), str) \\\n                or not transaction["id"] \\\n                or isinstance(cursor, bool) or not isinstance(cursor, int):\n            raise BadResponseError(code=SERVER_ERROR)\n        return _AppliedBatchResult(entry.operation_id, cursor)\n\n    # -- the terminal-event helpers ------------------------------------\n    def _finish(self, outcome):\n'''
    if text.count(anchor) != 1:
        raise RuntimeError("outbox helper insertion anchor changed")
    text = text.replace(anchor, methods, 1)

    tail = '''\ndef _wrap_unexpected(exc):\n'''
    result_class = '''\nclass _AppliedBatchResult(object):\n    """Minimal PushResult shape used by the finance transport path."""\n\n    __slots__ = ("applied", "conflicts", "cursor")\n\n    def __init__(self, operation_id, cursor):\n        self.applied = (operation_id,)\n        self.conflicts = ()\n        self.cursor = cursor\n\n\ndef _wrap_unexpected(exc):\n'''
    if text.count(tail) != 1:
        raise RuntimeError("outbox result class anchor changed")
    text = text.replace(tail, result_class, 1)
    path.write_text(text, encoding="utf-8")


def patch_panel() -> None:
    path = ROOT / "panel.py"
    text = path.read_text(encoding="utf-8")

    old = 'def _cloud_enqueue_mutation(entity, legacy_id, record=None, kind="upsert"):'
    new = 'def _cloud_enqueue_mutation(entity, legacy_id, record=None, kind="upsert", transport=None):'
    if text.count(old) != 1:
        raise RuntimeError(
            f"panel enqueue signature: expected one match, found {text.count(old)}"
        )
    text = text.replace(old, new, 1)

    old = '''        op = {\n            "kind": kind,\n            "entity": canon,\n            "id": cloud_id,\n            "base_version": base_ver,\n            "record": wire_record,\n        }\n        outbox.enqueue(op)\n'''
    new = '''        op = {\n            "kind": kind,\n            "entity": canon,\n            "id": cloud_id,\n            "base_version": base_ver,\n            "record": wire_record,\n        }\n        if transport:\n            op["transport"] = str(transport)\n        outbox.enqueue(op)\n'''
    if text.count(old) != 1:
        raise RuntimeError(
            f"panel enqueue operation: expected one match, found {text.count(old)}"
        )
    text = text.replace(old, new, 1)

    old = '''                        _cloud_enqueue_mutation("customer_transactions", f"{record.get('id')}/{seq}", tx_rec)\n                elif action == "void_tx" and isinstance(record, dict):\n'''
    new = '''                        _cloud_enqueue_mutation(\n                            "customer_transactions",\n                            f"{record.get('id')}/{seq}", tx_rec,\n                            transport="finance_append")\n                elif action == "void_tx" and isinstance(record, dict):\n'''
    count = text.count(old)
    if count != 1:
        raise RuntimeError(
            f"panel finance append call: expected one match, found {count}"
        )
    text = text.replace(old, new, 1)
    path.write_text(text, encoding="utf-8")


def write_tests() -> None:
    path = ROOT / "lab" / "tests" / "test_server_crm_v2_finance_outbox.py"
    path.write_text(r'''# -*- coding: utf-8 -*-
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
''', encoding="utf-8")


def main() -> None:
    patch_outbox()
    patch_panel()
    write_tests()
    print("phase 4 finance outbox patch applied")


if __name__ == "__main__":
    main()
