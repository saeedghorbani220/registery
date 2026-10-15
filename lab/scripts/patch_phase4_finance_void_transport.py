#!/usr/bin/env python3
"""One-shot guarded patch wiring atomic ledger voids through the durable outbox."""
from __future__ import annotations

import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[2]


def replace_once(path: pathlib.Path, old: str, new: str, label: str) -> None:
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one match, found {count}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def patch_index() -> None:
    path = ROOT / "host" / "public" / "index.php"
    replace_once(
        path,
        "        '/finance/transactions/append' => ['POST'],\n        '/bootstrap/import' => ['POST'],\n",
        "        '/finance/transactions/append' => ['POST'],\n        '/finance/transactions/void' => ['POST'],\n        '/bootstrap/import' => ['POST'],\n",
        "finance void route table",
    )
    replace_once(
        path,
        """        case '/bootstrap/import':\n""",
        """        case '/finance/transactions/void':\n            $device = requireDevice($auth, $request);\n            $body = $request->jsonBody();\n            $acting = $auth->actingUser($request);\n            $context = [\n                'device' => $device,\n                'user' => $acting,\n                'role' => $auth->effectiveRole([\n                    'device' => $device, 'user' => $acting,\n                ]),\n            ];\n            $payload = $finance->void($body, $context, $requestId);\n            $statusCode = 200;\n            $errorCode = '';\n            Response::ok($payload);\n            break;\n\n        case '/bootstrap/import':\n""",
        "finance void route handler",
    )


def patch_client() -> None:
    path = ROOT / "cloud_sync" / "client.py"
    anchor = '''        return self._request("POST", route, body=body)\n\n    def push(self, operations):\n'''
    method = '''        return self._request("POST", route, body=body)\n\n    def void_ledger_transaction(self, transaction_id, reason, *,\n                                operation_id=None):\n        """Atomically void one ledger row and create its audit reversal."""\n        route = "/finance/transactions/void"\n        if self.config.dataset_epoch is None:\n            raise BootstrapRequiredError(route=route)\n        if not isinstance(transaction_id, str) or not transaction_id:\n            raise BadResponseError(route=route)\n        if not isinstance(reason, str) or not reason.strip() \\\n                or len(reason.strip()) > 1000:\n            raise BadResponseError(route=route)\n        if operation_id is None:\n            operation_id = _ids.new_uuid()\n        if not isinstance(operation_id, str) or not operation_id:\n            raise BadResponseError(route=route)\n        return self._request("POST", route, body={\n            "operation_id": operation_id,\n            "transaction_id": transaction_id,\n            "reason": reason.strip(),\n        })\n\n    def push(self, operations):\n'''
    replace_once(path, anchor, method, "client void method")


def patch_outbox() -> None:
    path = ROOT / "cloud_sync" / "outbox.py"
    replace_once(
        path,
        '_FINANCE_APPEND_TRANSPORT = "finance_append"\n',
        '_FINANCE_APPEND_TRANSPORT = "finance_append"\n'
        '_FINANCE_VOID_TRANSPORT = "finance_void"\n',
        "finance void transport constant",
    )
    replace_once(
        path,
        '''    @staticmethod\n    def _is_finance_append(entry):\n        operation = getattr(entry, "operation", None)\n        return (isinstance(operation, dict)\n                and operation.get("transport") == _FINANCE_APPEND_TRANSPORT)\n\n''',
        '''    @staticmethod\n    def _finance_transport(entry):\n        operation = getattr(entry, "operation", None)\n        if not isinstance(operation, dict):\n            return None\n        marker = operation.get("transport")\n        if marker in (_FINANCE_APPEND_TRANSPORT, _FINANCE_VOID_TRANSPORT):\n            return marker\n        return None\n\n    @classmethod\n    def _is_finance_special(cls, entry):\n        return cls._finance_transport(entry) is not None\n\n''',
        "outbox finance classifier",
    )
    replace_once(
        path,
        '''        if self._is_finance_append(bounded[0]):\n            return [bounded[0]]\n        prefix = []\n        for entry in bounded:\n            if self._is_finance_append(entry):\n                break\n''',
        '''        if self._is_finance_special(bounded[0]):\n            return [bounded[0]]\n        prefix = []\n        for entry in bounded:\n            if self._is_finance_special(entry):\n                break\n''',
        "outbox finance batch isolation",
    )
    replace_once(
        path,
        '''    def _push_batch(self, batch):\n        if len(batch) == 1 and self._is_finance_append(batch[0]):\n            return self._push_finance_append(batch[0])\n        return self.client.push([entry.operation for entry in batch])\n\n''',
        '''    def _push_batch(self, batch):\n        if len(batch) == 1:\n            marker = self._finance_transport(batch[0])\n            if marker == _FINANCE_APPEND_TRANSPORT:\n                return self._push_finance_append(batch[0])\n            if marker == _FINANCE_VOID_TRANSPORT:\n                return self._push_finance_void(batch[0])\n        return self.client.push([entry.operation for entry in batch])\n\n''',
        "outbox finance dispatch",
    )
    anchor = '''        return _AppliedBatchResult(entry.operation_id, cursor)\n\n    # -- the terminal-event helpers ------------------------------------\n'''
    void_method = '''        return _AppliedBatchResult(entry.operation_id, cursor)\n\n    def _push_finance_void(self, entry):\n        operation = entry.operation\n        if operation.get("kind") != "upsert" \\\n                or operation.get("entity") != "customer_transactions":\n            raise BadResponseError(code=SERVER_ERROR)\n        transaction_id = operation.get("id")\n        record = operation.get("record")\n        if not isinstance(transaction_id, str) or not transaction_id \\\n                or not isinstance(record, dict):\n            raise BadResponseError(code=SERVER_ERROR)\n        reason = record.get("void_reason")\n        if not isinstance(reason, str) or not reason.strip():\n            raise BadResponseError(code=SERVER_ERROR)\n        payload = self.client.void_ledger_transaction(\n            transaction_id, reason, operation_id=entry.operation_id)\n        original = payload.get("original") if isinstance(payload, dict) else None\n        reversal = payload.get("reversal") if isinstance(payload, dict) else None\n        cursor = payload.get("cursor") if isinstance(payload, dict) else None\n        if not isinstance(original, dict) or original.get("id") != transaction_id \\\n                or not isinstance(reversal, dict) \\\n                or not isinstance(reversal.get("id"), str) \\\n                or not reversal["id"] \\\n                or isinstance(cursor, bool) or not isinstance(cursor, int):\n            raise BadResponseError(code=SERVER_ERROR)\n        return _AppliedBatchResult(entry.operation_id, cursor)\n\n    # -- the terminal-event helpers ------------------------------------\n'''
    replace_once(path, anchor, void_method, "outbox finance void sender")


def patch_panel() -> None:
    path = ROOT / "panel.py"
    old = '''                        tx_rec = {**txs[tx_index], "seq": tx_index, "customer_id": record.get("id")}\n                        _cloud_enqueue_mutation("customer_transactions", f"{record.get('id')}/{tx_index}", tx_rec)\n'''
    new = '''                        tx_rec = {**txs[tx_index], "seq": tx_index, "customer_id": record.get("id")}\n                        _cloud_enqueue_mutation(\n                            "customer_transactions",\n                            f"{record.get('id')}/{tx_index}", tx_rec,\n                            transport="finance_void")\n'''
    replace_once(path, old, new, "panel finance void tag")


def patch_tests() -> None:
    path = ROOT / "lab" / "tests" / "test_server_crm_v2_finance_outbox.py"
    text = path.read_text(encoding="utf-8")
    text = text.replace(
        '"""Outbox routing contract for server-authoritative financial appends."""',
        '"""Outbox routing contract for server-authoritative financial writes."""',
        1,
    )
    old = '''    def append_ledger_transaction(self, customer_id, amount, **kwargs):\n        self.events.append(("finance", customer_id, amount, dict(kwargs)))\n        self.cursor += 1\n        return {\n            "transaction": {\n                "id": "11111111-1111-5111-8111-111111111111",\n                "record": {"seq": 7},\n            },\n            "cursor": self.cursor,\n        }\n\n'''
    new = old + '''    def void_ledger_transaction(self, transaction_id, reason, **kwargs):\n        self.events.append(("void", transaction_id, reason, dict(kwargs)))\n        self.cursor += 2\n        return {\n            "original": {"id": transaction_id, "row_version": 2},\n            "reversal": {\n                "id": "44444444-4444-5444-8444-444444444444",\n                "row_version": 1,\n            },\n            "cursor": self.cursor,\n        }\n\n'''
    if text.count(old) != 1:
        raise RuntimeError("finance outbox fake client anchor changed")
    text = text.replace(old, new, 1)
    anchor = '''\ndef generic_op(identifier):\n'''
    helper = '''\ndef finance_void_op(reason="operator correction"):\n    return {\n        "kind": "upsert",\n        "entity": "customer_transactions",\n        "id": "55555555-5555-5555-8555-555555555555",\n        "base_version": 1,\n        "transport": "finance_void",\n        "record": {\n            "seq": 2,\n            "customer_id": "22222222-2222-5222-8222-222222222222",\n            "amount": 700,\n            "note": "old",\n            "kind": "receipt",\n            "image": "",\n            "device_id": None,\n            "voided_at": "2026-10-15T17:00:00+00:00",\n            "void_reason": reason,\n        },\n    }\n\n\ndef generic_op(identifier):\n'''
    if text.count(anchor) != 1:
        raise RuntimeError("finance void helper anchor changed")
    text = text.replace(anchor, helper, 1)
    anchor = '''    def test_only_explicit_transport_marker_uses_finance(self):\n'''
    tests = '''    def test_finance_void_reuses_outbox_operation_id_and_is_settled(self):\n        operation_id = self.outbox.enqueue(finance_void_op())\n        outcome = self.worker.run_once()\n        self.assertEqual(outcome.applied, 1)\n        self.assertEqual(self.outbox.pending_count, 0)\n        event = self.client.events[0]\n        self.assertEqual(event[0], "void")\n        self.assertEqual(event[1], "55555555-5555-5555-8555-555555555555")\n        self.assertEqual(event[2], "operator correction")\n        self.assertEqual(event[3]["operation_id"], operation_id)\n\n    def test_finance_void_isolated_between_generic_batches(self):\n        first_id = self.outbox.enqueue(generic_op("cust-before-void"))\n        void_id = self.outbox.enqueue(finance_void_op())\n        third_id = self.outbox.enqueue(generic_op("cust-after-void"))\n        self.worker.run_once()\n        self.assertEqual(self.client.events[0], ("generic", [first_id]))\n        self.worker.run_once()\n        self.assertEqual(self.client.events[1][0], "void")\n        self.assertEqual(self.client.events[1][3]["operation_id"], void_id)\n        self.worker.run_once()\n        self.assertEqual(self.client.events[2], ("generic", [third_id]))\n\n    def test_only_explicit_transport_marker_uses_finance(self):\n'''
    if text.count(anchor) != 1:
        raise RuntimeError("finance outbox test insertion anchor changed")
    text = text.replace(anchor, tests, 1)
    old_panel_test = '''    def test_only_new_transaction_enqueue_is_tagged_for_finance(self):\n        self.assertIn(\n            'def _cloud_enqueue_mutation(entity, legacy_id, record=None, kind="upsert", transport=None):',\n            self.panel,\n        )\n        self.assertIn('op["transport"] = str(transport)', self.panel)\n        self.assertEqual(self.panel.count('transport="finance_append"'), 1)\n        marker = self.panel.index('transport="finance_append"')\n        void_marker = self.panel.index('elif action == "void_tx"', marker)\n        self.assertLess(marker, void_marker)\n        void_window = self.panel[void_marker:void_marker + 900]\n        self.assertNotIn('transport="finance_append"', void_window)\n'''
    new_panel_test = '''    def test_new_and_void_transactions_have_distinct_finance_transports(self):\n        self.assertIn(\n            'def _cloud_enqueue_mutation(entity, legacy_id, record=None, kind="upsert", transport=None):',\n            self.panel,\n        )\n        self.assertIn('op["transport"] = str(transport)', self.panel)\n        self.assertEqual(self.panel.count('transport="finance_append"'), 1)\n        self.assertEqual(self.panel.count('transport="finance_void"'), 1)\n        append_marker = self.panel.index('transport="finance_append"')\n        void_action = self.panel.index('elif action == "void_tx"', append_marker)\n        void_marker = self.panel.index('transport="finance_void"', void_action)\n        self.assertLess(append_marker, void_action)\n        self.assertLess(void_action, void_marker)\n        self.assertNotIn('transport="finance_append"',\n                         self.panel[void_action:void_action + 1000])\n'''
    if text.count(old_panel_test) != 1:
        raise RuntimeError("finance panel tag test changed unexpectedly")
    text = text.replace(old_panel_test, new_panel_test, 1)
    path.write_text(text, encoding="utf-8")

    surface = ROOT / "lab" / "tests" / "test_server_crm_v2_finance_transport.py"
    surface.write_text(r'''# -*- coding: utf-8 -*-
"""Static transport surface for server-authoritative finance endpoints."""
import os
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


class FinanceTransportSurfaceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(os.path.join(ROOT, "host", "public", "index.php"),
                  "r", encoding="utf-8") as handle:
            cls.index = handle.read()
        with open(os.path.join(ROOT, "cloud_sync", "client.py"),
                  "r", encoding="utf-8") as handle:
            cls.client = handle.read()

    def test_append_and_void_routes_are_explicit(self):
        self.assertIn("'/finance/transactions/append' => ['POST']", self.index)
        self.assertIn("'/finance/transactions/void' => ['POST']", self.index)
        self.assertIn("$finance->append($body, $context, $requestId)", self.index)
        self.assertIn("$finance->void($body, $context, $requestId)", self.index)

    def test_client_has_distinct_finance_methods(self):
        self.assertIn("def append_ledger_transaction", self.client)
        self.assertIn("def void_ledger_transaction", self.client)
        self.assertIn('route = "/finance/transactions/void"', self.client)
        self.assertIn('"transaction_id": transaction_id', self.client)
        self.assertIn('"reason": reason.strip()', self.client)


if __name__ == "__main__":
    unittest.main()
''', encoding="utf-8")


def main() -> None:
    patch_index()
    patch_client()
    patch_outbox()
    patch_panel()
    patch_tests()
    print("finance void transport patch applied")


if __name__ == "__main__":
    main()
