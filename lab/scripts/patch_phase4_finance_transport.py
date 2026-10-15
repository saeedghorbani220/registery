#!/usr/bin/env python3
"""One-shot guarded patch for finance transport and push-cursor safety."""
from __future__ import annotations

import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[2]


def patch(rel: str, edits):
    path = ROOT / rel
    text = path.read_text(encoding="utf-8")
    for label, old, new, expected in edits:
        count = text.count(old)
        if count != expected:
            raise RuntimeError(
                f"{rel}:{label}: expected {expected} matches, found {count}"
            )
        text = text.replace(old, new, expected)
    path.write_text(text, encoding="utf-8")


def patch_client():
    append_anchor = '''    def trigger_backup(self):\n        """``POST /admin/backup`` — triggers automated DB dump to Telegram on the host."""\n        return self._request("POST", "/admin/backup", body={}, acting=True)\n\n'''
    append_method = append_anchor + '''    def append_ledger_transaction(self, customer_id, amount, *, note="",\n                                  kind="", image="", device_id=None,\n                                  operation_id=None):\n        """Append one monetary entry through the server serialization point.\n\n        This deliberately bypasses generic row CAS. Concurrent financial\n        intents from different desktops must both survive, so the host owns\n        sequence allocation and ``operation_id`` owns retry idempotency.\n        """\n        route = "/finance/transactions/append"\n        if self.config.dataset_epoch is None:\n            raise BootstrapRequiredError(route=route)\n        if not isinstance(customer_id, str) or not customer_id:\n            raise BadResponseError(route=route)\n        if isinstance(amount, bool) or not isinstance(amount, int):\n            raise BadResponseError(route=route)\n        if not all(isinstance(value, str) for value in (note, kind, image)):\n            raise BadResponseError(route=route)\n        if device_id is not None and (not isinstance(device_id, str)\n                                      or not device_id):\n            raise BadResponseError(route=route)\n        if operation_id is None:\n            operation_id = _ids.new_uuid()\n        if not isinstance(operation_id, str) or not operation_id:\n            raise BadResponseError(route=route)\n        body = {\n            "operation_id": operation_id,\n            "customer_id": customer_id,\n            "amount": amount,\n            "note": note,\n            "kind": kind,\n            "image": image,\n            "device_id": device_id,\n        }\n        return self._request("POST", route, body=body)\n\n'''
    old_cursor = '''        result = PushResult(applied, rows, cursor)\n        if result.cursor >= self.config.cursor:\n            # The server's cursor only ever moves forward; adopting it here is\n            # what keeps a pull after a push from re-reading what we just wrote.\n            self.config.set_cursor(result.cursor)\n            self.config.save()\n        return result\n'''
    new_cursor = '''        # A mutation response cursor is NOT a read checkpoint. Another desktop\n        # may have committed unseen changes between our previous pull cursor\n        # and this mutation. Advancing here would skip those rows forever.\n        # Only bootstrap/pull may advance the durable read cursor; replaying\n        # our own change on the next pull is safe because apply is versioned.\n        return PushResult(applied, rows, cursor)\n'''
    patch("cloud_sync/client.py", [
        ("ledger method", append_anchor, append_method, 1),
        ("push cursor", old_cursor, new_cursor, 1),
    ])


def patch_index():
    class_old = '''    'RateLimit', 'Auth', 'Devices', 'Sync', 'Import',\n'''
    class_new = '''    'RateLimit', 'Auth', 'Devices', 'Sync', 'Import', 'Finance',\n'''
    routes_old = '''        '/sync/mutations' => ['POST'],\n        '/bootstrap/import' => ['POST'],\n'''
    routes_new = '''        '/sync/mutations' => ['POST'],\n        '/finance/transactions/append' => ['POST'],\n        '/bootstrap/import' => ['POST'],\n'''
    service_old = '''    $sync = new Sync($db, $log, $config);\n    $import = new Import($db, $sync, $log, $config);\n'''
    service_new = '''    $sync = new Sync($db, $log, $config);\n    $import = new Import($db, $sync, $log, $config);\n    $finance = new Finance($db, $log, $config);\n'''
    case_anchor = '''        case '/bootstrap/import':\n'''
    finance_case = '''        case '/finance/transactions/append':\n            $device = requireDevice($auth, $request);\n            $body = $request->jsonBody();\n            $acting = $auth->actingUser($request);\n            $context = [\n                'device' => $device,\n                'user' => $acting,\n                'role' => $auth->effectiveRole([\n                    'device' => $device, 'user' => $acting,\n                ]),\n            ];\n            $payload = $finance->append($body, $context, $requestId);\n            $statusCode = 200;\n            $errorCode = '';\n            Response::ok($payload);\n            break;\n\n''' + case_anchor
    patch("host/public/index.php", [
        ("Finance require", class_old, class_new, 1),
        ("Finance route", routes_old, routes_new, 1),
        ("Finance service", service_old, service_new, 1),
        ("Finance case", case_anchor, finance_case, 1),
    ])


def patch_transport_test():
    anchor = '''    def test_operation_id_is_minted_once_into_the_caller_dict(self):\n'''
    test = '''    def test_push_never_advances_the_durable_pull_cursor(self):\n        self.enrol()\n        before = self.config.cursor\n        result = self.client.push([self.operation()])\n        self.assertGreater(result.cursor, before)\n        self.assertEqual(self.config.cursor, before)\n\n''' + anchor
    patch("lab/tests/test_cloud_transport.py", [
        ("push cursor test", anchor, test, 1),
    ])


def patch_finance_test():
    path = ROOT / "lab" / "tests" / "test_server_crm_v2_finance.py"
    text = path.read_text(encoding="utf-8")
    old_setup = '''    def setUpClass(cls):\n        cls.source = read(os.path.join(HOST, "src", "Finance.php"))\n'''
    new_setup = '''    def setUpClass(cls):\n        cls.source = read(os.path.join(HOST, "src", "Finance.php"))\n        cls.index = read(os.path.join(HOST, "public", "index.php"))\n        cls.client = read(os.path.join(ROOT, "cloud_sync", "client.py"))\n'''
    old_tail = '''        self.assertNotIn("floatval", self.source)\n        self.assertNotIn("(float)", self.source)\n'''
    new_tail = old_tail + '''\n    def test_route_and_client_use_the_finance_append_boundary(self):\n        self.assertIn("'Finance'", self.index)\n        self.assertIn("'/finance/transactions/append' => ['POST']", self.index)\n        self.assertIn("$finance->append($body, $context, $requestId)", self.index)\n        self.assertIn("def append_ledger_transaction", self.client)\n        self.assertIn('route = "/finance/transactions/append"', self.client)\n\n'''
    for label, old, new in (
        ("static setup", old_setup, new_setup),
        ("transport assertions", old_tail, new_tail),
    ):
        count = text.count(old)
        if count != 1:
            raise RuntimeError(f"finance test {label}: expected 1, found {count}")
        text = text.replace(old, new, 1)
    path.write_text(text, encoding="utf-8")


def main():
    patch_client()
    patch_index()
    patch_transport_test()
    patch_finance_test()
    print("phase 4 finance transport patch applied")


if __name__ == "__main__":
    main()
