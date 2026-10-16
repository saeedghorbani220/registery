# -*- coding: utf-8 -*-
"""Client contract tests for server CRM v2 device lifecycle routes."""
import json
import unittest

from cloud_sync.client import SyncClient
from cloud_sync.errors import BadResponseError, HttpError


class _Config:
    def __init__(self):
        self.sync_device_id = None
        self.cursor = 0
        self.saved = 0

    def url(self, route):
        return "https://api.example.test/v1" + route

    def save(self):
        self.saved += 1

    def set_cursor(self, value, epoch=None):
        self.cursor = value


class _Vault:
    def __init__(self):
        self.user_access_token = "user-access"
        self.access_token = None
        self.device_refresh_token = None
        self.saved_refresh = None

    @property
    def has_device_credentials(self):
        return bool(self.device_refresh_token)

    def save_device_refresh(self, token):
        self.saved_refresh = token
        self.device_refresh_token = token

    def set_access(self, token, ttl):
        self.access_token = token

    def revoke_local(self):
        self.access_token = None
        self.device_refresh_token = None


class _Response:
    def __init__(self, status, payload):
        self.status_code = status
        self.headers = {}
        self.content = json.dumps(payload).encode("utf-8")


def _ok(**payload):
    return _Response(200, {"ok": True, **payload})


def _error(status, code):
    return _Response(status, {
        "ok": False,
        "error": {
            "code": code,
            "message": "redacted test error",
            "request_id": "12345678-1234-4234-8234-123456789abc",
        },
    })


class ClientDeviceLifecycleTests(unittest.TestCase):
    def client(self, handler):
        return SyncClient(
            config=_Config(), vault=_Vault(), send=handler,
            clock=lambda: 1.0,
        )

    def test_enroll_prefers_self_enroll(self):
        seen = []

        def send(method, url, headers, body, timeout):
            seen.append((method, url, headers, body))
            self.assertTrue(url.endswith("/sync-devices/self-enroll"))
            return _ok(
                sync_device_id="dev-self",
                device_refresh_token="refresh-self",
                tenant_id="tenant-1",
            )

        client = self.client(send)
        result = client.enroll()
        self.assertEqual(result["sync_device_id"], "dev-self")
        self.assertEqual(client.config.sync_device_id, "dev-self")
        self.assertEqual(client.vault.saved_refresh, "refresh-self")
        self.assertEqual(client.config.saved, 1)
        self.assertEqual(seen[0][2]["Authorization"], "Bearer user-access")

    def test_enroll_falls_back_only_when_new_route_is_missing(self):
        routes = []

        def send(method, url, headers, body, timeout):
            route = url.split("/v1", 1)[1]
            routes.append(route)
            if route == "/sync-devices/self-enroll":
                return _error(404, "HTTP_404")
            self.assertEqual(route, "/sync-devices/enroll")
            return _ok(
                sync_device_id="dev-legacy",
                device_refresh_token="refresh-legacy",
            )

        client = self.client(send)
        client.enroll()
        self.assertEqual(routes, [
            "/sync-devices/self-enroll",
            "/sync-devices/enroll",
        ])
        self.assertEqual(client.config.sync_device_id, "dev-legacy")

    def test_enroll_does_not_turn_forbidden_into_legacy_retry(self):
        routes = []

        def send(method, url, headers, body, timeout):
            routes.append(url.split("/v1", 1)[1])
            return _error(403, "ROLE_FORBIDDEN")

        client = self.client(send)
        with self.assertRaises(HttpError) as raised:
            client.enroll()
        self.assertEqual(raised.exception.status, 403)
        self.assertEqual(routes, ["/sync-devices/self-enroll"])

    def test_revoke_routes_use_user_token_and_explicit_json(self):
        calls = []

        def send(method, url, headers, body, timeout):
            calls.append({
                "method": method,
                "route": url.split("/v1", 1)[1],
                "auth": headers.get("Authorization"),
                "body": json.loads(body.decode("utf-8")),
            })
            if url.endswith("/revoke-all"):
                return _ok(user_id="user-2", matched_devices=2, revoked_devices=2)
            return _ok(sync_device_id="device-1", revoked=True, changed=True)

        client = self.client(send)
        client.revoke_device("device-1")
        client.revoke_all_devices("user-2")
        self.assertEqual(calls, [
            {
                "method": "POST",
                "route": "/sync-devices/revoke",
                "auth": "Bearer user-access",
                "body": {"sync_device_id": "device-1"},
            },
            {
                "method": "POST",
                "route": "/sync-devices/revoke-all",
                "auth": "Bearer user-access",
                "body": {"user_id": "user-2"},
            },
        ])

    def test_revoke_argument_validation_does_not_send(self):
        def send(*args):
            self.fail("invalid input must not reach the network")

        client = self.client(send)
        with self.assertRaises(BadResponseError):
            client.revoke_device("")
        with self.assertRaises(BadResponseError):
            client.revoke_all_devices(7)


if __name__ == "__main__":
    unittest.main()
