# -*- coding: utf-8 -*-
"""Cloud sync conflict UI, pull & import wiring (workstream E).

Tests for:
* GET /cloud-conflicts (gated, reads outbox.conflicts(), format)
* POST /cloud-resolve-conflict (keep_local, accept_server, CAS, store write)
* cloud_worker_beat pull integration (apply_changes, apply_snapshot, versions, dirty)
* POST /cloud-import (admin-only, run_import, DATASET_NOT_EMPTY, IMPORT_CONFLICT)
* Persian error messages and UI rendering in PAGE_JS

Offline throughout: temp directories, loopback server, mocks.
No writes to %LOCALAPPDATA%\\irica\\.
"""
import copy
import json
import os
import re
import shutil
import sys
import tempfile
import time
import unittest
from unittest.mock import patch, MagicMock

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
TESTS = os.path.dirname(os.path.abspath(__file__))
for path in (ROOT, TESTS):
    if path not in sys.path:
        sys.path.insert(0, path)

import app_paths
import crm
import panel
import panel_auth
from cloud_sync import apply, ids, importer, mapper
from cloud_sync.errors import (
    AuthRequiredError, CloudSyncError, ConfigError, HttpError, RemoteNotReadyError
)
from cloud_sync.lease import LeaseExpiredError, OfflineLease
from cloud_sync.outbox import Entry, Outbox
from cloud_sync.state import (
    IllegalTransitionError, SyncEvent, SyncState, SyncStateMachine
)
from test_cloud_ui import (
    _FakeClient, _FakeLease, _FakeMachine, _FakeOutbox, _FakeVault,
    _fake_config, _fake_runtime, fn_body, node_syntax, reset_cloud_panel,
    run_node, NODE
)
from test_v1_2_0_login_gate import _GateHarness


def _make_conflict_entry(operation_id="op-1", entity="owners", record_id="own-1",
                         base_version=1, local_record=None, server_version=2,
                         server_record=None):
    if local_record is None:
        local_record = {"id": record_id, "first_name": "Local", "last_name": "Name"}
    if server_record is None:
        server_record = {"id": record_id, "first_name": "Server", "last_name": "Name"}
    op = {
        "kind": "upsert",
        "entity": entity,
        "id": record_id,
        "base_version": base_version,
        "record": local_record,
    }
    conflict = {
        "operation_id": operation_id,
        "entity": entity,
        "id": record_id,
        "server_version": server_version,
        "server_record": server_record,
    }
    return Entry(
        operation_id=operation_id,
        operation=op,
        attempts=1,
        parked="conflict",
        conflict=conflict,
        code="VERSION_CONFLICT",
    )


def _ok_machine(state=SyncState.IDLE, apply_error=None):
    return _FakeMachine(state=state, apply_error=apply_error)


class _TestClient(_FakeClient):
    def import_document(self, body):
        return {"ok": True}


def _test_config(**kwargs):
    cfg = _fake_config(**kwargs)
    cfg.save = MagicMock()
    return cfg


def _make_import_result(ok=True, code=None, backup_path="C:/fake/backup.json",
                        payload=None, terminal=False):
    return importer.ImportResult(
        ok=ok,
        code=code or ("" if ok else "SERVER_ERROR"),
        import_id="11111111-1111-4111-8111-111111111111",
        backup_path=backup_path,
        attempts=1,
        payload=payload if payload is not None else ({"cursor": 15, "dataset_epoch": 2} if ok else None),
        dropped_settings=(),
        terminal=terminal,
    )


# =====================================================================
# 1. Conflict endpoints: GET /cloud-conflicts
# =====================================================================
class ConflictEndpointTests(_GateHarness):
    def setUp(self):
        super().setUp()
        reset_cloud_panel()
        self.addCleanup(reset_cloud_panel)
        self.outbox_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.outbox_dir.cleanup)
        self.outbox_path = os.path.join(self.outbox_dir.name, "outbox.jsonl")
        self.outbox = Outbox(path=self.outbox_path)

    def test_get_conflicts_unauthenticated_returns_401(self):
        status, _h, body = self._op("/cloud-conflicts")
        self.assertEqual(status, 401)
        payload = json.loads(body)
        self.assertFalse(payload["ok"])

    def test_get_conflicts_empty_outbox(self):
        cookie = self.login()
        runtime = _fake_runtime(outbox=self.outbox)
        with patch.object(panel, "_cloud_runtime", return_value=runtime):
            status, _h, body = self.authed("/cloud-conflicts", cookie)
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["conflicts"], [])

    def test_get_conflicts_returns_parked_conflicts(self):
        cookie = self.login()
        entry = _make_conflict_entry(
            operation_id="op-test-1",
            entity="owners",
            record_id="own-42",
            local_record={"id": "own-42", "first_name": "Ali"},
            server_version=3,
            server_record={"id": "own-42", "first_name": "Reza"},
        )
        self.outbox.enqueue(entry.operation, operation_id="op-test-1")
        self.outbox.park("op-test-1", "conflict", code="VERSION_CONFLICT",
                         conflict=entry.conflict)

        runtime = _fake_runtime(outbox=self.outbox)
        with patch.object(panel, "_cloud_runtime", return_value=runtime):
            status, _h, body = self.authed("/cloud-conflicts", cookie)
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertTrue(payload["ok"])
        self.assertEqual(len(payload["conflicts"]), 1)
        c = payload["conflicts"][0]
        self.assertEqual(c["operation_id"], "op-test-1")
        self.assertEqual(c["entity"], "owners")
        self.assertEqual(c["id"], "own-42")
        self.assertEqual(c["local_record"], {"id": "own-42", "first_name": "Ali"})
        self.assertEqual(c["server_record"], {"id": "own-42", "first_name": "Reza"})
        self.assertEqual(c["server_version"], 3)

    def test_get_conflicts_excludes_attempts_parked(self):
        cookie = self.login()
        op = {"kind": "upsert", "entity": "owners", "id": "own-x", "base_version": 1,
              "record": {"id": "own-x"}}
        self.outbox.enqueue(op, operation_id="op-att")
        self.outbox.park("op-att", "attempts", code="HTTP_500")

        runtime = _fake_runtime(outbox=self.outbox)
        with patch.object(panel, "_cloud_runtime", return_value=runtime):
            status, _h, body = self.authed("/cloud-conflicts", cookie)
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertEqual(payload["conflicts"], [])


# =====================================================================
# 2. Conflict resolution: POST /cloud-resolve-conflict
# =====================================================================
class ConflictResolutionTests(_GateHarness):
    def setUp(self):
        super().setUp()
        reset_cloud_panel()
        self.addCleanup(reset_cloud_panel)
        self.outbox_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.outbox_dir.cleanup)
        self.outbox_path = os.path.join(self.outbox_dir.name, "outbox.jsonl")
        self.outbox = Outbox(path=self.outbox_path)
        self.store_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.store_dir.cleanup)
        self.store_path = os.path.join(self.store_dir.name, "crm_store.json")
        with open(self.store_path, "w", encoding="utf-8") as f:
            json.dump({
                "version": 1,
                "customers": [{"id": "c1", "full_name": "Customer 1", "transactions": [{"seq": 0, "amount": 100}]}],
                "owners": [{"id": "own-1", "first_name": "Original", "last_name": "Owner"}],
                "identities": [{"id": "id-1", "label": "Pool 1"}],
                "devices": [{"id": "d1", "name": "Device 1"}],
                "periods": [{"id": "p1", "number": 1}],
                "settings": {"business_name": "Initial Biz"},
            }, f, indent=1)
        self._crm_store_patch = patch.object(crm, "_store_path", return_value=self.store_path)
        self._crm_store_patch.start()
        self.addCleanup(self._crm_store_patch.stop)

    def _own_origin(self):
        return "http://127.0.0.1:%d" % self.port

    def _session_csrf(self, cookie):
        token = cookie.split("irica_session=", 1)[1].split(";", 1)[0]
        return panel_auth.session_csrf(token) or ""

    def test_resolve_unauthenticated_returns_401(self):
        status, _h, body = self._op("/cloud-resolve-conflict", data={
            "operation_id": "op-1", "resolution": "keep_local"
        })
        self.assertEqual(status, 401)

    def test_resolve_missing_csrf_returns_403(self):
        cookie = self.login()
        status, _h, body = self._op("/cloud-resolve-conflict", data={
            "operation_id": "op-1", "resolution": "keep_local"
        }, headers={"Cookie": cookie, "Origin": self._own_origin()})
        self.assertEqual(status, 403)

    def test_resolve_cross_origin_returns_403(self):
        cookie = self.login()
        status, _h, _b = self._op("/cloud-resolve-conflict", data={
            "operation_id": "op-1", "resolution": "keep_local"
        }, headers={"Cookie": cookie, "Origin": "http://evil.invalid",
                    "X-CSRF-Token": self._session_csrf(cookie)})
        self.assertEqual(status, 403)

    def test_resolve_bad_payload(self):
        cookie = self.login()
        # Missing fields
        for bad in ({}, {"operation_id": "op-1"}, {"resolution": "keep_local"},
                    {"operation_id": "op-1", "resolution": "bogus"}):
            status, _h, body = self.authed("/cloud-resolve-conflict", cookie, data=bad)
            self.assertEqual(status, 400)
            payload = json.loads(body)
            self.assertEqual(payload["code"], "BAD_PAYLOAD")

    def test_resolve_unknown_operation_returns_404(self):
        cookie = self.login()
        runtime = _fake_runtime(outbox=self.outbox)
        with patch.object(panel, "_cloud_runtime", return_value=runtime):
            status, _h, body = self.authed("/cloud-resolve-conflict", cookie, data={
                "operation_id": "nonexistent", "resolution": "keep_local"
            })
        self.assertEqual(status, 404)
        payload = json.loads(body)
        self.assertEqual(payload["code"], "HTTP_404")

    def test_resolve_not_a_conflict_returns_409(self):
        cookie = self.login()
        op = {"kind": "upsert", "entity": "owners", "id": "own-1", "base_version": 1,
              "record": {"id": "own-1"}}
        self.outbox.enqueue(op, operation_id="op-pending")
        runtime = _fake_runtime(outbox=self.outbox)
        with patch.object(panel, "_cloud_runtime", return_value=runtime):
            status, _h, body = self.authed("/cloud-resolve-conflict", cookie, data={
                "operation_id": "op-pending", "resolution": "keep_local"
            })
        self.assertEqual(status, 409)
        payload = json.loads(body)
        self.assertEqual(payload["code"], "TRANSITION_NOT_LEGAL")

    def test_resolve_keep_local_updates_base_version_and_releases(self):
        cookie = self.login()
        op = {"kind": "upsert", "entity": "owners", "id": "own-1", "base_version": 1,
              "record": {"id": "own-1", "first_name": "Local"}}
        self.outbox.enqueue(op, operation_id="op-kl")
        self.outbox.park("op-kl", "conflict", code="VERSION_CONFLICT",
                         conflict={"server_version": 5, "server_record": {"id": "own-1", "first_name": "Server"}})
        self.assertEqual(self.outbox.conflict_count, 1)

        machine = _ok_machine()
        machine._conflict_count = 1
        runtime = _fake_runtime(outbox=self.outbox, machine=machine)
        with patch.object(panel, "_cloud_runtime", return_value=runtime), \
             patch.object(panel, "cloud_worker_kick") as mock_kick:
            status, _h, body = self.authed("/cloud-resolve-conflict", cookie, data={
                "operation_id": "op-kl", "resolution": "keep_local"
            })
            self.assertEqual(status, 200)
            payload = json.loads(body)
            self.assertTrue(payload["ok"])
            self.assertEqual(payload["resolved"], "keep_local")
            mock_kick.assert_called_once()

        # Operation base_version was updated to server_version (5) and re-keyed to a fresh operation_id
        self.assertIsNone(self.outbox.get("op-kl"))
        self.assertEqual(len(self.outbox.entries()), 1)
        entry = self.outbox.entries()[0]
        self.assertEqual(entry.operation["base_version"], 5)
        self.assertIsNone(entry.parked)
        self.assertEqual(self.outbox.conflict_count, 0)
        self.assertEqual(self.outbox.pending_count, 1)

    def test_resolve_accept_server_applies_to_store_and_marks_done(self):
        cookie = self.login()
        op = {"kind": "upsert", "entity": "owners", "id": "own-1", "base_version": 1,
              "record": {"id": "own-1", "first_name": "MyLocalEdit", "last_name": "Owner"}}
        self.outbox.enqueue(op, operation_id="op-as")
        server_owner = {"id": "own-1", "first_name": "ServerWinner", "last_name": "Owner"}
        self.outbox.park("op-as", "conflict", code="VERSION_CONFLICT",
                         conflict={"server_version": 4, "server_record": server_owner})

        runtime = _fake_runtime(outbox=self.outbox)
        with patch.object(panel, "_cloud_runtime", return_value=runtime):
            status, _h, body = self.authed("/cloud-resolve-conflict", cookie, data={
                "operation_id": "op-as", "resolution": "accept_server"
            })
            self.assertEqual(status, 200)
            payload = json.loads(body)
            self.assertTrue(payload["ok"])
            self.assertEqual(payload["resolved"], "accept_server")

        # Outbox marked done
        self.assertIsNone(self.outbox.get("op-as"))
        self.assertEqual(self.outbox.conflict_count, 0)
        self.assertEqual(self.outbox.pending_count, 0)

        # Local store was updated with server_record
        with open(self.store_path, "r", encoding="utf-8") as f:
            doc = json.load(f)
        owner = next(o for o in doc["owners"] if o["id"] == "own-1")
        self.assertEqual(owner["first_name"], "ServerWinner")

    def test_resolve_accept_server_customer_preserves_transactions(self):
        cookie = self.login()
        op = {"kind": "upsert", "entity": "customers", "id": "c1", "base_version": 1,
              "record": {"id": "c1", "full_name": "Local Customer Edit"}}
        self.outbox.enqueue(op, operation_id="op-cust")
        server_customer = {"id": "c1", "full_name": "Server Customer Name"}
        self.outbox.park("op-cust", "conflict", code="VERSION_CONFLICT",
                         conflict={"server_version": 2, "server_record": server_customer})

        runtime = _fake_runtime(outbox=self.outbox)
        with patch.object(panel, "_cloud_runtime", return_value=runtime):
            status, _h, body = self.authed("/cloud-resolve-conflict", cookie, data={
                "operation_id": "op-cust", "resolution": "accept_server"
            })
            self.assertEqual(status, 200)

        with open(self.store_path, "r", encoding="utf-8") as f:
            doc = json.load(f)
        cust = next(c for c in doc["customers"] if c["id"] == "c1")
        self.assertEqual(cust["full_name"], "Server Customer Name")
        # Local transactions list preserved
        self.assertEqual(len(cust["transactions"]), 1)
        self.assertEqual(cust["transactions"][0]["amount"], 100)

    def test_resolve_accept_server_tombstone(self):
        cookie = self.login()
        op = {"kind": "upsert", "entity": "owners", "id": "own-1", "base_version": 1,
              "record": {"id": "own-1", "first_name": "StillHere"}}
        self.outbox.enqueue(op, operation_id="op-del")
        self.outbox.park("op-del", "conflict", code="VERSION_CONFLICT",
                         conflict={"server_version": 3, "server_record": None})

        runtime = _fake_runtime(outbox=self.outbox)
        with patch.object(panel, "_cloud_runtime", return_value=runtime):
            status, _h, body = self.authed("/cloud-resolve-conflict", cookie, data={
                "operation_id": "op-del", "resolution": "accept_server"
            })
            self.assertEqual(status, 200)

        with open(self.store_path, "r", encoding="utf-8") as f:
            doc = json.load(f)
        self.assertEqual([o for o in doc["owners"] if o["id"] == "own-1"], [])


# =====================================================================
# 3. Pull integration: cloud_pull_step & worker beat
# =====================================================================
class PullIntegrationTests(unittest.TestCase):
    def setUp(self):
        reset_cloud_panel()
        self.addCleanup(reset_cloud_panel)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store_path = os.path.join(self.tmp.name, "crm_store.json")
        with open(self.store_path, "w", encoding="utf-8") as f:
            json.dump({"version": 1, "customers": [], "owners": [], "identities": [],
                       "devices": [], "periods": [], "settings": {}}, f)
        self._store_patch = patch.object(crm, "_store_path", return_value=self.store_path)
        self._store_patch.start()
        self.addCleanup(self._store_patch.stop)

        self.versions_path = os.path.join(self.tmp.name, "cloud_sync_versions.json")
        self._versions_patch = patch.object(panel, "_cloud_versions_path",
                                            return_value=self.versions_path)
        self._versions_patch.start()
        self.addCleanup(self._versions_patch.stop)

    def test_pull_step_skipped_when_not_enrolled(self):
        config = _fake_config(api_base="https://api.test", sync_device_id="")
        runtime = _fake_runtime(config=config)
        res = panel.cloud_pull_step(runtime)
        self.assertEqual(res["skipped"], "not_enrolled")

    def test_pull_step_initial_bootstrap_when_cursor_zero(self):
        config = _fake_config(api_base="https://api.test", sync_device_id="dev-1",
                              cursor=0, source_installation_id="inst-1")
        client = MagicMock()
        client.bootstrap.return_value = {
            "collections": {
                "customers": [],
                "owners": [{"id": "uuid-own-1", "tenant_id": "ten-1",
                            "row_version": 1, "record": {"id": "o1", "first_name": "Test"}}],
                "identities": [], "devices": [], "periods": [], "settings": [],
                "customer_transactions": [],
            },
            "cursor": 10,
            "dataset_epoch": 1,
        }
        lease = _FakeLease(granted=time.time())
        runtime = _fake_runtime(config=config, client=client, lease=lease)

        with patch("cloud_sync.apply.apply_snapshot") as mock_snapshot:
            mock_snapshot.return_value = apply.ApplyReport(applied=1, written=True)
            res = panel.cloud_pull_step(runtime)

        self.assertEqual(res["pulled"], 1)
        client.bootstrap.assert_called_once()
        mock_snapshot.assert_called_once()

    def test_pull_step_incremental_when_cursor_positive(self):
        # A positive cursor only represents an initialized client when the
        # authoritative dataset epoch has already been committed as well.
        config = _fake_config(api_base="https://api.test", sync_device_id="dev-1",
                              cursor=10, dataset_epoch=1,
                              source_installation_id="inst-1")
        client = MagicMock()
        client.pull_all.return_value = 2
        lease = _FakeLease(granted=time.time())
        runtime = _fake_runtime(config=config, client=client, lease=lease)

        res = panel.cloud_pull_step(runtime)
        self.assertEqual(res["pulled"], 2)
        client.pull_all.assert_called_once()

    def test_pull_step_protects_dirty_rows(self):
        outbox_file = os.path.join(self.tmp.name, "outbox.jsonl")
        outbox = Outbox(path=outbox_file)
        outbox.enqueue({"kind": "upsert", "entity": "owners", "id": "own-dirty",
                        "base_version": 1, "record": {"id": "own-dirty"}},
                       operation_id="op-d")
        dirty = panel._cloud_dirty_set(outbox)
        self.assertIn(("owners", "own-dirty"), dirty)
        self.assertIn("own-dirty", dirty)

    def test_pull_step_returns_skipped_when_remote_not_ready(self):
        config = _fake_config(api_base="https://api.test", sync_device_id="dev-1",
                              cursor=0, source_installation_id="inst-1")
        client = MagicMock()
        client.bootstrap.return_value = {
            "collections": {entity: [] for entity in ("customers", "owners", "identities", "devices", "periods", "settings", "customer_transactions")},
            "cursor": 0,
            "dataset_epoch": 0,
            "bootstrap_status": "pending",
        }
        lease = _FakeLease(granted=time.time())
        runtime = _fake_runtime(config=config, client=client, lease=lease)

        with patch("cloud_sync.apply.apply_snapshot", side_effect=RemoteNotReadyError):
            res = panel.cloud_pull_step(runtime)

        self.assertEqual(res, {"pulled": 0, "skipped": "remote_not_ready"})

    def test_worker_beat_catches_lease_expired_by_name(self):
        config = _fake_config(api_base="https://api.test", sync_device_id="dev-1")
        lease = _FakeLease(granted=1.0, expired=True)
        worker = MagicMock()
        runtime = _fake_runtime(config=config, lease=lease, worker=worker)
        with patch.object(panel, "_cloud_runtime", return_value=runtime):
            beat = panel.cloud_worker_beat()
        self.assertEqual(beat["code"], "LEASE_EXPIRED")

    def test_worker_beat_catches_illegal_transition_by_name(self):
        # This test targets the state-machine error path, not first bootstrap.
        # Mark the fake runtime as already bound to an authoritative dataset.
        config = _fake_config(api_base="https://api.test", sync_device_id="dev-1",
                              dataset_epoch=1)
        lease = _FakeLease(granted=time.time())
        worker = MagicMock()
        worker.bind_auth.return_value = (None, None)
        worker.run_once.side_effect = IllegalTransitionError(
            SyncState.DISABLED, SyncEvent.START_SYNC, "not legal")
        runtime = _fake_runtime(config=config, lease=lease, worker=worker)
        with patch.object(panel, "_cloud_runtime", return_value=runtime):
            beat = panel.cloud_worker_beat()
        self.assertEqual(beat["code"], "TRANSITION_NOT_LEGAL")


# =====================================================================
# 4. Import endpoint: POST /cloud-import
# =====================================================================
class ImportEndpointTests(_GateHarness):
    def setUp(self):
        super().setUp()
        reset_cloud_panel()
        self.addCleanup(reset_cloud_panel)

    def _own_origin(self):
        return "http://127.0.0.1:%d" % self.port

    def _session_csrf(self, cookie):
        token = cookie.split("irica_session=", 1)[1].split(";", 1)[0]
        return panel_auth.session_csrf(token) or ""

    def test_import_unauthenticated_returns_401(self):
        status, _h, body = self._op("/cloud-import", data={})
        self.assertEqual(status, 401)

    def test_import_missing_csrf_returns_403(self):
        cookie = self.login()
        status, _h, body = self._op("/cloud-import", data={},
                                    headers={"Cookie": cookie, "Origin": self._own_origin()})
        self.assertEqual(status, 403)

    def test_import_non_admin_returns_403(self):
        cookie = self.login()
        panel._CLOUD_ACTOR = "regular-user"
        panel._CLOUD_ROLE = "user"
        client = _FakeClient(vault=_FakeVault("live-token"))
        runtime = _fake_runtime(client=client)
        with patch.object(panel, "_cloud_runtime", return_value=runtime):
            status, _h, body = self.authed("/cloud-import", cookie, data={})
        self.assertEqual(status, 403)
        payload = json.loads(body)
        self.assertEqual(payload["code"], "HTTP_403")

    def test_import_not_enrolled_returns_400(self):
        cookie = self.login()
        panel._CLOUD_ACTOR = "admin-op"
        panel._CLOUD_ROLE = "admin"
        client = _FakeClient(vault=_FakeVault("live-token"))
        config = _fake_config(api_base="https://api.test", sync_device_id="")
        runtime = _fake_runtime(client=client, config=config)
        with patch.object(panel, "_cloud_runtime", return_value=runtime):
            status, _h, body = self.authed("/cloud-import", cookie, data={})
        self.assertEqual(status, 400)
        payload = json.loads(body)
        self.assertEqual(payload["code"], "ENROL_REQUIRED")

    def test_import_success(self):
        cookie = self.login()
        panel._CLOUD_ACTOR = "admin-op"
        panel._CLOUD_ROLE = "admin"
        client = _TestClient(vault=_FakeVault("live-token"))
        config = _test_config(api_base="https://api.test", sync_device_id="dev-1",
                              cursor=0, source_installation_id="inst-1")
        runtime = _fake_runtime(client=client, config=config)

        mock_result = _make_import_result(
            ok=True,
            backup_path="C:/fake/backup.json",
            payload={"cursor": 15, "dataset_epoch": 2, "counts": {"owners": 5}},
        )
        with patch.object(panel, "_cloud_runtime", return_value=runtime), \
             patch("cloud_sync.importer.run_import", return_value=mock_result):
            status, _h, body = self.authed("/cloud-import", cookie, data={})

        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["imported"])
        self.assertEqual(payload["backup_path"], "C:/fake/backup.json")
        self.assertEqual(config.cursor, 15)
        self.assertEqual(config.dataset_epoch, 2)
        config.save.assert_called_once()

    def test_import_dataset_not_empty_returns_409(self):
        cookie = self.login()
        panel._CLOUD_ACTOR = "admin-op"
        panel._CLOUD_ROLE = "admin"
        client = _TestClient(vault=_FakeVault("live-token"))
        config = _test_config(api_base="https://api.test", sync_device_id="dev-1")
        runtime = _fake_runtime(client=client, config=config)

        mock_result = _make_import_result(
            ok=False,
            code="DATASET_NOT_EMPTY",
            terminal=True,
        )
        with patch.object(panel, "_cloud_runtime", return_value=runtime), \
             patch("cloud_sync.importer.run_import", return_value=mock_result), \
             patch.object(panel, "cloud_pull_step", return_value={"pulled": 0}):
            status, _h, body = self.authed("/cloud-import", cookie, data={})

        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertTrue(payload["ok"])
        self.assertTrue(payload.get("merged"))
        self.assertTrue(payload.get("imported"))
        self.assertIn("ادغام", payload.get("message", ""))

    def test_import_conflict_returns_409(self):
        cookie = self.login()
        panel._CLOUD_ACTOR = "admin-op"
        panel._CLOUD_ROLE = "admin"
        client = _TestClient(vault=_FakeVault("live-token"))
        config = _test_config(api_base="https://api.test", sync_device_id="dev-1")
        runtime = _fake_runtime(client=client, config=config)

        mock_result = _make_import_result(
            ok=False,
            code="IMPORT_CONFLICT",
            terminal=True,
        )
        with patch.object(panel, "_cloud_runtime", return_value=runtime), \
             patch("cloud_sync.importer.run_import", return_value=mock_result):
            status, _h, body = self.authed("/cloud-import", cookie, data={})

        self.assertEqual(status, 409)
        payload = json.loads(body)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["code"], "IMPORT_CONFLICT")
        self.assertIn("شناسه یا محتوای انتقال", payload["errors"][0])


# =====================================================================
# 5. Persian writing rules & error message mapping
# =====================================================================
class ErrorMessagesAndPersianTests(unittest.TestCase):
    def test_import_codes_in_messages_table(self):
        self.assertIn("DATASET_NOT_EMPTY", panel.CLOUD_ERROR_MESSAGES)
        self.assertIn("IMPORT_CONFLICT", panel.CLOUD_ERROR_MESSAGES)

    def test_persian_compliance_of_new_codes(self):
        for code in ("DATASET_NOT_EMPTY", "IMPORT_CONFLICT"):
            msg = panel.CLOUD_ERROR_MESSAGES[code]
            self.assertIsNone(re.search(r"[A-Za-z0-9]", msg), f"{code} has ASCII: {msg}")
            self.assertNotIn("—", msg, f"{code} has em dash")
            self.assertNotIn('"', msg, f"{code} has ASCII quotes")
            self.assertNotIn("  ", msg, f"{code} has double spaces")
            self.assertNotIn("ي", msg, f"{code} has Arabic yeh")
            self.assertNotIn("ك", msg, f"{code} has Arabic kaf")
            self.assertNotIn("‌ ", msg, f"{code} has ZWNJ before space")
            self.assertNotIn("‌‌", msg, f"{code} has double ZWNJ")


# =====================================================================
# 6. Versions persistence helpers
# =====================================================================
class VersionsPersistenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "cloud_sync_versions.json")

    def test_load_nonexistent_returns_empty_dict(self):
        self.assertEqual(panel._load_cloud_versions(self.path), {})

    def test_save_and_load_roundtrip(self):
        versions = {
            ("owners", "uuid-1"): 2,
            ("customers", "uuid-2"): 5,
            ("settings", "settings/settings"): 1,
        }
        panel._save_cloud_versions(versions, self.path)
        loaded = panel._load_cloud_versions(self.path)
        self.assertEqual(loaded, versions)


# =====================================================================
# 7. JavaScript / UI tests
# =====================================================================
class UIAndJSTests(unittest.TestCase):
    def test_cloud_shell_has_import_button(self):
        shell = fn_body(panel.PAGE_JS, "cloudShellHtml")
        self.assertIn('id="cloud-import-btn"', shell)
        self.assertIn("انتقال پرونده‌های فعلی به سرور (Import)", shell)

    def test_render_cloud_conflicts_body_has_action_buttons(self):
        body = fn_body(panel.PAGE_JS, "renderCloudConflicts")
        self.assertIn("نگه‌داشتن تغییرات من (روی سرور ذخیره شود)", body)
        self.assertIn("پذیرش نسخه سرور (تغییرات محلی لغو شود)", body)
        self.assertIn("cloud-conflict-card", body)
        self.assertIn("cloud-conflict-table", body)

    def test_crm_page_contains_cloud_sync_surface_and_guide(self):
        self.assertIn("['cloud','سرور ابری']", panel.CRM_PAGE)
        self.assertIn('id="crmCloudPill"', panel.CRM_PAGE)
        self.assertIn("cloudTabHtml", panel.CRM_PAGE)
        self.assertIn("php bin/create-user.php", panel.CRM_PAGE)
        self.assertIn("loadCloudStatus", panel.CRM_PAGE)

    def test_render_body_preserves_cloud_tab_inputs_during_refresh(self):
        self.assertIn("if(TAB==='cloud'&&document.getElementById('cloud-sync-section'))", panel.CRM_PAGE)
        self.assertIn("paintCloud();", panel.CRM_PAGE)

    def test_cloud_sync_route_and_js_matching(self):
        self.assertIn("cloudPost('/cloud-sync'", panel.CRM_PAGE)
        with open(panel.__file__, "r", encoding="utf-8") as f:
            src = f.read()
        self.assertIn('elif self.path in ("/cloud-sync", "/cloud-sync-now"):', src)

    @unittest.skipUnless(NODE, "node is not installed")
    def test_all_cloud_functions_syntax_valid(self):
        for name in ("cloudShellHtml", "paintCloud", "renderCloudConflicts",
                     "fetchCloudConflicts", "resolveCloudConflict",
                     "cloudImportPrompt"):
            body = fn_body(panel.PAGE_JS, name)
            self.assertTrue(body, f"{name} not found in PAGE_JS")
            code, err = node_syntax(body)
            self.assertEqual(code, 0, f"{name} syntax error:\n{err}")


if __name__ == "__main__":
    unittest.main()
