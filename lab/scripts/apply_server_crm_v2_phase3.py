#!/usr/bin/env python3
"""One-shot source patcher for the server-authoritative CRM phase.

This exists only because panel.py is a very large generated-style monolith and
replacing it through a remote contents API is riskier than asserting and
patching a handful of exact contracts on a checked-out runner. The script is
idempotent only at the workflow level: every replacement must match exactly
once or the run fails closed before committing anything.
"""
from __future__ import annotations

import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[2]


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def write(rel: str, text: str) -> None:
    (ROOT / rel).write_text(text, encoding="utf-8")


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected exactly one match, found {count}")
    return text.replace(old, new, 1)


def patch_state() -> None:
    path = "cloud_sync/state.py"
    text = read(path)
    text = replace_once(
        text,
        '    "AUTH_EXPIRED", "AUTH_REVOKED", "BAD_PAYLOAD", "HTTP_409", "HTTP_429",\n',
        '    "AUTH_EXPIRED", "AUTH_REVOKED", "BAD_PAYLOAD", "BOOTSTRAP_REQUIRED",\n'
        '    "DATASET_EPOCH_MISMATCH", "HTTP_409", "HTTP_429",\n',
        "state known error codes",
    )
    write(path, text)


def patch_errors() -> None:
    path = "cloud_sync/errors.py"
    text = read(path)
    text = replace_once(
        text,
        '    "TRANSITION_NOT_LEGAL", "REMOTE_NOT_READY",\n',
        '    "TRANSITION_NOT_LEGAL", "REMOTE_NOT_READY", "BOOTSTRAP_REQUIRED",\n'
        '    "DATASET_EPOCH_MISMATCH",\n',
        "errors exports codes",
    )
    text = replace_once(
        text,
        '    "QueueFullError", "UnresolvedReferenceCloudError", "RemoteNotReadyError",\n',
        '    "QueueFullError", "UnresolvedReferenceCloudError", "RemoteNotReadyError",\n'
        '    "BootstrapRequiredError", "DatasetEpochMismatchError",\n',
        "errors exports classes",
    )
    text = replace_once(
        text,
        'REMOTE_NOT_READY = "REMOTE_NOT_READY"\n\n#: Everything this client may emit.',
        'REMOTE_NOT_READY = "REMOTE_NOT_READY"\n'
        '#: This device has not durably applied a bootstrap snapshot yet.\n'
        'BOOTSTRAP_REQUIRED = "BOOTSTRAP_REQUIRED"\n'
        '#: The server identifies a different dataset generation than the one\n'
        '#: this local cache was materialized from. Never auto-adopt it.\n'
        'DATASET_EPOCH_MISMATCH = "DATASET_EPOCH_MISMATCH"\n\n'
        '#: Everything this client may emit.',
        "errors constants",
    )
    text = replace_once(
        text,
        '    UNRESOLVED_REFERENCE, REMOTE_NOT_READY,\n})',
        '    UNRESOLVED_REFERENCE, REMOTE_NOT_READY, BOOTSTRAP_REQUIRED,\n'
        '    DATASET_EPOCH_MISMATCH,\n})',
        "errors client code set",
    )
    text = replace_once(
        text,
        'class RemoteNotReadyError(CloudSyncError):\n'
        '    """The server dataset is empty or unseeded while local store has records.\n\n'
        '    Raised at the snapshot apply boundary to prevent destroying local CRM data.\n'
        '    """\n\n'
        '    code = REMOTE_NOT_READY',
        'class RemoteNotReadyError(CloudSyncError):\n'
        '    """The server dataset is empty or unseeded while local store has records.\n\n'
        '    Raised at the snapshot apply boundary to prevent destroying local CRM data.\n'
        '    """\n\n'
        '    code = REMOTE_NOT_READY\n\n\n'
        'class BootstrapRequiredError(CloudSyncError):\n'
        '    """A device must materialize the authoritative snapshot before push/pull."""\n\n'
        '    code = BOOTSTRAP_REQUIRED\n\n\n'
        'class DatasetEpochMismatchError(CloudSyncError):\n'
        '    """The remote dataset generation differs from the local cache authority."""\n\n'
        '    code = DATASET_EPOCH_MISMATCH',
        "errors classes",
    )
    write(path, text)


def patch_client() -> None:
    path = "cloud_sync/client.py"
    text = read(path)
    text = replace_once(
        text,
        '    AuthRequiredError, AuthRevokedError, BadResponseError, HttpError,\n'
        '    RequestTimeoutError, UnreachableError, UnresolvedReferenceCloudError,\n'
        '    code_for_status, envelope_code, parse_retry_after, safe_code,\n'
        '    safe_request_id, AUTH_REQUIRED, AUTH_REVOKED, ENROL_REQUIRED,\n',
        '    AuthRequiredError, AuthRevokedError, BadResponseError, HttpError,\n'
        '    RequestTimeoutError, UnreachableError, UnresolvedReferenceCloudError,\n'
        '    BootstrapRequiredError, DatasetEpochMismatchError,\n'
        '    code_for_status, envelope_code, parse_retry_after, safe_code,\n'
        '    safe_request_id, AUTH_REQUIRED, AUTH_REVOKED, ENROL_REQUIRED,\n',
        "client imports",
    )
    old_bootstrap = '''    def bootstrap(self):\n        """``GET /sync/bootstrap`` — full snapshot + cursor + dataset epoch.\n\n        The returned cursor is persisted so the first incremental pull resumes\n        exactly where the snapshot ended (spec §6.2: snapshot and cursor come\n        from one transaction, so nothing committed between them is missed).\n        """\n        payload = self._request("GET", "/sync/bootstrap")\n        self._remember_cursor(payload, "/sync/bootstrap")\n        return payload\n'''
    new_bootstrap = '''    def bootstrap(self):\n        """Fetch the authoritative snapshot without committing transport state.\n\n        The caller must first materialize the snapshot and persist its version\n        map, then call :meth:`commit_bootstrap`. Persisting the cursor here\n        would create a crash window where a restart skips a snapshot that was\n        never written to ``crm_store.json``.\n        """\n        payload = self._request("GET", "/sync/bootstrap")\n        self._bootstrap_state(payload, "/sync/bootstrap")\n        return payload\n\n    def commit_bootstrap(self, payload):\n        """Durably mark an already-applied bootstrap snapshot as authoritative."""\n        cursor, epoch = self._bootstrap_state(payload, "/sync/bootstrap")\n        self.config.set_cursor(cursor, epoch)\n        self.config.save()\n        return cursor\n'''
    text = replace_once(text, old_bootstrap, new_bootstrap, "client bootstrap")
    text = replace_once(
        text,
        '    def pull(self, cursor=None, limit=CHANGE_PAGE_LIMIT):\n'
        '        """``GET /sync/changes?cursor=&limit=`` — one page, never the whole log.\n',
        '    def pull(self, cursor=None, limit=CHANGE_PAGE_LIMIT):\n'
        '        """``GET /sync/changes?cursor=&limit=`` — one page, never the whole log.\n',
        "client pull anchor",
    )
    pull_guard_anchor = '''        from urllib.parse import urlencode\n        if cursor is None:\n            cursor = self.config.cursor\n'''
    pull_guard_new = '''        from urllib.parse import urlencode\n        if self.config.dataset_epoch is None:\n            raise BootstrapRequiredError(route="/sync/changes")\n        if cursor is None:\n            cursor = self.config.cursor\n'''
    text = replace_once(text, pull_guard_anchor, pull_guard_new, "client pull guard")
    push_anchor = '''        if not isinstance(operations, (list, tuple)) or not operations:\n            raise BadResponseError(route="/sync/mutations")\n'''
    push_new = '''        if self.config.dataset_epoch is None:\n            raise BootstrapRequiredError(route="/sync/mutations")\n        if not isinstance(operations, (list, tuple)) or not operations:\n            raise BadResponseError(route="/sync/mutations")\n'''
    text = replace_once(text, push_anchor, push_new, "client push guard")
    old_remember = '''    def _remember_cursor(self, payload, route):\n        cursor = payload.get("cursor")\n        if isinstance(cursor, bool) or not isinstance(cursor, int) \\\n                or cursor < 0:\n            raise BadResponseError(route=route, status=200)\n        if "collections" not in payload:\n            raise BadResponseError(route=route, status=200)\n        self.config.set_cursor(cursor, payload.get("dataset_epoch"))\n        self.config.save()\n        return cursor\n'''
    new_remember = '''    def _bootstrap_state(self, payload, route):\n        """Validate bootstrap commit metadata and refuse foreign datasets."""\n        if not isinstance(payload, dict):\n            raise BadResponseError(route=route, status=200)\n        cursor = payload.get("cursor")\n        if isinstance(cursor, bool) or not isinstance(cursor, int) \\\n                or cursor < 0 or "collections" not in payload:\n            raise BadResponseError(route=route, status=200)\n        epoch = payload.get("dataset_epoch")\n        if isinstance(epoch, bool) or not isinstance(epoch, (str, int)) \\\n                or str(epoch).strip() == "":\n            raise BadResponseError(route=route, status=200)\n        epoch = str(epoch)\n        known = self.config.dataset_epoch\n        if known is not None and str(known) != epoch:\n            raise DatasetEpochMismatchError(route=route)\n        return cursor, epoch\n'''
    text = replace_once(text, old_remember, new_remember, "client bootstrap state")
    write(path, text)


def patch_panel() -> None:
    path = "panel.py"
    text = read(path)
    old_pull = '''        if getattr(config, "cursor", 0) == 0:\n            snapshot = client.bootstrap()\n            try:\n                apply.apply_snapshot(\n                    snapshot,\n                    store=store,\n                    source_installation_id=source_installation_id,\n                    versions=versions,\n                    dirty=dirty,\n                )\n            except RemoteNotReadyError:\n                return {"pulled": 0, "skipped": "remote_not_ready"}\n            _save_cloud_versions(versions, versions_path)\n            pulled_pages = 1\n'''
    new_pull = '''        if getattr(config, "dataset_epoch", None) is None:\n            snapshot = client.bootstrap()\n            try:\n                apply.apply_snapshot(\n                    snapshot,\n                    store=store,\n                    source_installation_id=source_installation_id,\n                    versions=versions,\n                    dirty=dirty,\n                )\n            except RemoteNotReadyError:\n                return {"pulled": 0, "skipped": "remote_not_ready"}\n            # Cross-file commit order is deliberate: local CRM bytes first\n            # (inside apply_snapshot), then row versions, and only then the\n            # cursor/epoch marker. A crash can cause a harmless re-bootstrap,\n            # but can never make a restart skip an unapplied snapshot.\n            _save_cloud_versions(versions, versions_path)\n            client.commit_bootstrap(snapshot)\n            pulled_pages = 1\n'''
    text = replace_once(text, old_pull, new_pull, "panel bootstrap commit order")

    old_worker = '''        worker = runtime["worker"]\n        previous = worker.bind_auth()\n        try:\n            outcome = worker.run_once()\n        finally:\n            worker.unbind_auth(previous)\n        _cloud_save_machine(runtime)\n\n        pull_result = None\n        if (getattr(runtime["config"], "sync_device_id", None)\n'''
    new_worker = '''        # A fresh/legacy client must materialize server authority before\n        # the outbox is allowed to send its first mutation. This also repairs\n        # old configs that had a cursor but pre-date dataset_epoch tracking.\n        pull_result = None\n        if (getattr(runtime["config"], "sync_device_id", None)\n                and getattr(runtime["config"], "dataset_epoch", None) is None):\n            try:\n                pull_result = cloud_pull_step(runtime)\n            except CloudSyncError as exc:\n                return _cloud_note_beat(code=exc.code)\n            if pull_result.get("skipped"):\n                return _cloud_note_beat(skipped=pull_result.get("skipped"))\n\n        worker = runtime["worker"]\n        previous = worker.bind_auth()\n        try:\n            outcome = worker.run_once()\n        finally:\n            worker.unbind_auth(previous)\n        _cloud_save_machine(runtime)\n\n        if (pull_result is None\n                and getattr(runtime["config"], "sync_device_id", None)\n'''
    text = replace_once(text, old_worker, new_worker, "panel worker bootstrap-before-push")

    # Surface the two fail-closed states without exposing server text. Locate
    # the one operator-message line for REMOTE_NOT_READY and add siblings.
    lines = text.splitlines(True)
    hits = [i for i, line in enumerate(lines) if '"REMOTE_NOT_READY"' in line]
    if len(hits) != 1:
        raise RuntimeError(f"panel cloud error mapping: expected 1 REMOTE_NOT_READY line, found {len(hits)}")
    i = hits[0]
    indent = lines[i][: len(lines[i]) - len(lines[i].lstrip())]
    lines.insert(i + 1, indent + '"BOOTSTRAP_REQUIRED": "ابتدا همگام‌سازی اولیه با سرور باید کامل شود",\n')
    lines.insert(i + 2, indent + '"DATASET_EPOCH_MISMATCH": "نسخهٔ دیتابیس سرور با کش این سیستم متفاوت است؛ همگام‌سازی برای جلوگیری از بازنویسی متوقف شد",\n')
    text = "".join(lines)
    write(path, text)


def patch_transport_tests() -> None:
    path = "lab/tests/test_cloud_transport.py"
    text = read(path)
    old = '''        self.client.bootstrap()\n        self.api.requests.clear()\n'''
    new = '''        snapshot = self.client.bootstrap()\n        self.client.commit_bootstrap(snapshot)\n        self.api.requests.clear()\n'''
    text = replace_once(text, old, new, "transport warm bootstrap commit")
    write(path, text)


def write_phase3_tests() -> None:
    path = ROOT / "lab" / "tests" / "test_server_crm_v2_authority.py"
    content = r'''# -*- coding: utf-8 -*-
"""Crash-safe authority gates for server CRM v2 phase 3."""
import inspect
import os
import sys
import tempfile
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))
for _path in (_ROOT, _HERE):
    if _path not in sys.path:
        sys.path.insert(0, _path)

import _cloud_api_fake as fake_api
import panel
from cloud_sync.auth import MemorySecretStore, TokenVault
from cloud_sync.client import SyncClient
from cloud_sync.config import CloudConfig, load_config
from cloud_sync.errors import BootstrapRequiredError, DatasetEpochMismatchError


class AuthorityTransportTests(unittest.TestCase):
    def setUp(self):
        self.handle = fake_api.start_api(self, needs_fake=True)
        self.api = self.handle.fake
        self.tmp = tempfile.TemporaryDirectory(prefix="irica_authority_")
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "cloud_config.json")
        self.config = CloudConfig(
            api_base=self.handle.base_url,
            tenant_id=self.api.tenant_id,
            source_installation_id="authority-test-installation",
            path=self.path,
        )
        self.config.save()
        self.vault = TokenVault(store=MemorySecretStore(),
                                path=os.path.join(self.tmp.name, "auth.dat"))
        self.client = SyncClient(self.config, self.vault)
        self.client.login(fake_api.FAKE_USERNAME, fake_api.FAKE_PASSWORD)
        self.client.enroll()

    def test_bootstrap_is_not_committed_before_materialization(self):
        snapshot = self.client.bootstrap()
        self.assertIsNone(self.config.dataset_epoch)
        self.assertEqual(self.config.cursor, 0)
        restored = load_config(path=self.path)
        self.assertIsNone(restored.dataset_epoch)
        self.assertEqual(restored.cursor, 0)

        self.client.commit_bootstrap(snapshot)
        restored = load_config(path=self.path)
        self.assertEqual(restored.dataset_epoch, str(snapshot["dataset_epoch"]))
        self.assertEqual(restored.cursor, snapshot["cursor"])

    def test_push_and_incremental_pull_fail_closed_before_bootstrap_commit(self):
        with self.assertRaises(BootstrapRequiredError):
            self.client.push([{
                "kind": "upsert", "entity": "settings", "id": "x",
                "base_version": 0, "record": {},
            }])
        with self.assertRaises(BootstrapRequiredError):
            self.client.pull(0)
        self.assertEqual(self.api.calls("/sync/mutations"), [])
        self.assertEqual(self.api.calls("/sync/changes"), [])

    def test_foreign_dataset_epoch_is_quarantined(self):
        snapshot = self.client.bootstrap()
        self.client.commit_bootstrap(snapshot)
        before = load_config(path=self.path).to_dict()
        self.api.dataset_epoch = str(snapshot["dataset_epoch"]) + "-foreign"
        with self.assertRaises(DatasetEpochMismatchError):
            self.client.bootstrap()
        after = load_config(path=self.path).to_dict()
        self.assertEqual(after, before)


class AuthorityPanelContractTests(unittest.TestCase):
    def test_panel_commits_cursor_only_after_store_and_versions(self):
        source = inspect.getsource(panel.cloud_pull_step)
        self.assertLess(source.index("apply.apply_snapshot("),
                        source.index("_save_cloud_versions(versions, versions_path)"))
        self.assertLess(source.index("_save_cloud_versions(versions, versions_path)"),
                        source.index("client.commit_bootstrap(snapshot)"))
        self.assertIn('getattr(config, "dataset_epoch", None) is None', source)

    def test_worker_bootstraps_before_outbox_run(self):
        source = inspect.getsource(panel.cloud_worker_beat)
        self.assertLess(source.index("cloud_pull_step(runtime)"),
                        source.index("worker.run_once()"))
        self.assertIn('getattr(runtime["config"], "dataset_epoch", None) is None', source)


if __name__ == "__main__":
    unittest.main()
'''
    path.write_text(content, encoding="utf-8")


def main() -> None:
    patch_state()
    patch_errors()
    patch_client()
    patch_panel()
    patch_transport_tests()
    write_phase3_tests()
    print("phase3 authority patch applied")


if __name__ == "__main__":
    main()
