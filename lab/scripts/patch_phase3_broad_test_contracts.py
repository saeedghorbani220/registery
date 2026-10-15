#!/usr/bin/env python3
"""One-shot guarded patch for tests that predate durable bootstrap authority."""
from __future__ import annotations

import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[2]


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one match, found {count}")
    return text.replace(old, new, 1)


def patch_conflicts() -> None:
    path = ROOT / "lab" / "tests" / "test_cloud_conflicts.py"
    text = path.read_text(encoding="utf-8")

    old = '''    def test_pull_step_incremental_when_cursor_positive(self):\n        config = _fake_config(api_base="https://api.test", sync_device_id="dev-1",\n                              cursor=10, source_installation_id="inst-1")\n'''
    new = '''    def test_pull_step_incremental_when_cursor_positive(self):\n        config = _fake_config(api_base="https://api.test", sync_device_id="dev-1",\n                              cursor=10, dataset_epoch=1,\n                              source_installation_id="inst-1")\n'''
    text = replace_once(text, old, new, "incremental fixture")

    old = '''    def test_worker_beat_catches_illegal_transition_by_name(self):\n        config = _fake_config(api_base="https://api.test", sync_device_id="dev-1")\n'''
    new = '''    def test_worker_beat_catches_illegal_transition_by_name(self):\n        config = _fake_config(api_base="https://api.test", sync_device_id="dev-1",\n                              dataset_epoch=1)\n'''
    text = replace_once(text, old, new, "worker fixture")

    old = '''        self.assertEqual(res["pulled"], 1)\n        client.bootstrap.assert_called_once()\n        mock_snapshot.assert_called_once()\n'''
    new = '''        self.assertEqual(res["pulled"], 1)\n        client.bootstrap.assert_called_once()\n        mock_snapshot.assert_called_once()\n        client.commit_bootstrap.assert_called_once_with(\n            client.bootstrap.return_value)\n'''
    text = replace_once(text, old, new, "bootstrap commit assertion")
    path.write_text(text, encoding="utf-8")


def patch_integration() -> None:
    path = ROOT / "lab" / "tests" / "test_cloud_integration.py"
    text = path.read_text(encoding="utf-8")

    anchor = '''        return {\n            "install": install,\n            "config": cfg,\n            "vault": vault,\n            "client": client,\n            "store": store,\n            "outbox": outbox,\n            "versions": {},\n        }\n\n'''
    helper = anchor + '''    def _seed_and_bootstrap(self, primary, *others):\n        """Seed the empty host, then durably materialize authority on clients."""\n        body = importer.build_document(\n            primary["store"].read(),\n            source_installation_id=primary["install"],\n        )\n        imported = primary["client"].import_document(body)\n        self.assertTrue(imported.get("ok", True))\n        for current in (primary,) + tuple(others):\n            snapshot = current["client"].bootstrap()\n            apply.apply_snapshot(\n                snapshot,\n                store=current["store"],\n                versions=current["versions"],\n                source_installation_id=current["install"],\n            )\n            current["client"].commit_bootstrap(snapshot)\n\n'''
    text = replace_once(text, anchor, helper, "integration bootstrap helper")

    setup = '''        cA["client"].login(fake_api.FAKE_USERNAME, fake_api.FAKE_PASSWORD)\n        cA["client"].enroll()\n        cB["client"].login(fake_api.FAKE_USERNAME, fake_api.FAKE_PASSWORD)\n        cB["client"].enroll()\n'''
    replacement = setup + '''        self._seed_and_bootstrap(cA, cB)\n'''
    count = text.count(setup)
    if count != 3:
        raise RuntimeError(
            f"multi-client setup: expected three matches, found {count}"
        )
    text = text.replace(setup, replacement)
    path.write_text(text, encoding="utf-8")


def main() -> None:
    patch_conflicts()
    patch_integration()
    print("phase 3 broad test contracts patched")


if __name__ == "__main__":
    main()
