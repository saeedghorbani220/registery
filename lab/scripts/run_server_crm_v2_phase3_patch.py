#!/usr/bin/env python3
"""Run the one-shot phase 3 patcher with transport fixtures scoped safely."""
from __future__ import annotations

import importlib.util
import pathlib

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]
PATCHER = HERE / "apply_server_crm_v2_phase3.py"
spec = importlib.util.spec_from_file_location("phase3_patcher", PATCHER)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)

_original = module.replace_once


def _scoped_replace(text: str, old: str, new: str, label: str) -> str:
    if label != "transport warm bootstrap commit":
        return _original(text, old, new, label)
    start = text.index("    def warm(self):")
    end = text.index("    def new_machine(self):", start)
    before, block, after = text[:start], text[start:end], text[end:]
    count = block.count(old)
    if count != 1:
        raise RuntimeError(
            f"{label}: expected exactly one match inside warm(), found {count}"
        )
    return before + block.replace(old, new, 1) + after


module.replace_once = _scoped_replace
module.main()

# Existing transport tests historically treated enrollment as sufficient to
# push/pull. Under phase 3 the shared fixture must complete an empty bootstrap
# first; dedicated authority tests still exercise the pre-bootstrap refusal.
test_path = ROOT / "lab" / "tests" / "test_cloud_transport.py"
text = test_path.read_text(encoding="utf-8")
old_enrol = '''    def enrol(self):\n        """Log in as the fake admin and enrol this machine (spec §5)."""\n        self.client.login(fake_api.FAKE_USERNAME, fake_api.FAKE_PASSWORD)\n        self.client.enroll()\n        self.user_token = self.vault.user_access_token\n        return self.config.sync_device_id\n'''
new_enrol = '''    def enrol(self):\n        """Log in, enrol, then commit the initial authoritative snapshot."""\n        self.client.login(fake_api.FAKE_USERNAME, fake_api.FAKE_PASSWORD)\n        self.client.enroll()\n        snapshot = self.client.bootstrap()\n        self.client.commit_bootstrap(snapshot)\n        self.user_token = self.vault.user_access_token\n        return self.config.sync_device_id\n'''
if text.count(old_enrol) != 1:
    raise RuntimeError("transport enrol fixture changed unexpectedly")
text = text.replace(old_enrol, new_enrol, 1)

old_assert = '''        self.assertEqual(payload["dataset_epoch"], self.api.dataset_epoch)\n        self.assertEqual(self.config.cursor, self.api.seq)\n'''
new_assert = '''        self.assertEqual(payload["dataset_epoch"], self.api.dataset_epoch)\n        # Fetching a snapshot alone must not advance durable state. The fixture\n        # already committed an empty bootstrap, so its cursor remains zero\n        # until this newer snapshot is explicitly materialized/committed.\n        self.assertEqual(self.config.cursor, 0)\n        self.client.commit_bootstrap(payload)\n        self.assertEqual(self.config.cursor, self.api.seq)\n'''
if text.count(old_assert) != 1:
    raise RuntimeError("bootstrap cursor assertion changed unexpectedly")
text = text.replace(old_assert, new_assert, 1)
test_path.write_text(text, encoding="utf-8")
