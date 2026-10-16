# -*- coding: utf-8 -*-
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
