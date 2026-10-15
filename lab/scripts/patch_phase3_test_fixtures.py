#!/usr/bin/env python3
"""Migrate pre-authority cloud tests to the Phase 3 bootstrap contract.

This is a one-shot repository patch helper. It changes tests only; production
bootstrap guards stay untouched. The helper is removed after the patch lands.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def replace_once(text, old, new, label):
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, found {count}")
    return text.replace(old, new, 1)


def patch_conflicts():
    path = ROOT / "lab" / "tests" / "test_cloud_conflicts.py"
    text = path.read_text(encoding="utf-8")

    old = '''    def test_pull_step_incremental_when_cursor_positive(self):
        config = _fake_config(api_base="https://api.test", sync_device_id="dev-1",
                              cursor=10, source_installation_id="inst-1")
'''
    new = '''    def test_pull_step_incremental_when_cursor_positive(self):
        # A positive cursor only represents an initialized client when the
        # authoritative dataset epoch has already been committed as well.
        config = _fake_config(api_base="https://api.test", sync_device_id="dev-1",
                              cursor=10, dataset_epoch=1,
                              source_installation_id="inst-1")
'''
    text = replace_once(text, old, new, "incremental fixture")

    old = '''    def test_worker_beat_catches_illegal_transition_by_name(self):
        config = _fake_config(api_base="https://api.test", sync_device_id="dev-1")
'''
    new = '''    def test_worker_beat_catches_illegal_transition_by_name(self):
        # This test targets the state-machine error path, not first bootstrap.
        # Mark the fake runtime as already bound to an authoritative dataset.
        config = _fake_config(api_base="https://api.test", sync_device_id="dev-1",
                              dataset_epoch=1)
'''
    text = replace_once(text, old, new, "illegal-transition fixture")
    path.write_text(text, encoding="utf-8")


def patch_integration():
    path = ROOT / "lab" / "tests" / "test_cloud_integration.py"
    text = path.read_text(encoding="utf-8")

    marker = '''        return {
            "install": install,
            "config": cfg,
            "vault": vault,
            "client": client,
            "store": store,
            "outbox": outbox,
            "versions": {},
        }

    def test_client_login_and_enroll(self):
'''
    replacement = '''        return {
            "install": install,
            "config": cfg,
            "vault": vault,
            "client": client,
            "store": store,
            "outbox": outbox,
            "versions": {},
        }

    def _bootstrap_authority(self, client_state):
        """Materialize then commit the host snapshot before incremental IO."""
        snapshot = client_state["client"].bootstrap()
        apply.apply_snapshot(
            snapshot,
            store=client_state["store"],
            versions=client_state["versions"],
            source_installation_id=client_state["install"],
        )
        client_state["client"].commit_bootstrap(snapshot)
        return snapshot

    def test_client_login_and_enroll(self):
'''
    text = replace_once(text, marker, replacement, "integration helper insertion")

    pair = '''        cA["client"].login(fake_api.FAKE_USERNAME, fake_api.FAKE_PASSWORD)
        cA["client"].enroll()
        cB["client"].login(fake_api.FAKE_USERNAME, fake_api.FAKE_PASSWORD)
        cB["client"].enroll()
'''
    pair_bootstrapped = pair + '''        self._bootstrap_authority(cA)
        self._bootstrap_authority(cB)
'''
    count = text.count(pair)
    if count != 3:
        raise SystemExit(
            f"multi-client authority fixtures: expected 3 matches, found {count}"
        )
    text = text.replace(pair, pair_bootstrapped)
    path.write_text(text, encoding="utf-8")


def main():
    patch_conflicts()
    patch_integration()


if __name__ == "__main__":
    main()
