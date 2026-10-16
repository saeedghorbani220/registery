#!/usr/bin/env python3
"""Refresh two historical assertions that intentionally changed in v1.15."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def replace_once(path: Path, old: str, new: str, label: str) -> None:
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected exactly one match, found {count}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8", newline="\n")


def patch_cloud_mapper_contract() -> None:
    path = ROOT / "lab" / "tests" / "test_cloud_mapper.py"
    old = '''        with warnings.catch_warnings():\n            warnings.simplefilter("error", mapper.SettingsAllowlistWarning)\n            rows = mapper.split_store(data,\n                                      source_installation_id=self.INSTALL)\n        merged = mapper.merge_store(rows,\n                                    source_installation_id=self.INSTALL)\n        for key in ("customers", "owners", "identities", "devices", "periods"):\n            self.assertEqual(merged[key], data[key], key)\n        syncable, _local = mapper.split_settings(data["settings"])\n        self.assertEqual(merged["settings"], syncable)\n'''
    new = '''        # v1.15 adds database_mode as an explicitly device-local setting.\n        # split_store must keep it off the wire and surface the allowlist warning\n        # rather than treating that intentional local key as a mapper failure.\n        with warnings.catch_warnings(record=True) as caught:\n            warnings.simplefilter("always", mapper.SettingsAllowlistWarning)\n            rows = mapper.split_store(data,\n                                      source_installation_id=self.INSTALL)\n        self.assertTrue(any("database_mode" in str(item.message)\n                            for item in caught))\n        merged = mapper.merge_store(rows,\n                                    source_installation_id=self.INSTALL)\n        for key in ("customers", "owners", "identities", "devices", "periods"):\n            self.assertEqual(merged[key], data[key], key)\n        with warnings.catch_warnings():\n            warnings.simplefilter("ignore", mapper.SettingsAllowlistWarning)\n            syncable, local = mapper.split_settings(data["settings"])\n        self.assertEqual(merged["settings"], syncable)\n        self.assertEqual(local.get("database_mode"),\n                         data["settings"].get("database_mode"))\n'''
    replace_once(path, old, new, "cloud mapper local database_mode contract")


def patch_close_dialog_contract() -> None:
    path = ROOT / "lab" / "tests" / "test_v1_1_5_tabs_closed.py"
    old = '''        self.assertIn("confirmDlg('مختومه کردن پرونده'", self.page)\n'''
    new = '''        # The irreversible close flow now owns a dedicated reason modal; the\n        # legacy generic confirmDlg assertion became stale once that UX shipped.\n        self.assertIn("function closeCaseDialog(id){", self.page)\n        self.assertIn("openDlg('<h3>مختومه کردن پرونده</h3>'", self.page)\n'''
    replace_once(path, old, new, "dedicated close-case modal contract")


def main() -> None:
    patch_cloud_mapper_contract()
    patch_close_dialog_contract()
    print("v1.15 historical regression contracts refreshed")


if __name__ == "__main__":
    main()
