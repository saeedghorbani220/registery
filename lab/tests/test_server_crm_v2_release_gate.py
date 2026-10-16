# -*- coding: utf-8 -*-
"""Static release-candidate invariants for the Server CRM v1.15 phase plan."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


def text(path):
    return (ROOT / path).read_text(encoding="utf-8")


class ReleaseGateTests(unittest.TestCase):
    def test_release_identity_and_forward_migrations(self):
        self.assertEqual(text("VERSION").strip(), "1.15.0")
        self.assertTrue((ROOT / "RELEASE_NOTES_v1.15.0.md").is_file())
        expected = [
            "001_initial.sql",
            "002_server_crm_v2_foundation.sql",
            "003_server_crm_v2_device_auth.sql",
            "004_legacy_import_verification.sql",
        ]
        actual = sorted(p.name for p in (ROOT / "host" / "migrations").glob("*.sql"))
        for name in expected:
            self.assertIn(name, actual)

    def test_no_direct_desktop_database_credentials_or_driver_contract(self):
        client = text("cloud_sync/client.py").lower()
        requirements = text("requirements.txt").lower()
        for forbidden in ("pymysql", "mysql.connector", "mysqldb"):
            self.assertNotIn(forbidden, client)
            self.assertNotIn(forbidden, requirements)
        self.assertIn("https", text("lab/docs/CLOUD_SYNC_SPEC.md").lower())

    def test_phase4_presence_is_advisory_and_routed(self):
        presence = text("host/src/Presence.php")
        index = text("host/public/index.php")
        panel = text("panel.py")
        self.assertIn("Presence is deliberately NOT a lock", presence)
        self.assertNotIn("FOR UPDATE", presence)
        self.assertNotIn("GET_LOCK", presence)
        self.assertIn("/presence/heartbeat", index)
        self.assertIn("/presence/close", index)
        self.assertIn("case-presence", panel)
        self.assertIn("ویرایش قفل نمی‌شود", panel)

    def test_legacy_import_is_fail_closed_by_default(self):
        config = text("host/config/config.example.php")
        self.assertRegex(config, r"['\"]legacy_import_enabled['\"]\s*=>\s*false")
        self.assertIn("freshBoolean", text("host/src/Config.php"))
        self.assertTrue((ROOT / "lab" / "tests" / "test_v115_audit_config_switch.py").is_file())

    def test_permanent_ci_contains_every_phase6_stress_axis(self):
        ci = text(".github/workflows/server-crm-v2.yml")
        required_suites = (
            "test_cloud_transport",
            "test_cloud_conflicts",
            "test_cloud_integration",
            "test_server_crm_v2_database_resilience",
            "test_server_crm_v2_backup_restore",
            "test_server_crm_v2_finance",
            "test_server_crm_v2_presence",
            "test_server_crm_v2_presence_client",
            "test_server_crm_v2_release_gate",
        )
        for suite in required_suites:
            self.assertIn(suite, ci, suite)
        self.assertIn("mariadb:11.4", ci)
        self.assertIn("mysql:5.7", ci)
        self.assertIn("windows-latest", ci)

    def test_release_gate_document_keeps_deploy_truthful(self):
        gate = text("lab/docs/SERVER_CRM_V2_RELEASE_GATE.md")
        for phase in ("Phase 0", "Phase 1", "Phase 2", "Phase 3",
                      "Phase 4", "Phase 5", "Phase 6+"):
            self.assertIn(phase, gate)
        self.assertIn("ready for staged rollout", gate)
        self.assertIn("not “already deployed”", gate)
        self.assertIn("verify_windows_release.py", gate)


if __name__ == "__main__":
    unittest.main()
