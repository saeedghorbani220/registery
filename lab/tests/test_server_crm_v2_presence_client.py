# -*- coding: utf-8 -*-
"""Clean-checkout contracts for Phase-4 advisory presence wiring."""
import os
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def read(path):
    with open(os.path.join(ROOT, path), "r", encoding="utf-8") as handle:
        return handle.read()


class PresenceClientContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = read("cloud_sync/client.py")
        cls.panel = read("panel.py")

    def test_transport_uses_acting_user_for_heartbeat_and_close(self):
        self.assertIn("def presence_heartbeat", self.client)
        self.assertIn('"/presence/heartbeat"', self.client)
        self.assertIn("def presence_close", self.client)
        self.assertIn('"/presence/close"', self.client)
        self.assertGreaterEqual(self.client.count("acting=True"), 3)

    def test_case_modal_shows_presence_as_advisory_only(self):
        self.assertIn('id="case-presence"', self.panel)
        self.assertIn("presenceStart('crm_devices',id)", self.panel)
        self.assertIn("این فقط هشدار حضور است", self.panel)
        self.assertIn("ویرایش قفل نمی‌شود", self.panel)
        self.assertIn("/cloud-presence", self.panel)
        self.assertIn("/cloud-presence-close", self.panel)
        # Presence never enters stageReady/stageContinue as an edit gate.
        start = self.panel.index("function stageReady")
        end = self.panel.index("function stageActions", start)
        self.assertNotIn("presence", self.panel[start:end].lower())


if __name__ == "__main__":
    unittest.main()
