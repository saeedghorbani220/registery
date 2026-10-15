#!/usr/bin/env python3
"""Move the Phase 6 device-id test after the complete observable-count test."""
from pathlib import Path

path = Path(__file__).with_name("patch_phase6_cloud_device_ux_v3.py")
text = path.read_text(encoding="utf-8")
old = r'''    replace_exact(TESTS,
'''        self.assertEqual(payload["pending"], 3)
        self.assertEqual(payload["conflicts"], 2)
''',
'''        self.assertEqual(payload["pending"], 3)
        self.assertEqual(payload["conflicts"], 2)

    def test_device_identity_is_visible_but_not_a_credential(self):
        device_id = "12345678-1234-4234-8234-123456789abc"
        payload = panel.cloud_status_payload(
            _fake_runtime(config=_fake_config(api_base="https://api.x.test",
                                              sync_device_id=device_id)))
        self.assertTrue(payload["device_enrolled"])
        self.assertEqual(payload["device_id"], device_id)
        keys = " ".join(payload.keys()).lower()
        self.assertNotIn("refresh", keys)
        self.assertNotIn("token", keys)
''', "status device test")
'''
new = r'''    replace_exact(TESTS,
'''        self.assertEqual(payload["pending"], 3)
        self.assertEqual(payload["conflicts"], 2)
        self.assertEqual(payload["error_code"], "NET_TIMEOUT")
        self.assertEqual(payload["error_message"],
                         panel.cloud_error_message("NET_TIMEOUT"))
''',
'''        self.assertEqual(payload["pending"], 3)
        self.assertEqual(payload["conflicts"], 2)
        self.assertEqual(payload["error_code"], "NET_TIMEOUT")
        self.assertEqual(payload["error_message"],
                         panel.cloud_error_message("NET_TIMEOUT"))

    def test_device_identity_is_visible_but_not_a_credential(self):
        device_id = "12345678-1234-4234-8234-123456789abc"
        payload = panel.cloud_status_payload(
            _fake_runtime(config=_fake_config(api_base="https://api.x.test",
                                              sync_device_id=device_id)))
        self.assertTrue(payload["device_enrolled"])
        self.assertEqual(payload["device_id"], device_id)
        keys = " ".join(payload.keys()).lower()
        self.assertNotIn("refresh", keys)
        self.assertNotIn("token", keys)
''', "status device test")
'''
if text.count(old) != 1:
    raise RuntimeError(f"expected one Phase 6 test insertion block, found {text.count(old)}")
path.write_text(text.replace(old, new, 1), encoding="utf-8", newline="\n")
print("phase6 device-id test insertion moved after complete observable assertions")
