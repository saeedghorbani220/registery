#!/usr/bin/env python3
"""Keep the complete error-code/error-message assertion pair before the Phase 6 test insertion."""
from pathlib import Path

path = Path(__file__).with_name("patch_phase6_cloud_device_ux_v3.py")
text = path.read_text(encoding="utf-8")
needle = """'''        self.assertEqual(payload[\"pending\"], 3)\n        self.assertEqual(payload[\"conflicts\"], 2)\n        self.assertEqual(payload[\"error_code\"], \"NET_TIMEOUT\")\n"""
replacement = needle + """        self.assertEqual(payload[\"error_message\"],\n                         panel.cloud_error_message(\"NET_TIMEOUT\"))\n"""
count = text.count(needle)
if count != 2:
    raise RuntimeError(f"expected old/new status anchors exactly twice, found {count}")
path.write_text(text.replace(needle, replacement), encoding="utf-8", newline="\n")
print("phase6 status test anchor now includes the complete error assertion pair")
