#!/usr/bin/env python3
"""Align the one-shot Phase 6 shell-id test anchor with the shipped harness."""
from pathlib import Path

path = Path(__file__).with_name("patch_phase6_cloud_device_ux_v2.py")
text = path.read_text(encoding="utf-8")
old = '''''' 'cloud-actor','cloud-last-sync','cloud-pending','cloud-conflicts',
 'cloud-error-code','cloud-error-line','cloud-beat-line','cloud-action-status',
''',
''' 'cloud-actor','cloud-device','cloud-last-sync','cloud-pending','cloud-conflicts',
 'cloud-error-code','cloud-error-line','cloud-reconnect','cloud-reconnect-text','cloud-beat-line','cloud-action-status',
''''''
new = '''''' 'cloud-actor','cloud-last-sync','cloud-pending','cloud-conflicts',
 'cloud-error-code','cloud-error-line','cloud-error-text','cloud-beat-line','cloud-action-status',
''',
''' 'cloud-actor','cloud-device','cloud-last-sync','cloud-pending','cloud-conflicts',
 'cloud-error-code','cloud-error-line','cloud-error-text','cloud-reconnect','cloud-reconnect-text','cloud-beat-line','cloud-action-status',
''''''
if text.count(old) != 1:
    raise RuntimeError(f"expected one shell-id anchor, found {text.count(old)}")
path.write_text(text.replace(old, new, 1), encoding="utf-8", newline="\n")
print("phase6 shell-id test anchor aligned")
