#!/usr/bin/env python3
"""Normalize Phase 6 one-shot patch counts to panel.py's shared paint function."""
from pathlib import Path

path = Path(__file__).with_name("patch_phase6_cloud_device_ux_v2.py")
text = path.read_text(encoding="utf-8")
for label in ("paint device identity", "paint reconnect guidance"):
    old = f'"{label}", expected=2)'
    new = f'"{label}", expected=1)'
    if text.count(old) != 1:
        raise RuntimeError(f"missing count anchor: {label}")
    text = text.replace(old, new, 1)
path.write_text(text, encoding="utf-8", newline="\n")
print("phase6 shared paint-function counts normalized")
