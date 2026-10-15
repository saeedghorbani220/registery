#!/usr/bin/env python3
"""Normalize accidental source-line continuations in the one-shot Phase 6 patcher."""
from pathlib import Path

path = Path(__file__).with_name("patch_phase6_cloud_device_ux.py")
text = path.read_text(encoding="utf-8")
count = text.count("\\\n")
if count:
    path.write_text(text.replace("\\\n", "\n"), encoding="utf-8", newline="\n")
print(f"phase6 patcher newline anchors normalized: {count}")
