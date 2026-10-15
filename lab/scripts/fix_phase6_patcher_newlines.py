#!/usr/bin/env python3
"""Normalize accidental source-line continuations in the one-shot Phase 6 patcher."""
from pathlib import Path

path = Path(__file__).with_name("patch_phase6_cloud_device_ux.py")
text = path.read_text(encoding="utf-8")
count = text.count("\\\n")
if count != 6:
    raise RuntimeError(f"expected 6 accidental continuations, found {count}")
path.write_text(text.replace("\\\n", "\n"), encoding="utf-8", newline="\n")
print("phase6 patcher newline anchors normalized")
