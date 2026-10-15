#!/usr/bin/env python3
"""Run the one-shot phase 3 patcher with the warm() test edit scoped safely."""
from __future__ import annotations

import importlib.util
import pathlib

HERE = pathlib.Path(__file__).resolve().parent
PATCHER = HERE / "apply_server_crm_v2_phase3.py"
spec = importlib.util.spec_from_file_location("phase3_patcher", PATCHER)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)

_original = module.replace_once


def _scoped_replace(text: str, old: str, new: str, label: str) -> str:
    if label != "transport warm bootstrap commit":
        return _original(text, old, new, label)
    start = text.index("    def warm(self):")
    end = text.index("    def new_machine(self):", start)
    before, block, after = text[:start], text[start:end], text[end:]
    count = block.count(old)
    if count != 1:
        raise RuntimeError(
            f"{label}: expected exactly one match inside warm(), found {count}"
        )
    return before + block.replace(old, new, 1) + after


module.replace_once = _scoped_replace
module.main()
