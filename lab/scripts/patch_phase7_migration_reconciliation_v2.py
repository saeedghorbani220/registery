#!/usr/bin/env python3
"""Run the Phase 7 patch with the analyze-preview contract asserted correctly."""
from __future__ import annotations

import patch_phase7_migration_reconciliation as base

base.TEST_METHOD = base.TEST_METHOD.replace(
    '        self.assertEqual(staged["unresolved"], 0)\n',
    '        unresolved = [r for r in staged["records"] '
    'if r.get("action") in ("pending", "conflict", "invalid")]\n'
    '        self.assertEqual(unresolved, [])\n',
)

if __name__ == "__main__":
    base.main()
