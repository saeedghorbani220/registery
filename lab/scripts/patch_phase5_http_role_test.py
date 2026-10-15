#!/usr/bin/env python3
"""One-shot test-contract patch for the existing role error code."""
from __future__ import annotations

import pathlib

path = pathlib.Path(__file__).resolve().parents[2] / "lab" / "tests" / "test_host_api.py"
text = path.read_text(encoding="utf-8")
old = '''            member = _login(_state["user_user"], _state["user_password"])
            status, error, _h, _p = _fail(
                "POST", "/legacy-import/analyze", body,
                token=member["access_token"])
            self.assertEqual((status, error["code"]),
                             (403, "PERMISSION_DENIED"))
'''
new = '''            member = _login(_state["user_user"], _state["user_password"])
            status, error, _h, _p = _fail(
                "POST", "/legacy-import/analyze", body,
                token=member["access_token"])
            # Roles::requireImport uses the host's established role-matrix code.
            self.assertEqual((status, error["code"]),
                             (403, "ROLE_FORBIDDEN"))
'''
if text.count(old) != 1:
    raise RuntimeError("expected exactly one legacy member-role assertion")
path.write_text(text.replace(old, new, 1), encoding="utf-8")
print("legacy HTTP role assertion aligned")
