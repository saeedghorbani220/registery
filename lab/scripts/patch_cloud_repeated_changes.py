#!/usr/bin/env python3
"""One-shot patch: collapse repeated change-log rows to their latest state."""
from __future__ import annotations

import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[2]
APPLY = ROOT / "cloud_sync" / "apply.py"
TESTS = ROOT / "lab" / "tests" / "test_cloud_apply.py"


def replace_once(path: pathlib.Path, old: str, new: str, label: str) -> None:
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one match, found {count}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def main() -> None:
    old = '''    out = []
    seen = set()
    for change in changes:
        if not isinstance(change, dict):
            raise _bad(route)
        for field in _CHANGE_FIELDS:
            if field not in change:
                raise _bad(route)
        entity = change["entity"]
        cloud_id = change["id"]
        seq = change["seq"]
        row_version = change["row_version"]
        record = change["record"]
        if not isinstance(entity, str) or entity not in _ENTITY_SET:
            raise _bad(route)                  # unknown entity
        if not isinstance(cloud_id, str) or not cloud_id:
            raise _bad(route)
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
            raise _bad(route)
        if isinstance(row_version, bool) or not isinstance(row_version, int) \\
                or row_version < 1:
            raise _bad(route)
        if record is not None and not isinstance(record, dict):
            raise _bad(route)
        key = (entity, cloud_id)
        if key in seen:
            raise _bad(route)                  # duplicate id in one batch
        seen.add(key)
        out.append((entity, cloud_id, row_version, record))
    return out
'''
    new = '''    out = []
    seen = {}
    for change in changes:
        if not isinstance(change, dict):
            raise _bad(route)
        for field in _CHANGE_FIELDS:
            if field not in change:
                raise _bad(route)
        entity = change["entity"]
        cloud_id = change["id"]
        seq = change["seq"]
        row_version = change["row_version"]
        record = change["record"]
        if not isinstance(entity, str) or entity not in _ENTITY_SET:
            raise _bad(route)                  # unknown entity
        if not isinstance(cloud_id, str) or not cloud_id:
            raise _bad(route)
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
            raise _bad(route)
        if isinstance(row_version, bool) or not isinstance(row_version, int) \\
                or row_version < 1:
            raise _bad(route)
        if record is not None and not isinstance(record, dict):
            raise _bad(route)
        key = (entity, cloud_id)
        out_index = seen.get(key)
        if out_index is not None:
            # One row may legitimately have several change_log entries after
            # the caller's cursor. The real host returns the current live
            # snapshot for each entry while the executable fake preserves the
            # historical snapshots. In either representation the final entry
            # is the state the client must apply. Keep the first occurrence's
            # position so parent-before-child dependency order is preserved,
            # but replace its payload/version with the latest occurrence.
            out[out_index] = (entity, cloud_id, row_version, record)
            continue
        seen[key] = len(out)
        out.append((entity, cloud_id, row_version, record))
    return out
'''
    replace_once(APPLY, old, new, "incremental repeated-row handling")

    old = '''* **Fail closed**: an unknown entity, a malformed envelope, duplicate ids in
  one batch, a record that does not decode or a reference this machine cannot
  resolve raises *before* a single byte is written — half a store is worse
  than none. :class:`mapper.UnresolvedReferenceError` is never caught, so
'''
    new = '''* **Fail closed**: an unknown entity, a malformed envelope, a record that
  does not decode or a reference this machine cannot resolve raises *before*
  a single byte is written — half a store is worse than none. Repeated row ids
  in an incremental page are collapsed to their latest occurrence while
  retaining the first occurrence's position, because one row may legitimately
  have several ordered log entries after the cursor.
  :class:`mapper.UnresolvedReferenceError` is never caught, so
'''
    replace_once(APPLY, old, new, "apply contract documentation")

    old = '''    def test_duplicate_ids_in_one_page_are_rejected(self):
        row = {"entity": "owners", "id": "same-id", "seq": 1,
               "row_version": 1, "record": {}}
        self.assertRejected(page(row, dict(row, seq=2)), "duplicate")

'''
    new = '''    def test_repeated_row_keeps_first_position_but_latest_snapshot(self):
        first = {"entity": "owners", "id": "same-id", "seq": 1,
                 "row_version": 2, "record": {"id": "owner01", "name": "old"}}
        middle = {"entity": "customers", "id": "other-id", "seq": 2,
                  "row_version": 1, "record": {"id": "cust01"}}
        repeated = dict(first, seq=3, row_version=3,
                        record={"id": "owner01", "name": "latest"})
        parsed = apply._page_changes(
            page(first, middle, repeated), apply.CHANGES_ROUTE)
        self.assertEqual(parsed, [
            ("owners", "same-id", 3, {"id": "owner01", "name": "latest"}),
            ("customers", "other-id", 1, {"id": "cust01"}),
        ])

    def test_repeated_current_snapshot_with_same_version_is_collapsed(self):
        row = {"entity": "owners", "id": "same-id", "seq": 1,
               "row_version": 3, "record": {"id": "owner01"}}
        parsed = apply._page_changes(
            page(row, dict(row, seq=2)), apply.CHANGES_ROUTE)
        self.assertEqual(parsed, [
            ("owners", "same-id", 3, {"id": "owner01"}),
        ])

'''
    replace_once(TESTS, old, new, "repeated-row tests")
    print("repeated change-log row patch applied")


if __name__ == "__main__":
    main()
