#!/usr/bin/env python3
"""One-shot guarded patch for the host API fixture's CI account host."""
from __future__ import annotations

import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[2]
PATH = ROOT / "lab" / "tests" / "test_host_api.py"


def replace_once(old: str, new: str, label: str) -> None:
    text = PATH.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one match, found {count}")
    PATH.write_text(text.replace(old, new, 1), encoding="utf-8")


def main() -> None:
    old = '''    # A clean slate every run: the module owns both objects.\n    _run_sql("DROP DATABASE IF EXISTS `%s`;" % API_DB, expect_ok=False)\n    _run_sql("DROP USER IF EXISTS '%s'@'127.0.0.1';" % API_USER,\n             expect_ok=False)\n    _run_sql("CREATE DATABASE `%s` DEFAULT CHARACTER SET utf8mb4"\n             " COLLATE utf8mb4_unicode_ci;" % API_DB)\n    _run_sql("CREATE USER '%s'@'127.0.0.1' IDENTIFIED BY '%s';"\n             % (API_USER, app_password))\n    # Exactly the production grant set of spec §2: DML only, no CREATE.\n    _run_sql("GRANT SELECT, INSERT, UPDATE, DELETE ON `%s`.* TO"\n             " '%s'@'127.0.0.1';" % (API_DB, API_USER))\n'''
    new = '''    # A clean slate every run: the module owns both objects. The default\n    # account host is production-like localhost. Container CI may opt into '%'\n    # because a service container sees the runner through its bridge address.\n    account_host = os.environ.get("IRICA_TEST_DB_ACCOUNT_HOST", "127.0.0.1")\n    if account_host not in ("127.0.0.1", "%"):\n        raise AssertionError("IRICA_TEST_DB_ACCOUNT_HOST has an unsupported value")\n    _run_sql("DROP DATABASE IF EXISTS `%s`;" % API_DB, expect_ok=False)\n    _run_sql("DROP USER IF EXISTS '%s'@'%s';" % (API_USER, account_host),\n             expect_ok=False)\n    _run_sql("CREATE DATABASE `%s` DEFAULT CHARACTER SET utf8mb4"\n             " COLLATE utf8mb4_unicode_ci;" % API_DB)\n    _run_sql("CREATE USER '%s'@'%s' IDENTIFIED BY '%s';"\n             % (API_USER, account_host, app_password))\n    # Exactly the production grant set of spec §2: DML only, no CREATE.\n    _run_sql("GRANT SELECT, INSERT, UPDATE, DELETE ON `%s`.* TO"\n             " '%s'@'%s';" % (API_DB, API_USER, account_host))\n'''
    replace_once(old, new, "app-account host")

    old = '''    _state["drop_sql"] = (\n        "DROP DATABASE IF EXISTS `%s`;"\n        " DROP USER IF EXISTS '%s'@'127.0.0.1';" % (API_DB, API_USER))\n'''
    new = '''    _state["drop_sql"] = (\n        "DROP DATABASE IF EXISTS `%s`;"\n        " DROP USER IF EXISTS '%s'@'%s';"\n        % (API_DB, API_USER, account_host))\n'''
    replace_once(old, new, "fixture cleanup host")
    print("host API container-account patch applied")


if __name__ == "__main__":
    main()
