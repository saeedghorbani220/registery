#!/usr/bin/env python3
"""One-shot guarded fixes for the migration HTTP gate and its CI fixture."""
from __future__ import annotations

import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[2]
TESTS = ROOT / "lab" / "tests" / "test_host_api.py"
CONFIG = ROOT / "host" / "src" / "Config.php"
INDEX = ROOT / "host" / "public" / "index.php"


def replace_once(path: pathlib.Path, old: str, new: str, label: str) -> None:
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one match, found {count}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def main() -> None:
    old = '''    # A clean slate every run: the module owns both objects.\n    _run_sql("DROP DATABASE IF EXISTS `%s`;" % API_DB, expect_ok=False)\n    _run_sql("DROP USER IF EXISTS '%s'@'127.0.0.1';" % API_USER,\n             expect_ok=False)\n    _run_sql("CREATE DATABASE `%s` DEFAULT CHARACTER SET utf8mb4"\n             " COLLATE utf8mb4_unicode_ci;" % API_DB)\n    _run_sql("CREATE USER '%s'@'127.0.0.1' IDENTIFIED BY '%s';"\n             % (API_USER, app_password))\n    # Exactly the production grant set of spec §2: DML only, no CREATE.\n    _run_sql("GRANT SELECT, INSERT, UPDATE, DELETE ON `%s`.* TO"\n             " '%s'@'127.0.0.1';" % (API_DB, API_USER))\n'''
    new = '''    # A clean slate every run: the module owns both objects. The default\n    # account host is production-like localhost. Container CI may opt into '%'\n    # because a service container sees the runner through its bridge address.\n    account_host = os.environ.get("IRICA_TEST_DB_ACCOUNT_HOST", "127.0.0.1")\n    if account_host not in ("127.0.0.1", "%"):\n        raise AssertionError("IRICA_TEST_DB_ACCOUNT_HOST has an unsupported value")\n    _run_sql("DROP DATABASE IF EXISTS `%s`;" % API_DB, expect_ok=False)\n    _run_sql("DROP USER IF EXISTS '%s'@'%s';" % (API_USER, account_host),\n             expect_ok=False)\n    _run_sql("CREATE DATABASE `%s` DEFAULT CHARACTER SET utf8mb4"\n             " COLLATE utf8mb4_unicode_ci;" % API_DB)\n    _run_sql("CREATE USER '%s'@'%s' IDENTIFIED BY '%s';"\n             % (API_USER, account_host, app_password))\n    # Exactly the production grant set of spec §2: DML only, no CREATE.\n    _run_sql("GRANT SELECT, INSERT, UPDATE, DELETE ON `%s`.* TO"\n             " '%s'@'%s';" % (API_DB, API_USER, account_host))\n'''
    replace_once(TESTS, old, new, "app-account host")

    old = '''    _state["drop_sql"] = (\n        "DROP DATABASE IF EXISTS `%s`;"\n        " DROP USER IF EXISTS '%s'@'127.0.0.1';" % (API_DB, API_USER))\n'''
    new = '''    _state["drop_sql"] = (\n        "DROP DATABASE IF EXISTS `%s`;"\n        " DROP USER IF EXISTS '%s'@'%s';"\n        % (API_DB, API_USER, account_host))\n'''
    replace_once(TESTS, old, new, "fixture cleanup host")

    # Migration count assertions must follow the forward-only migration set,
    # not the historical assumption that 001_initial is the only file.
    old = '''            self.assertIn("APPLY 001_initial", first)\n            self.assertEqual(\n                _sql_value("SELECT COUNT(*) FROM `%s`.schema_migrations;"\n                           % SCRATCH_DB), "1")\n\n            # The recorded checksum must match the file.\n            checksum = _sql_value("SELECT checksum FROM `%s`"\n                                  ".schema_migrations;" % SCRATCH_DB)\n'''
    new = '''            self.assertIn("APPLY 001_initial", first)\n            migration_files = sorted(\n                name for name in os.listdir(os.path.join(HOST_DIR, "migrations"))\n                if name.endswith(".sql"))\n            self.assertEqual(\n                _sql_value("SELECT COUNT(*) FROM `%s`.schema_migrations;"\n                           % SCRATCH_DB), str(len(migration_files)))\n            for filename in migration_files:\n                self.assertIn("APPLY " + os.path.splitext(filename)[0], first)\n\n            # The recorded checksum for 001 must match that exact file.\n            checksum = _sql_value(\n                "SELECT checksum FROM `%s`.schema_migrations "\n                "WHERE version='001_initial';" % SCRATCH_DB)\n'''
    replace_once(TESTS, old, new, "migration count contract")

    # A cached config is desirable for normal requests, but an emergency-style
    # migration kill switch must notice on-disk disablement immediately even in
    # a long-lived PHP-FPM worker. Invalid/missing fresh values fail closed.
    anchor = '''    public static function path(): string\n    {\n'''
    method = r'''    /**
     * Read one boolean directly from the active config file without using the
     * process cache. Security kill switches use this so disabling them takes
     * effect on the very next request in long-lived PHP-FPM workers.
     */
    public static function freshBoolean(string $key, bool $default = false): bool
    {
        $file = self::$path !== '' ? self::$path : self::locate();
        if (!is_file($file)) {
            return $default;
        }
        try {
            $raw = require $file;
        } catch (\Throwable $error) {
            unset($error);
            return $default;
        }
        if (!is_array($raw) || !array_key_exists($key, $raw)
            || !is_bool($raw[$key])) {
            return $default;
        }
        return $raw[$key];
    }

'''
    replace_once(CONFIG, anchor, method + anchor, "fresh config boolean")

    old = '''function requireLegacyImportEnabled(array $config): void\n{\n    if (($config['legacy_import_enabled'] ?? false) !== true) {\n'''
    new = '''function requireLegacyImportEnabled(array $_config): void\n{\n    if (!Config::freshBoolean('legacy_import_enabled', false)) {\n'''
    replace_once(INDEX, old, new, "fresh migration switch")

    print("host API and migration-switch hardening patch applied")


if __name__ == "__main__":
    main()
