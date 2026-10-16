"""Adversarial checks for the legacy-import security kill switch."""
import os
import shutil
import subprocess
import tempfile
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
CONFIG_PHP = os.path.join(ROOT, "host", "src", "Config.php")


class FreshBooleanAdversarialTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.php = os.environ.get("IRICA_PHP") or shutil.which("php")
        if not cls.php:
            raise unittest.SkipTest("PHP CLI is not available")

    def _fresh_boolean(self, source):
        directory = tempfile.mkdtemp(prefix="irica_switch_audit_")
        self.addCleanup(shutil.rmtree, directory, True)
        config = os.path.join(directory, "config.php")
        probe = os.path.join(directory, "probe.php")
        with open(config, "w", encoding="utf-8") as handle:
            handle.write(source)
        with open(probe, "w", encoding="utf-8") as handle:
            handle.write(
                "<?php\ndeclare(strict_types=1);\n"
                "require " + repr(CONFIG_PHP.replace("\\", "/")) + ";\n"
                "putenv('IRICA_HOST_CONFIG=' . $argv[1]);\n"
                "Config::reset();\n"
                "echo Config::freshBoolean('legacy_import_enabled', false) ? '1' : '0';\n"
            )
        result = subprocess.run(
            [self.php, probe, config], capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def test_commented_true_cannot_override_live_false(self):
        source = """<?php
return [
    // 'legacy_import_enabled' => true,
    'legacy_import_enabled' => false,
];
"""
        self.assertEqual(self._fresh_boolean(source), "0")

    def test_duplicate_switch_is_ambiguous_and_fails_closed(self):
        source = """<?php
return [
    'legacy_import_enabled' => true,
    'legacy_import_enabled' => false,
];
"""
        self.assertEqual(self._fresh_boolean(source), "0")


if __name__ == "__main__":
    unittest.main()
