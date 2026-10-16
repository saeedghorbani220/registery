# -*- coding: utf-8 -*-
"""Security and delivery gates for the browser legacy migration center."""
import os
import shutil
import socket
import subprocess
import tempfile
import time
import unittest
import urllib.error
import urllib.request

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
PUBLIC = os.path.join(ROOT, "host", "public")
PAGE = os.path.join(PUBLIC, "legacy-import.php")
JS = os.path.join(PUBLIC, "legacy-import.js")
CSS = os.path.join(PUBLIC, "legacy-import.css")


def read(path):
    with open(path, encoding="utf-8") as handle:
        return handle.read()


class LegacyMigrationPageStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.page = read(PAGE)
        cls.js = read(JS)
        cls.css = read(CSS)

    def test_page_is_api_only_and_fail_closed(self):
        self.assertIn("Config::freshBoolean('legacy_import_enabled', false)", self.page)
        self.assertIn("Request::isSecureTransport", self.page)
        self.assertNotIn("Database::", self.page)
        self.assertNotIn("PDO", self.page)
        self.assertNotIn("SELECT ", self.page)
        self.assertNotIn("INSERT ", self.page)
        self.assertNotIn("UPDATE ", self.page)

    def test_page_uses_external_assets_under_a_strict_csp(self):
        self.assertIn("default-src 'none'", self.page)
        self.assertIn("script-src 'self'", self.page)
        self.assertIn("style-src 'self'", self.page)
        self.assertIn("connect-src 'self'", self.page)
        self.assertIn("frame-ancestors 'none'", self.page)
        self.assertNotIn("unsafe-inline", self.page)
        self.assertIn('src="legacy-import.js"', self.page)
        self.assertIn('href="legacy-import.css"', self.page)

    def test_browser_token_is_memory_only(self):
        for forbidden in ("localStorage", "sessionStorage", "document.cookie", "indexedDB"):
            self.assertNotIn(forbidden, self.js)
        self.assertIn('let accessToken = ""', self.js)
        self.assertIn('byId("password").value = ""', self.js)
        self.assertIn('credentials: "omit"', self.js)
        self.assertNotIn("innerHTML", self.js)

    def test_all_migration_steps_use_the_http_api(self):
        for route in (
            "/auth/login", "/auth/logout", "/legacy-import/analyze",
            "/legacy-import/review", "/legacy-import/decision",
            "/legacy-import/apply",
        ):
            self.assertIn(route, self.js)
        self.assertIn("file.text()", self.js)
        self.assertIn("JSON.parse(sourceText)", self.js)
        self.assertIn("window.confirm", self.js)
        self.assertIn("maxUploadBytes", self.js)

    def test_styles_cover_review_and_mobile_layout(self):
        for selector in (".table-wrap", ".decision-controls", ".count-grid", "@media"):
            self.assertIn(selector, self.css)


class LegacyMigrationPageHttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.php = os.environ.get("IRICA_PHP") or shutil.which("php")
        if not cls.php:
            raise unittest.SkipTest("PHP CLI is not available")
        cls.tmp = tempfile.mkdtemp(prefix="irica_legacy_page_")
        cls.config = os.path.join(cls.tmp, "config.php")
        cls._write_config(False)
        cls.port = cls._free_port()
        cls.log = open(os.path.join(cls.tmp, "server.log"), "wb")
        env = dict(os.environ)
        env["IRICA_HOST_CONFIG"] = cls.config
        cls.server = subprocess.Popen(
            [cls.php, "-d", "display_errors=0", "-S", "127.0.0.1:%d" % cls.port,
             "-t", PUBLIC], stdout=cls.log, stderr=subprocess.STDOUT,
            cwd=ROOT, env=env,
        )
        cls.base = "http://127.0.0.1:%d" % cls.port
        cls._wait_ready()

    @classmethod
    def tearDownClass(cls):
        server = getattr(cls, "server", None)
        if server is not None and server.poll() is None:
            server.kill()
            try:
                server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                pass
        log = getattr(cls, "log", None)
        if log is not None and not log.closed:
            log.close()
        shutil.rmtree(getattr(cls, "tmp", ""), ignore_errors=True)

    @classmethod
    def _free_port(cls):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", 0))
            return probe.getsockname()[1]

    @classmethod
    def _write_config(cls, enabled):
        flag = "true" if enabled else "false"
        source = """<?php
return [
  'base_path' => '/v1',
  'legacy_import_enabled' => %s,
  'db' => ['host'=>'127.0.0.1','port'=>3306,'dbname'=>'unit_db','user'=>'unit_user','password'=>'unit_password'],
  'jwt_secret' => '%s',
  'limits' => ['max_body_bytes'=>1048576,'max_import_body_bytes'=>16777216],
];
""" % (flag, "a" * 64)
        with open(cls.config, "w", encoding="utf-8") as handle:
            handle.write(source)

    @classmethod
    def _request(cls, path):
        request = urllib.request.Request(cls.base + path, method="GET")
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return response.status, dict(response.headers.items()), response.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as error:
            return error.code, dict(error.headers.items()), error.read().decode("utf-8", "replace")

    @classmethod
    def _wait_ready(cls):
        deadline = time.time() + 15
        while time.time() < deadline:
            if cls.server.poll() is not None:
                raise AssertionError("PHP test server exited early")
            try:
                status, _headers, _body = cls._request("/legacy-import.css")
                if status == 200:
                    return
            except OSError:
                pass
            time.sleep(0.1)
        raise AssertionError("PHP test server did not become ready")

    def setUp(self):
        self._write_config(False)

    def test_page_is_hidden_while_kill_switch_is_off(self):
        status, headers, body = self._request("/legacy-import.php")
        self.assertEqual(status, 404)
        self.assertEqual(body, "Not found.\n")
        self.assertIn("no-store", headers.get("Cache-Control", ""))
        self.assertNotIn("Set-Cookie", headers)

    def test_enabled_page_has_strict_security_headers_and_no_secret_bootstrap(self):
        self._write_config(True)
        status, headers, body = self._request("/legacy-import.php")
        self.assertEqual(status, 200)
        self.assertIn("Legacy Migration Center", body)
        self.assertIn('data-api-base="/v1"', body)
        self.assertIn('data-max-upload-bytes="16777216"', body)
        csp = headers.get("Content-Security-Policy", "")
        for rule in ("default-src 'none'", "script-src 'self'", "connect-src 'self'", "frame-ancestors 'none'"):
            self.assertIn(rule, csp)
        self.assertNotIn("unsafe-inline", csp)
        self.assertEqual(headers.get("X-Frame-Options"), "DENY")
        self.assertEqual(headers.get("Referrer-Policy"), "no-referrer")
        self.assertIn("no-store", headers.get("Cache-Control", ""))
        self.assertNotIn("Set-Cookie", headers)
        self.assertNotIn("jwt_secret", body)
        self.assertNotIn("unit_password", body)

    def test_disable_takes_effect_on_the_next_request_in_same_server_process(self):
        self._write_config(True)
        self.assertEqual(self._request("/legacy-import.php")[0], 200)
        self._write_config(False)
        self.assertEqual(self._request("/legacy-import.php")[0], 404)

    def test_external_assets_are_reachable_without_dynamic_credentials(self):
        for path, marker in (("/legacy-import.js", "/legacy-import/analyze"),
                             ("/legacy-import.css", ".decision-controls")):
            status, _headers, body = self._request(path)
            self.assertEqual(status, 200)
            self.assertIn(marker, body)


if __name__ == "__main__":
    unittest.main()
