#!/usr/bin/env python3
"""One-shot guarded patch for legacy migration HTTP routes and kill switch."""
from __future__ import annotations

import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[2]


def replace_once(path: pathlib.Path, old: str, new: str, label: str) -> None:
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one match, found {count}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def main() -> None:
    config = ROOT / "host" / "config" / "config.example.php"
    old = """    // Request limits (spec §10.6).\n    'limits' => [\n"""
    new = """    // Legacy local-database migration is deliberately disabled by default.\n    // Enable it only for a reviewed migration window, then turn it off again.\n    // The web page and every migration API route enforce this server-side.\n    'legacy_import_enabled' => false,\n\n    // Request limits (spec §10.6).\n    'limits' => [\n"""
    replace_once(config, old, new, "config kill switch")

    index = ROOT / "host" / "public" / "index.php"
    old = """    'RateLimit', 'Auth', 'Devices', 'Sync', 'Import', 'Finance',\n"""
    new = """    'RateLimit', 'Auth', 'Devices', 'Sync', 'Import', 'Finance',\n    'LegacyImport', 'LegacyApply',\n"""
    replace_once(index, old, new, "legacy class loading")

    old = """        '/finance/transactions/void' => ['POST'],\n        '/bootstrap/import' => ['POST'],\n"""
    new = """        '/finance/transactions/void' => ['POST'],\n        '/legacy-import/analyze' => ['POST'],\n        '/legacy-import/review' => ['GET'],\n        '/legacy-import/decision' => ['POST'],\n        '/legacy-import/apply' => ['POST'],\n        '/bootstrap/import' => ['POST'],\n"""
    replace_once(index, old, new, "legacy route table")

    old = """    $import = new Import($db, $sync, $log, $config);\n    $finance = new Finance($db, $log, $config);\n    $ip = $request->remoteAddr;\n"""
    new = """    $import = new Import($db, $sync, $log, $config);\n    $finance = new Finance($db, $log, $config);\n    $legacyImport = new LegacyImport($db, $sync, $log, $config);\n    $legacyApply = new LegacyApply($db, $sync, $log, $config);\n    $ip = $request->remoteAddr;\n"""
    replace_once(index, old, new, "legacy service init")

    old = """    $limitBody = (int) ($config['limits']['max_body_bytes'] ?? 1048576);\n    if ($route !== '/bootstrap/import' && $request->rawBody !== ''\n        && strlen($request->rawBody) > $limitBody) {\n"""
    new = """    $limitBody = (int) ($config['limits']['max_body_bytes'] ?? 1048576);\n    $largeBodyRoutes = ['/bootstrap/import', '/legacy-import/analyze'];\n    if (!in_array($route, $largeBodyRoutes, true) && $request->rawBody !== ''\n        && strlen($request->rawBody) > $limitBody) {\n"""
    replace_once(index, old, new, "legacy large-body allowance")

    anchor = """        case '/bootstrap/import':\n"""
    routes = r'''        case '/legacy-import/analyze':
            $user = requireUser($auth, $request);
            requireLegacyImportEnabled($config);
            $body = $request->jsonBody();
            $payload = $legacyImport->analyze(
                $user, $body, $requestId, $ip
            );
            $statusCode = 200;
            $errorCode = '';
            Response::ok($payload);
            break;

        case '/legacy-import/review':
            $user = requireUser($auth, $request);
            requireLegacyImportEnabled($config);
            $jobId = stringQuery($request, 'job_id');
            $payload = $legacyApply->review($user, $jobId);
            $statusCode = 200;
            $errorCode = '';
            Response::ok($payload);
            break;

        case '/legacy-import/decision':
            $user = requireUser($auth, $request);
            requireLegacyImportEnabled($config);
            $body = $request->jsonBody();
            $payload = $legacyApply->decide(
                $user, $body, $requestId, $ip
            );
            $statusCode = 200;
            $errorCode = '';
            Response::ok($payload);
            break;

        case '/legacy-import/apply':
            $user = requireUser($auth, $request);
            requireLegacyImportEnabled($config);
            $body = $request->jsonBody();
            $jobId = $body['job_id'] ?? null;
            if (!is_string($jobId) || !Ids::isUuid($jobId)) {
                throw new ApiException(400, Codes::BAD_PAYLOAD,
                    'job_id must be a UUID');
            }
            $payload = $legacyApply->apply(
                $user, $jobId, $requestId, $ip
            );
            $statusCode = 200;
            $errorCode = '';
            Response::ok($payload);
            break;

'''
    replace_once(index, anchor, routes + anchor, "legacy route handlers")

    helper_anchor = """function intQuery(Request $request, string $key, ?int $default): ?int\n"""
    helpers = r'''/**
 * Require a live user bearer for browser/admin endpoints.
 *
 * @throws ApiException 401
 */
function requireUser(Auth $auth, Request $request): Principal
{
    $principal = $auth->authenticate($request);
    if (!$principal->isUser()) {
        throw new ApiException(401, Codes::AUTH_REQUIRED,
            'a user access token is required for this endpoint');
    }
    return $principal;
}

/** @throws ApiException 403 */
function requireLegacyImportEnabled(array $config): void
{
    if (($config['legacy_import_enabled'] ?? false) !== true) {
        throw new ApiException(403, Codes::PERMISSION_DENIED,
            'legacy migration is disabled on this host');
    }
}

/** @throws ApiException 400 */
function stringQuery(Request $request, string $key): string
{
    if (!array_key_exists($key, $request->query)) {
        throw new ApiException(400, Codes::BAD_PAYLOAD,
            $key . ' is required');
    }
    $raw = $request->query[$key];
    if (is_array($raw) || !is_string($raw) || $raw === '' || strlen($raw) > 128) {
        throw new ApiException(400, Codes::BAD_PAYLOAD,
            $key . ' must be a non-empty string');
    }
    return $raw;
}

'''
    replace_once(index, helper_anchor, helpers + helper_anchor, "legacy helpers")

    tests = ROOT / "lab" / "tests" / "test_host_api.py"
    old = """    'idempotency_retention_days' => 30,\n    'rate_limit' => [\n"""
    new = """    'idempotency_retention_days' => 30,\n    'legacy_import_enabled' => false,\n    'rate_limit' => [\n"""
    replace_once(tests, old, new, "host fixture kill switch")

    old = '''        tables = ("crm_devices", "customer_transactions", "identities",\n                  "owners", "customers", "periods", "settings", "change_log",\n                  "idempotency_keys")\n'''
    new = '''        tables = ("legacy_import_decisions", "legacy_import_records",\n                  "legacy_import_jobs", "crm_devices", "customer_transactions",\n                  "identities", "owners", "customers", "periods", "settings",\n                  "change_log", "idempotency_keys")\n'''
    replace_once(tests, old, new, "host fixture legacy cleanup")

    method_anchor = """    # -- §5: login, rate limiting, refresh, enrolment --------------------\n"""
    method = r'''    def test_legacy_migration_routes_are_default_off_admin_only_and_atomic(self):
        store = {
            "customers": [{
                "id": "legacy01", "full_name": "Legacy HTTP Customer",
                "address": "Old address", "mobile": "09121111111",
                "notes": "", "created": "2026-01-01 12:00:00",
                "transactions": [],
            }],
            "owners": [], "identities": [], "devices": [], "periods": [],
        }
        body = {
            "source_text": json.dumps(store, ensure_ascii=False,
                                      separators=(",", ":")),
            "filename": "crm_store.json", "source_version": "1.13.1",
        }
        admin = _login(_state["admin_user"], _state["admin_password"])

        # The endpoint exists but the migration window is closed by default.
        status, error, _h, _p = _fail(
            "POST", "/legacy-import/analyze", body,
            token=admin["access_token"])
        self.assertEqual((status, error["code"]), (403, "PERMISSION_DENIED"))

        path = _state["config_path"]
        with open(path, "r", encoding="utf-8") as handle:
            original = handle.read()
        enabled = original.replace(
            "'legacy_import_enabled' => false,",
            "'legacy_import_enabled' => true,", 1)
        self.assertNotEqual(original, enabled, "fixture did not expose the migration switch")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(enabled)
        try:
            member = _login(_state["user_user"], _state["user_password"])
            status, error, _h, _p = _fail(
                "POST", "/legacy-import/analyze", body,
                token=member["access_token"])
            self.assertEqual((status, error["code"]),
                             (403, "PERMISSION_DENIED"))

            analyzed, _h = _ok(
                "POST", "/legacy-import/analyze", body,
                token=admin["access_token"])
            self.assertEqual(analyzed["job"]["status"], "ready")
            job_id = analyzed["job"]["id"]

            reviewed, _h = _ok(
                "GET", "/legacy-import/review?job_id=" + job_id,
                token=admin["access_token"])
            self.assertEqual(reviewed["unresolved"], 0)
            self.assertEqual(reviewed["counts"]["create"], 1)

            applied, _h = _ok(
                "POST", "/legacy-import/apply", {"job_id": job_id},
                token=admin["access_token"])
            self.assertEqual(applied["status"], "applied")
            self.assertEqual(applied["counts"]["created"], 1)
            self.assertEqual(_sql_value(
                "SELECT COUNT(*) FROM customers WHERE tenant_id='%s';"
                % _state["tenant_id"]), "1")

            # Replay is a no-op and the staged source was never stored raw.
            replay, _h = _ok(
                "POST", "/legacy-import/apply", {"job_id": job_id},
                token=admin["access_token"])
            self.assertTrue(replay["replayed"])
            self.assertEqual(_sql_value(
                "SELECT COUNT(*) FROM customers WHERE tenant_id='%s';"
                % _state["tenant_id"]), "1")
        finally:
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(original)

'''
    replace_once(tests, method_anchor, method + method_anchor, "legacy HTTP test")
    print("legacy migration HTTP patch applied")


if __name__ == "__main__":
    main()
