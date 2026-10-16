<?php
/**
 * index.php — the single front controller of the IRICA cloud-sync host API.
 *
 * Contract: lab/docs/CLOUD_SYNC_SPEC.md §6 (routes and envelope), §7 (roles),
 * §10 (the security controls). Plain PHP 8.1, no Composer, no framework: this
 * file is what `php -S … host/public index.php` and Apache's .htaccess both
 * point at, and it is the only code that runs for an HTTP request.
 *
 * Order of operations, and why:
 *   1. display_errors off — an exception message must never reach a client;
 *   2. configuration, because everything below needs it;
 *   3. capture the request with the body-size cap applied to Content-Length,
 *      so an oversized body is refused without being read;
 *   4. HTTPS gate (spec §2) before any routing;
 *   5. explicit route table — no regex over user input, no dynamic dispatch;
 *   6. authentication and authorization per route (§6, §7);
 *   7. one structured log line: request_id, route, status, duration, code.
 */

declare(strict_types=1);

// ---------------------------------------------------------------------------
// 1. Fail closed before anything can print
// ---------------------------------------------------------------------------
ini_set('display_errors', '0');
ini_set('display_startup_errors', '0');
ini_set('html_errors', '0');
error_reporting(E_ALL);

define('HOST_ROOT', dirname(__DIR__));

foreach ([
    'Schema', 'Database', 'Http', 'Ids', 'Config', 'Log', 'Tokens', 'Roles',
    'RateLimit', 'Auth', 'Devices', 'Sync', 'Import', 'Finance',
    'LegacyImport', 'LegacyVerify', 'LegacyApply',
] as $classFile) {
    require_once HOST_ROOT . '/src/' . $classFile . '.php';
}

// ---------------------------------------------------------------------------
// 2. Configuration and services
// ---------------------------------------------------------------------------
$requestId = Ids::v4();
$started = microtime(true);
$statusCode = 500;
$routeLabel = 'unrouted';
$errorCode = Codes::SERVER_ERROR;
$log = new Log(null);
$db = null;

try {
    try {
        $config = Config::load();
    } catch (\RuntimeException $configError) {
        // A missing or placeholder config is an installation problem, not a
        // generic 500 — and the message names the key, never a value.
        throw new ApiException(500, Codes::CONFIG_INVALID,
            $configError->getMessage());
    }
    $log = new Log(is_string($config['log_path'] ?? null)
        ? $config['log_path'] : null);
    $maxBody = max(
        (int) ($config['limits']['max_body_bytes'] ?? 1048576),
        (int) ($config['limits']['max_import_body_bytes'] ?? 16777216)
    );
    if ($maxBody < 1024) {
        $maxBody = 1048576;
    }

    $request = Request::capture($_SERVER, $_GET, $maxBody);
    $requestId = $request->requestId;

    // Optional web-setup runner for shared hosting (delegates to setup.php if present)
    if (str_ends_with($request->path, '/setup.php') && file_exists(__DIR__ . '/setup.php')) {
        require __DIR__ . '/setup.php';
        exit;
    }

    // Optional Telegram relay runner for shared hosting (delegates to telegram.php if present)
    if ((str_ends_with($request->path, '/telegram.php') || str_contains($request->path, '/telegram.php/'))
        && file_exists(__DIR__ . '/telegram.php')) {
        require __DIR__ . '/telegram.php';
        exit;
    }

    $route = routeOf($request->path, (string) ($config['base_path'] ?? '/v1'));

    // Route table. A path that exists under another verb answers 405, so a
    // typo'd method is distinguishable from a typo'd URL.
    $knownPaths = [
        '/health/live' => ['GET'],
        '/auth/login' => ['POST'],
        '/auth/refresh' => ['POST'],
        '/auth/logout' => ['POST'],
        '/sync-devices/enroll' => ['POST'],
        '/sync-devices/self-enroll' => ['POST'],
        '/sync-devices/revoke' => ['POST'],
        '/sync-devices/revoke-all' => ['POST'],
        '/sync/bootstrap' => ['GET'],
        '/sync/changes' => ['GET'],
        '/sync/mutations' => ['POST'],
        '/finance/transactions/append' => ['POST'],
        '/finance/transactions/void' => ['POST'],
        '/legacy-import/analyze' => ['POST'],
        '/legacy-import/review' => ['GET'],
        '/legacy-import/decision' => ['POST'],
        '/legacy-import/apply' => ['POST'],
        '/legacy-import/verify' => ['GET'],
        '/bootstrap/import' => ['POST'],
        '/admin/backup' => ['POST'],
    ];
    // Only a known route may be written to the log: an unknown path is user
    // input, and user input never reaches a log line (spec §5).
    $routeLabel = $request->method . ' '
        . (isset($knownPaths[$route]) ? $route : '<unknown>');

    // ---- spec §2: HTTPS is mandatory off-loopback -------------------------
    if (!Request::isSecureTransport(
        $request->header('x-forwarded-proto'),
        $request->remoteAddr,
        isset($_SERVER['HTTPS']) && is_string($_SERVER['HTTPS'])
            ? $_SERVER['HTTPS'] : ''
    )) {
        throw new ApiException(403, Codes::HTTPS_REQUIRED,
            'this API is reachable only over HTTPS');
    }

    $db = Database::fromConfig(Config::db());
    $auth = new Auth($db, $log, $config);
    $devices = new Devices($db, $log, $config);
    $sync = new Sync($db, $log, $config);
    $import = new Import($db, $sync, $log, $config);
    $finance = new Finance($db, $log, $config);
    $legacyImport = new LegacyImport($db, $sync, $log, $config);
    $legacyVerify = new LegacyVerify($db, $log, $config);
    $legacyApply = new LegacyApply($db, $sync, $log, $config);
    $ip = $request->remoteAddr;

    if (!isset($knownPaths[$route])) {
        throw new ApiException(404, Codes::HTTP_404, 'no such endpoint');
    }
    if (!in_array($request->method, $knownPaths[$route], true)) {
        throw new ApiException(405, Codes::HTTP_405,
            'this endpoint does not accept ' . $request->method);
    }

    $limitBody = (int) ($config['limits']['max_body_bytes'] ?? 1048576);
    $largeBodyRoutes = ['/bootstrap/import', '/legacy-import/analyze'];
    if (!in_array($route, $largeBodyRoutes, true) && $request->rawBody !== ''
        && strlen($request->rawBody) > $limitBody) {
        throw new ApiException(413, Codes::PAYLOAD_TOO_LARGE,
            'request body exceeds the configured limit');
    }

    switch ($route) {
        case '/health/live':
            // Liveness only: no database, no authentication, no payload
            // beyond {ok, time} (spec §6).
            $statusCode = 200;
            $errorCode = '';
            Response::ok(['time' => gmdate('Y-m-d\TH:i:s\Z')]);
            break;

        case '/auth/login':
            $body = $request->jsonBody();
            $payload = $auth->login($body, $ip, $requestId);
            $statusCode = 200;
            $errorCode = '';
            Response::ok($payload);
            break;

        case '/auth/refresh':
            $body = $request->jsonBody();
            $payload = $auth->refresh($body, $ip, $requestId);
            $statusCode = 200;
            $errorCode = '';
            Response::ok($payload);
            break;

        case '/auth/logout':
            $request->jsonBody(false);
            $principal = $auth->authenticate($request);
            if (!$principal->isUser()) {
                throw new ApiException(401, Codes::AUTH_REQUIRED,
                    'a user access token is required to log out');
            }
            $payload = $auth->logout($principal, $requestId, $ip);
            $statusCode = 200;
            $errorCode = '';
            Response::ok($payload);
            break;

        case '/sync-devices/enroll':
            $body = $request->jsonBody(false);
            $principal = $auth->authenticate($request);
            $payload = $auth->enroll($principal, $body, $requestId, $ip);
            $statusCode = 200;
            $errorCode = '';
            Response::ok($payload);
            break;

        case '/sync-devices/self-enroll':
            $body = $request->jsonBody(false);
            $principal = $auth->authenticate($request);
            $payload = $devices->selfEnroll(
                $principal, $body, $requestId, $ip
            );
            $statusCode = 200;
            $errorCode = '';
            Response::ok($payload);
            break;

        case '/sync-devices/revoke':
            $body = $request->jsonBody();
            $principal = $auth->authenticate($request);
            $deviceId = $body['sync_device_id'] ?? null;
            if (!is_string($deviceId)) {
                throw new ApiException(400, Codes::BAD_PAYLOAD,
                    'sync_device_id is required');
            }
            $payload = $devices->revoke(
                $principal, $deviceId, $requestId, $ip
            );
            $statusCode = 200;
            $errorCode = '';
            Response::ok($payload);
            break;

        case '/sync-devices/revoke-all':
            $body = $request->jsonBody(false);
            $principal = $auth->authenticate($request);
            $targetUserId = $body['user_id'] ?? null;
            if ($targetUserId !== null && !is_string($targetUserId)) {
                throw new ApiException(400, Codes::BAD_PAYLOAD,
                    'user_id must be a UUID when supplied');
            }
            $payload = $devices->revokeAll(
                $principal, $targetUserId, $requestId, $ip
            );
            $statusCode = 200;
            $errorCode = '';
            Response::ok($payload);
            break;

        case '/sync/bootstrap':
            $device = requireDevice($auth, $request);
            $payload = $sync->bootstrap($device->tenantId);
            $statusCode = 200;
            $errorCode = '';
            Response::ok($payload);
            break;

        case '/sync/changes':
            $device = requireDevice($auth, $request);
            $cursor = intQuery($request, 'cursor', null);
            $limit = intQuery($request, 'limit', null);
            $payload = $sync->changes($device->tenantId, $cursor, $limit);
            $statusCode = 200;
            $errorCode = '';
            Response::ok($payload);
            break;

        case '/sync/mutations':
            $device = requireDevice($auth, $request);
            $body = $request->jsonBody();
            $acting = $auth->actingUser($request);
            $context = [
                'device' => $device,
                'user' => $acting,
                'role' => $auth->effectiveRole([
                    'device' => $device, 'user' => $acting,
                ]),
            ];
            $operations = $body['operations'] ?? null;
            if (!is_array($operations) || !array_is_list($operations)) {
                throw new ApiException(400, Codes::BAD_PAYLOAD,
                    'operations must be a JSON array');
            }
            /** @var list<array<string, mixed>> $operations */
            $payload = $sync->mutations($operations, $context, $requestId);
            $statusCode = 200;
            $errorCode = '';
            Response::ok($payload);
            break;

        case '/finance/transactions/append':
            $device = requireDevice($auth, $request);
            $body = $request->jsonBody();
            $acting = $auth->actingUser($request);
            $context = [
                'device' => $device,
                'user' => $acting,
                'role' => $auth->effectiveRole([
                    'device' => $device, 'user' => $acting,
                ]),
            ];
            $payload = $finance->append($body, $context, $requestId);
            $statusCode = 200;
            $errorCode = '';
            Response::ok($payload);
            break;

        case '/finance/transactions/void':
            $device = requireDevice($auth, $request);
            $body = $request->jsonBody();
            $acting = $auth->actingUser($request);
            $context = [
                'device' => $device,
                'user' => $acting,
                'role' => $auth->effectiveRole([
                    'device' => $device, 'user' => $acting,
                ]),
            ];
            $payload = $finance->void($body, $context, $requestId);
            $statusCode = 200;
            $errorCode = '';
            Response::ok($payload);
            break;

        case '/legacy-import/analyze':
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

        case '/legacy-import/verify':
            $user = requireUser($auth, $request);
            requireLegacyImportEnabled($config);
            $jobId = stringQuery($request, 'job_id');
            $payload = $legacyVerify->report($user, $jobId);
            $statusCode = 200;
            $errorCode = '';
            Response::ok($payload);
            break;

        case '/bootstrap/import':
            $device = requireDevice($auth, $request);
            $acting = $auth->actingUser($request);
            if ($acting === null) {
                throw new ApiException(401, Codes::AUTH_REQUIRED,
                    'an import requires a user access token in X-Acting-User');
            }
            $body = $request->jsonBody();
            $payload = $import->run($device, $acting, $body, $requestId, $ip);
            $statusCode = 200;
            $errorCode = '';
            Response::ok($payload);
            break;

        case '/admin/backup':
            $device = requireDevice($auth, $request);
            $acting = $auth->actingUser($request);
            if ($acting === null) {
                throw new ApiException(401, Codes::AUTH_REQUIRED,
                    'backup requires a user access token in X-Acting-User');
            }
            Roles::requireAdmin($acting->role);
            require_once dirname(__DIR__) . '/bin/backup-to-telegram.php';
            $backupResult = run_database_backup($db, $config);
            $statusCode = 200;
            $errorCode = '';
            Response::ok($backupResult);
            break;

        default:
            throw new ApiException(404, Codes::HTTP_404, 'no such endpoint');
    }
} catch (ApiException $error) {
    $statusCode = $error->status;
    $errorCode = $error->errorCode;
    Response::fail($error, $requestId);
} catch (\PDOException $error) {
    $statusCode = 500;
    $errorCode = Codes::DB_UNAVAILABLE;
    Response::fail(new ApiException(500, Codes::DB_UNAVAILABLE,
        'the database is unavailable'), $requestId);
    $log->line(['request_id' => $requestId, 'route' => $routeLabel,
        'status' => 500, 'code' => $errorCode, 'level' => 'error']
        + Log::describe($error));
} catch (\Throwable $error) {
    $statusCode = 500;
    $errorCode = Codes::SERVER_ERROR;
    Response::fail(new ApiException(500, Codes::SERVER_ERROR,
        'internal server error'), $requestId);
    $log->line(['request_id' => $requestId, 'route' => $routeLabel,
        'status' => 500, 'code' => $errorCode, 'level' => 'error']
        + Log::describe($error));
} finally {
    $log->line([
        'request_id' => $requestId,
        'method' => $routeLabel === 'unrouted' ? '' : explode(' ', $routeLabel)[0],
        'route' => $routeLabel,
        'status' => $statusCode,
        'duration_ms' => (int) round((microtime(true) - $started) * 1000),
        'code' => $errorCode,
    ]);
}

// ---------------------------------------------------------------------------
// Helpers (declared after use; PHP hoists top-level functions)
// ---------------------------------------------------------------------------

/**
 * Map a request path onto a route key, honouring the configured base path.
 * The query string is deliberately discarded: a route label must never carry
 * user input (spec §5 — logs hold request_id, route, status, duration only).
 */
function routeOf(string $path, string $basePath): string
{
    $base = rtrim($basePath, '/');
    if ($base !== '') {
        if ($path === $base) {
            return '/';
        }
        if (strncmp($path, $base . '/', strlen($base) + 1) === 0) {
            return substr($path, strlen($base));
        }
    }
    return $path;
}

/**
 * The device access token every /sync route needs (spec §6).
 *
 * @throws ApiException 401
 */
function requireDevice(Auth $auth, Request $request): Principal
{
    $principal = $auth->authenticate($request);
    if (!$principal->isDevice()) {
        throw new ApiException(401, Codes::AUTH_REQUIRED,
            'a device access token is required for this endpoint');
    }
    return $principal;
}

/**
 * Read an integer query parameter, rejecting anything else (no coercion: a
 * `cursor=1e3` or `limit=abc` is a client bug and must not be guessed at).
 *
 * @throws ApiException 400
 */
/**
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
function requireLegacyImportEnabled(array $_config): void
{
    if (!Config::freshBoolean('legacy_import_enabled', false)) {
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

function intQuery(Request $request, string $key, ?int $default): ?int
{
    if (!array_key_exists($key, $request->query)) {
        return $default;
    }
    $raw = $request->query[$key];
    if (is_array($raw) || !is_string($raw) || !preg_match('/^\d+$/', $raw)) {
        throw new ApiException(400, Codes::BAD_PAYLOAD,
            $key . ' must be a non-negative integer');
    }
    return (int) $raw;
}
