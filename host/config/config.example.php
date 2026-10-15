<?php
/**
 * config.example.php — the template for host/config/config.php.
 *
 * Contract: lab/docs/CLOUD_SYNC_SPEC.md §10.8. This file is the ONLY one of
 * the two that may be committed: every value below is a placeholder. Copy it
 * on the host, fill it in, and never commit the copy — host/config/.gitignore
 * and the .htaccess rules both enforce that from their side.
 *
 * Every key is documented where it is used:
 *   db / db_migrate   host/src/Config.php, host/bin/migrate.php
 *   jwt_secret        host/src/Tokens.php (see host/SECURITY.md for why HS256)
 *   refresh           host/src/Auth.php (spec §5 lifetimes)
 *   rate_limit        host/src/RateLimit.php (spec §10.5)
 *   limits            host/src/Http.php, host/src/Sync.php, host/src/Import.php
 *   https / tenant    host/public/index.php, host/src/Auth.php
 *
 * Generate the signing key with:
 *     php -r "echo bin2hex(random_bytes(32)), PHP_EOL;"
 */

return [
    // 'production' logs nothing to the response; only this value changes
    // nothing else — the API is always fail-closed.
    'env' => 'production',

    // The version prefix of every route (spec §6: https://api.<domain>/v1).
    'base_path' => '/v1',

    // The one shared tenant of spec §7. bin/create-admin.php creates it.
    'tenant_slug' => 'default',

    // The application account: SELECT/INSERT/UPDATE/DELETE only (spec §2).
    // It must never hold CREATE — host/bin/smoke-test.php refuses to pass
    // a run where it does.
    'db' => [
        'host' => '127.0.0.1',
        'port' => 3306,
        'dbname' => 'REPLACE_WITH_DATABASE_NAME',
        'user' => 'REPLACE_WITH_APP_USER',
        'password' => 'REPLACE_WITH_APP_PASSWORD',
    ],

    // Optional: the privileged account bin/migrate.php uses, because the app
    // account cannot run DDL (spec §2, §10.6). Null = use `db`, which only
    // works if that account also holds CREATE.
    'db_migrate' => null,

    // 32 random bytes as 64 hex characters. Signs and verifies access tokens.
    'jwt_secret' => '0000000000000000000000000000000000000000000000000000000000000000',

    // Access-token lifetime in seconds (spec §5: 15 minutes).
    'jwt_ttl_seconds' => 900,

    // Refresh-token lifetimes (spec §5): idle window and absolute ceiling.
    'refresh' => [
        'user_idle_seconds' => 28800,        // 8 hours
        'user_absolute_seconds' => 86400,    // 24 hours
        'device_idle_seconds' => 7776000,    // 90 days
        'device_absolute_seconds' => 31536000, // 365 days
    ],

    // How long a replayed operation_id keeps returning its first result
    // (spec §6.1: retained >= 30 days).
    'idempotency_retention_days' => 30,

    // Spec §10.5: growing delay, then a TEMPORARY lock. There is no permanent
    // lockout column anywhere — a lock that never expires is a DoS weapon.
    'rate_limit' => [
        'window_seconds' => 900,   // consecutive-failure counting window
        'delay_after' => 4,        // failures before a delay starts
        'base_delay_seconds' => 1, // 1, 2, 4, 8 … capped below
        'max_delay_seconds' => 60,
        'lock_after' => 10,        // failures before the temporary lock
        'lock_seconds' => 300,     // … which then simply expires
    ],

    // Legacy local-database migration is deliberately disabled by default.
    // Enable it only for a reviewed migration window, then turn it off again.
    // The web page and every migration API route enforce this server-side.
    'legacy_import_enabled' => false,

    // Request limits (spec §10.6).
    'limits' => [
        'max_body_bytes' => 1048576,        // every route except import
        'max_import_body_bytes' => 16777216, // POST /bootstrap/import
        'max_operations' => 500,            // operations in one push
        'max_import_rows' => 100000,        // rows in one import
        'default_changes_limit' => 500,
        'max_changes_limit' => 5000,
    ],

    // The request log (spec §5). Must be outside public_html. `null` disables
    // file logging; errors are still suppressed from the response either way.
    'log_path' => __DIR__ . '/../var/log/api.log',

    // Optional: an operator sets this to the public health URL so that
    // bin/smoke-test.php can prove TLS and response headers on the live host.
    'smoke_probe_url' => null,

    // Optional setup key for web-based installation on shared hosting without SSH.
    // If set, you can visit https://api.<domain>/setup.php?key=YOUR_SETUP_KEY
    'setup_key' => null,

    // Optional secret key to secure public/telegram.php relay from unauthorized use.
    // If set, clients must supply X-Relay-Secret header or relay_secret parameter.
    'telegram_relay_secret' => null,

    // Automated 4-hour database backup to Telegram (bin/backup-to-telegram.php).
    // Can also fallback to tenant settings table or environment variables.
    'backup' => [
        'bot_token' => 'REPLACE_WITH_TELEGRAM_BOT_TOKEN',
        'chat_id' => 'REPLACE_WITH_TELEGRAM_CHAT_ID',
    ],
];
