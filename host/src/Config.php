<?php
/**
 * Config.php — the one place host/config/config.php is read.
 *
 * Contract: lab/docs/CLOUD_SYNC_SPEC.md §10.8 — configuration and keys live
 * outside public_html and are never committed. Only config.example.php (all
 * placeholders) is in the repository; the real file is created on the host.
 *
 * Nothing here ever prints, logs or throws a message that contains a value:
 * a database password or the signing key must not reach an error page.
 */

declare(strict_types=1);

final class Config
{
    /** The only environment variable that redirects the config file lookup. */
    public const ENV_PATH = 'IRICA_HOST_CONFIG';

    /** Recognised at both the top level and inside db sections. */
    private const DB_KEYS = ['host', 'port', 'dbname', 'user', 'password'];

    /** @var array<string, mixed>|null */
    private static ?array $cache = null;

    private static string $path = '';

    /**
     * Load and validate the configuration once per process.
     *
     * @throws RuntimeException when the file is missing or a required key is
     *         absent/unset — the message names the key, never its value.
     */
    public static function load(?string $path = null): array
    {
        if (self::$cache !== null && ($path === null || $path === self::$path)) {
            return self::$cache;
        }
        $file = $path ?? self::locate();
        if (!is_file($file)) {
            throw new RuntimeException(
                'configuration file is missing: copy config.example.php to '
                . 'config.php and fill it in (see host/INSTALL.md)'
            );
        }
        $raw = require $file;
        if (!is_array($raw)) {
            throw new RuntimeException('configuration file must return an array');
        }
        self::validate($raw);
        self::$cache = $raw;
        self::$path = $file;
        return $raw;
    }

    /** Forget the cached configuration (used by the tests and the CLIs). */
    public static function reset(): void
    {
        self::$cache = null;
        self::$path = '';
    }

    /**
     * Read one literal boolean directly from the active config source without
     * executing the file or consulting the process cache. Security kill
     * switches use this so edits take effect on the very next request even
     * when PHP OPcache is configured not to revalidate scripts.
     */
    public static function freshBoolean(string $key, bool $default = false): bool
    {
        $file = self::$path !== '' ? self::$path : self::locate();
        $source = @file_get_contents($file);
        if (!is_string($source) || $source === '') {
            return $default;
        }
        $quoted = preg_quote($key, '/');
        $pattern = '/[\'\"]' . $quoted . '[\'\"]\s*=>\s*(true|false)\b/i';
        $matched = preg_match($pattern, $source, $match);
        if ($matched !== 1 || !isset($match[1])) {
            return $default;
        }
        return strtolower((string) $match[1]) === 'true';
    }

    public static function path(): string
    {
        return self::$path;
    }

    /** Resolve the configuration file: env override, then the default. */
    public static function locate(): string
    {
        $override = getenv(self::ENV_PATH);
        if (is_string($override) && trim($override) !== '') {
            return trim($override);
        }
        return dirname(__DIR__) . '/config/config.php';
    }

    /**
     * Structural checks only. Every failure names a key and never a value.
     *
     * @param array<string, mixed> $cfg
     */
    private static function validate(array $cfg): void
    {
        foreach (['db', 'jwt_secret'] as $key) {
            if (!array_key_exists($key, $cfg)) {
                throw new RuntimeException('configuration key is missing: ' . $key);
            }
        }
        self::validateDb($cfg['db'], 'db');
        if (array_key_exists('db_migrate', $cfg) && $cfg['db_migrate'] !== null) {
            if (!is_array($cfg['db_migrate'])) {
                throw new RuntimeException('configuration key db_migrate must be '
                    . 'an array or null');
            }
            self::validateDb($cfg['db_migrate'], 'db_migrate');
        }
        if (!is_string($cfg['jwt_secret']) || !self::isUsableSecret($cfg['jwt_secret'])) {
            throw new RuntimeException(
                'jwt_secret must be at least 32 bytes of random hex — generate '
                . 'one with: php -r "echo bin2hex(random_bytes(32));"'
            );
        }
    }

    /**
     * @param mixed $db
     */
    private static function validateDb($db, string $where): void
    {
        if (!is_array($db)) {
            throw new RuntimeException('configuration key ' . $where
                . ' must be an array');
        }
        foreach (['host', 'dbname', 'user', 'password'] as $key) {
            if (!array_key_exists($key, $db)
                || !is_string($db[$key]) || $db[$key] === '') {
                throw new RuntimeException('configuration key ' . $where . '.'
                    . $key . ' must be a non-empty string');
            }
        }
        if (strpos($db['dbname'], 'REPLACE_') === 0
            || strpos($db['password'], 'REPLACE_') === 0
            || strpos($db['user'], 'REPLACE_') === 0) {
            throw new RuntimeException(
                'configuration still holds a placeholder in ' . $where
                . ' — edit config.php before continuing'
            );
        }
        if (isset($db['port'])
            && (!is_int($db['port']) || $db['port'] < 1 || $db['port'] > 65535)) {
            throw new RuntimeException('configuration key ' . $where
                . '.port must be an integer between 1 and 65535');
        }
    }

    /** A usable key is long, hex, and not the value shipped in the example. */
    public static function isUsableSecret(string $secret): bool
    {
        if (strlen($secret) < 64 || !ctype_xdigit($secret)) {
            return false;
        }
        return $secret !== self::exampleSecret();
    }

    /** The literal placeholder written into config.example.php. */
    public static function exampleSecret(): string
    {
        return str_repeat('0', 64);
    }

    /**
     * The connection array for the runtime app account (DML only).
     *
     * @return array<string, mixed>
     */
    public static function db(): array
    {
        $cfg = self::load();
        return self::withPort($cfg['db']);
    }

    /**
     * The connection bin/migrate.php uses — the privileged account.
     *
     * Falls back to the app account so a single-user install works, but
     * smoke-test.php then reports that CREATE is unavailable (spec §2: the web
     * user must never hold DDL).
     *
     * @return array<string, mixed>
     */
    public static function dbMigrate(): array
    {
        $cfg = self::load();
        if (isset($cfg['db_migrate']) && is_array($cfg['db_migrate'])) {
            return self::withPort($cfg['db_migrate']);
        }
        return self::withPort($cfg['db']);
    }

    /**
     * @param array<string, mixed> $db
     * @return array<string, mixed>
     */
    private static function withPort(array $db): array
    {
        if (!isset($db['port'])) {
            $db['port'] = 3306;
        }
        return $db;
    }

    /** @return array<string, mixed> */
    public static function all(): array
    {
        return self::load();
    }

    /**
     * Read one configured value, with a typed default.
     *
     * @param mixed $default
     * @return mixed
     */
    public static function get(string $key, $default = null)
    {
        $cfg = self::load();
        $node = $cfg;
        foreach (explode('.', $key) as $part) {
            if (!is_array($node) || !array_key_exists($part, $node)) {
                return $default;
            }
            $node = $node[$part];
        }
        return $node;
    }
}
