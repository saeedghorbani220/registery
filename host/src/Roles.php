<?php
/**
 * Roles.php — the server CRM authorization matrix, in one place.
 *
 *   capability                                   admin   user
 *   read all synced data                          yes     yes
 *   create/edit cases, transactions, owners,
 *     identities, stages                          yes     yes
 *   open/close periods, delete records            yes      no
 *   settings read                                 yes     yes
 *   settings write                                yes      no
 *   self-enrol a desktop device                    yes     yes
 *   admin enrol/manage other users/devices         yes      no
 *   run import                                     yes      no
 *
 * There are exactly two roles and no row-owner concept for CRM business data.
 * Device ownership is different: a user may enrol a device for their own
 * account, while management of somebody else's device remains an admin task.
 * A capability that is not listed here is denied.
 */

declare(strict_types=1);

final class Roles
{
    public const ADMIN = 'admin';
    public const USER = 'user';

    /** The only roles the membership column may hold (mirrors the SQL CHECK). */
    public const ALL = [self::ADMIN, self::USER];

    /**
     * May this role write `entity` with `kind`?
     *
     * Reads are not gated here: every authenticated principal may read the
     * synced dataset.
     */
    public static function canWrite(string $role, string $entity, string $kind): bool
    {
        if (!self::isKnown($role)) {
            return false;
        }
        if ($kind === 'delete') {
            return $role === self::ADMIN;
        }
        if ($entity === 'settings' || $entity === 'periods') {
            return $role === self::ADMIN;
        }
        return $kind === 'upsert';
    }

    /** Historical/admin enrol endpoint: remains admin-only for compatibility. */
    public static function canEnroll(string $role): bool
    {
        return $role === self::ADMIN;
    }

    /** A logged-in CRM user may enrol the machine for their own account. */
    public static function canSelfEnroll(string $role): bool
    {
        return self::isKnown($role);
    }

    /** Running bootstrap/legacy import remains admin-only. */
    public static function canImport(string $role): bool
    {
        return $role === self::ADMIN;
    }

    /** Reading the synced dataset: both roles. */
    public static function canRead(string $role): bool
    {
        return self::isKnown($role);
    }

    public static function isKnown(string $role): bool
    {
        return in_array($role, self::ALL, true);
    }

    /**
     * Assert a write capability or fail closed with 403 ROLE_FORBIDDEN.
     *
     * The message names the operation, never the record: a role refusal must
     * not become a probe for what exists.
     *
     * @throws ApiException
     */
    public static function requireWrite(string $role, string $entity,
                                        string $kind): void
    {
        if (!self::canWrite($role, $entity, $kind)) {
            throw new ApiException(403, Codes::ROLE_FORBIDDEN,
                'the acting role may not ' . $kind . ' ' . $entity
                . ' records');
        }
    }

    /** @throws ApiException */
    public static function requireEnroll(string $role): void
    {
        if (!self::canEnroll($role)) {
            throw new ApiException(403, Codes::ROLE_FORBIDDEN,
                'the acting role may not enrol devices');
        }
    }

    /** @throws ApiException */
    public static function requireSelfEnroll(string $role): void
    {
        if (!self::canSelfEnroll($role)) {
            throw new ApiException(403, Codes::ROLE_FORBIDDEN,
                'the acting role may not self-enrol a device');
        }
    }

    /** @throws ApiException */
    public static function requireImport(string $role): void
    {
        if (!self::canImport($role)) {
            throw new ApiException(403, Codes::ROLE_FORBIDDEN,
                'the acting role may not run an import');
        }
    }

    /** @throws ApiException */
    public static function requireAdmin(string $role): void
    {
        if ($role !== self::ADMIN) {
            throw new ApiException(403, Codes::ROLE_FORBIDDEN,
                'the acting role must be an administrator');
        }
    }
}
