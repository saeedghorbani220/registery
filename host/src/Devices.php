<?php
/**
 * Devices.php — user-owned desktop enrolment and revocation for server CRM v2.
 *
 * Device credentials remain independent refresh-token families. A user may
 * enrol and revoke their own machines; an administrator may revoke another
 * user's machine(s). CRM business rows themselves have no row-owner model.
 *
 * Security properties:
 *   * self-enrolment writes enrolled_by in the same SQL transaction that
 *     creates the first device refresh session; migration 003 mirrors that
 *     value into owner_user_id before the INSERT completes;
 *   * revocation changes the device status, bumps token_version and revokes
 *     every refresh family for that device before the transaction commits;
 *   * a non-admin querying somebody else's device receives 404, not an
 *     ownership oracle;
 *   * logs contain stable ids and counts only — never names or credentials.
 */

declare(strict_types=1);

final class Devices
{
    /** @param array<string, mixed> $cfg */
    public function __construct(
        private readonly Database $db,
        private readonly Log $log,
        private readonly array $cfg
    ) {
    }

    /**
     * Enrol one machine for the currently authenticated user.
     *
     * @param array<string, mixed> $body
     * @return array<string, mixed>
     * @throws ApiException
     */
    public function selfEnroll(Principal $principal, array $body,
                               string $requestId, string $ip): array
    {
        if (!$principal->isUser()) {
            throw new ApiException(401, Codes::AUTH_REQUIRED,
                'a user access token is required to enrol a device');
        }
        Roles::requireSelfEnroll($principal->role);

        $name = isset($body['name']) && is_string($body['name'])
            ? substr(trim($body['name']), 0, 120) : '';
        if ($name === '') {
            $name = 'device-' . substr(Ids::v4(), 0, 8);
        }

        $deviceId = Ids::v4();
        $familyId = Ids::v4();
        $refreshToken = Tokens::newOpaque();
        $now = gmdate('Y-m-d H:i:s');
        $nowEpoch = time();
        [$idle, $absolute] = $this->deviceRefreshWindow();

        $this->db->transaction(function (Database $tx) use (
            $principal, $deviceId, $familyId, $refreshToken, $name,
            $now, $nowEpoch, $idle, $absolute
        ): void {
            // Database::insert remains constrained by Schema.php. Migration
            // 003's BEFORE INSERT trigger copies enrolled_by to owner_user_id
            // within this exact transaction before the row becomes visible.
            $tx->insert('sync_devices', [
                'id' => $deviceId,
                'tenant_id' => $principal->tenantId,
                'name' => $name,
                'status' => 'active',
                'token_version' => 1,
                'created_at' => $now,
                'updated_at' => $now,
                'enrolled_by' => $principal->userId,
            ]);
            $tx->insert('auth_sessions', [
                'id' => Ids::v4(),
                'tenant_id' => $principal->tenantId,
                'family_id' => $familyId,
                'kind' => Tokens::KIND_DEVICE,
                'token_hash' => Tokens::hashOpaque($refreshToken),
                'user_id' => null,
                'sync_device_id' => $deviceId,
                'parent_id' => null,
                'issued_at' => $now,
                'idle_expires_at' => gmdate('Y-m-d H:i:s', $nowEpoch + $idle),
                'absolute_expires_at' => gmdate(
                    'Y-m-d H:i:s', $nowEpoch + $absolute
                ),
                'used_at' => null,
                'revoked_at' => null,
                'revoked_reason' => '',
                'rotated_to' => null,
                'created_at' => $now,
            ]);
        });

        $this->log->line([
            'request_id' => $requestId,
            'action' => 'device.self_enroll',
            'outcome' => 'success',
            'tenant_id' => $principal->tenantId,
            'user_id' => $principal->userId,
            'device_id' => $deviceId,
        ]);
        $this->log->audit($this->db, [
            'tenant_id' => $principal->tenantId,
            'action' => 'device.self_enroll',
            'actor_type' => 'user',
            'actor_user_id' => $principal->userId,
            'actor_device_id' => null,
            'entity' => 'sync_devices',
            'entity_id' => $deviceId,
            'request_id' => $requestId,
            'ip' => $ip,
            'outcome' => 'ok',
        ]);

        return [
            'sync_device_id' => $deviceId,
            'device_refresh_token' => $refreshToken,
            'tenant_id' => $principal->tenantId,
        ];
    }

    /**
     * Revoke exactly one device. Users may revoke only their own; admins may
     * revoke any device in the tenant.
     *
     * @return array<string, mixed>
     * @throws ApiException
     */
    public function revoke(Principal $principal, string $deviceId,
                           string $requestId, string $ip): array
    {
        $this->requireUser($principal);
        if (!Ids::isUuid($deviceId)) {
            throw new ApiException(400, Codes::BAD_PAYLOAD,
                'sync_device_id must be a UUID');
        }
        $now = gmdate('Y-m-d H:i:s');

        $wasChanged = $this->db->transaction(function (Database $tx) use (
            $principal, $deviceId, $now
        ): bool {
            $row = $tx->queryOne(
                'SELECT id, owner_user_id, enrolled_by, status FROM sync_devices'
                . ' WHERE id = ? AND tenant_id = ? AND deleted_at IS NULL'
                . ' FOR UPDATE',
                [$deviceId, $principal->tenantId]
            );
            if ($row === null) {
                throw new ApiException(404, Codes::NOT_FOUND,
                    'device was not found');
            }
            $owner = $row['owner_user_id'] ?? $row['enrolled_by'] ?? null;
            if ($principal->role !== Roles::ADMIN
                && $owner !== $principal->userId) {
                // Do not disclose whether another user's device exists.
                throw new ApiException(404, Codes::NOT_FOUND,
                    'device was not found');
            }

            $changed = 0;
            if (($row['status'] ?? '') !== 'revoked') {
                $changed = $tx->execute(
                    'UPDATE sync_devices SET status = ?, token_version = '
                    . 'token_version + 1, updated_at = ?'
                    . ' WHERE id = ? AND tenant_id = ?',
                    ['revoked', $now, $deviceId, $principal->tenantId]
                );
            }
            $tx->execute(
                'UPDATE auth_sessions SET revoked_at = ?, revoked_reason = ?'
                . ' WHERE tenant_id = ? AND sync_device_id = ?'
                . ' AND kind = ? AND revoked_at IS NULL',
                [$now, 'device_revoked', $principal->tenantId, $deviceId,
                 Tokens::KIND_DEVICE]
            );
            return $changed > 0;
        });

        $this->auditRevocation(
            $principal, $requestId, $ip, 'device.revoke', $deviceId,
            $wasChanged ? 'revoked' : 'already_revoked'
        );
        return [
            'sync_device_id' => $deviceId,
            'revoked' => true,
            'changed' => $wasChanged,
        ];
    }

    /**
     * Revoke all devices owned by one user. A normal user can target only
     * themselves; an admin may supply another tenant user id.
     *
     * @return array<string, mixed>
     * @throws ApiException
     */
    public function revokeAll(Principal $principal, ?string $targetUserId,
                              string $requestId, string $ip): array
    {
        $this->requireUser($principal);
        $target = $targetUserId === null || trim($targetUserId) === ''
            ? $principal->userId : trim($targetUserId);
        if (!Ids::isUuid($target)) {
            throw new ApiException(400, Codes::BAD_PAYLOAD,
                'user_id must be a UUID');
        }
        if ($target !== $principal->userId
            && $principal->role !== Roles::ADMIN) {
            throw new ApiException(403, Codes::ROLE_FORBIDDEN,
                'the acting role may not revoke another user devices');
        }

        $exists = $this->db->queryValue(
            'SELECT id FROM users WHERE id = ? AND tenant_id = ? LIMIT 1',
            [$target, $principal->tenantId]
        );
        if (!is_string($exists) || $exists === '') {
            throw new ApiException(404, Codes::NOT_FOUND,
                'user was not found');
        }

        $now = gmdate('Y-m-d H:i:s');
        $result = $this->db->transaction(function (Database $tx) use (
            $principal, $target, $now
        ): array {
            $matched = (int) ($tx->queryValue(
                'SELECT COUNT(*) FROM sync_devices WHERE tenant_id = ?'
                . ' AND COALESCE(owner_user_id, enrolled_by) = ?'
                . ' AND deleted_at IS NULL',
                [$principal->tenantId, $target]
            ) ?? 0);
            $changed = $tx->execute(
                'UPDATE sync_devices SET status = ?, token_version = '
                . 'token_version + 1, updated_at = ?'
                . ' WHERE tenant_id = ?'
                . ' AND COALESCE(owner_user_id, enrolled_by) = ?'
                . ' AND deleted_at IS NULL AND status <> ?',
                ['revoked', $now, $principal->tenantId, $target, 'revoked']
            );
            $tx->execute(
                'UPDATE auth_sessions SET revoked_at = ?, revoked_reason = ?'
                . ' WHERE tenant_id = ? AND kind = ? AND revoked_at IS NULL'
                . ' AND sync_device_id IN ('
                . 'SELECT id FROM sync_devices WHERE tenant_id = ?'
                . ' AND COALESCE(owner_user_id, enrolled_by) = ?'
                . ' AND deleted_at IS NULL)',
                [$now, 'user_devices_revoked', $principal->tenantId,
                 Tokens::KIND_DEVICE, $principal->tenantId, $target]
            );
            return ['matched' => $matched, 'changed' => $changed];
        });

        $this->auditRevocation(
            $principal, $requestId, $ip, 'device.revoke_all', null, 'revoked',
            ['target_user_id' => $target, 'matched' => $result['matched'],
             'changed' => $result['changed']]
        );
        return [
            'user_id' => $target,
            'matched_devices' => $result['matched'],
            'revoked_devices' => $result['changed'],
        ];
    }

    /** @return array{0:int,1:int} */
    private function deviceRefreshWindow(): array
    {
        $refresh = is_array($this->cfg['refresh'] ?? null)
            ? $this->cfg['refresh'] : [];
        $idle = isset($refresh['device_idle_seconds'])
            && is_int($refresh['device_idle_seconds'])
            && $refresh['device_idle_seconds'] > 0
            ? $refresh['device_idle_seconds'] : 7776000;
        $absolute = isset($refresh['device_absolute_seconds'])
            && is_int($refresh['device_absolute_seconds'])
            && $refresh['device_absolute_seconds'] > 0
            ? $refresh['device_absolute_seconds'] : 31536000;
        return [$idle, max($idle, $absolute)];
    }

    /** @throws ApiException */
    private function requireUser(Principal $principal): void
    {
        if (!$principal->isUser()) {
            throw new ApiException(401, Codes::AUTH_REQUIRED,
                'a user access token is required for device management');
        }
        if (!Roles::isKnown($principal->role)) {
            throw new ApiException(403, Codes::ROLE_FORBIDDEN,
                'the acting role may not manage devices');
        }
    }

    /** @param array<string, mixed> $metadata */
    private function auditRevocation(Principal $principal, string $requestId,
                                     string $ip, string $action,
                                     ?string $deviceId, string $outcome,
                                     array $metadata = []): void
    {
        $line = [
            'request_id' => $requestId,
            'action' => $action,
            'outcome' => $outcome,
            'tenant_id' => $principal->tenantId,
            'user_id' => $principal->userId,
        ];
        if ($deviceId !== null) {
            $line['device_id'] = $deviceId;
        }
        if (isset($metadata['matched'])) {
            $line['matched'] = (int) $metadata['matched'];
            $line['changed'] = (int) ($metadata['changed'] ?? 0);
        }
        $this->log->line($line);

        $audit = [
            'tenant_id' => $principal->tenantId,
            'action' => $action,
            'actor_type' => 'user',
            'actor_user_id' => $principal->userId,
            'actor_device_id' => null,
            'entity' => 'sync_devices',
            'entity_id' => $deviceId,
            'request_id' => $requestId,
            'ip' => $ip,
            'outcome' => $outcome,
        ];
        if ($metadata !== []) {
            $audit['metadata'] = $metadata;
        }
        $this->log->audit($this->db, $audit);
    }
}
