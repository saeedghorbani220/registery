<?php
/**
 * Presence.php — advisory record-presence heartbeats for concurrent operators.
 *
 * Presence is deliberately NOT a lock. Multiple devices may heartbeat the same
 * record at the same time; optimistic row_version conflict handling remains the
 * write authority. Rows are short-lived and contain only internal identifiers.
 */

declare(strict_types=1);

final class Presence
{
    private const TTL_SECONDS = 45;

    public function __construct(
        private readonly Database $db,
        private readonly Log $log
    ) {
    }

    /**
     * @param array<string, mixed> $body
     * @return array<string, mixed>
     */
    public function heartbeat(Principal $device, Principal $user, array $body,
                              string $requestId): array
    {
        $this->assertContext($device, $user);
        $entity = isset($body['entity']) && is_string($body['entity'])
            ? trim($body['entity']) : '';
        $entityId = isset($body['entity_id']) && is_string($body['entity_id'])
            ? trim($body['entity_id']) : '';
        if ($entity === '' || Schema::tableForEntity($entity) === null) {
            throw new ApiException(400, Codes::BAD_PAYLOAD,
                'entity must name a synced entity');
        }
        if (!Ids::isUuid($entityId)) {
            throw new ApiException(400, Codes::BAD_PAYLOAD,
                'entity_id must be a UUID');
        }

        $nowEpoch = time();
        $now = gmdate('Y-m-d H:i:s', $nowEpoch);
        $expires = gmdate('Y-m-d H:i:s', $nowEpoch + self::TTL_SECONDS);

        // Expiry is the cleanup mechanism. It also makes a crashed desktop
        // disappear without requiring a close request to have reached us.
        $this->db->execute(
            'DELETE FROM record_presence WHERE expires_at <= ?', [$now]
        );

        // A duplicate PK is the same enrolled PC reopening/refreshing the same
        // record. Keep its original lease id/opened_at; refresh only identity
        // and heartbeat timestamps. This never excludes a different device.
        $candidateLease = Ids::v4();
        $this->db->execute(
            'INSERT INTO record_presence '
            . '(tenant_id,entity,entity_id,user_id,sync_device_id,lease_id,'
            . 'opened_at,heartbeat_at,expires_at) VALUES (?,?,?,?,?,?,?,?,?) '
            . 'ON DUPLICATE KEY UPDATE user_id=VALUES(user_id), '
            . 'heartbeat_at=VALUES(heartbeat_at), expires_at=VALUES(expires_at)',
            [
                $device->tenantId, $entity, $entityId, $user->userId,
                $device->deviceId, $candidateLease, $now, $now, $expires,
            ]
        );

        $self = $this->db->queryOne(
            'SELECT lease_id,opened_at,heartbeat_at,expires_at '
            . 'FROM record_presence WHERE tenant_id=? AND entity=? '
            . 'AND entity_id=? AND sync_device_id=?',
            [$device->tenantId, $entity, $entityId, $device->deviceId]
        );
        if ($self === null) {
            throw new ApiException(500, Codes::DB_UNAVAILABLE,
                'presence heartbeat was not persisted');
        }

        $peers = $this->db->query(
            'SELECT rp.user_id,rp.sync_device_id,rp.heartbeat_at,rp.expires_at,'
            . "COALESCE(NULLIF(u.display_name,''),u.username,'') AS display_name "
            . 'FROM record_presence rp LEFT JOIN users u '
            . 'ON u.id=rp.user_id AND u.tenant_id=rp.tenant_id '
            . 'WHERE rp.tenant_id=? AND rp.entity=? AND rp.entity_id=? '
            . 'AND rp.expires_at>? AND rp.sync_device_id<>? '
            . 'ORDER BY rp.heartbeat_at DESC',
            [$device->tenantId, $entity, $entityId, $now, $device->deviceId]
        );

        $this->log->line([
            'request_id' => $requestId,
            'tenant_id' => $device->tenantId,
            'user_id' => $user->userId,
            'device_id' => $device->deviceId,
            'entity' => $entity,
            'action' => 'presence.heartbeat',
            'outcome' => 'ok',
            'count' => count($peers),
        ]);

        return [
            'lease_id' => (string) $self['lease_id'],
            'opened_at' => (string) $self['opened_at'],
            'heartbeat_at' => (string) $self['heartbeat_at'],
            'expires_at' => (string) $self['expires_at'],
            'ttl_seconds' => self::TTL_SECONDS,
            'peers' => array_map(static function (array $row): array {
                return [
                    'user_id' => (string) $row['user_id'],
                    'sync_device_id' => (string) $row['sync_device_id'],
                    'display_name' => (string) $row['display_name'],
                    'heartbeat_at' => (string) $row['heartbeat_at'],
                    'expires_at' => (string) $row['expires_at'],
                ];
            }, $peers),
            'advisory' => true,
        ];
    }

    /**
     * @param array<string, mixed> $body
     * @return array<string, mixed>
     */
    public function close(Principal $device, Principal $user, array $body,
                          string $requestId): array
    {
        $this->assertContext($device, $user);
        $leaseId = isset($body['lease_id']) && is_string($body['lease_id'])
            ? trim($body['lease_id']) : '';
        if (!Ids::isUuid($leaseId)) {
            throw new ApiException(400, Codes::BAD_PAYLOAD,
                'lease_id must be a UUID');
        }
        $affected = $this->db->execute(
            'DELETE FROM record_presence WHERE tenant_id=? AND lease_id=? '
            . 'AND sync_device_id=? AND user_id=?',
            [$device->tenantId, $leaseId, $device->deviceId, $user->userId]
        );
        $this->log->line([
            'request_id' => $requestId,
            'tenant_id' => $device->tenantId,
            'user_id' => $user->userId,
            'device_id' => $device->deviceId,
            'action' => 'presence.close',
            'outcome' => $affected > 0 ? 'ok' : 'noop',
        ]);
        return ['closed' => $affected > 0, 'advisory' => true];
    }

    private function assertContext(Principal $device, Principal $user): void
    {
        if (!$device->isDevice() || !$user->isUser()) {
            throw new ApiException(401, Codes::AUTH_REQUIRED,
                'device and acting user credentials are required');
        }
        if ($device->tenantId === '' || $device->tenantId !== $user->tenantId
            || $device->deviceId === '' || $user->userId === '') {
            throw new ApiException(403, Codes::PERMISSION_DENIED,
                'presence principals must belong to the same tenant');
        }
    }
}
