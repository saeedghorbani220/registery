<?php
/**
 * Finance.php — append-only, concurrency-safe customer ledger writes.
 *
 * Ledger entries are special: optimistic CAS is correct for editable records,
 * but an append from two desktops must preserve BOTH entries. This service
 * therefore serializes only the sequence allocation for one customer with a
 * short SELECT ... FOR UPDATE, while operation_id provides retry idempotency.
 *
 * Money is always integer Toman. No float or numeric-string coercion is
 * accepted at this boundary.
 */

declare(strict_types=1);

final class Finance
{
    public function __construct(
        private readonly \Database $db,
        private readonly Log $log,
        private readonly array $cfg
    ) {
    }

    /**
     * Append exactly one ledger entry.
     *
     * @param array<string, mixed> $body
     * @param array{device: ?Principal, user: ?Principal, role: string} $context
     * @return array<string, mixed>
     * @throws ApiException
     */
    public function append(array $body, array $context, string $requestId): array
    {
        $tenantId = $this->tenantId($context);
        $role = (string) ($context['role'] ?? '');
        Roles::requireWrite($role, 'customer_transactions', 'upsert');

        $operationId = $body['operation_id'] ?? null;
        $customerId = $body['customer_id'] ?? null;
        $amount = $body['amount'] ?? null;
        $note = $body['note'] ?? '';
        $kind = $body['kind'] ?? '';
        $image = $body['image'] ?? '';
        $deviceId = $body['device_id'] ?? null;

        if (!is_string($operationId) || !Ids::isUuid($operationId)) {
            throw new ApiException(400, Codes::BAD_PAYLOAD,
                'operation_id must be a UUID');
        }
        if (!is_string($customerId) || !Ids::isUuid($customerId)) {
            throw new ApiException(400, Codes::BAD_PAYLOAD,
                'customer_id must be a UUID');
        }
        if (is_bool($amount) || !is_int($amount)) {
            throw new ApiException(400, Codes::VALIDATION_FAILED,
                'amount must be an integer number of Toman');
        }
        if (!is_string($note) || strlen($note) > 1000
            || !is_string($kind) || strlen($kind) > 32
            || !is_string($image) || strlen($image) > 64) {
            throw new ApiException(400, Codes::VALIDATION_FAILED,
                'ledger text fields exceed their accepted shape');
        }
        if ($deviceId === '') {
            $deviceId = null;
        }
        if ($deviceId !== null
            && (!is_string($deviceId) || !Ids::isUuid($deviceId))) {
            throw new ApiException(400, Codes::VALIDATION_FAILED,
                'device_id must be a UUID or null');
        }

        $normalized = [
            'customer_id' => $customerId,
            'amount' => $amount,
            'note' => trim($note),
            'kind' => trim($kind),
            'image' => trim($image),
            'device_id' => $deviceId,
        ];
        $requestHash = hash('sha256', json_encode(
            $normalized,
            JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
        ) ?: '');

        $result = $this->db->transaction(function (\Database $tx) use (
            $tenantId, $operationId, $requestHash, $normalized, $context
        ): array {
            $now = gmdate('Y-m-d H:i:s');
            $days = (int) ($this->cfg['idempotency_retention_days'] ?? 30);
            if ($days < 1) {
                $days = 30;
            }

            // Claim the operation before touching money. ON DUPLICATE KEY is
            // deliberate: a concurrent retry blocks on this primary key until
            // the first transaction commits, then reads the stored response.
            $tx->execute(
                'INSERT INTO idempotency_keys '
                . '(operation_id, tenant_id, request_hash, status, response, '
                . 'created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?) '
                . 'ON DUPLICATE KEY UPDATE operation_id = operation_id',
                [
                    $operationId, $tenantId, $requestHash, 'rejected', '{}',
                    $now, gmdate('Y-m-d H:i:s', time() + $days * 86400),
                ]
            );
            $claim = $tx->queryOne(
                'SELECT tenant_id, request_hash, status, response '
                . 'FROM idempotency_keys WHERE operation_id = ? FOR UPDATE',
                [$operationId]
            );
            if ($claim === null) {
                throw new ApiException(500, Codes::SERVER_ERROR,
                    'idempotency claim disappeared');
            }
            if ((string) $claim['tenant_id'] !== $tenantId
                || (string) ($claim['request_hash'] ?? '') !== $requestHash) {
                throw new ApiException(409, Codes::IDEMPOTENCY_MISMATCH,
                    'operation_id was already used for a different request');
            }
            $stored = json_decode((string) $claim['response'], true);
            if (($claim['status'] ?? '') === 'applied'
                && is_array($stored) && isset($stored['transaction'])) {
                return $stored;
            }

            // This row is the per-customer serialization point. It does not
            // lock operator editing; it only makes sequence allocation atomic.
            $customer = $tx->queryOne(
                'SELECT id, legacy_id FROM customers '
                . 'WHERE id = ? AND tenant_id = ? AND deleted_at IS NULL '
                . 'FOR UPDATE',
                [$normalized['customer_id'], $tenantId]
            );
            if ($customer === null) {
                throw new ApiException(404, Codes::NOT_FOUND,
                    'no such customer in this tenant');
            }
            $customerLegacy = $customer['legacy_id'] ?? null;
            if (!is_string($customerLegacy) || $customerLegacy === '') {
                throw new ApiException(409, Codes::VERSION_CONFLICT,
                    'customer has no stable legacy identity');
            }

            if ($normalized['device_id'] !== null) {
                $device = $tx->queryOne(
                    'SELECT id FROM crm_devices WHERE id = ? AND tenant_id = ? '
                    . 'AND deleted_at IS NULL',
                    [$normalized['device_id'], $tenantId]
                );
                if ($device === null) {
                    throw new ApiException(404, Codes::NOT_FOUND,
                        'no such case in this tenant');
                }
            }

            $nextSeq = (int) ($tx->queryValue(
                'SELECT MAX(seq) FROM customer_transactions '
                . 'WHERE tenant_id = ? AND customer_id = ? AND deleted_at IS NULL',
                [$tenantId, $normalized['customer_id']]
            ) ?? -1) + 1;
            $legacyId = Ids::transactionLegacyId($customerLegacy, $nextSeq);
            $sourceInstallationId = $tx->queryValue(
                'SELECT source_installation_id FROM tenant_state '
                . 'WHERE tenant_id = ?',
                [$tenantId]
            );
            if (!is_string($sourceInstallationId)
                || !Ids::isUuid($sourceInstallationId)) {
                throw new ApiException(409, Codes::VERSION_CONFLICT,
                    'dataset authority has no source installation identity');
            }
            // Keep the row id compatible with mapper._minted_id(). The
            // operation id is only the idempotency key; the record id remains
            // uuid5(source installation, customer legacy id / server seq).
            $transactionId = Ids::uuid5(
                $sourceInstallationId, 'customer_transactions', $legacyId
            );

            $tx->insert('customer_transactions', [
                'id' => $transactionId,
                'tenant_id' => $tenantId,
                'legacy_id' => $legacyId,
                'row_version' => 1,
                'created_at' => $now,
                'updated_at' => $now,
                'deleted_at' => null,
                'deleted_by' => null,
                'seq' => $nextSeq,
                'customer_id' => $normalized['customer_id'],
                'at' => $now,
                'amount' => $normalized['amount'],
                'note' => $normalized['note'],
                'kind' => $normalized['kind'],
                'image' => $normalized['image'],
                'device_id' => $normalized['device_id'],
                'voided_at' => null,
                'void_reason' => '',
            ]);

            $actorUserId = $this->actorUserId($context);
            $actorDeviceId = $this->actorDeviceId($context);
            $tx->insert('change_log', [
                'tenant_id' => $tenantId,
                'entity' => 'customer_transactions',
                'id' => $transactionId,
                'row_version' => 1,
                'action' => 'upsert',
                'actor_type' => $actorDeviceId !== null ? 'device' : 'user',
                'actor_user_id' => $actorUserId,
                'actor_device_id' => $actorDeviceId,
                'operation_id' => $operationId,
                'changed_at' => $now,
            ]);
            $cursor = (int) $tx->queryValue('SELECT LAST_INSERT_ID()');

            $wireAt = Schema::toWireTimestamp($now);
            $response = [
                'transaction' => [
                    'id' => $transactionId,
                    'tenant_id' => $tenantId,
                    'row_version' => 1,
                    'record' => [
                        'seq' => $nextSeq,
                        'customer_id' => $normalized['customer_id'],
                        'at' => $wireAt,
                        'amount' => $normalized['amount'],
                        'note' => $normalized['note'],
                        'kind' => $normalized['kind'],
                        'image' => $normalized['image'],
                        'device_id' => $normalized['device_id'],
                        'voided_at' => null,
                        'void_reason' => '',
                    ],
                ],
                'cursor' => $cursor,
            ];
            $encoded = json_encode($response,
                JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
            if (!is_string($encoded)) {
                throw new ApiException(500, Codes::SERVER_ERROR,
                    'ledger response could not be encoded');
            }
            $tx->update('idempotency_keys', [
                'status' => 'applied',
                'response' => $encoded,
            ], 'operation_id = ?', [$operationId]);
            return $response;
        });

        $this->log->line([
            'request_id' => $requestId,
            'action' => 'finance.append',
            'outcome' => 'ok',
            'entity' => 'customer_transactions',
        ]);
        return $result;
    }

    /** @param array{device: ?Principal, user: ?Principal, role: string} $context */
    private function tenantId(array $context): string
    {
        $device = $context['device'] ?? null;
        $user = $context['user'] ?? null;
        $tenantId = $device instanceof Principal ? $device->tenantId
            : ($user instanceof Principal ? $user->tenantId : '');
        if ($tenantId === '' || !Ids::isUuid($tenantId)) {
            throw new ApiException(401, Codes::AUTH_REQUIRED,
                'authenticated tenant context is required');
        }
        if ($device instanceof Principal && $user instanceof Principal
            && $device->tenantId !== $user->tenantId) {
            throw new ApiException(403, Codes::PERMISSION_DENIED,
                'acting user does not belong to the device tenant');
        }
        return $tenantId;
    }

    /** @param array{device: ?Principal, user: ?Principal, role: string} $context */
    private function actorUserId(array $context): ?string
    {
        $user = $context['user'] ?? null;
        if ($user instanceof Principal && $user->userId !== '') {
            return $user->userId;
        }
        $device = $context['device'] ?? null;
        return $device instanceof Principal && $device->userId !== ''
            ? $device->userId : null;
    }

    /** @param array{device: ?Principal, user: ?Principal, role: string} $context */
    private function actorDeviceId(array $context): ?string
    {
        $device = $context['device'] ?? null;
        return $device instanceof Principal && $device->deviceId !== ''
            ? $device->deviceId : null;
    }
}
