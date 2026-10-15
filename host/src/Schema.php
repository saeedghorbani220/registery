<?php
/**
 * Schema.php — the machine-readable contract for the IRICA cloud-sync host.
 *
 * One declared structure, from which everything else is derived: table list,
 * column list, column type, nullability, SQL default, enum, reference target
 * and the spec §3 settings allowlist. There is no second copy of any of it, so
 * `tables()`, `columnsFor()` and `validate()` cannot drift from each other —
 * and lab/tests/test_host_schema.py proves this file matches
 * information_schema exactly, which is what stops the PHP API and
 * host/migrations/001_initial.sql from diverging.
 *
 * Validation reports STRUCTURED failures, never prose: each failure is
 * `["code", "table", "column"]` with a stable `code` the HTTP layer maps to a
 * stable `error.code` (spec §6). The offending VALUE is deliberately absent —
 * echoing it back would leak PII into a response or a log (spec §10.9).
 *
 * Timestamps: every datetime column holds UTC ISO-8601 WITH an explicit
 * offset (spec §4). A naive `2026-10-05 10:00:00` is rejected — guessing
 * whether it meant Tehran or UTC would silently move a time.
 */

declare(strict_types=1);

final class Schema
{
    /** Spec §4: the envelope carried by every synced table, in order. */
    public const ENVELOPE = [
        'id', 'tenant_id', 'legacy_id', 'row_version',
        'created_at', 'updated_at', 'deleted_at', 'deleted_by',
    ];

    /** The envelope without `legacy_id` (users / sync_devices have no legacy). */
    public const ENVELOPE_PLAIN = [
        'id', 'tenant_id', 'row_version',
        'created_at', 'updated_at', 'deleted_at', 'deleted_by',
    ];

    // Stable failure codes (spec §6 — the client maps codes, not messages).
    public const E_UNKNOWN_TABLE   = 'UNKNOWN_TABLE';
    public const E_UNKNOWN_ENTITY  = 'UNKNOWN_ENTITY';
    public const E_UNKNOWN_COLUMN  = 'UNKNOWN_COLUMN';
    public const E_MISSING_COLUMN  = 'MISSING_COLUMN';
    public const E_NULL_NOT_ALLOWED = 'NULL_NOT_ALLOWED';
    public const E_TYPE_MISMATCH   = 'TYPE_MISMATCH';
    public const E_ENUM_MISMATCH   = 'ENUM_MISMATCH';
    public const E_TOO_LONG        = 'TOO_LONG';
    public const E_INVALID_TIMESTAMP = 'INVALID_TIMESTAMP';
    public const E_INVALID_UUID    = 'INVALID_UUID';
    public const E_INVALID_LEGACY_ID = 'INVALID_LEGACY_ID';
    public const E_INVALID_JSON    = 'INVALID_JSON';
    public const E_EMPTY_REFERENCE = 'EMPTY_REFERENCE';
    public const E_OUT_OF_RANGE    = 'OUT_OF_RANGE';

    /** @var array<string, array<string, mixed>>|null */
    private static ?array $schema = null;

    // ------------------------------------------------------------------
    // The one declared structure
    // ------------------------------------------------------------------

    /**
     * Column spec keys:
     *   sql      exact information_schema type, e.g. "varchar(80)"
     *   type     validation family: char|varchar|int|bigint|tinyint|datetime|
     *            text|mediumtext
     *   nullable whether SQL NULL is allowed
     *   default  SQL default as declared; null means "no default"
     *   enum     allowed values, or null
     *   format   uuid|timestamp|json|legacy_id, or null
     *   ref      "table.column" foreign key target, or null
     *   auto     true when the server generates the value (AUTO_INCREMENT)
     *
     * `required` is DERIVED (NOT NULL, no default, not auto-generated), never
     * declared, so it can never disagree with the SQL.
     *
     * @return array<string, array<string, mixed>>
     */
    private static function schema(): array
    {
        if (self::$schema !== null) {
            return self::$schema;
        }

        $envelope = [
            'id'          => ['sql' => 'char(36)', 'type' => 'char',
                              'nullable' => false, 'format' => 'uuid'],
            'tenant_id'   => ['sql' => 'char(36)', 'type' => 'char',
                              'nullable' => false, 'format' => 'uuid',
                              'ref' => 'tenants.id'],
            'legacy_id'   => ['sql' => 'varchar(64)', 'type' => 'varchar',
                              'nullable' => true, 'format' => 'legacy_id'],
            'row_version' => ['sql' => 'int', 'type' => 'int',
                              'nullable' => false, 'default' => 1],
            'created_at'  => ['sql' => 'datetime', 'type' => 'datetime',
                              'nullable' => false, 'format' => 'timestamp'],
            'updated_at'  => ['sql' => 'datetime', 'type' => 'datetime',
                              'nullable' => false, 'format' => 'timestamp'],
            'deleted_at'  => ['sql' => 'datetime', 'type' => 'datetime',
                              'nullable' => true, 'format' => 'timestamp'],
            'deleted_by'  => ['sql' => 'char(36)', 'type' => 'char',
                              'nullable' => true, 'format' => 'uuid',
                              'ref' => 'users.id'],
        ];

        $tables = [
            // ---- infrastructure -----------------------------------------
            'schema_migrations' => [
                'entity' => null, 'envelope' => 'none',
                'columns' => [
                    'version'     => ['sql' => 'varchar(64)', 'type' => 'varchar',
                                      'nullable' => false],
                    'description' => ['sql' => 'varchar(255)', 'type' => 'varchar',
                                      'nullable' => false, 'default' => ''],
                    'checksum'    => ['sql' => 'char(64)', 'type' => 'char',
                                      'nullable' => false],
                    'applied_at'  => ['sql' => 'datetime', 'type' => 'datetime',
                                      'nullable' => false, 'format' => 'timestamp'],
                    'applied_by'  => ['sql' => 'varchar(64)', 'type' => 'varchar',
                                      'nullable' => false, 'default' => ''],
                ],
            ],
            'tenants' => [
                'entity' => null, 'envelope' => 'none',
                'columns' => [
                    'id'         => ['sql' => 'char(36)', 'type' => 'char',
                                     'nullable' => false, 'format' => 'uuid'],
                    'slug'       => ['sql' => 'varchar(64)', 'type' => 'varchar',
                                     'nullable' => false],
                    'name'       => ['sql' => 'varchar(120)', 'type' => 'varchar',
                                     'nullable' => false, 'default' => ''],
                    'status'     => ['sql' => 'varchar(16)', 'type' => 'varchar',
                                     'nullable' => false, 'default' => 'active',
                                     'enum' => ['active', 'suspended']],
                    'created_at' => ['sql' => 'datetime', 'type' => 'datetime',
                                     'nullable' => false, 'format' => 'timestamp'],
                    'updated_at' => ['sql' => 'datetime', 'type' => 'datetime',
                                     'nullable' => false, 'format' => 'timestamp'],
                ],
            ],
            'users' => [
                'entity' => null, 'envelope' => 'plain',
                'columns' => [
                    'username'             => ['sql' => 'varchar(64)', 'type' => 'varchar',
                                                'nullable' => false],
                    'password_hash'        => ['sql' => 'varchar(255)', 'type' => 'varchar',
                                                'nullable' => false],
                    'display_name'         => ['sql' => 'varchar(120)', 'type' => 'varchar',
                                                'nullable' => false, 'default' => ''],
                    'must_change_password' => ['sql' => 'tinyint(1)', 'type' => 'tinyint',
                                                'nullable' => false, 'default' => 1,
                                                'enum' => [0, 1]],
                    'status'               => ['sql' => 'varchar(16)', 'type' => 'varchar',
                                                'nullable' => false, 'default' => 'active',
                                                'enum' => ['active', 'disabled']],
                    'token_version'        => ['sql' => 'int', 'type' => 'int',
                                                'nullable' => false, 'default' => 1],
                    'last_login_at'        => ['sql' => 'datetime', 'type' => 'datetime',
                                                'nullable' => true, 'format' => 'timestamp'],
                ],
            ],
            'memberships' => [
                'entity' => null, 'envelope' => 'none',
                'columns' => [
                    'id'         => ['sql' => 'char(36)', 'type' => 'char',
                                     'nullable' => false, 'format' => 'uuid'],
                    'tenant_id'  => ['sql' => 'char(36)', 'type' => 'char',
                                     'nullable' => false, 'format' => 'uuid',
                                     'ref' => 'tenants.id'],
                    'user_id'    => ['sql' => 'char(36)', 'type' => 'char',
                                     'nullable' => false, 'format' => 'uuid',
                                     'ref' => 'users.id'],
                    'role'       => ['sql' => 'varchar(16)', 'type' => 'varchar',
                                     'nullable' => false, 'enum' => ['admin', 'user']],
                    'created_at' => ['sql' => 'datetime', 'type' => 'datetime',
                                     'nullable' => false, 'format' => 'timestamp'],
                    'updated_at' => ['sql' => 'datetime', 'type' => 'datetime',
                                     'nullable' => false, 'format' => 'timestamp'],
                ],
            ],
            'sync_devices' => [
                'entity' => null, 'envelope' => 'plain',
                'columns' => [
                    'name'          => ['sql' => 'varchar(120)', 'type' => 'varchar',
                                        'nullable' => false, 'default' => ''],
                    'status'        => ['sql' => 'varchar(16)', 'type' => 'varchar',
                                        'nullable' => false, 'default' => 'active',
                                        'enum' => ['active', 'revoked']],
                    'token_version' => ['sql' => 'int', 'type' => 'int',
                                        'nullable' => false, 'default' => 1],
                    'last_auth_at'  => ['sql' => 'datetime', 'type' => 'datetime',
                                        'nullable' => true, 'format' => 'timestamp'],
                    'last_seen_at'  => ['sql' => 'datetime', 'type' => 'datetime',
                                        'nullable' => true, 'format' => 'timestamp'],
                    'enrolled_by'   => ['sql' => 'char(36)', 'type' => 'char',
                                        'nullable' => true, 'format' => 'uuid',
                                        'ref' => 'users.id'],
                ],
            ],
            'auth_sessions' => [
                'entity' => null, 'envelope' => 'none',
                'columns' => [
                    'id'                  => ['sql' => 'char(36)', 'type' => 'char',
                                              'nullable' => false, 'format' => 'uuid'],
                    'tenant_id'           => ['sql' => 'char(36)', 'type' => 'char',
                                              'nullable' => false, 'format' => 'uuid',
                                              'ref' => 'tenants.id'],
                    'family_id'           => ['sql' => 'char(36)', 'type' => 'char',
                                              'nullable' => false, 'format' => 'uuid'],
                    'kind'                => ['sql' => 'varchar(8)', 'type' => 'varchar',
                                              'nullable' => false,
                                              'enum' => ['user', 'device']],
                    'token_hash'          => ['sql' => 'char(64)', 'type' => 'char',
                                              'nullable' => false],
                    'user_id'             => ['sql' => 'char(36)', 'type' => 'char',
                                              'nullable' => true, 'format' => 'uuid',
                                              'ref' => 'users.id'],
                    'sync_device_id'      => ['sql' => 'char(36)', 'type' => 'char',
                                              'nullable' => true, 'format' => 'uuid',
                                              'ref' => 'sync_devices.id'],
                    'parent_id'           => ['sql' => 'char(36)', 'type' => 'char',
                                              'nullable' => true, 'format' => 'uuid',
                                              'ref' => 'auth_sessions.id'],
                    'issued_at'           => ['sql' => 'datetime', 'type' => 'datetime',
                                              'nullable' => false, 'format' => 'timestamp'],
                    'idle_expires_at'     => ['sql' => 'datetime', 'type' => 'datetime',
                                              'nullable' => false, 'format' => 'timestamp'],
                    'absolute_expires_at' => ['sql' => 'datetime', 'type' => 'datetime',
                                              'nullable' => false, 'format' => 'timestamp'],
                    'used_at'             => ['sql' => 'datetime', 'type' => 'datetime',
                                              'nullable' => true, 'format' => 'timestamp'],
                    'revoked_at'          => ['sql' => 'datetime', 'type' => 'datetime',
                                              'nullable' => true, 'format' => 'timestamp'],
                    'revoked_reason'      => ['sql' => 'varchar(64)', 'type' => 'varchar',
                                              'nullable' => false, 'default' => ''],
                    'rotated_to'          => ['sql' => 'char(36)', 'type' => 'char',
                                              'nullable' => true, 'format' => 'uuid',
                                              'ref' => 'auth_sessions.id'],
                    'created_at'          => ['sql' => 'datetime', 'type' => 'datetime',
                                              'nullable' => false, 'format' => 'timestamp'],
                ],
            ],
            'login_attempts' => [
                'entity' => null, 'envelope' => 'none',
                'columns' => [
                    'id'           => ['sql' => 'bigint', 'type' => 'bigint',
                                       'nullable' => false, 'auto' => true],
                    'tenant_id'    => ['sql' => 'char(36)', 'type' => 'char',
                                       'nullable' => true, 'format' => 'uuid',
                                       'ref' => 'tenants.id'],
                    'account'      => ['sql' => 'varchar(120)', 'type' => 'varchar',
                                       'nullable' => false],
                    'ip'           => ['sql' => 'varchar(45)', 'type' => 'varchar',
                                       'nullable' => false],
                    'attempted_at' => ['sql' => 'datetime', 'type' => 'datetime',
                                       'nullable' => false, 'format' => 'timestamp'],
                    'outcome'      => ['sql' => 'varchar(16)', 'type' => 'varchar',
                                       'nullable' => false,
                                       'enum' => ['success', 'failure', 'locked']],
                ],
            ],
            'audit_events' => [
                'entity' => null, 'envelope' => 'none',
                'columns' => [
                    'id'              => ['sql' => 'char(36)', 'type' => 'char',
                                          'nullable' => false, 'format' => 'uuid'],
                    'tenant_id'       => ['sql' => 'char(36)', 'type' => 'char',
                                          'nullable' => false, 'format' => 'uuid',
                                          'ref' => 'tenants.id'],
                    'occurred_at'     => ['sql' => 'datetime', 'type' => 'datetime',
                                          'nullable' => false, 'format' => 'timestamp'],
                    'action'          => ['sql' => 'varchar(64)', 'type' => 'varchar',
                                          'nullable' => false],
                    'actor_type'      => ['sql' => 'varchar(16)', 'type' => 'varchar',
                                          'nullable' => false, 'default' => 'system',
                                          'enum' => ['system', 'user', 'device']],
                    'actor_user_id'   => ['sql' => 'char(36)', 'type' => 'char',
                                          'nullable' => true, 'format' => 'uuid',
                                          'ref' => 'users.id'],
                    'actor_device_id' => ['sql' => 'char(36)', 'type' => 'char',
                                          'nullable' => true, 'format' => 'uuid',
                                          'ref' => 'sync_devices.id'],
                    'entity'          => ['sql' => 'varchar(64)', 'type' => 'varchar',
                                          'nullable' => false, 'default' => ''],
                    'entity_id'       => ['sql' => 'char(36)', 'type' => 'char',
                                          'nullable' => true, 'format' => 'uuid'],
                    'request_id'      => ['sql' => 'char(36)', 'type' => 'char',
                                          'nullable' => true, 'format' => 'uuid'],
                    'ip'              => ['sql' => 'varchar(45)', 'type' => 'varchar',
                                          'nullable' => true],
                    'outcome'         => ['sql' => 'varchar(16)', 'type' => 'varchar',
                                          'nullable' => false, 'default' => 'ok'],
                    'metadata'        => ['sql' => 'mediumtext', 'type' => 'mediumtext',
                                          'nullable' => true, 'format' => 'json'],
                ],
            ],
            'idempotency_keys' => [
                'entity' => null, 'envelope' => 'none',
                'columns' => [
                    'operation_id' => ['sql' => 'char(36)', 'type' => 'char',
                                       'nullable' => false, 'format' => 'uuid'],
                    'tenant_id'    => ['sql' => 'char(36)', 'type' => 'char',
                                       'nullable' => false, 'format' => 'uuid',
                                       'ref' => 'tenants.id'],
                    'request_hash' => ['sql' => 'char(64)', 'type' => 'char',
                                       'nullable' => true],
                    'status'       => ['sql' => 'varchar(16)', 'type' => 'varchar',
                                       'nullable' => false, 'default' => 'applied',
                                       'enum' => ['applied', 'conflict', 'rejected']],
                    'response'     => ['sql' => 'mediumtext', 'type' => 'mediumtext',
                                       'nullable' => false],
                    'created_at'   => ['sql' => 'datetime', 'type' => 'datetime',
                                       'nullable' => false, 'format' => 'timestamp'],
                    'expires_at'   => ['sql' => 'datetime', 'type' => 'datetime',
                                       'nullable' => false, 'format' => 'timestamp'],
                ],
            ],
            'change_log' => [
                'entity' => null, 'envelope' => 'none',
                'columns' => [
                    'seq'             => ['sql' => 'bigint', 'type' => 'bigint',
                                          'nullable' => false, 'auto' => true],
                    'tenant_id'       => ['sql' => 'char(36)', 'type' => 'char',
                                          'nullable' => false, 'format' => 'uuid',
                                          'ref' => 'tenants.id'],
                    'entity'          => ['sql' => 'varchar(64)', 'type' => 'varchar',
                                          'nullable' => false],
                    'id'              => ['sql' => 'char(36)', 'type' => 'char',
                                          'nullable' => false, 'format' => 'uuid'],
                    'row_version'     => ['sql' => 'int', 'type' => 'int',
                                          'nullable' => false],
                    'action'          => ['sql' => 'varchar(16)', 'type' => 'varchar',
                                          'nullable' => false, 'default' => 'upsert',
                                          'enum' => ['upsert', 'delete']],
                    'actor_type'      => ['sql' => 'varchar(16)', 'type' => 'varchar',
                                          'nullable' => false, 'default' => 'system',
                                          'enum' => ['system', 'user', 'device']],
                    'actor_user_id'   => ['sql' => 'char(36)', 'type' => 'char',
                                          'nullable' => true, 'format' => 'uuid',
                                          'ref' => 'users.id'],
                    'actor_device_id' => ['sql' => 'char(36)', 'type' => 'char',
                                          'nullable' => true, 'format' => 'uuid',
                                          'ref' => 'sync_devices.id'],
                    'operation_id'    => ['sql' => 'char(36)', 'type' => 'char',
                                          'nullable' => true, 'format' => 'uuid'],
                    'changed_at'      => ['sql' => 'datetime', 'type' => 'datetime',
                                          'nullable' => false, 'format' => 'timestamp'],
                ],
            ],
            'tenant_state' => [
                'entity' => null, 'envelope' => 'none',
                'columns' => [
                    'tenant_id'        => ['sql' => 'char(36)', 'type' => 'char',
                                           'nullable' => false, 'format' => 'uuid',
                                           'ref' => 'tenants.id'],
                    'bootstrap_status' => ['sql' => 'varchar(16)', 'type' => 'varchar',
                                           'nullable' => false, 'default' => 'pending',
                                           'enum' => ['pending', 'running', 'done']],
                    'dataset_epoch'    => ['sql' => 'int', 'type' => 'int',
                                           'nullable' => false, 'default' => 0],
                    'last_import_id'   => ['sql' => 'char(36)', 'type' => 'char',
                                           'nullable' => true, 'format' => 'uuid'],
                    'last_import_hash' => ['sql' => 'char(64)', 'type' => 'char',
                                           'nullable' => true],
                    'source_installation_id' => ['sql' => 'char(36)', 'type' => 'char',
                                           'nullable' => true, 'format' => 'uuid'],
                    'created_at'       => ['sql' => 'datetime', 'type' => 'datetime',
                                           'nullable' => false, 'format' => 'timestamp'],
                    'updated_at'       => ['sql' => 'datetime', 'type' => 'datetime',
                                           'nullable' => false, 'format' => 'timestamp'],
                ],
            ],

            // ---- business (spec §3) -------------------------------------
            'periods' => [
                'entity' => 'periods', 'envelope' => 'legacy',
                'columns' => [
                    'number'        => ['sql' => 'int', 'type' => 'int',
                                        'nullable' => false],
                    'label'         => ['sql' => 'varchar(120)', 'type' => 'varchar',
                                        'nullable' => false, 'default' => ''],
                    'opened_at'     => ['sql' => 'datetime', 'type' => 'datetime',
                                        'nullable' => false, 'format' => 'timestamp'],
                    'opened_by'     => ['sql' => 'varchar(64)', 'type' => 'varchar',
                                        'nullable' => false, 'default' => 'system'],
                    'closed_at'     => ['sql' => 'datetime', 'type' => 'datetime',
                                        'nullable' => true, 'format' => 'timestamp'],
                    'closed_by'     => ['sql' => 'varchar(64)', 'type' => 'varchar',
                                        'nullable' => false, 'default' => ''],
                    'closed_reason' => ['sql' => 'varchar(1000)', 'type' => 'varchar',
                                        'nullable' => false, 'default' => ''],
                ],
            ],
            'settings' => [
                'entity' => 'settings', 'envelope' => 'legacy',
                'columns' => [
                    'business_name'             => ['sql' => 'varchar(80)', 'type' => 'varchar',
                                                    'nullable' => false, 'default' => ''],
                    'business_phone'            => ['sql' => 'varchar(80)', 'type' => 'varchar',
                                                    'nullable' => false, 'default' => ''],
                    'watch_interval_hours'      => ['sql' => 'int', 'type' => 'int',
                                                    'nullable' => false, 'default' => 2,
                                                    'min' => 1, 'max' => 72],
                    'scheduler_enabled'         => ['sql' => 'tinyint(1)', 'type' => 'tinyint',
                                                    'nullable' => false, 'default' => 1,
                                                    'enum' => [0, 1]],
                    'auto_advance_default'      => ['sql' => 'tinyint(1)', 'type' => 'tinyint',
                                                    'nullable' => false, 'default' => 0,
                                                    'enum' => [0, 1]],
                    'telegram_report_full_data' => ['sql' => 'tinyint(1)', 'type' => 'tinyint',
                                                    'nullable' => false, 'default' => 1,
                                                    'enum' => [0, 1]],
                    'registry_fee_amount'       => ['sql' => 'bigint', 'type' => 'bigint',
                                                    'nullable' => false,
                                                    'default' => 24000000],
                    'registration_chat_id'      => ['sql' => 'varchar(32)', 'type' => 'varchar',
                                                    'nullable' => false, 'default' => ''],
                    'report_chat_id'            => ['sql' => 'varchar(32)', 'type' => 'varchar',
                                                    'nullable' => false, 'default' => ''],
                    'sound_enabled'             => ['sql' => 'tinyint(1)', 'type' => 'tinyint',
                                                    'nullable' => false, 'default' => 1,
                                                    'enum' => [0, 1]],
                    'current_period_id'         => ['sql' => 'char(36)', 'type' => 'char',
                                                    'nullable' => true, 'format' => 'uuid',
                                                    'ref' => 'periods.id'],
                    'links'                     => ['sql' => 'mediumtext', 'type' => 'mediumtext',
                                                    'nullable' => true, 'format' => 'json'],
                ],
            ],
            'customers' => [
                'entity' => 'customers', 'envelope' => 'legacy',
                'columns' => [
                    'full_name'    => ['sql' => 'varchar(80)', 'type' => 'varchar',
                                       'nullable' => false],
                    'address'      => ['sql' => 'varchar(300)', 'type' => 'varchar',
                                       'nullable' => false, 'default' => ''],
                    'mobile'       => ['sql' => 'varchar(11)', 'type' => 'varchar',
                                       'nullable' => false, 'default' => ''],
                    'telegram_id'  => ['sql' => 'varchar(64)', 'type' => 'varchar',
                                       'nullable' => false, 'default' => ''],
                    'instagram_id' => ['sql' => 'varchar(64)', 'type' => 'varchar',
                                       'nullable' => false, 'default' => ''],
                    'notes'        => ['sql' => 'varchar(500)', 'type' => 'varchar',
                                       'nullable' => false, 'default' => ''],
                    'created'      => ['sql' => 'datetime', 'type' => 'datetime',
                                       'nullable' => true, 'format' => 'timestamp'],
                    'updated'      => ['sql' => 'datetime', 'type' => 'datetime',
                                       'nullable' => true, 'format' => 'timestamp'],
                ],
            ],
            'owners' => [
                'entity' => 'owners', 'envelope' => 'legacy',
                'columns' => [
                    'first_name' => ['sql' => 'varchar(120)', 'type' => 'varchar',
                                     'nullable' => false],
                    'last_name'  => ['sql' => 'varchar(120)', 'type' => 'varchar',
                                     'nullable' => false],
                    'national'   => ['sql' => 'varchar(10)', 'type' => 'varchar',
                                     'nullable' => false],
                    'birth'      => ['sql' => 'varchar(10)', 'type' => 'varchar',
                                     'nullable' => false],
                    'mobile'     => ['sql' => 'varchar(11)', 'type' => 'varchar',
                                     'nullable' => false],
                    'card_no'    => ['sql' => 'varchar(16)', 'type' => 'varchar',
                                     'nullable' => false, 'default' => ''],
                    'passport'   => ['sql' => 'varchar(20)', 'type' => 'varchar',
                                     'nullable' => false, 'default' => ''],
                    'created'    => ['sql' => 'datetime', 'type' => 'datetime',
                                     'nullable' => true, 'format' => 'timestamp'],
                    'updated'    => ['sql' => 'datetime', 'type' => 'datetime',
                                     'nullable' => true, 'format' => 'timestamp'],
                ],
            ],
            'identities' => [
                'entity' => 'identities', 'envelope' => 'legacy',
                'columns' => [
                    'label'    => ['sql' => 'varchar(80)', 'type' => 'varchar',
                                   'nullable' => false, 'default' => ''],
                    'national' => ['sql' => 'varchar(10)', 'type' => 'varchar',
                                   'nullable' => false],
                    'birth'    => ['sql' => 'varchar(10)', 'type' => 'varchar',
                                   'nullable' => false],
                    'mobile'   => ['sql' => 'varchar(11)', 'type' => 'varchar',
                                   'nullable' => false],
                    'created'  => ['sql' => 'datetime', 'type' => 'datetime',
                                   'nullable' => true, 'format' => 'timestamp'],
                    'updated'  => ['sql' => 'datetime', 'type' => 'datetime',
                                   'nullable' => true, 'format' => 'timestamp'],
                ],
            ],
            'crm_devices' => [
                'entity' => 'crm_devices', 'envelope' => 'legacy',
                'columns' => [
                    'name'                 => ['sql' => 'varchar(40)', 'type' => 'varchar',
                                               'nullable' => false],
                    'serial1'              => ['sql' => 'varchar(15)', 'type' => 'varchar',
                                               'nullable' => false],
                    'serial2'              => ['sql' => 'varchar(15)', 'type' => 'varchar',
                                               'nullable' => false, 'default' => ''],
                    'customer_id'          => ['sql' => 'char(36)', 'type' => 'char',
                                               'nullable' => true, 'format' => 'uuid',
                                               'ref' => 'customers.id'],
                    'owner_id'             => ['sql' => 'char(36)', 'type' => 'char',
                                               'nullable' => true, 'format' => 'uuid',
                                               'ref' => 'owners.id'],
                    'stage'                => ['sql' => 'varchar(16)', 'type' => 'varchar',
                                               'nullable' => false, 'default' => 'new',
                                               'enum' => ['new', 'inquiry', 'problem',
                                                          'ready_owner', 'handed',
                                                          'to_payment', 'payment',
                                                          'payment_done', 'done',
                                                          'closed']],
                    'auto_advance'         => ['sql' => 'tinyint(1)', 'type' => 'tinyint',
                                               'nullable' => false, 'default' => 0,
                                               'enum' => [0, 1]],
                    'profile_id'           => ['sql' => 'varchar(64)', 'type' => 'varchar',
                                               'nullable' => false, 'default' => ''],
                    'handed_at'            => ['sql' => 'datetime', 'type' => 'datetime',
                                               'nullable' => true, 'format' => 'timestamp'],
                    'registered_at'        => ['sql' => 'datetime', 'type' => 'datetime',
                                               'nullable' => true, 'format' => 'timestamp'],
                    'payment_confirmed_at' => ['sql' => 'datetime', 'type' => 'datetime',
                                               'nullable' => true, 'format' => 'timestamp'],
                    'code_delivered_at'    => ['sql' => 'datetime', 'type' => 'datetime',
                                               'nullable' => true, 'format' => 'timestamp'],
                    'done_at'              => ['sql' => 'datetime', 'type' => 'datetime',
                                               'nullable' => true, 'format' => 'timestamp'],
                    'last_inquiry_at'      => ['sql' => 'datetime', 'type' => 'datetime',
                                               'nullable' => true, 'format' => 'timestamp'],
                    'notes'                => ['sql' => 'varchar(500)', 'type' => 'varchar',
                                               'nullable' => false, 'default' => ''],
                    'advance_attempts'     => ['sql' => 'int', 'type' => 'int',
                                               'nullable' => false, 'default' => 0],
                    'period_id'            => ['sql' => 'char(36)', 'type' => 'char',
                                               'nullable' => true, 'format' => 'uuid',
                                               'ref' => 'periods.id'],
                    'created'              => ['sql' => 'datetime', 'type' => 'datetime',
                                               'nullable' => true, 'format' => 'timestamp'],
                    'updated'              => ['sql' => 'datetime', 'type' => 'datetime',
                                               'nullable' => true, 'format' => 'timestamp'],
                    'skipped_stages'       => ['sql' => 'mediumtext', 'type' => 'mediumtext',
                                               'nullable' => true, 'format' => 'json'],
                    'closed_at'            => ['sql' => 'datetime', 'type' => 'datetime',
                                               'nullable' => true, 'format' => 'timestamp'],
                    'closed_reason'        => ['sql' => 'varchar(1000)', 'type' => 'varchar',
                                               'nullable' => false, 'default' => ''],
                    'periodic_opt_out'     => ['sql' => 'tinyint(1)', 'type' => 'tinyint',
                                               'nullable' => false, 'default' => 0,
                                               'enum' => [0, 1]],
                    'payment_started_at'   => ['sql' => 'datetime', 'type' => 'datetime',
                                               'nullable' => true, 'format' => 'timestamp'],
                ],
            ],
            'customer_transactions' => [
                'entity' => 'customer_transactions', 'envelope' => 'legacy',
                'columns' => [
                    'seq'         => ['sql' => 'int', 'type' => 'int',
                                      'nullable' => false],
                    'customer_id' => ['sql' => 'char(36)', 'type' => 'char',
                                      'nullable' => false, 'format' => 'uuid',
                                      'ref' => 'customers.id'],
                    'at'          => ['sql' => 'datetime', 'type' => 'datetime',
                                      'nullable' => true, 'format' => 'timestamp'],
                    'amount'      => ['sql' => 'bigint', 'type' => 'bigint',
                                      'nullable' => false],
                    'note'        => ['sql' => 'varchar(1000)', 'type' => 'varchar',
                                      'nullable' => false, 'default' => ''],
                    'kind'        => ['sql' => 'varchar(32)', 'type' => 'varchar',
                                      'nullable' => false, 'default' => ''],
                    'image'       => ['sql' => 'varchar(64)', 'type' => 'varchar',
                                      'nullable' => false, 'default' => ''],
                    'device_id'   => ['sql' => 'char(36)', 'type' => 'char',
                                      'nullable' => true, 'format' => 'uuid',
                                      'ref' => 'crm_devices.id'],
                    'voided_at'   => ['sql' => 'datetime', 'type' => 'datetime',
                                      'nullable' => true, 'format' => 'timestamp'],
                    'void_reason' => ['sql' => 'varchar(1000)', 'type' => 'varchar',
                                      'nullable' => false, 'default' => ''],
                ],
            ],
        ];

        // Merge the envelope in front of each table's business columns, from
        // the single declaration above, so no table can be given a different
        // envelope by hand.
        $built = [];
        foreach ($tables as $name => $spec) {
            $columns = match ($spec['envelope']) {
                'legacy' => $envelope + $spec['columns'],
                'plain'  => array_intersect_key(
                                $envelope, array_flip(self::ENVELOPE_PLAIN))
                            + $spec['columns'],
                default  => $spec['columns'],
            };
            unset($spec['envelope']);
            $spec['columns'] = $columns;
            $built[$name] = $spec;
        }

        self::$schema = $built;
        return self::$schema;
    }

    // ------------------------------------------------------------------
    // Introspection
    // ------------------------------------------------------------------

    /** @return list<string> every table name, sorted */
    public static function tables(): array
    {
        $names = array_keys(self::schema());
        sort($names);
        return $names;
    }

    public static function isTable(string $table): bool
    {
        return isset(self::schema()[$table]);
    }

    /**
     * Column names of one table, in declaration order.
     *
     * @return list<string>
     */
    public static function columnsFor(string $table): array
    {
        $spec = self::schema()[$table] ?? null;
        if ($spec === null) {
            return [];
        }
        return array_keys($spec['columns']);
    }

    public static function hasColumn(string $table, string $column): bool
    {
        return isset(self::schema()[$table]['columns'][$column]);
    }

    /**
     * Full spec of one column: sql, type, nullable, required, default, enum,
     * format, ref. null when the table or column is unknown.
     *
     * @return array<string, mixed>|null
     */
    public static function column(string $table, string $column): ?array
    {
        $raw = self::schema()[$table]['columns'][$column] ?? null;
        if ($raw === null) {
            return null;
        }
        return self::withRequired($raw);
    }

    /**
     * Full spec of one table: entity (or null) and every column spec.
     *
     * @return array<string, mixed>|null
     */
    public static function table(string $table): ?array
    {
        $spec = self::schema()[$table] ?? null;
        if ($spec === null) {
            return null;
        }
        $columns = [];
        foreach ($spec['columns'] as $name => $raw) {
            $columns[$name] = self::withRequired($raw);
        }
        return ['entity' => $spec['entity'], 'columns' => $columns];
    }

    /**
     * Spec of every table: table => ['entity' => ..., 'columns' => [...]].
     *
     * @return array<string, array<string, mixed>>
     */
    public static function describe(): array
    {
        $out = [];
        foreach (array_keys(self::schema()) as $name) {
            $out[$name] = self::table($name);
        }
        return $out;
    }

    /** Spec §3 entity name -> table name, for the synced collections only. */
    public static function entities(): array
    {
        $out = [];
        foreach (self::schema() as $name => $spec) {
            if ($spec['entity'] !== null) {
                $out[$spec['entity']] = $name;
            }
        }
        return $out;
    }

    public static function tableForEntity(string $entity): ?string
    {
        return self::entities()[$entity] ?? null;
    }

    public static function entityForTable(string $table): ?string
    {
        return self::schema()[$table]['entity'] ?? null;
    }

    /**
     * Business columns of a table — everything that is not the §4 envelope.
     *
     * @return list<string>
     */
    public static function businessColumns(string $table): array
    {
        $envelope = self::envelopeFor($table);
        return array_values(array_diff(self::columnsFor($table), $envelope));
    }

    /** The envelope column names actually present on this table. */
    public static function envelopeFor(string $table): array
    {
        $columns = self::columnsFor($table);
        if ($columns === []) {
            return [];
        }
        // `legacy_id` exists only on the tables that have a legacy source.
        $names = isset(self::schema()[$table]['columns']['legacy_id'])
            ? self::ENVELOPE : self::ENVELOPE_PLAIN;
        return array_values(array_intersect($names, $columns));
    }

    /**
     * Spec §3 settings allowlist — the ONLY settings keys that may cross the
     * wire. The client keeps its own copy in cloud_sync/mapper.py; workstream
     * G owns the cross-language consistency test.
     *
     * @return list<string>
     */
    public static function settingsAllowlist(): array
    {
        return self::businessColumns('settings');
    }

    // ------------------------------------------------------------------
    // Timestamp conversion (SQL DATETIME <-> spec §4 wire form)
    // ------------------------------------------------------------------

    /**
     * Convert a wire timestamp to the text a DATETIME column accepts.
     *
     * A SQL DATETIME carries no offset, so the ISO-8601 value of spec §4 has
     * to be normalised to UTC before it can be bound. A value that already has
     * no offset is passed through untouched: the connection time zone is
     * '+00:00', so it is already UTC (Database::fromConfig sets it).
     *
     * Returns null for null — a NULL timestamp stays NULL.
     */
    public static function toSqlTimestamp(?string $value): ?string
    {
        if ($value === null) {
            return null;
        }
        if (preg_match('/(Z|z|[+-]\d{2}:?\d{2})$/', $value) !== 1) {
            return $value;
        }
        try {
            $moment = new \DateTimeImmutable($value);
        } catch (\Exception $e) {
            // Let the database raise its own error rather than guessing.
            return $value;
        }
        return $moment->setTimezone(new \DateTimeZone('UTC'))
            ->format('Y-m-d H:i:s');
    }

    /**
     * Convert a DATETIME read back from the database into the wire form of
     * spec §4: UTC ISO-8601 with an explicit offset. The client rejects a
     * naive timestamp, so a raw `2026-10-05 01:23:45` must not be sent as-is.
     */
    public static function toWireTimestamp(?string $sqlDateTime): ?string
    {
        if ($sqlDateTime === null || $sqlDateTime === '') {
            return null;
        }
        try {
            $moment = new \DateTimeImmutable($sqlDateTime,
                new \DateTimeZone('UTC'));
        } catch (\Exception $e) {
            return null;
        }
        return $moment->format('Y-m-d\TH:i:s+00:00');
    }

    // ------------------------------------------------------------------
    // Validation
    // ------------------------------------------------------------------

    /**
     * Validate one incoming business record against a table's schema.
     *
     * "Record" is what travels on the wire (spec §6.1): the business columns
     * plus `id`. The client mints every id — including `settings` and
     * `customer_transactions`, as a uuid5 of (installation, entity, legacy id)
     * — so a push without one is rejected here rather than silently receiving
     * a server-minted identity. The rest of the envelope (tenant_id, the
     * server timestamps, the tombstone) is minted by the server and is NOT
     * demanded here; envelope keys that ARE supplied are still type-checked.
     *
     * Returns a list of failures, each `['code' => ..., 'table' => ...,
     * 'column' => ...]`, empty when the record is acceptable. Never includes
     * the rejected value: a national code or a phone number must not leave the
     * validator (spec §10.9).
     *
     * Rules encoded here, derived from the code that writes the store:
     *   * unknown column -> UNKNOWN_COLUMN (this is what drops a settings key
     *     that is not on the allowlist, and what stops a client inventing one)
     *   * NOT NULL without a default and absent -> MISSING_COLUMN
     *   * a reference column given as "" -> EMPTY_REFERENCE; SQL NULL is the
     *     only way to say "no customer / no owner / no period"
     *   * datetime must carry an explicit UTC offset -> INVALID_TIMESTAMP
     *
     * @param array<string, mixed> $record
     * @return list<array{code: string, table: string, column: string}>
     */
    public static function validate(string $table, array $record): array
    {
        return self::validateInternal($table, $record, false);
    }

    /**
     * Validate a complete row as it will be written, envelope included.
     *
     * Use this immediately before INSERT/UPDATE: it additionally requires
     * id, tenant_id and the server timestamps, so a row can never reach the
     * database missing a column that has no default.
     *
     * @param array<string, mixed> $row
     * @return list<array{code: string, table: string, column: string}>
     */
    public static function validateRow(string $table, array $row): array
    {
        return self::validateInternal($table, $row, true);
    }

    /**
     * Validate a record addressed by spec §3 entity name rather than table.
     *
     * @param array<string, mixed> $record
     * @return list<array{code: string, table: string, column: string}>
     */
    public static function validateEntity(string $entity, array $record): array
    {
        $table = self::tableForEntity($entity);
        if ($table === null) {
            return [self::failure(self::E_UNKNOWN_ENTITY, $entity, '')];
        }
        return self::validate($table, $record);
    }

    /**
     * @param array<string, mixed> $record
     * @return list<array{code: string, table: string, column: string}>
     */
    private static function validateInternal(string $table, array $record,
                                             bool $row): array
    {
        $spec = self::schema()[$table] ?? null;
        if ($spec === null) {
            return [self::failure(self::E_UNKNOWN_TABLE, $table, '')];
        }

        $envelope = self::envelopeFor($table);
        $failures = [];
        foreach ($record as $column => $value) {
            if (!isset($spec['columns'][$column])) {
                $failures[] = self::failure(self::E_UNKNOWN_COLUMN, $table,
                                            (string) $column);
            }
        }

        foreach ($spec['columns'] as $column => $raw) {
            $check = self::withRequired($raw);
            $isEnvelope = in_array($column, $envelope, true);
            if ($isEnvelope && !$row && $column !== 'id') {
                // The server mints the rest of the envelope; only check what
                // arrived. `id` is the exception: the client mints it, so a
                // record without one must never pass.
                if (!array_key_exists($column, $record)) {
                    continue;
                }
            }
            $present = array_key_exists($column, $record);

            if (!$present || $record[$column] === null) {
                if (!empty($check['required'])) {
                    $failures[] = self::failure(self::E_MISSING_COLUMN, $table,
                                                $column);
                }
                continue;
            }

            $failures = array_merge(
                $failures,
                self::validateValue($table, $column, $check, $record[$column])
            );
        }

        return $failures;
    }

    /**
     * @param array<string, mixed> $check
     * @return list<array{code: string, table: string, column: string}>
     */
    private static function validateValue(string $table, string $column,
                                          array $check, mixed $value): array
    {
        $type = (string) $check['type'];

        if ($check['ref'] !== null && is_string($value) && $value === '') {
            // An empty string cannot satisfy a foreign key. Say so precisely
            // instead of letting SQL raise 1452 with no column context.
            return [self::failure(self::E_EMPTY_REFERENCE, $table, $column)];
        }

        switch ($type) {
            case 'tinyint':
                if (is_bool($value)) {
                    $value = $value ? 1 : 0;
                }
                if (!is_int($value)) {
                    return [self::failure(self::E_TYPE_MISMATCH, $table, $column)];
                }
                if ($check['enum'] !== null && !in_array($value, $check['enum'], true)) {
                    return [self::failure(self::E_ENUM_MISMATCH, $table, $column)];
                }
                return [];

            case 'int':
            case 'bigint':
                if (is_bool($value) || !is_int($value)) {
                    return [self::failure(self::E_TYPE_MISMATCH, $table, $column)];
                }
                if ($check['enum'] !== null && !in_array($value, $check['enum'], true)) {
                    return [self::failure(self::E_ENUM_MISMATCH, $table, $column)];
                }
                if (($check['min'] !== null && $value < $check['min'])
                    || ($check['max'] !== null && $value > $check['max'])) {
                    return [self::failure(self::E_OUT_OF_RANGE, $table, $column)];
                }
                return [];

            case 'datetime':
                if (!is_string($value) || !self::isUtcTimestamp($value)) {
                    return [self::failure(self::E_INVALID_TIMESTAMP, $table, $column)];
                }
                return [];

            case 'char':
            case 'varchar':
            case 'text':
            case 'mediumtext':
                if (!is_string($value)) {
                    return [self::failure(self::E_TYPE_MISMATCH, $table, $column)];
                }
                if ($check['enum'] !== null
                    && !in_array($value, $check['enum'], true)) {
                    return [self::failure(self::E_ENUM_MISMATCH, $table, $column)];
                }
                if ($check['format'] === 'uuid' && !self::isUuid($value)) {
                    return [self::failure(self::E_INVALID_UUID, $table, $column)];
                }
                if ($check['format'] === 'legacy_id'
                    && (strlen($value) === 0 || strlen($value) > 64)) {
                    return [self::failure(self::E_INVALID_LEGACY_ID, $table, $column)];
                }
                if ($check['format'] === 'json' && !self::isJson($value)) {
                    return [self::failure(self::E_INVALID_JSON, $table, $column)];
                }
                $limit = self::lengthLimit((string) $check['sql']);
                if ($limit !== null && mb_strlen($value, 'UTF-8') > $limit) {
                    return [self::failure(self::E_TOO_LONG, $table, $column)];
                }
                return [];

            default:
                return [self::failure(self::E_TYPE_MISMATCH, $table, $column)];
        }
    }

    /** ISO-8601 with an explicit offset (or Z), e.g. 2026-10-05T01:23:45+00:00. */
    private static function isUtcTimestamp(string $value): bool
    {
        if (preg_match(
            '/^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2})?(\.\d+)?'
            . '(Z|[z]|[+-]\d{2}:?\d{2})$/',
            $value
        ) !== 1) {
            return false;
        }
        $normalized = ($value[-1] === 'Z' || $value[-1] === 'z')
            ? substr($value, 0, -1) . '+00:00' : $value;
        try {
            new \DateTimeImmutable($normalized);
        } catch (\Exception $e) {
            return false;
        }
        return true;
    }

    private static function isUuid(string $value): bool
    {
        return preg_match(
            '/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-'
            . '[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/',
            $value
        ) === 1;
    }

    private static function isJson(string $value): bool
    {
        json_decode($value, true, 32, JSON_BIGINT_AS_STRING);
        return json_last_error() === JSON_ERROR_NONE;
    }

    /** Character capacity of a char(n)/varchar(n) declaration, else null. */
    private static function lengthLimit(string $sql): ?int
    {
        if (preg_match('/^(?:char|varchar)\((\d+)\)$/', $sql, $m) === 1) {
            return (int) $m[1];
        }
        return null;
    }

    /**
     * @param array<string, mixed> $raw
     * @return array<string, mixed>
     */
    private static function withRequired(array $raw): array
    {
        $raw += [
            'type' => 'varchar', 'nullable' => false, 'default' => null,
            'enum' => null, 'format' => null, 'ref' => null, 'auto' => false,
            'min' => null, 'max' => null,
        ];
        // Required <=> NOT NULL with no default and not server-generated:
        // derived so it cannot drift from the SQL it describes. An
        // AUTO_INCREMENT key (change_log.seq, login_attempts.id) is filled in
        // by the server, so demanding it from an incoming record would be a
        // false rejection.
        $raw['required'] = !$raw['nullable']
            && $raw['default'] === null
            && !$raw['auto'];
        return $raw;
    }

    /**
     * @return array{code: string, table: string, column: string}
     */
    private static function failure(string $code, string $table,
                                    string $column): array
    {
        return ['code' => $code, 'table' => $table, 'column' => $column];
    }
}
