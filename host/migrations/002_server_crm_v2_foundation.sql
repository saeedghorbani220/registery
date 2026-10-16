-- ===========================================================================
-- 002_server_crm_v2_foundation.sql
--
-- Additive foundation for the server-authoritative CRM rollout.
--
-- Goals:
--   * identify which user owns each enrolled desktop device;
--   * expose advisory edit presence without hard-locking CRM records;
--   * stage legacy <=1.13.1 imports for validation, deduplication and preview
--     before an atomic merge into the live dataset.
--
-- Safety rules:
--   * forward-only migration; no DROP and no destructive rewrite;
--   * existing sync behaviour remains valid after this migration;
--   * staging rows may contain customer data and therefore never belong in
--     application logs; only stable ids/counts/error codes may be logged;
--   * source files are not stored in SQL. Only normalized staging rows and a
--     SHA-256 fingerprint are retained.
-- ===========================================================================

SET NAMES utf8mb4;
SET time_zone = '+00:00';

-- A device may be enrolled by an administrator for somebody else. Keep the
-- historical `enrolled_by` meaning and add an explicit owner instead of
-- overloading that column. Existing installations are backfilled from
-- enrolled_by where possible and remain valid when it was NULL.
ALTER TABLE sync_devices
  ADD COLUMN owner_user_id CHAR(36) NULL AFTER enrolled_by,
  ADD KEY ix_sync_devices_owner (tenant_id, owner_user_id),
  ADD CONSTRAINT fk_sync_devices_owner
    FOREIGN KEY (owner_user_id) REFERENCES users (id);

UPDATE sync_devices
   SET owner_user_id = enrolled_by
 WHERE owner_user_id IS NULL
   AND enrolled_by IS NOT NULL;

-- Advisory presence only. It must never become a hard lock: a crashed client
-- simply stops heartbeating and the row expires. Multiple users/devices may
-- have presence on the same record at the same time.
CREATE TABLE record_presence (
  tenant_id       CHAR(36)    NOT NULL,
  entity          VARCHAR(64) NOT NULL,
  entity_id       CHAR(36)    NOT NULL,
  user_id         CHAR(36)    NOT NULL,
  sync_device_id  CHAR(36)    NOT NULL,
  lease_id        CHAR(36)    NOT NULL,
  opened_at       DATETIME    NOT NULL,
  heartbeat_at    DATETIME    NOT NULL,
  expires_at      DATETIME    NOT NULL,
  PRIMARY KEY (tenant_id, entity, entity_id, sync_device_id),
  UNIQUE KEY uq_record_presence_lease (lease_id),
  KEY ix_record_presence_expiry (expires_at),
  KEY ix_record_presence_user (tenant_id, user_id),
  CONSTRAINT fk_record_presence_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
  CONSTRAINT fk_record_presence_user
    FOREIGN KEY (user_id) REFERENCES users (id),
  CONSTRAINT fk_record_presence_device
    FOREIGN KEY (sync_device_id) REFERENCES sync_devices (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- One row per uploaded legacy database. Re-uploading the exact same source
-- file for a tenant is idempotent by source_sha256. `error_code` is a stable
-- machine code only; raw exception text and PII are never stored here.
CREATE TABLE legacy_import_jobs (
  id                     CHAR(36)     NOT NULL,
  tenant_id              CHAR(36)     NOT NULL,
  source_sha256          CHAR(64)     NOT NULL,
  source_version         VARCHAR(32)  NOT NULL DEFAULT '',
  source_installation_id CHAR(36)     NULL,
  original_filename      VARCHAR(255) NOT NULL DEFAULT '',
  status                 VARCHAR(24)  NOT NULL DEFAULT 'uploaded'
                         CHECK (status IN (
                           'uploaded', 'analyzing', 'review', 'ready',
                           'applying', 'applied', 'failed', 'cancelled'
                         )),
  record_count           INT          NOT NULL DEFAULT 0,
  created_by             CHAR(36)     NOT NULL,
  created_at             DATETIME     NOT NULL,
  updated_at             DATETIME     NOT NULL,
  applied_at             DATETIME     NULL,
  error_code             VARCHAR(40)  NOT NULL DEFAULT '',
  PRIMARY KEY (id),
  UNIQUE KEY uq_legacy_import_source (tenant_id, source_sha256),
  KEY ix_legacy_import_status (tenant_id, status, created_at),
  CONSTRAINT fk_legacy_import_jobs_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
  CONSTRAINT fk_legacy_import_jobs_user
    FOREIGN KEY (created_by) REFERENCES users (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Normalized staging rows. `record_json` intentionally contains the proposed
-- business record so the admin preview and later atomic merge operate on the
-- exact bytes that were reviewed. These rows are database data, not logs.
-- `issues_json` contains structured issue codes/field names only.
CREATE TABLE legacy_import_records (
  id             CHAR(36)      NOT NULL,
  tenant_id      CHAR(36)      NOT NULL,
  job_id         CHAR(36)      NOT NULL,
  entity         VARCHAR(64)   NOT NULL,
  source_key     VARCHAR(128)  NOT NULL,
  source_hash    CHAR(64)      NOT NULL,
  action         VARCHAR(24)   NOT NULL DEFAULT 'pending'
                 CHECK (action IN (
                   'pending', 'create', 'merge', 'skip', 'conflict', 'invalid'
                 )),
  target_id      CHAR(36)      NULL,
  record_json    MEDIUMTEXT    NOT NULL,
  issues_json    MEDIUMTEXT    NULL,
  created_at     DATETIME      NOT NULL,
  updated_at     DATETIME      NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_legacy_import_record (job_id, entity, source_key),
  KEY ix_legacy_import_action (job_id, action, entity),
  KEY ix_legacy_import_target (tenant_id, entity, target_id),
  CONSTRAINT fk_legacy_import_records_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
  CONSTRAINT fk_legacy_import_records_job
    FOREIGN KEY (job_id) REFERENCES legacy_import_jobs (id),
  CHECK (json_valid(record_json)),
  CHECK (issues_json IS NULL OR json_valid(issues_json))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Admin decisions are separated from normalized source rows so re-analysis can
-- safely regenerate detection results without silently discarding a reviewed
-- choice. No PII is duplicated here.
CREATE TABLE legacy_import_decisions (
  id          CHAR(36)    NOT NULL,
  tenant_id   CHAR(36)    NOT NULL,
  job_id      CHAR(36)    NOT NULL,
  record_id   CHAR(36)    NOT NULL,
  resolution  VARCHAR(24) NOT NULL
              CHECK (resolution IN ('create', 'merge', 'skip', 'reject')),
  target_id   CHAR(36)    NULL,
  decided_by  CHAR(36)    NOT NULL,
  decided_at  DATETIME    NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_legacy_import_decision (job_id, record_id),
  KEY ix_legacy_import_decisions_job (job_id, decided_at),
  CONSTRAINT fk_legacy_import_decisions_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
  CONSTRAINT fk_legacy_import_decisions_job
    FOREIGN KEY (job_id) REFERENCES legacy_import_jobs (id),
  CONSTRAINT fk_legacy_import_decisions_record
    FOREIGN KEY (record_id) REFERENCES legacy_import_records (id),
  CONSTRAINT fk_legacy_import_decisions_user
    FOREIGN KEY (decided_by) REFERENCES users (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
