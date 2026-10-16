-- ===========================================================================
-- 004_legacy_import_verification.sql
--
-- Persist PII-free before/after summaries for one reviewed legacy migration.
-- The raw source and row-level customer data stay in the existing staging
-- tables; this table stores only aggregate counts, sums, stages and link-health
-- metrics captured inside the same transaction as apply.
-- ===========================================================================

SET NAMES utf8mb4;
SET time_zone = '+00:00';

CREATE TABLE legacy_import_verifications (
  job_id       CHAR(36)    NOT NULL,
  tenant_id    CHAR(36)    NOT NULL,
  before_json  MEDIUMTEXT  NOT NULL,
  after_json   MEDIUMTEXT  NOT NULL,
  captured_at  DATETIME    NOT NULL,
  PRIMARY KEY (job_id),
  KEY ix_legacy_verify_tenant (tenant_id, captured_at),
  CONSTRAINT fk_legacy_verify_job
    FOREIGN KEY (job_id) REFERENCES legacy_import_jobs (id),
  CONSTRAINT fk_legacy_verify_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
  CHECK (json_valid(before_json)),
  CHECK (json_valid(after_json))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
