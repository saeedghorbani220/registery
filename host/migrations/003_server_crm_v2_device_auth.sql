-- ===========================================================================
-- 003_server_crm_v2_device_auth.sql
--
-- Device-ownership enforcement for server CRM v2.
--
-- The existing admin enrol endpoint historically wrote only `enrolled_by`.
-- Migration 002 introduced `owner_user_id`; this trigger keeps every future
-- insert explicit without rewriting the legacy endpoint or weakening its
-- authorization. A later caller may still provide a different owner explicitly
-- (for an admin-managed assignment); only NULL is defaulted.
-- ===========================================================================

SET NAMES utf8mb4;
SET time_zone = '+00:00';

CREATE TRIGGER trg_sync_devices_owner_default
BEFORE INSERT ON sync_devices
FOR EACH ROW
SET NEW.owner_user_id = COALESCE(NEW.owner_user_id, NEW.enrolled_by);
