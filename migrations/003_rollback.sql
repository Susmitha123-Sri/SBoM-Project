-- Rollback 003. Drops the update-queue category and priority model version.
-- Stop the app first (its queries read these columns). Run this before any
-- 002b rollback. Back up first:
--   mysqldump -u root -p sbom_common --result-file=sbom_backup_before_003_rollback.sql
DROP INDEX IF EXISTS idx_pkg_priority_category ON packages;

ALTER TABLE packages
  DROP COLUMN IF EXISTS priority_category,
  DROP COLUMN IF EXISTS priority_model_version;
