-- Rollback 004. Back to one snapshot row per package per run.
-- Works only BEFORE collection starts: recreating uq_snap_run_pkg fails as soon
-- as a run has the same package in two repositories, and those rows can't be
-- deleted (insert-only). After that, restore sbom_backup_before_004.sql instead.
-- Stop the app first. Back up first (from the project root):
--   C:\xampp\mysql\bin\mysqldump.exe -u root -p sbom_common --result-file=sbom_backup_before_004_rollback.sql
--   C:\xampp\mysql\bin\mysql.exe -u root -p sbom_common -e "source migrations/004_rollback.sql"
SET NAMES utf8mb4;

-- The only step that can fail, so it runs first and nothing else changes if it
-- does (it fails when a run has the same package twice)
CREATE UNIQUE INDEX IF NOT EXISTS uq_snap_run_pkg ON package_snapshots (run_id, package_id);
DROP INDEX IF EXISTS uq_snap_run_version ON package_snapshots;

DROP INDEX IF EXISTS idx_snap_scan_date ON package_snapshots;
ALTER TABLE package_snapshots DROP COLUMN IF EXISTS scan_id;

ALTER TABLE package_snapshots MODIFY version_id INT NULL;
