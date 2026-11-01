-- 004: package_snapshots holds one row per versions row (repo + package) per run.
-- Additive where possible, idempotent. MariaDB 10.4. Needs 002b. The insert-only
-- triggers (trg_snap_no_update, trg_snap_no_delete) are not touched.
-- Back up first, then run BEFORE starting the code that writes snapshots
-- (from the project root):
--   C:\xampp\mysql\bin\mysqldump.exe -u root -p sbom_common --result-file=sbom_backup_before_004.sql
--   C:\xampp\mysql\bin\mysql.exe -u root -p sbom_common -e "source migrations/004_snapshot_per_version.sql"
SET NAMES utf8mb4;

-- New unique key first: fk_snap_run needs an index that starts with run_id,
-- which the old key provides until it is dropped.
CREATE UNIQUE INDEX IF NOT EXISTS uq_snap_run_version ON package_snapshots (run_id, version_id);
DROP INDEX IF EXISTS uq_snap_run_pkg ON package_snapshots;

-- Every snapshot row names its versions row (fails if a row has none;
-- the table is empty before collection starts).
ALTER TABLE package_snapshots MODIFY version_id INT NOT NULL;

-- The repository of the row, so it stays known even if the versions row
-- is later deleted.
ALTER TABLE package_snapshots ADD COLUMN IF NOT EXISTS scan_id INT NULL AFTER version_id;
CREATE INDEX IF NOT EXISTS idx_snap_scan_date ON package_snapshots (scan_id, snapshot_date);
