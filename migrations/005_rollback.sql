-- Rollback 005. Drops the /trends summary tables (children first). Only derived
-- data is lost: python sbom-tools/summarize_snapshots.py --apply rebuilds it
-- from package_snapshots after 005 is applied again. package_snapshots and
-- scan_runs are not touched.
-- Stop the app first. Back up first (from the project root):
--   C:\xampp\mysql\bin\mysqldump.exe -u root -p sbom_common --result-file=sbom_backup_before_005_rollback.sql
--   C:\xampp\mysql\bin\mysql.exe -u root -p sbom_common -e "source migrations/005_rollback.sql"
SET NAMES utf8mb4;

DROP TABLE IF EXISTS snapshot_transitions;
DROP TABLE IF EXISTS snapshot_transition_pairs;
DROP TABLE IF EXISTS snapshot_summary;
DROP TABLE IF EXISTS snapshot_summary_runs;
