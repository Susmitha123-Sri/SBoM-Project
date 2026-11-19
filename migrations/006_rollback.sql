-- Rollback 006. Revert the code first (the old code writes no
-- risk_model_version into snapshots and reads no risk_models).
-- Only safe while every score is still v1: migrate_006.py --rollback refuses
-- when any package, snapshot or saved formula uses another version, because
-- dropping risk_models would lose what that version means. The risk_* rows
-- in the settings table are left (the old code ignores them).
-- Dry run first, then apply (from the project root):
--   python sbom-tools/migrate_006.py --database sbom_common --rollback
--   python sbom-tools/migrate_006.py --database sbom_common --rollback --apply
-- Or by hand, after a backup:
--   C:\xampp\mysql\bin\mysqldump.exe -u root -p sbom_common --result-file=sbom_backup_before_006_rollback.sql
--   C:\xampp\mysql\bin\mysql.exe -u root -p sbom_common -e "source migrations/006_rollback.sql"
SET NAMES utf8mb4;

ALTER TABLE package_snapshots DROP COLUMN IF EXISTS risk_model_version;
DROP TRIGGER IF EXISTS trg_risk_models_no_update;
DROP TRIGGER IF EXISTS trg_risk_models_no_delete;
DROP TABLE IF EXISTS risk_models;
