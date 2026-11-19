-- 006: the risk formula becomes settings (Settings page, "Risk formula").
--   risk_models                         every formula ever used: model version ->
--                                       parameters (canonical JSON), insert-only;
--                                       seeded with v1 = the original hard-coded values
--   package_snapshots.risk_model_version  the formula behind each snapshot's risk score
-- Additive and idempotent. MariaDB 10.4. Needs 004. Apply BEFORE running the
-- code that writes risk_model_version into snapshots (a missing column makes
-- that day's snapshot run fail). Run while no daily pass is running.
-- Dry run first, then apply (from the project root):
--   python sbom-tools/migrate_006.py --database sbom_common
--   python sbom-tools/migrate_006.py --database sbom_common --apply
-- Or by hand, after a backup:
--   C:\xampp\mysql\bin\mysqldump.exe -u root -p sbom_common --result-file=sbom_backup_before_006.sql
--   C:\xampp\mysql\bin\mysql.exe -u root -p sbom_common -e "source migrations/006_risk_models.sql"
SET NAMES utf8mb4;

CREATE TABLE IF NOT EXISTS risk_models (
  model_version  VARCHAR(30) NOT NULL,
  params         TEXT NOT NULL,
  created_at     DATETIME NOT NULL DEFAULT current_timestamp(),
  note           VARCHAR(255) NULL,
  PRIMARY KEY (model_version)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

INSERT IGNORE INTO risk_models (model_version, params, note) VALUES ('v1', '{"risk_abandoned_points": 25, "risk_band1_max_days": 30, "risk_band1_points": 0, "risk_band2_max_days": 365, "risk_band2_points": 15, "risk_band3_max_days": 730, "risk_band3_points": 30, "risk_critical_min": 70, "risk_high_min": 45, "risk_max_score": 100, "risk_medium_min": 20, "risk_over_points": 40, "risk_vuln1_min": 1, "risk_vuln1_points": 20, "risk_vuln2_min": 2, "risk_vuln2_points": 30, "risk_vuln3_min": 5, "risk_vuln3_points": 45}', 'risk score v1 (original hard-coded values)');

CREATE TRIGGER IF NOT EXISTS trg_risk_models_no_update
  BEFORE UPDATE ON risk_models FOR EACH ROW
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'risk_models is insert-only';

CREATE TRIGGER IF NOT EXISTS trg_risk_models_no_delete
  BEFORE DELETE ON risk_models FOR EACH ROW
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'risk_models is insert-only';

ALTER TABLE package_snapshots ADD COLUMN IF NOT EXISTS risk_model_version VARCHAR(30) NULL AFTER risk_level;
