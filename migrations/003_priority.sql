-- 003: update queue category + priority model version. Additive, idempotent. MariaDB 10.4.
-- Needs 002b (packages.priority_* columns). Back up first, then run BEFORE starting
-- the code that reads these columns:
--   mysqldump -u root -p sbom_common --result-file=sbom_backup_before_003.sql
--   mysql -u root -p sbom_common -e "source migrations/003_priority.sql"
-- Fill the values afterwards with: python sbom-tools/backfill_priority.py [--apply]
SET NAMES utf8mb4;

ALTER TABLE packages
  ADD COLUMN IF NOT EXISTS priority_category      VARCHAR(20) NULL,
  ADD COLUMN IF NOT EXISTS priority_model_version VARCHAR(30) NULL;

CREATE INDEX IF NOT EXISTS idx_pkg_priority_category ON packages (priority_category);
