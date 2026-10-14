-- Rollback 002b. DESTROYS snapshots, labels, and all match/risk/priority values.
-- Back up first:
--   mysqldump -u root -p sbom_common > sbom_backup_before_002b_rollback.sql
DROP TRIGGER IF EXISTS trg_snap_no_update;
DROP TRIGGER IF EXISTS trg_snap_no_delete;
DROP TRIGGER IF EXISTS trg_runs_no_delete;
DROP TABLE IF EXISTS package_snapshots;
DROP TABLE IF EXISTS scan_runs;
DROP TABLE IF EXISTS labeled_pairs;

DROP INDEX IF EXISTS idx_pkg_normalized_name ON packages;
DROP INDEX IF EXISTS idx_pkg_match_status    ON packages;
DROP INDEX IF EXISTS idx_pkg_risk_level      ON packages;
DROP INDEX IF EXISTS idx_pkg_risk_tier       ON packages;
DROP INDEX IF EXISTS idx_pkg_priority_rank   ON packages;
DROP INDEX IF EXISTS idx_pkg_priority_score  ON packages;

ALTER TABLE packages
  DROP COLUMN IF EXISTS normalized_name,
  DROP COLUMN IF EXISTS matched_name,
  DROP COLUMN IF EXISTS match_ecosystem,
  DROP COLUMN IF EXISTS match_method,
  DROP COLUMN IF EXISTS match_score,
  DROP COLUMN IF EXISTS match_status,
  DROP COLUMN IF EXISTS matched_at,
  DROP COLUMN IF EXISTS risk_score,
  DROP COLUMN IF EXISTS risk_level,
  DROP COLUMN IF EXISTS risk_reasons,
  DROP COLUMN IF EXISTS risk_tier,
  DROP COLUMN IF EXISTS risk_days_behind,
  DROP COLUMN IF EXISTS risk_vuln_count,
  DROP COLUMN IF EXISTS risk_is_abandoned,
  DROP COLUMN IF EXISTS installed_release_date,
  DROP COLUMN IF EXISTS latest_release_date,
  DROP COLUMN IF EXISTS risk_version_id,
  DROP COLUMN IF EXISTS risk_model_version,
  DROP COLUMN IF EXISTS risk_computed_at,
  DROP COLUMN IF EXISTS priority_score,
  DROP COLUMN IF EXISTS priority_rank,
  DROP COLUMN IF EXISTS priority_reason,
  DROP COLUMN IF EXISTS priority_version_id,
  DROP COLUMN IF EXISTS priority_computed_at;
