-- 005: summary tables for the /trends page, filled by sbom-tools/summarize_snapshots.py
-- (one completed or partial run at a time). Only new tables: package_snapshots,
-- scan_runs and their insert-only triggers are not touched, and everything here
-- can be rebuilt from package_snapshots. Idempotent. MariaDB 10.4. Needs 004.
-- Run while no daily pass is running (the foreign keys briefly lock scan_runs).
-- Back up first, then (from the project root):
--   C:\xampp\mysql\bin\mysqldump.exe -u root -p sbom_common --result-file=sbom_backup_before_005.sql
--   C:\xampp\mysql\bin\mysql.exe -u root -p sbom_common -e "source migrations/005_snapshot_summary.sql"
SET NAMES utf8mb4;

-- One row per summarised run, written in the same transaction as its
-- snapshot_summary rows: a run with a row here is completely summarised.
CREATE TABLE IF NOT EXISTS snapshot_summary_runs (
  run_id         INT NOT NULL,
  snapshot_date  DATE NOT NULL,
  run_status     VARCHAR(20) NOT NULL,       -- completed / partial when summarised
  rows_n         INT NOT NULL,               -- snapshot rows (repo rows)
  packages_n     INT NOT NULL,               -- distinct packages
  summarized_at  DATETIME NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (run_id),
  KEY idx_ssr_date (snapshot_date),
  CONSTRAINT fk_ssr_run FOREIGN KEY (run_id)
    REFERENCES scan_runs (run_id) ON DELETE RESTRICT ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Counts per run and value: tier (age_tier, NULL = 'unknown'), risk
-- (risk_level, NULL = 'Not scored') and review (review_status).
CREATE TABLE IF NOT EXISTS snapshot_summary (
  run_id      INT NOT NULL,
  dimension   VARCHAR(10) NOT NULL,
  value       VARCHAR(40) NOT NULL,
  rows_n      INT NOT NULL,                  -- repo rows with this value
  packages_n  INT NOT NULL,                  -- distinct packages with this value
  PRIMARY KEY (run_id, dimension, value),
  CONSTRAINT fk_ss_run FOREIGN KEY (run_id)
    REFERENCES snapshot_summary_runs (run_id) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT chk_ss_dimension CHECK (dimension IN ('tier', 'risk', 'review'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- One row per compared pair of consecutive runs: a pair with a row here has
-- complete transitions, also when nothing changed.
CREATE TABLE IF NOT EXISTS snapshot_transition_pairs (
  prev_run_id    INT NOT NULL,
  run_id         INT NOT NULL,
  rows_both      INT NOT NULL,               -- repo rows in both runs
  rows_changed   INT NOT NULL,               -- of those, tier changed
  rows_new       INT NOT NULL,               -- only in run_id
  rows_gone      INT NOT NULL,               -- only in prev_run_id
  summarized_at  DATETIME NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (prev_run_id, run_id),
  KEY idx_stp_run (run_id),
  CONSTRAINT fk_stp_prev FOREIGN KEY (prev_run_id)
    REFERENCES scan_runs (run_id) ON DELETE RESTRICT ON UPDATE CASCADE,
  CONSTRAINT fk_stp_run FOREIGN KEY (run_id)
    REFERENCES scan_runs (run_id) ON DELETE RESTRICT ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Tier of the same versions row in the two runs ('(new)' / '(gone)' for rows
-- in only one of them). Unchanged tiers are kept too, as the denominator.
CREATE TABLE IF NOT EXISTS snapshot_transitions (
  prev_run_id  INT NOT NULL,
  run_id       INT NOT NULL,
  from_tier    VARCHAR(20) NOT NULL,
  to_tier      VARCHAR(20) NOT NULL,
  rows_n       INT NOT NULL,
  PRIMARY KEY (prev_run_id, run_id, from_tier, to_tier),
  CONSTRAINT fk_st_pair FOREIGN KEY (prev_run_id, run_id)
    REFERENCES snapshot_transition_pairs (prev_run_id, run_id) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
