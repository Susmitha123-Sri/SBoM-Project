-- 002b: name matching, labeled pairs, risk, priority, snapshots.
-- Additive, idempotent. MariaDB 10.4. Independent of 002a.
SET NAMES utf8mb4;

-- ---------- packages: name matching + risk + priority ----------
ALTER TABLE packages
  ADD COLUMN IF NOT EXISTS normalized_name        VARCHAR(255)  NULL,
  ADD COLUMN IF NOT EXISTS matched_name           VARCHAR(255)  NULL,
  ADD COLUMN IF NOT EXISTS match_ecosystem        VARCHAR(100)  NULL,
  ADD COLUMN IF NOT EXISTS match_method           VARCHAR(30)   NULL,
  ADD COLUMN IF NOT EXISTS match_score            DECIMAL(5,4)  NULL,
  ADD COLUMN IF NOT EXISTS match_status           VARCHAR(20)   NULL,
  ADD COLUMN IF NOT EXISTS matched_at             DATETIME      NULL,
  ADD COLUMN IF NOT EXISTS risk_score             DECIMAL(5,2)  NULL,
  ADD COLUMN IF NOT EXISTS risk_level             VARCHAR(10)   NULL,
  ADD COLUMN IF NOT EXISTS risk_reasons           VARCHAR(1000) NULL,
  ADD COLUMN IF NOT EXISTS risk_tier              VARCHAR(20)   NULL,
  ADD COLUMN IF NOT EXISTS risk_days_behind       INT           NULL,
  ADD COLUMN IF NOT EXISTS risk_vuln_count        INT           NULL,
  ADD COLUMN IF NOT EXISTS risk_is_abandoned      TINYINT(1)    NULL,
  ADD COLUMN IF NOT EXISTS installed_release_date DATE          NULL,
  ADD COLUMN IF NOT EXISTS latest_release_date    DATE          NULL,
  ADD COLUMN IF NOT EXISTS risk_version_id        INT           NULL,
  ADD COLUMN IF NOT EXISTS risk_model_version     VARCHAR(30)   NULL,
  ADD COLUMN IF NOT EXISTS risk_computed_at       DATETIME      NULL,
  ADD COLUMN IF NOT EXISTS priority_score         DECIMAL(6,2)  NULL,
  ADD COLUMN IF NOT EXISTS priority_rank          INT           NULL,
  ADD COLUMN IF NOT EXISTS priority_reason        VARCHAR(500)  NULL,
  ADD COLUMN IF NOT EXISTS priority_version_id    INT           NULL,
  ADD COLUMN IF NOT EXISTS priority_computed_at   DATETIME      NULL;

CREATE INDEX IF NOT EXISTS idx_pkg_normalized_name ON packages (normalized_name);
CREATE INDEX IF NOT EXISTS idx_pkg_match_status    ON packages (match_status);
CREATE INDEX IF NOT EXISTS idx_pkg_risk_level      ON packages (risk_level);
CREATE INDEX IF NOT EXISTS idx_pkg_risk_tier       ON packages (risk_tier);
CREATE INDEX IF NOT EXISTS idx_pkg_priority_rank   ON packages (priority_rank);
CREATE INDEX IF NOT EXISTS idx_pkg_priority_score  ON packages (priority_score);

-- ---------- labeled_pairs ----------
CREATE TABLE IF NOT EXISTS labeled_pairs (
  pair_id      INT NOT NULL AUTO_INCREMENT,
  name_a       VARCHAR(255) NOT NULL,
  ecosystem_a  VARCHAR(100) NULL,
  name_b       VARCHAR(255) NOT NULL,
  ecosystem_b  VARCHAR(100) NULL,
  label        VARCHAR(10)  NOT NULL,
  labeled_by   VARCHAR(100) NOT NULL,
  labeled_at   DATETIME NOT NULL DEFAULT current_timestamp(),
  source       VARCHAR(50)  NOT NULL DEFAULT 'manual',
  package_id   INT NULL,
  note         VARCHAR(500) NULL,
  PRIMARY KEY (pair_id),
  KEY idx_lp_pair (name_a, name_b),
  KEY idx_lp_label (label),
  KEY idx_lp_labeled_at (labeled_at),
  KEY idx_lp_package (package_id),
  CONSTRAINT fk_lp_package FOREIGN KEY (package_id)
    REFERENCES packages (package_id) ON DELETE SET NULL ON UPDATE CASCADE,
  CONSTRAINT chk_lp_label CHECK (label IN ('match','non-match'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- ---------- scan_runs ----------
CREATE TABLE IF NOT EXISTS scan_runs (
  run_id          INT NOT NULL AUTO_INCREMENT,
  snapshot_date   DATE NOT NULL DEFAULT curdate(),
  started_at      DATETIME NOT NULL DEFAULT current_timestamp(),
  finished_at     DATETIME NULL,
  status          VARCHAR(20) NOT NULL DEFAULT 'running',
  package_count   INT NULL,
  trigger_source  VARCHAR(30) NULL,
  notes           TEXT NULL,
  PRIMARY KEY (run_id),
  KEY idx_runs_date (snapshot_date),
  KEY idx_runs_status (status),
  CONSTRAINT chk_runs_status CHECK (status IN ('running','completed','failed','partial'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- ---------- package_snapshots ----------
CREATE TABLE IF NOT EXISTS package_snapshots (
  snapshot_id            INT NOT NULL AUTO_INCREMENT,
  run_id                 INT NOT NULL,
  package_id             INT NOT NULL,
  version_id             INT NULL,          -- source versions row (no FK, see plan)
  snapshot_date          DATE NOT NULL,
  package_name           VARCHAR(255) NULL,
  ecosystem              VARCHAR(100) NULL,
  installed_version      VARCHAR(100) NULL,
  latest_version         VARCHAR(100) NULL,
  version_status         VARCHAR(50)  NULL,
  age_tier               VARCHAR(20)  NULL,
  days_behind            INT NULL,
  days_since_release     INT NULL,
  versions_behind        VARCHAR(50)  NULL,
  installed_release_date DATE NULL,
  latest_release_date    DATE NULL,
  is_abandoned           TINYINT(1) NULL,
  vuln_count             INT NULL,
  normalized_name        VARCHAR(255) NULL,
  match_status           VARCHAR(20)  NULL,
  match_score            DECIMAL(5,4) NULL,
  risk_score             DECIMAL(5,2) NULL,
  risk_level             VARCHAR(10)  NULL,
  priority_score         DECIMAL(6,2) NULL,
  priority_rank          INT NULL,
  review_status          VARCHAR(30)  NULL,
  created_at             DATETIME NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (snapshot_id),
  UNIQUE KEY uq_snap_run_pkg (run_id, package_id),
  KEY idx_snap_date (snapshot_date),
  KEY idx_snap_pkg_date (package_id, snapshot_date),
  KEY idx_snap_tier (age_tier),
  KEY idx_snap_risk (risk_level),
  KEY idx_snap_review (review_status),
  CONSTRAINT fk_snap_run FOREIGN KEY (run_id)
    REFERENCES scan_runs (run_id) ON DELETE RESTRICT ON UPDATE CASCADE,
  CONSTRAINT fk_snap_package FOREIGN KEY (package_id)
    REFERENCES packages (package_id) ON DELETE RESTRICT ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Insert-only enforcement
CREATE TRIGGER IF NOT EXISTS trg_snap_no_update
  BEFORE UPDATE ON package_snapshots FOR EACH ROW
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'package_snapshots is insert-only';
CREATE TRIGGER IF NOT EXISTS trg_snap_no_delete
  BEFORE DELETE ON package_snapshots FOR EACH ROW
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'package_snapshots is insert-only';
-- scan_runs: the job closes a run with UPDATE (finished_at/status/count); deletes are blocked.
CREATE TRIGGER IF NOT EXISTS trg_runs_no_delete
  BEFORE DELETE ON scan_runs FOR EACH ROW
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'scan_runs rows are never deleted';
