-- 002a: review check mark. Additive, idempotent. MariaDB 10.4.
-- Run: mysql -u root -p sbom_common < migrations/002a_reviews.sql
SET NAMES utf8mb4;

CREATE TABLE IF NOT EXISTS package_reviews (
  review_id    INT NOT NULL AUTO_INCREMENT,
  package_id   INT NOT NULL,
  status       VARCHAR(30) NOT NULL DEFAULT 'Open',
  reviewer     VARCHAR(100) NULL,
  reviewed_at  DATETIME NULL,
  note         TEXT NULL,
  created_at   DATETIME NOT NULL DEFAULT current_timestamp(),
  updated_at   DATETIME NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (review_id),
  UNIQUE KEY uq_review_package (package_id),
  KEY idx_review_status (status),
  KEY idx_review_reviewed_at (reviewed_at),
  CONSTRAINT fk_review_package FOREIGN KEY (package_id)
    REFERENCES packages (package_id) ON DELETE RESTRICT ON UPDATE CASCADE,
  CONSTRAINT chk_review_status CHECK (status IN
    ('Open','Reviewed - Accepted','Compensating Control','Resolved'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE IF NOT EXISTS package_review_history (
  history_id   INT NOT NULL AUTO_INCREMENT,
  package_id   INT NOT NULL,
  old_status   VARCHAR(30) NULL,
  new_status   VARCHAR(30) NOT NULL,
  reviewer     VARCHAR(100) NOT NULL,
  note         TEXT NULL,
  changed_at   DATETIME NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (history_id),
  KEY idx_rh_package_time (package_id, changed_at),
  KEY idx_rh_new_status (new_status),
  KEY idx_rh_changed_at (changed_at),
  CONSTRAINT fk_rh_package FOREIGN KEY (package_id)
    REFERENCES packages (package_id) ON DELETE RESTRICT ON UPDATE CASCADE,
  CONSTRAINT chk_rh_new_status CHECK (new_status IN
    ('Open','Reviewed - Accepted','Compensating Control','Resolved')),
  CONSTRAINT chk_rh_old_status CHECK (old_status IS NULL OR old_status IN
    ('Open','Reviewed - Accepted','Compensating Control','Resolved'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Insert-only: history rows can never be changed or removed.
CREATE TRIGGER IF NOT EXISTS trg_rh_no_update
  BEFORE UPDATE ON package_review_history FOR EACH ROW
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'package_review_history is insert-only';
CREATE TRIGGER IF NOT EXISTS trg_rh_no_delete
  BEFORE DELETE ON package_review_history FOR EACH ROW
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'package_review_history is insert-only';

-- Reviews are never deleted (status changes are UPDATEs, logged to history).
CREATE TRIGGER IF NOT EXISTS trg_review_no_delete
  BEFORE DELETE ON package_reviews FOR EACH ROW
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'package_reviews rows are never deleted';

-- Seed: every existing package starts Open (safe to re-run).
INSERT IGNORE INTO package_reviews (package_id, status)
SELECT package_id, 'Open' FROM packages;
