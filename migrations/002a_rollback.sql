-- Rollback 002a. DESTROYS review data. Back up first:
--   mysqldump -u root -p sbom_common package_reviews package_review_history > reviews_backup.sql
DROP TRIGGER IF EXISTS trg_rh_no_update;
DROP TRIGGER IF EXISTS trg_rh_no_delete;
DROP TRIGGER IF EXISTS trg_review_no_delete;
DROP TABLE IF EXISTS package_review_history;
DROP TABLE IF EXISTS package_reviews;
