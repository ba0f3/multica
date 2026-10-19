DELETE FROM r2d_git_source_quarantine WHERE kind='execution';
ALTER TABLE IF EXISTS r2d_git_source_quarantine DROP CONSTRAINT IF EXISTS r2d_git_source_quarantine_kind_check;
ALTER TABLE IF EXISTS r2d_git_source_quarantine ADD CONSTRAINT r2d_git_source_quarantine_kind_check CHECK(kind IN ('workspace','audience','restore'));
