package r2dgit

import "context"

// Quarantine is monotonic. Deleting a repository, run or membership cannot
// establish that its historical comments, sessions and attachments were public.
func quarantineScopes(ctx context.Context, db Database, workspaces []string, users []string) error {
	for _, workspace := range workspaces {
		if _, err := db.Exec(ctx, `INSERT INTO r2d_git_source_quarantine(kind,subject_id) VALUES('workspace',$1) ON CONFLICT DO NOTHING`, workspace); err != nil {
			return err
		}
		if _, err := db.Exec(ctx, `INSERT INTO r2d_git_source_quarantine(kind,subject_id) SELECT 'audience',user_id FROM member WHERE workspace_id=$1 ON CONFLICT DO NOTHING`, workspace); err != nil {
			return err
		}
	}
	for _, user := range users {
		if _, err := db.Exec(ctx, `INSERT INTO r2d_git_source_quarantine(kind,subject_id) VALUES('audience',$1) ON CONFLICT DO NOTHING`, user); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) QuarantinedAudience(ctx context.Context, user string) (bool, error) {
	if err := s.checkRestore(ctx, s.Store.DB); err != nil {
		return true, err
	}
	var blocked bool
	err := s.Store.DB.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM r2d_git_source_quarantine q WHERE (q.kind='audience' AND q.subject_id=$1) OR (q.kind='workspace' AND EXISTS(SELECT 1 FROM member m WHERE m.workspace_id=q.subject_id AND m.user_id=$1)))`, user).Scan(&blocked)
	return blocked, err
}

func (s *Service) QuarantinedWorkspace(ctx context.Context, workspace string) (bool, error) {
	if err := s.checkRestore(ctx, s.Store.DB); err != nil {
		return true, err
	}
	var blocked bool
	err := s.Store.DB.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM r2d_git_source_quarantine WHERE kind='workspace' AND subject_id=$1) OR EXISTS(SELECT 1 FROM r2d_git_repository r JOIN project p ON p.id=r.project_id WHERE p.workspace_id=$1 AND r.protected)`, workspace).Scan(&blocked)
	return blocked, err
}

// Readerless media/plugin capabilities cannot prove a current Git reader. The
// protected instance refuses them, including legacy keys with unknown scope.
func (s *Service) ReaderlessSourceBlocked(ctx context.Context) (bool, error) {
	if err := s.checkRestore(ctx, s.Store.DB); err != nil {
		return true, err
	}
	var blocked bool
	err := s.Store.DB.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM r2d_git_source_quarantine) OR EXISTS(SELECT 1 FROM r2d_git_repository WHERE protected) OR EXISTS(SELECT 1 FROM r2d_git_restore_checkpoint)`).Scan(&blocked)
	return blocked, err
}
