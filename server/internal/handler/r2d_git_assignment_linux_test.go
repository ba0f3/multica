//go:build linux

package handler

import (
	"context"
	"testing"
)

func TestR2DGitS5AssignmentRequiresExactFreshOperatorClassification(t *testing.T) {
	for _, change := range []string{"missing", "changed_bytes", "wrong_key", "restored"} {
		t.Run(change, func(t *testing.T) {
			f := newGitWorkloadFixture(t)
			run := f.admit(t, f.f.token, f.f.runRequest())
			switch change {
			case "missing":
				dbfx.Exec(t, `DELETE FROM r2d_git_security_event WHERE subject_id=$1 AND action='assignment_classified'`, f.f.issue)
			case "changed_bytes":
				dbfx.Exec(t, `UPDATE issue SET description='synthetic unclassified history' WHERE id=$1`, f.f.issue)
			case "wrong_key":
				dbfx.Exec(t, `UPDATE r2d_git_security_event SET details=jsonb_set(details,'{signature}','"AAAA"') WHERE subject_id=$1 AND action='assignment_classified'`, f.f.issue)
			case "restored":
				dbfx.Exec(t, `UPDATE r2d_git_security_event SET action='restore_invalidated_classification' WHERE subject_id=$1 AND action='assignment_classified'`, f.f.issue)
			}
			if _, err := f.app.Prepare(context.Background(), run.Context.ID); err == nil {
				t.Fatal("unclassified assignment reached workload")
			}
			select {
			case <-f.engine.started:
				t.Fatal("engine started before classification")
			default:
			}
			f.classifyAssignment(t, f.f.runRequest())
			_, _ = f.start(t, run)
			if err := f.app.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
