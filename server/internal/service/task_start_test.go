package service

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	db "github.com/multica-ai/multica/server/pkg/db/generated"
)

type startReplayDB struct {
	pgx.Tx
	startErr   error
	calls      int
	policyErr  error
	protected  pgtype.Bool
	rolledBack bool
	committed  bool
}

func (m *startReplayDB) Begin(context.Context) (pgx.Tx, error) { return m, nil }
func (m *startReplayDB) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.NewCommandTag("SELECT 1"), nil
}
func (m *startReplayDB) Rollback(context.Context) error { m.rolledBack = true; return nil }
func (m *startReplayDB) Commit(context.Context) error   { m.committed = true; return nil }

type startPolicyRow struct {
	value pgtype.Bool
	err   error
}

func (r startPolicyRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	*dest[0].(*pgtype.Bool) = r.value
	return nil
}

func (m *startReplayDB) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	if strings.Contains(sql, "-- name: IsR2DGitProtectedTask") {
		return startPolicyRow{value: m.protected, err: m.policyErr}
	}
	m.calls++
	return &mockRow{err: m.startErr}
}

func TestStartTaskLegacyDoesNotAcknowledgeReplayOrDatabaseFailure(t *testing.T) {
	for _, want := range []error{pgx.ErrNoRows, errors.New("database unavailable")} {
		store := &startReplayDB{startErr: want, protected: pgtype.Bool{Valid: true}}
		svc := &TaskService{Queries: db.New(store), TxStarter: store}
		got, err := svc.StartTask(context.Background(), testUUID(1))
		if got != nil || !errors.Is(err, want) || store.calls != 1 || store.committed || !store.rolledBack {
			t.Fatalf("legacy start: task=%v err=%v queries=%d", got, err, store.calls)
		}
	}
}

func TestStartTaskLegacyFailsClosedWithoutPolicyOrTransaction(t *testing.T) {
	store := &startReplayDB{}
	svc := &TaskService{Queries: db.New(store)}
	if task, err := svc.StartTask(context.Background(), testUUID(1)); task != nil || err == nil || store.calls != 0 {
		t.Fatalf("missing transaction adapter: task=%v err=%v writes=%d", task, err, store.calls)
	}
	for _, tc := range []struct {
		name  string
		value pgtype.Bool
		err   error
	}{
		{name: "protected", value: pgtype.Bool{Bool: true, Valid: true}},
		{name: "unknown"},
		{name: "policy unavailable", err: errors.New("policy unavailable")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := &startReplayDB{protected: tc.value, policyErr: tc.err}
			svc := &TaskService{Queries: db.New(store), TxStarter: store}
			if task, err := svc.StartTask(context.Background(), testUUID(1), true); task != nil || err == nil || store.calls != 0 || store.committed || !store.rolledBack {
				t.Fatalf("denied start: task=%v err=%v writes=%d committed=%t rollback=%t", task, err, store.calls, store.committed, store.rolledBack)
			}
		})
	}
}
