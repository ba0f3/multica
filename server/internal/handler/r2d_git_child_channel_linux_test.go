//go:build linux

package handler

import (
	"context"
	"github.com/multica-ai/multica/server/internal/r2dgit"
	"testing"
)

func TestR2DGitChildChannelHandoffUsesFreshIsolation(t *testing.T) {
	f := newGitWorkloadFixture(t)
	ctx := context.Background()
	root := f.admit(t, f.f.token, f.f.runRequest())
	parent, parentJob := f.start(t, root)
	parentClient, err := r2dgit.NewWorkloadClient(parentJob.socket)
	if err != nil {
		t.Fatal(err)
	}
	defer parentClient.Close()
	if _, _, err := parentClient.Prepare(ctx, "/usr/bin/git", t.TempDir()); err != nil {
		t.Fatal(err)
	}
	request := f.f.runRequest()
	request.AgentID = f.f.child
	id, err := parentClient.EnqueueChild(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	child, err := f.f.h.GitSecurity.GetRun(ctx, f.f.user, id)
	if err != nil {
		t.Fatal(err)
	}
	if child.Context.Binding.OriginatorUserID != f.f.user || child.Context.ParentID != root.Context.ID || child.Context.AttemptID == root.Context.AttemptID || child.Context.Binding.TaskID == root.Context.Binding.TaskID {
		t.Fatal("child changed human or inherited execution identity")
	}
	handle, job := f.start(t, child)
	if job.socket == parentJob.socket {
		t.Fatal("child inherited parent channel")
	}
	if _, err := parentClient.Submit(ctx, "artifact", "parent restricted result"); err != nil {
		t.Fatal(err)
	}
	f.engine.exit(parentJob, 0)
	if result := waitGitWorkload(t, parent); result.Err != nil {
		t.Fatal(result.Err)
	}
	client, err := r2dgit.NewWorkloadClient(job.socket)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, _, err := client.Prepare(ctx, "/usr/bin/git", t.TempDir()); err != nil {
		t.Fatal("normally completed parent revoked issued child", err)
	}
	output, err := client.Submit(ctx, "artifact", "child restricted result")
	if err != nil {
		t.Fatal(err)
	}
	f.engine.exit(job, 0)
	if result := waitGitWorkload(t, handle); result.Err != nil {
		t.Fatal(result.Err)
	}
	f.f.call(t, f.f.token, "GET", "/api/me/git-outputs/"+output, nil, 200)
	f.f.call(t, f.f.otherToken, "GET", "/api/me/git-outputs/"+output, nil, 404)
	if err := f.f.h.GitSecurity.RevokeRoot(ctx, f.f.user, root.Context.ID); err != nil {
		t.Fatal(err)
	}
	f.f.call(t, f.f.token, "GET", "/api/me/git-outputs/"+output, nil, 409)
}
