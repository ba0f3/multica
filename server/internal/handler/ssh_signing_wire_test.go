package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/multica-ai/multica/server/internal/daemon"
	"github.com/multica-ai/multica/server/internal/middleware"
	"github.com/multica-ai/multica/server/internal/testutil"
)

// Use the real daemon client against the authenticated HTTP handlers. A
// handler-only test with a hand-written modern payload missed the legacy
// attempt_id field that the actual daemon still sends.
func TestSSHSigningWireContractAndLifecycle(t *testing.T) {
	for _, transition := range []string{"attempt", "redispatch", "completed", "failed", "cancelled"} {
		t.Run(transition, func(t *testing.T) {
			if testHandler == nil || testPool == nil {
				t.Skip("database not available")
			}
			signing := installGitSigningService(t)
			provider := newGitTestProvider(t, "github", "github.com")
			identity, err := signing.Generate(t.Context(), testUserID, provider, "wire-"+transition, nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := signing.Verify(t.Context(), testUserID, identity.ID, identity.Generation); err != nil {
				t.Fatal(err)
			}
			runtimeID := dbfx.Runtime(t, "wire signing", testutil.Cols{"daemon_id": testDaemonID})
			agentID := dbfx.Agent(t, "wire signing", runtimeID)
			issueID := dbfx.Issue(t, "wire signing")
			taskID := dbfx.Task(t, agentID, testutil.Cols{
				"runtime_id": runtimeID, "issue_id": issueID, "status": "queued",
				"originator_user_id": testUserID, "accountable_user_id": testUserID,
			})
			claim := withURLParam(newRequest(http.MethodPost, "/api/daemon/runtimes/"+runtimeID+"/tasks/claim", map[string]any{}), "runtimeId", runtimeID)
			var claimed struct {
				Task *AgentTaskResponse `json:"task"`
			}
			testutil.Call(t, testHandler.ClaimTaskByRuntime, claim).Want(http.StatusOK).JSON(&claimed)
			if claimed.Task == nil || claimed.Task.GitSigningDaemonToken == "" {
				t.Fatal("claim did not return a supervisor credential")
			}
			token := claimed.Task.GitSigningDaemonToken
			router := chi.NewRouter()
			router.Use(middleware.DaemonAuth(testHandler.Queries, nil, nil, nil))
			router.Post("/api/daemon/tasks/{taskId}/git-signing-lease", testHandler.OpenGitSigningLease)
			router.Post("/api/daemon/git-signatures", testHandler.SignGitData)
			router.Post("/api/daemon/git-signing-lease/renew", testHandler.RenewGitSigningLease)
			server := httptest.NewServer(router)
			t.Cleanup(server.Close)
			client := daemon.NewClient(server.URL)
			t.Cleanup(client.CloseIdleConnections)
			lease, err := client.OpenGitSigningLease(t.Context(), taskID, "forged-client-attempt", provider, token)
			if err != nil {
				t.Fatalf("actual daemon request must be compatible: %v", err)
			}
			row, err := testHandler.Queries.GetAgentTask(t.Context(), parseUUID(taskID))
			if err != nil {
				t.Fatal(err)
			}
			boundTask, boundAttempt, err := signing.LeaseScope(t.Context(), lease.LeaseID, testDaemonID)
			if err != nil || boundTask != taskID || boundAttempt != taskSigningAttemptID(row.Attempt, row.DispatchedAt) {
				t.Fatalf("server authority mismatch: task=%q attempt=%q err=%v", boundTask, boundAttempt, err)
			}
			if _, err := client.SignGitData(t.Context(), lease.LeaseID, []byte("positive control"), token); err != nil {
				t.Fatalf("current attempt could not sign: %v", err)
			}
			post := func(path string, body map[string]string, want int) {
				t.Helper()
				data, err := json.Marshal(body)
				if err != nil {
					t.Fatal(err)
				}
				req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+path, bytes.NewReader(data))
				if err != nil {
					t.Fatal(err)
				}
				req.Header.Set("Authorization", "Bearer "+token)
				req.Header.Set("Content-Type", "application/json")
				response, err := server.Client().Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer response.Body.Close()
				if response.StatusCode != want {
					t.Fatalf("%s returned %d, want %d", path, response.StatusCode, want)
				}
			}
			renewPath := "/api/daemon/git-signing-lease/renew"
			post(renewPath, map[string]string{"lease_id": lease.LeaseID}, http.StatusNoContent)
			openPath := "/api/daemon/tasks/" + taskID + "/git-signing-lease"
			// Omitting the legacy field remains compatible; arbitrary authority
			// fields remain rejected by the strict decoder.
			post(openPath, map[string]string{"provider_id": provider}, http.StatusOK)
			post(openPath, map[string]string{"provider_id": provider, "user_id": "victim"}, http.StatusBadRequest)

			switch transition {
			case "attempt":
				dbfx.Exec(t, `UPDATE agent_task_queue SET attempt=attempt+1 WHERE id=$1`, taskID)
			case "redispatch":
				dbfx.Exec(t, `UPDATE agent_task_queue SET dispatched_at=dispatched_at+interval '1 second' WHERE id=$1`, taskID)
			default:
				dbfx.Exec(t, `UPDATE agent_task_queue SET status=$2 WHERE id=$1`, taskID, transition)
			}
			post("/api/daemon/git-signatures", map[string]string{"lease_id": lease.LeaseID, "data": "ZGF0YQ=="}, http.StatusForbidden)
			post(renewPath, map[string]string{"lease_id": lease.LeaseID}, http.StatusForbidden)
			if transition == "attempt" || transition == "redispatch" {
				fresh, err := client.OpenGitSigningLease(t.Context(), taskID, "another-untrusted-local-id", provider, token)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := client.SignGitData(t.Context(), fresh.LeaseID, []byte("new attempt"), token); err != nil {
					t.Fatalf("new current attempt must remain usable: %v", err)
				}
			} else {
				post(openPath, map[string]string{"provider_id": provider}, http.StatusForbidden)
			}
		})
	}
}
