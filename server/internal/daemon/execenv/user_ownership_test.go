package execenv

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestExecutionUsersCannotAdoptEachOthersTaskRoot(t *testing.T) {
	root := t.TempDir()
	paramsFor := func(user string) RootDirParams {
		data, _ := json.Marshal(map[string]string{"WorkspacesRoot": root, "WorkspaceID": "workspace", "TaskID": "task", "ExecutionUserID": user})
		var params RootDirParams
		if err := json.Unmarshal(data, &params); err != nil {
			t.Fatal(err)
		}
		return params
	}
	a, err := ResolveRootDir(paramsFor("alice"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(a, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(a, "alice-code"), []byte("private"), 0600); err != nil {
		t.Fatal(err)
	}
	b, err := ResolveRootDir(paramsFor("bob"))
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("Bob was assigned Alice's existing task root")
	}
	again, err := ResolveRootDir(paramsFor("alice"))
	if err != nil || again != a {
		t.Fatalf("Alice lost her stable root: %s %v", again, err)
	}
	if _, err := os.Stat(filepath.Join(a, "alice-code")); err != nil {
		t.Fatal("existing user work was changed", err)
	}
}

func TestReuseRejectsWrongOrLegacyExecutionOwner(t *testing.T) {
	for _, ownerUser := range []string{"alice", ""} {
		t.Run("owner-"+ownerUser, func(t *testing.T) {
			root := t.TempDir()
			envRoot := filepath.Join(root, "workspace", "prior-task")
			work := filepath.Join(envRoot, "workdir")
			if err := os.MkdirAll(work, 0700); err != nil {
				t.Fatal(err)
			}
			data, err := json.Marshal(EnvRootOwner{WorkspaceID: "workspace", TaskID: "prior-task", ExecutionUserID: ownerUser})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(envRoot, envRootOwnerFile), data, 0600); err != nil {
				t.Fatal(err)
			}
			env := Reuse(ReuseParams{WorkspacesRoot: root, WorkspaceID: "workspace", ExecutionUserID: "bob", WorkDir: work}, testLogger())
			if env != nil {
				t.Fatal("reused a workdir without matching execution-user proof")
			}
			if _, err := os.Stat(filepath.Join(envRoot, "multica-config")); !os.IsNotExist(err) {
				t.Fatalf("declined reuse wrote into another user's environment: %v", err)
			}
		})
	}
}
