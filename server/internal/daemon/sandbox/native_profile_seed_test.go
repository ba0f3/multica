package sandbox

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSeedNativeExecutionProfileCopiesAuth(t *testing.T) {
	root := t.TempDir()
	operatorHome := filepath.Join(root, "runtime")
	operatorCodex := filepath.Join(operatorHome, ".codex")
	if err := os.MkdirAll(operatorCodex, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(operatorCodex, "auth.json"), []byte(`{"token":"operator"}`), 0600); err != nil {
		t.Fatal(err)
	}
	req := NativeRuntimeRequest{
		Home:            operatorHome,
		Provider:        "codex",
		ExecutionUserID: "user-a",
		Env: map[string]string{
			"CODEX_HOME": operatorCodex,
		},
	}
	var runtime NativeRuntime
	runtime.Env = make(map[string]string)
	scopedPaths, err := nativeProfilePaths(req, &runtime)
	if err != nil {
		t.Fatalf("nativeProfilePaths: %v", err)
	}
	if err := seedNativeExecutionProfile(req, scopedPaths); err != nil {
		t.Fatalf("seedNativeExecutionProfile: %v", err)
	}
	scopedHome := nativeExecutionProfileHome(req)
	authPath := filepath.Join(scopedHome, ".codex", "auth.json")
	data, err := os.ReadFile(authPath)
	if err != nil {
		t.Fatalf("read scoped auth: %v", err)
	}
	if string(data) != `{"token":"operator"}` {
		t.Fatalf("scoped auth = %q", string(data))
	}
}

func TestSeedNativeExecutionProfileCopiesCustomCodexSelector(t *testing.T) {
	root := t.TempDir()
	operatorHome := filepath.Join(root, "runtime")
	operatorCodex := filepath.Join(root, "srv", "codex-account")
	if err := os.MkdirAll(operatorCodex, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(operatorCodex, "auth.json"), []byte(`{"token":"external"}`), 0600); err != nil {
		t.Fatal(err)
	}
	req := NativeRuntimeRequest{
		Home:            operatorHome,
		Provider:        "codex",
		ExecutionUserID: "user-a",
		Env: map[string]string{
			"CODEX_HOME": operatorCodex,
		},
	}
	var runtime NativeRuntime
	runtime.Env = make(map[string]string)
	scopedPaths, err := nativeProfilePaths(req, &runtime)
	if err != nil {
		t.Fatalf("nativeProfilePaths: %v", err)
	}
	if err := seedNativeExecutionProfile(req, scopedPaths); err != nil {
		t.Fatalf("seedNativeExecutionProfile: %v", err)
	}
	authPath := filepath.Join(scopedPaths[0], "auth.json")
	data, err := os.ReadFile(authPath)
	if err != nil {
		t.Fatalf("read scoped auth: %v", err)
	}
	if string(data) != `{"token":"external"}` {
		t.Fatalf("scoped auth = %q", string(data))
	}
}


func TestSeedNativeExecutionProfileCopiesCustomCursorData(t *testing.T) {
	root := t.TempDir()
	operatorHome := filepath.Join(root, "runtime")
	operatorData := filepath.Join(root, "srv", "cursor-data")
	if err := os.MkdirAll(operatorData, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(operatorData, "credentials.json"), []byte(`{"token":"cursor-external"}`), 0600); err != nil {
		t.Fatal(err)
	}
	req := NativeRuntimeRequest{
		Home:            operatorHome,
		Provider:        "cursor",
		ExecutionUserID: "user-a",
		Env: map[string]string{
			"CURSOR_DATA_DIR": operatorData,
		},
	}
	var runtime NativeRuntime
	runtime.Env = make(map[string]string)
	scopedPaths, err := nativeProfilePaths(req, &runtime)
	if err != nil {
		t.Fatalf("nativeProfilePaths: %v", err)
	}
	if err := seedNativeExecutionProfile(req, scopedPaths); err != nil {
		t.Fatalf("seedNativeExecutionProfile: %v", err)
	}
	scopedData := runtime.Env["CURSOR_DATA_DIR"]
	if scopedData == "" || scopedData == operatorData {
		t.Fatalf("CURSOR_DATA_DIR = %q, want isolated scoped path", scopedData)
	}
	data, err := os.ReadFile(filepath.Join(scopedData, "credentials.json"))
	if err != nil {
		t.Fatalf("read scoped cursor credentials: %v", err)
	}
	if string(data) != `{"token":"cursor-external"}` {
		t.Fatalf("scoped cursor credentials = %q", string(data))
	}
}
