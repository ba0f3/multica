package sandbox

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestNativeExecutionProfileHomeScopesByUser(t *testing.T) {
	baseHome := "/home/runtime"
	a := NativeRuntimeRequest{Home: baseHome, ExecutionUserID: "user-a"}
	b := NativeRuntimeRequest{Home: baseHome, ExecutionUserID: "user-b"}
	legacy := NativeRuntimeRequest{Home: baseHome}

	homeA := nativeExecutionProfileHome(a)
	homeB := nativeExecutionProfileHome(b)
	if homeA == homeB {
		t.Fatal("execution users must not share native profile home")
	}
	if nativeExecutionProfileHome(legacy) != baseHome {
		t.Fatalf("empty execution user keeps runtime home, got %q", nativeExecutionProfileHome(legacy))
	}
	if !strings.Contains(homeA, "multica-native-execution-profiles") {
		t.Fatalf("scoped home = %q, want multica-native-execution-profiles segment", homeA)
	}
}

func TestNativeProfilePathsIgnoreHostSelectorsWhenExecutionUserScoped(t *testing.T) {
	baseHome := "/home/runtime"
	hostCodex := "/shared/host/.codex"
	req := NativeRuntimeRequest{
		Home:            baseHome,
		Provider:        "codex",
		ExecutionUserID: "scoped-user",
		Env: map[string]string{
			"CODEX_HOME": hostCodex,
		},
	}
	var runtime NativeRuntime
	runtime.Env = make(map[string]string)
	paths, err := nativeProfilePaths(req, &runtime)
	if err != nil {
		t.Fatalf("nativeProfilePaths: %v", err)
	}
	if len(paths) != 1 {
		t.Fatalf("paths = %#v, want one codex profile dir", paths)
	}
	scopedHome := nativeExecutionProfileHome(req)
	want := filepath.Join(scopedHome, ".codex")
	if paths[0] != want {
		t.Fatalf("profile path = %q, want scoped fallback %q (not host %q)", paths[0], want, hostCodex)
	}
	if runtime.Env["CODEX_HOME"] != want {
		t.Fatalf("CODEX_HOME env = %q, want %q", runtime.Env["CODEX_HOME"], want)
	}
}
