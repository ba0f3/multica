package sandbox

import (
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
