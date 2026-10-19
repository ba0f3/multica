package handler

import (
	"os/exec"
	"testing"
)

func TestProtectedControlBrowserLogic(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node unavailable for isolated browser-logic tests")
	}
	command := exec.Command(node, "--test", "protected_control_ui_test.cjs")
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("protected UI behavior: %v %s", err, out)
	}
}
