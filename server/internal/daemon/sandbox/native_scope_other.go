//go:build !linux

package sandbox

import (
	"context"
	"fmt"
	"os/exec"
)

func (s *NativeScope) Preflight(context.Context) error {
	return fmt.Errorf("native sandbox requires Linux")
}
func (s *NativeScope) Command(string, []string) (*exec.Cmd, error) {
	return nil, fmt.Errorf("native sandbox requires Linux")
}
func (s *NativeScope) Stop(context.Context, string) error {
	return fmt.Errorf("native sandbox requires Linux")
}
func StartNativeOwnedProcess(*exec.Cmd) (func(), error) {
	return nil, fmt.Errorf("native sandbox requires Linux")
}
func AcquireNativeProfileLease(context.Context, string, string) (*NativeProfileLease, error) {
	return nil, fmt.Errorf("native sandbox requires Linux")
}
