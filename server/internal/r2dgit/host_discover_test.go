package r2dgit

import (
	"testing"
)

func TestParseKeyscanFingerprints(t *testing.T) {
	stdout := `github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl
`
	pins, err := parseKeyscanFingerprints([]byte(stdout))
	if err != nil {
		t.Fatalf("parseKeyscanFingerprints: %v", err)
	}
	if len(pins) != 1 {
		t.Fatalf("pins = %v, want 1", pins)
	}
	if !stringsHasPrefix(pins[0], "SHA256:") {
		t.Fatalf("pin %q missing SHA256 prefix", pins[0])
	}
}

func stringsHasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}
