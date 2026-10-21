package daemon

import "testing"

func TestParseTaskSandboxEnv(t *testing.T) {
	for _, tc := range []struct {
		raw           string
		wantEnabled   bool
		wantBackend   string
	}{
		{raw: "", wantEnabled: true, wantBackend: "docker"},
		{raw: "docker", wantEnabled: true, wantBackend: "docker"},
		{raw: "bwrap", wantEnabled: true, wantBackend: "bwrap"},
		{raw: "1", wantEnabled: true, wantBackend: "docker"},
		{raw: "true", wantEnabled: true, wantBackend: "docker"},
		{raw: "false", wantEnabled: false, wantBackend: ""},
		{raw: "0", wantEnabled: false, wantBackend: ""},
		{raw: "off", wantEnabled: false, wantBackend: ""},
	} {
		enabled, backend := parseTaskSandboxEnv(tc.raw)
		if enabled != tc.wantEnabled || backend != tc.wantBackend {
			t.Fatalf("parseTaskSandboxEnv(%q) = (%v, %q), want (%v, %q)",
				tc.raw, enabled, backend, tc.wantEnabled, tc.wantBackend)
		}
	}
}
