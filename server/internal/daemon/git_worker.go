package daemon

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/multica-ai/multica/server/internal/daemon/execenv"
	"github.com/multica-ai/multica/server/internal/daemon/sandbox"
	"golang.org/x/crypto/ssh"
)

func taskWorkerGitEnvironment(task Task, socket string, env *execenv.Environment) (map[string]string, error) {
	values := map[string]string{"SSH_AUTH_SOCK": socket, "GIT_TERMINAL_PROMPT": "0", "GCM_INTERACTIVE": "never", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_KEY_0": "safe.directory", "GIT_CONFIG_VALUE_0": "*"}
	count := 1
	for _, rewrite := range taskGitURLRewrites(task, socket) {
		values["GIT_CONFIG_KEY_"+strconv.Itoa(count)] = rewrite.key
		values["GIT_CONFIG_VALUE_"+strconv.Itoa(count)] = rewrite.value
		count++
	}
	values["GIT_CONFIG_COUNT"] = strconv.Itoa(count)
	// Workers inherit public host trust, never SSH config or private keys.
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	var trusted strings.Builder
	for _, path := range []string{filepath.Join(home, ".ssh", "known_hosts"), "/etc/ssh/ssh_known_hosts"} {
		file, err := os.Open(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("read SSH host trust: %w", err)
		}
		scanner := bufio.NewScanner(io.LimitReader(file, 4<<20))
		scanner.Buffer(make([]byte, 4096), 1<<20)
		for scanner.Scan() {
			line := scanner.Text()
			if _, _, _, _, _, err := ssh.ParseKnownHosts([]byte(line + "\n")); err == nil {
				trusted.WriteString(line + "\n")
			}
		}
		_ = file.Close()
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("read SSH host trust: %w", err)
		}
	}
	path := filepath.Join(env.RootDir, "git-known-hosts")
	if err := os.WriteFile(path, []byte(trusted.String()), 0644); err != nil {
		return nil, err
	}
	env.GitKnownHostsPath = path
	values["GIT_SSH_COMMAND"] = sandbox.GitSSHCommand(path)
	return values, nil
}
