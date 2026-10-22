package r2dgit

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"os/exec"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// DiscoverSSHHostKeys returns SHA256 fingerprints of the SSH host keys offered
// at host:port. The Multica server performs the lookup so operators do not
// need to run ssh-keyscan themselves.
func DiscoverSSHHostKeys(ctx context.Context, host string, port int) ([]string, error) {
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "" {
		return nil, ErrScope
	}
	if port <= 0 {
		port = 22
	}
	if port >= 65536 {
		return nil, ErrScope
	}

	if pins, err := discoverHostKeysViaKeyscan(ctx, host, port); err == nil && len(pins) > 0 {
		return pins, nil
	}
	return discoverHostKeysViaSSH(ctx, host, port)
}

func discoverHostKeysViaKeyscan(ctx context.Context, host string, port int) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	cmd := exec.CommandContext(
		ctx,
		"ssh-keyscan",
		"-p", fmt.Sprintf("%d", port),
		"-t", "rsa,ecdsa,ed25519",
		host,
	)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	return parseKeyscanFingerprints(stdout.Bytes())
}

func parseKeyscanFingerprints(stdout []byte) ([]string, error) {
	seen := map[string]struct{}{}
	var pins []string
	scanner := bufio.NewScanner(bytes.NewReader(stdout))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		keyLine := fields[1] + " " + fields[2]
		keyBlob, _, _, _, err := ssh.ParseAuthorizedKey([]byte(keyLine))
		if err != nil {
			continue
		}
		pin := ssh.FingerprintSHA256(keyBlob)
		if _, ok := seen[pin]; ok {
			continue
		}
		seen[pin] = struct{}{}
		pins = append(pins, pin)
	}
	if len(pins) == 0 {
		return nil, ErrProvider
	}
	sort.Strings(pins)
	return pins, nil
}

func discoverHostKeysViaSSH(ctx context.Context, host string, port int) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	algorithms := []string{
		ssh.KeyAlgoED25519,
		ssh.KeyAlgoECDSA256,
		ssh.KeyAlgoRSASHA256,
	}
	seen := map[string]struct{}{}
	var pins []string
	for _, algo := range algorithms {
		pin, err := fingerprintForAlgorithm(ctx, addr, host, algo)
		if err != nil {
			continue
		}
		if _, ok := seen[pin]; ok {
			continue
		}
		seen[pin] = struct{}{}
		pins = append(pins, pin)
	}
	if len(pins) == 0 {
		return nil, ErrProvider
	}
	sort.Strings(pins)
	return pins, nil
}

func fingerprintForAlgorithm(ctx context.Context, addr, host, algorithm string) (string, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	var captured ssh.PublicKey
	config := &ssh.ClientConfig{
		User: "git",
		Auth: []ssh.AuthMethod{},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			captured = key
			return nil
		},
		HostKeyAlgorithms: []string{algorithm},
		Timeout:           10 * time.Second,
	}
	sshConn, _, _, err := ssh.NewClientConn(conn, host, config)
	if sshConn != nil {
		sshConn.Close()
	}
	if captured == nil {
		return "", err
	}
	return ssh.FingerprintSHA256(captured), nil
}
