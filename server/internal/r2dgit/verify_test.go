package r2dgit

import (
	"bytes"
	cryptorand "crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"

	"golang.org/x/crypto/ssh"
)

const (
	githubBannerFixture = "Hi octocat! You've successfully authenticated, but GitHub does not provide shell access."

	giteaBannerFixture = "Hi there, alice! You've successfully authenticated with the SSH key named laptop.\n" +
		"Gitea does not provide shell access. If this is unexpected, please setup Gitea under another SSH user or use container to deploy."
)

func TestParseProviderLoginRecognizesGitHub(t *testing.T) {
	login, err := ParseProviderLogin("github", githubBannerFixture)
	if err != nil {
		t.Fatalf("ParseProviderLogin: %v", err)
	}
	if login != "octocat" {
		t.Fatalf("login = %q, want %q", login, "octocat")
	}
}

func TestParseProviderLoginRecognizesGitea(t *testing.T) {
	login, err := ParseProviderLogin("gitea", giteaBannerFixture)
	if err != nil {
		t.Fatalf("ParseProviderLogin: %v", err)
	}
	if login != "alice" {
		t.Fatalf("login = %q, want %q", login, "alice")
	}
}

func TestParseProviderLoginRecognizesLegacyGiteaBanner(t *testing.T) {
	banner := "Hi there, alice! You've successfully authenticated with the key named laptop.\n" +
		"Gitea does not provide shell access.\n" +
		"If this is unexpected, please log in with password and setup Gitea under another user."
	login, err := ParseProviderLogin("gitea", banner)
	if err != nil {
		t.Fatalf("ParseProviderLogin: %v", err)
	}
	if login != "alice" {
		t.Fatalf("login = %q, want %q", login, "alice")
	}
}

func TestParseProviderLoginRejectsTheOtherProvidersBanner(t *testing.T) {
	if _, err := ParseProviderLogin("gitea", githubBannerFixture); !errors.Is(err, ErrIdentity) {
		t.Fatalf("GitHub banner parsed as Gitea: err = %v, want %v", err, ErrIdentity)
	}
	if _, err := ParseProviderLogin("github", giteaBannerFixture); !errors.Is(err, ErrIdentity) {
		t.Fatalf("Gitea banner parsed as GitHub: err = %v, want %v", err, ErrIdentity)
	}
}

func TestParseProviderLoginRejectsIncompleteBanners(t *testing.T) {
	cases := map[string]string{
		"empty":                  "",
		"truncated":              "Hi octocat! You've successfully authenticated",
		"missing sentence":       "Hi octocat!",
		"extra text":             githubBannerFixture + " and more",
		"gitea without key line": "Hi there, alice!\nGitea does not provide shell access.",
	}
	for name, banner := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseProviderLogin("github", banner); err == nil && name != "gitea without key line" {
				t.Fatal("expected the incomplete banner to be refused")
			}
			if _, err := ParseProviderLogin("gitea", banner); err == nil && name == "gitea without key line" {
				t.Fatal("expected the truncated Gitea banner to be refused")
			}
		})
	}
}

func TestParseProviderLoginRejectsAnUnknownProvider(t *testing.T) {
	if _, err := ParseProviderLogin("bitbucket", githubBannerFixture); !errors.Is(err, ErrProvider) {
		t.Fatalf("err = %v, want %v", err, ErrProvider)
	}
}

func TestProviderSuccessExitMatchesTheDocumentedStatus(t *testing.T) {
	if !ProviderSuccessExit("github", 1) {
		t.Fatal("GitHub reports a successful authentication with exit status 1")
	}
	if ProviderSuccessExit("github", 0) {
		t.Fatal("GitHub must not accept exit status 0 as proof")
	}
	if !ProviderSuccessExit("gitea", 0) {
		t.Fatal("Gitea reports a successful authentication with exit status 0")
	}
	if ProviderSuccessExit("gitea", 1) {
		t.Fatal("Gitea must not accept exit status 1 as proof")
	}
	if ProviderSuccessExit("bitbucket", 0) {
		t.Fatal("an unknown provider has no accepted exit status")
	}
}

func TestPinnedHostKeyCallbackAcceptsOnlyPinnedFingerprints(t *testing.T) {
	allowedKey := testPublicKey(t)
	otherKey := testOtherPublicKey(t)

	pinned, err := pinnedHostKeyCallback([]string{ssh.FingerprintSHA256(allowedKey)})
	if err != nil {
		t.Fatalf("pinnedHostKeyCallback: %v", err)
	}
	other, err := pinnedHostKeyCallback([]string{ssh.FingerprintSHA256(otherKey)})
	if err != nil {
		t.Fatalf("pinnedHostKeyCallback: %v", err)
	}

	if err := pinned("github.com", &net.TCPAddr{}, allowedKey); err != nil {
		t.Fatalf("the pinned key was refused: %v", err)
	}
	if err := pinned("github.com", &net.TCPAddr{}, otherKey); !errors.Is(err, ErrProvider) {
		t.Fatalf("an unpinned key was accepted: err = %v, want %v", err, ErrProvider)
	}
	if err := other("github.com", &net.TCPAddr{}, allowedKey); !errors.Is(err, ErrProvider) {
		t.Fatalf("a key from another pin set was accepted: err = %v, want %v", err, ErrProvider)
	}
}

func TestPinnedHostKeyCallbackRequiresAtLeastOnePin(t *testing.T) {
	if _, err := pinnedHostKeyCallback(nil); !errors.Is(err, ErrProvider) {
		t.Fatalf("err = %v, want %v", err, ErrProvider)
	}
	if _, err := pinnedHostKeyCallback([]string{"  "}); !errors.Is(err, ErrProvider) {
		t.Fatalf("err = %v, want %v", err, ErrProvider)
	}
}

func TestSSHVerifierRefusesAProviderWithoutPins(t *testing.T) {
	verifier := NewSSHVerifier(newFakeCustody())
	_, err := verifier.Verify(t.Context(), Provider{ID: "p", Kind: "github", Host: "github.com", Port: 22}, "ref", 1)
	if !errors.Is(err, ErrProvider) {
		t.Fatalf("err = %v, want %v", err, ErrProvider)
	}
}

func testPublicKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	return parseGeneratedKey(t)
}

func testOtherPublicKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	return parseGeneratedKey(t)
}

func parseGeneratedKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	material, err := GenerateKeyMaterial(cryptorand.Reader)
	if err != nil {
		t.Fatalf("GenerateKeyMaterial: %v", err)
	}
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(material.PublicKey))
	if err != nil {
		t.Fatalf("parse authorized key: %v", err)
	}
	return key
}

func TestSSHVerifierProviderShellGreeting(t *testing.T) {
	for _, tc := range []struct {
		name, kind, greeting, login string
		stderr                      bool
		exit                        uint32
		wantErr                     bool
	}{
		{"github stdout", "github", githubBannerFixture, "octocat", false, 1, false},
		{"github stderr", "github", githubBannerFixture, "octocat", true, 1, false},
		{"gitea stdout", "gitea", giteaBannerFixture, "alice", false, 0, false},
		{"github wrong status", "github", githubBannerFixture, "", false, 0, true},
		{"github invalid greeting", "github", "Invalid command: true", "", false, 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			material, err := GenerateKeyMaterial(cryptorand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			signer, err := ssh.ParsePrivateKey(material.Private)
			if err != nil {
				t.Fatal(err)
			}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			config := &ssh.ServerConfig{PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
				if meta.User() != "git" || !bytes.Equal(key.Marshal(), signer.PublicKey().Marshal()) {
					return nil, errors.New("unexpected identity")
				}
				return nil, nil
			}}
			config.AddHostKey(signer)
			done := make(chan error, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					done <- err
					return
				}
				defer conn.Close()
				server, channels, requests, err := ssh.NewServerConn(conn, config)
				if err != nil {
					done <- err
					return
				}
				defer server.Close()
				go ssh.DiscardRequests(requests)
				incoming := <-channels
				channel, reqs, err := incoming.Accept()
				if err != nil {
					done <- err
					return
				}
				defer channel.Close()
				req := <-reqs
				req.Reply(true, nil)
				if req.Type != "shell" {
					fmt.Fprintln(channel.Stderr(), "Invalid command: true")
					channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{1}))
					done <- fmt.Errorf("expected shell request, got %s", req.Type)
					return
				}
				var output io.Writer = channel
				if tc.stderr {
					output = channel.Stderr()
				}
				fmt.Fprintln(output, tc.greeting)
				channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{tc.exit}))
				done <- nil
			}()
			custody := newFakeCustody()
			custody.signing = true
			custody.stored["ref"] = material
			address := listener.Addr().(*net.TCPAddr)
			login, err := NewSSHVerifier(custody).Verify(t.Context(), Provider{Kind: tc.kind, Host: "127.0.0.1", Port: address.Port, HostPins: []string{ssh.FingerprintSHA256(signer.PublicKey())}}, "ref", 1)
			if serverErr := <-done; serverErr != nil {
				t.Error(serverErr)
			}
			if tc.wantErr {
				if !errors.Is(err, ErrIdentity) {
					t.Fatalf("error = %v, want ErrIdentity", err)
				}
			} else if err != nil || login != tc.login {
				t.Fatalf("login = %q, error = %v", login, err)
			}
		})
	}
}
