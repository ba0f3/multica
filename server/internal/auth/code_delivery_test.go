package auth

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"strings"
	"testing"
	"time"
)

func TestSMTPCodeDeliveryUsesVerifiedTLSAndFixedAuthenticationBody(t *testing.T) {
	certificate := httptest.NewTLSServer(http.NotFoundHandler())
	roots := x509.NewCertPool()
	roots.AddCert(certificate.Certificate())
	conf := &tls.Config{Certificates: certificate.TLS.Certificates, MinVersion: tls.VersionTLS13}
	certificate.Close()
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener := tls.NewListener(raw, conf)
	defer listener.Close()
	body := make(chan string, 1)
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		reader := bufio.NewReader(conn)
		_, err = io.WriteString(conn, "220 fixture ESMTP\r\n")
		for err == nil {
			var line string
			line, err = reader.ReadString('\n')
			if err != nil {
				break
			}
			switch {
			case strings.HasPrefix(line, "EHLO "):
				_, err = io.WriteString(conn, "250-fixture\r\n250 AUTH PLAIN\r\n")
			case strings.HasPrefix(line, "AUTH PLAIN "):
				proof, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(strings.TrimPrefix(line, "AUTH PLAIN ")))
				if string(proof) != "\x00synthetic-smtp-user\x00synthetic-smtp-password" {
					t.Error("wrong SMTP identity")
				}
				_, err = io.WriteString(conn, "235 authenticated\r\n")
			case strings.HasPrefix(line, "MAIL FROM:"), strings.HasPrefix(line, "RCPT TO:"):
				_, err = io.WriteString(conn, "250 ok\r\n")
			case line == "DATA\r\n":
				_, err = io.WriteString(conn, "354 continue\r\n")
				if err != nil {
					break
				}
				var message []byte
				message, err = textproto.NewReader(reader).ReadDotBytes()
				if err == nil {
					body <- string(message)
					_, err = io.WriteString(conn, "250 accepted\r\n")
				}
			case line == "QUIT\r\n":
				_, err = io.WriteString(conn, "221 bye\r\n")
				done <- err
				return
			default:
				t.Error("unexpected SMTP command")
				_, err = io.WriteString(conn, "500 unavailable\r\n")
			}
		}
		done <- err
	}()
	sender := SMTPCodeDelivery{Address: listener.Addr().String(), From: "signin@fixture.invalid", Username: "synthetic-smtp-user", Password: "synthetic-smtp-password", TLS: &tls.Config{RootCAs: roots, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS13}}
	if err := sender.DeliverCode(context.Background(), "human@fixture.invalid", "123456"); err != nil {
		t.Fatal(err)
	}
	select {
	case message := <-body:
		want := "From: signin@fixture.invalid\nTo: human@fixture.invalid\nSubject: Multica sign-in code\nMIME-Version: 1.0\nContent-Type: text/plain; charset=utf-8\n\nYour Multica sign-in code is 123456. It expires in three minutes.\n"
		if message != want {
			t.Fatalf("unexpected authentication body %q", message)
		}
	case <-time.After(time.Second):
		t.Fatal("missing authentication delivery")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ recipient, code string }{{"human@fixture.invalid", "source-narrative"}, {"human@fixture.invalid", "123456\r\nBcc: other@invalid"}, {"human@fixture.invalid\r\nBcc: other@invalid", "123456"}, {"Name <human@fixture.invalid>", "123456"}} {
		if err := sender.DeliverCode(context.Background(), c.recipient, c.code); err == nil {
			t.Fatal("arbitrary source/mail header accepted")
		}
	}
	insecure := sender
	insecure.TLS = sender.TLS.Clone()
	insecure.TLS.InsecureSkipVerify = true
	if err := insecure.DeliverCode(context.Background(), "human@fixture.invalid", "123456"); err == nil {
		t.Fatal("unverified TLS accepted")
	}
}

func TestSMTPCodeDeliveryCancellationIsBounded(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			defer conn.Close()
			_, _ = io.Copy(io.Discard, conn)
		}
		close(done)
	}()
	sender := SMTPCodeDelivery{Address: listener.Addr().String(), From: "signin@fixture.invalid", TLS: &tls.Config{ServerName: "127.0.0.1", MinVersion: tls.VersionTLS13}}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := sender.DeliverCode(ctx, "human@fixture.invalid", "123456"); err == nil {
		t.Fatal("stalled handshake succeeded")
	}
	if time.Since(start) > time.Second {
		t.Fatal("authentication delivery ignored cancellation")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("stalled connection retained")
	}
}
