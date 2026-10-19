package auth

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/mail"
	"net/smtp"
	"strings"
	"time"
)

// CodeDelivery has no arbitrary subject, template, attachment or source body.
// Protected authentication uses this narrow channel while legacy mail stays held.
type CodeDelivery interface {
	DeliverCode(context.Context, string, string) error
}

// SMTPCodeDelivery is explicitly configured; it never reads ambient mail settings.
// TLS and server certificate verification are mandatory, including for fixtures.
type SMTPCodeDelivery struct {
	Address, From, Username, Password string
	TLS                               *tls.Config
}

func (s SMTPCodeDelivery) DeliverCode(ctx context.Context, recipient, code string) error {
	if len(code) != 6 {
		return fmt.Errorf("invalid authentication message")
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			return fmt.Errorf("invalid authentication message")
		}
	}
	if err := s.Validate(); err != nil {
		return err
	}
	address, err := mail.ParseAddress(recipient)
	if err != nil || address.Address != recipient || len(recipient) > 254 || strings.ContainsAny(recipient, "\r\n") {
		return fmt.Errorf("invalid authentication message")
	}
	host, _, _ := net.SplitHostPort(s.Address)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	dialer := tls.Dialer{NetDialer: &net.Dialer{Timeout: 5 * time.Second}, Config: s.TLS.Clone()}
	conn, err := dialer.DialContext(ctx, "tcp", s.Address)
	if err != nil {
		return fmt.Errorf("authentication delivery unavailable")
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	client, err := smtp.NewClient(conn, host)
	if err != nil {
		return fmt.Errorf("authentication delivery unavailable")
	}
	defer client.Close()
	if s.Username != "" {
		if err = client.Auth(smtp.PlainAuth("", s.Username, s.Password, host)); err != nil {
			return fmt.Errorf("authentication delivery unavailable")
		}
	}
	if client.Mail(s.From) != nil || client.Rcpt(recipient) != nil {
		return fmt.Errorf("authentication delivery unavailable")
	}
	data, err := client.Data()
	if err != nil {
		return fmt.Errorf("authentication delivery unavailable")
	}
	body := "From: " + s.From + "\r\nTo: " + recipient + "\r\nSubject: Multica sign-in code\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nYour Multica sign-in code is " + code + ". It expires in three minutes.\r\n"
	if _, err = io.WriteString(data, body); err != nil {
		return fmt.Errorf("authentication delivery unavailable")
	}
	if data.Close() != nil || client.Quit() != nil {
		return fmt.Errorf("authentication delivery unavailable")
	}
	return nil
}

// Validate performs no network or credential operation and is used before the
// local serving composition constructs its protected worker.
func (s SMTPCodeDelivery) Validate() error {
	host, _, err := net.SplitHostPort(s.Address)
	address, addressErr := mail.ParseAddress(s.From)
	if err != nil || addressErr != nil || address.Address != s.From || len(s.From) > 254 || strings.ContainsAny(s.From, "\r\n") || s.TLS == nil || s.TLS.InsecureSkipVerify || s.TLS.ServerName == "" || s.TLS.MinVersion < tls.VersionTLS13 || host != s.TLS.ServerName {
		return fmt.Errorf("authentication delivery unavailable")
	}
	return nil
}
