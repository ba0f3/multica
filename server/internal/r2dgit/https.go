package r2dgit

import (
	"crypto/tls"
	"net/http"
	"time"
)

// trustedHTTPSClient keeps secret-bearing transports independent of ambient
// proxies/cookie jars. Supplied TLS roots are copied; verification cannot be
// disabled by a compatibility callback or an insecure client configuration.
func trustedHTTPSClient(client *http.Client, timeout time.Duration, serverName string) (*http.Client, error) {
	var transport *http.Transport
	if client == nil || client.Transport == nil {
		transport = &http.Transport{}
	} else {
		original, ok := client.Transport.(*http.Transport)
		if !ok {
			return nil, ErrUnavailable
		}
		transport = original.Clone()
	}
	transport.Proxy = nil
	if transport.DialTLS != nil || transport.DialTLSContext != nil {
		return nil, ErrUnavailable
	}
	transport.ResponseHeaderTimeout = timeout
	transport.MaxConnsPerHost = 4
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS13}
	} else {
		transport.TLSClientConfig = transport.TLSClientConfig.Clone()
		if transport.TLSClientConfig.InsecureSkipVerify || transport.TLSClientConfig.VerifyConnection != nil || transport.TLSClientConfig.VerifyPeerCertificate != nil || (transport.TLSClientConfig.ServerName != "" && transport.TLSClientConfig.ServerName != serverName) {
			return nil, ErrUnavailable
		}
		transport.TLSClientConfig.MinVersion = tls.VersionTLS13
		if transport.TLSClientConfig.RootCAs != nil {
			transport.TLSClientConfig.RootCAs = transport.TLSClientConfig.RootCAs.Clone()
		}
	}
	transport.TLSClientConfig.ServerName = serverName
	return &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}
