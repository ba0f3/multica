package r2dgit

// DefaultGitHubHostPins are github.com SSH host key fingerprints (SHA256).
// Used by the seed migration and when registering GitHub without outbound SSH
// from the API process (for example API in Docker with no egress on port 22).
var DefaultGitHubHostPins = []string{
	"SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s",
	"SHA256:p2QAMXNIC1TJYWeIOttrVc98/R1BUFWu3/LiyKgUfQM",
	"SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU",
}

func defaultHostPinsForProvider(kind, host string) []string {
	if kind == "github" && host == "github.com" {
		return append([]string(nil), DefaultGitHubHostPins...)
	}
	return nil
}
