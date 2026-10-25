package handler

// GitIdentityBinding is one verified Git credential of the human who
// authorized a task.
//
// It carries the public half only: the daemon uses it to choose the provider
// whose key signs the run's Git operations, then exchanges it for a
// short-lived signing lease. Neither this struct nor the claim response it
// travels in can carry a private key.
type GitIdentityBinding struct {
	ProviderID  string `json:"provider_id"`
	Host        string `json:"host"`
	Port        int    `json:"port,omitempty"`
	IdentityID  string `json:"identity_id"`
	Generation  uint64 `json:"generation"`
	PublicKey   string `json:"public_key"`
	Fingerprint string `json:"fingerprint"`
}
