/**
 * Per-user Git credentials.
 *
 * A user registers one public key per Git provider. The private key never
 * leaves the server's encrypted custody store, so nothing in this file
 * describes it: the browser sees the public key, its fingerprint and the
 * state of the credential, and nothing else.
 */

/**
 * Lifecycle of one key generation.
 *
 * Server-driven: a newer server may add a state, so switch with a `default`
 * and treat an unknown value as "not usable yet".
 */
export type GitIdentityState =
  | "provisioning"
  | "pending_verification"
  | "ready"
  | "revoked";

/** An operator-approved Git provider instance. */
export interface GitProvider {
  id: string;
  label: string;
  kind: string;
  host: string;
  port: number;
}

/** One key generation of one user's credential on one provider. */
export interface GitIdentity {
  id: string;
  user_id: string;
  provider_id: string;
  generation: number;
  public_key: string;
  fingerprint: string;
  state: GitIdentityState | string;
  account_id?: string;
  login?: string;
  verified_at?: string | null;
  /** Whether a run may use this generation. */
  active: boolean;
  /** Whether the stored secret still has to be destroyed. */
  cleanup_pending: boolean;
  diagnostic?: string;
}

/** The account-scoped view of a user's Git credentials. */
export interface GitProfile {
  providers: GitProvider[];
  identities: GitIdentity[];
}

/** Armored SSH signature for Gitea's key verification token. */
export interface GiteaVerifySignResponse {
  signature: string;
}
