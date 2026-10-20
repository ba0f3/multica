import { describe, expect, it } from "vitest";
import {
  EMPTY_GIT_PROFILE,
  GitIdentitySchema,
  GitProfileSchema,
  GitProviderSchema,
} from "./schemas";
import { parseWithFallback } from "./schema";

describe("Git provider schema", () => {
  it("keeps an unknown provider kind as a plain string", () => {
    const parsed = GitProviderSchema.safeParse({
      id: "provider-1",
      label: "GitHub",
      kind: "gitlab",
      host: "gitlab.example.com",
      port: 22,
    });
    expect(parsed.success).toBe(true);
    if (!parsed.success) return;
    expect(parsed.data.kind).toBe("gitlab");
  });

  it("drops the host key pins, which the browser has no use for", () => {
    const parsed = GitProviderSchema.safeParse({
      id: "provider-1",
      label: "GitHub",
      kind: "github",
      host: "github.com",
      port: 22,
      host_pins: ["SHA256:secret-pin"],
    });
    expect(parsed.success).toBe(true);
    if (!parsed.success) return;
    expect(parsed.data).not.toHaveProperty("host_pins");
  });
});

describe("Git identity schema", () => {
  const identity = {
    id: "identity-1",
    user_id: "user-1",
    provider_id: "provider-1",
    generation: 1,
    public_key: "ssh-ed25519 AAAA",
    fingerprint: "SHA256:abc",
    state: "ready",
    active: true,
    cleanup_pending: false,
    consent_project_ids: [],
  };

  it("parses a verified identity", () => {
    const parsed = GitIdentitySchema.safeParse(identity);
    expect(parsed.success).toBe(true);
    if (!parsed.success) return;
    expect(parsed.data.generation).toBe(1);
    expect(parsed.data.state).toBe("ready");
  });

  it("keeps an unknown state instead of failing", () => {
    const parsed = GitIdentitySchema.safeParse({ ...identity, state: "rotating" });
    expect(parsed.success).toBe(true);
    if (!parsed.success) return;
    expect(parsed.data.state).toBe("rotating");
  });

  it("strips a secret reference even when the server sends one", () => {
    const parsed = GitIdentitySchema.safeParse({
      ...identity,
      internal_secret_ref: "r2d-git-identity-1-1",
      private_key: "-----BEGIN OPENSSH PRIVATE KEY-----",
    });
    expect(parsed.success).toBe(true);
    if (!parsed.success) return;
    expect(parsed.data).not.toHaveProperty("internal_secret_ref");
    expect(parsed.data).not.toHaveProperty("private_key");
  });

  it("falls back to an empty profile when the response is malformed", () => {
    const parsed = parseWithFallback(
      { providers: "not-an-array" },
      GitProfileSchema,
      EMPTY_GIT_PROFILE,
      { endpoint: "GET /api/me/git-identities" },
    );
    expect(parsed.providers).toEqual([]);
    expect(parsed.identities).toEqual([]);
  });
});
