// @vitest-environment node
import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiClient } from "./client";
import { parseGitProfile, parseGitIdentity, parseGitRun, parseGitAcknowledgement, parseGitOutputReceipt } from "./git-schemas";
import { setSchemaLogger } from "./schema";

const id = "11111111-1111-4111-8111-111111111111";
const key = { id, user_id: id, provider_id: id, generation: 1, public_key: "ssh-ed25519 synthetic", fingerprint: "SHA256:synthetic", state: "pending_verification" };
afterEach(() => { vi.unstubAllGlobals(); setSchemaLogger({ debug: () => {}, info: () => {}, warn: () => {}, error: () => {} }); });

describe("Git identity API boundary", () => {
  it("accepts only an output receipt and never logs unexpected source", () => {
    const warn = vi.fn(); setSchemaLogger({ debug: vi.fn(), info: vi.fn(), warn, error: vi.fn() });
    expect(parseGitOutputReceipt({ id, content: "PRIVATE SOURCE" })).toEqual({ id });
    expect(() => parseGitOutputReceipt({ id: "bad", content: "PRIVATE SOURCE" })).toThrow("Invalid Git output receipt");
    expect(JSON.stringify(warn.mock.calls)).not.toContain("PRIVATE SOURCE");
  });
  it("strips secret fields and disables malformed profile responses without logging them", () => {
    const warn = vi.fn(); setSchemaLogger({ debug: vi.fn(), info: vi.fn(), warn, error: vi.fn() });
    const parsed = parseGitProfile({ management_available: true, providers: [], identities: [{ ...key, private_key: "SECRET", internal_secret_ref: "SECRET" }] });
    expect(JSON.stringify(parsed)).not.toContain("SECRET");
    expect(parsed.identities[0]?.active).toBe(false);
    const malformed = parseGitProfile({ identities: "wrong", private_key: "SECRET" });
    expect(malformed.management_available).toBe(false);
    expect(JSON.stringify(warn.mock.calls)).not.toContain("SECRET");
    expect(() => parseGitIdentity({ generation: "bad", private_key: "SECRET" })).toThrow("Invalid Git identity response");
  });
  it("preserves unknown states for safe UI fallback and defaults missing capabilities", () => {
    expect(parseGitIdentity({ ...key, state: "future_state" }).state).toBe("future_state");
    expect(parseGitProfile({ providers: [], identities: [] }).management_available).toBe(false);
  });
  it("rejects malformed acknowledgements, sealed runs and private material in public-key fields", () => {
    expect(() => parseGitIdentity({ ...key, public_key: "-----BEGIN PRIVATE KEY-----" })).toThrow();
    expect(() => parseGitRun({ execution_available: true, context: { user_id: id } })).toThrow("Invalid Git run response");
    expect(() => parseGitAcknowledgement({ cleanup_complete: false }, "cleanup_complete")).toThrow();
    expect(() => parseGitAcknowledgement({ locally_revoked: true }, "locally_revoked")).not.toThrow();
  });
  it("sends only provider, consent and idempotency fields on account-scoped creation", async () => {
    const fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify(key), { headers: { "Content-Type": "application/json" } })); vi.stubGlobal("fetch", fetch);
    const api = new ApiClient("https://api.fixture.invalid");
    const result = await api.generateGitIdentity(id, [id], id);
    expect(result.public_key).toBe(key.public_key);
    expect(fetch.mock.calls[0]?.[0]).toBe("https://api.fixture.invalid/api/me/git-identities");
    expect(JSON.parse(fetch.mock.calls[0]?.[1]?.body)).toEqual({ provider_id: id, consent_project_ids: [id], request_id: id });
  });
});
