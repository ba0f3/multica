import { beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { I18nProvider } from "@multica/core/i18n/react";
import type { GitProfile } from "@multica/core/git-identities";
import enCommon from "../../locales/en/common.json";
import enSettings from "../../locales/en/settings.json";

const api = vi.hoisted(() => ({ getGitIdentities: vi.fn(), generateGitIdentity: vi.fn(), gitIdentityAction: vi.fn(), revokeGitIdentity: vi.fn(), cleanupGitIdentity: vi.fn() }));
const copy = vi.hoisted(() => vi.fn());
vi.mock("@multica/core/api", () => ({ api }));
vi.mock("@multica/ui/lib/clipboard", () => ({ copyText: copy }));
import { GitIdentitiesSection } from "./git-identities-section";

const id = "11111111-1111-4111-8111-111111111111";
const provider = "22222222-2222-4222-8222-222222222222";
const project = "33333333-3333-4333-8333-333333333333";
const key = { id, user_id: id, provider_id: provider, generation: 1, public_key: "ssh-ed25519 c3ludGhldGlj", fingerprint: "SHA256:synthetic", state: "pending_verification", active: false, cleanup_pending: false, consent_project_ids: [project] };
let profile: GitProfile;
function mount(userId = id, client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })) {
  const wrap = (account: string) => <QueryClientProvider client={client}><I18nProvider locale="en" resources={{ en: { common: enCommon, settings: enSettings } }}><GitIdentitiesSection key={account} userId={account} /></I18nProvider></QueryClientProvider>;
  const result = render(wrap(userId));
  return { ...result, account: (account: string) => result.rerender(wrap(account)) };
}
beforeEach(() => {
  cleanup(); vi.clearAllMocks();
  profile = { management_available: true, providers: [{ id: provider, label: "Fixture provider", host: "git.fixture.invalid", kind: "github", port: 22 }], projects: [{ id: project, title: "Explicit shared project" }], identities: [] };
  api.getGitIdentities.mockImplementation(async () => profile);
  api.generateGitIdentity.mockResolvedValue(key);
  api.gitIdentityAction.mockResolvedValue(key);
  api.revokeGitIdentity.mockResolvedValue(undefined);
  copy.mockResolvedValue(true);
});

describe("Git identities account section", () => {
  it("generates with explicit consent, refreshes after verification and copies only the public key", async () => {
    const user = userEvent.setup(); mount();
    await screen.findByText("Explicit shared project");
    await user.selectOptions(screen.getByRole("combobox", { name: "Git provider" }), provider);
    await user.click(screen.getByRole("checkbox", { name: "Explicit shared project" }));
    api.generateGitIdentity.mockImplementation(async () => { profile = { ...profile, identities: [key] }; return key; });
    await user.click(screen.getByRole("button", { name: "Generate key" }));
    await screen.findByRole("textbox", { name: "Public key" });
    expect(api.generateGitIdentity).toHaveBeenCalledWith(provider, [project], expect.any(String));
    await user.click(screen.getByRole("button", { name: "Copy public key" }));
    expect(copy).toHaveBeenCalledWith(key.public_key);
    api.gitIdentityAction.mockImplementation(async () => { profile = { ...profile, identities: [{ ...key, state: "ready", active: true }] }; return profile.identities[0]; });
    await user.click(screen.getByRole("button", { name: "Verify" }));
    await screen.findByRole("button", { name: "Rotate key" });
    expect(api.gitIdentityAction).toHaveBeenCalledWith(id, 1, "verify");
  });

  it("rotates using the existing consent and retries the same failed intent with the same idempotency key", async () => {
    profile.identities = [{ ...key, state: "ready", active: true }];
    api.generateGitIdentity.mockRejectedValue(new Error("git_recent_auth_required"));
    const user = userEvent.setup(); mount();
    await user.click(await screen.findByRole("button", { name: "Rotate key" }));
    await screen.findByText("Sign in again before managing Git identities.");
    await user.click(screen.getByRole("button", { name: "Rotate key" }));
    await waitFor(() => expect(api.generateGitIdentity).toHaveBeenCalledTimes(2));
    expect(api.generateGitIdentity.mock.calls[0]).toEqual(api.generateGitIdentity.mock.calls[1]);
    expect(api.generateGitIdentity.mock.calls[0]?.slice(0, 2)).toEqual([provider, [project]]);
  });

  it("requires confirmation for family revocation and permits local revoke during custody outage", async () => {
    profile.management_available = false;
    profile.identities = [key, { ...key, generation: 2 }];
    const user = userEvent.setup(); mount();
    expect(await screen.findByRole("button", { name: "Generate key" })).toBeDisabled();
    expect((await screen.findAllByRole("button", { name: "Verify" }))[0]).toBeDisabled();
    await user.click(screen.getAllByRole("button", { name: "Revoke" })[0]!);
    expect(api.revokeGitIdentity).not.toHaveBeenCalled();
    expect(screen.getAllByRole("button", { name: "Confirm revocation" })).toHaveLength(1);
    await user.click(screen.getByRole("button", { name: "Confirm revocation" }));
    await waitFor(() => expect(api.revokeGitIdentity).toHaveBeenCalledWith(id));
  });

  it("does not reuse another account's cached keys", async () => {
    profile.identities = [key];
    const view = mount(); await screen.findByRole("textbox", { name: "Public key" });
    profile = { ...profile, identities: [] };
    view.account("44444444-4444-4444-8444-444444444444");
    await waitFor(() => expect(api.getGitIdentities).toHaveBeenCalledTimes(2));
    expect(screen.queryByRole("textbox", { name: "Public key" })).not.toBeInTheDocument();
  });
});
