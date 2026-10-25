import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { I18nProvider } from "@multica/core/i18n/react";
import enCommon from "../../locales/en/common.json";
import enSettings from "../../locales/en/settings.json";

const mockGenerate = vi.hoisted(() =>
  vi.fn((_input: { provider_id: string; request_id: string }) =>
    Promise.resolve({}),
  ),
);
const mockVerify = vi.hoisted(() =>
  vi.fn((_input: { identityId: string; generation: number }) =>
    Promise.resolve({}),
  ),
);
const mockRevoke = vi.hoisted(() =>
  vi.fn((_identityId: string) => Promise.resolve(undefined)),
);
const mockSign = vi.hoisted(() =>
  vi.fn((_input: { identityId: string; generation: number; token: string }) =>
    Promise.resolve({ signature: "-----BEGIN SSH SIGNATURE-----" }),
  ),
);
const mockToastError = vi.hoisted(() => vi.fn());
const profileRef = vi.hoisted(() => ({
  current: {
    providers: [] as {
      id: string;
      label: string;
      kind: string;
      host: string;
      port: number;
    }[],
    identities: [] as {
      id: string;
      user_id: string;
      provider_id: string;
      generation: number;
      public_key: string;
      fingerprint: string;
      state: string;
      account_id?: string;
      login?: string;
      verified_at?: string | null;
      active: boolean;
      cleanup_pending: boolean;
      diagnostic?: string;
    }[],
  },
}));

const mockUseMutation = vi.hoisted(() => {
  return (options: {
    mutationFn: (input: any) => Promise<unknown>;
    onSettled?: () => void;
  }) => ({
    mutate: (
      input: any,
      mutateOptions?: {
        onSuccess?: (result: unknown) => void;
        onError?: (error: unknown) => void;
      },
    ) => {
      void options.mutationFn(input).then(
        (result) => {
          mutateOptions?.onSuccess?.(result);
          options.onSettled?.();
        },
        (error: unknown) => {
          // The component owns the error handling: the mock only reports
          // the rejection, so the test proves the component reacts to it.
          mutateOptions?.onError?.(error);
        },
      );
    },
    isPending: false,
    isError: false,
  });
});

vi.mock("@tanstack/react-query", () => ({
  useQuery: () => ({ data: profileRef.current, isPending: false, isError: false }),
  useQueryClient: () => ({ invalidateQueries: vi.fn() }),
  queryOptions: <T,>(options: T) => options,
  useMutation: mockUseMutation,
}));

vi.mock("@multica/core/git-identities", () => ({
  gitIdentityListOptions: (userID: string) => ({
    queryKey: ["git-identities", userID, "list"],
    queryFn: () => undefined,
  }),
  useGenerateGitIdentity: () => mockUseMutation({ mutationFn: mockGenerate }),
  useVerifyGitIdentity: () => mockUseMutation({ mutationFn: mockVerify }),
  useRevokeGitIdentity: () => mockUseMutation({ mutationFn: mockRevoke }),
  useSignGiteaGitIdentityVerification: () =>
    mockUseMutation({ mutationFn: mockSign }),
}));

vi.mock("@multica/core/auth", () => ({
  useAuthStore: (selector: (state: { user: { id: string } }) => unknown) =>
    selector({ user: { id: "user-1" } }),
}));

vi.mock("sonner", () => ({
  toast: { error: mockToastError },
}));

import { GitIdentitiesSection } from "./git-identities-section";

function renderSection() {
  return render(
    <I18nProvider
      resources={{ en: { common: enCommon, settings: enSettings } }}
      locale="en"
    >
      <GitIdentitiesSection />
    </I18nProvider>,
  );
}

function provider() {
  return {
    id: "provider-1",
    label: "GitHub",
    kind: "github",
    host: "github.com",
    port: 22,
  };
}

function identity(overrides: Partial<(typeof profileRef.current)["identities"][number]> = {}) {
  return {
    id: "identity-1",
    user_id: "user-1",
    provider_id: "provider-1",
    generation: 1,
    public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyMaterial",
    fingerprint: "SHA256:exampleFingerprint",
    state: "ready",
    active: true,
    cleanup_pending: false,
    ...overrides,
  };
}

describe("GitIdentitiesSection", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockGenerate.mockResolvedValue({});
    profileRef.current = { providers: [], identities: [] };
  });

  it("lists a key with its provider, fingerprint and state", () => {
    profileRef.current = {
      providers: [provider()],
      identities: [identity()],
    };
    renderSection();

    expect(screen.getByText("GitHub")).toBeTruthy();
    expect(screen.getByText("SHA256:exampleFingerprint")).toBeTruthy();
    expect(screen.getByText("SSH authenticated")).toBeTruthy();
  });

  it("hides generate when the provider already has a key", () => {
    profileRef.current = {
      providers: [provider()],
      identities: [identity()],
    };
    renderSection();

    expect(screen.queryByRole("button", { name: /generate/i })).toBeNull();
  });

  it("keeps Gitea token signing available after the SSH connection is checked", async () => {
    profileRef.current = {
      providers: [{ ...provider(), kind: "gitea", label: "Gitea" }],
      identities: [identity()],
    };
    renderSection();

    await userEvent.type(
      screen.getByRole("textbox", { name: "Gitea verification token" }),
      "gitea-token",
    );
    await userEvent.click(screen.getByRole("button", { name: "Sign token" }));

    await waitFor(() =>
      expect(mockSign).toHaveBeenCalledWith({
        identityId: "identity-1",
        generation: 1,
        token: "gitea-token",
      }),
    );
    expect(screen.getByText("SSH authenticated")).toBeTruthy();
    expect(
      screen.getByRole("textbox", { name: "Signature for Gitea" }),
    ).toBeTruthy();
  });

  it("generates a key for a provider", async () => {
    profileRef.current = { providers: [provider()], identities: [] };
    renderSection();

    await userEvent.click(screen.getByRole("button", { name: /generate/i }));

    await waitFor(() => expect(mockGenerate).toHaveBeenCalledTimes(1));
    const input = mockGenerate.mock.calls[0]?.[0];
    expect(input?.provider_id).toBe("provider-1");
    expect(input?.request_id).toBeTruthy();
  });

  it("shows the public key of a key and never a private key", () => {
    profileRef.current = {
      providers: [provider()],
      identities: [identity()],
    };
    renderSection();

    const field = screen.getByDisplayValue(
      /ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyMaterial/,
    );
    expect(field.getAttribute("readonly")).not.toBeNull();
    expect(document.body.innerHTML).not.toContain("PRIVATE KEY");
  });

  it("verifies a key that is waiting for verification", async () => {
    profileRef.current = {
      providers: [provider()],
      identities: [identity({ state: "pending_verification", active: false })],
    };
    renderSection();

    await userEvent.click(screen.getByRole("button", { name: /check connection/i }));

    await waitFor(() => expect(mockVerify).toHaveBeenCalledTimes(1));
    const input = mockVerify.mock.calls[0]?.[0];
    expect(input?.identityId).toBe("identity-1");
    expect(input?.generation).toBe(1);
  });

  it("revokes a key", async () => {
    profileRef.current = { providers: [provider()], identities: [identity()] };
    renderSection();

    await userEvent.click(screen.getByRole("button", { name: /revoke/i }));

    await waitFor(() => expect(mockRevoke).toHaveBeenCalledTimes(1));
    expect(mockRevoke.mock.calls[0]?.[0]).toBe("identity-1");
  });

  it("offers no way to view or download a private key", () => {
    profileRef.current = { providers: [provider()], identities: [identity()] };
    renderSection();

    expect(screen.queryByRole("button", { name: /private/i })).toBeNull();
    expect(screen.queryByText(/private key/i)).toBeNull();
  });

  it("reports a failed generation without showing a public key", async () => {
    mockGenerate.mockImplementation(() => Promise.reject(new Error("boom")));
    profileRef.current = { providers: [provider()], identities: [] };
    renderSection();

    await userEvent.click(screen.getByRole("button", { name: /generate/i }));

    await waitFor(() => expect(mockToastError).toHaveBeenCalled());
    expect(
      screen.queryByDisplayValue(/ssh-ed25519/),
    ).toBeNull();
  });
});
