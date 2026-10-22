import { test, expect } from "@playwright/test";
import { execFileSync } from "node:child_process";
import path from "node:path";

/**
 * Task isolation is enforced by the Go daemon and sandbox worker, not the web UI.
 * This spec runs the Go end-to-end isolation suite so `pnpm exec playwright test`
 * exercises the default-isolated contract in CI alongside UI specs.
 */
test.describe("task isolation (daemon sandbox)", () => {
  test("default config and OpenCode worker argv e2e", () => {
    const serverDir = path.join(process.cwd(), "server");
    const output = execFileSync(
      "go",
      [
        "test",
        "./internal/daemon/",
        "-run",
        "TestTaskIsolationE2E_",
        "-count=1",
      ],
      {
        cwd: serverDir,
        encoding: "utf8",
        env: {
          ...process.env,
          // Never spend model quota in the default Playwright run.
          MULTICA_RUN_REAL_AGENT_SMOKE: "",
        },
      },
    );
    expect(output).toMatch(/\bok\s+github\.com\/multica-ai\/multica\/server\/internal\/daemon\b/);
  });
});
