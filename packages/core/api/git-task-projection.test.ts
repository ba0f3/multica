// @vitest-environment node
import { afterEach, expect, it, vi } from "vitest";
import { ApiClient } from "./client";
import { AgentTaskSchema } from "./schemas";

afterEach(() => vi.unstubAllGlobals());

it("accepts a progress-only protected task through the history client", async () => {
  const row = {
    id: "protected-run", agent_id: "shared-agent", runtime_id: "runtime",
    issue_id: "issue", status: "failed", priority: 0,
    created_at: "2026-10-16T00:00:00Z", dispatched_at: null,
    started_at: null, completed_at: null, result: null, error: null,
    delivered_comment_ids: [],
  };
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify([row]))));
  const tasks = await new ApiClient("https://fixture.invalid").listTasksByIssue("issue");
  expect(tasks).toHaveLength(1);
  expect(tasks[0]).toMatchObject({ id: row.id, status: "failed", result: null, error: null });
  expect(tasks[0]?.work_dir).toBeUndefined();
  expect(tasks[0]?.trigger_summary).toBeUndefined();
});

it("retains progress when optional coverage metadata is malformed", () => {
  const row = AgentTaskSchema.parse({ id: "protected-run", status: "queued", delivered_comment_ids: 42, work_dir: false });
  expect(row).toMatchObject({ id: "protected-run", status: "queued", result: null, error: null });
  expect(row.delivered_comment_ids).toBeUndefined();
  expect(row.work_dir).toBeUndefined();
});

it("does not turn malformed task identity into a valid history row", async () => {
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify([{ id: 42, result: "synthetic malformed detail" }]))));
  await expect(new ApiClient("https://fixture.invalid").listTasksByIssue("issue")).resolves.toEqual([]);
});
