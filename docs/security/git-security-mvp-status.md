# Git security MVP — implementation status

Status date: **2026-10-21**. Source baseline: [`feature/git-security-mvp@d67d4d548962a22f11001490e784955fedc9127f`](https://github.com/r2d-ai/multica/commit/d67d4d548962a22f11001490e784955fedc9127f).

[Spec hiện tại](per-user-git-credentials-plan.md) đổi execution backend sang Docker cho **Codex, Cursor Agent, OpenCode**, tiếp tục credentials và worker trên branch. [Handoff](git-security-agent-handoff.md) là checklist sửa tiếp. Lần cập nhật này chỉ sửa docs; Docker chưa được implement hoặc nghiệm thu bởi thay đổi này.

## 1. Source đã có: giữ làm nền

| Thành phần | Source tại baseline | Trạng thái |
| --- | --- | --- |
| Key generation, public representation, lifecycle | `server/internal/r2dgit/{identity,service}.go` | Có code; giữ cho #86 |
| OpenBao KV v2 encrypted custody, signer callback | `server/internal/r2dgit/custody.go` | Có code/config; không local-file fallback |
| Pinned-host SSH identity verification | `server/internal/r2dgit/verify.go` | Có code/fixture tests; live GitHub/Gitea chưa xác minh |
| Human-owned account endpoints | `server/internal/handler/r2d_git.go`, `server/internal/middleware/human_session.go` | Có code; public DTO và CLI-issued-token gate cần giữ |
| Shared UI/API/query | `packages/views/settings/components/git-identities-section.tsx`, `packages/core/api/{schemas,client}.ts`, `packages/core/git-identities/` | Có account UI và translations; không cần port lại #93 |
| Side tables/queries | `server/migrations/900100–900113_*.sql`, `server/pkg/db/queries/r2d_git.sql` | 14 migration numbers có trên branch; applied DB state chưa xác minh |
| Signing lease/API | `server/internal/r2dgit/signing.go`, `server/internal/handler/r2d_git_sign.go` | Có per-key-generation checks và daemon-bound lease; cần active-attempt/lifetime sửa tiếp |
| Originator metadata, signing socket/client | `server/internal/handler/{daemon,agent}.go`, `server/internal/daemon/{git_agent,client}.go`, `server/internal/daemon/gitagent/socket.go` | Có List/Sign và key selection; chưa đủ để chứng nhận task/API isolation |
| Worker/manifest/IPC/backend | `server/internal/daemon/sandbox/{manifest,ipc,worker,backend}.go` | Có adapter execution trong worker; transport mới chỉ message/result |
| bwrap launch/config/hidden command | `server/internal/daemon/{sandbox_launch,config}.go`, `server/internal/daemon/sandbox/policy.go`, `server/cmd/multica/main.go` | Có implementation opt-in; cần thay backend theo spec |

Custody yêu cầu `MULTICA_GIT_CUSTODY_URL`, `MULTICA_GIT_CUSTODY_MOUNT`, `MULTICA_GIT_CUSTODY_TOKEN`. Thiếu cấu hình trả service unavailable. Đó là source behavior đã review, không phải xác nhận production có custody/config/key.

Signer hiện dùng registry trong một backend process. Multi-instance không được xem là đã hỗ trợ. Claim trả verified identities và daemon chọn first matching repo host; cần đổi sang repo/provider được chọn cho task. Git-key originator logic và task JWT authority là hai đường khác nhau: đường đầu tồn tại không chứng minh đường sau đã an toàn.

## 2. Boundary hiện tại và gap cụ thể

| Quan sát tại `d67d4d5` | Ý nghĩa / việc còn thiếu |
| --- | --- |
| `MULTICA_TASK_SANDBOX=1` mới bật bwrap; unset chạy host | Chưa có protected deployment mặc định; socket không task-isolated khi chạy cùng host identity |
| Host HOME read-only với một số path shadows; HOME vẫn là host path | Không phải private HOME. `.aws`, `.kube`, `.docker` và source/state khác có thể đọc được theo default mount |
| System/CLI host directories được mount; cwd/PATH/env thay qua nhiều lớp | Compatibility và secret/source exposure chưa giải quyết bằng một clean runtime |
| Codex auth có host symlink; Cursor trust metadata dùng host cwd | Cần private auth/state và tạo config sau khi có container paths |
| Manifest đi qua stdin | Tránh secret trong launch argv; **không** có nghĩa secret không vào environment của native child |
| Backend đặt `AttemptID = TaskID`, stdin đóng sau manifest | Cần attempt identity thật và IPC hai chiều |
| Wrapper không forward full `agent.Session` | Supplements/readiness, activity, background interruption, terminal observation cần parity theo native support |
| Prepare/finalize/repocache/host checkout ở ngoài worker | Malicious repo hoặc task API có thể chạm execution path ngoài boundary; phải chuyển/chặn |
| Network hiện shared; host health/checkout/control services tồn tại | Docker migration cần deny policy có hiệu lực và server-side task API gates |
| Task JWT dùng runtime-owner context; generic CLI-token exchange route tồn tại | Phải giữ restricted task actor; không coi việc sửa env hoặc Git originator là đủ |
| Successful sign slides lease TTL; revoke rechecks key state | Cần active-attempt + finite lifetime/trusted renewal; cleanup phải đóng connections và authenticated processes |
| OpenCode 2.x service lifecycle khác client; managed MCP có `ErrOpenCodeV2MCPUnsupported` | Cô lập service, preserve version detection và verify private config delivery |

Các điểm trên là source review, không phải tuyên bố đã thực hiện exploit trên deployment. Không giữ các kết luận cũ “chưa có worker”, “HOME private đã đạt” hoặc “mount host HOME không ảnh hưởng security”.

## 3. Work còn mở

| Issue | Bước tiếp theo | Chưa được claim |
| --- | --- | --- |
| [#86](https://github.com/r2d-ai/multica/issues/86) | Giữ/verify UI, lifecycle, custody, human owner, account cache và public-only responses | Live provider/production onboarding đã pass |
| [#89](https://github.com/r2d-ai/multica/issues/89) | Docker worker/image, private runtime state, native three-provider support, bidirectional IPC, effective network/resource policy, full-container cleanup | Docker implementation hay native compatibility đã đạt |
| [#88](https://github.com/r2d-ai/multica/issues/88) | Task-token/API scope, chosen repo/provider/unique attempt lease, socket env, all Git inside worker, revoke/cancel | Task principal và all-path containment đã hoàn thành |

Không mở lại #85/#87/#90/#91. Tool-only exec-server/SDK/driver experiments là optional PoC sau; không cản common Docker implementation.

## 4. Verification: phân biệt evidence

| Evidence | Đã biết | Giới hạn |
| --- | --- | --- |
| Historical branch report | [Status trước revision](https://github.com/r2d-ai/multica/blob/d67d4d548962a22f11001490e784955fedc9127f/docs/security/git-security-mvp-status.md) ghi unit/fixture/frontend results và một real bwrap smoke trên một host | Kết quả do implementation trước báo; không được rerun trong docs revision; không chứng minh private HOME/native CLI/Docker |
| Source review | Credential, worker, native config, Session IPC, Git và control-plane paths ở pinned baseline đã đọc | Static evidence; không phải deployed behavior |
| Review canary trước revision | Synthetic bwrap canary bị UID-map setup chặn trước payload | Không có kết quả payload; không được tính pass/fail containment |
| Docs revision này | Link/source-path, Markdown/whitespace, scope review | Không chạy code tests, Docker/native-agent/live GitHub/Gitea, migration hoặc deployment |
| Docker/native/provider matrix | **Not run** | Phải làm khi implementation sẵn sàng và được authorize cho real accounts |

Implementation tiếp theo ghi mỗi kết quả bằng **commit + image digest + Docker mode/host controls + native version + command/test type + result**. Không nâng “code exists” hoặc “fixture passes” thành “production verified”.

Các command hiện có để implementer dùng đúng scope (không phải test results mới):

| Scope | Command |
| --- | --- |
| Credential/signing core | `go -C server test ./internal/r2dgit/` |
| API/principal regression | `go -C server test ./internal/handler/ ./internal/middleware/` |
| Socket | `go -C server test ./internal/daemon/gitagent/` |
| Worker/launch | `go -C server test ./internal/daemon/sandbox/ ./internal/daemon/ -run 'TestSandbox\|TestBuildArgs\|TestStartGitAgentSocket'` |
| Credential frontend | `pnpm --filter @multica/core test`, `pnpm --filter @multica/views test` |

Thêm Docker integration checks theo tám acceptance cases trong spec; actual limits/network/teardown cần target backend thật. Default tests dùng fake executable paths/synthetic keys. Real-agent tests chỉ chạy sau explicit authorization, gate `agentintegration` + `MULTICA_RUN_REAL_AGENT_SMOKE=1` trước CLI/account lookup theo AGENTS.md. Không chạy `make migrate-up` hoặc truy cập production keys chỉ để cập nhật status.

## 5. Migration và delivery cursor

- Existing feature migrations: **900100–900113**, từ `r2d_git_provider` tới `r2d_git_key_job_idempotency_index`; gồm table/index/primary-key/idempotency migrations. Ghi occupied branch range ở [#12](https://github.com/r2d-ai/multica/issues/12), không cấp số mới trong docs.
- Applied/deployed schema và deployed daemon SHA: **chưa xác minh**. Giữ R2D range/no-FK/concurrent-index rules; không renumber trước inventory.
- PR #94/#95 là merged spec history; #93 closed unmerged, không port whole engine. Implementation source của revision này là `feature/git-security-mvp`.
- Docs-only revision không đóng #84/#86/#88/#89, không thay runtime, tạo key, deploy hoặc đổi upstream sync/backport cursor.
