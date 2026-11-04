# Audit lại các đường leak SSH key theo ba0f3/multica#109

## Phạm vi và mức xác nhận

| Thuộc tính | Giá trị |
| --- | --- |
| Repository | `r2d-ai/multica` (fork của `ba0f3/multica`; cả hai trỏ cùng main head) |
| Revision được audit | `c864efca5f2ef939681afdeec5f82acaa9f8eb6d` — main, 2026-11-04T01:01:42Z |
| Bản vá được audit | PR #112 → merge `084f55570b91c2cc63b87712cf187106449fcbf0` (head `23cbe8fcb246fae9a660fa7433d44e773c8f081f`, 19 commit / 35 file) |
| Báo cáo gốc | `docs/security/ssh-key-security-review-2026-11-03.md` @ `f86a27d6` — mã F1–F5, C1 |
| Câu hỏi | Sau PR #112, các đường để A dùng SSH signing identity của B còn tồn tại không? |
| Phương pháp | Đọc source tại HEAD, lần theo chuỗi principal → `agent_task_queue.originator_user_id` → `execution_user_id` → signing lease/socket; đối chiếu từng guard với test hồi quy; chạy test Go với PostgreSQL thật |
| Đã chạy | `go test -count=1 ./internal/handler/... ./internal/service/... ./internal/r2dgit/... ./internal/daemon/... ./internal/attribution/...` trên PostgreSQL 17.11 cục bộ, migrations đã apply bằng `cmd/migrate up` |
| Chưa chạy | `MULTICA_REQUIRE_BWRAP_SECURITY_TESTS=1` (runner này chặn unprivileged user namespace: `kernel.apparmor_restrict_unprivileged_userns=1`; CI workflow chạy được); smoke test provider CLI với 2 tài khoản + repo Git thật; hạ tầng multi-backend thật |

Mọi kết luận dưới đây là đọc source + chạy test trên revision đã nêu, không phải PoC khai thác trên deployment. Bảng trạng thái trả lời đúng câu hỏi của #109: đường nào đã bịt, đường nào còn.

## Kết luận

Tất cả sáu mã đã được vá ở PR #112, và các guard vẫn còn nguyên sau khi merge upstream v0.8.0 (`824acb09`) và hai commit sửa sau đó. Không tìm thấy đường nào trong F1–F5/C1 còn mở trên `c864efca`.

| Mã | Vấn đề | Trạng thái tại `c864efca` |
| --- | --- | --- |
| F1 | Rerun bằng task token lệch principal giữa authorize và enqueue | **Đã bịt** — principal resolve một lần, giữ xuyên suốt authorize → enqueue; agent actor không có task sống thì bị từ chối 403 trước khi enqueue |
| F2 | Quick-create origin nhận task của user khác cùng agent | **Đã bịt** — `origin_id` bắt buộc bằng chính task đã xác thực (`X-Task-ID`) |
| F3 | Supplement/comment steering đưa lệnh A vào session B đang giữ signer | **Đã bịt** — cả hai đường đều so execution principal của task đích với human đang yêu cầu |
| F4 | Native bwrap dùng writable provider profile chung | **Đã bịt ở native** — profile writable tách theo execution user; host view của worker không còn thừa kế HOME của operator |
| F5 | Task lịch sử còn làm căn cứ mở signing lease | **Đã bịt** — lease gắn với attempt do server xác lập; task terminal / stale attempt bị từ chối ở cả open, renew và sign |
| C1 | Rotation trên backend khác để lease cũ còn sống | **Đã bịt về mặt rò rỉ** — sign/renew kiểm tra durable active generation; phần *khả dụng* (lease registry process-local) vẫn còn mở |

Chuỗi quyền sau khi vá — và là điểm mấu chốt để đọc các mục bên dưới:

```
principal đã xác thực
  → agent_task_queue.originator_user_id   (điểm quyết định duy nhất)
  → claim response.execution_user_id      (server/internal/handler/daemon.go:2859)
  → daemon SSH_AUTH_SOCK / repo cache scope (per execution user)
  → signing lease: identity + generation của đúng user đó
```

Chỉ còn một chỗ quyết định principal (`originator_user_id`); mọi lớp về sau chỉ đọc lại giá trị đó.

## F1 — Đã bịt

Vấn đề gốc: handler authorize theo originator của request nhưng enqueue lại rơi về attribution lịch sử (comment/issue creator), nên task mới mang identity của B.

Cách vá: một seam duy nhất resolve principal và truyền xuyên suốt.

- `server/internal/handler/agent_access.go:295` — `memberActorUserID`: actor loại `agent` không bao giờ trở thành human.
- `server/internal/handler/agent_access.go:309` — `executionActorUserID`: member thì là chính mình; agent thì kế thừa originator của task đã xác thực trong `X-Task-ID`.
- `server/internal/handler/agent_access.go:324` — `credentialEnqueueActorUserID`: agent actor không resolve được human thì trả `ok=false`, cấm enqueue.
- `server/internal/handler/agent_access.go:222` — `invokeOriginatorFromRequest` trả `""` cho task đã terminal, nên một task đã kết thúc không còn "cho mượn" quyền của human.

Các entrypoint đã cắm seam:

| Entrypoint | Vị trí | Hành vi khi không resolve được principal |
| --- | --- | --- |
| Rerun issue / rerun task | `server/internal/handler/task_lifecycle.go:235` | 403 `invocation_not_allowed`, không enqueue |
| Assign / promote / batch update | `server/internal/handler/issue_trigger.go:101` | 403 + `run_dispatch` outcome trong payload |
| Squad leader dispatch | `server/internal/handler/squad.go:1204` | dùng `actorUserID` đã resolve; không có fallback sang attribution lịch sử |
| Quick-create (agent actor) | `server/internal/handler/issue.go:2784` | 403 |

Lớp service cũng không còn fallback: `server/internal/service/task.go:513` (`attributionForIssueTask`) kiểm tra `actorUserID.Valid` **trước** nhánh trigger comment và nhánh issue creator, nên attribution lịch sử chỉ còn là đường khi không có actor hợp lệ — tức là khi đã bị chặn ở tầng handler.

Hồi quy: `TestRerunIssue_ExecutionPrincipalOverridesSourceOriginator` (A rerun issue của B → task mới mang `originator_user_id` của A), `TestRerunIssue_AgentTerminalTaskRefusesCredentialEnqueue` (task token terminal → 403, không đổi số task), `TestUpdateIssue_AgentTerminalTaskReportsBlockedRunDispatch`.

## F2 — Đã bịt

Vấn đề gốc: client được tự chỉ định `origin_type=quick_create` + `origin_id` trỏ tới task của B trong cùng shared agent; guard chỉ kiểm tra workspace/agent/context.

Cách vá: ràng buộc origin vào task đã xác thực.

- `server/internal/handler/issue.go:3417` — `authenticatedTaskID` lấy từ `X-Task-ID` server-stamp (middleware xóa header client gửi rồi re-stamp từ task token).
- `server/internal/service/issue.go:445` — với `CreatorType == "agent"`, bắt buộc `AuthenticatedTaskID == OriginID`, nếu không trả `ErrQuickCreateOriginMismatch`.
- `server/internal/handler/issue.go:3581` — map lỗi thành 403.
- `server/internal/handler/issue.go:2784` — quick-create do agent actor tạo cũng phải dùng execution principal làm requester.

Nhánh `agent_create` (agent tạo issue bằng đường thường) vốn đã tự stamp origin từ `X-Task-ID` và kiểm tra task thuộc đúng agent đang tạo, nên không cần thêm guard.

Hồi quy: `TestIssueService_QuickCreateOriginMustMatchAuthenticatedTask`.

## F3 — Đã bịt

Vấn đề gốc: A gửi supplement/steering vào task đang chạy của B; nội dung tới thẳng session B đang giữ `SSH_AUTH_SOCK` của B, signer không phân biệt người viết.

Cách vá: so execution principal của task đích với human đang yêu cầu, ở cả hai bề mặt.

- `server/internal/handler/agent_access.go:344` — `mayControlCredentialTask`: yêu cầu `requestExecutionUserID == task.OriginatorUserID`.
- `server/internal/handler/agent_access.go:357` — `mayControlCredentialTaskForActor`: biến thể cho đường steer/comment (đã resolve human trước).
- `server/internal/handler/task_supplement.go:313` — direct supplement: 403 `invocation_not_allowed` nếu lệch principal. Route vẫn giữ `RequireHumanActor` (`server/cmd/server/router.go:2158`).
- `server/internal/handler/task_supplement.go:192-224` — comment steering: cả nhánh "named task" (`steer_task_ids`) và nhánh "all tasks" đều loại bỏ target không thuộc principal của requester.

Điểm cần nói rõ: đây là chặn ở tầng server, không phải bằng prompt. Nội dung của A không còn tới được session B.

Hồi quy: `TestSSHSteeringPrincipalMatrix` (named/all × same-user/cross-user), `TestCreateTaskSupplement_DeniesCrossUserCredentialTask`, `TestCreateTaskSupplement_AllowsSameExecutionUser`, `TestMayControlCredentialTaskForActor`.

## F4 — Đã bịt ở native bwrap

Vấn đề gốc: native worker ghi vào provider profile chung (theo provider + path canonical, không theo user), nên plugin/config A viết được có thể được task B nạp khi B khởi động và chạy trong môi trường có signer B.

Cách vá: tách writable provider state theo execution user + cắt host view.

- `server/internal/daemon/sandbox/native_runtime.go:246` — `nativeExecutionProfileHome`: profile root = `sha256(execution_user_id)` dưới `multica-native-execution-profiles/`; `ProfileKey` cũng trộn `ExecutionUserID` vào digest (`native_runtime.go:238`).
- `server/internal/daemon/sandbox/native_runtime.go:271` — `nativeProfilePathSpecs`: khi đã scope theo user thì bỏ qua các biến selector của host (`CODEX_HOME`, `CURSOR_CONFIG_DIR`, `CURSOR_DATA_DIR`, `OPENCODE_CONFIG_DIR`, `XDG_*`) để không trỏ về cây cấu hình chung; `CURSOR_DATA_DIR` bị dẫn sang `~/.cursor-data` riêng.
- `server/internal/daemon/sandbox/native_profile_seed.go:30` — `seedNativeExecutionProfile`: copy auth của operator vào cây scoped (bỏ các thư mục session/log lớn), copy là bản sao file — không phải symlink — nên credential không bị host symlink dẫn vào worker.
- `server/internal/daemon/sandbox/restricted_view.go:12` — `BuildRestrictedArgs`: worker native và version probe không còn thừa kế host directory nào, kể cả read-only; HOME của operator thành một thư mục rỗng, chỉ `/usr`, `/bin`, `/sbin`, `/lib*`, vài `/etc/*` công khai được mount.
- `server/internal/daemon/native_sandbox.go:343` và `:126` — native worker lẫn version probe đều dùng `BuildRestrictedArgs`; `BuildArgs` cũ (read-only host view) được giữ lại cho caller cũ và ghi rõ trong `server/internal/daemon/sandbox/policy.go:52` rằng nó không phải ranh giới confidentiality.

Docker không cần vá cùng dạng: `prepareGenericProviderHome` (`server/internal/daemon/execenv/provider_home.go:303`) copy provider home vào **home riêng của từng task**, nên profile của A không nằm trong cây của B.

Hồi quy: `TestNativeExecutionProfileHomeScopesByUser`, `TestNativeProfilePathsIgnoreHostSelectorsWhenExecutionUserScoped`, `TestSeedNativeExecutionProfileCopiesAuth` (+ 2 biến thể selector), `TestRestrictedViewDoesNotInheritHostDataRoots`, `TestRestrictedViewRecreatesCustomInstallationLinks`, `TestRestrictedViewBwrapDeniesPeerReadAndLateSocket` (probe bwrap thật; CI bắt buộc bằng `MULTICA_REQUIRE_BWRAP_SECURITY_TESTS=1` trong `.github/workflows/ssh-boundary.yml`).

## F5 — Đã bịt

Vấn đề gốc: endpoint lease xác thực daemon nhưng không chứng minh task/attempt đang sống, nên task đã terminal vẫn xin được lease mới; `attempt_id` do client gửi được lưu nguyên vào lease.

Cách vá: server là nguồn của attempt scope và kiểm tra lại ở mọi lệnh ký.

- `server/internal/handler/git_signing_access.go:35` — `taskEligibleForNewSigningLease`: chỉ `running`, `waiting_local_directory`, `dispatched`; terminal và chưa dispatch đều bị từ chối.
- `server/internal/handler/r2d_git_sign.go:63` — `attempt_id` của client vẫn parse (tương thích wire) nhưng **không dùng làm authority**; scope lấy từ `taskSigningAttemptID(task.Attempt, task.DispatchedAt)` — do server tự tính.
- `server/internal/handler/r2d_git_sign.go:78` — `requireGitSigningLeaseTaskEligible`: mỗi lần renew/sign đều đọc lại task row, kiểm tra daemon sở hữu runtime, kiểm tra task còn eligible, và so `lease.AttemptID` với scope hiện tại → lease của attempt cũ bị từ chối với `git_signing_stale_attempt`.
- `server/internal/handler/r2d_git_sign.go:40` — open lease cũng qua cùng gate.

Hồi quy: `TestOpenGitSigningLease_RejectsTerminalTask`, `TestSignGitData_RejectsLeaseAfterTaskTerminal`, `TestSignGitData_RejectsLeaseAfterTaskRedispatch` (test còn giả mạo `attempt_id` của client để chứng minh server không tin nó), `TestTaskEligibleForNewSigningLease`, `TestSSHSigningWireContractAndLifecycle` (attempt / redispatch / completed / failed / cancelled).

## C1 — Đã bịt về rò rỉ, còn mở về khả dụng

Vấn đề gốc: rotation gọi `revokeStaleLeases` trong RAM của instance đang xử lý; lease nằm ở instance khác vẫn sống, và sign/renew chỉ đọc state của key row (key cũ vẫn `Ready`) nên vẫn ký được.

Cách vá: kiểm tra trạng thái bền vững thay vì bản ghi lease trong RAM.

- `server/internal/r2dgit/signing.go:257` — `activeLeaseKey`: đọc `GetIdentityForUser` mỗi lần sign/renew và từ chối nếu `identity.Revoked` **hoặc** `identity.ActiveGeneration != lease.Generation`; key cũ sau rotation không còn là generation active nên chết dù vẫn `Ready` trong DB.
- `server/internal/r2dgit/signing.go:284, 338` — renew và sign dùng chính hàm này.
- `server/internal/r2dgit/signing.go:231` — `LeaseScope` trả về cả task id và attempt scope của lease để handler dùng.

Hồi quy: `TestSigningLeaseRejectsRotationFromAnotherBackend` — hai `Service` riêng, store/custody chung; xoay trên backend thứ hai, lease cũ ở backend thứ nhất bị `ErrRevoked` cả khi sign lẫn renew, key cũ vẫn `Ready` và lease không bị revoke cục bộ (test tự khẳng định điều kiện tái hiện được giữ nguyên).

Phần **còn mở**: lease registry vẫn nằm trong RAM của từng process (`s.leases` trong `server/internal/r2dgit/signing.go`). Request routed sang instance không giữ lease bị từ chối (`unknown lease`) — đây là fail-closed, an toàn nhưng là rủi ro *khả dụng*, và #109 đã ghi nhận mục "lease request affinity hoặc shared lease registry cho multi-backend" là chưa đóng. Bản vá C1 không thay thế việc đó.

## Đường còn tồn tại hoặc ngoài phạm vi bảo đảm

1. **Lease registry process-local (C1, khả dụng).** Đã mô tả ở trên. Chưa cần gấp nếu deployment single-backend; nếu chạy nhiều replica thì phải thêm affinity hoặc registry dùng chung, và tới lúc đó phải giữ bằng chứng rằng rotation trên một instance làm lease trên instance khác chết.

2. **Task không có originator vẫn dùng layout native dùng chung.** `nativeExecutionProfileHome` (`server/internal/daemon/sandbox/native_runtime.go:247`) giữ layout cũ khi `ExecutionUserID` rỗng, tức là task không có `originator_user_id`. Task như vậy **không có signer** (`TaskOriginator` trả `ErrPrincipal` → daemon không mở SSH_AUTH_SOCK, `server/internal/r2dgit/sqlc_store.go:476`, `server/internal/daemon/git_agent.go:94`), nên không rò khóa nào. Đây là bề mặt truyền code giữa các task *không gắn principal*, không phải đường leak SSH key. Nếu sản phẩm muốn task không-attributed cũng được cô lập profile thì cần tách `ExecutionUserID` rỗng thành một bucket riêng thay vì dùng layout cũ.

3. **Steering task không có originator vẫn mở cho thành viên khác.** `mayControlCredentialTask` trả `true` khi `task.OriginatorUserID` không hợp lệ (`server/internal/handler/agent_access.go:345`) — cùng lý do như (2): task đó không có SSH signer nên không rò khóa. Hành vi này là audit-only fallback (`attribution.OwnerFallback` chỉ set `AccountableUserID`, `originator` vẫn NULL — `server/internal/attribution/attribution.go:529`), nhưng nếu sau này ai đó cho task unattributed mang signer thì gate này sẽ mở theo.

4. **`docs/security/tool-isolation.md` chưa cập nhật theo F4.** Tài liệu vẫn viết "Native workers inherit the host filesystem read-only at its original paths", "Explicitly shared provider profiles remain one account trust domain", "Provider credential secrecy is currently deferred" (`docs/security/tool-isolation.md`, mục *Filesystem and shared profiles*). Sau PR #112, worker native có credential đã chạy trong restricted view với profile scope theo user, nên mô tả tài liệu đã lệch hành vi thực thi. PR #112 cũng không sửa tài liệu này.

5. **Smoke test provider CLI thật chưa chạy.** Mục nghiệm thu của #109 vẫn mở: chưa có bằng chứng end-to-end với hai tài khoản/repo Git thật trên host. Bộ test hiện tại dùng fake CLI/session và DB thật.

6. **Bwrap confidentiality probe không chạy được ở runner của audit này.** `TestRestrictedViewBwrapDeniesPeerReadAndLateSocket` bị skip vì kernel chặn unprivileged user namespace; CI workflow `ssh-boundary.yml` bắt buộc chạy nó với `MULTICA_REQUIRE_BWRAP_SECURITY_TESTS=1` nên sẽ fail nếu probe không chạy được. Kết luận F4 ở đây dựa vào đọc source + các test không cần namespace, không dựa vào probe bwrap.

7. **Isolation tắt và host bị chiếm quyền nằm ngoài phạm vi.** `MULTICA_TASK_SANDBOX=false/off` bỏ boundary; chmod 0700/0600 trên socket phân biệt OS UID chứ không phân biệt user Multica. Không thay đổi so với #109.

8. **Ngoài phạm vi #109 (không phải đường SSH key).** `GET /api/issues/{id}/task-runs` trả `agent_id` + `task_id` cho mọi thành viên workspace; điều này không còn là vector trực tiếp vì middleware xóa `X-Agent-ID`/`X-Task-ID` của client và chỉ re-stamp từ task token đã xác thực (`server/internal/middleware/auth.go:83`), nhưng nó vẫn là metadata nên giới hạn theo vai trò là hợp lý.

## Kiểm chứng đã chạy

Môi trường: Go 1.27.3, PostgreSQL 17.11 cục bộ, migrations `cmd/migrate up` đã apply trên `multica`.

| Lệnh | Kết quả |
| --- | --- |
| `go test -count=1 ./internal/handler/...` | ok (133s) — gồm `TestSSHSigningWireContractAndLifecycle`, `TestSSHSteeringPrincipalMatrix`, `TestRerunIssue_*`, `TestCreateTaskSupplement_*`, `TestOpenGitSigningLease_RejectsTerminalTask`, `TestSignGitData_RejectsLeaseAfterTask*` |
| `go test -count=1 ./internal/service/...` | ok (65s) |
| `go test -count=1 ./internal/r2dgit/...` | ok — gồm `TestSigningLeaseRejectsRotationFromAnotherBackend` |
| `go test -count=1 ./internal/daemon/sandbox/...` | ok |
| `go test -count=1 ./internal/daemon/gitagent/...` | ok |
| `go test -count=1 ./internal/daemon/...` | 2 fail **không liên quan** và **không phải hồi quy**: `TestWatchTaskCancellation_RunningTaskNotInterrupted` (`daemon_test.go:1637`, đòi poll ≥5 lần trong 150ms) và `TestRunTask_PrepareTimeoutStopsLeaseDuringBlockedStartTask` (`workdir_race_test.go:693`) — cả hai là test nhạy thời gian, pass khi chạy riêng (`-count=3`/`-count=5`), và `TestWatchTaskCancellation_RunningTaskNotInterrupted` fail y hệt trên base trước PR (`cd845448f`) |
| `go test -count=1 ./internal/attribution/...` | ok |
| `go test -count=1 -v ./internal/daemon/sandbox -run '^TestRestrictedView'` | 2 pass, probe bwrap thật bị **skip** (không có unprivileged user namespace) |

## Đề xuất

1. Cập nhật `docs/security/tool-isolation.md` theo hành vi F4 mới (restricted view + profile scope theo execution user) — mục (4) ở trên.
2. Quyết định rõ chính sách cho task không-attributed: hoặc tách bucket profile riêng, hoặc ghi rõ trong tài liệu rằng chúng không bao giờ có signer (hiện tại đúng nhưng chưa được viết ra).
3. Nếu triển khai nhiều backend replica: thêm lease affinity hoặc registry dùng chung, và giữ test hai-service dùng chung store làm hồi quy bắt buộc.
4. Chạy smoke test provider CLI thật (2 tài khoản + repo Git thật) để đóng mục nghiệm thu còn mở của #109.
5. Giữ `.github/workflows/ssh-boundary.yml` bắt buộc trong CI của nhánh chính — đó là chốt chặn duy nhất cho probe bwrap.

## Phụ lục — test hồi quy theo mã

| Mã | Test hồi quy | File |
| --- | --- | --- |
| F1 | `TestRerunIssue_ExecutionPrincipalOverridesSourceOriginator` | `server/internal/handler/ssh_signing_identity_test.go` |
| F1 | `TestRerunIssue_AgentTerminalTaskRefusesCredentialEnqueue` | `server/internal/handler/ssh_signing_identity_test.go` |
| F1 | `TestUpdateIssue_AgentTerminalTaskReportsBlockedRunDispatch` | `server/internal/handler/ssh_signing_identity_test.go` |
| F2 | `TestIssueService_QuickCreateOriginMustMatchAuthenticatedTask` | `server/internal/handler/ssh_signing_identity_test.go` |
| F3 | `TestSSHSteeringPrincipalMatrix` | `server/internal/handler/ssh_steering_matrix_test.go` |
| F3 | `TestCreateTaskSupplement_DeniesCrossUserCredentialTask` | `server/internal/handler/ssh_signing_identity_test.go` |
| F3 | `TestCreateTaskSupplement_AllowsSameExecutionUser` | `server/internal/handler/ssh_signing_identity_test.go` |
| F3 | `TestMayControlCredentialTaskForActor` | `server/internal/handler/ssh_signing_identity_test.go` |
| F4 | `TestNativeExecutionProfileHomeScopesByUser` | `server/internal/daemon/sandbox/native_execution_profile_test.go` |
| F4 | `TestNativeProfilePathsIgnoreHostSelectorsWhenExecutionUserScoped` | `server/internal/daemon/sandbox/native_execution_profile_test.go` |
| F4 | `TestSeedNativeExecutionProfileCopiesAuth` (+ `...CustomCodexSelector`, `...CustomCursorData`) | `server/internal/daemon/sandbox/native_profile_seed_test.go` |
| F4 | `TestRestrictedViewDoesNotInheritHostDataRoots` | `server/internal/daemon/sandbox/restricted_view_test.go` |
| F4 | `TestRestrictedViewRecreatesCustomInstallationLinks` | `server/internal/daemon/sandbox/restricted_view_test.go` |
| F4 | `TestRestrictedViewBwrapDeniesPeerReadAndLateSocket` (probe bwrap thật) | `server/internal/daemon/sandbox/restricted_view_test.go` |
| F5 | `TestOpenGitSigningLease_RejectsTerminalTask` | `server/internal/handler/ssh_signing_identity_test.go` |
| F5 | `TestSignGitData_RejectsLeaseAfterTaskTerminal` | `server/internal/handler/ssh_signing_identity_test.go` |
| F5 | `TestSignGitData_RejectsLeaseAfterTaskRedispatch` | `server/internal/handler/ssh_signing_identity_test.go` |
| F5 | `TestTaskEligibleForNewSigningLease` | `server/internal/handler/ssh_signing_identity_test.go` |
| F5 | `TestSSHSigningWireContractAndLifecycle` | `server/internal/handler/ssh_signing_wire_test.go` |
| C1 | `TestSigningLeaseRejectsRotationFromAnotherBackend` | `server/internal/r2dgit/signing_replica_test.go` |

CI bắt buộc: `.github/workflows/ssh-boundary.yml` chạy `go test -count=1 -v ./internal/daemon/sandbox -run '^TestRestrictedView'` với `MULTICA_REQUIRE_BWRAP_SECURITY_TESTS=1` (fail nếu probe bwrap bị skip) và `go test -count=1 ./internal/r2dgit ./internal/daemon/gitagent`.

## Tham chiếu bất biến

Tất cả đường dẫn trong báo cáo này trỏ tới `c864efca5f2ef939681afdeec5f82acaa9f8eb6d` trong repo `r2d-ai/multica` (fork của `ba0f3/multica`; hai repo cùng trỏ main head này). Báo cáo gốc của #109: `docs/security/ssh-key-security-review-2026-11-03.md` @ `f86a27d6e3f98fd3bdac59757c7ca3a502c1ffd6`.
