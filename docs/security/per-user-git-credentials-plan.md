# Git security MVP: Docker task worker và per-user SSH agent

Cập nhật **2026-10-21**. Tiếp tục trên **`feature/git-security-mvp`** của **`r2d-ai/multica`**, từ implementation baseline [`d67d4d548962a22f11001490e784955fedc9127f`](https://github.com/r2d-ai/multica/commit/d67d4d548962a22f11001490e784955fedc9127f). Đây là spec sửa tiếp code đã có, không phải yêu cầu làm lại từ main.

Đọc cùng [handoff](git-security-agent-handoff.md) và [implementation status](git-security-mvp-status.md). Tracker: [#84](https://github.com/r2d-ai/multica/issues/84); ba việc đang mở: [#86](https://github.com/r2d-ai/multica/issues/86), [#89](https://github.com/r2d-ai/multica/issues/89), [#88](https://github.com/r2d-ai/multica/issues/88). Spec này thay các chỉ dẫn bwrap/broker cũ (kể cả bản đã merge trên `main` qua #94); việc sửa docs không chứng nhận runtime đã an toàn hoặc đã deploy.

## 1. Quyết định và giới hạn

Dùng **một Docker container cho mỗi task attempt**, chạy trong VM Linux hiện có trên Proxmox. Giữ native adapters và CLI của đúng ba runtime: **Codex, Cursor Agent, OpenCode**. Shared daemon giữ orchestration; worker trong container thực thi adapter, agent, local MCP, native subagent, shell/file tools và toàn bộ Git lifecycle.

Giữ UI tạo key per-user/provider, encrypted custody và SSH-agent-compatible socket **List/Sign** đã có. Private Git key ở ngoài container; task chỉ nhận socket của attempt và public metadata. Không mount SSH agent, HOME hay credentials của host.

MVP vẫn có ba hạng mục, không mở lại S0–S6:

| Hạng mục | Tiếp tục phần đã có |
| --- | --- |
| #86 — keys/UI | Giữ public-key UI/API, generation/custody/verify/revoke; xác minh production wiring và quyền owner |
| #89 — worker | Thay bwrap launcher bằng Docker; hoàn thiện environment, native compatibility, IPC, network và cleanup |
| #88 — identity/signer | Gắn đúng originator + attempt + key; sửa task-token/API authority và tích hợp Git trong worker |

**Scope Git được giữ:** ban đầu chỉ cấp checkout của repo được chọn. Nếu user A có quyền X và Y, task cho X được phép clone Y vào filesystem riêng; provider phải từ chối repo Z ngoài quyền của A. Socket ký không biết Git repository path. GitHub/Gitea quyết định quyền read/write và branch protection; không hứa task-only repo/ref/read-only enforcement.

Không cần Firecracker, nested VM, Kubernetes, fleet manager, custom Git remote helper, exact-repo broker, grant database mới, second control/OTP server hoặc broad output/ACL rewrite. Không đưa nguyên execution engine của PR #93 trở lại.

Docker là boundary dùng chung cho ba runtime, vẫn chia sẻ kernel của VM. Yêu cầu bên dưới chặn các đường host/API/socket đã biết; không phải tuyên bố chống mọi kernel/container escape. Public Internet/model access vẫn được phép theo profile: đây không phải hệ thống ngăn agent gửi source ra mọi dịch vụ.

## 2. Reuse và lỗi cần sửa trên branch

Branch đã có credential primitives, worker entrypoint và native adapter dispatch. Giữ các phần đó; không port lại toàn bộ #93. [Status](git-security-mvp-status.md) ghi source map và evidence riêng.

| Quan sát tại baseline | Hướng sửa bắt buộc |
| --- | --- |
| `sandbox_launch.go` mount host HOME read-only, shadow một số credentials; workspace mặc định cũng nằm dưới HOME | Private writable HOME và checkout riêng; bỏ host-home mount/credential denylist workaround |
| Cwd đổi thành `/workspace/repo` sau khi tạo config; PATH/env/socket có nhiều lớp override | Chốt container paths trước khi tạo native config; một environment cuối dùng cho worker lẫn provider child |
| Codex auth có symlink ra profile host; Cursor trust/MCP hashes dựa vào host cwd | Provision đúng auth/state vào private profile; tính metadata từ container cwd |
| `sandbox/backend.go` gán `AttemptID = TaskID`, IPC chỉ message/result | Attempt ID thật; typed IPC hai chiều giữ contract của `agent.Session` |
| Prepare/finalize, repocache và host checkout RPC còn chạy ngoài worker | Chuyển Git execution vào worker; vô hiệu đường host checkout/cache cho protected tasks |
| Task JWT còn được mint theo runtime owner; đường `POST /api/cli-token` cần chặn task actor | Giữ task principal xuyên middleware; task credential không được đổi thành full CLI/user/admin credential |
| OpenCode 2.x có service riêng; custom wrapper mất native version detection; managed MCP đang bị từ chối | Cô lập cả service, pin native version và sửa/kiểm chứng config delivery trước khi công bố MCP support |

## 3. Docker worker contract

### Launch và filesystem

Trusted launcher chọn image, mounts, limits, network và attempt ID từ cấu hình server. Task không được chọn Docker engine endpoint, host path, capabilities hay network mode. Không mount Docker/Podman/containerd socket hoặc expose engine API vào task.

Image versioned gồm Multica worker/CLI, Git/SSH, ba native CLI phiên bản đã pin và toolchain cần cho repo. Không bind host binary install directories để làm runtime hoạt động. Chọn một deployment backend; ưu tiên rootless nếu các controls cần thiết thực sự hoạt động, hoặc cấu hình hardened rootful Docker rõ ràng. Không tự chuyển backend khi setup lỗi.

Container chạy non-root, drop all capabilities, no-new-privileges, default seccomp và LSM phù hợp host; không privileged, host PID/IPC/network hay host devices. Runtime root read-only; HOME, repo, tmp và cache cần ghi được cấp riêng. Giới hạn CPU, RAM, PIDs, timeout và log/output phải có hiệu lực trước untrusted execution. Ghi rõ writable-storage budget/retention; không gọi retention là hard disk quota.

Rootless resource limits cần kiểm tra cgroup v2/systemd/controller delegation trên host thật. Có flags nhưng limits bị bỏ qua không đạt gate. Không bắt buộc xây lại hệ thống quản lý daemon để có rootless.

Các đường chuẩn trong container:

| Path | Nội dung |
| --- | --- |
| `/workspace/repo` | Checkout task; Git metadata tự chứa |
| `/home/agent` | Writable HOME/config/session của execution profile đã được cấp |
| `/run/multica/ssh-agent.sock` | Chỉ socket của attempt hiện tại |
| Private tmp/cache paths | Không dùng chung writable state với task/user khác |

Không mount host HOME, daemon profile, shared workspace/repo ancestor hoặc sibling attempts. `.git` không trỏ tới host common-dir/object alternates; không cross-user writable hardlinks. Agent được ghi hoặc tạo repo khác bên trong filesystem riêng theo quyền provider của user.

Host chỉ tạo trusted launch metadata và xử lý protocol/output đã giới hạn; không chạy shell, Git hooks, repo scripts, archive helpers hay command do task quyết định. Repo-derived execution luôn ở trong container. Không thêm generic host-exec/mount/checkout RPC. Bind/import/export chỉ dùng task/profile roots đã xác định và kiểm tra, không theo symlink, ancestor alias hoặc path từ worker ra ngoài roots đó; restore không import nguyên HOME hoặc ghi vào profile user/attempt khác.

### Environment, native state và IPC

Chốt container cwd/HOME/config/socket paths trước khi compose native config. Resolve PATH trong image và một final environment dùng thống nhất bởi worker, adapter và child processes. Task/custom env không được ghi đè các bindings do launcher quản lý: HOME, PATH, SSH_AUTH_SOCK, task token/identity, protected context hoặc service endpoint. Agent sửa env bên trong container không được đổi authorization ở server.

AI-provider authentication tách biệt với Git identity. Cấp tường minh auth/config tối thiểu cho profile được phép dùng; có thể là service profile được operator cấp cho task, không cần xây UI/provider-auth broker mới. Không mount toàn bộ native profile của daemon. Credential file mà native agent cần đọc trong container **có thể được process đó đọc**; không hứa che được nó như SSH private key.

Native config/auth refresh/session phải ghi được vào private state. Không để symlink phụ thuộc shared host auth. Nếu cần persist/refresh, chỉ ghi về đúng authorized profile/state, không mở shared writable HOME. Resume giữ scope execution user, conversation, agent, repo và auth profile; reauthorize trước restore. B rerun issue của A không lấy native history, token hoặc socket của A. Retry có attempt ID/lease mới.

Giữ toàn bộ hành vi mà native `agent.Session` hỗ trợ: message/result streams, `Supplement` và readiness, `ToolActivity`, `InterruptBackgroundTools`, `TerminalObserved`, cancellation và bounded backpressure. Dùng typed bidirectional IPC; protocol lỗi phải kết thúc attempt rõ ràng, terminal result chỉ ghi một lần. Không buộc adapter cung cấp feature mà bản native của nó chưa hỗ trợ.

## 4. Compatibility của ba native agents

| Runtime | Phải giữ/sửa | Gate chức năng |
| --- | --- | --- |
| **Codex** | Giữ native app-server adapter trong container; private writable `CODEX_HOME`, auth/config đúng profile; bỏ host auth symlink | Start, shell/file tools, Git, managed MCP, auth/state write và authorized resume |
| **Cursor Agent** | Giữ native adapter; writable HOME kể cả không dùng managed MCP; trust/project slug/MCP approval hash theo container cwd | Native config/skills, shell/file tools, MCP, supplements/activity/background interrupt khi adapter hỗ trợ, resume/cancel |
| **OpenCode** | Cả CLI **và service** ở trong container. Với 2.x dùng `--standalone` đã kiểm chứng hoặc dedicated per-attempt server trong cùng container; chặn custom `--server`/attach redirect ra host | Pin version, đúng flags/model variant, shell/file tools, Git, resume/cancel và service chết cùng attempt |

Giữ native `BuiltinRuntime`/version detection; không đăng ký một opaque `docker ...` custom runtime làm adapter hiểu OpenCode 2.x thành v1. Nhánh hiện tại có `ErrOpenCodeV2MCPUnsupported`: ghi rõ version/profile chưa hỗ trợ và từ chối task yêu cầu feature đó, hoặc sửa private MCP config delivery và test trước khi claim support. Không ghi secret MCP vào file có thể commit trong repo, không âm thầm bỏ MCP để báo success.

Local MCP/subagents thuộc execution tree trong container. Remote MCP dùng đúng connections được cấp cho task, không tự lấy credentials/quyền runtime owner. Runtime khác ba tên trên chưa nằm trong support contract; protected mode báo unsupported thay vì chạy host.

## 5. Principal, API và SSH signer

Giữ UI Generate → Copy public key → register GitHub/Gitea → Verify → Revoke; rotation có thể dùng revoke + generate. API/UI chỉ trả public key, fingerprint và trạng thái. Human owner gate và account cache scoping vẫn bắt buộc; task/daemon/CLI-issued actors không được quản lý user keys.

Backend xác định authenticated originator từ task context có thẩm quyền, không tin user ID từ env/worker và không fallback runtime/agent owner. Chọn identity từ **repo/provider được chọn cho task**, không lấy first matching repo của toàn workspace. Bind immutable task, unique attempt, execution user, provider, key generation và daemon được phép ký. Thiếu hoặc sai context/key/custody thì block.

Task token vẫn mang giới hạn task/attempt sau mọi middleware; stale/terminal attempt không tiếp tục dùng token cũ. Cho phép đúng workflow API của task, gồm các thao tác Multica CLI cần thiết đã được authorize; từ chối token exchange/refresh thành full CLI/user/PAT/admin credential, gồm `POST /api/cli-token`, và runtime/daemon administration, host checkout hoặc key custody APIs. Kiểm tra bằng HTTP thật với task bearer, không chỉ bằng lệnh Multica CLI. Sửa `MULTICA_USER_ID` không giải quyết được token đã mang quyền owner.

List/Sign socket hiện có chỉ đưa selected public identity và signatures; reject add/remove/import/lock/unsupported operations. Mount đúng endpoint, kiểm tra UID/socket permissions của Docker mode, đặt `SSH_AUTH_SOCK` thống nhất tới container path. Không đưa daemon bearer, custody token, private Git key hoặc host Git config/helpers vào worker. Dùng public identity/known_hosts được cấp và strict host-key checking cho native Git path.

Clone, access probe, fetch, checkout, hooks, build và finalization chạy trong container với signer của user. Không dùng host Git để warm cache, prepare/finalize hay phục vụ `/repo/checkout` cho protected task. Trước cấp lại checkout/session, kiểm tra task authorization và quyền Git hiện tại; SSH banner verification chỉ xác nhận identity, không chứng minh quyền repo.

Reuse current lease service nhưng kiểm tra active attempt và key generation; lease có finite expiry, renewal chỉ từ trusted supervisor trong task lifetime. Một signature thành công không được tự giữ attempt chết sống vô hạn. Single-backend in-memory leases được chấp nhận cho MVP; multi-instance chưa hỗ trợ phải fail closed, không chọn key/backend fallback.

Multica child tasks kế thừa authorized originator qua server và nhận attempt/socket mới. Local revoke/rotate/cancel/timeout/end đóng accepted signer connections, ngừng ký, dừng toàn bộ container và authenticated SSH processes rồi cleanup. Unlink socket hoặc kill Docker client không đủ. Provider-side revoke có semantics của provider; không hứa cắt ngay một SSH session đã authenticated chỉ nhờ lần sign tiếp theo.

## 6. Network và lifecycle không được để thành đường vòng

Docker bridge hoặc private PID namespace không tự chứng minh task không gọi được host services. Enforce policy bên ngoài task trên **Docker network backend thực tế**:

- Chặn host management/daemon health-shutdown-checkout, Docker API, Proxmox management, link-local/metadata, LAN chưa được cấp và task containers khác.
- Cho phép đúng Multica **task API**, Git provider, model endpoint, DNS và public package/network access cần thiết. Gitea/model nội bộ là exception host/IP/port được operator khai báo; không mở cả LAN.
- Kiểm tra IPv4 và IPv6, hoặc disable IPv6 rõ ràng; hostname resolve về địa chỉ bị chặn không được bypass. Không giả định rootless user-mode network đi qua `DOCKER-USER`.
- API authorization ở mục 5 vẫn cần dù endpoint Multica được allow: network rule không phân biệt full-admin JWT với task JWT trên cùng URL.

Không cần generic egress-proxy platform/domain DLP trong MVP. Chọn một backend triển khai được, ghi cấu hình và kiểm tra negative/positive paths trên host thật.

Supervisor giữ container ID và ownership của attempt. Cancel/timeout/worker failure dừng container với finite grace rồi force kill; daemon mất kết nối/crash phải có bounded expiry/cleanup, startup reconcile orphan containers/sockets, không tự khôi phục lease cũ. Dọn task state theo retention, không theo path tùy ý từ worker.

Protected mode yêu cầu preflight image, mounts, signer, effective limits và network policy. Thiếu Docker/control cần thiết hoặc runtime unsupported thì báo task failure/blocked rõ ràng. Không fallback direct host exec, shared credentials hoặc bwrap workaround. Mặc định daemon bật Docker sandbox (`MULTICA_TASK_SANDBOX` unset); opt-out `false` chỉ cho dev. `MULTICA_TASK_PROTECTED=1` fail closed khi boundary không build được. **Node phục vụ protected attempts không chạy untrusted tasks ngoài sandbox bằng cùng host identity hoặc quyền truy cập daemon profile/Docker engine.** Unsupported runtime phải bị từ chối, không đưa sang direct-host execution trên node đó.

## 7. Thứ tự sửa và acceptance

Tiếp tục branch hiện tại bằng các commit nhỏ, không tạo implementation branch mới từ main và không reset/cherry-pick toàn #93. #89 có thể scaffold bằng fake CLI/socket; #88 tích hợp signer/authority; #86 giữ code và đóng các gap có evidence. Không đóng tracker chỉ vì docs hoặc UI đã merge.

1. **Worker contract:** Docker launcher, image/paths/attempt ID, native identity/version, private state, Session IPC và teardown; fake CLI chứng minh boundary.
2. **Integration:** chuyển Git lifecycle vào worker, signer path/principal/task-token/API gate, network policy; giữ credentials UI đang có.
3. **Compatibility và pilot:** pin ba native versions, chạy matrix dưới đây; ghi image/commit/deployment mode và actual results trong status.

| Check | Điều kiện đạt |
| --- | --- |
| A/B cùng shared runtime | Đúng originator/key; không đọc HOME, checkout, proc/env, socket hoặc native history của nhau; B rerun không reuse A |
| Native functionality | Cả ba runtime start, shell/file tools, config/auth state, Git và resume/cancel hoạt động; MCP/steering theo support contract, không silently downgrade |
| Host boundary | Host/sibling file canaries không đọc được; repo script/local MCP/subagent không chạy ở host; host checkout/admin/network canaries bị chặn |
| Task authority | Task bearer không mint CLI JWT, điều khiển runtime, đọc credentials hoặc đổi user/task/workspace/attempt để tăng quyền; intended task APIs vẫn hoạt động |
| Git identity/scope | A task X clone Y được nếu A có quyền; Z ngoài quyền bị provider deny; host credential canary không được dùng; self-contained `.git` |
| Secrets/UI | Public-only UI/API; không raw Git private key, daemon/admin/custody token trong worker/env/IPC/log; account switching đúng owner |
| Cleanup/limits | Cancel/revoke/crash/expiry đóng signer connections và dừng container, OpenCode service, SSH/children; retry có attempt mới; actual CPU/RAM/PID limits và bounded failure được kiểm tra |
| Fail closed | Missing image/Docker/signer/policy, unsupported runtime, bad host pin hoặc permission failure không chạy host/fallback identity; thử chọn unprotected execution trên protected node phải bị từ chối |

Default checks dùng synthetic keys, disposable repos/provider fixture và fake CLI. Docker integration cần kiểm tra trên deployment backend được chọn. Native-agent/account smoke chỉ chạy khi được ủy quyền, với `agentintegration` và `MULTICA_RUN_REAL_AGENT_SMOKE=1` trước executable/account lookup theo AGENTS.md. Báo rõ not-run/blocked; unit tests và bwrap smoke cũ không thay native Docker evidence.

Migrations `900100–900113` đã tồn tại trên branch cho credentials. Ghi inventory này ở #12; DB deployment chưa xác minh, spec không cấp số mới. Giữ `r2d_*`, no-FK và concurrent-index rules. Không thay upstream sync/backport cursor. Rollback là pause protected tasks, revoke/stop attempts và sửa; không chạy lại trên host.

## 8. Tool-only execution: PoC riêng, không chặn MVP

Mục tiêu tách agent loop khỏi tool executor hợp lý, nhưng ba native CLI chưa có một contract tích hợp chung đã kiểm chứng trong Multica. Không thay native CLI bằng ba SDK chỉ để hoàn thành việc này.

| Runtime | Candidate có thể thử sau | Điều kiện trước khi chọn |
| --- | --- | --- |
| Codex | [exec-server](https://github.com/openai/codex/blob/main/codex-rs/exec-server/README.md) + app-server environment | Chứng minh toàn bộ process/filesystem paths cần dùng đi qua remote boundary; không host fallback |
| Cursor | [SDK tools/custom tools](https://cursor.com/docs/sdk/typescript) và [bridge](https://cursor.com/docs/sdk/bridge) | Adapter khác native CLI; chứng minh no built-in bypass, ambient config/hooks/MCP/subagent containment và reapply restrictions khi resume |
| OpenCode | [v2 SDK](https://opencode.ai/v2/docs/build/sdk/effect/) / environment drivers | API còn version-sensitive; chứng minh full filesystem/process delegation, gồm config/instructions/plugins, trước khi để loop ở host |

PoC phải giữ model/account/quota/UX cần dùng, test file-read/write/exec/MCP/config/resume và fail-closed. Candidate nào chưa đạt vẫn chạy native worker trong Docker. Không yêu cầu Cloud Agents/Enterprise hoặc đổi billing plan.

## Nguồn và trạng thái bằng chứng

Source review pin tại `d67d4d5`: [launcher](https://github.com/r2d-ai/multica/blob/d67d4d548962a22f11001490e784955fedc9127f/server/internal/daemon/sandbox_launch.go), [worker/IPC backend](https://github.com/r2d-ai/multica/blob/d67d4d548962a22f11001490e784955fedc9127f/server/internal/daemon/sandbox/backend.go), [Session contract](https://github.com/r2d-ai/multica/blob/d67d4d548962a22f11001490e784955fedc9127f/server/pkg/agent/agent.go), [daemon Git paths](https://github.com/r2d-ai/multica/blob/d67d4d548962a22f11001490e784955fedc9127f/server/internal/daemon/daemon.go), [task auth middleware](https://github.com/r2d-ai/multica/blob/d67d4d548962a22f11001490e784955fedc9127f/server/internal/middleware/auth.go), [token handlers](https://github.com/r2d-ai/multica/blob/d67d4d548962a22f11001490e784955fedc9127f/server/internal/handler/auth.go), [OpenCode v2](https://github.com/r2d-ai/multica/blob/d67d4d548962a22f11001490e784955fedc9127f/server/pkg/agent/opencode_v2.go).

Deployment references: [Docker security](https://docs.docker.com/engine/security/), [rootless resource limits](https://docs.docker.com/engine/security/rootless/tips/#limiting-resources), [Docker packet filtering](https://docs.docker.com/engine/network/packet-filtering-firewalls/), [OpenCode v2 CLI](https://opencode.ai/v2/docs/cli/commands/).

PR #94 và #95 đã merge các bản spec trước; #93 closed, không merge. Chỉ dùng history #93 khi cần tra credential provenance; implementation baseline là feature branch hiện tại. Source review chỉ chứng minh code path cần sửa, không phải exploit/runtime proof. Cập nhật status và #84/#12 theo evidence của từng implementation commit.
