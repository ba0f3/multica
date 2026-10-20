# Spec: bwrap theo task, Git identity theo user

Ngày: 2026-10-20. Trạng thái: đặc tả để implement; chưa triển khai runtime mới.

Thay đổi lần này chỉ cập nhật spec/handoff. Chưa trích code credentials từ PR #93, chưa triển khai bwrap và chưa chạy acceptance tests của runtime mới.

- Repo đích: **r2d-ai/multica**, base **main** tại `ef0972f21e5825fb281957ede41a1072aa008a02`.
- Tracker: [#84](https://github.com/r2d-ai/multica/issues/84), patch/backport cursor [#12](https://github.com/r2d-ai/multica/issues/12).
- Thay thế kiến trúc implementation của [PR #93](https://github.com/r2d-ai/multica/pull/93). Chỉ trích phần credentials được liệt kê ở mục 10; không merge toàn PR.
- Quyết định của user: Linux + bubblewrap, key riêng từng user/provider, UI chỉ hiện public key, task chỉ tiếp cận repo được cấp và không sử dụng Git credentials của host.
- Handoff ngắn: [git-security-agent-handoff.md](git-security-agent-handoff.md).

## 1. Quyết định kiến trúc

**Mỗi task attempt chạy một Multica worker bên trong bwrap. Worker chứa cả agent adapter, coding-agent process, ACP terminal callbacks, local MCP và subprocess. Shared daemon ở ngoài làm supervisor.**

Tên binary không quyết định isolation. `bwrap ... multica internal-task-worker` bao được coding agent do worker sinh ra. `bwrap ... multica issue run` không bao được agent nếu lệnh này chỉ gửi request tới daemon đang chạy ngoài sandbox.

| Vị trí bọc | Đánh giá |
| --- | --- |
| CLI gửi request tới daemon có sẵn | Không cô lập tiến trình do daemon tạo sau đó |
| Toàn bộ shared daemon | Con của daemon kế thừa sandbox, nhưng các user/task vẫn chung boundary và tập mount |
| Chỉ binary coding agent | Bao local descendants; bỏ sót callback chạy trong Multica adapter bên ngoài |
| **Per-task Multica worker** | **Chọn:** bao adapter, callbacks và toàn bộ cây tiến trình của đúng task |

### 1.1 Hai vùng riêng trong một run

~~~mermaid
flowchart TD
  A["Server: xác thực user và cấp run grant"] --> B["Shared daemon: supervisor"]
  B --> C
  subgraph S["bwrap của task attempt"]
    C["Multica task worker"] --> D["Coding agent và ACP terminal"]
    D --> E["Shell, build, local MCP, native subagent"]
    C --> R["Repo task và HOME riêng"]
    E --> R
    E --> H["Git remote helper"]
  end
  H --> G["Git transport broker: đúng user và repo"]
  A --> G
  G --> K["Kho private key mã hóa"]
  G --> V["GitHub hoặc Gitea"]
~~~

Coding sandbox chỉ có socket Git gắn với run. Broker sử dụng private key của user để mở SSH cho đúng repo. Nếu cần key file, chỉ mount tạm key đó vào tiến trình SSH riêng của broker; không mount private key hoặc socket `ssh-agent` tổng quát vào coding sandbox.

Đây vẫn là **Git chạy bằng credential của user**. Read-only mount private key vào coding agent sẽ cho agent đọc/copy key; key của một account cũng có thể truy cập các repo khác của account đó. Vì vậy mount một checkout không tự giới hạn quyền Git theo repo.

### 1.2 Phạm vi V1

- Một repo được chọn rõ ràng cho mỗi run; repo phải thuộc project/resource hợp lệ và user có quyền thực tế trên Git provider. Có thể chạy nhiều run đồng thời, mỗi run một boundary.
- Linux runner; Codex và Cursor là hai adapter phải nghiệm thu đầu tiên. Adapter khác chỉ advertise hỗ trợ khi qua cùng các gate.
- Clone/fetch/pull/commit/push Git native, gồm file binary Git thông thường; không đặt giới hạn text-only như candidate cũ.
- GitHub và Gitea đều cần read/write integration. V1 dùng SSH transport native; không tự viết Git pack protocol hoặc một hệ thống quản trị execution thứ hai.
- Giữ API, UI login, task orchestration và reporting hiện có. Bổ sung worker, grant, transport và các authorization hook cần thiết.
- Submodules, LFS, multi-repo, PR/API automation và commit signing cần adapter/grant riêng; khi chưa hỗ trợ phải báo rõ. Không dùng PAT chung để lấp chỗ thiếu.

**Giới hạn phải nói đúng:** V1 giới hạn repository và quyền read/write. Native `receive-pack` vẫn cho client yêu cầu thay đổi các ref trong repo đó; branch/tag protection do GitHub/Gitea thực thi. Không tuyên bố broker V1 ép được task chỉ push một feature branch. Nếu deployment yêu cầu ref allowlist riêng của Multica, giữ write disabled cho tới khi có enforcement phía tin cậy và test riêng.

Không biến feature này thành chương trình chống mọi hình thức sao chép source. Agent được phép đọc source của task và gửi cho model được duyệt. bwrap dùng chung kernel với host; host-root, control-plane compromise và kernel escape nằm ngoài bảo đảm này.

## 2. Hiện trạng đã kiểm tra

Các nhận xét dưới đây dựa trên source ở main SHA nêu trên, không phải kết luận về daemon đang deploy. Default branch của fork là `main`; không có branch `release` tại lúc kiểm tra. PR #92 đã merge; PR #93 chưa merge tại thời điểm đánh giá.

| Source hiện tại | Hành vi quan sát | Thay đổi bắt buộc |
| --- | --- | --- |
| `server/internal/daemon/daemon.go`, `runTask`, `prepareExecutionEnvironment`, `executeAndDrain` | Orchestration, prepare và backend execution trong daemon | Tách phần thực thi theo task vào worker; daemon chỉ giữ lifecycle/typed IPC |
| `server/pkg/agent/acp_terminal.go`, `acpTerminalCreate` | Agent yêu cầu command/CWD/env; adapter gọi `exec`/shell | Callback phải ở trong worker; không gửi arbitrary exec về host |
| `daemon.go`, đoạn HOME/XDG | Cố ý giữ HOME/XDG của daemon để các CLI dùng host state | Worker nhận environment từ allowlist và HOME riêng |
| `server/internal/daemon/execenv/isolation.go`, `PrepareIsolated` | Helper process có thể kill; chưa phải OS sandbox | Không coi tên `Isolated` là bằng chứng có bwrap |
| `server/internal/handler/daemon.go`, claim/finalize | Task token dùng `rt.OwnerID`, rồi `locked.OwnerID` | Protected task token và grant phải dùng cùng execution principal |
| `server/internal/attribution/attribution.go`; `server/internal/service/task.go` | Có `originator_user_id` và parent/source-task lineage; audit owner có thể khác | Tái sử dụng authorization originator đã xác minh; cấm audit-owner fallback |
| `server/internal/handler/project_resource.go`, `resolveClaimProjectContext` | Có fallback về workspace repositories | Protected run không fallback; phải có repo grant cụ thể |
| `server/internal/daemon/health.go`, `repoCheckoutHandler` | Checkout dựa task/workdir nhưng repo allowance theo workspace | Không expose endpoint cũ cho protected worker; grant quyết định repo |
| `server/internal/daemon/repocache/cache.go` | Git env bắt đầu từ `os.Environ()`; cache workspace+URL; Linux local clone có hardlinks | Không chạy protected Git qua ambient path; metadata/cache riêng |
| `execenv/codex_home.go`; `execenv/execenv.go` | Shared auth symlink; native session/provenance thiếu execution user | Không mount shared home để sửa symlink; bind session theo principal/repo |

Các đường dẫn trên được liên kết tại mục 13. `server/pkg/agent/launch.go` là điểm tạo command chung hữu ích để assert/test, nhưng chỉ sửa điểm này không đủ nếu callback vẫn chạy trong shared daemon.

Tracker #12 ghi lịch sử ACL riêng của fork, nhưng package `server/internal/r2dauth` không có trong tree baseline đã đọc. S0 phải đối chiếu policy đang có và chốt adapter authorization; không giả định historical ACL đã hiện diện, không lén backport cả stack trong feature này.

## 3. Invariants để nghiệm thu

1. Execution principal là human thật sự cấp quyền cho run, do server xác định; không lấy từ prompt, env, header do agent đưa, agent owner hoặc runtime owner.
2. Mọi executable có thể chịu ảnh hưởng từ task/repo chạy trong bwrap worker: prepare hooks, coding agent, terminal callbacks, tools, local MCP, tests, finalize và Git inspection.
3. Một attempt chỉ thấy repo đã cấp, HOME/session/temp của chính nó, runtime/toolchain được duyệt và các capability socket hẹp.
4. Không thấy host HOME, sibling tasks, `.repos` chung, DB/admin credentials, SSH agent, daemon admin token hoặc container-engine socket.
5. Git authorization = quyền Multica hiện tại AND repo được bind vào run AND quyền provider với key đúng user AND operation được phép.
6. Key generation/ownership chỉ dựa authenticated human session. Private key không có trong UI/API DTO/task payload/agent mounts/logs.
7. Không có fallback sang shared/admin/host Git credentials; không hạ xuống unsandboxed execution khi bwrap/namespace/network policy lỗi.
8. Native subagents cùng process tree có cùng hoặc ít quyền hơn boundary cha; server-dispatched child có context/attempt riêng và không được mở rộng grant.
9. Resume/cache/output đều có principal và source scope; đổi user không được reuse session người trước.
10. Revoke/cancel ngăn operation mới, đóng transport đang mở và dừng descendants theo latency có test.

## 4. Key management trên UI

### 4.1 Luồng user

Account/Profile → Git identities → chọn GitHub/Gitea instance do admin cấu hình → **Generate key** → **Copy public key** → user add vào account Git của mình → **Verify** → Ready.

Hiển thị provider, provider account đã verify, public key, SHA256 fingerprint, generation, trạng thái và lỗi có cách khắc phục. Không có nút xem/tải/copy private key. Không yêu cầu user tự tạo hay upload private key trong V1.

Một key family cho mỗi user/provider instance; rotate tạo generation mới. Chưa verify key mới thì key đang active vẫn hoạt động. Activate generation mới thu hồi lease generation cũ. Revoke vô hiệu local use ngay; UI ghi riêng trạng thái cleanup và nhắc user xóa public key cũ trên provider. Local revoke không đồng nghĩa public key đã được GitHub/Gitea xóa.

Verify chứng minh key đăng nhập vào account nào qua SSH host đã pin; không suy ra repo permission từ thành công SSH login. Parser greeting GitHub/Gitea phải có fixture, xử lý exit status theo provider. Nếu cần immutable provider account ID, dùng provider adapter đã xác thực; không coi username do user nhập là bằng chứng. Không cho một key family đổi sang account khác khi rotate mà không qua linking flow mới.

Verify/activate phải chỉ rõ generation và expected state/version để request từ UI cũ không thao tác nhầm key. Revoke toàn identity cố ý vô hiệu cả active/pending generations; nếu hỗ trợ revoke một generation thì API phải phân biệt rõ hai thao tác.

### 4.2 Custody và API

- Backend sinh Ed25519 bằng CSPRNG; lưu private key mã hóa qua custody adapter. Ưu tiên trích OpenBao/Vault KV v2 adapter từ #93 để dùng secret store đã có; không đưa token secret store vào daemon worker.
- DB chỉ giữ identity/provider/user/generation, public key, fingerprint, state, secret reference nội bộ và lifecycle jobs. Secret reference cũng không trả cho browser.
- Tái sử dụng session/CSRF và recent-auth của ứng dụng hiện tại. Không mang local OTP/control server riêng của #93 sang chỉ để quản lý keys.
- Owner lấy từ authenticated session, không nhận `user_id` làm authority. Agent/task/daemon token không được gọi key-management API. Workspace admin không được export hoặc Git impersonate user qua API này.
- Generate/verify/activate/rotate/revoke cần idempotency, CAS và retryable cleanup. Không giả định DB transaction bao được secret store. Không đánh dấu Ready nếu secret/verification chưa xong.
- Hủy tất cả secret versions cần hủy, không chỉ soft-delete KV version. Sau restore, protected execution mặc định pause cho tới khi đối chiếu identity/generation/revocation; V1 không xây witnessed-restore platform riêng.

| API family | Contract |
| --- | --- |
| `GET /api/me/git-identities` | Public metadata của chính user |
| `POST /api/me/git-identities` | Sinh key cho approved provider, có idempotency |
| `POST /api/me/git-identities/{id}/verify` | Verify provider account với host pinning |
| `POST /api/me/git-identities/{id}/rotate` | Tạo pending generation |
| `POST /api/me/git-identities/{id}/activate` | Activate verified generation và invalidate generation cũ |
| `POST /api/me/git-identities/{id}/revoke` | Local revoke đồng bộ; cleanup có thể retry |

Đây là contract logic; khi port có thể giữ tên route tương đương từ #93 để giảm thay đổi, nhưng không giữ endpoints không thuộc scope. Public DTO qua zod; Query cache có user ID và được clear khi đổi account. UI shared web/desktop trong `packages/views`, API/schema/query trong `packages/core`.

## 5. Run identity, grant và delegation

### 5.1 Context bất biến

Server tạo record riêng của fork, liên kết task/attempt bằng ID; không thêm custom columns vào upstream tables. Contract tối thiểu:

~~~text
run_id, attempt_id, task_id, root_run_id, parent_run_id
execution_user_id, authorization_provenance
execution_workspace_id, resource_workspace_id, project_id
provider_id, canonical_repository_id, canonical_repository_path
credential_identity_id, credential_generation
allow_read, allow_write, policy_epoch, expires_at
runtime_id, runtime_profile_digest, network_policy_id, model_auth_profile_id
~~~

Manifest đưa cho worker chỉ là subset cần thiết; không có private key, secret-store reference/token, admin identity hoặc đường dẫn host tùy chọn. Repo/host/path/policy do server và supervisor giải quyết từ registry, không nhận nguyên xi từ agent.

Giữ Team = Workspace và project collaboration semantics đã được chốt ở #12. Nếu repo thuộc resource workspace khác execution workspace, chỉ grant tài nguyên đã authorize, không cấp inventory/secret của workspace đó.

### 5.2 Quy tắc theo trigger

| Tình huống | Principal và state |
| --- | --- |
| Human A trực tiếp run/comment/mention/assign | A sau khi server kiểm tra quyền thao tác |
| A dùng agent hoặc squad do admin sở hữu | Vẫn A; ownership agent không chọn Git key |
| Native subagent do CLI spawn | Trong sandbox cha; không coi là identity mới |
| Child task qua Multica | Xác minh source task/parent/root từ DB; cùng A, repo/operation là subset; lease mới |
| Auto retry | Giữ A, attempt mới, reauthorize; không replay token attempt cũ |
| Human B tiếp tục/rerun | Context mới của B, HOME/native session mới; không kế thừa key/history của A |
| Schedule/webhook không có grant rõ ràng | Block protected Git; audit owner không đủ |

Null originator, parent giả/stale, chuỗi vòng, project chuyển hoặc grant hết hạn phải deny. Normal parent completion không tự hủy child hợp lệ; root cancellation/offboarding/revoke thì hủy toàn lineage. User mới chỉ nhận source/context cũ qua output/handoff đã được authorize.

### 5.3 Task-token phải khớp grant

Main hiện mint task token theo runtime owner. S2 phải thay protected claim/finalize và middleware để effective execution user của task token lấy từ context đã khóa, đồng thời ràng buộc task/agent/workspace/project/repo/attempt.

Không chỉ thêm `EXECUTION_USER_ID` vào env rồi giữ owner token. Không chỉ đổi `UserID` mà cho token thừa hưởng toàn bộ API quyền human. Protected task actor chỉ có endpoint/resource capabilities của run; không gọi key management, runtime admin, workspace-wide secret/MCP/integration hoặc generic checkout để mở rộng quyền.

Runtime advertise capability **`r2d-bwrap-task-v1`** sau self-check. Server chỉ claim protected tasks cho runtime có capability và policy digest được operator chấp nhận. Old daemon/unsupported adapter bị block với lỗi rõ, không trả payload nhạy cảm rồi mới kiểm tra.

## 6. Worker bwrap

### 6.1 Vòng đời

1. Server authorize enqueue/claim, khóa immutable run context, xác minh identity Ready và repo binding.
2. Supervisor tạo attempt directory riêng, cgroup và các run-specific sockets. Limits và cgroup placement phải có hiệu lực trước khi worker/untrusted code được chạy, qua atomic placement hoặc start-block gate; không launch rồi mới attach. Chưa cung cấp source từ cache khi chưa có provider proof hợp lệ.
3. Supervisor khởi chạy bwrap bằng argv đã build từ policy; bên trong gọi hidden subcommand `multica internal-task-worker` với manifest qua FD/pipe được kiểm soát.
4. Worker tạo config/HOME sạch, clone repo qua scoped transport, rồi mới chạy prepare có thể thực thi repo code và instantiate `agent.ResolveBackend`.
5. Adapter, ACP terminal, local MCP, CLI hooks, native subagents, tests và finalize chạy trong worker. Supervisor nhận typed progress/result và truyền supplement/cancel qua IPC hẹp.
6. Artifact/diff inspection chạy trong sandbox hoặc unprivileged collector bị giới hạn. Không chạy host `git status/diff/clean` trên `.git` do agent sửa.
7. Finish/cancel/revoke đóng lease và streams, dừng toàn cgroup, collect output có authorization, rồi cleanup. Crash/restart phải reconcile các run còn sót trước khi nhận run mới.

Provider version/model-discovery probes có thể chịu ảnh hưởng từ task/custom runtime, cùng retry/fresh-session fallback, phải chạy trong worker hoặc probe sandbox có policy tương đương. Không chạy wrapper của task trên host trong preflight rồi mới sandbox bước Execute.

Worker không cung cấp RPC `exec_on_host`, arbitrary mount, arbitrary path read hoặc generic network forwarding. IPC event từ worker là untrusted output: identity/path/resource ngoài event vẫn lấy từ context của supervisor. Đặt giới hạn message size, backpressure, deadline và cancel trong lúc queue đầy.

### 6.2 Mount và environment

| Trong sandbox | Quyền / nguồn |
| --- | --- |
| `/workspace/repo` | RW, chỉ checkout của run; `.git` tự chứa metadata riêng |
| `/home/agent` | HOME riêng; session chỉ restore sau reauthorization cùng principal/repo |
| `/tmp`, `/run/task` | Private tmpfs/runtime state của attempt |
| Runtime/toolchain root | Read-only, operator chuẩn bị; binary và helper không ghi được bởi repo |
| `/proc`, `/dev` | proc mới trong PID namespace, device tối thiểu; không bind host proc/dev |
| `/run/task/git.sock` | Chỉ transport capability của run; không phải ssh-agent |
| Model/network/API bridge | Chỉ capability được grant; không expose admin listener |

Không `--ro-bind / /`, không bind `/home`, toàn `/run`, toàn workspace root, `/var/lib`, shared `.repos`, host `.ssh`, D-Bus/systemd/Docker/Podman sockets. Bind RO vẫn đọc được secret nên không phải cách che host data.

Bắt đầu environment rỗng (`--clearenv`) rồi allowlist PATH/HOME/XDG/temp, locale, task metadata, scoped API và runtime config cần thiết. Không copy `os.Environ()`, host `SSH_AUTH_SOCK`, `GIT_*`, `GH_TOKEN`, provider PAT, cloud/DB variables. User custom env không được override security paths, proxy policy hoặc capability selection.

Mount sources lấy từ trusted registry; supervisor tạo và sở hữu ancestors, không follow symlink do task kiểm soát, không resolve lại agent-supplied host paths sau authorize. FD inheritance theo allowlist: không lọt directory FD, namespace FD, DB socket, daemon connection hoặc file private key vào worker.

### 6.3 Kernel và process policy

- Required mount/user/PID/IPC/UTS/network namespaces; explicit flags và startup verification. Không dựa riêng vào `--unshare-all` vì một số thành phần dùng chế độ try. Không dùng `--share-net` cho protected profile.
- Unprivileged worker, drop capabilities, no-new-privileges, `--new-session`, `--die-with-parent`, proc private và seccomp profile đã test. Chặn nested namespace escape khi toolchain không cần; browser/Electron có nhu cầu riêng phải có profile/test riêng.
- Supervisor dùng cgroup v2 để giới hạn CPU/RAM/PIDs, timeout và kill subtree; disk/temp/output có quota/limit riêng. PID namespace hoặc process-group cleanup một mình không đủ chống tài nguyên cạn hoặc daemonized child còn sống.
- Mount/cgroup/userns/seccomp/network setup không đạt → `sandbox_unavailable`, không launch trực tiếp. Không tự đổi sysctl, thêm privilege hoặc tắt host security để chạy qua gate.
- Bwrap không yêu cầu chuyển daemon sang Docker hoặc systemd. Provisioning phải cấp đủ delegated cgroup/network prerequisites cho launcher; `multica daemon start` vẫn có thể là cách vận hành. Broker/secret service chạy dưới service identity riêng, không cùng trust domain với untrusted worker.

### 6.4 Network và coding-provider auth

Private network namespace mặc định không có đường tới host/LAN/Internet. Cung cấp loopback-to-UDS relay tới egress proxy được kiểm soát bên ngoài; proxy quyết định destination từ policy, không tin riêng biến `HTTP_PROXY`. Direct sockets/DNS, host loopback, metadata endpoints và private ranges bị chặn trừ dịch vụ cụ thể được cấp.

- Git chỉ đi qua Git broker; không mở GitHub/Gitea SSH/HTTPS/API chung trong model/package proxy.
- LLM endpoints có allowlist riêng. Package install dùng registry/cache được duyệt; không cấp unrestricted CONNECT để làm mọi download chạy được. Kiểm tra redirect, DNS rebinding và private IP ở proxy.
- Local test servers chạy trong namespace của run. Host services cần thiết phải có bridge cụ thể và credentials tối thiểu; Docker build/deploy dùng CI sau push, không mount Docker socket.
- Local MCP nằm trong worker. Remote MCP/API access được cấp theo user/task/resource; không inherit toàn bộ MCP connections của runtime owner.

Git identity và model subscription identity là hai contract riêng. Spec này không yêu cầu thay routing Codex/Cursor hiện tại, nhưng bắt buộc bỏ ambient host auth discovery. Runtime auth adapter chỉ cấp đúng auth/config tối thiểu đã được duyệt cho run, không mount cả `.codex`/`.cursor`, history, plugins hay keychain host.

Nếu coding CLI cần đọc một auth token, phải ghi rõ token đó nhìn thấy trong coding sandbox và rủi ro của profile; không gọi nó là secret ẩn với agent. Shared coding subscription chỉ dùng khi là một auth profile được operator cấu hình rõ, không phải host-credential fallback. Provider chưa chạy được với clean HOME và egress profile thì chưa được advertise protected support.

## 7. Git transport hẹp, giữ Git native

### 7.1 Contract

Cài helper tin cậy `git-remote-multica` trong read-only runtime. Remote có dạng `multica::<opaque-grant-handle>`; helper hỗ trợ native Git `connect` cho `git-upload-pack` hoặc `git-receive-pack`. Clone/fetch/pull/push vẫn dùng Git thông thường trong sandbox; source parsing, hooks và filters không chạy ở host.

Broker gắn mỗi socket với run/attempt/principal/repo/key generation đã đăng ký. Request chỉ chọn operation được allow, không được chọn user, secret ID, host, URL, port, repo path, remote executable hay SSH options. Handle không thay thế server authorization; giả handle/cross-run/replayed lease đều bị chặn.

Broker mở **một SSH session mới cho mỗi operation**, dùng credential đúng user và đúng command do server dựng:

~~~text
read  -> git-upload-pack '<registered canonical repository path>'
write -> git-receive-pack '<registered canonical repository path>'
~~~

Client gửi/nhận Git protocol bytes qua hai pipe. Broker không chạy Git trong working tree của agent, không parse pack để xây một source-transfer protocol mới, không đưa raw SSH channel hoặc signer API cho agent.

`SO_PEERCRED` chỉ là defense bổ sung: nếu các sandbox dùng cùng host UID thì nó không phân biệt user/task. Mỗi run có socket directory riêng và capability được bind với context, expiry, attempt; chỉ mount endpoint đó. Capability/lease không được log hoặc được user khác enumerate.

### 7.2 Provider authorization

Admission và trước resume/cache delivery: dùng key đúng user mở read transport thật tới repo và hoàn thành probe Git hợp lệ, không chỉ `ssh -T`. Trước mỗi operation broker recheck local user/project/grant/credential epoch; provider kiểm tra quyền bằng SSH session mới đó. Write yêu cầu cả task allow_write và provider cho phép write.

Không coi public repo clone được là bằng chứng user có membership hay write. Nếu project policy yêu cầu membership hoặc role cụ thể ngoài provider read, dùng provider permission adapter hoặc grant đã xác minh; không suy luận từ read success.

Canonical repo lấy từ registry: provider instance, SSH authority, repository identity/path. Nếu provider có stable ID thì giữ ID; rename/path reuse phải rebind/revalidate. Không tự follow redirect/alias sang repo khác. Gitea nội bộ chỉ mở đúng host/IP/port đã duyệt.

### 7.3 SSH và key lease

V1 chọn **OpenSSH với broker-only temporary key materialization** để giữ một transport implementation cần nghiệm thu. Broker dùng custody service lấy key đã đăng ký của user, không tạo key SSH mới mỗi task; materialize ngắn hạn vào broker-only tmpfs/FD phù hợp, permission chặt và cleanup khi operation kết thúc. Coding sandbox không thấy secret file, secret directory hay signer socket.

`WithSigner` của #93 không cung cấp key path: credential extraction phải bổ sung internal materialization/lease adapter chỉ dành cho trusted transport, không thêm API reveal/export cho browser, daemon worker hoặc agent. Go SSH signer transport là lựa chọn có thể đánh giá sau nếu cần, không implement hai đường trong V1.

SSH argv/config cố định: clean environment, absolute binary, isolated HOME, `BatchMode=yes`, `IdentitiesOnly=yes`, `IdentityAgent=none`, strict host-key pins, TTY/forwarding/X11/agent forwarding disabled, không multiplex/ControlPath, không ProxyCommand/LocalCommand/host config. Truyền stdin cho Git; không dùng `ssh -n`.

Remote path có grammar allowlist và quoting đúng theo provider; không nối shell từ agent input. Reject control characters, traversal, tùy chọn giả, URL credentials và service override như `--upload-pack`/`servpath`. Chỉ operation enum read/write được map tới command cố định. Không có shell, generic SSH exec, port forwarding hoặc `git-lfs-authenticate` trong V1.

Key plaintext chỉ tồn tại trong trust domain custody/transport cần dùng nó; không tuyên bố HSM/non-exportable hoặc memory wipe tuyệt đối. Không core dump, không disk-backed temp lưu key; crash sweeper và revoke đóng active SSH sessions. Broker/secret-store admin vẫn là trusted operator.

### 7.4 Write và audit

V1 không đọc Git pack để áp ref ACL. GitHub/Gitea branch/tag protections và actor permissions là enforcement cho force/delete/default branch. Task feature-branch naming là workflow, không phải security boundary. S0/S6 phải kiểm tra protection của pilot repo trước khi enable write; nơi chưa đủ protection chạy read-only.

Audit server ghi principal/task/attempt, repo ID, fingerprint/generation, operation, decision, timestamps, byte count và SSH outcome; không raw key/token/source. Opaque forwarding không cung cấp ref-level audit đáng tin từ client; dùng provider audit/verified result khi cần. Không coi narrative của agent là bằng chứng push thành công.

Nếu write mất kết nối sau khi có thể đã áp dụng, đánh dấu outcome unknown và reconcile remote ref qua operation đã authorize; không tự retry push mù. Lease expiry/cancel/revoke đóng cả hai pipe và SSH process. Limits cho concurrent streams, bytes, idle/total duration có config và test.

Task/transfer dài được gia hạn lease bởi trusted supervisor qua server trước expiry, sau current permission/epoch/generation checks. Renewal giữ nguyên principal/repo/attempt/operations, không tăng quyền và không đổi key generation. Worker không có quyền tự mint/renew. Active stream chỉ được tiếp tục nếu đã có renewal hợp lệ; expiry hoặc renewal failure đóng stream và pause/stop run. Lease TTL khác maximum operation duration; duration vẫn có budget riêng.

## 8. Repo/cache/session/output

### 8.1 Repo và disk

V1 clone qua scoped transport vào task checkout riêng. Không gọi `registerTaskRepos`/background sync bằng host key cho protected repo; không dùng workspace union trong `ensureRepoReady` để lấy thêm repo.

`.git` phải tự chứa metadata cho task. Không bind common worktree dir, không object alternates tới shared pool, không hardlink writable object với user khác. Clone/copy/reflink chỉ dùng khi isolation và quyền đã được kiểm tra; không coi `--local` là safe vì Linux có thể hardlink objects.

Giảm disk bằng retention/cleanup, quota và reuse cùng principal sau reauthorization. Shared immutable package cache hoặc filesystem reflink có thể thêm ở PR sau; không mở lại shared writable `.repos`/pnpm store chỉ để tiết kiệm dung lượng. Trước cache hit vẫn kiểm tra quyền hiện tại; provider unavailable không được xem như authorized.

### 8.2 Resume

Khóa session mở rộng scope hiện có: execution user, execution workspace, conversation kind/ID (issue/chat/autopilot), agent ID, resource project, canonical repo, coding provider/auth profile và policy/runtime version. Mỗi attempt có lease riêng; khác conversation hoặc agent không tự reuse native history dù cùng user/repo. Native session ID do client gửi không đủ quyền restore. B đổi user trên issue của A phải khởi tạo session sạch, kể cả đang dùng cùng agent.

Restore cùng user vẫn kiểm tra project/repo/key generation hiện tại. Không hồi sinh revoked capability qua snapshot. Đường host của session không được đưa vào sandbox. Trạng thái còn lưu sau run phải không chứa private Git key hoặc reusable transport lease.

### 8.3 Output và API

Source-bound output gồm transcript, tool logs, diff, generated code, artifact và native history. Các reader phải có quyền project/resource và source repo hiện tại. Không auto-post source vào issue/comment/email có audience rộng hơn; progress chung dùng structured status do server tạo.

HTTP/WS/output authorization dùng authenticated viewer/subscriber, không dùng execution-user grant thay quyền người đang đọc. Check viewer khi mở stream và khi access epoch thay đổi; viewer không có identity/proof cần thiết không được nhận source bằng fallback về quyền run owner.

Dùng authorization hook/route scoping của ứng dụng hiện tại, không dựng output application riêng. Protected task token không được dùng generic comment/file/download/MCP/API để bypass restriction. HTTP/WS/open streams cũng cần current access khi delivery; chỉ hide UI là chưa đủ.

Artifact paths resolve bên trong attempt root, chống symlink/hardlink/traversal; archive extraction và Git diff generation không chạy privileged trên host. S0 inventory các output paths thực sự enabled; disable path chưa có enforcement cho protected runs.

## 9. Revoke, failure và trạng thái

Các mốc dưới đây là **acceptance targets**, chưa phải số đo hệ thống hiện tại:

- Local revoke/offboard/root cancel: reject operation mới ngay sau acknowledge; đóng streams và dừng run/descendants trong tối đa 5 giây.
- Transport lease TTL tối đa 5 phút và kiểm tra state/epoch khi mở operation; TTL không thay thế revoke.
- Provider ACL external: check mỗi connection, admission, resume/cache/output delivery; run/stream dài revalidate theo chu kỳ tối đa 60 giây. Nêu latency đo được, không hứa provider revoke tức thời.
- Revalidation phải đúng operation: upload-pack/read success không chứng minh write vẫn còn sau khi provider hạ quyền. Active receive-pack cần write-permission proof đáng tin từ adapter/provider, hoặc stream lifetime/reconnect policy có bound được nghiệm thu. Nếu chưa chứng minh được write-revocation bound thì không advertise/enable protected write cho profile đó.
- Policy/key service outage hoặc revalidation quá hạn: stop/pause protected run và deny new source delivery; không phục vụ bằng quyền cached cũ.

State tối thiểu: queued → authorizing → preparing_sandbox → running → finalizing → completed; nhánh blocked/failed/cancelled có error code rõ. `git_identity_required`, `git_identity_unverified`, `git_repo_forbidden`, `git_grant_revoked`, `sandbox_unavailable`, `runtime_unsupported`, `provider_unavailable`, `git_write_outcome_unknown` không được đổi thành generic success.

Không dump secrets khi báo lỗi. Audit/cancel/cleanup idempotent. Nếu process/stream cleanup chưa xong, không báo run đã kết thúc an toàn; supervisor reconcile hoặc quarantine attempt trước khi recycle slot. Revoke không thể lấy lại source đã được process/user đọc.

## 10. Tái sử dụng PR #93

Nguồn duy nhất để trích: commit `a0c48fb5483f2f4404a050a60c3aff2e88eadcfb`, branch `feat/git-security-local`. PR có 268 files changed; không dùng whole-commit cherry-pick.

| Phần | File nguồn | Hành động |
| --- | --- | --- |
| UI public-key lifecycle | `packages/views/settings/components/git-identities-section.tsx`, account-tab integration, locales/tests | Manual port component; giữ generate/copy/verify/rotate/revoke |
| Public DTO/query/client | `packages/core/api/git-schemas.ts`, `packages/core/git-identities/index.ts`, selected API client methods/tests | Chỉ identity slice; giữ account-scoped cache và schema secret stripping |
| Sinh key/state machine | `server/internal/r2dgit/identity.go` và tests | Trích Ed25519/fingerprint/public representation/generation logic |
| Custody | `server/internal/r2dgit/custody.go` và tests | Trích KV v2 adapter, no redirect, CAS, destroy-version và log redaction |
| Identity handlers | `server/internal/handler/r2d_git.go` | Trích owner/session/CSRF/DTO/error handling; không copy toàn route registration |
| Store/jobs | `server/internal/r2dgit/store.go` | Trích provisioning/revoke/cleanup/idempotency logic; bỏ dependencies restore/grant engine cũ |
| Provider SSH | `server/internal/r2dgit/ssh_transport.go` và verifier tests | Tham khảo host pinning/principal verification; review từng dependency trước reuse |

Các tables credential trong candidate là `r2d_git_provider`, `r2d_git_identity`, `r2d_git_key`, `r2d_git_key_job`. Giữ uniqueness user/provider và identity/generation, idempotency jobs/lease, nhưng **không copy nguyên migrations 900100–900129** vì còn nhiều schema của kiến trúc cũ.

Không port Docker execution engine, `protected-agent`/`protected-provider` binaries, second OTP/control server, text-only repository transport, workload enrollment PKI, witnessed restore/quarantine framework hoặc cả ACL model chỉ vì nằm trong PR đó.

`NewService`/production wiring của candidate không phải evidence credentials đã usable: generator/custody/verifier và protected worker cần wiring; ordinary entrypoint còn nil config. Tách credential service có interface revoke lease mới, gắn thật vào account UI/backend, chạy tests rồi mới đánh dấu S1 complete.

## 11. Implementation slices và tracker

Giữ #84 và #85–#91 để không mất cursor; cập nhật phạm vi theo spec này. Mỗi slice có thể gồm vài PR nhỏ, luôn target fork `main`. Không gộp upstream sync với feature. Không mark complete chỉ vì docs/UI merge.

| Slice / issue | Output cụ thể | Gate để qua bước |
| --- | --- | --- |
| **S0 / #85** | Refresh main/deployment baseline, task/token/project/source policy adapter, worker manifest/IPC, provider/runtime support matrix, migration inventory | Contract tests bắt wrong-user, workspace-repo fallback, unsupported daemon; không còn identity ambiguity |
| **S1 / #86** | Trích key UI/DTO/custody/lifecycle từ #93, nối session/UI/backend hiện có | A không quản lý B, private bytes không ra API/UI/log, verify/rotate/revoke/crash tests |
| **S2 / #87** | Immutable principal/grant, protected token binding, root/child/retry và capability handshake | A gọi admin agent vẫn là A; B rerun không reuse A; no owner fallback |
| **S4 / #89 — scaffold sớm** | Hidden per-task worker, bwrap policy, typed IPC, cgroup/cleanup; chạy fake coding CLI | ACP callback, shell/MCP/native child cùng sandbox; host canary không đọc được |
| **S3 / #88** | Scoped native Git remote helper + SSH broker, GitHub/Gitea, per-user key lease | A có quyền repo X/Y nhưng task X không đọc/push Y; read-only không mở write; arbitrary SSH denied |
| **S4 / #89 — integration** | Worker prepare/run/finalize, clean runtime auth, private repo/session, egress bridge, Codex/Cursor | Không ambient clone/finalize/cache/health/MCP bypass; native clean-HOME compatibility |
| **S5 / #90** | Output/API gates, resume/revoke propagation, actor-visible errors, audit | Cross-user/output leakage denied; active streams/processes bị dừng; no stale cache access |
| **S6 / #91** | Adversarial integration, canary rollout/rollback, docs/operator handoff | Fixture A/B và supported-provider matrix pass, independent review |

S0 trước; sau đó S1/S2/S4 scaffold có thể song song; S3 tích hợp sau S1+S2; integrated S4 rồi S5/S6. Bước implementation đầu tiên: worker/grant contract cùng red tests ở S0 và scaffold S4, đồng thời chuẩn bị credential extraction; không bắt đầu bằng copy 268 files.

### 11.1 Vị trí tích hợp dự kiến

- `server/cmd/multica/main.go`: hidden worker subcommand, theo pattern helper đang có.
- `server/internal/daemon/daemon.go`: dispatch sang `SandboxLauncher` và typed lifecycle; giữ host orchestrator nhỏ.
- Package mới `server/internal/daemon/sandbox/` và task-worker package: policy/manifest/IPC/cleanup; tên cuối theo S0.
- `server/pkg/agent/`: adapters chạy trong worker; tests cho ACP/launch và provider callbacks, không thêm cách exec host riêng.
- `server/internal/r2dgit/`: identity/custody/grant/SSH transport hẹp; không import toàn protected framework của #93.
- Claim/auth/project-resource/health/repocache/session/output handlers: hooks tối thiểu và explicit protected path.
- `packages/core`, `packages/views`: trích credential UI theo repository boundaries.

R2D state dùng side tables `r2d_*`. Main baseline chưa có file migrations `900xxx`; range `900100–900129` đã tồn tại ở candidate chưa merge và deployment chưa xác minh. S0 kiểm tra cả DB deployment trước khi cấp số mới trong `900000–999999` và ghi #12. Không cấp số trong docs PR này. Tuân thủ no-FK và concurrent-index migrations trong AGENTS.md.

## 12. Acceptance và rollout

Fixture bắt buộc: user A/B; agent/squad owner admin; repo X dùng chung, Y chỉ A; A còn có repo Z ngoài task; keys khác nhau; fake coding CLI; disposable SSH/Git provider; host/task canary files. Test phải chứng minh positive path hoạt động và negative path thật sự bị chặn.

| Case | Kết quả bắt buộc |
| --- | --- |
| A/B đồng thời dùng cùng coding agent | Đúng identity, repo, HOME/session/socket; không đọc proc/env/file của nhau |
| Thin CLI gọi host daemon | Task vẫn đi qua sandbox dispatcher; không có host execution fallback |
| ACP terminal/create, init/finalize, local MCP, package script, native child | Cùng namespace/cgroup; không đọc host canary; không gọi host arbitrary exec |
| Sửa env/HOME/PATH/remote/helper/.git/hooks/config | Chỉ ảnh hưởng sandbox; không đổi broker user/host/repo hoặc lấy host key |
| Agent có key quyền X/Y/Z nhưng task chỉ X | Custom helper/socket request/SSH/HTTPS/API tới Y/Z bị deny |
| Task read-only gửi receive-pack | Broker deny trước khi SSH write session bắt đầu |
| Write vào protected/default ref | Provider protection deny; không báo broker có task-ref ACL khi chưa implement |
| Wrong/missing/unverified key, host pin mismatch, provider outage | Block, không dùng host credentials |
| Host cache đã warm Y, task B xin Y hoặc task X đổi URL | Deny trước checkout/cache delivery; health endpoint cũ không bypass |
| Linked worktree, object alternates, hardlink/symlink, artifact traversal | Không lộ hoặc sửa shared metadata/source/host file |
| B tiếp tục issue của A; đổi project hoặc credential generation | Session/lease mới và reauthorize; history A không tự restore |
| Forged token/user/task/attempt/root, stale child/retry | Deny từ real API/claim/broker path, không chỉ unit helper |
| Revoke trong khi SSH/WS/model/worker đang chạy | Stop future operations/output, kill descendants theo target đã đo |
| Missing bwrap/userns/cgroup/egress/seccomp, unsupported adapter | Visible blocked state; không unsandboxed execution |
| Cancellation lúc IPC/output queue đầy; daemon/worker crash | Không deadlock/rogue child/secret temp leak; recovery idempotent |
| Worker fork ngay khi start, trước handshake | Mọi child đã ở trong cgroup/limits; không có launch-then-attach race |
| Task/clone/push dài hơn lease TTL | Hoàn tất nhờ trusted renewal; revoke/renew failure vẫn cắt stream, không tự renew từ worker |
| Cùng user/repo nhưng khác issue/chat/agent | Native session vẫn tách theo conversation/agent, không collision |
| UI generate/verify/rotate/revoke và account switch | Public-only, owner-only, đúng cache scope, cleanup lỗi hiển thị rõ |
| Secret scan mount/env/FD/browser/task/log | Không có private Git key, host/admin token hoặc secret-store credential |
| Codex và Cursor clean HOME, supplements, native subagent, resume | Chạy end-to-end bằng profile đã khai; không bind host home để chữa lỗi |
| Provider ACL mất quyền khi đang chạy | Revalidation/cancel đúng latency; không coi TTL là bảo đảm revoke tức thời |
| Provider hạ write xuống read trong active push | Read probe không duy trì write lease; write-specific gate/bound thực sự có hiệu lực |

Default tests dùng fake CLI/synthetic keys và disposable repos. Real-agent smoke tuân thủ `agentintegration` + `MULTICA_RUN_REAL_AGENT_SMOKE=1` trong AGENTS.md, chỉ chạy khi được ủy quyền. Không cần real user secrets để chứng minh namespace/authorization boundaries.

Đo startup overhead bwrap so với baseline, peak RSS/PIDs, clone time, disk/retention, concurrent A/B isolation và cancel/revoke latency; không cam kết hiệu năng bằng số chưa đo. Resource budgets cấu hình theo runtime profile và host capacity.

### Rollout

1. Inventory deployment SHA, old candidate migrations, Git credentials/session/cache ambient; không đưa secret vào issue.
2. Provision bwrap/rootfs/cgroup/egress/broker/custody. Server/daemon handshake và doctor report phải phản ánh capability thật.
3. Enable account key UI; onboard A/B với repo pilot. UI Ready chỉ nói identity verified, không nói sandbox production đã đạt.
4. Enable protected read-only pilot sau integrated identity/worker/Git/output gates; bật write khi provider protection và write tests đạt.
5. Chạy S6 và independent review; sau đó mở rộng. Remove/rotate host admin Git credentials theo lịch operator, không coi việc này đã được thực hiện bởi spec.

Rollback: pause protected queue, revoke leases, stop workers và sửa lỗi. Không quay về host credentials/unsandboxed mode cho protected repos. Legacy runs nếu còn tồn tại phải ở trust domain riêng không thấy broker keys/cache protected. Không cần migrate/import toàn bộ lịch sử source/restore framework để ra V1; lịch sử chưa có scope không được phục vụ cho protected users bằng fallback.

## 13. Nguồn và handoff evidence

Source baseline được pin để implementer thấy đúng code đã đánh giá:

- [Daemon task execution](https://github.com/r2d-ai/multica/blob/ef0972f21e5825fb281957ede41a1072aa008a02/server/internal/daemon/daemon.go), [ACP terminal](https://github.com/r2d-ai/multica/blob/ef0972f21e5825fb281957ede41a1072aa008a02/server/pkg/agent/acp_terminal.go), [launch](https://github.com/r2d-ai/multica/blob/ef0972f21e5825fb281957ede41a1072aa008a02/server/pkg/agent/launch.go).
- [Claim/finalize token](https://github.com/r2d-ai/multica/blob/ef0972f21e5825fb281957ede41a1072aa008a02/server/internal/handler/daemon.go), [claim DTO](https://github.com/r2d-ai/multica/blob/ef0972f21e5825fb281957ede41a1072aa008a02/server/internal/daemon/types.go), [authorization attribution](https://github.com/r2d-ai/multica/blob/ef0972f21e5825fb281957ede41a1072aa008a02/server/internal/attribution/attribution.go), [task lineage](https://github.com/r2d-ai/multica/blob/ef0972f21e5825fb281957ede41a1072aa008a02/server/internal/service/task.go).
- [Project resources](https://github.com/r2d-ai/multica/blob/ef0972f21e5825fb281957ede41a1072aa008a02/server/internal/handler/project_resource.go), [health checkout](https://github.com/r2d-ai/multica/blob/ef0972f21e5825fb281957ede41a1072aa008a02/server/internal/daemon/health.go), [repo cache](https://github.com/r2d-ai/multica/blob/ef0972f21e5825fb281957ede41a1072aa008a02/server/internal/daemon/repocache/cache.go).
- [Preparation helper](https://github.com/r2d-ai/multica/blob/ef0972f21e5825fb281957ede41a1072aa008a02/server/internal/daemon/execenv/isolation.go), [session/provenance](https://github.com/r2d-ai/multica/blob/ef0972f21e5825fb281957ede41a1072aa008a02/server/internal/daemon/execenv/execenv.go), [Codex home](https://github.com/r2d-ai/multica/blob/ef0972f21e5825fb281957ede41a1072aa008a02/server/internal/daemon/execenv/codex_home.go), [runtime MCP](https://github.com/r2d-ai/multica/blob/ef0972f21e5825fb281957ede41a1072aa008a02/server/internal/daemon/runtime_mcp.go).
- [PR #93 credential UI](https://github.com/r2d-ai/multica/blob/a0c48fb5483f2f4404a050a60c3aff2e88eadcfb/packages/views/settings/components/git-identities-section.tsx), [identity](https://github.com/r2d-ai/multica/blob/a0c48fb5483f2f4404a050a60c3aff2e88eadcfb/server/internal/r2dgit/identity.go), [custody](https://github.com/r2d-ai/multica/blob/a0c48fb5483f2f4404a050a60c3aff2e88eadcfb/server/internal/r2dgit/custody.go), [production wiring](https://github.com/r2d-ai/multica/blob/a0c48fb5483f2f4404a050a60c3aff2e88eadcfb/server/cmd/server/protected_runtime_linux.go).
- [Bubblewrap README](https://github.com/containers/bubblewrap/blob/main/README.md), [security model](https://github.com/containers/bubblewrap/blob/main/SECURITY.md), [manual source](https://github.com/containers/bubblewrap/blob/main/bwrap.xml): caller chịu trách nhiệm policy, namespaces, mounts và exposed sockets.
- [Git remote helpers](https://git-scm.com/docs/gitremote-helpers), [Git security](https://git-scm.com/docs/git#_security), [worktrees](https://git-scm.com/docs/git-worktree): native connect transport, untrusted repository execution và shared metadata.
- [OpenSSH client config](https://man.openbsd.org/ssh_config), [agent destination constraints](https://man.openbsd.org/ssh-add), [Linux cgroup v2](https://docs.kernel.org/admin-guide/cgroup-v2.html), [OpenBao KV v2](https://openbao.org/docs/secrets/kv/kv-v2/).

Đây là source review và thiết kế đề xuất, chưa phải test evidence của bwrap implementation. Sau mỗi PR, cập nhật #84 với slice/PR/SHA/tests/gate còn thiếu và #12 với patch/migration cursor. Không thay upstream sync cursor khi chưa sync; không tạo PR lên `multica-ai/multica`.
