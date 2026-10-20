# Spec MVP: bwrap runner và SSH-agent theo task

Quyết định cập nhật: **2026-10-20**. Trạng thái: đặc tả để implement; chưa có runtime mới.

Bản này rút gọn thiết kế đã merge trong [PR #94](https://github.com/r2d-ai/multica/pull/94). User chốt ba phần: **worker trong bwrap, socket SSH-agent riêng cho task, UI tạo key chỉ hiện public key**. Bỏ Git transport broker và hệ thống grant theo từng repo khỏi V1.

- Fork/target: **r2d-ai/multica / main**; baseline `5080ef180d1cb9be540895666e18a46235e9737c`.
- Tracker: [#84](https://github.com/r2d-ai/multica/issues/84); patch/migration cursor: [#12](https://github.com/r2d-ai/multica/issues/12).
- [PR #93](https://github.com/r2d-ai/multica/pull/93) đã đóng, chỉ dùng làm nguồn trích code credentials. Handoff: [git-security-agent-handoff.md](git-security-agent-handoff.md).

## 1. Phạm vi đã chốt

**Cô lập filesystem theo task; Git chạy bằng quyền của user; private Git key nằm ngoài runner sandbox.**

| Bảo đảm V1 | Cách thực hiện |
| --- | --- |
| Task chỉ trực tiếp thấy các mount được cấp; HOME/session và Git/admin credentials của host/task khác không được mount | Bwrap worker, mount tối thiểu, HOME/env riêng |
| Git dùng key của người yêu cầu chạy task | Backend chọn identity; socket riêng chỉ phục vụ key đã chọn |
| Coding agent và browser không nhận private Git key | Kho key mã hóa ngoài sandbox; socket trả public identity/chữ ký |
| Repo ngoài quyền user bị từ chối | GitHub/Gitea kiểm tra quyền khi truy cập bằng key user |

**User A có quyền repo X và Y thì task đang làm X vẫn có thể clone Y vào filesystem riêng của task. Đây là hành vi được chấp nhận trong V1.** Chỉ checkout được chọn được mount lúc khởi tạo; đó không phải giới hạn remote Git theo repo. SSH-agent ký bước xác thực SSH, không kiểm soát đường dẫn repo được gửi sau đó. Destination constraints của OpenSSH cũng không giới hạn repo path ([tài liệu OpenSSH](https://www.openssh.org/agent-restrict.html)).

V1 dùng Git SSH native với GitHub/Gitea; quyền read/write và branch protection theo provider. Không thêm task-specific read-only/ref policy. Git qua HTTPS, LFS cần token riêng hoặc tích hợp API tạo PR không được tự fallback sang PAT/key chung.

Giữ networking hiện tại để Git, model và package download hoạt động. V1 **chưa cô lập dịch vụ host/LAN hoặc kiểm soát exfiltration qua network**. ACL/output của Multica giữ theo cơ chế hiện có; không xây lại viewer/source authorization trong feature này. Không bắt buộc Git gateway, custom remote helper, policy/grant engine, egress gateway hay nền tảng execution thứ hai.

## 2. Bwrap bao worker thực thi task

Shared daemon ở ngoài làm supervisor. Mỗi task attempt chạy một worker trong bwrap; **worker chứa adapter, coding-agent process, ACP terminal callback, local MCP, native subagent và mọi subprocess của task**. `prepare/clone`, task-influenced probes, retry và `finalize` có chạy command/Git đều thuộc worker.

Chỉ bọc CLI gửi request tới shared daemon không cô lập task. Chỉ bọc binary coding agent bỏ sót callbacks chạy ở adapter; đường này hiện có trong [`acp_terminal.go`](https://github.com/r2d-ai/multica/blob/5080ef180d1cb9be540895666e18a46235e9737c/server/pkg/agent/acp_terminal.go). Tách hidden task-worker tại seam thực thi hiện có, giữ orchestration/reporting đang dùng.

| Đưa vào sandbox | Quyền / yêu cầu |
| --- | --- |
| Checkout của task | Read/write; `.git` tự chứa hoặc metadata riêng task |
| Binary/runtime/toolchain cần thiết | Read-only, mount theo allowlist |
| HOME, temp, native session | Riêng từng user/task; không kế thừa home host |
| `/proc`, `/dev` tối thiểu | Thuộc môi trường sandbox; PID namespace riêng |
| Socket SSH-agent của task, public key, known_hosts | Chỉ identity được cấp; kiểm tra host key của Git provider |

- Launcher/worker không đặc quyền; dùng mount/user/PID/IPC namespaces riêng, drop capabilities/no-new-privileges, `--new-session`, `--die-with-parent` hoặc cơ chế tương đương đã kiểm thử. Environment theo allowlist. Không bind host root/home, workspace root/shared repo pool, Docker/D-Bus socket, host SSH-agent, Git credential helper hoặc daemon/admin token.
- Linked worktree có thể trỏ `.git` ra shared common dir. Dùng checkout tự chứa; không chữa lỗi Git bằng mount shared `.repos`, alternates hoặc hardlink writable metadata/object giữa users.
- Clone/fetch ban đầu dùng key của task trong sandbox. Không để background repocache, health checkout hay supervisor chạy host Git trên checkout/config/hooks do task sửa. IPC chỉ phục vụ lifecycle/reporting; task không được gọi host-exec/mount/checkout tùy ý.
- Codex/Cursor dùng HOME/session riêng. Chỉ cấp cấu hình/auth AI tối thiểu mà runtime cần; không mount toàn bộ `.codex`, `.cursor` hay HOME host. Auth dịch vụ AI tách khỏi Git credentials; V1 không xây thêm model-auth broker.
- Thiếu bwrap, namespace hoặc setup mount lỗi thì block task, không direct-exec fallback. Cancel/timeout/worker crash phải dừng toàn bộ descendants, kể cả process đã detach; dùng lifecycle hiện có nếu đáp ứng được kiểm thử này.

Bubblewrap cung cấp các primitive isolation; ứng dụng vẫn phải chọn mount/process policy đúng ([README](https://github.com/containers/bubblewrap/blob/main/README.md)). Không coi một wrapper CLI là đủ bằng chứng isolation.

## 3. SSH-agent socket riêng và identity đúng user

Backend resolve người yêu cầu chạy task từ authenticated actor/originator đã lưu. Thiếu principal hợp lệ thì báo lỗi; không lấy runtime owner, agent owner, audit/accountable owner hoặc user ID do coding agent truyền vào để chọn key.

Supervisor xin signer theo task/attempt qua đường backend đã xác thực. Backend cố định `execution_user_id`, provider và key generation cho attempt. Listener/signer nằm ngoài coding sandbox; chỉ mount socket của attempt và đặt `SSH_AUTH_SOCK=/run/multica/ssh-agent.sock`. Nhiều task của cùng user vẫn nhận các socket riêng.

**Chọn một SSH-agent-compatible proxy mỏng**, dùng thư viện protocol sẵn. Interface với runner chỉ cần list public identity được cấp và sign bằng identity đó; từ chối đổi user/key, add/remove/import key, thao tác quản trị và message không hỗ trợ. Không tự viết Git/SSH transport. Nếu custody nằm trên server khác, listener ngoài sandbox chuyển tiếp yêu cầu ký qua backend đã xác thực; worker chỉ nhận public key/chữ ký.

Private key và credential của secret store không xuất hiện trong mount, environment, inherited FD, IPC payload gửi cho worker, logs hay response browser. Key loader ở ngoài sandbox và đóng secret FD trước khi launch worker. Socket là quyền dùng key: read-only bind không biến nó thành credential chỉ đọc.

Native child kế thừa sandbox/socket. Child task do Multica dispatch giữ originator của parent, tạo attempt/socket mới. Retry giữ user; user B chủ động rerun tạo context, HOME/session và socket của B. Không reuse native history của A cho B. Tận dụng originator/lineage có sẵn, không tạo grant framework mới.

Task kết thúc, cancel, timeout hoặc credential bị revoke: từ chối yêu cầu ký mới, đóng agent connections, dừng task descendants/SSH sessions và dọn socket/temp. Rotate sang generation mới cũng dừng attempts còn dùng generation cũ. Supervisor crash/restart phải thu dọn attempts mồ côi trước khi resume. **Unlink socket hoặc remove key không dừng SSH session đã authenticate.** Không đặt SLA mới cho thay đổi quyền ở provider; lần kết nối mới chịu kiểm tra quyền của provider, local revoke chủ động dừng task.

## 4. UI và code tái sử dụng từ #93

UI account settings: chọn GitHub/Gitea instance → Generate → Copy public key → user add key vào tài khoản Git → kiểm tra kết nối. Hiện public key, fingerprint và status. Revoke khả dụng ngay; rotate có thể là revoke + generate trong MVP, không bắt buộc seamless rotation. Kiểm tra SSH login không chứng minh quyền mọi repo; clone/push thực tế vẫn do provider quyết định.

Key tạo ở backend, mã hóa trong custody hiện có. API lấy owner từ authenticated user; A không được xem/quản lý identity của B. Không có import/reveal/export private key. Revoke tại Multica dừng sử dụng key tại Multica; UI nhắc user xóa public key trên Git provider khi cần.

Nguồn trích thủ công: `a0c48fb5483f2f4404a050a60c3aff2e88eadcfb` của #93, chưa được tích hợp vào main.

| Thành phần | Hướng dùng lại |
| --- | --- |
| `packages/views/settings/components/git-identities-section.tsx` | Generate/copy/verify/revoke UI; nối account settings hiện tại |
| `packages/core/api/git-schemas.ts`, `packages/core/git-identities/` | Public DTO, client/query; cache key theo user |
| `server/internal/r2dgit/identity.go`, `custody.go` | Ed25519/fingerprint, encrypted custody, signer primitives |
| `server/internal/handler/r2d_git.go`, phần lifecycle trong `store.go` | Owner authorization, generate/revoke/cleanup; tách dependencies của kiến trúc cũ |

`SigningCustody.WithSigner` trong [`ssh_transport.go`](https://github.com/r2d-ai/multica/blob/a0c48fb5483f2f4404a050a60c3aff2e88eadcfb/server/internal/r2dgit/ssh_transport.go) và implementation trong [`custody.go`](https://github.com/r2d-ai/multica/blob/a0c48fb5483f2f4404a050a60c3aff2e88eadcfb/server/internal/r2dgit/custody.go) dùng được cho List/Sign proxy. Trích interface/constructor cần thiết vào phần credentials nhỏ; không import `SSHWorker`, toàn bộ `Store` hoặc `RestoreGuard`. Per-task SSH-agent socket là code mới, chưa có sẵn trong #93.

Chỉ port phần cần cho ba hạng mục dưới. Không import nguyên PR93, Docker runner, OTP/control server thứ hai, old grant/transport hoặc restore/quarantine framework. Refresh main và constructors thật trước khi port. Schema cần `r2d_*` side tables; inventory rồi reserve migration trong #12, theo no-FK/concurrent-index rules của AGENTS.md. Bản spec này không cấp số migration.

## 5. Ba hạng mục implementation

| Issue | Deliverable |
| --- | --- |
| [#86](https://github.com/r2d-ai/multica/issues/86) | **MVP1 — Keys/UI:** trích generation/custody/public API/UI và revoke |
| [#89](https://github.com/r2d-ai/multica/issues/89) | **MVP2 — Runner:** bwrap task worker, callbacks, private HOME/checkout, cleanup |
| [#88](https://github.com/r2d-ai/multica/issues/88) | **MVP3 — SSH-agent:** originator binding, per-task signing socket, Git integration, revoke |

MVP1 và MVP2 làm song song; MVP3 tích hợp cả hai. Test nằm cùng hạng mục, không tạo phase test độc lập. Các issue cũ #85/#87/#90/#91 được gộp hoặc bỏ scope; đóng dạng superseded/not planned, không đánh dấu đã implement. Principal và revocation tối thiểu vẫn thuộc MVP3; HOME/resume isolation thuộc MVP2.

## 6. Nghiệm thu trước khi bật

Default tests dùng synthetic keys, Git/SSH fixture và fake coding CLI. Dùng A/B cùng shared agent, repo X/Y thuộc A và repo Z ngoài quyền A.

1. **Identity:** task A dùng key A, task B dùng key B dù runtime thuộc admin; thiếu user/key, forged selector hoặc stale attempt bị từ chối. Child/retry không đổi principal; B rerun không dùng state A.
2. **Containment:** coding CLI, ACP terminal, build hook, local MCP và native subagent không đọc được host/sibling canaries, HOME hoặc process state.
3. **Git filesystem:** clone/status/commit hoạt động với `.git` riêng; không mount shared repo metadata hoặc đi qua host checkout/background sync để lấy source.
4. **Secrets/UI:** browser/API và worker mounts/env/FD/logs không chứa private Git key hay Git/admin credential của host; A không quản lý key B; socket không thể chọn key khác hoặc mutate signer.
5. **Provider scope:** native clone/fetch/push với key đúng hoạt động; task X của A truy cập Y được phép, Z bị provider từ chối. Provider branch protection được giữ; không test repo-X-only hay task-read-only như bảo đảm V1.
6. **Lifecycle:** cancel/timeout/crash/revoke dừng descendants, SSH sessions và signer; connection đã mở không ký tiếp; dọn socket/temp; restart không phục hồi quyền bằng key cũ.
7. **Fail closed:** bwrap/setup lỗi, key revoked, custody không khả dụng hoặc host key mismatch đều báo lỗi; không dùng host/admin key hay chạy task ngoài sandbox.
8. **Runtime:** Codex/Cursor chạy với HOME riêng và auth AI tối thiểu; kiểm thử GitHub và phiên bản Gitea được hỗ trợ trước khi quảng bá tương thích.

Real-agent smoke chỉ chạy khi được ủy quyền và đúng `agentintegration`/environment gate của AGENTS.md. Báo chính xác fixture/provider/runtime nào đã kiểm tra. Không dùng test cũ của #93 làm bằng chứng cho runner mới.

Rollout thử A/B sau khi ba hạng mục tích hợp; rollback pause task bị ảnh hưởng và dừng signer, không khôi phục shared admin key. Cập nhật #84/#12 bằng PR/SHA/evidence. **Spec merge không có nghĩa code đã chạy hoặc cho phép thay đổi production credentials.**
