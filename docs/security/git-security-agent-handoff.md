# Handoff: bwrap task isolation và per-user Git keys

Đọc [spec chính](per-user-git-credentials-plan.md) trước khi implement. Bản ngày 2026-10-20 thay kiến trúc candidate PR #93; không merge/cherry-pick nguyên PR đó.

Thay đổi lần này chỉ là spec/handoff; chưa trích code credentials hoặc triển khai/test bwrap mới.

## Quyết định đã chốt

- Linux + **mỗi task attempt một bwrap worker**. Worker chứa agent adapter, coding-agent binary, ACP terminal callback, local MCP, prepare/finalize và subprocess.
- Shared daemon ở ngoài giữ orchestration và typed IPC. Worker không có arbitrary host-exec/mount/checkout RPC.
- UI tạo key riêng mỗi user/provider, chỉ show public key/fingerprint. Private key ở custody mã hóa; coding agent không nhận raw key hoặc generic ssh-agent socket.
- Git remote helper đi qua transport broker bind đúng execution user + attempt + repo + read/write. Broker chạy SSH command cố định với key user, giữ Git native pack protocol.
- V1 chọn OpenSSH; key file tạm chỉ thuộc trusted broker, cần internal materialization/lease adapter. Không xây đồng thời Go SSH signer transport.
- V1 scope một repo/run; GitHub/Gitea branch protection thực thi ref policy. Không quảng cáo task-only branch enforcement nếu broker chỉ forward receive-pack.
- Không ambient host HOME/env/auth/MCP, không shared workspace repo fallback, không shared Git metadata, không fallback khi sandbox không khả dụng.

## Baseline và source reuse

- Fork: `r2d-ai/multica`; target `main`.
- Observed main: `ef0972f21e5825fb281957ede41a1072aa008a02`.
- PR #93 extraction source: `a0c48fb5483f2f4404a050a60c3aff2e88eadcfb`.
- Refresh main trước coding và ghi drift. Không giả định code ACL lịch sử của #12 còn tồn tại.
- Credential components/schema/custody/lifecycle/tests có thể port thủ công theo mục 10 của spec. Không port Docker engine, second control/OTP server, text-only Git transport hoặc restore/quarantine platform.
- Chưa cấp số migration mới. Kiểm tra schema deployment/candidate trước khi reserve số trong #12; `r2d_*` side tables, no FK, concurrent index theo AGENTS.md.

## Bốn lỗi kiến trúc phải giải quyết

1. `acpTerminalCreate` thực thi command từ adapter process: chỉ wrap provider binary sẽ để callback ngoài sandbox.
2. Claim/finalize task token đang dùng runtime owner: protected API/Git phải bind cùng authorization originator, không chỉ đặt env user ID.
3. Project repo fallback, health checkout và background repocache đang theo workspace: protected path cần exact repo grant và không dùng host Git.
4. Native HOME/auth/session và Git local clones có shared state: clean HOME, principal-bound resume, self-contained `.git`, không cross-user mutable hardlinks/alternates.

## Thứ tự làm

| Issue | Việc |
| --- | --- |
| #85 / S0 | Baseline/policy/token/worker contract, support matrix, migration inventory, red tests |
| #86 / S1 | Extract key UI/API/custody/lifecycle và nối vào app hiện tại |
| #87 / S2 | Immutable principal/grant/attempt/delegation, protected task tokens và runtime capability |
| #89 / S4 scaffold | Hidden worker + bwrap + IPC/cgroup/cleanup với fake coding CLI |
| #88 / S3 | Native Git remote helper + fixed SSH transport + per-user key lease |
| #89 / S4 integration | Prepare/run/finalize, egress, private repo/session, Codex/Cursor clean auth |
| #90 / S5 | Output/API/current-access gates, revoke/resume/audit |
| #91 / S6 | Adversarial fixture, pilot rollout/rollback và independent review |

S0 trước; S1/S2/S4 scaffold song song được sau contract. Giữ mỗi PR nhỏ và reviewable; docs/UI merge chưa đóng tracker.

## Gate không được bỏ

- A/B đồng thời cùng shared agent: không thấy checkout/HOME/session/proc/socket/key của nhau.
- A có repo X/Y nhưng task X: không truy cập Y qua broker, URL rewrite, raw SSH/HTTPS, health/API/MCP.
- ACP terminal, script build, local MCP và native subagent ở trong bwrap; malicious `.git` không được chạy host commands.
- B rerun issue A không reuse token/native history A; revoked/offboarded user không dùng warm cache.
- Session scope giữ conversation/agent hiện có và thêm execution user; reader output được authorize bằng identity người đọc.
- Missing bwrap/userns/cgroup/egress hoặc unsupported provider → blocked, không direct exec.
- Public-only UI/API; Git private key không xuất hiện trong worker mounts/env/FD/logs. Broker-only key materialization có cleanup.
- Read-only task không mở receive-pack; branch/ref restrictions nghiệm thu ở Git provider.
- Cancel/revoke dừng active SSH, streams và descendant cgroup; IPC backpressure/crash không để rogue child.
- Cgroup placement có trước untrusted execution; task dài renew lease qua trusted server, đúng operation, không worker self-renew.
- Không dùng host `.codex`/`.cursor` mount để làm auth test pass; provider clean-HOME profile phải có evidence.

Default CI dùng synthetic keys và fake CLI, không resolve/run CLI đăng nhập sẵn của user. Real-agent smoke chỉ khi được ủy quyền và đủ gate AGENTS.md. Report chính xác đã chạy gì; không biến test candidate #93 thành test bwrap mới.

## Delivery

Commit/push/PR chỉ trên **r2d-ai/multica**, không upstream. Cập nhật [#84](https://github.com/r2d-ai/multica/issues/84) với slice/PR/SHA/evidence/next action; cập nhật [#12](https://github.com/r2d-ai/multica/issues/12) với patch và migration cursor. PR #93 giữ branch/commit để tra cứu, bỏ implementation architecture cũ.

Rollback protected mode là pause và sửa; không bật shared admin key hoặc unsandboxed execution. Không deploy, generate real keys hoặc rotate production credentials chỉ vì spec đã merge.
