# Handoff MVP: bwrap + SSH-agent theo task

Đọc [spec chính](per-user-git-credentials-plan.md). Quyết định 2026-10-20 rút gọn thiết kế đã merge trong #94; PR #93 đóng, chỉ trích code credentials. Bản cập nhật này chỉ sửa tài liệu.

## Contract cần implement

- **Worker của từng task attempt ở trong bwrap:** adapter, coding agent, ACP terminal, local MCP, subprocess, prepare/clone/finalize đều nằm trong boundary. Shared daemon làm supervisor bên ngoài.
- **Filesystem riêng:** task checkout với `.git` tự chứa, HOME/temp/session riêng, runtime read-only. Launcher không đặc quyền, namespace riêng và cleanup cả process tree. Không mount host home, workspace/shared repo pool, host SSH-agent, privileged sockets hay admin token.
- **SSH-agent-compatible signer ngoài sandbox:** mount đúng socket của attempt qua `SSH_AUTH_SOCK`; chỉ public identity + sign. Backend chọn key theo originator hợp lệ; runner không chọn user/key hoặc quản trị signer. Không private Git key trong worker.
- **Remote Git theo quyền user:** A có quyền X/Y thì task X được phép clone Y; Z ngoài quyền A do provider từ chối. Không implement Git transport broker, custom remote helper, repo grant/ref-policy engine.
- **Identity/lifecycle:** children giữ originator; B rerun dùng HOME/session/key B. Cancel/timeout/crash/revoke dừng task descendants, SSH sessions, signer và dọn socket. Missing bwrap/setup lỗi thì block.
- **UI:** generate/copy public key/check connection/revoke; backend mã hóa private key. Rotate có thể revoke + generate; không bắt buộc seamless rotation.

Networking giữ hiện tại; host/LAN isolation, egress enforcement và output/ACL redesign nằm ngoài MVP. Git quyền read/write và branch protection theo GitHub/Gitea. Auth AI cấp tối thiểu, tách khỏi Git; không cần model-auth broker.

## Ba việc, không thêm phase

| Issue | Phần cần giao |
| --- | --- |
| #86 | MVP1: key generation/custody/public API/UI/revoke từ #93 |
| #89 | MVP2: bwrap worker + callbacks + private HOME/checkout/session + cleanup |
| #88 | MVP3: user binding + per-task SSH-agent socket + Git/lifecycle integration |

#86/#89 song song được; #88 tích hợp. Tests thuộc từng phần. #85/#87/#90/#91 được gộp hoặc bỏ scope, không phải đã hoàn thành implementation.

## Những chỗ dễ làm sai

1. Bọc CLI gửi request hoặc chỉ coding-agent binary vẫn có thể để ACP callback chạy host. Tạo backend/adapter trong worker.
2. Linked worktree `.git` trỏ ra ngoài: dùng metadata riêng, không bind shared `.repos`; mọi Git task chạy trong sandbox, kể cả clone/finalize.
3. Runtime owner/accountable owner không phải user chọn SSH key. Dùng originator đã xác thực, không fallback admin; không cấp host daemon token cho worker.
4. Không dùng key-loader FD, shared socket hoặc host `.codex`/`.cursor`/HOME mount để chữa lỗi auth.
5. Xóa socket chưa dừng connection/SSH session đang mở; teardown phải dừng cả cây process và signer. Local revoke áp dụng cả active tasks.

Nghiệm thu theo 8 mục trong spec: A/B identity, callback containment, Git metadata riêng, secret/public API, provider-scope positive/negative, cleanup/revoke, fail-closed và clean-HOME Codex/Cursor. Default dùng fake CLI/synthetic keys; real-agent smoke theo gate AGENTS.md.

## Source và delivery

Fork **r2d-ai/multica**, target **main**, baseline `5080ef180d1cb9be540895666e18a46235e9737c`. Reuse source #93: `a0c48fb5483f2f4404a050a60c3aff2e88eadcfb`; chỉ lấy UI/DTO/generation/custody/lifecycle cần thiết, không nhập Docker/control server/grant/restore framework. Refresh main trước coding; không giả định patch ACL lịch sử còn hiện diện.

Chưa reserve migration; inventory và cập nhật #12 trước khi cấp số, giữ `r2d_*`, no-FK/concurrent-index rules. PR nhỏ, theo AGENTS.md; cập nhật #84/#12 với SHA và evidence thật. Rollback pause task, không fallback shared Git credentials hoặc unsandboxed execution.
