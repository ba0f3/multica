# Handoff: sửa Docker task isolation trên branch hiện tại

Đọc [spec chính](per-user-git-credentials-plan.md) và [status](git-security-mvp-status.md). Bản ngày **2026-10-21** áp dụng cho **`r2d-ai/multica:feature/git-security-mvp`**, implementation baseline **`d67d4d548962a22f11001490e784955fedc9127f`**. Tiếp tục branch này; không bắt đầu lại từ main hoặc port nguyên PR #93.

**Lưu ý merge:** `main` vẫn mang spec/handoff **bwrap** đã merge trong #94. Branch này **thay bwrap bằng Docker** cho MVP; khi merge vào `main`, giữ tài liệu và code Docker của branch này, không quay lại bwrap-only contract.

## Đã chốt

- **Một Docker container/attempt**, native **Codex, Cursor Agent, OpenCode**. Supervisor ở ngoài; worker/adapter/agent/local MCP/subagent và toàn bộ Git prepare → run → finalize ở trong.
- Giữ credentials UI/API/custody và SSH-agent List/Sign đã có; mount chỉ socket attempt, không private Git key hoặc host credentials.
- Cấp native writable HOME/config/auth/session và image toolchain đầy đủ. Không chữa compatibility bằng mount host HOME.
- Backend chọn originator/key/attempt; task token không trở thành full CLI/user/admin token hoặc runtime-owner authority.
- Chặn task gọi host control/checkout APIs và host/LAN services; allow đúng task API/Git/model/DNS/package access.
- Git theo quyền user: A có X/Y thì task X clone Y được; Z ngoài quyền bị provider deny. Không exact-repo broker/ref policy.
- Tool-only Codex exec-server/Cursor SDK/OpenCode driver là PoC tùy chọn, không prerequisite và không thay ba native adapters trong MVP.

## Giữ và sửa ở đâu

| Phần | Hành động |
| --- | --- |
| `server/internal/r2dgit/`, `server/internal/handler/r2d_git*.go`, credential UI/core | Giữ lifecycle/public DTO/custody/verify; kiểm tra owner, secret exclusion, revoke và wiring |
| `server/internal/daemon/sandbox/{manifest,worker,backend,ipc}.go`, hidden worker command | Giữ entrypoint/adapter dispatch; thêm true attempt ID và typed bidirectional Session IPC |
| `server/internal/daemon/sandbox_launch.go`, config | Thay bwrap launch/home shadows bằng Docker lifecycle và trusted mount/env policy |
| `server/internal/daemon/execenv/`, `server/pkg/agent/{codex,cursor,opencode}*.go` | Container paths trước config; native state/auth; giữ version detection; service OpenCode trong container |
| `server/internal/daemon/{daemon,health}.go`, `server/internal/daemon/repocache/`, `server/cmd/multica/cmd_repo.go` | Đưa task Git vào worker, chặn host execution bypass |
| Claim/auth/router, `git_agent.go`, `r2dgit/signing.go` | Task principal/API gate + selected repo/provider + attempt/key lease + actual socket teardown |

Đọc source trước khi sửa. Source tồn tại không có nghĩa deployment hoặc ba provider đã được nghiệm thu.

## Thứ tự làm, chỉ ba issue

1. **#89:** Docker worker/image, private filesystem/native environment, full Session IPC và lifecycle; scaffold với fake CLI/socket.
2. **#88:** signer/API authority/network integration và chuyển toàn bộ Git vào container. #89 sở hữu Docker network enforcement; #88 sở hữu server authorization.
3. **#86:** giữ và kiểm tra credentials UI/custody hiện có, sửa gap cần thiết; không port lại. Làm song song được.
4. Tích hợp matrix của spec, ghi actual evidence. Không mở lại #85/#87/#90/#91 hoặc dựng một phase framework mới.

## Các lỗi không được mang sang Docker

- `AttemptID = TaskID`; host-home read-only vẫn lộ source/credentials; shared Git common-dir/alternates.
- PATH hoặc `SSH_AUTH_SOCK` bị adapter/custom env ghi đè về host path.
- Codex host auth symlink; Cursor trust/config hash tạo theo host cwd; HOME chỉ đọc khiến native state write lỗi.
- IPC chỉ message/result làm mất supplements, activity, background interrupt hoặc terminal state vốn adapter hỗ trợ.
- OpenCode client ở container nhưng service ở host; kill client còn service/tools chạy; opaque custom wrapper làm 2.x bị hiểu là v1.
- `ErrOpenCodeV2MCPUnsupported` còn nguyên nhưng báo Docker đã hỗ trợ managed MCP. Ghi rõ unsupported hoặc sửa/test; task yêu cầu feature unsupported phải bị từ chối, không silently bỏ MCP.
- Task token mang runtime owner, mint full CLI JWT qua `POST /api/cli-token`, hoặc đi host `/repo/checkout`.
- Lease chỉ slide TTL sau mỗi sign, unlink socket nhưng không đóng accepted connections/SSH/container.
- Docker bridge/rootless flags được coi là bằng chứng network/resource policy đã có hiệu lực.
- Protected node vẫn chạy untrusted task trực tiếp bằng cùng host identity hoặc quyền daemon profile/Docker engine. Node này phải từ chối unprotected execution.

## Gate hoàn thành

Dùng tám check trong spec: A/B; ba native runtimes; host filesystem/network boundary; task API authority; actual Git permissions; public-only secrets/UI; cleanup/effective limits; fail-closed. Chứng minh cả positive path và negative path bằng fixture phù hợp.

Pin commit/image/native CLI versions và Docker mode. Codex/Cursor/OpenCode phải giữ supported config/auth, shell/file tools, session/resume và cancellation; MCP/steering theo native adapter/version đã hỗ trợ. Feature chưa hỗ trợ phải báo rõ và từ chối task yêu cầu nó, không tự đổi sang host hoặc bỏ config. AI auth provisioned trong task có thể đọc được bởi native process; Git private key và host/admin/custody credentials phải ở ngoài.

Default tests dùng synthetic keys/fake CLIs, không tự discover tài khoản/CLI đã đăng nhập của user. Real-agent smoke cần ủy quyền và gate `agentintegration` + `MULTICA_RUN_REAL_AGENT_SMOKE=1` theo AGENTS.md. Không dùng bwrap smoke hoặc fixture banner tests để chứng nhận Docker/native/provider compatibility.

## Manual Docker verification

Cloud CI has no Docker engine. Operators follow [docker-task-worker-manual-test.md](docker-task-worker-manual-test.md). Git performance tradeoffs: [git-lifecycle-in-worker.md](git-lifecycle-in-worker.md).

## Source và delivery

Migrations **900100–900113 đã có trên feature branch**; cập nhật inventory #12, không cấp/renumber trong docs. DB deployment chưa xác minh. Giữ no-FK/concurrent-index rules.

Commit nhỏ trực tiếp tiếp nối branch, chỉ fork **r2d-ai/multica**. Refresh head trước sửa; không overwrite code người khác. Cập nhật status, #84 và active cursor #12; giữ upstream cursor/historical stack. #94/#95 là spec history đã merge; #93 closed để tham khảo credentials.

Protected mode fail closed. Rollback pause tasks, revoke/stop attempts và sửa; không host execution fallback. Spec này không tự authorize deploy, tạo/rotate production keys hoặc real-agent account tests.
