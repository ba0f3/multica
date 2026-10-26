# Sandbox trên host cho agent CLI

Filesystem và repo ownership được thay bằng [user codebases and read-only host view](./2026-10-26-user-codebases-host-view-design.md). Giữ PID namespace riêng; MCode không được hỗ trợ trên native worker; dùng MiniMax qua OpenCode.

Mục tiêu: bỏ việc tạo Docker container cho mỗi task trên Linux, giữ nguyên bộ cài và phiên đăng nhập của CLI, đồng thời giới hạn filesystem và process của task.

1. **Backend và phạm vi**

   Nâng cấp backend `bwrap` hiện có. Giai đoạn đầu hỗ trợ Codex, Cursor, OpenCode và MCode, bật bằng `MULTICA_TASK_SANDBOX=bwrap`.

   Giữ Docker để operator chọn và cho các nền tảng hoặc provider chưa được kiểm chứng. Khi đã chọn bwrap mà dựng sandbox thất bại, task phải dừng với lỗi rõ nguyên nhân. Không tự chạy ngoài sandbox hoặc chuyển sang Docker.

   Chỉ đổi mặc định trên Linux sau khi đạt toàn bộ tiêu chí nghiệm thu bên dưới.

2. **Luồng chạy**

   ```text
   Nhận task
     → resolve runtime/profile và quyền truy cập
     → chuẩn bị workdir, mount và giới hạn tài nguyên
     → khởi động worker Multica trong bubblewrap
     → worker báo ready
     → adapter khởi động CLI
     → chạy task
     → kết thúc toàn bộ process thuộc attempt
   ```

   Đặt cả worker, adapter, CLI, MCP, hooks và process con trong sandbox từ trước khi CLI đọc config của repo. Tái sử dụng worker protocol và các provider adapter hiện có.

3. **Runtime và filesystem**

   - Chạy executable, interpreter và thư viện tại đường dẫn gốc. Không chuyển launcher sang `/usr/local/bin`, sửa shim hoặc thay Node của provider.
   - Mỗi provider có resolver khai báo bộ cài, profile, thư mục được ghi và yêu cầu lock. Chỉ nhận đường dẫn từ cấu hình runtime đã được daemon kiểm tra.
   - Mount bộ cài và thư viện read-only. Khai báo riêng phần trạng thái mà installer cần ghi.
   - Dùng home rỗng tại đúng đường dẫn home gốc, sau đó mount các thư mục được cấp quyền. Không mount toàn bộ home, kể cả read-only.
   - Task chỉ được ghi vào workdir, temp, output và phần profile được cho phép. Không thấy repo hoặc task khác, SSH keys, Git credential store, token quản trị Multica, Docker socket hoặc keyring socket.
   - Giữ Git signing qua socket có quyền theo task. Cấp repo cache read-only và manifest theo cùng cơ chế checkout của Docker.
   - Dùng namespace riêng, bỏ capabilities, bật `no_new_privs`. Giữ giới hạn CPU, RAM và PID đã cấu hình. Preflight báo lỗi nếu host không thực thi được giới hạn đó.

4. **Auth, session và lock**

   Profile được xác định theo tài khoản sở hữu runtime, provider và profile đang chọn. Không đổi chủ credential theo người bấm rerun.

   Dùng profile gốc tại đường dẫn gốc. Không chép token, export/import credential mỗi task, sửa khóa trong SQLite hoặc giả lập trạng thái đã đăng nhập.

   Profile này là trạng thái dùng chung của cùng tài khoản. Sandbox không cam kết giấu credential hoặc session của profile đó khỏi agent. Không cấp chung profile cho các principal chưa được phép.

   Trước khi công nhận một provider hỗ trợ bwrap, phải xác minh:

   - Host CLI và worker phối hợp đúng khi refresh token hoặc migrate database.
   - Các worker dùng chung native auth lock và thống nhất lock bảo vệ database dùng chung.
   - PID trong namespace không khiến CLI xóa nhầm lease hoặc lock của process trên host.
   - Không xóa lock chỉ vì PID không tồn tại trong namespace của worker.

   Riêng MCode, `.mcode-active` dùng trạng thái riêng theo sandbox. Migration lock và auth lock phải theo đúng phạm vi dữ liệu mà chúng bảo vệ. Mặc định giới hạn một task đang chạy trên mỗi profile cho đến khi kiểm chứng an toàn khi chạy song song.

   Resume phải dùng đúng profile và session trước đó. Nếu provider từ chối resume, báo mất continuity theo hợp đồng hiện có. Không ghi nhận thành công chỉ vì đã gửi session ID.

5. **Lifecycle và hiệu năng**

   Không chạy kiểm tra version, quét bộ cài hoặc sao chép profile nặng trong mỗi task. Cache kết quả resolve/preflight, làm mới khi bộ cài hoặc cấu hình thay đổi. CLI được nâng cấp phải được resolve lại ở lần chạy tiếp theo.

   Giữ workdir và dữ liệu cần cho resume qua các lượt. Cancel, timeout, daemon crash và worker exit phải dọn toàn bộ process thuộc attempt, kể cả process chạy nền.

   Chưa thay luồng fetch repo trong thay đổi này. Đo riêng thời gian repo cache để tránh quy toàn bộ độ trễ khởi động cho sandbox.

6. **Telemetry**

   Ghi thời gian bằng clock monotonic, kèm `task_id`, `attempt_id`, provider và backend:

   | Metric | Khoảng đo |
   | --- | --- |
   | `repo_prepare_ms` | Chuẩn bị/fetch repo |
   | `runtime_resolve_ms` | Resolve CLI, profile và preflight |
   | `environment_prepare_ms` | Chuẩn bị filesystem, mount và resource limits |
   | `sandbox_launch_ms` | Spawn bwrap đến nhận `worker_ready` |
   | `cli_start_ms` | Worker ready đến spawn CLI thành công |
   | `first_output_ms` | CLI started đến output có ý nghĩa đầu tiên |
   | `turn_total_ms` | Toàn bộ lượt chạy |

   Không coi khoảng chờ output là thời gian model thuần túy. Không ghi token hoặc nội dung profile vào log.

   Mục tiêu nghiệm thu: `sandbox_launch_ms` p95 ≤ 250 ms qua ít nhất 100 lần chạy worker giả trên máy tham chiếu, cache nóng. Không đặt cam kết thời gian trả lời của model từ chỉ số này.

7. **Kiểm thử bắt buộc**

   - Kiểm tra filesystem và process bằng dữ liệu giả: truy cập ngoài phạm vi, symlink escape, mount lồng nhau, process con, cancel và cleanup.
   - Với cả bốn provider: fresh, resume đối chiếu session ID và nhớ được canary của lượt trước, chuyển provider, task mới sau task lỗi và daemon restart.
   - Kiểm chứng bằng tool tạo artifact đúng nội dung. Không chỉ kiểm tra câu trả lời cuối.
   - Kiểm tra host CLI chạy đồng thời với worker, hai worker cùng profile, token refresh, migration lock và nâng cấp CLI.
   - Chạy thực tế trên cả k7 và garlic. Real-agent tests phải có `agentintegration` và `MULTICA_RUN_REAL_AGENT_SMOKE=1`.

8. **Triển khai**

   Tập trung thay đổi tại `server/internal/daemon/sandbox_launch.go`, `server/internal/daemon/sandbox/policy.go`, `server/internal/daemon/sandbox/providers.go`, `server/internal/daemon/execenv/`, worker protocol và task timing. Tách phần chuẩn bị môi trường native khỏi phần dành cho Docker. Cập nhật tài liệu, preflight và thông báo lỗi cùng thay đổi.

   Giai đoạn này giữ chính sách network hiện tại. Egress filtering là hạng mục tiếp theo. Không mô tả backend này là cô lập credential hoặc chống exfiltration đầy đủ.

   Phạm vi phát hành là daemon/CLI. Backend và frontend chỉ cần thay đổi nếu bổ sung hiển thị capability hoặc telemetry qua API. Phần thực thi không phụ thuộc thay đổi đó.
