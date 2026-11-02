# Review bảo mật SSH key: phân tách quyền ký giữa các user

## Phạm vi và mức xác nhận

| Thuộc tính | Giá trị |
| --- | --- |
| Repository | [ba0f3/multica](https://github.com/ba0f3/multica), fork trước đây dùng URL r2d-ai/multica |
| Revision được review | [07e553524fc332c5330d373cc357171c158beb6f](https://github.com/ba0f3/multica/commit/07e553524fc332c5330d373cc357171c158beb6f) |
| Nhánh tại thời điểm review | main |
| Ngày lập báo cáo | 2026-11-03 (UTC+7; 2026-11-02 UTC) |
| Câu hỏi | User A có thể đọc private key hoặc sử dụng quyền ký SSH của user B không? |
| Phương pháp | Đọc source tại revision cố định, lần theo authentication → task attribution → execution user → signing lease/socket; đối chiếu các guard và test liên quan |
| Giới hạn | Chưa chạy PoC end-to-end, Go test hoặc container/native-agent integration test; chưa xác minh phiên bản triển khai hay có khai thác thực tế |

Các mã F1–F5 và C1 chỉ dùng để tham chiếu trong báo cáo này. Mức P1/P2 là đề xuất thứ tự xử lý, không phải điểm CVSS hoặc kết quả tái hiện trên production.

## Kết luận

**Có các đường đi trong source có thể khiến yêu cầu do A điều khiển chạy với SSH signing identity của B.** Lỗ hổng trọng tâm nằm ở cách chọn hoặc giữ execution principal của task. Việc private key được mã hóa và không trả về worker chưa ngăn được việc dùng sai quyền ký.

Chưa tìm thấy endpoint trong luồng quản lý key đã review cho phép user thường tải private-key bytes của user khác. Không có bằng chứng trong đợt review này rằng private key đã bị trích xuất hoặc hệ thống triển khai đã bị xâm nhập.

Quy tắc cần bảo đảm:

> Task và từng attempt chỉ được cấp quyền ký của principal đã được server xác thực hoặc ủy quyền rõ ràng. Quyền xem issue, gọi shared agent, sửa nội dung hay gửi hướng dẫn không tự động cấp quyền sử dụng SSH identity của người tạo issue hoặc người mở task trước đó.

Nếu một task được gán nhầm B, cả checkout/cache và signer đều có thể nhất quán với B nhưng vẫn sai về phân quyền: đầu vào hiện tại do A kiểm soát. Cần sửa tại điểm quyết định principal, không chỉ tại bước xuất key hoặc mount socket.

## Tổng hợp

| Mã | Vấn đề | Điều kiện chính | Ưu tiên đề xuất | Mức bằng chứng |
| --- | --- | --- | --- | --- |
| F1 | Agent-token rerun kiểm tra quyền gọi theo A nhưng enqueue theo attribution của B | A có task token hợp lệ, quyền trên issue và quyền invoke agent; issue/comment gốc quy về B | P1 | Đường đi và thiếu propagation principal xác nhận từ source; chưa PoC E2E |
| F2 | Quick-create chấp nhận origin task của B trong cùng shared agent | A và B dùng cùng agent/workspace; origin của B đáp ứng guard quick-create | P1 | Thiếu binding với task token hiện tại xác nhận từ source; chưa PoC E2E |
| F3 | Supplement/comment steering đưa lệnh A vào task B đang giữ signer | A được truy cập issue và invoke agent; task B đang chạy và hỗ trợ supplement | P1 | Delivery vào session cũ xác nhận từ source; hành vi agent/Git cần kiểm thử |
| F4 | Native worker dùng writable provider profile chung, có thể truyền executable config/plugin sang task B | Backend bwrap, cùng provider profile, phiên bản provider nạp phần cấu hình/plugin đó | P1 nếu triển khai cấu hình này | Writable boundary xác nhận từ source; chuỗi OpenCode dựa trên tài liệu chính thức, cần test phiên bản cụ thể |
| F5 | Daemon token có thể xin lease mới từ task lịch sử; attempt/lifecycle chưa ràng buộc đủ | Có daemon token hợp lệ cho đúng runtime; task còn liên kết; B có identity ready | P2, phụ thuộc mô hình tin cậy supervisor | Thiếu lifecycle/attempt validation xác nhận từ source; không phải bypass trực tiếp bằng user token |
| C1 | Rotation có thể không vô hiệu lease nằm trên backend instance khác | Nhiều backend dùng chung DB nhưng lease giữ trong RAM từng instance | Cần xác minh trước khi hỗ trợ nhiều replica | Giả thuyết có căn cứ source; ngoài phạm vi single-backend được chấp nhận trước đây |

## F1 — Rerun bằng task token làm lệch principal giữa authorize và enqueue

### Điều kiện và tác động

A có một task đang hoạt động và task bearer hợp lệ, được truy cập issue liên quan và được invoke agent đích. Issue do B tạo, hoặc source task/comment làm attribution quy về B. B có SSH identity ready phù hợp provider/repo của task mới.

Trong trường hợp này, kiểm tra invoke sử dụng originator A của request nhưng enqueue không giữ A. Attribution mặc định có thể chọn B, làm task mới nhận quyền ký của B. Không cần giả mạo header người dùng hoặc biết private key. Rerun body không trực tiếp nhận một lệnh Git tùy ý; để biến việc gán sai principal thành thao tác Git do A chọn, A còn phải kiểm soát nội dung task/issue và agent phải thực thi thao tác đó.

### Bằng chứng source

- Route rerun không có `RequireHumanActor`; route supplement bên cạnh có guard này: [router.go][R1].
- Handler tạo `actorUserID := memberActorUserID(actorType, actorID)`. Với actor loại agent, hàm này trả UUID không hợp lệ. Handler resolve originator từ request để kiểm tra invoke, nhưng vẫn chuyển `actorUserID` không hợp lệ vào `RerunIssue`: [task_lifecycle.go][R2], [issue_trigger.go][R3], [agent_access.go][R4].
- Service rerun giữ source task/comment hợp lệ trong cùng issue rồi enqueue; attribution ưu tiên actor user nếu có, nếu thiếu thì xét comment/issue origin. Issue creator loại member quy về B: [RerunIssue][R5], [resolveTaskOriginatorUserID][R6], [attribution][R50].
- `OriginatorUserID` được lưu trên task, sau đó thành `ExecutionUserID`; signer cũng resolve key theo originator đó: [task creation][R7], [daemon claim][R8], [signing lease][R9].
- Với quyền sửa issue, A còn có thể thay đổi description trước rerun; claim đọc nội dung issue hiện tại: [issue update][R51], [claim payload][R52].

### Guard đang có và giới hạn kết luận

Human rerun có actor user hợp lệ nên không mặc nhiên gặp đường fallback này. Middleware xóa header giả mạo và tự đóng dấu identity từ token; source task vẫn phải khớp issue, và ACL invoke vẫn được kiểm tra. Đây không phải quyền chọn bất kỳ user/agent/workspace nào: [authentication][R45], [rerun validation][R5].

### Hướng sửa và nghiệm thu

Giữ execution principal đã resolve từ authenticated task xuyên suốt authorize → enqueue. Tách audit attribution của issue/comment khỏi quyền chọn credential. Nếu không xác lập được principal hoặc delegation, từ chối enqueue có quyền ký.

Test hai user A/B với shared agent và key thử nghiệm khác nhau. A dùng task token rerun issue/source task của B: task mới phải dùng A hoặc bị từ chối theo policy; không được chọn B chỉ vì attribution lịch sử. Giữ test human rerun hợp lệ và test forged header bị loại bỏ.

## F2 — Explicit quick-create origin nhận task của user khác cùng agent

### Điều kiện và tác động

A có task token hợp lệ của shared agent X. Trong cùng workspace có quick-create task của B do X thực hiện; A biết task ID và origin đáp ứng các kiểm tra hiện có. Trường hợp plain quick-create có `SourceContextID` rỗng cần được kiểm thử riêng.

Client có thể chỉ định explicit `origin_type=quick_create` và `origin_id`. Guard cùng workspace và cùng agent không chứng minh đó là task hiện tại của A. Attribution của issue/task phát sinh có thể quay về B.

### Bằng chứng source

- Handler ưu tiên origin do client gửi; chỉ dùng task ID đáng tin cậy từ request ở nhánh `else if`: [issue handler][R10].
- Service kiểm tra workspace, agent, context type và context workspace. Không yêu cầu origin ID bằng authenticated task ID hoặc originator bằng requester. Nhánh `SourceContextID` không rỗng có kiểm tra attach riêng; không thể xem nhánh đó là bảo vệ cho mọi quick-create: [issue service][R11].
- Auto-enqueue khi assign gọi đường enqueue không có override human actor của request; task attribution có thể thừa hưởng origin quick-create: [assignment enqueue][R12], [originator resolution][R6].
- Shared-agent task history là một nguồn có thể lộ các task ID thích hợp; không nên coi task ID là bí mật thay cho authorization: [task history][R46].

### Guard đang có và giới hạn kết luận

Khác agent hoặc khác workspace bị kiểm tra; không mô tả đây là IDOR tùy ý trên mọi task. Khả năng tái sử dụng một origin còn phụ thuộc trạng thái source context và các ràng buộc dữ liệu. Chưa có test runtime chứng minh tái sử dụng mọi quick-create task đã hoàn tất; thiếu binding với caller là kết luận source chắc chắn hơn.

### Hướng sửa và nghiệm thu

Với task actor, derive origin từ authenticated task. Nếu vẫn nhận explicit origin cho tương thích, yêu cầu nó bằng chính task đó hoặc có delegation được server xác thực. Quyền dùng cùng một agent không đủ để dùng originator của người khác.

Test same-agent/same-workspace nhưng khác user; cả source context rỗng và không rỗng; origin hợp lệ của chính caller; origin không khớp authenticated task; source đã terminal. Đảm bảo task phát sinh không lấy SSH identity B từ origin A tự chọn.

## F3 — Cross-user supplement/steering giữ nguyên signer của task B

### Điều kiện và tác động

A và B cùng workspace. B có task đang chạy với signer B; A được truy cập issue và invoke agent tương ứng. Task/session phải có capability `task-supplement-v1`. SQL hiện cho phép `codex`, `claude`, `grok`, `cursor`, `kiro`; OpenCode không nằm trong allowlist này, nên F3 và F4 là các đường độc lập: [supplement SQL][R16].

A gửi bổ sung hoặc chủ động yêu cầu comment steering (`steer:true` hoặc `steer_task_ids`) vào task đang chạy. Comment thông thường không tự động điều khiển task: [comment request][R53]. Nội dung đến chính session B đang có `SSH_AUTH_SOCK` của B; signer không phân biệt người viết từng thông điệp. Nếu agent làm theo yêu cầu Git từ A, quyền Git B được sử dụng dù A không có quyền Git tương ứng.

Quyền cộng tác trên issue và quyền sử dụng key cá nhân là hai quyền cần được phân biệt trong policy. Nếu muốn cho phép cross-user steering, phải có cơ chế ủy quyền rõ ràng cho các thao tác dùng credential.

### Bằng chứng source

- Direct supplement kiểm tra issue access, task thuộc issue, invoke ACL, trạng thái và capability; không đối chiếu requester với execution principal của task đích: [supplement handler][R13], [SQL enqueue][R16].
- Comment steering cũng dispatch vào task cũ và kiểm tra invoke, không tái gán principal: [comment input][R15], [steering dispatch][R14], [comment supplement SQL][R17].
- Daemon đưa nội dung vào `session.Supplement` của session hiện hữu; hướng dẫn còn cho phép thay đổi mục tiêu khi human yêu cầu: [daemon supplement][R18].
- Git socket được mở cho task, cleanup theo vòng đời task; môi trường task có socket đó: [socket lifecycle][R19], [task environment][R20].

### Guard đang có và giới hạn kết luận

Direct supplement có `RequireHumanActor`, nhưng comment route là bề mặt riêng cần kiểm tra cho task actor. User không được invoke, task khác issue/workspace, task terminal hoặc provider không hỗ trợ bị chặn ở các bước tương ứng. Test hiện có về non-invoker/foreign tenant không thay thế test giữa hai user đều được invoke: [routes][R1], [existing tests][R48].

Agent-authored steering còn có kiểm tra khác source/target agent và giới hạn theo lượt; daemon trình bày peer input khác human guidance. Các guard này ảnh hưởng khả năng sử dụng đường comment nhưng không tạo kiểm tra equality của execution principal: [steering checks][R55], [daemon guidance][R18].

Đã xác nhận đường delivery; chưa chạy agent thực để chứng minh nó làm theo một yêu cầu cụ thể. Không cần mô tả prompt injection là chắc chắn thành công để nhận ra session đang được điều khiển mà không đổi quyền ký.

### Hướng sửa và nghiệm thu

Kiểm tra execution principal/delegation tại cả direct supplement và comment steering. Với A khác B, từ chối thao tác điều khiển session có credential B hoặc tạo run riêng dưới A, theo policy sản phẩm. Hướng dẫn bằng prompt không thay thế authorization tại server.

Dùng fake session để kiểm tra delivery bị chặn trước khi đến session B; sau đó dùng synthetic Git transport kiểm tra A không truy cập repo chỉ key B được cấp quyền. Giữ hành vi supplement chính chủ và delegation hợp lệ nếu được hỗ trợ.

## F4 — Writable native profile có thể đưa code của A vào task B

### Điều kiện và tác động

Triển khai chọn `MULTICA_TASK_SANDBOX=bwrap` và chạy A/B qua cùng provider profile. A phải điều khiển được code trong một native task hợp lệ; sau đó B chạy task dùng cùng profile và được cấp signer B. Đây không phải cấu hình Docker mặc định.

Native worker được ghi vào toàn bộ một số thư mục profile. Nếu profile chứa cấu hình nạp code/plugin, A có thể để lại nội dung được nạp khi task B khởi động. Code đó chạy trong môi trường B có signer B. Profile lock chỉ tuần tự hóa truy cập, không xóa thay đổi có chủ ý trước lượt chạy sau.

### Bằng chứng source

- Runtime đưa provider profile vào `Writable`; profile key dựa trên provider và đường dẫn canonical, không dựa trên execution user. OpenCode dùng các thư mục config/data/state/cache trong profile: [native profile grants][R21], [profile key/paths][R22].
- Native sandbox mount các đường writable này, thiết lập provider env/HOME, rồi truyền task socket vào cấu hình worker: [native sandbox][R23].
- OpenCode isolation chặn external server/đặt standalone cho phiên bản phù hợp; cấu hình MCP được merge, không chứng minh global executable profile bị vô hiệu: [OpenCode isolation][R24], [MCP config][R25].
- Tài liệu chính thức [OpenCode plugins](https://opencode.ai/docs/plugins/) và [OpenCode v2 plugins](https://dev.opencode.ai/v2/docs/plugins) mô tả global plugin discovery dưới `~/.config/opencode/plugins/`. Đây là cơ sở cho kịch bản cần kiểm thử: một plugin canary được A ghi vào profile chung được tiến trình của B nạp và nhìn thấy signer B.
- Tài liệu repository đã nêu shared provider profiles thuộc một account trust domain và hoãn provider credential secrecy: [tool isolation][R26]. Điều đó cần được xem xét riêng với yêu cầu không dùng chéo SSH identity của các human user.

### Giới hạn và hướng sửa

Chưa chạy canary plugin trên binary OpenCode của deployment. Cần pin version, backend, config path và xác minh code thực sự được nạp trong task B; không suy diễn đường này áp dụng y hệt Docker hoặc mọi provider.

Tách writable executable config/plugin/session theo execution user hoặc task. Phần cấu hình chung được tin cậy có thể mount read-only. Nếu cần cùng subscription account, đồng bộ auth bằng thành phần tin cậy với phạm vi hẹp; không dùng chung toàn bộ cây config có thể thực thi code giữa các user không tin cậy nhau.

Test hai task chạy nối tiếp trên cùng runtime/profile: canary do A ghi không được B nạp; B vẫn dùng đúng key B cho thao tác hợp lệ. Kiểm tra cả fresh session và resume, đồng thời giữ khả năng dùng chung subscription nếu đó là yêu cầu sản phẩm.

## F5 — Task lịch sử còn có thể làm căn cứ mở signing lease

### Điều kiện và tác động

Actor có daemon/supervisor token hợp lệ, khớp daemon và runtime chứa task lịch sử. Task còn giữ originator/runtime và B còn identity ready. Đây là quyền đặc biệt của supervisor hoặc tình huống supervisor bị compromise; không phải user thường chỉ cần đoán task ID là gọi được signer API.

Endpoint xác thực daemon/runtime nhưng không chứng minh task đang chạy đúng attempt. Vì vậy một task đã kết thúc có thể tiếp tục được dùng để xin lease mới. TTL ngắn của từng lease không tự đóng khả năng xin lease mới từ task cũ. Lease đã hết hạn vẫn bị từ chối; vấn đề là tạo một lease mới khi task đã terminal.

### Bằng chứng source

- Handler nhận task/provider/attempt rồi gọi signing service sau kiểm tra daemon access: [signing handler][R27], [token restriction][R28], [runtime access][R29].
- Task-originator query chỉ lấy `originator_user_id` theo ID; completion/cancel vẫn giữ attribution/runtime cần thiết: [originator SQL][R30], [complete SQL][R32], [cancel SQL][R33].
- `OpenLease` lấy identity ready hiện tại của originator và lưu attempt do caller cung cấp; không so với một active claim/attempt do server cấp: [OpenLease][R9].
- Renew/sign kiểm tra daemon, lease expiry/revocation và key state; không truy vấn lại active task/attempt: [renew/sign][R31].
- Daemon token có lifetime riêng và binding daemon/runtime owner; không tương đương token chỉ được sử dụng cho một attempt đang chạy: [daemon token issue][R47].

### Guard đang có và giới hạn kết luận

Endpoint yêu cầu daemon token thật; task token không tự biến thành daemon token. Worker nhận task bearer/socket theo đường môi trường đã review. Key bị revoke hoặc custody không khả dụng vẫn có thể chặn signing. Không kết luận mọi lease sống vô hạn, hoặc revoke key không có tác dụng.

Test hiện có chứng minh lease cũ không tự hồi sinh sau revoke/generate; nó chưa chứng minh task terminal không thể xin một lease mới với generation mới: [existing signing test][R49].

### Hướng sửa và nghiệm thu

Gắn quyền mở/renew/sign với claim/attempt do server xác lập: task, execution user, runtime, provider, attempt và key generation phải nhất quán. Kiểm tra trạng thái ở server; vô hiệu hóa quyền khi task terminal hoặc attempt bị thay thế. Giữ phạm vi sửa phù hợp mô hình supervisor đã chọn, không bổ sung cả framework ủy quyền mới nếu không cần.

Test task completed/failed/cancelled, attempt cũ và attempt do caller tự đặt đều bị từ chối; attempt hiện hành đúng scope vẫn ký được. Kiểm tra cả mở lease mới lẫn lease đã tồn tại, kể cả sau rotation/generate.

## C1 — Cần xác minh rotation với nhiều backend instance

Rotation cập nhật active generation và gọi `revokeStaleLeases` trên service hiện tại. Lease giữ trong RAM từng instance; sign/renew đọc trạng thái key nhưng không chứng minh generation vẫn là generation active của identity. Generation cũ có thể vẫn ở trạng thái ready: [rotation][R34], [active generation SQL][R35], [sign/renew][R31].

Kịch bản cần kiểm thử: X mở lease; Y rotate cùng identity trên DB chung; client tiếp tục dùng lease ở X. Không coi việc revoke trong RAM Y là bằng chứng lease ở X đã bị chặn.

Gửi request đến instance không giữ lease thường bị từ chối vì unknown lease; kịch bản trên cần request quay về đúng instance X giữ lease. Full key revoke còn cập nhật key state trong DB, khác với chỉ rotate active generation: [single-instance scope][R54], [sign/renew][R31], [revoke][R56].

Đây là **mục cần xác minh có điều kiện**, không phải kết luận mọi deployment mắc lỗi. [Issue #88](https://github.com/ba0f3/multica/issues/88) từng chấp nhận single-backend và yêu cầu multi-instance unsupported/fail-closed. Khi giữ giới hạn đó, cần chứng minh deployment từ chối cấu hình không hỗ trợ. Khi hỗ trợ nhiều replica, kiểm tra active generation/epoch từ trạng thái authoritative hoặc triển khai invalidation tương đương; test bằng hai service dùng chung store.

## Cấu hình không có sandbox

`MULTICA_TASK_SANDBOX=false/off` bỏ isolation; mặc định là Docker và protected mode có guard từ chối host fallback: [backend selection][R36].

Socket có directory mode 0700 và socket mode 0600, nằm trong cây profile daemon: [socket permissions][R37], [socket path][R38]. Các mode này phân biệt OS UID, không phân biệt user Multica. Nếu chạy các task không tin cậy dưới cùng UID và cùng filesystem visibility, chmod không tạo ranh giới A/B.

Đây là điều kiện triển khai làm mất isolation, không phải bằng chứng Docker mặc định lộ socket. Nếu cần tách user không tin cậy, dùng sandbox được hỗ trợ hoặc một boundary OS/VM tương đương và kiểm thử việc truy cập socket/task lân cận.

## Các kiểm soát đã thấy hoạt động ở mức source

| Bề mặt | Kiểm soát đã có | Ý nghĩa và giới hạn |
| --- | --- | --- |
| Key management API | Human session, recent authentication cho thao tác nhạy cảm, reject unknown JSON fields; [handler][R39] | Không thấy client chọn user ID tùy ý để quản lý key người khác |
| Identity service | Ownership check, public identity response không có private bytes; [service][R40] | Hạn chế IDOR trực tiếp ở CRUD; không sửa task bị gán nhầm principal |
| Custody | Lưu key được mã hóa, giải mã trong đường ký; [DB custody][R41] | Worker không cần giữ private key để dùng được quyền Git |
| SSH agent protocol | Chỉ key đã chọn, ràng buộc request; add/remove/lock không được hỗ trợ; [socket operations][R42] | Ngăn sửa keyring qua agent protocol |
| Socket mount | Docker bind đúng task socket; [Docker mount][R43] | Giảm truy cập socket lân cận khi isolation hoạt động; không sửa socket được cấp cho sai user |
| Repo scope | Workspace + execution user; [repo scope][R44] | Cache phân tách theo principal server đưa xuống; principal cần đúng ngay từ đầu |

Không suy diễn “chưa thấy private key leak” thành bảo đảm tuyệt đối cho mọi endpoint, log, backup hoặc cấu hình deployment; các bề mặt đó chưa được audit toàn diện trong nhiệm vụ này.

## Thứ tự xử lý đề xuất

1. **F1/F2:** sửa nguồn principal tại enqueue; giữ attribution phục vụ audit riêng với credential authority.
2. **F3:** chốt và enforce policy điều khiển task có credential qua cả supplement và comment steering.
3. **F4:** nếu dùng native bwrap với user không tin cậy nhau, tách writable executable provider state trước khi coi native là boundary SSH đa user.
4. **F5:** làm rõ và enforce vòng đời quyền ký theo task/attempt; không chỉ TTL của lease.
5. **C1:** giữ single-backend fail-closed có kiểm chứng, hoặc bổ sung kiểm thử/đảm bảo invalidation trước khi hỗ trợ replica.

Sửa trong kiến trúc hiện có; báo cáo không yêu cầu khôi phục các kế hoạch/framework từng bị supersede. Không cần thêm exact-repo broker: tiêu chí ở đây là credential đúng user; Git provider tiếp tục quyết định repo/branch mà credential đó được phép truy cập.

## Checklist nghiệm thu

Mọi test dùng user, key, repo và provider fixture riêng cho kiểm thử. Default suite dùng fake CLI/session, không truy cập account provider hay repo thật.

- [ ] F1: agent-token rerun issue/source của B không cấp SSH identity B cho request do A khởi phát; human rerun vẫn đúng principal.
- [ ] F2: origin quick-create khác authenticated task bị từ chối hoặc có delegation được kiểm chứng; same-agent khác-user không vượt qua bằng equality của agent ID.
- [ ] F3: A không đưa chỉ thị vào credential-bearing session B qua direct supplement hoặc comment steering nếu chưa có quyền delegation.
- [ ] F4: native task A không để lại executable profile state được task B thực thi; ghi nhận provider version/backend và kết quả canary.
- [ ] F5: task terminal, stale attempt hoặc forged attempt không open/renew/sign; attempt hợp lệ vẫn hoạt động.
- [ ] C1: single-instance constraint được enforce, hoặc lease trên X bị vô hiệu đúng policy khi rotate trên Y.
- [ ] Giữ các negative test cho outsider, non-invoker, cross-workspace, forged user/task header, sai daemon/runtime và key bị revoke.
- [ ] Synthetic Git test: A chỉ có quyền repo A, B có quyền repo B; mọi đường A khởi phát vẫn bị từ chối với repo chỉ B được quyền.
- [ ] Public API, worker manifest/env và log thử nghiệm không chứa private-key bytes hay privileged supervisor token.
- [ ] Kiểm thử cleanup/cancel và accepted socket connections; không dùng việc unlink socket đơn thuần làm bằng chứng kết thúc quyền ký.
- [ ] Ghi lại SHA đã sửa, backend/provider version, test đã chạy và giới hạn còn lại trước khi đóng issue.

## Trạng thái xác minh và liên hệ công việc cũ

Báo cáo này là kết quả review source, không phải patch hoặc chứng nhận đã khắc phục. Các regression test trong checklist là yêu cầu nghiệm thu đề xuất, chưa được chạy trong phiên review. Môi trường review không có Go/Docker; không dùng production credentials hoặc thực hiện khai thác trên deployment.

Các issue [#84](https://github.com/ba0f3/multica/issues/84), [#86](https://github.com/ba0f3/multica/issues/86), [#88](https://github.com/ba0f3/multica/issues/88), [#89](https://github.com/ba0f3/multica/issues/89) là lịch sử thiết kế/triển khai và đã đóng tại thời điểm lập báo cáo. Trạng thái đóng của chúng không được dùng thay bằng chứng rằng các đường đi trên revision đang review đã được chặn.

## Tham chiếu source bất biến

Toàn bộ liên kết source bên dưới trỏ vào đúng revision được review, không trỏ vào nhánh main có thể thay đổi.

[R1]: https://github.com/ba0f3/multica/blob/07e553524fc332c5330d373cc357171c158beb6f/server/cmd/server/router.go#L2075-L2099
[R2]: https://github.com/ba0f3/multica/blob/07e553524fc332c5330d373cc357171c158beb6f/server/internal/handler/task_lifecycle.go#L225-L246
[R3]: https://github.com/ba0f3/multica/blob/07e553524fc332c5330d373cc357171c158beb6f/server/internal/handler/issue_trigger.go#L97-L109
[R4]: https://github.com/ba0f3/multica/blob/07e553524fc332c5330d373cc357171c158beb6f/server/internal/handler/agent_access.go#L222-L238
[R5]: https://github.com/ba0f3/multica/blob/07e553524fc332c5330d373cc357171c158beb6f/server/internal/service/task.go#L5875-L6040
[R6]: https://github.com/ba0f3/multica/blob/07e553524fc332c5330d373cc357171c158beb6f/server/internal/service/task.go#L513-L597
[R7]: https://github.com/ba0f3/multica/blob/07e553524fc332c5330d373cc357171c158beb6f/server/internal/service/task.go#L1313-L1335
[R8]: https://github.com/ba0f3/multica/blob/07e553524fc332c5330d373cc357171c158beb6f/server/internal/handler/daemon.go#L2833-L2849
[R9]: https://github.com/ba0f3/multica/blob/07e553524fc332c5330d373cc357171c158beb6f/server/internal/r2dgit/signing.go#L150-L225
[R10]: https://github.com/ba0f3/multica/blob/07e553524fc332c5330d373cc357171c158beb6f/server/internal/handler/issue.go#L3366-L3418
[R11]: https://github.com/ba0f3/multica/blob/07e553524fc332c5330d373cc357171c158beb6f/server/internal/service/issue.go#L434-L483
[R12]: https://github.com/ba0f3/multica/blob/07e553524fc332c5330d373cc357171c158beb6f/server/internal/service/issue.go#L865-L905
[R13]: https://github.com/ba0f3/multica/blob/07e553524fc332c5330d373cc357171c158beb6f/server/internal/handler/task_supplement.go#L271-L362
[R14]: https://github.com/ba0f3/multica/blob/07e553524fc332c5330d373cc357171c158beb6f/server/internal/handler/task_supplement.go#L188-L239
[R15]: https://github.com/ba0f3/multica/blob/07e553524fc332c5330d373cc357171c158beb6f/server/internal/handler/comment.go#L1700-L1706
[R16]: https://github.com/ba0f3/multica/blob/07e553524fc332c5330d373cc357171c158beb6f/server/pkg/db/queries/supplement.sql#L41-L80
[R17]: https://github.com/ba0f3/multica/blob/07e553524fc332c5330d373cc357171c158beb6f/server/pkg/db/queries/supplement.sql#L115-L145
[R18]: https://github.com/ba0f3/multica/blob/07e553524fc332c5330d373cc357171c158beb6f/server/internal/daemon/task_supplement.go#L110-L181
[R19]: https://github.com/ba0f3/multica/blob/07e553524fc332c5330d373cc357171c158beb6f/server/internal/daemon/daemon.go#L8041-L8047
[R20]: https://github.com/ba0f3/multica/blob/07e553524fc332c5330d373cc357171c158beb6f/server/internal/daemon/daemon.go#L8969-L8976
[R21]: https://github.com/ba0f3/multica/blob/07e553524fc332c5330d373cc357171c158beb6f/server/internal/daemon/sandbox/native_runtime.go#L153-L176
[R22]: https://github.com/ba0f3/multica/blob/07e553524fc332c5330d373cc357171c158beb6f/server/internal/daemon/sandbox/native_runtime.go#L222-L260
[R23]: https://github.com/ba0f3/multica/blob/07e553524fc332c5330d373cc357171c158beb6f/server/internal/daemon/native_sandbox.go#L231-L310
[R24]: https://github.com/ba0f3/multica/blob/07e553524fc332c5330d373cc357171c158beb6f/server/pkg/agent/opencode_isolated.go#L17-L25
[R25]: https://github.com/ba0f3/multica/blob/07e553524fc332c5330d373cc357171c158beb6f/server/pkg/agent/opencode_mcp.go#L81-L109
[R26]: https://github.com/ba0f3/multica/blob/07e553524fc332c5330d373cc357171c158beb6f/docs/security/tool-isolation.md#L35-L39
[R27]: https://github.com/ba0f3/multica/blob/07e553524fc332c5330d373cc357171c158beb6f/server/internal/handler/r2d_git_sign.go#L24-L58
[R28]: https://github.com/ba0f3/multica/blob/07e553524fc332c5330d373cc357171c158beb6f/server/internal/handler/git_signing_access.go#L19-L53
[R29]: https://github.com/ba0f3/multica/blob/07e553524fc332c5330d373cc357171c158beb6f/server/internal/handler/daemon.go#L220-L278
[R30]: https://github.com/ba0f3/multica/blob/07e553524fc332c5330d373cc357171c158beb6f/server/pkg/db/queries/r2d_git.sql#L186-L188
[R31]: https://github.com/ba0f3/multica/blob/07e553524fc332c5330d373cc357171c158beb6f/server/internal/r2dgit/signing.go#L228-L325
[R32]: https://github.com/ba0f3/multica/blob/07e553524fc332c5330d373cc357171c158beb6f/server/pkg/db/queries/agent.sql#L1004-L1014
[R33]: https://github.com/ba0f3/multica/blob/07e553524fc332c5330d373cc357171c158beb6f/server/pkg/db/queries/agent.sql#L1412-L1416
[R34]: https://github.com/ba0f3/multica/blob/07e553524fc332c5330d373cc357171c158beb6f/server/internal/r2dgit/service.go#L364-L374
[R35]: https://github.com/ba0f3/multica/blob/07e553524fc332c5330d373cc357171c158beb6f/server/pkg/db/queries/r2d_git.sql#L77-L84
[R36]: https://github.com/ba0f3/multica/blob/07e553524fc332c5330d373cc357171c158beb6f/server/internal/daemon/sandbox_launch.go#L24-L64
[R37]: https://github.com/ba0f3/multica/blob/07e553524fc332c5330d373cc357171c158beb6f/server/internal/daemon/gitagent/socket.go#L90-L106
[R38]: https://github.com/ba0f3/multica/blob/07e553524fc332c5330d373cc357171c158beb6f/server/internal/daemon/git_agent.go#L174-L188
[R39]: https://github.com/ba0f3/multica/blob/07e553524fc332c5330d373cc357171c158beb6f/server/internal/handler/r2d_git.go#L29-L101
[R40]: https://github.com/ba0f3/multica/blob/07e553524fc332c5330d373cc357171c158beb6f/server/internal/r2dgit/service.go#L460-L504
[R41]: https://github.com/ba0f3/multica/blob/07e553524fc332c5330d373cc357171c158beb6f/server/internal/r2dgit/db_custody.go#L37-L107
[R42]: https://github.com/ba0f3/multica/blob/07e553524fc332c5330d373cc357171c158beb6f/server/internal/daemon/gitagent/socket.go#L229-L283
[R43]: https://github.com/ba0f3/multica/blob/07e553524fc332c5330d373cc357171c158beb6f/server/internal/daemon/sandbox_launch_docker.go#L83-L88
[R44]: https://github.com/ba0f3/multica/blob/07e553524fc332c5330d373cc357171c158beb6f/server/internal/daemon/repo_scope.go#L1-L24
[R45]: https://github.com/ba0f3/multica/blob/07e553524fc332c5330d373cc357171c158beb6f/server/internal/middleware/auth.go#L83-L144
[R46]: https://github.com/ba0f3/multica/blob/07e553524fc332c5330d373cc357171c158beb6f/server/internal/handler/agent.go#L2911-L3000
[R47]: https://github.com/ba0f3/multica/blob/07e553524fc332c5330d373cc357171c158beb6f/server/internal/handler/daemon.go#L2674-L2695
[R48]: https://github.com/ba0f3/multica/blob/07e553524fc332c5330d373cc357171c158beb6f/server/internal/handler/task_supplement_test.go#L595-L617
[R49]: https://github.com/ba0f3/multica/blob/07e553524fc332c5330d373cc357171c158beb6f/server/internal/r2dgit/signing_test.go#L152-L183
[R50]: https://github.com/ba0f3/multica/blob/07e553524fc332c5330d373cc357171c158beb6f/server/internal/attribution/attribution.go#L325-L330
[R51]: https://github.com/ba0f3/multica/blob/07e553524fc332c5330d373cc357171c158beb6f/server/internal/handler/issue.go#L3793-L3863
[R52]: https://github.com/ba0f3/multica/blob/07e553524fc332c5330d373cc357171c158beb6f/server/internal/handler/daemon.go#L3118-L3150
[R53]: https://github.com/ba0f3/multica/blob/07e553524fc332c5330d373cc357171c158beb6f/server/internal/handler/comment.go#L1417-L1424
[R54]: https://github.com/ba0f3/multica/blob/07e553524fc332c5330d373cc357171c158beb6f/server/internal/r2dgit/service.go#L69-L76
[R55]: https://github.com/ba0f3/multica/blob/07e553524fc332c5330d373cc357171c158beb6f/server/internal/handler/task_supplement.go#L150-L176
[R56]: https://github.com/ba0f3/multica/blob/07e553524fc332c5330d373cc357171c158beb6f/server/internal/r2dgit/service.go#L397-L418
