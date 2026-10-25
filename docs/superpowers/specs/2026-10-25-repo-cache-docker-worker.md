# Repo cache for Docker workers — operator spec

Status date: **2026-10-25**. Provided by the operator in the current session.

Phạm vi: Áp dụng cho repo được khai báo trong task.Repos. local_directory giữ luồng hiện tại. Mỗi task vẫn có workdir ghi được riêng; không mount checkout dùng chung.

1. Làm mới trước khi chạy: Daemon đồng bộ cache cho các repo của task, fetch ở bước chuẩn bị và phân giải ref được yêu cầu thành commit SHA. Nếu fetch hoặc phân giải ref thất bại, báo lỗi rõ ràng; không âm thầm dùng cache cũ. “Mới nhất” là trạng thái remote tại thời điểm fetch.
2. Mount: Chỉ mount bare cache của các repo thuộc task vào container ở chế độ read-only. Ghi URL, SHA và đường dẫn cache vào manifest riêng của task; không cho worker chọn một cache path tùy ý.
3. Checkout trong worker: multica repo checkout <url> dùng manifest để tạo checkout trong workdir của task, với .git riêng và origin trỏ về URL thật. Commit, fetch và push của agent tiếp tục chạy trong container bằng SSH socket của task. Lệnh checkout qua host daemon vẫn bị chặn.
4. Vòng đời objects: Nếu checkout dùng Git alternates để tránh copy toàn bộ lịch sử, cache phải được giữ đến khi mọi workdir phụ thuộc vào nó được dọn, kể cả qua lần khởi động lại daemon. GC không được prune/repack làm mất objects đang được tham chiếu. Worker không được sửa cache qua hardlink.
5. Tái sử dụng workdir: Giữ thay đổi và commit chưa push trong checkout cũ; không reset về SHA mới. Daemon vẫn fetch và cung cấp SHA mới để agent biết nhánh của mình đã lệch bao xa.
6. Kiểm chứng: Test commit mới xuất hiện trước task kế tiếp, fetch lỗi không chạy trên bản cũ, hai task không sửa checkout/cache của nhau, cache sống qua restart và bị dọn đúng lúc. Benchmark repo lớn với cache lạnh/ấm, tách thời gian fetch, tạo checkout và ghi working tree.

Cache lạnh vẫn cần tải repo một lần. Mục tiêu là các task sau không phải tải lại toàn bộ lịch sử từ remote.
