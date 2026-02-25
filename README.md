# 🏥 MANI Learning Hub v2.0 - LMS Lite

Nền tảng đào tạo & cấp chứng chỉ nội bộ cho Mani Medical Hanoi.

---

## 🚀 HƯỚNG DẪN CẬP NHẬT TRÊN RENDER (Dành cho người không biết code)

### Tình huống: Bạn ĐÃ có repo GitHub và đã deploy trên Render

#### Bước 1: Cập nhật code trên GitHub

**Cách 1: Dùng GitHub web (Dễ nhất - không cần cài gì)**

1. Vào repo GitHub của bạn (ví dụ: `github.com/YOUR_USERNAME/mani-lms`)
2. Giải nén file `mani-lms-v2.zip` trên máy tính
3. Trên GitHub, xóa TẤT CẢ file cũ:
   - Click vào từng file → nhấn biểu tượng 🗑 (Delete) → Commit
   - HOẶC: Click nút "Add file" → "Upload files" → kéo thả TẤT CẢ file từ thư mục `mani-lms-v2/` vào
4. GitHub sẽ tự động cập nhật

**Cách 2: Dùng GitHub Desktop (Dễ hơn dòng lệnh)**

1. Tải GitHub Desktop: https://desktop.github.com/
2. Clone repo của bạn về máy
3. Xóa tất cả file cũ trong thư mục repo (trừ folder `.git`)
4. Copy tất cả file từ `mani-lms-v2/` vào thư mục repo
5. Trong GitHub Desktop: nhập commit message "Update to v2.0" → Click "Commit" → Click "Push"

**Cách 3: Dùng dòng lệnh (Nếu đã quen)**

```bash
cd mani-lms          # thư mục repo của bạn
# Xóa file cũ (giữ .git)
find . -maxdepth 1 ! -name '.git' ! -name '.' -exec rm -rf {} +
# Copy file mới
cp -r /path/to/mani-lms-v2/* .
cp /path/to/mani-lms-v2/.gitignore .
# Push
git add -A
git commit -m "Update to v2.0 - all fixes and new features"
git push
```

#### Bước 2: Render sẽ tự động deploy

- Sau khi push code lên GitHub, Render sẽ **tự động** phát hiện thay đổi
- Render sẽ build lại và deploy phiên bản mới
- Quá trình mất khoảng 2-5 phút
- Kiểm tra tại: Render Dashboard → Service → Events (xem log)

#### Bước 3: Kiểm tra database (QUAN TRỌNG)

- Code v2.0 tự động thêm các cột mới vào database cũ (migration-safe)
- **KHÔNG cần xóa database** — tất cả accounts, courses, history đều được giữ nguyên
- Các cột mới: `quiz_count`, `max_attempts`, `source`, `attempt_number`, `is_valid`

---

### Tình huống: Deploy LẦN ĐẦU trên Render

#### Bước 1: Tạo repo GitHub

1. Vào https://github.com → Đăng nhập/Đăng ký
2. Click **"New repository"** (nút xanh lá)
3. Đặt tên: `mani-lms`
4. Chọn **Public** hoặc **Private**
5. Click **"Create repository"**
6. Click **"uploading an existing file"**
7. Giải nén `mani-lms-v2.zip` → kéo thả TẤT CẢ file vào
8. Click **"Commit changes"**

#### Bước 2: Deploy trên Render

1. Vào https://render.com → Đăng ký bằng GitHub
2. Click **"New +"** → **"Web Service"**
3. Chọn repo `mani-lms` → Click **"Connect"**
4. Cấu hình:
   - **Name:** `mani-learning-hub`
   - **Region:** Singapore (gần VN nhất)
   - **Branch:** `main`
   - **Runtime:** `Python 3`
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `gunicorn app:app --bind 0.0.0.0:$PORT --workers 2 --timeout 120`
5. Chọn plan **Free** (hoặc Starter $7/tháng nếu muốn nhanh hơn)
6. Click **"Create Web Service"**

#### Bước 3: Thêm Disk (LƯU TRỮ database)

⚠️ **RẤT QUAN TRỌNG** — Không có Disk, data sẽ mất khi Render restart!

1. Trong trang service, vào **Settings** → kéo xuống **Disks**
2. Click **"Add Disk"**
   - **Name:** `lms-data`
   - **Mount Path:** `/opt/render/project/data`
   - **Size:** `1 GB`
3. Click **"Save"**

#### Bước 4: Thêm Environment Variables

Vào **Settings** → **Environment** → thêm các biến sau:

| Key | Value | Ghi chú |
|-----|-------|---------|
| `DATABASE_PATH` | `/opt/render/project/data/lms.db` | **BẮT BUỘC** |
| `SECRET_KEY` | (click Generate) | **BẮT BUỘC** |

#### Bước 5: Cấu hình Email (ĐỂ GỬI ĐƯỢC EMAIL)

Thêm tiếp các biến sau nếu muốn gửi email tự động:

| Key | Value | Ghi chú |
|-----|-------|---------|
| `SMTP_SERVER` | `smtp.gmail.com` | Hoặc SMTP server khác |
| `SMTP_PORT` | `587` | Port TLS |
| `SMTP_USER` | `your-email@gmail.com` | Email dùng để gửi |
| `SMTP_PASS` | `abcd efgh ijkl mnop` | App Password (KHÔNG phải mật khẩu Gmail) |
| `SMTP_FROM` | `your-email@gmail.com` | Email hiển thị khi gửi |

**Cách tạo App Password cho Gmail:**
1. Vào https://myaccount.google.com/security
2. Bật **"Xác minh 2 bước"** (2-Step Verification) nếu chưa bật
3. Tìm **"Mật khẩu ứng dụng"** (App passwords)
4. Chọn app: **"Mail"**, device: **"Other"** → nhập "MANI LMS"
5. Google sẽ cho bạn 1 mã 16 ký tự (ví dụ: `abcd efgh ijkl mnop`)
6. Copy mã này vào `SMTP_PASS` trên Render

⚠️ Nếu KHÔNG cấu hình SMTP, mã xác nhận đăng ký sẽ hiển thị trực tiếp trên màn hình (và trong server logs). Admin có thể cung cấp mã cho người đăng ký.

#### Bước 6: Deploy xong!

- URL của bạn sẽ là: `https://mani-learning-hub.onrender.com`
- Share link này cho team để sử dụng

---

## 📋 THÔNG TIN TÀI KHOẢN

### Admin mặc định
| Email | Mật khẩu |
|-------|-----------|
| `mmh.product@manimedicalhanoi.com` | `123456` |

⚠️ Hãy đổi mật khẩu sau khi đăng nhập lần đầu!

### Email được phép đăng ký (Whitelist)
Chỉ các email sau mới được đăng ký tài khoản:

```
tt.tuyen@manimedicalhanoi.com
nt.ha@manimedicalhanoi.com
marketing.mmh@manimedicalhanoi.com
marketing.mmh2@manimedicalhanoi.com
marketing.mmh1@manimedicalhanoi.com
mmh.product@manimedicalhanoi.com
mmh.admin@manimedicalhanoi.com
mmh.danang@manimedicalhanoi.com
mmh.hanoi@manimedicalhanoi.com
mmh.saigon@manimedicalhanoi.com
mmh.hanoi2@manimedicalhanoi.com
vtt.hoa@manimedicalhanoi.com
ntt.hang@manimedicalhanoi.com
mmh.order@manimedicalhanoi.com
mmh.backoffice@manimedicalhanoi.com
```

---

## ✨ TÍNH NĂNG v2.0

### Đã sửa (Fixes)
- ✅ CSV Import: Hoạt động đầy đủ - hỗ trợ kéo thả file + dán text
- ✅ Certificate: Tải được trên điện thoại (hiện ảnh để long-press save)
- ✅ Email: Hiển thị mã xác nhận trên màn hình nếu SMTP chưa cấu hình

### Tính năng mới
- ✅ Tìm kiếm khóa học bằng text
- ✅ Duyệt theo Category (Compliance/SOP/Product/Skills/Education) - thanh chips ở header
- ✅ Ngân hàng câu hỏi: CSV + thủ công bổ sung cho nhau, không xóa lẫn nhau
- ✅ Trainer setup: số câu hỏi random, điểm đạt, max lượt thi
- ✅ Giới hạn 3 lượt thi (cấu hình được), câu hỏi ngẫu nhiên mỗi lượt
- ✅ Trainer yêu cầu thi lại: reset kết quả, gửi email thông báo
- ✅ Phân quyền: Admin cấp quyền Trainer, mọi người mặc định là Learner
- ✅ Gửi email nhắc nhở: cho cá nhân / phòng ban / tất cả
- ✅ Gửi chứng chỉ qua email (nút trên trang kết quả + trang chứng chỉ)

---

## 📁 Cấu trúc file

```
mani-lms-v2/
├── app.py              # Flask application (main code)
├── requirements.txt    # Python dependencies
├── Procfile           # Render start command
├── render.yaml        # Render config
├── .gitignore         # Git ignore rules
└── templates/         # HTML templates (14 files)
    ├── base.html          # Layout chung
    ├── login.html         # Đăng nhập
    ├── register.html      # Đăng ký
    ├── verify.html        # Xác nhận email
    ├── dashboard.html     # Trang chủ
    ├── category.html      # Duyệt theo danh mục
    ├── search.html        # Kết quả tìm kiếm
    ├── course_detail.html # Chi tiết khóa học
    ├── quiz.html          # Làm bài thi
    ├── quiz_result.html   # Kết quả thi
    ├── certificate.html   # Chứng chỉ (in/tải/email)
    ├── my_certs.html      # Chứng chỉ của tôi
    ├── admin.html         # Quản trị (users/content/remind)
    ├── course_form.html   # Form thêm/sửa khóa học
    ├── questions.html     # Quản lý ngân hàng câu hỏi
    └── analytics.html     # Thống kê & báo cáo
```
