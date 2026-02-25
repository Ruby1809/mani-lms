# 🏥 MANI Learning Hub - LMS Lite

Nền tảng đào tạo & cấp chứng chỉ nội bộ cho Mani Medical Hanoi.

## 🚀 Deploy nhanh lên Render (Miễn phí)

### Bước 1: Push code lên GitHub
```bash
git init
git add .
git commit -m "MANI Learning Hub v1.0"
git remote add origin https://github.com/YOUR_USERNAME/mani-lms.git
git push -u origin main
```

### Bước 2: Deploy trên Render
1. Vào [render.com](https://render.com) → Đăng ký/Đăng nhập
2. Click **"New +"** → **"Web Service"**
3. Kết nối GitHub repo
4. Cấu hình:
   - **Name:** `mani-learning-hub`
   - **Runtime:** Python 3
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `gunicorn app:app --bind 0.0.0.0:$PORT --workers 2`
5. Thêm **Disk** (Settings → Disks):
   - Mount Path: `/opt/render/project/data`
   - Size: 1 GB
6. Thêm **Environment Variables:**
   - `SECRET_KEY` = (tự generate)
   - `DATABASE_PATH` = `/opt/render/project/data/lms.db`
   - `SMTP_SERVER` = `smtp.gmail.com` (tùy chọn)
   - `SMTP_PORT` = `587`
   - `SMTP_USER` = (email gửi thông báo)
   - `SMTP_PASS` = (App Password)
7. Click **Deploy**

### Bước 3: Cấu hình Email (Tùy chọn)
Để gửi email xác nhận, thêm các biến môi trường SMTP:
- `SMTP_USER`: Email Gmail (ví dụ: mani.lms@gmail.com)
- `SMTP_PASS`: App Password từ Google Account Settings
- Nếu không cấu hình, mã xác nhận sẽ hiển thị trong server logs

## 📋 Tài khoản mặc định

| Vai trò | Email | Mật khẩu |
|---------|-------|-----------|
| Admin | mmh.product@manimedicalhanoi.com | 123456 |

## 📧 Email được phép đăng ký

Chỉ các email nội bộ sau được phép:
- tt.tuyen@manimedicalhanoi.com
- nt.ha@manimedicalhanoi.com
- marketing.mmh@manimedicalhanoi.com
- marketing.mmh2@manimedicalhanoi.com
- marketing.mmh1@manimedicalhanoi.com
- mmh.product@manimedicalhanoi.com
- mmh.admin@manimedicalhanoi.com
- mmh.danang@manimedicalhanoi.com
- mmh.hanoi@manimedicalhanoi.com
- mmh.saigon@manimedicalhanoi.com
- mmh.hanoi2@manimedicalhanoi.com
- vtt.hoa@manimedicalhanoi.com
- ntt.hang@manimedicalhanoi.com
- mmh.order@manimedicalhanoi.com
- mmh.backoffice@manimedicalhanoi.com

## ✨ Tính năng

### Học viên (Learner)
- Xem video bài giảng (YouTube embed)
- Đọc tài liệu PDF
- Làm bài kiểm tra trắc nghiệm
- Tải chứng chỉ PDF khi đạt
- Xem lịch sử học tập

### Admin / Trainer
- Quản lý người dùng & phân quyền
- Tạo/sửa/xóa khóa học
- Upload câu hỏi CSV hoặc tạo thủ công
- Set điểm đạt, deadline, phòng ban đối tượng
- Thống kê theo phòng ban
- Xuất báo cáo CSV

## 🛠 Chạy Local

```bash
pip install -r requirements.txt
python app.py
# Mở http://localhost:5000
```

## 📁 Cấu trúc

```
mani-lms/
├── app.py              # Flask application
├── requirements.txt    # Python dependencies
├── Procfile           # Deployment config
├── render.yaml        # Render.com config
└── templates/         # HTML templates
    ├── base.html
    ├── login.html
    ├── register.html
    ├── verify.html
    ├── dashboard.html
    ├── course_detail.html
    ├── quiz.html
    ├── quiz_result.html
    ├── certificate.html
    ├── my_certs.html
    ├── admin.html
    ├── course_form.html
    ├── questions.html
    └── analytics.html
```
