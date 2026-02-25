import os
import sqlite3
import hashlib
import secrets
import json
import csv
import io
import smtplib
import random
import string
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from functools import wraps
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, jsonify, send_file, g, make_response
)

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.permanent_session_lifetime = timedelta(days=7)

DATABASE = os.environ.get('DATABASE_PATH', 'lms.db')

# ─────────── WHITELISTED EMAILS ───────────
ALLOWED_EMAILS = [
    "tt.tuyen@manimedicalhanoi.com",
    "nt.ha@manimedicalhanoi.com",
    "marketing.mmh@manimedicalhanoi.com",
    "marketing.mmh2@manimedicalhanoi.com",
    "marketing.mmh1@manimedicalhanoi.com",
    "mmh.product@manimedicalhanoi.com",
    "mmh.admin@manimedicalhanoi.com",
    "mmh.danang@manimedicalhanoi.com",
    "mmh.hanoi@manimedicalhanoi.com",
    "mmh.saigon@manimedicalhanoi.com",
    "mmh.hanoi2@manimedicalhanoi.com",
    "vtt.hoa@manimedicalhanoi.com",
    "ntt.hang@manimedicalhanoi.com",
    "mmh.order@manimedicalhanoi.com",
    "mmh.backoffice@manimedicalhanoi.com",
]

DEPARTMENTS = ["Sales", "Marketing", "Back Office", "R&D", "QA/QC", "Management", "Production"]
CATEGORIES = ["Compliance", "SOP", "Product Training", "Skills Training", "Education"]

# ─────────── SMTP CONFIG (env-based) ───────────
SMTP_SERVER = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
SMTP_PORT = int(os.environ.get('SMTP_PORT', 587))
SMTP_USER = os.environ.get('SMTP_USER', '')
SMTP_PASS = os.environ.get('SMTP_PASS', '')
SMTP_FROM = os.environ.get('SMTP_FROM', 'noreply@manimedicalhanoi.com')


# ─────────── DATABASE ───────────
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
    return g.db

@app.teardown_appcontext
def close_db(exc):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    db.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            name TEXT NOT NULL,
            department TEXT DEFAULT 'Sales',
            role TEXT DEFAULT 'learner',
            status TEXT DEFAULT 'active',
            verified INTEGER DEFAULT 0,
            verify_code TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS courses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title_vi TEXT NOT NULL,
            title_en TEXT,
            desc_vi TEXT,
            desc_en TEXT,
            category TEXT DEFAULT 'Compliance',
            video_url TEXT,
            pdf_url TEXT,
            target_groups TEXT DEFAULT '[]',
            deadline TEXT,
            pass_score INTEGER DEFAULT 3,
            time_limit INTEGER DEFAULT 15,
            lang TEXT DEFAULT 'vi',
            created_by TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS questions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            course_id INTEGER NOT NULL,
            text TEXT NOT NULL,
            option_a TEXT NOT NULL,
            option_b TEXT NOT NULL,
            option_c TEXT,
            option_d TEXT,
            answer TEXT NOT NULL,
            explanation TEXT,
            FOREIGN KEY (course_id) REFERENCES courses(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_email TEXT NOT NULL,
            course_id INTEGER NOT NULL,
            score INTEGER NOT NULL,
            total INTEGER NOT NULL,
            passed INTEGER DEFAULT 0,
            answers_json TEXT,
            completed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (course_id) REFERENCES courses(id)
        );
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        );
    ''')
    # Create default admin
    admin_exists = db.execute("SELECT id FROM users WHERE email=?",
                              ("mmh.product@manimedicalhanoi.com",)).fetchone()
    if not admin_exists:
        db.execute(
            "INSERT INTO users (email, password_hash, name, department, role, verified) VALUES (?,?,?,?,?,?)",
            ("mmh.product@manimedicalhanoi.com", hash_password("123456"),
             "Admin MMH", "Management", "admin", 1)
        )
    # Create sample course
    sample = db.execute("SELECT id FROM courses LIMIT 1").fetchone()
    if not sample:
        db.execute(
            '''INSERT INTO courses (title_vi, title_en, desc_vi, desc_en, category,
               video_url, target_groups, deadline, pass_score, time_limit, created_by)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)''',
            ("Quy định An toàn Lao động", "Workplace Safety Regulations",
             "Khóa học về các quy định an toàn lao động cơ bản tại nhà máy MANI.",
             "Training on basic workplace safety regulations at MANI factory.",
             "Compliance", "https://www.youtube.com/embed/dQw4w9WgXcQ",
             json.dumps(["Sales", "Marketing", "Back Office", "Production"]),
             "2026-04-30", 3, 15, "mmh.product@manimedicalhanoi.com")
        )
        cid = db.execute("SELECT last_insert_rowid()").fetchone()[0]
        sample_qs = [
            ("Khi phát hiện sự cố cháy nổ, bước đầu tiên cần làm là gì?",
             "Chạy ra ngoài ngay", "Bấm chuông báo cháy", "Gọi điện cho bạn bè",
             "Tiếp tục làm việc", "b", "Bấm chuông báo cháy để thông báo cho toàn bộ nhân viên."),
            ("Thiết bị bảo hộ cá nhân (PPE) bắt buộc tại khu vực sản xuất gồm?",
             "Mũ bảo hiểm và giày", "Chỉ cần găng tay", "Mũ, kính, găng tay, giày bảo hộ",
             "Không cần PPE", "c", "Khu vực sản xuất yêu cầu đầy đủ PPE."),
            ("Tần suất kiểm tra thiết bị an toàn là?",
             "1 năm/lần", "6 tháng/lần", "Mỗi tháng",
             "Khi nào hỏng mới kiểm tra", "c", "Thiết bị an toàn cần được kiểm tra hàng tháng."),
            ("Ai chịu trách nhiệm chính về an toàn tại nơi làm việc?",
             "Chỉ ban quản lý", "Chỉ bộ phận an toàn", "Mọi nhân viên",
             "Khách hàng", "c", "Mọi nhân viên đều có trách nhiệm về an toàn."),
        ]
        for q in sample_qs:
            db.execute(
                '''INSERT INTO questions (course_id, text, option_a, option_b, option_c, option_d, answer, explanation)
                   VALUES (?,?,?,?,?,?,?,?)''',
                (cid, *q)
            )
    db.commit()
    db.close()


# ─────────── HELPERS ───────────
def hash_password(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_email' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_email' not in session:
            return redirect(url_for('login'))
        db = get_db()
        user = db.execute("SELECT role FROM users WHERE email=?", (session['user_email'],)).fetchone()
        if not user or user['role'] not in ('admin', 'trainer'):
            flash('Bạn không có quyền truy cập trang này.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated

def get_current_user():
    if 'user_email' not in session:
        return None
    db = get_db()
    return db.execute("SELECT * FROM users WHERE email=?", (session['user_email'],)).fetchone()

def get_youtube_embed(url):
    if not url:
        return None
    if 'embed' in url:
        return url
    import re
    m = re.search(r'(?:youtube\.com/watch\?v=|youtu\.be/)([\w-]+)', url)
    return f'https://www.youtube.com/embed/{m.group(1)}' if m else url

def send_verification_email(to_email, code):
    """Send verification email. Returns True on success."""
    if not SMTP_USER or not SMTP_PASS:
        print(f"[EMAIL MOCK] Verification code for {to_email}: {code}")
        return True
    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = 'MANI Learning Hub - Xác nhận đăng ký / Verify Registration'
        msg['From'] = SMTP_FROM
        msg['To'] = to_email
        html = f"""
        <div style="font-family:Arial,sans-serif;max-width:500px;margin:0 auto;padding:20px;">
            <div style="background:#003047;padding:20px;text-align:center;border-radius:10px 10px 0 0;">
                <h2 style="color:#FFE100;margin:0;">MANI Learning Hub</h2>
            </div>
            <div style="background:#fff;padding:30px;border:1px solid #eee;border-radius:0 0 10px 10px;">
                <p>Xin chào,</p>
                <p>Mã xác nhận đăng ký của bạn là:</p>
                <div style="background:#F2F2F2;padding:20px;text-align:center;border-radius:8px;margin:20px 0;">
                    <span style="font-size:32px;font-weight:bold;color:#003047;letter-spacing:8px;">{code}</span>
                </div>
                <p>Mã này có hiệu lực trong 30 phút.</p>
                <hr style="border:none;border-top:1px solid #eee;margin:20px 0;">
                <p style="color:#888;font-size:12px;">Your verification code is: <strong>{code}</strong><br>This code expires in 30 minutes.</p>
                <p style="color:#888;font-size:12px;">— MANI Medical Hanoi</p>
            </div>
        </div>
        """
        msg.attach(MIMEText(html, 'html'))
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as s:
            s.starttls()
            s.login(SMTP_USER, SMTP_PASS)
            s.send_message(msg)
        return True
    except Exception as e:
        print(f"[EMAIL ERROR] {e}")
        return False

def generate_code():
    return ''.join(random.choices(string.digits, k=6))


# ─────────── ROUTES: AUTH ───────────
@app.route('/')
def index():
    if 'user_email' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE email=? AND password_hash=?",
                          (email, hash_password(password))).fetchone()
        if user:
            if not user['verified']:
                flash('Tài khoản chưa được xác nhận. Vui lòng kiểm tra email.', 'warning')
                return redirect(url_for('verify', email=email))
            session.permanent = True
            session['user_email'] = user['email']
            session['user_name'] = user['name']
            session['user_role'] = user['role']
            return redirect(url_for('dashboard'))
        flash('Email hoặc mật khẩu không đúng. / Invalid credentials.', 'error')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        name = request.form.get('name', '').strip()
        department = request.form.get('department', 'Sales')

        if email not in ALLOWED_EMAILS:
            flash('Email này không được phép đăng ký. Liên hệ Admin. / Email not whitelisted.', 'error')
            return render_template('register.html', departments=DEPARTMENTS)

        db = get_db()
        existing = db.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
        if existing:
            flash('Email đã được đăng ký. / Email already registered.', 'error')
            return render_template('register.html', departments=DEPARTMENTS)

        if not name or not password or len(password) < 4:
            flash('Vui lòng điền đầy đủ thông tin. Mật khẩu ít nhất 4 ký tự.', 'error')
            return render_template('register.html', departments=DEPARTMENTS)

        code = generate_code()
        db.execute(
            "INSERT INTO users (email, password_hash, name, department, role, verified, verify_code) VALUES (?,?,?,?,?,?,?)",
            (email, hash_password(password), name, department, 'learner', 0, code)
        )
        db.commit()
        send_verification_email(email, code)
        flash(f'Mã xác nhận đã được gửi đến {email}. / Verification code sent.', 'success')
        return redirect(url_for('verify', email=email))

    return render_template('register.html', departments=DEPARTMENTS)

@app.route('/verify', methods=['GET', 'POST'])
def verify():
    email = request.args.get('email', '') or request.form.get('email', '')
    if request.method == 'POST':
        code = request.form.get('code', '').strip()
        email = request.form.get('email', '').strip().lower()
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE email=? AND verify_code=?", (email, code)).fetchone()
        if user:
            db.execute("UPDATE users SET verified=1, verify_code=NULL WHERE email=?", (email,))
            db.commit()
            session.permanent = True
            session['user_email'] = user['email']
            session['user_name'] = user['name']
            session['user_role'] = user['role']
            flash('Xác nhận thành công! Chào mừng bạn. / Verified!', 'success')
            return redirect(url_for('dashboard'))
        flash('Mã xác nhận không đúng. / Invalid code.', 'error')
    return render_template('verify.html', email=email)

@app.route('/resend-code')
def resend_code():
    email = request.args.get('email', '')
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE email=? AND verified=0", (email,)).fetchone()
    if user:
        code = generate_code()
        db.execute("UPDATE users SET verify_code=? WHERE email=?", (code, email))
        db.commit()
        send_verification_email(email, code)
        flash('Đã gửi lại mã xác nhận. / Code resent.', 'success')
    return redirect(url_for('verify', email=email))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


# ─────────── ROUTES: DASHBOARD ───────────
@app.route('/dashboard')
@login_required
def dashboard():
    user = get_current_user()
    db = get_db()
    courses = db.execute("SELECT * FROM courses ORDER BY created_at DESC").fetchall()
    my_results = db.execute("SELECT * FROM results WHERE user_email=?", (user['email'],)).fetchall()
    passed_ids = set(r['course_id'] for r in my_results if r['passed'])

    # Filter courses for learner
    visible = []
    for c in courses:
        groups = json.loads(c['target_groups'] or '[]')
        if user['role'] in ('admin', 'trainer') or user['department'] in groups:
            visible.append(c)

    return render_template('dashboard.html', user=user, courses=visible,
                           passed_ids=passed_ids, results=my_results)


# ─────────── ROUTES: COURSES ───────────
@app.route('/course/<int:cid>')
@login_required
def course_detail(cid):
    user = get_current_user()
    db = get_db()
    course = db.execute("SELECT * FROM courses WHERE id=?", (cid,)).fetchone()
    if not course:
        flash('Khóa học không tồn tại.', 'error')
        return redirect(url_for('dashboard'))
    questions = db.execute("SELECT * FROM questions WHERE course_id=?", (cid,)).fetchall()
    my_results = db.execute("SELECT * FROM results WHERE user_email=? AND course_id=? ORDER BY completed_at DESC",
                            (user['email'], cid)).fetchall()
    has_passed = any(r['passed'] for r in my_results)
    embed_url = get_youtube_embed(course['video_url'])
    return render_template('course_detail.html', user=user, course=course,
                           questions=questions, results=my_results,
                           has_passed=has_passed, embed_url=embed_url)

@app.route('/quiz/<int:cid>', methods=['GET', 'POST'])
@login_required
def take_quiz(cid):
    user = get_current_user()
    db = get_db()
    course = db.execute("SELECT * FROM courses WHERE id=?", (cid,)).fetchone()
    questions = db.execute("SELECT * FROM questions WHERE course_id=?", (cid,)).fetchall()

    if not course or not questions:
        flash('Không có câu hỏi cho khóa học này.', 'error')
        return redirect(url_for('course_detail', cid=cid))

    if request.method == 'POST':
        score = 0
        total = len(questions)
        answers = {}
        for q in questions:
            ans = request.form.get(f'q_{q["id"]}', '')
            answers[str(q['id'])] = ans
            if ans == q['answer']:
                score += 1
        passed = 1 if score >= course['pass_score'] else 0
        db.execute(
            "INSERT INTO results (user_email, course_id, score, total, passed, answers_json) VALUES (?,?,?,?,?,?)",
            (user['email'], cid, score, total, passed, json.dumps(answers))
        )
        db.commit()
        return redirect(url_for('quiz_result', cid=cid, rid=db.execute("SELECT last_insert_rowid()").fetchone()[0]))

    # Shuffle questions
    q_list = list(questions)
    random.shuffle(q_list)
    return render_template('quiz.html', user=user, course=course, questions=q_list)

@app.route('/quiz-result/<int:cid>/<int:rid>')
@login_required
def quiz_result(cid, rid):
    user = get_current_user()
    db = get_db()
    course = db.execute("SELECT * FROM courses WHERE id=?", (cid,)).fetchone()
    result = db.execute("SELECT * FROM results WHERE id=? AND user_email=?", (rid, user['email'])).fetchone()
    questions = db.execute("SELECT * FROM questions WHERE course_id=?", (cid,)).fetchall()
    if not result:
        return redirect(url_for('course_detail', cid=cid))
    answers = json.loads(result['answers_json'] or '{}')
    return render_template('quiz_result.html', user=user, course=course,
                           result=result, questions=questions, answers=answers)


# ─────────── ROUTES: CERTIFICATE ───────────
@app.route('/certificate/<int:cid>/<int:rid>')
@login_required
def download_cert(cid, rid):
    user = get_current_user()
    db = get_db()
    course = db.execute("SELECT * FROM courses WHERE id=?", (cid,)).fetchone()
    result = db.execute("SELECT * FROM results WHERE id=? AND user_email=? AND passed=1",
                        (rid, user['email'])).fetchone()
    if not course or not result:
        flash('Chứng chỉ không khả dụng.', 'error')
        return redirect(url_for('dashboard'))

    # Generate certificate HTML for print/save
    return render_template('certificate.html', user=user, course=course, result=result)


# ─────────── ROUTES: MY CERTS ───────────
@app.route('/my-certs')
@login_required
def my_certs():
    user = get_current_user()
    db = get_db()
    passed = db.execute(
        '''SELECT r.*, c.title_vi, c.title_en, c.category
           FROM results r JOIN courses c ON r.course_id = c.id
           WHERE r.user_email=? AND r.passed=1
           ORDER BY r.completed_at DESC''',
        (user['email'],)
    ).fetchall()
    # Deduplicate by course
    seen = set()
    unique = []
    for r in passed:
        if r['course_id'] not in seen:
            seen.add(r['course_id'])
            unique.append(r)
    return render_template('my_certs.html', user=user, certs=unique)


# ─────────── ROUTES: ADMIN ───────────
@app.route('/admin')
@admin_required
def admin_panel():
    user = get_current_user()
    db = get_db()
    users = db.execute("SELECT * FROM users ORDER BY created_at DESC").fetchall()
    courses = db.execute("SELECT * FROM courses ORDER BY created_at DESC").fetchall()
    results = db.execute("SELECT * FROM results").fetchall()
    # Stats
    total_users = len([u for u in users if u['role'] == 'learner'])
    total_courses = len(courses)
    total_certs = len(set(f"{r['user_email']}-{r['course_id']}" for r in results if r['passed']))
    total_attempts = len(results)
    return render_template('admin.html', user=user, users=users, courses=courses,
                           results=results, stats={
                               'total_users': total_users, 'total_courses': total_courses,
                               'total_certs': total_certs, 'total_attempts': total_attempts
                           }, departments=DEPARTMENTS, categories=CATEGORIES)

@app.route('/admin/user/<int:uid>/update', methods=['POST'])
@admin_required
def update_user(uid):
    db = get_db()
    role = request.form.get('role', 'learner')
    department = request.form.get('department')
    status = request.form.get('status', 'active')
    db.execute("UPDATE users SET role=?, department=?, status=? WHERE id=?",
               (role, department, status, uid))
    db.commit()
    flash('Cập nhật người dùng thành công!', 'success')
    return redirect(url_for('admin_panel') + '#users')

@app.route('/admin/course/new', methods=['GET', 'POST'])
@admin_required
def new_course():
    user = get_current_user()
    if request.method == 'POST':
        db = get_db()
        groups = request.form.getlist('target_groups')
        db.execute(
            '''INSERT INTO courses (title_vi, title_en, desc_vi, desc_en, category,
               video_url, pdf_url, target_groups, deadline, pass_score, time_limit, created_by)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)''',
            (
                request.form.get('title_vi', ''), request.form.get('title_en', ''),
                request.form.get('desc_vi', ''), request.form.get('desc_en', ''),
                request.form.get('category', 'Compliance'),
                request.form.get('video_url', ''), request.form.get('pdf_url', ''),
                json.dumps(groups), request.form.get('deadline', ''),
                int(request.form.get('pass_score', 3)),
                int(request.form.get('time_limit', 15)),
                user['email']
            )
        )
        db.commit()
        cid = db.execute("SELECT last_insert_rowid()").fetchone()[0]
        flash('Khóa học đã được tạo! Bây giờ hãy thêm câu hỏi.', 'success')
        return redirect(url_for('manage_questions', cid=cid))
    return render_template('course_form.html', user=user, course=None,
                           departments=DEPARTMENTS, categories=CATEGORIES)

@app.route('/admin/course/<int:cid>/edit', methods=['GET', 'POST'])
@admin_required
def edit_course(cid):
    user = get_current_user()
    db = get_db()
    course = db.execute("SELECT * FROM courses WHERE id=?", (cid,)).fetchone()
    if not course:
        flash('Khóa học không tồn tại.', 'error')
        return redirect(url_for('admin_panel'))
    if request.method == 'POST':
        groups = request.form.getlist('target_groups')
        db.execute(
            '''UPDATE courses SET title_vi=?, title_en=?, desc_vi=?, desc_en=?, category=?,
               video_url=?, pdf_url=?, target_groups=?, deadline=?, pass_score=?, time_limit=?
               WHERE id=?''',
            (
                request.form.get('title_vi', ''), request.form.get('title_en', ''),
                request.form.get('desc_vi', ''), request.form.get('desc_en', ''),
                request.form.get('category', 'Compliance'),
                request.form.get('video_url', ''), request.form.get('pdf_url', ''),
                json.dumps(groups), request.form.get('deadline', ''),
                int(request.form.get('pass_score', 3)),
                int(request.form.get('time_limit', 15)), cid
            )
        )
        db.commit()
        flash('Cập nhật khóa học thành công!', 'success')
        return redirect(url_for('admin_panel') + '#content')
    return render_template('course_form.html', user=user, course=course,
                           departments=DEPARTMENTS, categories=CATEGORIES)

@app.route('/admin/course/<int:cid>/delete', methods=['POST'])
@admin_required
def delete_course(cid):
    db = get_db()
    db.execute("DELETE FROM questions WHERE course_id=?", (cid,))
    db.execute("DELETE FROM results WHERE course_id=?", (cid,))
    db.execute("DELETE FROM courses WHERE id=?", (cid,))
    db.commit()
    flash('Đã xóa khóa học.', 'success')
    return redirect(url_for('admin_panel') + '#content')

@app.route('/admin/course/<int:cid>/questions', methods=['GET', 'POST'])
@admin_required
def manage_questions(cid):
    user = get_current_user()
    db = get_db()
    course = db.execute("SELECT * FROM courses WHERE id=?", (cid,)).fetchone()
    if not course:
        return redirect(url_for('admin_panel'))

    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'add':
            db.execute(
                '''INSERT INTO questions (course_id, text, option_a, option_b, option_c, option_d, answer, explanation)
                   VALUES (?,?,?,?,?,?,?,?)''',
                (cid, request.form.get('text'), request.form.get('option_a'),
                 request.form.get('option_b'), request.form.get('option_c', ''),
                 request.form.get('option_d', ''), request.form.get('answer', 'a'),
                 request.form.get('explanation', ''))
            )
            db.commit()
            flash('Đã thêm câu hỏi!', 'success')
        elif action == 'csv':
            csv_text = request.form.get('csv_data', '')
            count = 0
            for line in csv_text.strip().split('\n'):
                parts = [p.strip() for p in line.split('|')]
                if len(parts) >= 6:
                    db.execute(
                        '''INSERT INTO questions (course_id, text, option_a, option_b, option_c, option_d, answer, explanation)
                           VALUES (?,?,?,?,?,?,?,?)''',
                        (cid, parts[0], parts[1], parts[2], parts[3] if len(parts) > 3 else '',
                         parts[4] if len(parts) > 4 else '', parts[5].lower() if len(parts) > 5 else 'a',
                         parts[6] if len(parts) > 6 else '')
                    )
                    count += 1
            db.commit()
            flash(f'Đã import {count} câu hỏi từ CSV!', 'success')
        elif action == 'delete':
            qid = request.form.get('question_id')
            db.execute("DELETE FROM questions WHERE id=? AND course_id=?", (qid, cid))
            db.commit()
            flash('Đã xóa câu hỏi.', 'success')
        return redirect(url_for('manage_questions', cid=cid))

    questions = db.execute("SELECT * FROM questions WHERE course_id=?", (cid,)).fetchall()
    return render_template('questions.html', user=user, course=course, questions=questions)


# ─────────── ROUTES: ANALYTICS ───────────
@app.route('/admin/analytics')
@admin_required
def analytics():
    user = get_current_user()
    db = get_db()
    users_all = db.execute("SELECT * FROM users").fetchall()
    courses = db.execute("SELECT * FROM courses").fetchall()
    results = db.execute(
        '''SELECT r.*, u.name, u.department, c.title_vi, c.title_en, c.category
           FROM results r
           LEFT JOIN users u ON r.user_email = u.email
           LEFT JOIN courses c ON r.course_id = c.id
           ORDER BY r.completed_at DESC'''
    ).fetchall()

    # Dept stats
    dept_stats = {}
    for dept in DEPARTMENTS:
        dept_users = [u for u in users_all if u['department'] == dept and u['role'] == 'learner']
        dept_results = [r for r in results if r['department'] == dept]
        dept_passed = [r for r in dept_results if r['passed']]
        total_att = len(dept_results)
        dept_stats[dept] = {
            'users': len(dept_users),
            'attempts': total_att,
            'passed': len(dept_passed),
            'rate': round(len(dept_passed) / total_att * 100) if total_att > 0 else 0
        }

    return render_template('analytics.html', user=user, results=results,
                           dept_stats=dept_stats, users_all=users_all, courses=courses)

@app.route('/admin/export-csv')
@admin_required
def export_csv():
    db = get_db()
    results = db.execute(
        '''SELECT r.*, u.name, u.department, c.title_vi, c.title_en
           FROM results r
           LEFT JOIN users u ON r.user_email = u.email
           LEFT JOIN courses c ON r.course_id = c.id
           ORDER BY r.completed_at DESC'''
    ).fetchall()
    output = io.StringIO()
    output.write('\ufeff')  # BOM for Excel
    writer = csv.writer(output)
    writer.writerow(['Name', 'Email', 'Department', 'Course', 'Score', 'Total', 'Passed', 'Date'])
    for r in results:
        writer.writerow([r['name'], r['user_email'], r['department'],
                         r['title_vi'] or r['title_en'], r['score'], r['total'],
                         'Yes' if r['passed'] else 'No', r['completed_at']])
    output.seek(0)
    return make_response(
        output.getvalue(),
        200,
        {'Content-Type': 'text/csv; charset=utf-8',
         'Content-Disposition': f'attachment; filename=training_report_{datetime.now().strftime("%Y%m%d")}.csv'}
    )


# ─────────── INIT & RUN ───────────
@app.context_processor
def inject_now():
    return {'now': datetime.now().strftime('%Y-%m-%d')}

@app.template_filter('from_json')
def from_json_filter(s):
    try:
        return json.loads(s) if s else []
    except:
        return []

with app.app_context():
    init_db()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=os.environ.get('DEBUG', 'false').lower() == 'true')
