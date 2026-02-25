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
import base64
import traceback
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
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
    "mmh.saigon@manimedicalhanoi.com",
    "ntt.hang@manimedicalhanoi.com",
    "mmh.order@manimedicalhanoi.com",
    "mmh.backoffice@manimedicalhanoi.com",
]

DEPARTMENTS = ["Sales", "Marketing", "Back Office", "R&D", "QA/QC", "Management", "Production"]
CATEGORIES = ["Compliance", "SOP", "Product Training", "Skills Training", "Education"]

# ─────────── SMTP CONFIG ───────────
SMTP_SERVER = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
SMTP_PORT = int(os.environ.get('SMTP_PORT', '587'))
SMTP_USER = os.environ.get('SMTP_USER', '')
SMTP_PASS = os.environ.get('SMTP_PASS', '')
SMTP_FROM = os.environ.get('SMTP_FROM', '')


# ─────────── DATABASE ───────────
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop('db', None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row

    # Create tables
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
            quiz_count INTEGER DEFAULT 0,
            time_limit INTEGER DEFAULT 15,
            max_attempts INTEGER DEFAULT 3,
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
            source TEXT DEFAULT 'manual',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
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
            attempt_number INTEGER DEFAULT 1,
            is_valid INTEGER DEFAULT 1,
            completed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (course_id) REFERENCES courses(id)
        );
        CREATE TABLE IF NOT EXISTS retest_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            course_id INTEGER NOT NULL,
            target_type TEXT DEFAULT 'all',
            target_value TEXT,
            requested_by TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (course_id) REFERENCES courses(id)
        );
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        );
    ''')

    # Add columns if missing (migration-safe)
    existing_cols_courses = [r[1] for r in db.execute("PRAGMA table_info(courses)").fetchall()]
    if 'quiz_count' not in existing_cols_courses:
        db.execute("ALTER TABLE courses ADD COLUMN quiz_count INTEGER DEFAULT 0")
    if 'max_attempts' not in existing_cols_courses:
        db.execute("ALTER TABLE courses ADD COLUMN max_attempts INTEGER DEFAULT 3")

    existing_cols_questions = [r[1] for r in db.execute("PRAGMA table_info(questions)").fetchall()]
    if 'source' not in existing_cols_questions:
        db.execute("ALTER TABLE questions ADD COLUMN source TEXT DEFAULT 'manual'")
    if 'created_at' not in existing_cols_questions:
        db.execute("ALTER TABLE questions ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP")

    existing_cols_results = [r[1] for r in db.execute("PRAGMA table_info(results)").fetchall()]
    if 'attempt_number' not in existing_cols_results:
        db.execute("ALTER TABLE results ADD COLUMN attempt_number INTEGER DEFAULT 1")
    if 'is_valid' not in existing_cols_results:
        db.execute("ALTER TABLE results ADD COLUMN is_valid INTEGER DEFAULT 1")

    # Create retest_requests table if missing
    db.execute('''CREATE TABLE IF NOT EXISTS retest_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        course_id INTEGER NOT NULL,
        target_type TEXT DEFAULT 'all',
        target_value TEXT,
        requested_by TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')

    # Create default admin
    admin_exists = db.execute("SELECT id FROM users WHERE email=?",
                              ("mmh.product@manimedicalhanoi.com",)).fetchone()
    if not admin_exists:
        db.execute(
            "INSERT INTO users (email, password_hash, name, department, role, verified) VALUES (?,?,?,?,?,?)",
            ("mmh.product@manimedicalhanoi.com", hash_password("123456"),
             "Admin MMH", "Management", "admin", 1)
        )

    # Create sample course if empty
    sample = db.execute("SELECT id FROM courses LIMIT 1").fetchone()
    if not sample:
        db.execute(
            '''INSERT INTO courses (title_vi, title_en, desc_vi, desc_en, category,
               video_url, target_groups, deadline, pass_score, quiz_count, time_limit, max_attempts, created_by)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)''',
            ("Quy định An toàn Lao động", "Workplace Safety Regulations",
             "Khóa học về các quy định an toàn lao động cơ bản tại nhà máy MANI.",
             "Training on basic workplace safety regulations at MANI factory.",
             "Compliance", "https://www.youtube.com/embed/dQw4w9WgXcQ",
             json.dumps(["Sales", "Marketing", "Back Office", "Production"]),
             "2026-04-30", 3, 4, 15, 3, "mmh.product@manimedicalhanoi.com")
        )
        cid = db.execute("SELECT last_insert_rowid()").fetchone()[0]
        sample_qs = [
            ("Khi phát hiện sự cố cháy nổ, bước đầu tiên cần làm là gì?",
             "Chạy ra ngoài ngay", "Bấm chuông báo cháy", "Gọi điện cho bạn bè",
             "Tiếp tục làm việc", "b", "Bấm chuông báo cháy để thông báo cho toàn bộ nhân viên.", "sample"),
            ("Thiết bị bảo hộ cá nhân (PPE) bắt buộc tại khu vực sản xuất gồm?",
             "Mũ bảo hiểm và giày", "Chỉ cần găng tay", "Mũ, kính, găng tay, giày bảo hộ",
             "Không cần PPE", "c", "Khu vực sản xuất yêu cầu đầy đủ PPE.", "sample"),
            ("Tần suất kiểm tra thiết bị an toàn là?",
             "1 năm/lần", "6 tháng/lần", "Mỗi tháng",
             "Khi nào hỏng mới kiểm tra", "c", "Thiết bị an toàn cần được kiểm tra hàng tháng.", "sample"),
            ("Ai chịu trách nhiệm chính về an toàn tại nơi làm việc?",
             "Chỉ ban quản lý", "Chỉ bộ phận an toàn", "Mọi nhân viên",
             "Khách hàng", "c", "Mọi nhân viên đều có trách nhiệm về an toàn.", "sample"),
        ]
        for q in sample_qs:
            db.execute(
                '''INSERT INTO questions (course_id, text, option_a, option_b, option_c, option_d, answer, explanation, source)
                   VALUES (?,?,?,?,?,?,?,?,?)''', (cid, *q))

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


def generate_code():
    return ''.join(random.choices(string.digits, k=6))


def send_email(to_email, subject, html_body):
    """Send email. Returns True on success, False on failure."""
    sender = SMTP_FROM or SMTP_USER
    if not SMTP_USER or not SMTP_PASS or not sender:
        print(f"[EMAIL-MOCK] To: {to_email} | Subject: {subject}")
        print(f"[EMAIL-MOCK] SMTP not configured. Set SMTP_USER, SMTP_PASS, SMTP_FROM env vars.")
        return False
    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = sender
        msg['To'] = to_email
        msg.attach(MIMEText(html_body, 'html'))
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=15) as s:
            s.ehlo()
            s.starttls()
            s.ehlo()
            s.login(SMTP_USER, SMTP_PASS)
            s.send_message(msg)
        print(f"[EMAIL-OK] Sent to {to_email}: {subject}")
        return True
    except Exception as e:
        print(f"[EMAIL-ERROR] Failed to send to {to_email}: {e}")
        traceback.print_exc()
        return False


def send_verification_email(to_email, code):
    html = f"""
    <div style="font-family:Arial,sans-serif;max-width:500px;margin:0 auto;padding:20px;">
        <div style="background:#003047;padding:20px;text-align:center;border-radius:10px 10px 0 0;">
            <h2 style="color:#FFE100;margin:0;">MANI Learning Hub</h2>
        </div>
        <div style="background:#fff;padding:30px;border:1px solid #eee;border-radius:0 0 10px 10px;">
            <p>Xin chào / Hello,</p>
            <p>Mã xác nhận đăng ký / Your verification code:</p>
            <div style="background:#F2F2F2;padding:20px;text-align:center;border-radius:8px;margin:20px 0;">
                <span style="font-size:32px;font-weight:bold;color:#003047;letter-spacing:8px;">{code}</span>
            </div>
            <p style="color:#888;font-size:13px;">Mã có hiệu lực 30 phút / Valid for 30 minutes.</p>
            <p style="color:#888;font-size:12px;">— MANI Medical Hanoi</p>
        </div>
    </div>"""
    result = send_email(to_email, 'MANI Learning Hub - Xác nhận đăng ký / Verify Registration', html)
    if not result:
        print(f"[VERIFY-CODE] Email: {to_email} | Code: {code}")
    return result


def send_certificate_email(to_email, user_name, course_title, score, total, date_str):
    html = f"""
    <div style="font-family:Arial,sans-serif;max-width:500px;margin:0 auto;padding:20px;">
        <div style="background:#003047;padding:20px;text-align:center;border-radius:10px 10px 0 0;">
            <h2 style="color:#FFE100;margin:0;">🏆 MANI Learning Hub</h2>
        </div>
        <div style="background:#fff;padding:30px;border:1px solid #eee;border-radius:0 0 10px 10px;">
            <h3 style="color:#003047;">Chúc mừng {user_name}!</h3>
            <p>Bạn đã hoàn thành khóa đào tạo:</p>
            <div style="background:#F2F2F2;padding:16px;border-radius:8px;margin:16px 0;border-left:4px solid #FFE100;">
                <strong style="color:#003047;font-size:18px;">{course_title}</strong><br>
                <span style="color:#28A745;font-weight:bold;">Điểm: {score}/{total} ✓</span>
            </div>
            <p>Ngày hoàn thành: {date_str}</p>
            <p>Bạn có thể tải chứng chỉ từ hệ thống MANI Learning Hub.</p>
            <p style="color:#888;font-size:12px;">— MANI Medical Hanoi</p>
        </div>
    </div>"""
    return send_email(to_email, f'🏆 Chứng chỉ hoàn thành: {course_title}', html)


def send_reminder_email(to_email, user_name, course_title, message_text, sender_name):
    html = f"""
    <div style="font-family:Arial,sans-serif;max-width:500px;margin:0 auto;padding:20px;">
        <div style="background:#003047;padding:20px;text-align:center;border-radius:10px 10px 0 0;">
            <h2 style="color:#FFE100;margin:0;">📢 MANI Learning Hub</h2>
        </div>
        <div style="background:#fff;padding:30px;border:1px solid #eee;border-radius:0 0 10px 10px;">
            <p>Xin chào <strong>{user_name}</strong>,</p>
            <div style="background:#fff3cd;padding:16px;border-radius:8px;margin:16px 0;border-left:4px solid #FFE100;">
                <strong style="color:#003047;">{course_title}</strong><br>
                <p style="margin:8px 0 0;color:#555;">{message_text}</p>
            </div>
            <p style="color:#888;font-size:12px;">Gửi bởi: {sender_name}<br>— MANI Medical Hanoi</p>
        </div>
    </div>"""
    return send_email(to_email, f'📢 Nhắc nhở: {course_title} - MANI Learning Hub', html)


def get_user_attempt_info(email, course_id):
    """Get attempt count and status for a user on a course."""
    db = get_db()
    valid_results = db.execute(
        "SELECT * FROM results WHERE user_email=? AND course_id=? AND is_valid=1 ORDER BY completed_at DESC",
        (email, course_id)).fetchall()
    has_passed = any(r['passed'] for r in valid_results)
    attempt_count = len(valid_results)

    # Check for retest request
    has_retest = db.execute(
        """SELECT r.id FROM retest_requests r WHERE r.course_id=? AND
           ((r.target_type='individual' AND r.target_value=?) OR
            r.target_type='all' OR
            (r.target_type='department' AND r.target_value=(SELECT department FROM users WHERE email=?)))
           AND r.created_at > COALESCE((SELECT MAX(completed_at) FROM results WHERE user_email=? AND course_id=? AND is_valid=1), '2000-01-01')
        """, (course_id, email, email, email, course_id)).fetchone()

    return {
        'attempt_count': attempt_count,
        'has_passed': has_passed,
        'has_retest_request': has_retest is not None,
        'results': valid_results
    }


# ─────────── JINJA HELPERS ───────────
@app.context_processor
def inject_globals():
    return {
        'now': datetime.now().strftime('%Y-%m-%d'),
        'categories': CATEGORIES
    }


@app.template_filter('from_json')
def from_json_filter(s):
    try:
        return json.loads(s) if s else []
    except Exception:
        return []


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
            if user['status'] == 'inactive':
                flash('Tài khoản đã bị vô hiệu hóa. Liên hệ Admin.', 'error')
                return render_template('login.html')
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
        existing = db.execute("SELECT id, verified FROM users WHERE email=?", (email,)).fetchone()
        if existing:
            if existing['verified']:
                flash('Email đã được đăng ký. / Email already registered.', 'error')
            else:
                flash('Email đã đăng ký nhưng chưa xác nhận. / Already registered, please verify.', 'warning')
                return redirect(url_for('verify', email=email))
            return render_template('register.html', departments=DEPARTMENTS)

        if not name or not password or len(password) < 4:
            flash('Vui lòng điền đầy đủ. Mật khẩu ít nhất 4 ký tự.', 'error')
            return render_template('register.html', departments=DEPARTMENTS)

        code = generate_code()
        db.execute(
            "INSERT INTO users (email, password_hash, name, department, role, verified, verify_code) VALUES (?,?,?,?,?,?,?)",
            (email, hash_password(password), name, department, 'learner', 0, code))
        db.commit()

        email_sent = send_verification_email(email, code)
        if email_sent:
            flash(f'Mã xác nhận đã được gửi đến {email}. / Verification code sent!', 'success')
        else:
            flash(f'Mã xác nhận: {code} (Email chưa được cấu hình, liên hệ Admin). / Code: {code}', 'warning')
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
        email_sent = send_verification_email(email, code)
        if email_sent:
            flash('Đã gửi lại mã xác nhận. / Code resent!', 'success')
        else:
            flash(f'Mã xác nhận: {code} (Liên hệ Admin nếu không nhận được email).', 'warning')
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
    my_results = db.execute("SELECT * FROM results WHERE user_email=? AND is_valid=1",
                            (user['email'],)).fetchall()
    passed_ids = set(r['course_id'] for r in my_results if r['passed'])

    visible = []
    for c in courses:
        groups = json.loads(c['target_groups'] or '[]')
        if user['role'] in ('admin', 'trainer') or user['department'] in groups:
            visible.append(c)

    # Count questions per course
    q_counts = {}
    for c in visible:
        cnt = db.execute("SELECT COUNT(*) as cnt FROM questions WHERE course_id=?", (c['id'],)).fetchone()
        q_counts[c['id']] = cnt['cnt'] if cnt else 0

    return render_template('dashboard.html', user=user, courses=visible,
                           passed_ids=passed_ids, results=my_results,
                           q_counts=q_counts, categories=CATEGORIES)


# ─────────── ROUTES: BROWSE BY CATEGORY ───────────
@app.route('/category/<cat>')
@login_required
def browse_category(cat):
    user = get_current_user()
    db = get_db()
    courses = db.execute("SELECT * FROM courses WHERE category=? ORDER BY created_at DESC", (cat,)).fetchall()
    visible = []
    for c in courses:
        groups = json.loads(c['target_groups'] or '[]')
        if user['role'] in ('admin', 'trainer') or user['department'] in groups:
            visible.append(c)
    my_results = db.execute("SELECT * FROM results WHERE user_email=? AND is_valid=1",
                            (user['email'],)).fetchall()
    passed_ids = set(r['course_id'] for r in my_results if r['passed'])
    q_counts = {}
    for c in visible:
        cnt = db.execute("SELECT COUNT(*) as cnt FROM questions WHERE course_id=?", (c['id'],)).fetchone()
        q_counts[c['id']] = cnt['cnt'] if cnt else 0
    return render_template('category.html', user=user, courses=visible,
                           category=cat, passed_ids=passed_ids, q_counts=q_counts)


# ─────────── ROUTES: SEARCH ───────────
@app.route('/search')
@login_required
def search_courses():
    user = get_current_user()
    db = get_db()
    q = request.args.get('q', '').strip()
    cat = request.args.get('category', '')

    sql = "SELECT * FROM courses WHERE 1=1"
    params = []
    if q:
        sql += " AND (title_vi LIKE ? OR title_en LIKE ? OR desc_vi LIKE ? OR desc_en LIKE ?)"
        params.extend([f'%{q}%'] * 4)
    if cat:
        sql += " AND category=?"
        params.append(cat)
    sql += " ORDER BY created_at DESC"
    courses = db.execute(sql, params).fetchall()

    visible = []
    for c in courses:
        groups = json.loads(c['target_groups'] or '[]')
        if user['role'] in ('admin', 'trainer') or user['department'] in groups:
            visible.append(c)
    my_results = db.execute("SELECT * FROM results WHERE user_email=? AND is_valid=1",
                            (user['email'],)).fetchall()
    passed_ids = set(r['course_id'] for r in my_results if r['passed'])
    q_counts = {}
    for c in visible:
        cnt = db.execute("SELECT COUNT(*) as cnt FROM questions WHERE course_id=?", (c['id'],)).fetchone()
        q_counts[c['id']] = cnt['cnt'] if cnt else 0
    return render_template('search.html', user=user, courses=visible,
                           query=q, filter_cat=cat, passed_ids=passed_ids,
                           q_counts=q_counts, categories=CATEGORIES)


# ─────────── ROUTES: COURSE DETAIL ───────────
@app.route('/course/<int:cid>')
@login_required
def course_detail(cid):
    user = get_current_user()
    db = get_db()
    course = db.execute("SELECT * FROM courses WHERE id=?", (cid,)).fetchone()
    if not course:
        flash('Khóa học không tồn tại.', 'error')
        return redirect(url_for('dashboard'))
    q_count = db.execute("SELECT COUNT(*) as cnt FROM questions WHERE course_id=?", (cid,)).fetchone()['cnt']
    attempt_info = get_user_attempt_info(user['email'], cid)
    embed_url = get_youtube_embed(course['video_url'])

    # Determine if user can take quiz
    max_att = course['max_attempts'] or 3
    can_take_quiz = False
    if attempt_info['has_retest_request']:
        can_take_quiz = True
    elif not attempt_info['has_passed'] and attempt_info['attempt_count'] < max_att:
        can_take_quiz = True

    return render_template('course_detail.html', user=user, course=course,
                           q_count=q_count, attempt_info=attempt_info,
                           embed_url=embed_url, can_take_quiz=can_take_quiz,
                           max_attempts=max_att)


# ─────────── ROUTES: QUIZ ───────────
@app.route('/quiz/<int:cid>', methods=['GET', 'POST'])
@login_required
def take_quiz(cid):
    user = get_current_user()
    db = get_db()
    course = db.execute("SELECT * FROM courses WHERE id=?", (cid,)).fetchone()
    all_questions = db.execute("SELECT * FROM questions WHERE course_id=?", (cid,)).fetchall()

    if not course or not all_questions:
        flash('Không có câu hỏi cho khóa học này.', 'error')
        return redirect(url_for('course_detail', cid=cid))

    attempt_info = get_user_attempt_info(user['email'], cid)
    max_att = course['max_attempts'] or 3

    # Check if user is allowed to take quiz
    if attempt_info['has_passed'] and not attempt_info['has_retest_request']:
        flash('Bạn đã đạt bài test này rồi. / You already passed.', 'warning')
        return redirect(url_for('course_detail', cid=cid))
    if attempt_info['attempt_count'] >= max_att and not attempt_info['has_retest_request']:
        flash(f'Bạn đã hết {max_att} lượt làm bài. Liên hệ Trainer. / Max attempts reached.', 'error')
        return redirect(url_for('course_detail', cid=cid))

    # Select random questions
    quiz_count = course['quiz_count'] or len(all_questions)
    if quiz_count > len(all_questions):
        quiz_count = len(all_questions)
    if quiz_count <= 0:
        quiz_count = len(all_questions)

    if request.method == 'POST':
        # Get the question IDs from hidden fields
        q_ids = request.form.get('question_ids', '').split(',')
        questions = []
        for qid in q_ids:
            if qid.strip():
                q = db.execute("SELECT * FROM questions WHERE id=?", (int(qid.strip()),)).fetchone()
                if q:
                    questions.append(q)

        score = 0
        total = len(questions)
        answers = {}
        for q in questions:
            ans = request.form.get(f'q_{q["id"]}', '')
            answers[str(q['id'])] = ans
            if ans == q['answer']:
                score += 1
        passed = 1 if score >= (course['pass_score'] or 1) else 0

        # If retest was requested, invalidate old results
        if attempt_info['has_retest_request']:
            db.execute("UPDATE results SET is_valid=0 WHERE user_email=? AND course_id=?",
                       (user['email'], cid))

        new_attempt = (attempt_info['attempt_count'] + 1) if not attempt_info['has_retest_request'] else 1
        db.execute(
            "INSERT INTO results (user_email, course_id, score, total, passed, answers_json, attempt_number) VALUES (?,?,?,?,?,?,?)",
            (user['email'], cid, score, total, passed, json.dumps(answers), new_attempt))
        db.commit()
        rid = db.execute("SELECT last_insert_rowid()").fetchone()[0]

        # Send certificate email if passed
        if passed:
            send_certificate_email(
                user['email'], user['name'],
                course['title_vi'] or course['title_en'],
                score, total,
                datetime.now().strftime('%d/%m/%Y'))

        return redirect(url_for('quiz_result', cid=cid, rid=rid))

    # GET: Shuffle and select
    q_list = list(all_questions)
    random.shuffle(q_list)
    selected = q_list[:quiz_count]
    return render_template('quiz.html', user=user, course=course, questions=selected)


@app.route('/quiz-result/<int:cid>/<int:rid>')
@login_required
def quiz_result(cid, rid):
    user = get_current_user()
    db = get_db()
    course = db.execute("SELECT * FROM courses WHERE id=?", (cid,)).fetchone()
    result = db.execute("SELECT * FROM results WHERE id=? AND user_email=?",
                        (rid, user['email'])).fetchone()
    if not result:
        return redirect(url_for('course_detail', cid=cid))
    answers = json.loads(result['answers_json'] or '{}')
    q_ids = list(answers.keys())
    questions = []
    for qid in q_ids:
        q = db.execute("SELECT * FROM questions WHERE id=?", (int(qid),)).fetchone()
        if q:
            questions.append(q)
    attempt_info = get_user_attempt_info(user['email'], cid)
    return render_template('quiz_result.html', user=user, course=course,
                           result=result, questions=questions, answers=answers,
                           attempt_info=attempt_info)


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
    return render_template('certificate.html', user=user, course=course, result=result)


@app.route('/certificate/<int:cid>/<int:rid>/send-email', methods=['POST'])
@login_required
def send_cert_email(cid, rid):
    user = get_current_user()
    db = get_db()
    course = db.execute("SELECT * FROM courses WHERE id=?", (cid,)).fetchone()
    result = db.execute("SELECT * FROM results WHERE id=? AND user_email=? AND passed=1",
                        (rid, user['email'])).fetchone()
    if course and result:
        sent = send_certificate_email(
            user['email'], user['name'],
            course['title_vi'] or course['title_en'],
            result['score'], result['total'],
            result['completed_at'][:10] if result['completed_at'] else '')
        if sent:
            flash('Chứng chỉ đã được gửi đến email của bạn! / Certificate sent to your email!', 'success')
        else:
            flash('Không gửi được email. SMTP chưa được cấu hình. / Email sending failed.', 'error')
    return redirect(url_for('download_cert', cid=cid, rid=rid))


# ─────────── ROUTES: MY CERTS ───────────
@app.route('/my-certs')
@login_required
def my_certs():
    user = get_current_user()
    db = get_db()
    passed = db.execute(
        '''SELECT r.*, c.title_vi, c.title_en, c.category
           FROM results r JOIN courses c ON r.course_id = c.id
           WHERE r.user_email=? AND r.passed=1 AND r.is_valid=1
           ORDER BY r.completed_at DESC''',
        (user['email'],)).fetchall()
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
    results = db.execute("SELECT * FROM results WHERE is_valid=1").fetchall()
    q_counts = {}
    for c in courses:
        cnt = db.execute("SELECT COUNT(*) as cnt FROM questions WHERE course_id=?", (c['id'],)).fetchone()
        q_counts[c['id']] = cnt['cnt'] if cnt else 0
    total_users = len([u for u in users if u['role'] in ('learner', 'trainer')])
    total_courses = len(courses)
    total_certs = len(set(f"{r['user_email']}-{r['course_id']}" for r in results if r['passed']))
    total_attempts = len(results)
    return render_template('admin.html', user=user, users=users, courses=courses,
                           results=results, q_counts=q_counts,
                           stats={'total_users': total_users, 'total_courses': total_courses,
                                  'total_certs': total_certs, 'total_attempts': total_attempts},
                           departments=DEPARTMENTS, categories=CATEGORIES)


@app.route('/admin/user/<int:uid>/update', methods=['POST'])
@admin_required
def update_user(uid):
    db = get_db()
    current_user = get_current_user()
    role = request.form.get('role', 'learner')
    department = request.form.get('department')
    status = request.form.get('status', 'active')
    # Only admin can set admin role
    if role == 'admin' and current_user['role'] != 'admin':
        role = 'trainer'
    db.execute("UPDATE users SET role=?, department=?, status=? WHERE id=?",
               (role, department, status, uid))
    db.commit()
    flash('Cập nhật người dùng thành công! / User updated!', 'success')
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
               video_url, pdf_url, target_groups, deadline, pass_score, quiz_count, time_limit, max_attempts, created_by)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
            (request.form.get('title_vi', ''), request.form.get('title_en', ''),
             request.form.get('desc_vi', ''), request.form.get('desc_en', ''),
             request.form.get('category', 'Compliance'),
             request.form.get('video_url', ''), request.form.get('pdf_url', ''),
             json.dumps(groups), request.form.get('deadline', ''),
             int(request.form.get('pass_score', 3)),
             int(request.form.get('quiz_count', 0)),
             int(request.form.get('time_limit', 15)),
             int(request.form.get('max_attempts', 3)),
             user['email']))
        db.commit()
        cid = db.execute("SELECT last_insert_rowid()").fetchone()[0]
        flash('Khóa học đã được tạo! Hãy thêm câu hỏi. / Course created!', 'success')
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
               video_url=?, pdf_url=?, target_groups=?, deadline=?, pass_score=?,
               quiz_count=?, time_limit=?, max_attempts=? WHERE id=?''',
            (request.form.get('title_vi', ''), request.form.get('title_en', ''),
             request.form.get('desc_vi', ''), request.form.get('desc_en', ''),
             request.form.get('category', 'Compliance'),
             request.form.get('video_url', ''), request.form.get('pdf_url', ''),
             json.dumps(groups), request.form.get('deadline', ''),
             int(request.form.get('pass_score', 3)),
             int(request.form.get('quiz_count', 0)),
             int(request.form.get('time_limit', 15)),
             int(request.form.get('max_attempts', 3)), cid))
        db.commit()
        flash('Cập nhật thành công! / Updated!', 'success')
        return redirect(url_for('admin_panel') + '#content')
    q_count = db.execute("SELECT COUNT(*) as cnt FROM questions WHERE course_id=?", (cid,)).fetchone()['cnt']
    return render_template('course_form.html', user=user, course=course,
                           departments=DEPARTMENTS, categories=CATEGORIES, q_count=q_count)


@app.route('/admin/course/<int:cid>/delete', methods=['POST'])
@admin_required
def delete_course(cid):
    db = get_db()
    db.execute("DELETE FROM questions WHERE course_id=?", (cid,))
    db.execute("DELETE FROM results WHERE course_id=?", (cid,))
    db.execute("DELETE FROM retest_requests WHERE course_id=?", (cid,))
    db.execute("DELETE FROM courses WHERE id=?", (cid,))
    db.commit()
    flash('Đã xóa khóa học. / Course deleted.', 'success')
    return redirect(url_for('admin_panel') + '#content')


# ─────────── ROUTES: QUESTIONS MANAGEMENT ───────────
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
                '''INSERT INTO questions (course_id, text, option_a, option_b, option_c, option_d, answer, explanation, source)
                   VALUES (?,?,?,?,?,?,?,?,?)''',
                (cid, request.form.get('text'), request.form.get('option_a'),
                 request.form.get('option_b'), request.form.get('option_c', ''),
                 request.form.get('option_d', ''), request.form.get('answer', 'a'),
                 request.form.get('explanation', ''), 'manual'))
            db.commit()
            flash('Đã thêm câu hỏi! / Question added!', 'success')

        elif action == 'csv':
            csv_text = request.form.get('csv_data', '')
            count = 0
            for line in csv_text.strip().split('\n'):
                if not line.strip():
                    continue
                parts = [p.strip() for p in line.split('|')]
                if len(parts) >= 6:
                    ans_raw = parts[5].strip().lower()
                    if ans_raw not in ('a', 'b', 'c', 'd'):
                        ans_raw = 'a'
                    db.execute(
                        '''INSERT INTO questions (course_id, text, option_a, option_b, option_c, option_d, answer, explanation, source)
                           VALUES (?,?,?,?,?,?,?,?,?)''',
                        (cid, parts[0], parts[1], parts[2],
                         parts[3] if len(parts) > 3 else '',
                         parts[4] if len(parts) > 4 else '',
                         ans_raw,
                         parts[6] if len(parts) > 6 else '', 'csv'))
                    count += 1
            db.commit()
            if count > 0:
                flash(f'Đã import {count} câu hỏi từ CSV! / {count} questions imported!', 'success')
            else:
                flash('Không tìm thấy câu hỏi hợp lệ trong CSV. Kiểm tra lại định dạng (dùng dấu | ngăn cách).', 'error')

        elif action == 'csv_file':
            file = request.files.get('csv_file')
            if file and file.filename:
                try:
                    content = file.read().decode('utf-8-sig')
                    count = 0
                    for line in content.strip().split('\n'):
                        if not line.strip():
                            continue
                        parts = [p.strip() for p in line.split('|')]
                        if len(parts) >= 6:
                            ans_raw = parts[5].strip().lower()
                            if ans_raw not in ('a', 'b', 'c', 'd'):
                                ans_raw = 'a'
                            db.execute(
                                '''INSERT INTO questions (course_id, text, option_a, option_b, option_c, option_d, answer, explanation, source)
                                   VALUES (?,?,?,?,?,?,?,?,?)''',
                                (cid, parts[0], parts[1], parts[2],
                                 parts[3] if len(parts) > 3 else '',
                                 parts[4] if len(parts) > 4 else '',
                                 ans_raw,
                                 parts[6] if len(parts) > 6 else '', 'csv'))
                            count += 1
                    db.commit()
                    if count > 0:
                        flash(f'Đã import {count} câu hỏi từ file! / {count} questions imported!', 'success')
                    else:
                        flash('File không chứa câu hỏi hợp lệ. Kiểm tra lại định dạng.', 'error')
                except Exception as e:
                    flash(f'Lỗi đọc file: {str(e)}', 'error')
            else:
                flash('Vui lòng chọn file CSV.', 'error')

        elif action == 'delete':
            qid = request.form.get('question_id')
            db.execute("DELETE FROM questions WHERE id=? AND course_id=?", (qid, cid))
            db.commit()
            flash('Đã xóa câu hỏi. / Question deleted.', 'success')

        elif action == 'update_settings':
            quiz_count = int(request.form.get('quiz_count', 0))
            pass_score = int(request.form.get('pass_score', 3))
            max_attempts = int(request.form.get('max_attempts', 3))
            db.execute("UPDATE courses SET quiz_count=?, pass_score=?, max_attempts=? WHERE id=?",
                       (quiz_count, pass_score, max_attempts, cid))
            db.commit()
            flash('Cập nhật cài đặt bài thi thành công! / Quiz settings updated!', 'success')

        return redirect(url_for('manage_questions', cid=cid))

    questions = db.execute("SELECT * FROM questions WHERE course_id=? ORDER BY created_at ASC", (cid,)).fetchall()
    return render_template('questions.html', user=user, course=course, questions=questions)


# ─────────── ROUTES: RETEST / SEND REMINDERS ───────────
@app.route('/admin/course/<int:cid>/retest', methods=['POST'])
@admin_required
def request_retest(cid):
    user = get_current_user()
    db = get_db()
    target_type = request.form.get('target_type', 'all')
    target_value = request.form.get('target_value', '')

    db.execute("INSERT INTO retest_requests (course_id, target_type, target_value, requested_by) VALUES (?,?,?,?)",
               (cid, target_type, target_value, user['email']))
    db.commit()

    course = db.execute("SELECT * FROM courses WHERE id=?", (cid,)).fetchone()
    course_title = course['title_vi'] or course['title_en'] if course else 'Unknown'

    # Find affected users and send emails
    sent_count = 0
    if target_type == 'all':
        targets = db.execute("SELECT * FROM users WHERE role IN ('learner','trainer') AND verified=1 AND status='active'").fetchall()
    elif target_type == 'department':
        targets = db.execute("SELECT * FROM users WHERE department=? AND verified=1 AND status='active'", (target_value,)).fetchall()
    elif target_type == 'individual':
        targets = db.execute("SELECT * FROM users WHERE email=? AND verified=1", (target_value,)).fetchall()
    else:
        targets = []

    for t in targets:
        sent = send_reminder_email(
            t['email'], t['name'], course_title,
            'Bạn được yêu cầu làm lại bài test / You are required to retake this test.',
            user['name'])
        if sent:
            sent_count += 1

    flash(f'Đã gửi yêu cầu làm test lại cho {len(targets)} người ({sent_count} email gửi thành công). / Retest requested!', 'success')
    return redirect(url_for('manage_questions', cid=cid))


@app.route('/admin/send-reminder', methods=['POST'])
@admin_required
def send_reminder():
    user = get_current_user()
    db = get_db()
    course_id = request.form.get('course_id')
    target_type = request.form.get('target_type', 'all')
    target_value = request.form.get('target_value', '')
    message = request.form.get('message', 'Vui lòng hoàn thành bài đào tạo và bài test.')

    course = db.execute("SELECT * FROM courses WHERE id=?", (course_id,)).fetchone()
    if not course:
        flash('Khóa học không tồn tại.', 'error')
        return redirect(url_for('admin_panel'))

    course_title = course['title_vi'] or course['title_en']

    if target_type == 'all':
        targets = db.execute("SELECT * FROM users WHERE role IN ('learner','trainer') AND verified=1 AND status='active'").fetchall()
    elif target_type == 'department':
        targets = db.execute("SELECT * FROM users WHERE department=? AND verified=1 AND status='active'", (target_value,)).fetchall()
    elif target_type == 'individual':
        targets = db.execute("SELECT * FROM users WHERE email=? AND verified=1", (target_value,)).fetchall()
    else:
        targets = []

    sent_count = 0
    for t in targets:
        sent = send_reminder_email(t['email'], t['name'], course_title, message, user['name'])
        if sent:
            sent_count += 1

    flash(f'Đã gửi nhắc nhở cho {len(targets)} người ({sent_count} email thành công). / Reminders sent!', 'success')
    return redirect(request.referrer or url_for('admin_panel'))


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
           WHERE r.is_valid=1
           ORDER BY r.completed_at DESC''').fetchall()

    dept_stats = {}
    for dept in DEPARTMENTS:
        dept_users = [u for u in users_all if u['department'] == dept and u['role'] in ('learner', 'trainer')]
        dept_results = [r for r in results if r['department'] == dept]
        dept_passed = [r for r in dept_results if r['passed']]
        total_att = len(dept_results)
        dept_stats[dept] = {
            'users': len(dept_users), 'attempts': total_att,
            'passed': len(dept_passed),
            'rate': round(len(dept_passed) / total_att * 100) if total_att > 0 else 0
        }

    return render_template('analytics.html', user=user, results=results,
                           dept_stats=dept_stats, users_all=users_all, courses=courses,
                           departments=DEPARTMENTS)


@app.route('/admin/export-csv')
@admin_required
def export_csv():
    db = get_db()
    results = db.execute(
        '''SELECT r.*, u.name, u.department, c.title_vi, c.title_en
           FROM results r
           LEFT JOIN users u ON r.user_email = u.email
           LEFT JOIN courses c ON r.course_id = c.id
           WHERE r.is_valid=1
           ORDER BY r.completed_at DESC''').fetchall()
    output = io.StringIO()
    output.write('\ufeff')
    writer = csv.writer(output)
    writer.writerow(['Name', 'Email', 'Department', 'Course', 'Score', 'Total', 'Passed', 'Attempt', 'Date'])
    for r in results:
        writer.writerow([r['name'], r['user_email'], r['department'],
                         r['title_vi'] or r['title_en'], r['score'], r['total'],
                         'Yes' if r['passed'] else 'No', r['attempt_number'] or 1,
                         r['completed_at']])
    output.seek(0)
    return make_response(output.getvalue(), 200,
                         {'Content-Type': 'text/csv; charset=utf-8',
                          'Content-Disposition': f'attachment; filename=training_report_{datetime.now().strftime("%Y%m%d")}.csv'})


# ─────────── INIT ───────────
@app.context_processor
def inject_now():
    return {'now': datetime.now().strftime('%Y-%m-%d')}


@app.template_filter('from_json')
def from_json_filter(s):
    try:
        return json.loads(s) if s else []
    except Exception:
        return []


with app.app_context():
    init_db()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('DEBUG', 'false').lower() == 'true'
    app.run(host='0.0.0.0', port=port, debug=debug)
