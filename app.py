import os
import sqlite3
import hashlib
import secrets
import json
import csv
import io
import smtplib
import ssl
import random
import string
import base64
import traceback
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from functools import wraps
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, jsonify, g, make_response
)

# ═══════════════ TURSO CLOUD DB (FREE) ═══════════════
# If TURSO_DATABASE_URL is set → use cloud DB (data never lost)
# Otherwise → fall back to local SQLite file
TURSO_URL = os.environ.get('TURSO_DATABASE_URL', '')
TURSO_TOKEN = os.environ.get('TURSO_AUTH_TOKEN', '')
USE_TURSO = bool(TURSO_URL)

try:
    import libsql_experimental as libsql
    HAVE_LIBSQL = True
except ImportError:
    HAVE_LIBSQL = False
    if USE_TURSO:
        print("[DB] WARNING: libsql-experimental not installed! pip install libsql-experimental")

DATABASE = os.environ.get('DATABASE_PATH', 'lms.db')

if USE_TURSO and HAVE_LIBSQL:
    print(f"[DB] ☁️ Using Turso cloud database: {TURSO_URL[:50]}...")
else:
    _render_disk = '/opt/render/project/data'
    if os.path.isdir(_render_disk):
        DATABASE = os.path.join(_render_disk, 'lms.db')
    print(f"[DB] 💾 Using local SQLite: {DATABASE}")

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.permanent_session_lifetime = timedelta(days=7)
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5MB

# ═══════════════ DEFAULT WHITELIST ═══════════════
DEFAULT_EMAILS = [
    "tt.tuyen@manimedicalhanoi.com", "nt.ha@manimedicalhanoi.com",
    "marketing.mmh@manimedicalhanoi.com", "marketing.mmh2@manimedicalhanoi.com",
    "marketing.mmh1@manimedicalhanoi.com", "mmh.product@manimedicalhanoi.com",
    "mmh.admin@manimedicalhanoi.com", "mmh.danang@manimedicalhanoi.com",
    "mmh.hanoi@manimedicalhanoi.com", "mmh.saigon@manimedicalhanoi.com",
    "mmh.hanoi2@manimedicalhanoi.com", "vtt.hoa@manimedicalhanoi.com",
    "ntt.hang@manimedicalhanoi.com", "mmh.order@manimedicalhanoi.com",
    "mmh.backoffice@manimedicalhanoi.com",
]

# ═══════════════ ORG STRUCTURE ═══════════════
DEPARTMENTS = ["Sales & Marketing Vietnam", "Back-office", "Management"]
TEAMS = ["N/A", "Product Team", "Marketing Team", "Dental Sales Team", "Surgical Sales Team", "Stock Team"]
JOB_TITLES = [
    "General Director", "Head of Sales & Marketing Vietnam", "Head of Back Office",
    "Product Team Leader", "Marketing Team Leader", "Designer",
    "Digital Marketing Executive", "Trade Marketing Executive",
    "Sales Representative", "Sale Team Leader",
    "Accounting & Import-Export Executive", "Purchasing & Sales Support Executive",
    "Operations & Registration Team Leader", "Operations Executive", "Stock Executive", "Other",
]
JOB_LEVELS = ["Manager", "Assistant Manager", "Senior Staff", "Staff"]
CATEGORIES = ["Compliance", "SOP", "Product Training", "Skills Training", "Education"]

# Manager per department (for certificates)
DEPT_MANAGERS = {
    "Sales & Marketing Vietnam": {
        "email": "tt.tuyen@manimedicalhanoi.com",
        "name": "Tran Thai Tuyen",
        "title": "MKT & Sales Manager"
    },
    "Back-office": {
        "email": "vtt.hoa@manimedicalhanoi.com",
        "name": "Vu Thi Thanh Hoa",
        "title": "Head of Back Office"
    },
    "Management": {
        "email": "tt.tuyen@manimedicalhanoi.com",
        "name": "Tran Thai Tuyen",
        "title": "MKT & Sales Manager"
    }
}

# ═══════════════ SMTP ═══════════════
SMTP_SERVER = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
SMTP_PORT = int(os.environ.get('SMTP_PORT', '587'))
SMTP_USER = os.environ.get('SMTP_USER', '')
SMTP_PASS = os.environ.get('SMTP_PASS', '')
SMTP_FROM = os.environ.get('SMTP_FROM', '') or SMTP_USER


# ═══════════════ DATABASE ═══════════════
def _create_connection():
    """Create DB connection - Turso cloud or local SQLite."""
    if USE_TURSO and HAVE_LIBSQL:
        conn = libsql.connect(database=TURSO_URL, auth_token=TURSO_TOKEN)
    else:
        conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def get_db():
    if 'db' not in g:
        g.db = _create_connection()
        if not USE_TURSO:
            try:
                g.db.execute("PRAGMA journal_mode=WAL")
                g.db.execute("PRAGMA foreign_keys=ON")
            except: pass
    return g.db

@app.teardown_appcontext
def close_db(exc):
    db = g.pop('db', None)
    if db:
        try: db.close()
        except: pass


def get_allowed_emails():
    try:
        db = get_db()
        rows = db.execute("SELECT email FROM allowed_emails WHERE active=1").fetchall()
        if rows: return [r['email'].lower() for r in rows]
    except: pass
    return [e.lower() for e in DEFAULT_EMAILS]


def init_db():
    db = _create_connection()
    # Create tables one by one (Turso doesn't support executescript)
    tables = [
        '''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
            name TEXT NOT NULL, department TEXT DEFAULT 'Sales & Marketing Vietnam',
            team TEXT DEFAULT 'N/A', job_title TEXT DEFAULT 'Staff',
            job_level TEXT DEFAULT 'Staff', role TEXT DEFAULT 'learner',
            status TEXT DEFAULT 'active', verified INTEGER DEFAULT 0,
            verify_code TEXT, avatar_data TEXT, signature_data TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''',
        '''CREATE TABLE IF NOT EXISTS courses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title_vi TEXT NOT NULL, title_en TEXT, desc_vi TEXT, desc_en TEXT,
            category TEXT DEFAULT 'Compliance', video_url TEXT, pdf_url TEXT,
            target_groups TEXT DEFAULT '[]', deadline TEXT,
            pass_score INTEGER DEFAULT 3, quiz_count INTEGER DEFAULT 0,
            time_limit INTEGER DEFAULT 15, max_attempts INTEGER DEFAULT 3,
            lang TEXT DEFAULT 'vi', created_by TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''',
        '''CREATE TABLE IF NOT EXISTS questions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            course_id INTEGER NOT NULL, text TEXT NOT NULL,
            option_a TEXT NOT NULL, option_b TEXT NOT NULL,
            option_c TEXT, option_d TEXT, answer TEXT NOT NULL,
            explanation TEXT, source TEXT DEFAULT 'manual',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''',
        '''CREATE TABLE IF NOT EXISTS results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_email TEXT NOT NULL, course_id INTEGER NOT NULL,
            score INTEGER NOT NULL, total INTEGER NOT NULL,
            passed INTEGER DEFAULT 0, answers_json TEXT,
            attempt_number INTEGER DEFAULT 1, is_valid INTEGER DEFAULT 1,
            completed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''',
        '''CREATE TABLE IF NOT EXISTS retest_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            course_id INTEGER NOT NULL, target_type TEXT DEFAULT 'all',
            target_value TEXT, deadline TEXT, requested_by TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''',
        '''CREATE TABLE IF NOT EXISTS allowed_emails (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL, note TEXT DEFAULT '',
            active INTEGER DEFAULT 1, added_by TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''',
        "CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)",
    ]
    for sql in tables:
        try: db.execute(sql)
        except Exception as e: print(f"[DB] Table create warning: {e}")
    db.commit()
    # Safe migrations
    def add_col(table, col, typedef):
        try:
            cols = [r[1] for r in db.execute(f"PRAGMA table_info({table})").fetchall()]
            if col not in cols:
                db.execute(f"ALTER TABLE {table} ADD COLUMN {col} {typedef}")
        except Exception as e:
            print(f"[DB] Migration warning {table}.{col}: {e}")
    add_col('users','team',"TEXT DEFAULT 'N/A'")
    add_col('users','job_title',"TEXT DEFAULT 'Staff'")
    add_col('users','job_level',"TEXT DEFAULT 'Staff'")
    add_col('users','avatar_data',"TEXT")
    add_col('users','signature_data',"TEXT")
    # Rename avatar_url to avatar_data if needed
    try:
        ucols = [r[1] for r in db.execute("PRAGMA table_info(users)").fetchall()]
        if 'avatar_url' in ucols and 'avatar_data' not in ucols:
            db.execute("ALTER TABLE users RENAME COLUMN avatar_url TO avatar_data")
    except: pass
    add_col('courses','quiz_count',"INTEGER DEFAULT 0")
    add_col('courses','max_attempts',"INTEGER DEFAULT 3")
    add_col('questions','source',"TEXT DEFAULT 'manual'")
    add_col('questions','created_at',"TIMESTAMP DEFAULT CURRENT_TIMESTAMP")
    add_col('results','attempt_number',"INTEGER DEFAULT 1")
    add_col('results','is_valid',"INTEGER DEFAULT 1")
    add_col('retest_requests','deadline',"TEXT")

    # Seed whitelist
    for em in DEFAULT_EMAILS:
        try: db.execute("INSERT OR IGNORE INTO allowed_emails (email,note,added_by) VALUES (?,?,?)", (em.lower(),'Default','system'))
        except: pass

    # Default admin
    if not db.execute("SELECT id FROM users WHERE email=?", ("mmh.product@manimedicalhanoi.com",)).fetchone():
        db.execute("INSERT INTO users (email,password_hash,name,department,team,job_title,job_level,role,verified) VALUES (?,?,?,?,?,?,?,?,?)",
            ("mmh.product@manimedicalhanoi.com", hash_password("123456"), "Admin MMH",
             "Management","Product Team","Product Team Leader","Assistant Manager","admin",1))

    # Sample course
    if not db.execute("SELECT id FROM courses LIMIT 1").fetchone():
        db.execute('''INSERT INTO courses (title_vi,title_en,desc_vi,desc_en,category,target_groups,deadline,pass_score,quiz_count,time_limit,max_attempts,created_by) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)''',
            ("Quy định An toàn Lao động","Workplace Safety Regulations",
             "Khóa học về quy định an toàn lao động.","Safety training.",
             "Compliance",json.dumps(["Sales & Marketing Vietnam","Back-office"]),
             "2026-06-30",3,4,15,3,"mmh.product@manimedicalhanoi.com"))
        cid = db.execute("SELECT last_insert_rowid()").fetchone()[0]
        for q in [("Khi phát hiện cháy nổ, bước đầu tiên?","Chạy ra ngoài","Bấm chuông báo cháy","Gọi điện bạn bè","Tiếp tục làm việc","b","Bấm chuông báo cháy."),
                  ("PPE bắt buộc tại khu vực sản xuất?","Mũ và giày","Chỉ găng tay","Mũ, kính, găng tay, giày","Không cần","c","Yêu cầu đầy đủ PPE."),
                  ("Tần suất kiểm tra thiết bị an toàn?","1 năm/lần","6 tháng/lần","Mỗi tháng","Khi hỏng","c","Kiểm tra hàng tháng."),
                  ("Ai chịu trách nhiệm an toàn?","Ban quản lý","Bộ phận an toàn","Mọi nhân viên","Khách hàng","c","Mọi nhân viên.")]:
            db.execute("INSERT INTO questions (course_id,text,option_a,option_b,option_c,option_d,answer,explanation,source) VALUES (?,?,?,?,?,?,?,?,?)",(cid,*q,"sample"))
    db.commit()
    try: db.close()
    except: pass
    db_type = "Turso Cloud" if USE_TURSO else f"Local SQLite ({DATABASE})"
    print(f"[DB] ✅ Initialized: {db_type}")


# ═══════════════ HELPERS ═══════════════
def hash_password(pw): return hashlib.sha256(pw.encode()).hexdigest()
def generate_code(): return ''.join(random.choices(string.digits, k=6))

def login_required(f):
    @wraps(f)
    def d(*a, **k):
        if 'user_email' not in session: return redirect(url_for('login'))
        return f(*a, **k)
    return d

def admin_required(f):
    @wraps(f)
    def d(*a, **k):
        if 'user_email' not in session: return redirect(url_for('login'))
        u = get_db().execute("SELECT role FROM users WHERE email=?",(session['user_email'],)).fetchone()
        if not u or u['role'] not in ('admin','trainer'):
            flash('Không có quyền.','error'); return redirect(url_for('dashboard'))
        return f(*a, **k)
    return d

def admin_only(f):
    @wraps(f)
    def d(*a, **k):
        if 'user_email' not in session: return redirect(url_for('login'))
        u = get_db().execute("SELECT role FROM users WHERE email=?",(session['user_email'],)).fetchone()
        if not u or u['role'] != 'admin':
            flash('Chỉ Admin.','error'); return redirect(url_for('dashboard'))
        return f(*a, **k)
    return d

def get_current_user():
    if 'user_email' not in session: return None
    return get_db().execute("SELECT * FROM users WHERE email=?",(session['user_email'],)).fetchone()

def get_youtube_embed(url):
    if not url: return None
    if 'embed' in url: return url
    import re
    m = re.search(r'(?:youtube\.com/watch\?v=|youtu\.be/)([\w-]+)', url)
    return f'https://www.youtube.com/embed/{m.group(1)}' if m else url


# ═══════════════ EMAIL (ROBUST) ═══════════════
def send_email(to_email, subject, html_body):
    """Send email with multiple fallbacks. Returns True on success."""
    if not SMTP_USER or not SMTP_PASS:
        print(f"[EMAIL-SKIP] SMTP not configured. To={to_email}")
        return False

    sender = SMTP_FROM or SMTP_USER
    msg = MIMEMultipart('alternative')
    msg['Subject'] = subject
    msg['From'] = sender
    msg['To'] = to_email
    msg.attach(MIMEText(html_body, 'html', 'utf-8'))

    # Method 1: STARTTLS (587)
    try:
        print(f"[EMAIL] Trying STARTTLS to {to_email}...")
        ctx = ssl.create_default_context()
        with smtplib.SMTP(SMTP_SERVER, 587, timeout=30) as s:
            s.ehlo()
            s.starttls(context=ctx)
            s.ehlo()
            s.login(SMTP_USER, SMTP_PASS)
            s.send_message(msg)
        print(f"[EMAIL-OK] Sent via STARTTLS to {to_email}")
        return True
    except Exception as e1:
        print(f"[EMAIL-TLS-FAIL] {e1}")

    # Method 2: SSL (465)
    try:
        print(f"[EMAIL] Trying SSL to {to_email}...")
        ctx = ssl.create_default_context()
        with smtplib.SMTP_SSL(SMTP_SERVER, 465, context=ctx, timeout=30) as s:
            s.login(SMTP_USER, SMTP_PASS)
            s.send_message(msg)
        print(f"[EMAIL-OK] Sent via SSL to {to_email}")
        return True
    except Exception as e2:
        print(f"[EMAIL-SSL-FAIL] {e2}")

    print(f"[EMAIL-ERROR] All methods failed for {to_email}")
    return False


def send_verification_email(to_email, code):
    html = f'''<div style="font-family:Arial;max-width:500px;margin:0 auto">
    <div style="background:#003047;padding:20px;text-align:center;border-radius:10px 10px 0 0"><h2 style="color:#FFE100;margin:0">MANI Learning Hub</h2></div>
    <div style="background:#fff;padding:30px;border:1px solid #eee;border-radius:0 0 10px 10px">
    <p>Xin chào,</p><p>Mã xác nhận:</p>
    <div style="background:#F2F2F2;padding:20px;text-align:center;border-radius:8px;margin:20px 0">
    <span style="font-size:32px;font-weight:bold;color:#003047;letter-spacing:8px">{code}</span></div>
    <p style="color:#888;font-size:12px">— MANI Medical Hanoi</p></div></div>'''
    ok = send_email(to_email, 'MANI Learning Hub - Mã xác nhận', html)
    if not ok: print(f"[CODE] {to_email} => {code}")
    return ok


def send_test_request_email(to_email, user_name, course_title, deadline, sender_name):
    html = f'''<div style="font-family:Arial;max-width:500px;margin:0 auto">
    <div style="background:#003047;padding:20px;text-align:center;border-radius:10px 10px 0 0"><h2 style="color:#FFE100;margin:0">📢 Yêu cầu hoàn thành bài kiểm tra</h2></div>
    <div style="background:#fff;padding:30px;border:1px solid #eee;border-radius:0 0 10px 10px">
    <p>Dear <strong>{user_name}</strong>,</p>
    <p>Vui lòng hoàn thành bài test về bài đào tạo:</p>
    <div style="background:#fff3cd;padding:16px;border-radius:8px;margin:16px 0;border-left:4px solid #FFE100">
    <strong style="color:#003047;font-size:18px">"{course_title}"</strong>
    <p style="margin:8px 0 0;color:#555">⏰ Deadline: <strong style="color:#DC3545">{deadline}</strong></p></div>
    <p style="color:#888;font-size:12px">Gửi bởi: {sender_name}<br>— MANI Medical Hanoi</p></div></div>'''
    return send_email(to_email, f'Yêu cầu hoàn thành bài kiểm tra: {course_title}', html)


def send_reminder_email(to_email, user_name, course_title, deadline, sender_name):
    html = f'''<div style="font-family:Arial;max-width:500px;margin:0 auto">
    <div style="background:#003047;padding:20px;text-align:center;border-radius:10px 10px 0 0"><h2 style="color:#FFE100;margin:0">📢 Nhắc nhở đào tạo</h2></div>
    <div style="background:#fff;padding:30px;border:1px solid #eee;border-radius:0 0 10px 10px">
    <p>Dear <strong>{user_name}</strong>,</p>
    <p>Vui lòng hoàn thành bài đào tạo:</p>
    <div style="background:#e8f4fd;padding:16px;border-radius:8px;margin:16px 0;border-left:4px solid #3A7595">
    <strong style="color:#003047;font-size:18px">"{course_title}"</strong>
    <p style="margin:8px 0 0;color:#555">⏰ Trước ngày: <strong style="color:#DC3545">{deadline}</strong></p></div>
    <p style="color:#888;font-size:12px">Gửi bởi: {sender_name}<br>— MANI Medical Hanoi</p></div></div>'''
    return send_email(to_email, f'Nhắc nhở hoàn thành đào tạo: {course_title}', html)


def send_certificate_email(to_email, user_name, course_title, score, total, date_str):
    html = f'''<div style="font-family:Arial;max-width:500px;margin:0 auto">
    <div style="background:#003047;padding:20px;text-align:center;border-radius:10px 10px 0 0"><h2 style="color:#FFE100;margin:0">🏆 Chứng chỉ</h2></div>
    <div style="background:#fff;padding:30px;border:1px solid #eee;border-radius:0 0 10px 10px">
    <h3 style="color:#003047">Chúc mừng {user_name}!</h3>
    <p>Hoàn thành: <strong>{course_title}</strong></p>
    <p style="color:#28A745;font-weight:bold">Điểm: {score}/{total} ✓</p>
    <p>Ngày: {date_str}</p>
    <p style="color:#888;font-size:12px">— MANI Medical Hanoi</p></div></div>'''
    return send_email(to_email, f'🏆 Chứng chỉ: {course_title}', html)


def get_user_attempt_info(email, course_id):
    db = get_db()
    valid = db.execute("SELECT * FROM results WHERE user_email=? AND course_id=? AND is_valid=1 ORDER BY completed_at DESC",
                       (email, course_id)).fetchall()
    has_passed = any(r['passed'] for r in valid)
    has_retest = db.execute(
        """SELECT id FROM retest_requests WHERE course_id=? AND
           ((target_type='individual' AND target_value=?) OR target_type='all' OR
            (target_type='department' AND target_value=(SELECT department FROM users WHERE email=?)) OR
            (target_type='team' AND target_value=(SELECT team FROM users WHERE email=?)))
           AND created_at > COALESCE((SELECT MAX(completed_at) FROM results WHERE user_email=? AND course_id=? AND is_valid=1),'2000-01-01')
        """, (course_id, email, email, email, email, course_id)).fetchone()
    return {'attempt_count':len(valid),'has_passed':has_passed,'has_retest_request':has_retest is not None,'results':valid}


def get_cert_manager(user_dept):
    """Get manager info for certificate based on user department."""
    mgr_info = DEPT_MANAGERS.get(user_dept, DEPT_MANAGERS.get("Sales & Marketing Vietnam"))
    db = get_db()
    mgr_user = db.execute("SELECT * FROM users WHERE email=?", (mgr_info['email'],)).fetchone()
    return {
        'name': mgr_info['name'],
        'title': mgr_info['title'],
        'signature_data': mgr_user['signature_data'] if mgr_user else None
    }


def get_targets(target_type, target_value):
    """Get target users based on type and value."""
    db = get_db()
    if target_type == 'department':
        return db.execute("SELECT * FROM users WHERE department=? AND verified=1 AND status='active'", (target_value,)).fetchall()
    elif target_type == 'team':
        return db.execute("SELECT * FROM users WHERE team=? AND verified=1 AND status='active'", (target_value,)).fetchall()
    elif target_type == 'individual':
        return db.execute("SELECT * FROM users WHERE email=? AND verified=1", (target_value,)).fetchall()
    else:
        return db.execute("SELECT * FROM users WHERE role IN ('learner','trainer') AND verified=1 AND status='active'").fetchall()


# ═══════════════ JINJA ═══════════════
@app.context_processor
def inject_globals():
    return {'now':datetime.now().strftime('%Y-%m-%d'),'categories':CATEGORIES,
            'DEPARTMENTS':DEPARTMENTS,'TEAMS':TEAMS,'JOB_TITLES':JOB_TITLES,'JOB_LEVELS':JOB_LEVELS}

@app.template_filter('from_json')
def from_json_filter(s):
    try: return json.loads(s) if s else []
    except: return []


# ═══════════════ AUTH ═══════════════
@app.route('/')
def index():
    return redirect(url_for('dashboard') if 'user_email' in session else url_for('login'))

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email','').strip().lower()
        pw = request.form.get('password','')
        db = get_db()
        u = db.execute("SELECT * FROM users WHERE email=? AND password_hash=?",(email,hash_password(pw))).fetchone()
        if u:
            if not u['verified']:
                flash('Chưa xác nhận.','warning'); return redirect(url_for('verify',email=email))
            if u['status'] == 'inactive':
                flash('Tài khoản bị vô hiệu hóa.','error'); return render_template('login.html')
            session.permanent = True
            session['user_email'] = u['email']; session['user_name'] = u['name']; session['user_role'] = u['role']
            session['user_avatar'] = u['avatar_data'] or ''
            return redirect(url_for('dashboard'))
        flash('Email hoặc mật khẩu không đúng.','error')
    return render_template('login.html')

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email','').strip().lower()
        pw = request.form.get('password','')
        name = request.form.get('name','').strip()
        dept = request.form.get('department',DEPARTMENTS[0])
        team = request.form.get('team','N/A')
        jt = request.form.get('job_title','Other')
        jl = request.form.get('job_level','Staff')
        if email not in get_allowed_emails():
            flash('Email không được phép đăng ký.','error'); return render_template('register.html')
        db = get_db()
        ex = db.execute("SELECT id,verified FROM users WHERE email=?",(email,)).fetchone()
        if ex:
            if ex['verified']: flash('Email đã đăng ký.','error')
            else: flash('Đã đăng ký, chưa xác nhận.','warning'); return redirect(url_for('verify',email=email))
            return render_template('register.html')
        if not name or len(pw) < 4:
            flash('Điền đủ thông tin, mật khẩu ≥ 4 ký tự.','error'); return render_template('register.html')
        code = generate_code()
        db.execute("INSERT INTO users (email,password_hash,name,department,team,job_title,job_level,role,verified,verify_code) VALUES (?,?,?,?,?,?,?,?,?,?)",
                   (email,hash_password(pw),name,dept,team,jt,jl,'learner',0,code))
        db.commit()
        ok = send_verification_email(email, code)
        flash(f'Mã đã gửi đến {email}!' if ok else f'SMTP chưa cấu hình. Mã: {code}', 'success' if ok else 'warning')
        return redirect(url_for('verify',email=email))
    return render_template('register.html')

@app.route('/verify', methods=['GET','POST'])
def verify():
    email = request.args.get('email','') or request.form.get('email','')
    if request.method == 'POST':
        code = request.form.get('code','').strip()
        email = request.form.get('email','').strip().lower()
        db = get_db()
        u = db.execute("SELECT * FROM users WHERE email=? AND verify_code=?",(email,code)).fetchone()
        if u:
            db.execute("UPDATE users SET verified=1,verify_code=NULL WHERE email=?",(email,))
            db.commit()
            session.permanent = True
            session['user_email']=u['email'];session['user_name']=u['name'];session['user_role']=u['role']
            session['user_avatar']=u['avatar_data'] or ''
            flash('Xác nhận thành công!','success'); return redirect(url_for('dashboard'))
        flash('Mã không đúng.','error')
    return render_template('verify.html',email=email)

@app.route('/resend-code')
def resend_code():
    email = request.args.get('email','')
    db = get_db()
    u = db.execute("SELECT * FROM users WHERE email=? AND verified=0",(email,)).fetchone()
    if u:
        code = generate_code()
        db.execute("UPDATE users SET verify_code=? WHERE email=?",(code,email))
        db.commit()
        ok = send_verification_email(email,code)
        flash('Đã gửi lại!' if ok else f'Mã: {code}','success' if ok else 'warning')
    return redirect(url_for('verify',email=email))

@app.route('/logout')
def logout():
    session.clear(); return redirect(url_for('login'))


# ═══════════════ PROFILE ═══════════════
@app.route('/profile', methods=['GET','POST'])
@login_required
def profile():
    user = get_current_user()
    db = get_db()
    if request.method == 'POST':
        action = request.form.get('action','update')
        if action == 'update':
            name = request.form.get('name','').strip() or user['name']
            db.execute("UPDATE users SET name=?,department=?,team=?,job_title=?,job_level=? WHERE email=?",
                       (name,request.form.get('department',user['department']),
                        request.form.get('team',user['team'] or 'N/A'),
                        request.form.get('job_title',user['job_title'] or 'Other'),
                        request.form.get('job_level',user['job_level'] or 'Staff'),user['email']))
            db.commit(); session['user_name'] = name
            flash('Cập nhật hồ sơ thành công!','success')
        elif action == 'upload_avatar':
            f = request.files.get('avatar_file')
            if f and f.filename:
                data = f.read()
                if len(data) > 2*1024*1024:
                    flash('Ảnh quá lớn (max 2MB).','error')
                else:
                    ext = f.filename.rsplit('.',1)[-1].lower()
                    mime = {'jpg':'image/jpeg','jpeg':'image/jpeg','png':'image/png','gif':'image/gif','webp':'image/webp'}.get(ext,'image/png')
                    b64 = f"data:{mime};base64,{base64.b64encode(data).decode()}"
                    db.execute("UPDATE users SET avatar_data=? WHERE email=?",(b64,user['email']))
                    db.commit(); session['user_avatar'] = b64; flash('Đã cập nhật ảnh đại diện!','success')
            else: flash('Chọn file ảnh.','error')
        elif action == 'save_signature':
            db.execute("UPDATE users SET signature_data=? WHERE email=?",(request.form.get('signature_data',''),user['email']))
            db.commit(); flash('Đã lưu chữ ký!','success')
        elif action == 'change_password':
            old_pw = request.form.get('old_password','')
            new_pw = request.form.get('new_password','')
            if hash_password(old_pw) != user['password_hash']:
                flash('Mật khẩu cũ không đúng.','error')
            elif len(new_pw) < 4:
                flash('Mật khẩu mới ≥ 4 ký tự.','error')
            else:
                db.execute("UPDATE users SET password_hash=? WHERE email=?",(hash_password(new_pw),user['email']))
                db.commit(); flash('Đổi mật khẩu thành công!','success')
        return redirect(url_for('profile'))
    return render_template('profile.html',user=get_current_user())


# ═══════════════ DASHBOARD ═══════════════
@app.route('/dashboard')
@login_required
def dashboard():
    user = get_current_user()
    db = get_db()
    courses = db.execute("SELECT * FROM courses ORDER BY created_at DESC").fetchall()
    my_results = db.execute("SELECT * FROM results WHERE user_email=? AND is_valid=1",(user['email'],)).fetchall()
    passed_ids = set(r['course_id'] for r in my_results if r['passed'])
    visible = [c for c in courses if user['role'] in ('admin','trainer') or user['department'] in json.loads(c['target_groups'] or '[]')]
    q_counts = {c['id']:db.execute("SELECT COUNT(*) as cnt FROM questions WHERE course_id=?",(c['id'],)).fetchone()['cnt'] for c in visible}
    return render_template('dashboard.html',user=user,courses=visible,passed_ids=passed_ids,results=my_results,q_counts=q_counts)


@app.route('/category/<cat>')
@login_required
def browse_category(cat):
    user = get_current_user(); db = get_db()
    courses = db.execute("SELECT * FROM courses WHERE category=? ORDER BY created_at DESC",(cat,)).fetchall()
    visible = [c for c in courses if user['role'] in ('admin','trainer') or user['department'] in json.loads(c['target_groups'] or '[]')]
    my_r = db.execute("SELECT * FROM results WHERE user_email=? AND is_valid=1",(user['email'],)).fetchall()
    passed_ids = set(r['course_id'] for r in my_r if r['passed'])
    q_counts = {c['id']:db.execute("SELECT COUNT(*) as cnt FROM questions WHERE course_id=?",(c['id'],)).fetchone()['cnt'] for c in visible}
    return render_template('category.html',user=user,courses=visible,category=cat,passed_ids=passed_ids,q_counts=q_counts)

@app.route('/search')
@login_required
def search_courses():
    user = get_current_user(); db = get_db()
    q = request.args.get('q','').strip(); cat = request.args.get('category','')
    sql,params = "SELECT * FROM courses WHERE 1=1",[]
    if q: sql += " AND (title_vi LIKE ? OR title_en LIKE ? OR desc_vi LIKE ? OR desc_en LIKE ?)"; params.extend([f'%{q}%']*4)
    if cat: sql += " AND category=?"; params.append(cat)
    courses = db.execute(sql+" ORDER BY created_at DESC",params).fetchall()
    visible = [c for c in courses if user['role'] in ('admin','trainer') or user['department'] in json.loads(c['target_groups'] or '[]')]
    my_r = db.execute("SELECT * FROM results WHERE user_email=? AND is_valid=1",(user['email'],)).fetchall()
    passed_ids = set(r['course_id'] for r in my_r if r['passed'])
    q_counts = {c['id']:db.execute("SELECT COUNT(*) as cnt FROM questions WHERE course_id=?",(c['id'],)).fetchone()['cnt'] for c in visible}
    return render_template('search.html',user=user,courses=visible,query=q,filter_cat=cat,passed_ids=passed_ids,q_counts=q_counts)


# ═══════════════ COURSE / QUIZ ═══════════════
@app.route('/course/<int:cid>')
@login_required
def course_detail(cid):
    user = get_current_user(); db = get_db()
    course = db.execute("SELECT * FROM courses WHERE id=?",(cid,)).fetchone()
    if not course: flash('Không tồn tại.','error'); return redirect(url_for('dashboard'))
    q_count = db.execute("SELECT COUNT(*) as cnt FROM questions WHERE course_id=?",(cid,)).fetchone()['cnt']
    ai = get_user_attempt_info(user['email'],cid)
    embed = get_youtube_embed(course['video_url'])
    max_att = course['max_attempts'] or 3
    can_quiz = ai['has_retest_request'] or (not ai['has_passed'] and ai['attempt_count']<max_att)
    trainer = db.execute("SELECT name FROM users WHERE email=?",(course['created_by'] or '',)).fetchone()
    return render_template('course_detail.html',user=user,course=course,q_count=q_count,
                           attempt_info=ai,embed_url=embed,can_take_quiz=can_quiz,max_attempts=max_att,
                           trainer_name=trainer['name'] if trainer else '')

@app.route('/quiz/<int:cid>', methods=['GET','POST'])
@login_required
def take_quiz(cid):
    user = get_current_user(); db = get_db()
    course = db.execute("SELECT * FROM courses WHERE id=?",(cid,)).fetchone()
    allq = db.execute("SELECT * FROM questions WHERE course_id=?",(cid,)).fetchall()
    if not course or not allq: flash('Không có câu hỏi.','error'); return redirect(url_for('course_detail',cid=cid))
    ai = get_user_attempt_info(user['email'],cid); max_att = course['max_attempts'] or 3
    if ai['has_passed'] and not ai['has_retest_request']:
        flash('Đã đạt.','warning'); return redirect(url_for('course_detail',cid=cid))
    if ai['attempt_count'] >= max_att and not ai['has_retest_request']:
        flash(f'Hết {max_att} lượt.','error'); return redirect(url_for('course_detail',cid=cid))
    qc = course['quiz_count'] or len(allq); qc = min(qc,len(allq)) or len(allq)
    if request.method == 'POST':
        try:
            qids = [x.strip() for x in request.form.get('question_ids','').split(',') if x.strip()]
            qs = [db.execute("SELECT * FROM questions WHERE id=?",(int(x),)).fetchone() for x in qids]
            qs = [q for q in qs if q]
            score,ans = 0,{}
            for q in qs:
                a = request.form.get(f'q_{q["id"]}',''); ans[str(q['id'])] = a
                if a == q['answer']: score += 1
            passed = 1 if score >= (course['pass_score'] or 1) else 0
            if ai['has_retest_request']:
                db.execute("UPDATE results SET is_valid=0 WHERE user_email=? AND course_id=?",(user['email'],cid))
            na = 1 if ai['has_retest_request'] else ai['attempt_count']+1
            cur = db.execute("INSERT INTO results (user_email,course_id,score,total,passed,answers_json,attempt_number) VALUES (?,?,?,?,?,?,?)",
                       (user['email'],cid,score,len(qs),passed,json.dumps(ans),na))
            db.commit()
            # Get inserted ID - try cursor.lastrowid first, then fallback
            rid = getattr(cur, 'lastrowid', None)
            if not rid:
                rid = db.execute("SELECT id FROM results WHERE user_email=? AND course_id=? ORDER BY id DESC LIMIT 1",
                                 (user['email'],cid)).fetchone()['id']
            if passed:
                try: send_certificate_email(user['email'],user['name'],course['title_vi'] or course['title_en'],score,len(qs),datetime.now().strftime('%d/%m/%Y'))
                except: pass
            return redirect(url_for('quiz_result',cid=cid,rid=rid))
        except Exception as e:
            print(f"[QUIZ-ERROR] {e}")
            db.commit()  # commit whatever was saved
            # Try to find the result anyway
            latest = db.execute("SELECT id FROM results WHERE user_email=? AND course_id=? ORDER BY id DESC LIMIT 1",
                                (user['email'],cid)).fetchone()
            if latest:
                return redirect(url_for('quiz_result',cid=cid,rid=latest['id']))
            flash('Đã lưu kết quả. Vui lòng kiểm tra lại.','warning')
            return redirect(url_for('course_detail',cid=cid))
    ql = list(allq); random.shuffle(ql)
    return render_template('quiz.html',user=user,course=course,questions=ql[:qc])

@app.route('/quiz-result/<int:cid>/<int:rid>')
@login_required
def quiz_result(cid,rid):
    user = get_current_user(); db = get_db()
    course = db.execute("SELECT * FROM courses WHERE id=?",(cid,)).fetchone()
    result = db.execute("SELECT * FROM results WHERE id=? AND user_email=?",(rid,user['email'])).fetchone()
    if not result: return redirect(url_for('course_detail',cid=cid))
    ans = json.loads(result['answers_json'] or '{}')
    qs = [db.execute("SELECT * FROM questions WHERE id=?",(int(qid),)).fetchone() for qid in ans.keys()]
    qs = [q for q in qs if q]
    ai = get_user_attempt_info(user['email'],cid)
    return render_template('quiz_result.html',user=user,course=course,result=result,questions=qs,answers=ans,attempt_info=ai)


# ═══════════════ CERTIFICATE ═══════════════
@app.route('/certificate/<int:cid>/<int:rid>')
@login_required
def download_cert(cid,rid):
    user = get_current_user(); db = get_db()
    course = db.execute("SELECT * FROM courses WHERE id=?",(cid,)).fetchone()
    result = db.execute("SELECT * FROM results WHERE id=? AND user_email=? AND passed=1",(rid,user['email'])).fetchone()
    if not course or not result: flash('Chứng chỉ không khả dụng.','error'); return redirect(url_for('dashboard'))
    # Trainer = người tạo khóa học
    trainer = db.execute("SELECT * FROM users WHERE email=?",(course['created_by'] or '',)).fetchone()
    # Manager = theo department của người nhận chứng chỉ
    manager = get_cert_manager(user['department'])
    return render_template('certificate.html',user=user,course=course,result=result,trainer=trainer,manager=manager)

@app.route('/certificate/<int:cid>/<int:rid>/send-email', methods=['POST'])
@login_required
def send_cert_email(cid,rid):
    user = get_current_user(); db = get_db()
    course = db.execute("SELECT * FROM courses WHERE id=?",(cid,)).fetchone()
    result = db.execute("SELECT * FROM results WHERE id=? AND user_email=? AND passed=1",(rid,user['email'])).fetchone()
    if course and result:
        ok = send_certificate_email(user['email'],user['name'],course['title_vi'] or course['title_en'],result['score'],result['total'],(result['completed_at'] or '')[:10])
        flash('Đã gửi email!' if ok else 'Gửi thất bại. Kiểm tra SMTP.','success' if ok else 'error')
    return redirect(url_for('download_cert',cid=cid,rid=rid))

@app.route('/my-certs')
@login_required
def my_certs():
    user = get_current_user()
    passed = get_db().execute("SELECT r.*,c.title_vi,c.title_en,c.category FROM results r JOIN courses c ON r.course_id=c.id WHERE r.user_email=? AND r.passed=1 AND r.is_valid=1 ORDER BY r.completed_at DESC",(user['email'],)).fetchall()
    seen,unique = set(),[]
    for r in passed:
        if r['course_id'] not in seen: seen.add(r['course_id']); unique.append(r)
    return render_template('my_certs.html',user=user,certs=unique)


# ═══════════════ ADMIN ═══════════════
@app.route('/admin')
@admin_required
def admin_panel():
    user = get_current_user(); db = get_db()
    users = db.execute("SELECT * FROM users ORDER BY created_at DESC").fetchall()
    courses = db.execute("SELECT c.*, u.name as trainer_name FROM courses c LEFT JOIN users u ON c.created_by=u.email ORDER BY c.created_at DESC").fetchall()
    results = db.execute("SELECT * FROM results WHERE is_valid=1").fetchall()
    q_counts = {c['id']:db.execute("SELECT COUNT(*) as cnt FROM questions WHERE course_id=?",(c['id'],)).fetchone()['cnt'] for c in courses}
    allowed = db.execute("SELECT * FROM allowed_emails ORDER BY created_at DESC").fetchall()
    stats = {'total_users':len([u for u in users if u['role'] in ('learner','trainer')]),
             'total_courses':len(courses),
             'total_certs':len(set(f"{r['user_email']}-{r['course_id']}" for r in results if r['passed'])),
             'total_attempts':len(results)}
    return render_template('admin.html',user=user,users=users,courses=courses,results=results,
                           q_counts=q_counts,stats=stats,allowed_emails=allowed)

@app.route('/admin/user/<int:uid>/update', methods=['POST'])
@admin_required
def update_user(uid):
    db = get_db(); cu = get_current_user()
    role = request.form.get('role','learner')
    if role == 'admin' and cu['role'] != 'admin': role = 'trainer'
    db.execute("UPDATE users SET role=?,department=?,team=?,job_title=?,job_level=?,status=? WHERE id=?",
               (role,request.form.get('department'),request.form.get('team','N/A'),
                request.form.get('job_title','Other'),request.form.get('job_level','Staff'),
                request.form.get('status','active'),uid))
    db.commit(); flash('Cập nhật!','success')
    return redirect(url_for('admin_panel')+'#users')

@app.route('/admin/email/add', methods=['POST'])
@admin_only
def add_allowed_email():
    email = request.form.get('email','').strip().lower()
    note = request.form.get('note','')
    init_pw = request.form.get('initial_password','').strip()
    if email and '@' in email:
        db = get_db()
        try:
            db.execute("INSERT INTO allowed_emails (email,note,added_by) VALUES (?,?,?)",(email,note,session.get('user_email','')))
            db.commit()
            # If admin sets initial password, pre-create the account
            if init_pw and len(init_pw) >= 4:
                existing = db.execute("SELECT id FROM users WHERE email=?",(email,)).fetchone()
                if not existing:
                    db.execute("INSERT INTO users (email,password_hash,name,department,role,verified) VALUES (?,?,?,?,?,?)",
                               (email,hash_password(init_pw),email.split('@')[0],'Sales & Marketing Vietnam','learner',1))
                    db.commit()
                    flash(f'Đã thêm {email} + tạo tài khoản (MK: {init_pw})!','success')
                else:
                    flash(f'Đã thêm {email} (tài khoản đã tồn tại).','success')
            else:
                flash(f'Đã thêm {email}!','success')
        except sqlite3.IntegrityError: flash('Email đã có.','warning')
    else: flash('Email không hợp lệ.','error')
    return redirect(url_for('admin_panel')+'#emails')

@app.route('/admin/email/<int:eid>/toggle', methods=['POST'])
@admin_only
def toggle_email(eid):
    db = get_db(); r = db.execute("SELECT * FROM allowed_emails WHERE id=?",(eid,)).fetchone()
    if r: db.execute("UPDATE allowed_emails SET active=? WHERE id=?",(0 if r['active'] else 1,eid)); db.commit()
    return redirect(url_for('admin_panel')+'#emails')

@app.route('/admin/email/<int:eid>/delete', methods=['POST'])
@admin_only
def delete_email(eid):
    get_db().execute("DELETE FROM allowed_emails WHERE id=?",(eid,)); get_db().commit()
    flash('Đã xóa.','success'); return redirect(url_for('admin_panel')+'#emails')


# ═══════════════ COURSE MANAGEMENT ═══════════════
@app.route('/admin/course/new', methods=['GET','POST'])
@admin_required
def new_course():
    user = get_current_user()
    if request.method == 'POST':
        db = get_db()
        db.execute('''INSERT INTO courses (title_vi,title_en,desc_vi,desc_en,category,video_url,pdf_url,
            target_groups,deadline,pass_score,quiz_count,time_limit,max_attempts,created_by) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
            (request.form.get('title_vi',''),request.form.get('title_en',''),request.form.get('desc_vi',''),request.form.get('desc_en',''),
             request.form.get('category','Compliance'),request.form.get('video_url',''),request.form.get('pdf_url',''),
             json.dumps(request.form.getlist('target_groups')),request.form.get('deadline',''),
             int(request.form.get('pass_score',3)),int(request.form.get('quiz_count',0)),
             int(request.form.get('time_limit',15)),int(request.form.get('max_attempts',3)),user['email']))
        db.commit(); cid = db.execute("SELECT last_insert_rowid()").fetchone()[0]
        flash('Đã tạo!','success'); return redirect(url_for('manage_questions',cid=cid))
    return render_template('course_form.html',user=user,course=None)

@app.route('/admin/course/<int:cid>/edit', methods=['GET','POST'])
@admin_required
def edit_course(cid):
    user = get_current_user(); db = get_db()
    course = db.execute("SELECT * FROM courses WHERE id=?",(cid,)).fetchone()
    if not course: flash('Không tồn tại.','error'); return redirect(url_for('admin_panel'))
    if request.method == 'POST':
        db.execute('''UPDATE courses SET title_vi=?,title_en=?,desc_vi=?,desc_en=?,category=?,video_url=?,pdf_url=?,
            target_groups=?,deadline=?,pass_score=?,quiz_count=?,time_limit=?,max_attempts=? WHERE id=?''',
            (request.form.get('title_vi',''),request.form.get('title_en',''),request.form.get('desc_vi',''),request.form.get('desc_en',''),
             request.form.get('category','Compliance'),request.form.get('video_url',''),request.form.get('pdf_url',''),
             json.dumps(request.form.getlist('target_groups')),request.form.get('deadline',''),
             int(request.form.get('pass_score',3)),int(request.form.get('quiz_count',0)),
             int(request.form.get('time_limit',15)),int(request.form.get('max_attempts',3)),cid))
        db.commit(); flash('Cập nhật!','success'); return redirect(url_for('admin_panel')+'#content')
    qc = db.execute("SELECT COUNT(*) as cnt FROM questions WHERE course_id=?",(cid,)).fetchone()['cnt']
    return render_template('course_form.html',user=user,course=course,q_count=qc)

@app.route('/admin/course/<int:cid>/delete', methods=['POST'])
@admin_required
def delete_course(cid):
    db = get_db()
    for t in ['questions','results','retest_requests']: db.execute(f"DELETE FROM {t} WHERE course_id=?",(cid,))
    db.execute("DELETE FROM courses WHERE id=?",(cid,)); db.commit()
    flash('Đã xóa.','success'); return redirect(url_for('admin_panel')+'#content')

@app.route('/admin/course/<int:cid>/questions', methods=['GET','POST'])
@admin_required
def manage_questions(cid):
    user = get_current_user(); db = get_db()
    course = db.execute("SELECT * FROM courses WHERE id=?",(cid,)).fetchone()
    if not course: return redirect(url_for('admin_panel'))
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'add':
            db.execute("INSERT INTO questions (course_id,text,option_a,option_b,option_c,option_d,answer,explanation,source) VALUES (?,?,?,?,?,?,?,?,?)",
                       (cid,request.form.get('text'),request.form.get('option_a'),request.form.get('option_b'),
                        request.form.get('option_c',''),request.form.get('option_d',''),
                        request.form.get('answer','a'),request.form.get('explanation',''),'manual'))
            db.commit(); flash('Đã thêm!','success')
        elif action == 'csv':
            count = 0
            for line in request.form.get('csv_data','').strip().split('\n'):
                if not line.strip(): continue
                parts = [p.strip() for p in line.split('|')]
                if len(parts) >= 6:
                    ans = parts[5].strip().lower()
                    if ans not in ('a','b','c','d'): ans = 'a'
                    db.execute("INSERT INTO questions (course_id,text,option_a,option_b,option_c,option_d,answer,explanation,source) VALUES (?,?,?,?,?,?,?,?,?)",
                               (cid,parts[0],parts[1],parts[2],parts[3] if len(parts)>3 else '',parts[4] if len(parts)>4 else '',ans,parts[6] if len(parts)>6 else '','csv'))
                    count += 1
            db.commit(); flash(f'Import {count} câu!' if count else 'Không hợp lệ.','success' if count else 'error')
        elif action == 'csv_file':
            f = request.files.get('csv_file')
            if f and f.filename:
                try:
                    content = f.read().decode('utf-8-sig'); count = 0
                    for line in content.strip().split('\n'):
                        if not line.strip(): continue
                        parts = [p.strip() for p in line.split('|')]
                        if len(parts) >= 6:
                            ans = parts[5].strip().lower()
                            if ans not in ('a','b','c','d'): ans = 'a'
                            db.execute("INSERT INTO questions (course_id,text,option_a,option_b,option_c,option_d,answer,explanation,source) VALUES (?,?,?,?,?,?,?,?,?)",
                                       (cid,parts[0],parts[1],parts[2],parts[3] if len(parts)>3 else '',parts[4] if len(parts)>4 else '',ans,parts[6] if len(parts)>6 else '','csv'))
                            count += 1
                    db.commit(); flash(f'Import {count} câu!' if count else 'File không hợp lệ.','success' if count else 'error')
                except Exception as e: flash(f'Lỗi: {e}','error')
        elif action == 'delete':
            db.execute("DELETE FROM questions WHERE id=? AND course_id=?",(request.form.get('question_id'),cid)); db.commit(); flash('Đã xóa.','success')
        elif action == 'update_settings':
            db.execute("UPDATE courses SET quiz_count=?,pass_score=?,max_attempts=? WHERE id=?",
                       (int(request.form.get('quiz_count',0)),int(request.form.get('pass_score',3)),int(request.form.get('max_attempts',3)),cid))
            db.commit(); flash('Đã lưu!','success')
        return redirect(url_for('manage_questions',cid=cid))
    questions = db.execute("SELECT * FROM questions WHERE course_id=? ORDER BY created_at ASC",(cid,)).fetchall()
    return render_template('questions.html',user=user,course=course,questions=questions)


# ═══════════════ RETEST & REMINDER ═══════════════
@app.route('/admin/course/<int:cid>/retest', methods=['POST'])
@admin_required
def request_retest(cid):
    user = get_current_user(); db = get_db()
    tt = request.form.get('target_type','all')
    tv = request.form.get('target_value','')
    deadline = request.form.get('deadline','')
    db.execute("INSERT INTO retest_requests (course_id,target_type,target_value,deadline,requested_by) VALUES (?,?,?,?,?)",
               (cid,tt,tv,deadline,user['email']))
    db.commit()
    course = db.execute("SELECT * FROM courses WHERE id=?",(cid,)).fetchone()
    ct = course['title_vi'] or course['title_en'] if course else ''
    targets = get_targets(tt, tv)
    sent = sum(1 for t in targets if send_test_request_email(t['email'],t['name'],ct,deadline or 'Không giới hạn',user['name']))
    flash(f'Đã gửi yêu cầu: {len(targets)} người ({sent} email OK).','success')
    return redirect(url_for('manage_questions',cid=cid))

@app.route('/admin/send-reminder', methods=['POST'])
@admin_required
def send_reminder():
    user = get_current_user(); db = get_db()
    cid = request.form.get('course_id')
    course = db.execute("SELECT * FROM courses WHERE id=?",(cid,)).fetchone()
    if not course: flash('Không tồn tại.','error'); return redirect(url_for('admin_panel'))
    ct = course['title_vi'] or course['title_en']
    tt = request.form.get('target_type','all')
    tv = request.form.get('target_value','')
    deadline = request.form.get('deadline','')
    targets = get_targets(tt, tv)
    sent = sum(1 for t in targets if send_reminder_email(t['email'],t['name'],ct,deadline or 'Không giới hạn',user['name']))
    flash(f'Gửi {len(targets)} người ({sent} email OK).','success')
    return redirect(request.referrer or url_for('admin_panel'))


# ═══════════════ ANALYTICS ═══════════════
@app.route('/admin/analytics')
@admin_required
def analytics():
    user = get_current_user(); db = get_db()
    users_all = db.execute("SELECT * FROM users").fetchall()
    courses = db.execute("SELECT * FROM courses").fetchall()
    results = db.execute('''SELECT r.*,u.name,u.department,c.title_vi,c.title_en,c.category
        FROM results r LEFT JOIN users u ON r.user_email=u.email LEFT JOIN courses c ON r.course_id=c.id
        WHERE r.is_valid=1 ORDER BY r.completed_at DESC''').fetchall()
    dept_stats = {}
    for dept in DEPARTMENTS:
        du=[u for u in users_all if u['department']==dept and u['role'] in ('learner','trainer')]
        dr=[r for r in results if r['department']==dept]; dp=[r for r in dr if r['passed']]
        dept_stats[dept]={'users':len(du),'attempts':len(dr),'passed':len(dp),'rate':round(len(dp)/len(dr)*100) if dr else 0}
    return render_template('analytics.html',user=user,results=results,dept_stats=dept_stats,users_all=users_all,courses=courses)

@app.route('/admin/export-csv')
@admin_required
def export_csv():
    results = get_db().execute('''SELECT r.*,u.name,u.department,c.title_vi,c.title_en FROM results r
        LEFT JOIN users u ON r.user_email=u.email LEFT JOIN courses c ON r.course_id=c.id
        WHERE r.is_valid=1 ORDER BY r.completed_at DESC''').fetchall()
    out=io.StringIO();out.write('\ufeff');w=csv.writer(out)
    w.writerow(['Name','Email','Department','Course','Score','Total','Passed','Attempt','Date'])
    for r in results: w.writerow([r['name'],r['user_email'],r['department'],r['title_vi'] or r['title_en'],r['score'],r['total'],'Yes' if r['passed'] else 'No',r['attempt_number'] or 1,r['completed_at']])
    out.seek(0)
    return make_response(out.getvalue(),200,{'Content-Type':'text/csv; charset=utf-8','Content-Disposition':f'attachment; filename=report_{datetime.now().strftime("%Y%m%d")}.csv'})

@app.route('/admin/test-smtp')
@admin_only
def test_smtp():
    user = get_current_user()
    ok = send_email(user['email'],'🧪 MANI LMS - SMTP Test','<h2 style="color:#003047">✅ SMTP hoạt động!</h2><p>Email test thành công.</p>')
    flash(f'SMTP {"OK! Kiểm tra "+user["email"] if ok else "FAILED. Kiểm tra SMTP_USER & SMTP_PASS."}','success' if ok else 'error')
    return redirect(url_for('admin_panel')+'#emails')


# ═══════════════ DB INFO (for debugging) ═══════════════
@app.route('/admin/db-info')
@admin_only
def db_info():
    info = {
        'db_type': 'Turso Cloud' if USE_TURSO else 'Local SQLite',
        'turso_url': TURSO_URL[:50] + '...' if TURSO_URL else 'Not set',
        'local_db_path': DATABASE,
        'local_db_exists': os.path.exists(DATABASE) if not USE_TURSO else 'N/A',
        'render_disk_exists': os.path.isdir('/opt/render/project/data'),
        'libsql_available': HAVE_LIBSQL,
    }
    # Test connection
    try:
        db = get_db()
        uc = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        cc = db.execute("SELECT COUNT(*) FROM courses").fetchone()[0]
        info['users_count'] = uc
        info['courses_count'] = cc
        info['connection'] = 'OK'
    except Exception as e:
        info['connection'] = f'ERROR: {e}'
    return jsonify(info)


# ═══════════════ INIT ═══════════════
with app.app_context(): init_db()

if __name__ == '__main__':
    app.run(host='0.0.0.0',port=int(os.environ.get('PORT',5000)),debug=os.environ.get('DEBUG','false').lower()=='true')
