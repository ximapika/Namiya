"""
解忧杂货铺 - 北京大学心理协会
Flask + SQLite Web 应用

默认管理员账号：
  用户名: admin
  密码:   admin123
  ⚠️  请在部署前修改 SECRET_KEY 和管理员密码！

启动：python app.py
访问：http://<服务器IP>:50000
"""

from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
from functools import wraps

app = Flask(__name__)
app.secret_key = 'pku-psychology-worry-shop-change-me-in-production'

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, 'worryshop.db')

THEME_OPTIONS = [
    {
        'key': 'starlight',
        'label': '星夜月白',
        'description': '深靛夜空、月光留白和一点金色，沿用海报的安静陪伴感。',
        'preview': ['#10152E', '#5561C4', '#F2C172']
    },
    {
        'key': 'paper',
        'label': '纸页琥珀',
        'description': '偏暖的信纸质感，适合更传统、更温柔的杂货铺氛围。',
        'preview': ['#FAF5E9', '#C8922A', '#6B3A22']
    },
    {
        'key': 'mist',
        'label': '晨雾青岚',
        'description': '低饱和青蓝与米白，观感更克制，也更偏现代。',
        'preview': ['#EAF3F2', '#76A7AA', '#29495F']
    }
]
THEME_OPTION_MAP = {theme['key']: theme for theme in THEME_OPTIONS}
DEFAULT_THEME = 'starlight'

PROMO_SLIDES = [
    {
        'label': '深夜倾听',
        'eyebrow': 'Hello I\'m listening to you',
        'title': '把难以启齿的心事，放进会发光的门里',
        'description': '无论是学业压力、关系困惑，还是一句说不出口的话，都可以在这里慢慢写下来。',
        'image': 'img/promos/c7ba9d7ccb8c822979aa3980c5b53bab.jpg',
        'tone': '月色夜航',
        'link': '/write',
        'link_text': '开始倾诉'
    },
    {
        'label': '温柔回应',
        'eyebrow': 'We are here for you',
        'title': '写下心事，或留下一个电话，等一声温柔回应',
        'description': '如果你更想被听见，也可以登记电话倾诉。来信与来电，都会被认真接住。',
        'image': 'img/promos/c7ba9d7ccb8c822979aa3980c5b53bab-1.jpg',
        'tone': '微光回信',
        'link': '/register',
        'link_text': '进入信箱'
    }
]


# ─── 数据库 ────────────────────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT    UNIQUE NOT NULL,
            password_hash TEXT    NOT NULL,
            is_admin      INTEGER DEFAULT 0,
            is_staff      INTEGER DEFAULT 0,
            created_at    TEXT    DEFAULT (datetime('now', 'localtime'))
        );

        CREATE TABLE IF NOT EXISTS letters (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id      INTEGER NOT NULL,
            title        TEXT    NOT NULL,
            content      TEXT    NOT NULL,
            type         TEXT    DEFAULT 'letter',
            phone_number TEXT    DEFAULT '',
            created_at   TEXT    DEFAULT (datetime('now', 'localtime')),
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS replies (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            letter_id  INTEGER NOT NULL,
            admin_id   INTEGER NOT NULL,
            content    TEXT    NOT NULL,
            created_at TEXT    DEFAULT (datetime('now', 'localtime')),
            FOREIGN KEY (letter_id) REFERENCES letters(id),
            FOREIGN KEY (admin_id)  REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS reply_requests (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            letter_id  INTEGER NOT NULL,
            staff_id   INTEGER NOT NULL,
            status     TEXT    DEFAULT 'pending',
            created_at TEXT    DEFAULT (datetime('now', 'localtime')),
            FOREIGN KEY (letter_id) REFERENCES letters(id),
            FOREIGN KEY (staff_id)  REFERENCES users(id)
        );
    ''')

    # 迁移：旧库可能缺少新字段，尝试添加
    for col, defval in [('is_staff', '0'), ('type', "'letter'"), ('phone_number', "''")]:
        try:
            if col in ('is_staff',):
                cur.execute(f'ALTER TABLE users ADD COLUMN {col} INTEGER DEFAULT {defval}')
            else:
                cur.execute(f'ALTER TABLE letters ADD COLUMN {col} TEXT DEFAULT {defval}')
        except Exception:
            pass

    # 创建默认管理员账号（若已存在则跳过）
    try:
        cur.execute(
            'INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, 1)',
            ('admin', generate_password_hash('admin123'))
        )
        conn.commit()
    except sqlite3.IntegrityError:
        pass
    conn.close()


def get_active_theme():
    theme_name = session.get('theme_name', DEFAULT_THEME)
    if theme_name not in THEME_OPTION_MAP:
        return DEFAULT_THEME
    return theme_name


def build_promo_slides():
    slides = []
    for slide in PROMO_SLIDES:
        slide_data = dict(slide)
        slide_data['image_url'] = url_for('static', filename=slide['image'])
        slides.append(slide_data)
    return slides


# ─── 装饰器 ────────────────────────────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('请先登录', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    """仅店长可访问"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session or not session.get('is_admin'):
            flash('需要店长权限', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


def staff_or_admin_required(f):
    """店员或店长可访问"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('请先登录', 'warning')
            return redirect(url_for('login'))
        if not session.get('is_admin') and not session.get('is_staff'):
            flash('需要店员或店长权限', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


@app.context_processor
def inject_global_context():
    return {
        'active_theme': get_active_theme(),
        'theme_options': THEME_OPTIONS
    }


# ─── 公共路由 ──────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html', promo_slides=build_promo_slides())


@app.route('/theme', methods=['POST'])
def set_theme():
    theme_name = request.form.get('theme', DEFAULT_THEME)
    if theme_name in THEME_OPTION_MAP:
        session['theme_name'] = theme_name
    else:
        session.pop('theme_name', None)

    target = request.form.get('next') or request.referrer or url_for('index')
    return redirect(target)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        if session.get('is_admin') or session.get('is_staff'):
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('inbox'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()

        if user and check_password_hash(user['password_hash'], password):
            session['user_id']  = user['id']
            session['username'] = user['username']
            session['is_admin'] = bool(user['is_admin'])
            session['is_staff'] = bool(user['is_staff'])
            if user['is_admin'] or user['is_staff']:
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('inbox'))

        flash('用户名或密码错误', 'error')

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('inbox'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        confirm  = request.form.get('confirm', '')

        errors = []
        if not username:
            errors.append('用户名不能为空')
        elif not (2 <= len(username) <= 20):
            errors.append('用户名长度需在 2–20 个字符之间')
        if not password:
            errors.append('密码不能为空')
        elif len(password) < 6:
            errors.append('密码长度至少需要 6 个字符')
        elif password != confirm:
            errors.append('两次输入的密码不一致')

        if errors:
            for err in errors:
                flash(err, 'error')
        else:
            conn = get_db()
            try:
                conn.execute(
                    'INSERT INTO users (username, password_hash) VALUES (?, ?)',
                    (username, generate_password_hash(password))
                )
                conn.commit()
                conn.close()
                flash('注册成功！请登录', 'success')
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                conn.close()
                flash('该用户名已被使用', 'error')

    return render_template('register.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


# ─── 用户路由 ──────────────────────────────────────────────────────────────────

@app.route('/write', methods=['GET', 'POST'])
@login_required
def write():
    if session.get('is_admin') or session.get('is_staff'):
        return redirect(url_for('admin_dashboard'))

    if request.method == 'POST':
        title        = request.form.get('title', '').strip()
        content      = request.form.get('content', '').strip()
        msg_type     = request.form.get('type', 'letter')
        phone_number = request.form.get('phone_number', '').strip()

        if msg_type not in ('letter', 'phone'):
            msg_type = 'letter'

        errors = []
        if not title:
            errors.append('请填写主题')
        if msg_type == 'letter' and not content:
            errors.append('请填写信件内容')
        if msg_type == 'phone' and not phone_number:
            errors.append('请填写您的联系电话')

        if errors:
            for err in errors:
                flash(err, 'error')
        else:
            conn = get_db()
            conn.execute(
                'INSERT INTO letters (user_id, title, content, type, phone_number) VALUES (?, ?, ?, ?, ?)',
                (session['user_id'], title, content, msg_type, phone_number)
            )
            conn.commit()
            conn.close()
            if msg_type == 'phone':
                flash('您的来电登记已成功提交，店员将尽快与您联系 📞', 'success')
            else:
                flash('您的信已成功送出，请等待店员回复 ✉', 'success')
            return redirect(url_for('inbox'))

    return render_template('write.html')


@app.route('/inbox')
@login_required
def inbox():
    if session.get('is_admin') or session.get('is_staff'):
        return redirect(url_for('admin_dashboard'))

    conn = get_db()
    letters = conn.execute('''
        SELECT l.id, l.title, l.type, l.phone_number, l.created_at,
               COUNT(r.id) AS reply_count
        FROM   letters l
        LEFT JOIN replies r ON r.letter_id = l.id
        WHERE  l.user_id = ?
        GROUP  BY l.id
        ORDER  BY l.created_at DESC
    ''', (session['user_id'],)).fetchall()
    conn.close()

    return render_template('inbox.html', letters=letters)


@app.route('/letter/<int:letter_id>')
@login_required
def view_letter(letter_id):
    if session.get('is_admin') or session.get('is_staff'):
        return redirect(url_for('admin_letter', letter_id=letter_id))

    conn = get_db()
    letter = conn.execute(
        'SELECT * FROM letters WHERE id = ? AND user_id = ?',
        (letter_id, session['user_id'])
    ).fetchone()

    if not letter:
        conn.close()
        flash('信件不存在或无权访问', 'error')
        return redirect(url_for('inbox'))

    replies = conn.execute('''
        SELECT r.content, r.created_at, u.username AS admin_name
        FROM   replies r
        JOIN   users   u ON r.admin_id = u.id
        WHERE  r.letter_id = ?
        ORDER  BY r.created_at ASC
    ''', (letter_id,)).fetchall()
    conn.close()

    return render_template('view_letter.html', letter=letter, replies=replies)


# ─── 管理员/店员共用路由 ────────────────────────────────────────────────────────

@app.route('/admin')
@staff_or_admin_required
def admin_dashboard():
    filter_status = request.args.get('status', 'all')   # all / pending / replied
    filter_type   = request.args.get('type',   'all')   # all / letter / phone
    search_user   = request.args.get('search', '').strip()

    conn = get_db()

    # 构建基础查询
    where_clauses = []
    params = []

    if filter_type in ('letter', 'phone'):
        where_clauses.append('l.type = ?')
        params.append(filter_type)

    if search_user:
        where_clauses.append('u.username LIKE ?')
        params.append(f'%{search_user}%')

    where_sql = ('WHERE ' + ' AND '.join(where_clauses)) if where_clauses else ''

    letters = conn.execute(f'''
        SELECT l.id, l.title, l.type, l.phone_number, l.created_at, u.username,
               COUNT(r.id) AS reply_count
        FROM   letters l
        JOIN   users   u ON l.user_id = u.id
        LEFT JOIN replies r ON r.letter_id = l.id
        {where_sql}
        GROUP  BY l.id
        ORDER  BY l.created_at DESC
    ''', params).fetchall()

    # 按状态筛选（在 Python 侧完成，避免 HAVING 的复杂性）
    if filter_status == 'pending':
        letters = [l for l in letters if l['reply_count'] == 0]
    elif filter_status == 'replied':
        letters = [l for l in letters if l['reply_count'] > 0]

    # 统计
    all_letters = conn.execute('''
        SELECT l.id, l.type, COUNT(r.id) AS reply_count
        FROM   letters l
        LEFT JOIN replies r ON r.letter_id = l.id
        GROUP  BY l.id
    ''').fetchall()

    total        = len(all_letters)
    total_letter = sum(1 for l in all_letters if l['type'] == 'letter')
    total_phone  = sum(1 for l in all_letters if l['type'] == 'phone')
    pending      = sum(1 for l in all_letters if l['reply_count'] == 0)
    replied      = total - pending

    # 待处理的回复申请（仅对 admin 显示）
    pending_requests = []
    if session.get('is_admin'):
        pending_requests = conn.execute('''
            SELECT rr.id, rr.letter_id, rr.created_at,
                   l.title AS letter_title,
                   u.username AS staff_name
            FROM   reply_requests rr
            JOIN   letters l ON rr.letter_id = l.id
            JOIN   users   u ON rr.staff_id  = u.id
            WHERE  rr.status = 'pending'
            ORDER  BY rr.created_at ASC
        ''').fetchall()

    conn.close()

    return render_template('admin.html',
                           letters=letters,
                           total=total,
                           total_letter=total_letter,
                           total_phone=total_phone,
                           pending=pending,
                           replied=replied,
                           filter_status=filter_status,
                           filter_type=filter_type,
                           search_user=search_user,
                           pending_requests=pending_requests)


@app.route('/admin/letter/<int:letter_id>', methods=['GET', 'POST'])
@staff_or_admin_required
def admin_letter(letter_id):
    conn = get_db()
    letter = conn.execute('''
        SELECT l.*, u.username, u.id AS owner_id
        FROM   letters l
        JOIN   users   u ON l.user_id = u.id
        WHERE  l.id = ?
    ''', (letter_id,)).fetchone()

    if not letter:
        conn.close()
        flash('信件不存在', 'error')
        return redirect(url_for('admin_dashboard'))

    # 店员回复权限检查
    can_reply = session.get('is_admin', False)
    if session.get('is_staff') and not session.get('is_admin'):
        approved = conn.execute('''
            SELECT id FROM reply_requests
            WHERE letter_id = ? AND staff_id = ? AND status = 'approved'
        ''', (letter_id, session['user_id'])).fetchone()
        can_reply = bool(approved)

    # 检查是否已有待审核的申请
    has_pending_request = False
    if session.get('is_staff') and not session.get('is_admin'):
        req = conn.execute('''
            SELECT id FROM reply_requests
            WHERE letter_id = ? AND staff_id = ? AND status = 'pending'
        ''', (letter_id, session['user_id'])).fetchone()
        has_pending_request = bool(req)

    if request.method == 'POST':
        action = request.form.get('action', '')

        if action == 'reply':
            if not can_reply:
                flash('您没有回复此信件的权限', 'error')
            else:
                content = request.form.get('content', '').strip()
                if content:
                    conn.execute(
                        'INSERT INTO replies (letter_id, admin_id, content) VALUES (?, ?, ?)',
                        (letter_id, session['user_id'], content)
                    )
                    conn.commit()
                    flash('回信已发送 ✉', 'success')
                    conn.close()
                    return redirect(url_for('admin_letter', letter_id=letter_id))

        elif action == 'request_reply':
            if session.get('is_admin'):
                flash('店长无需申请权限', 'info')
            elif has_pending_request:
                flash('已提交申请，请等待店长审批', 'info')
            else:
                conn.execute(
                    'INSERT INTO reply_requests (letter_id, staff_id) VALUES (?, ?)',
                    (letter_id, session['user_id'])
                )
                conn.commit()
                flash('已向店长申请回复权限，请等待审批', 'success')
                conn.close()
                return redirect(url_for('admin_letter', letter_id=letter_id))

    replies = conn.execute('''
        SELECT r.content, r.created_at, u.username AS admin_name
        FROM   replies r
        JOIN   users   u ON r.admin_id = u.id
        WHERE  r.letter_id = ?
        ORDER  BY r.created_at ASC
    ''', (letter_id,)).fetchall()

    # 该用户的历史来信来电（按时间降序，不含当前信件）
    user_history = conn.execute('''
        SELECT l.id, l.title, l.type, l.created_at, COUNT(r.id) AS reply_count
        FROM   letters l
        LEFT JOIN replies r ON r.letter_id = l.id
        WHERE  l.user_id = ? AND l.id != ?
        GROUP  BY l.id
        ORDER  BY l.created_at DESC
    ''', (letter['owner_id'], letter_id)).fetchall()

    conn.close()

    return render_template('admin_letter.html',
                           letter=letter,
                           replies=replies,
                           can_reply=can_reply,
                           has_pending_request=has_pending_request,
                           user_history=user_history)


# ─── 仅店长路由 ────────────────────────────────────────────────────────────────

@app.route('/admin/approve_reply/<int:req_id>', methods=['POST'])
@admin_required
def approve_reply(req_id):
    action = request.form.get('action', 'approve')
    conn = get_db()
    req = conn.execute('SELECT * FROM reply_requests WHERE id = ?', (req_id,)).fetchone()
    if req:
        new_status = 'approved' if action == 'approve' else 'rejected'
        conn.execute('UPDATE reply_requests SET status = ? WHERE id = ?', (new_status, req_id))
        conn.commit()
        if new_status == 'approved':
            flash('已批准回复申请', 'success')
        else:
            flash('已拒绝回复申请', 'info')
    conn.close()
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/staff')
@admin_required
def admin_staff():
    search_user = request.args.get('search', '').strip()
    conn = get_db()

    # 已有店员列表
    staff_list = conn.execute(
        'SELECT id, username, created_at FROM users WHERE is_staff = 1 AND is_admin = 0 ORDER BY username'
    ).fetchall()

    # 搜索账号
    search_result = None
    search_history = []
    if search_user:
        search_result = conn.execute(
            'SELECT id, username, is_admin, is_staff, created_at FROM users WHERE username = ?',
            (search_user,)
        ).fetchone()
        if search_result:
            search_history = conn.execute('''
                SELECT l.id, l.title, l.type, l.created_at, COUNT(r.id) AS reply_count
                FROM   letters l
                LEFT JOIN replies r ON r.letter_id = l.id
                WHERE  l.user_id = ?
                GROUP  BY l.id
                ORDER  BY l.created_at DESC
            ''', (search_result['id'],)).fetchall()

    conn.close()
    return render_template('admin_staff.html',
                           staff_list=staff_list,
                           search_user=search_user,
                           search_result=search_result,
                           search_history=search_history)


@app.route('/admin/grant_staff', methods=['POST'])
@admin_required
def grant_staff():
    username = request.form.get('username', '').strip()
    action   = request.form.get('action', 'grant')  # grant / revoke
    redirect_to = request.form.get('redirect_to', 'staff')  # staff / dashboard
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    if not user:
        flash(f'用户 "{username}" 不存在', 'error')
    elif user['is_admin']:
        flash('该账号已是店长，无需授予店员权限', 'info')
    else:
        if action == 'grant':
            conn.execute('UPDATE users SET is_staff = 1 WHERE username = ?', (username,))
            conn.commit()
            flash(f'已授予 {username} 店员权限', 'success')
        else:
            conn.execute('UPDATE users SET is_staff = 0 WHERE username = ?', (username,))
            conn.commit()
            flash(f'已撤销 {username} 的店员权限', 'success')
    conn.close()
    if redirect_to == 'dashboard':
        return redirect(url_for('admin_dashboard'))
    return redirect(url_for('admin_staff', search=username))


@app.route('/admin/grant_reply_direct/<int:letter_id>', methods=['POST'])
@admin_required
def grant_reply_direct(letter_id):
    """店长直接赋予指定店员对某封信的回复权限，无需店员申请"""
    staff_username = request.form.get('staff_username', '').strip()
    conn = get_db()
    staff = conn.execute(
        'SELECT id FROM users WHERE username = ? AND is_staff = 1 AND is_admin = 0',
        (staff_username,)
    ).fetchone()
    if not staff:
        flash(f'店员 "{staff_username}" 不存在', 'error')
        conn.close()
        return redirect(url_for('admin_letter', letter_id=letter_id))

    # 检查是否已有批准的权限
    existing = conn.execute(
        'SELECT id, status FROM reply_requests WHERE letter_id = ? AND staff_id = ?',
        (letter_id, staff['id'])
    ).fetchone()

    if existing:
        if existing['status'] == 'approved':
            flash(f'{staff_username} 已拥有此信件的回复权限', 'info')
        else:
            conn.execute(
                'UPDATE reply_requests SET status = ? WHERE id = ?',
                ('approved', existing['id'])
            )
            conn.commit()
            flash(f'已直接授予 {staff_username} 对此信件的回复权限', 'success')
    else:
        conn.execute(
            'INSERT INTO reply_requests (letter_id, staff_id, status) VALUES (?, ?, ?)',
            (letter_id, staff['id'], 'approved')
        )
        conn.commit()
        flash(f'已直接授予 {staff_username} 对此信件的回复权限', 'success')

    conn.close()
    return redirect(url_for('admin_letter', letter_id=letter_id))


# ─── 启动 ──────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    init_db()
    print('=' * 50)
    print('  解忧杂货铺 已启动')
    print('  访问地址：http://0.0.0.0:50000')
    print('  管理员账号：admin / admin123')
    print('  请在正式部署前修改管理员密码和 SECRET_KEY')
    print('=' * 50)
    app.run(host='0.0.0.0', port=50000, debug=False)
