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

DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'worryshop.db')


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
            created_at    TEXT    DEFAULT (datetime('now', 'localtime'))
        );

        CREATE TABLE IF NOT EXISTS letters (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER NOT NULL,
            title      TEXT    NOT NULL,
            content    TEXT    NOT NULL,
            created_at TEXT    DEFAULT (datetime('now', 'localtime')),
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
    ''')
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
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session or not session.get('is_admin'):
            flash('需要管理员权限', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


# ─── 公共路由 ──────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('admin_dashboard' if session.get('is_admin') else 'inbox'))

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
            return redirect(url_for('admin_dashboard' if user['is_admin'] else 'inbox'))

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
    if session.get('is_admin'):
        return redirect(url_for('admin_dashboard'))

    if request.method == 'POST':
        title   = request.form.get('title', '').strip()
        content = request.form.get('content', '').strip()

        if not title or not content:
            flash('请填写完整的信件内容', 'error')
        else:
            conn = get_db()
            conn.execute(
                'INSERT INTO letters (user_id, title, content) VALUES (?, ?, ?)',
                (session['user_id'], title, content)
            )
            conn.commit()
            conn.close()
            flash('您的信已成功送出，请等待店员回复 ✉', 'success')
            return redirect(url_for('inbox'))

    return render_template('write.html')


@app.route('/inbox')
@login_required
def inbox():
    if session.get('is_admin'):
        return redirect(url_for('admin_dashboard'))

    conn = get_db()
    letters = conn.execute('''
        SELECT l.id, l.title, l.created_at,
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
    if session.get('is_admin'):
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


# ─── 管理员路由 ────────────────────────────────────────────────────────────────

@app.route('/admin')
@admin_required
def admin_dashboard():
    conn = get_db()
    letters = conn.execute('''
        SELECT l.id, l.title, l.created_at, u.username,
               COUNT(r.id) AS reply_count
        FROM   letters l
        JOIN   users   u ON l.user_id = u.id
        LEFT JOIN replies r ON r.letter_id = l.id
        GROUP  BY l.id
        ORDER  BY l.created_at DESC
    ''').fetchall()
    conn.close()

    total   = len(letters)
    pending = sum(1 for l in letters if l['reply_count'] == 0)
    replied = total - pending

    return render_template('admin.html', letters=letters,
                           total=total, pending=pending, replied=replied)


@app.route('/admin/letter/<int:letter_id>', methods=['GET', 'POST'])
@admin_required
def admin_letter(letter_id):
    conn = get_db()
    letter = conn.execute('''
        SELECT l.*, u.username
        FROM   letters l
        JOIN   users   u ON l.user_id = u.id
        WHERE  l.id = ?
    ''', (letter_id,)).fetchone()

    if not letter:
        conn.close()
        flash('信件不存在', 'error')
        return redirect(url_for('admin_dashboard'))

    if request.method == 'POST':
        content = request.form.get('content', '').strip()
        if content:
            conn.execute(
                'INSERT INTO replies (letter_id, admin_id, content) VALUES (?, ?, ?)',
                (letter_id, session['user_id'], content)
            )
            conn.commit()
            conn.close()
            flash('回信已发送 ✉', 'success')
            return redirect(url_for('admin_letter', letter_id=letter_id))

    replies = conn.execute('''
        SELECT r.content, r.created_at, u.username AS admin_name
        FROM   replies r
        JOIN   users   u ON r.admin_id = u.id
        WHERE  r.letter_id = ?
        ORDER  BY r.created_at ASC
    ''', (letter_id,)).fetchall()
    conn.close()

    return render_template('admin_letter.html', letter=letter, replies=replies)


# ─── 启动 ──────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    init_db()
    print('=' * 50)
    print('  解忧杂货铺 已启动')
    print('  访问地址：http://0.0.0.0:5000')
    print('  管理员账号：admin / admin123')
    print('  请在正式部署前修改管理员密码和 SECRET_KEY')
    print('=' * 50)
    app.run(host='0.0.0.0', port=50000, debug=False)
