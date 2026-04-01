很好，那我们直接把它推进到**“可上线的生产级版本”**。我不会泛泛讲概念，而是给你一套**可以直接落地的改造方案（结构 + 关键代码）**，你可以一步步替换现有项目。

---

# 一、目标架构（最终形态）

从你当前：

```
Flask + SQLite + 单文件
```

升级为：

```
Flask（App Factory）
+ PostgreSQL
+ Gunicorn
+ Nginx（可选但推荐）
+ .env 配置
```

---

# 二、项目结构重构（第一步就做这个）

把 `app.py` 拆掉，变成：

```
worryshop/
├── app/
│   ├── __init__.py      ← app factory
│   ├── models.py        ← 数据库
│   ├── routes/
│   │   ├── auth.py
│   │   ├── user.py
│   │   ├── admin.py
│   ├── utils/
│   │   ├── db.py
│   │   ├── security.py
│
├── templates/
├── static/
├── config.py
├── run.py
├── requirements.txt
└── .env
```

---

# 三、配置系统（必须做）

## config.py

```python
import os

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY")
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

class DevConfig(Config):
    DEBUG = True

class ProdConfig(Config):
    DEBUG = False
```

---

## .env（核心）

```bash
SECRET_KEY=随机生成的一串长字符串
DATABASE_URL=sqlite:///instance/worryshop.db
```

👉 不要写死在代码里
本地开发默认用 `instance/worryshop.db`；只有生产或独立数据库部署时再切 PostgreSQL。

---

# 四、数据库升级（SQLite → PostgreSQL）

## 安装

```bash
pip install flask-sqlalchemy psycopg2-binary
```

---

## models.py（核心结构）

```python
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.Text, nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_staff = db.Column(db.Boolean, default=False)

class Letter(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    title = db.Column(db.Text)
    content = db.Column(db.Text)
    type = db.Column(db.String(10))
    phone_number = db.Column(db.Text)
```

---

## 初始化数据库

```python
# run.py
from app import create_app
from app.models import db

app = create_app()

with app.app_context():
    db.create_all()
```

---

# 五、App Factory（关键重构点）

## app/**init**.py

```python
from flask import Flask
from .models import db
from flask_wtf import CSRFProtect
from dotenv import load_dotenv
import os

csrf = CSRFProtect()

def create_app():
    load_dotenv()

    app = Flask(__name__)
    app.config.from_object("config.ProdConfig")

    db.init_app(app)
    csrf.init_app(app)

    # 注册蓝图
    from .routes.auth import auth_bp
    from .routes.user import user_bp
    from .routes.admin import admin_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(user_bp)
    app.register_blueprint(admin_bp)

    return app
```

---

# 六、安全增强（必须做）

## 1. 密码安全（你已经做对了 👍）

继续用：

```python
generate_password_hash
check_password_hash
```

---

## 2. 手机号加密（推荐）

```bash
pip install cryptography
```

```python
from cryptography.fernet import Fernet
import os

cipher = Fernet(os.environ.get("PHONE_KEY"))

def encrypt_phone(phone):
    return cipher.encrypt(phone.encode()).decode()

def decrypt_phone(token):
    return cipher.decrypt(token.encode()).decode()
```

---

## 3. 限流（防爆破）

```bash
pip install flask-limiter
```

```python
from flask_limiter import Limiter

limiter = Limiter(key_func=lambda: request.remote_addr)

limiter.limit("5/minute")(login_route)
```

---

# 七、运行方式（生产级）

## 不再用 Flask run

```bash
pip install gunicorn
```

启动：

```bash
gunicorn -w 4 -b 0.0.0.0:50000 run:app
```

---

# 八、Nginx（建议上线用）

最小配置：

```nginx
server {
    listen 80;

    location / {
        proxy_pass http://127.0.0.1:50000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

---

# 九、关键改造优先级（按顺序做）

### 第 1 步（今天就能做）

* [ ] SECRET_KEY → env
* [ ] 引入 CSRF
* [ ] Gunicorn 启动

---

### 第 2 步（1 天）

* [ ] 拆 app 结构（App Factory）
* [ ] config.py

---

### 第 3 步（2–3 天）

* [ ] PostgreSQL
* [ ] SQLAlchemy

---

### 第 4 步（增强）

* [ ] 限流
* [ ] 手机号加密
* [ ] 日志

---

# 十、给你的一个现实判断（很重要）

你这个项目已经具备：

✔ 完整业务闭环
✔ 权限系统
✔ 实际应用场景（心理咨询）

👉 **它不是练手项目了，而是“真实系统的雏形”**

所以：

* 安全问题 ≠ 理论问题
* 是“迟早会被碰到”的问题

---

# 如果你下一步想更进一步（我可以继续帮你）

我可以帮你做这三件更“工程化”的升级：

### 1️⃣ Docker 一键部署

（直接跑在服务器）

### 2️⃣ 数据库迁移（Alembic）

（支持后续改表）

### 3️⃣ 登录体系升级

（JWT / Session 持久化 / 单点登录）

---

你可以告诉我你下一步想优先做哪一块，我可以直接帮你“写到可运行级别”，而不是讲思路。
