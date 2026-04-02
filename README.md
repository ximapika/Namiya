# 解忧杂货铺

面向校园心理倾诉场景的 Flask Web 系统，支持来信、来电登记、店员回复、店长审批、账号查询、权限分配与账号删除。

当前版本已从单文件 SQLite Demo 升级为更接近生产环境的结构：

- `app factory + blueprints`
- `SQLAlchemy` 数据访问层
- `PostgreSQL / SQLite` 双支持
- `CSRF`、登录/写信限流、会话安全配置
- 手机号与来电时间字段加密存储
- `Gunicorn` 部署入口与环境变量配置
- 兼容旧版 SQLite 数据并在初始化时自动补齐字段/加密历史号码

## 目录结构

```text
app/
  __init__.py
  auth.py
  bootstrap.py
  cli.py
  content.py
  extensions.py
  models.py
  routes/
  services/
config.py
run.py
gunicorn.conf.py
templates/
static/
instance/
```

## 本地启动

1. 创建虚拟环境并安装依赖：

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

2. 配置环境变量：

```bash
cp .env.example .env
```

至少填写这些值：

- `SECRET_KEY`
- `PHONE_ENCRYPTION_KEY`
- `BOOTSTRAP_ADMIN_USERNAME`
- `BOOTSTRAP_ADMIN_PASSWORD`

开发环境如果缺少 `SECRET_KEY` 或 `PHONE_ENCRYPTION_KEY`，系统会在 `instance/` 下自动生成本地密钥文件；生产环境不会自动生成。

3. 初始化数据库：

```bash
flask --app run.py init-db
```

4. 启动开发服务：

```bash
python run.py
```

访问地址：

```text
http://127.0.0.1:50000
```

## 生产部署

推荐使用 PostgreSQL，并显式配置 `DATABASE_URL`：

```bash
DATABASE_URL=postgresql://user:password@host:5432/worryshop
APP_ENV=production
SECRET_KEY=...
PHONE_ENCRYPTION_KEY=...
SESSION_COOKIE_SECURE=true
ENABLE_HSTS=true
```

初始化数据库：

```bash
flask --app run.py init-db
```

Gunicorn 启动：

```bash
gunicorn -c gunicorn.conf.py run:app
```

如果前面有 Nginx / 反向代理，应用已启用 `ProxyFix`。

## 安全特性

- 密码使用 `werkzeug.security` 哈希存储
- `CSRFProtect` 覆盖全部表单 POST
- `Flask-Limiter` 对登录、注册、写信和管理操作限流
- Session Cookie 默认 `HttpOnly`，支持 `Secure` 与 `SameSite`
- 手机号与来电时间使用 `Fernet` 加密后落库
- 响应头默认加入 `CSP`、`X-Frame-Options`、`X-Content-Type-Options`
- 登录重定向做了同源校验，避免开放重定向

## 数据迁移说明

如果仓库里已有旧版 `worryshop.db`：

- 初始化时会自动补齐缺失字段
- 旧版明文手机号和来电时间会自动迁移为加密存储
- 旧数据表名和页面功能保持兼容

## 管理命令

初始化数据库：

```bash
flask --app run.py init-db
```

创建或重置店长账号：

```bash
flask --app run.py create-admin
```

## 重要配置项

- `DATABASE_URL`：数据库连接串，生产建议 PostgreSQL
- `SECRET_KEY`：Flask Session 与 CSRF 使用
- `PHONE_ENCRYPTION_KEY`：Fernet 加密密钥
- `LOGIN_RATE_LIMIT`：登录限流，例如 `10 per minute`
- `WRITE_RATE_LIMIT`：写信/来电登记限流
- `ADMIN_MUTATION_RATE_LIMIT`：后台写操作限流
- `SESSION_COOKIE_SECURE`：HTTPS 部署时应设为 `true`
- `RATELIMIT_STORAGE_URI`：多实例部署建议接 Redis，而不是默认 `memory://`

## 并发与扩展建议

- 开发环境默认可用 SQLite，但高并发生产环境应切换到 PostgreSQL
- Gunicorn 默认启用多 worker + 多线程，见 [gunicorn.conf.py](/Users/ximapika/vscode/psychology/gunicorn.conf.py)
- 如果要做多实例部署，`Flask-Limiter` 的存储后端应改为 Redis
- 后续如果继续演进，建议补 Alembic 迁移和审计日志
