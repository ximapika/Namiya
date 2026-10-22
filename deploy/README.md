# 校园服务器部署

2026-10-14 新增的邮箱验证、密码传输密钥、数据库迁移、清理定时任务及恢复步骤见 [本次更新部署说明](UPDATE-2026-10-14.md)。该文档是部署准备与验收流程，不代表线上已执行更新。

运行架构：systemd 管理 Gunicorn，Redis 提供跨 worker 限流，SQLite 保留原有数据。
当前访问入口为校园网 HTTP `:50000`，`TRUST_PROXY=false`，不信任外部转发头。
HTTP 不加密账号、会话或信件的传输；迁移到域名和 HTTPS 后应启用 Secure cookie 和 HSTS。
当前部署不需要购买域名，也不进行阿里云迁移。

- 代码：`/opt/namiya/releases/<release>/`，`/opt/namiya/current` 指向运行版本。
- Python：`/opt/namiya/venv`，依赖版本见 `requirements.lock`。
- 数据：`/var/lib/namiya/worryshop.db`，独立于代码更新。
- 配置及原有加密密钥：`/etc/namiya.env`，root:namiya 0640。
- 服务账号：`namiya`，禁止登录；数据库目录 0700，文件 0600。
- Redis 只监听回环接口；生产限流后端 `redis://127.0.0.1:6379/0`。
- 服务：`namiya.service`，开机自启、进程退出后重启。
- 备份：`namiya-backup.timer`，每天 03:15（服务器时区），补跑错过的任务。
- 备份目录：`/var/backups/namiya`，root 0700；包含数据库、配置/密钥和代码。
  每份成功备份含 `COMPLETE` 文件；当前不自动删除历史备份，应监测磁盘容量。

检查运行：

```sh
sudo systemctl status namiya redis-server namiya-backup.timer
sudo journalctl -u namiya -n 50 --no-pager
curl -I http://127.0.0.1:50000/login
sudo systemctl start namiya-backup.service
```

更新步骤：先备份，将经过测试的代码解压到新的 release 目录并创建空 `instance/`，
使用锁定依赖，保留 `/etc/namiya.env` 和 `/var/lib/namiya/`。在数据库副本上验证
`flask --app run.py init-db`，比较迁移前后记录及解密后内容，再停服务进行正式迁移，
更新 `current` 符号链接并启动、检查服务。不要以 `.env.example` 覆盖生产配置。
`init-db` 不再重置已有账号的密码或权限；显式重置使用 `create-admin`。

恢复时先停止服务，选取含 `COMPLETE` 的备份，同时恢复对应数据库、密钥和代码。
数据库和密钥必须配套，否则应停止恢复；不要生成新密钥替代旧密钥。
恢复数据库至 `/var/lib/namiya/worryshop.db`（namiya:namiya 0600），
恢复配置至 `/etc/namiya.env`（root:namiya 0640），解压代码至新的 release 并切换链接，
检查 SQLite 完整性后重启服务。恢复备份会回退该备份之后的数据，操作前另存当前数据库。
同机备份不能防止整台机器或磁盘丢失，后续云迁移时应增加独立备份。

最初部署前的 `predeploy-*` 备份另外保存了两份原项目（含配置、密钥和 Git 记录）、
四份 SQLite 和 PostgreSQL dump。原 `/home/ubuntu/` 项目及 `/mnt/` 数据库保留，
不再作为新服务的写入位置；不要同时启动旧实例。
