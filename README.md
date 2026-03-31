# 解忧杂货铺

一个基于 Flask + SQLite 的校园心理倾诉项目，面向“来信 / 来电登记 / 店员回复 / 店长管理”场景，支持账号隔离、店员权限审批，以及首页广告轮播和全站主题色切换。

## 当前功能

- 首页支持多图广告轮播、手动切换和自动播放。
- 首页支持主题色切换，当前提供 `星夜月白 / 纸页琥珀 / 晨雾青岚` 三套风格。
- 普通用户可注册、登录、写信、登记电话倾诉，并在自己的信箱查看回信。
- 店长可查看全部来信来电、筛选状态、搜索账号、管理店员、审批或直接授予回复权限。
- 店员可查看全部信件，但仅在获批后才能回复指定信件。
- 来信人与来信人之间严格隔离，普通账号只能访问自己的信件和回复。

## 本地启动

1. 创建虚拟环境并安装依赖：

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

2. 启动服务：

```bash
python app.py
```

3. 浏览器访问：

```text
http://127.0.0.1:50000
```

默认店长账号：

- 用户名：`admin`
- 密码：`admin123`

正式部署前请至少修改：

- `app.py` 中的 `app.secret_key`
- 默认店长密码

## 在 clab / 校园网环境部署

项目默认监听：

```text
0.0.0.0:50000
```

在服务器上执行 `python app.py` 后，只要该端口已放行，就可以通过：

```text
http://<服务器IP>:50000
```

从校园网浏览器访问。

## 广告轮播如何扩展

广告位配置集中在 [app.py](app.py) 的 `PROMO_SLIDES`。

每一项都支持这些字段：

- `label`：缩略选择卡标题
- `eyebrow`：广告小标题
- `title`：主标题
- `description`：说明文字
- `image`：静态图片路径，默认放在 `static/img/promos/`
- `tone`：广告图的风格说明
- `link`：可选跳转链接，不需要可留空
- `link_text`：按钮文案

新增广告图的方式：

1. 把图片放到 `static/img/promos/`
2. 在 `PROMO_SLIDES` 里新增一个字典
3. 刷新首页即可进入轮播和下方选择器

当前已接入的示例图：

- `static/img/promos/c7ba9d7ccb8c822979aa3980c5b53bab.jpg`
- `static/img/promos/c7ba9d7ccb8c822979aa3980c5b53bab-1.jpg`

## 主题色如何调整

主题配置集中在 [app.py](app.py) 的 `THEME_OPTIONS`，具体变量实现写在 [static/css/style.css](static/css/style.css)。

如果要新增主题：

1. 在 `THEME_OPTIONS` 里新增一个 `key / label / description / preview`
2. 在 `style.css` 里增加对应的 `body[data-theme="..."]` 变量块
3. 首页会自动出现新的主题卡片

## 数据与权限说明

- 用户账号存储在 `users` 表
- 来信 / 来电登记存储在 `letters` 表
- 店员 / 店长回复存储在 `replies` 表
- 店员申请回复权限存储在 `reply_requests` 表

权限边界：

- 普通用户：只能查看自己的信件和回复
- 店员：可查看全部，但不能私自回复
- 店长：可查看全部并管理店员权限

## 项目结构

```text
app.py
templates/
static/css/style.css
static/js/home.js
static/img/promos/
worryshop.db
```
