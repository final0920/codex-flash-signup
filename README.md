<p align="center">
  <h1 align="center">Mongoose Svelte</h1>
  <p align="center">
    轻量级 C 后端 + Svelte 前端一体化账号自动化管理平台
  </p>
  <p align="center">
    <a href="#功能特性">功能特性</a> •
    <a href="#快速开始">快速开始</a> •
    <a href="#docker-部署">Docker 部署</a> •
    <a href="#项目结构">项目结构</a> •
    <a href="#api-文档">API 文档</a> •
    <a href="#贡献指南">贡献指南</a>
  </p>
  <p align="center">
    <img src="https://img.shields.io/badge/language-C11-blue?style=flat-square" alt="Language">
    <img src="https://img.shields.io/badge/frontend-Svelte%20%2B%20TypeScript-orange?style=flat-square" alt="Frontend">
    <img src="https://img.shields.io/badge/license-AGPL--3.0-red?style=flat-square" alt="License">
    <img src="https://img.shields.io/badge/platform-Linux%20x86__64-lightgrey?style=flat-square" alt="Platform">
  </p>
</p>

---

## 概述

Mongoose Svelte 是一个基于 [Mongoose](https://github.com/cesanta/mongoose) 嵌入式网络库构建的单体应用，前端使用 Vite + Svelte + TypeScript 开发，编译后打包进可执行文件中，运行时零外部文件依赖。

核心能力包括：账号批量注册与 OAuth 授权、代理池管理与健康检测、邮箱验证码自动收取，以及通过 WebSocket 实时推送任务状态。

## 功能特性

| 模块 | 说明 |
|------|------|
| **控制台** | 实时监控 CPU、内存、存储、网络和 SQLite 数据库状态 |
| **代理池** | 管理 HTTP/SOCKS5/SOCKS5H 代理，批量导入与健康检测 |
| **邮件配置** | 对接 Rapid-Inbox 或 OTPRelay C 邮箱服务，管理可用邮箱域名规则 |
| **账号管理** | 查看账号状态与凭证，执行 OAuth、Token 刷新、上传和删除 |
| **注册工作台** | 批量/无限注册任务，支持常规与高速调度模式，WebSocket 实时日志 |

**技术亮点：**

- 单一可执行文件部署，前端资源通过 `mg_fs_packed` 内嵌
- `curl-impersonate` 浏览器指纹模拟，支持多版本 TLS 指纹选择
- 通用流程状态机 + Provider 架构，易于扩展新注册方式
- SQLite 触发器维护统计表，千万级账号下页面秒开
- 双链路 OAuth 竞速验证码，提升成功率
- 深色/浅色主题切换

## 环境要求

- Linux x86_64（推荐 Debian/Ubuntu 或 Arch Linux）
- GCC（支持 C11）
- libcurl 开发库
- SQLite3 开发库
- Node.js 18+（构建前端）
- Python 3（资源打包脚本）

## 快速开始

### 编译

```bash
make
```

### 运行

首次启动需通过环境变量创建管理员账号：

```bash
APP_ADMIN_USER=admin APP_ADMIN_PASSWORD='your-strong-password' ./build/mongoose-svelte
```

账号写入 `data/app.db` 后，后续启动无需再携带密码环境变量。

访问 http://127.0.0.1:8000 进入控制台。

### 开发模式

```bash
make run
```

每次执行会生成随机管理员密码并重置本地数据库，方便调试。

### 自定义监听地址

```bash
./build/mongoose-svelte http://0.0.0.0:9000
```

## Docker 部署

### 使用 Docker Compose（推荐）

```bash
cp .env.docker.example .env.docker
# 编辑 .env.docker，至少修改 APP_ADMIN_PASSWORD
docker-compose --env-file .env.docker up -d --build
```

### 使用 docker run

```bash
docker build --platform linux/amd64 -t mongoose-svelte:local .
docker volume create mongoose-data
docker run -d --name mongoose-svelte \
  --platform linux/amd64 \
  -p 8000:8000 \
  -v mongoose-data:/app/data \
  -e APP_ADMIN_USER=admin \
  -e APP_ADMIN_PASSWORD='your-strong-password' \
  mongoose-svelte:local
```

### 环境变量

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `APP_ADMIN_USER` | 管理员用户名 | — |
| `APP_ADMIN_PASSWORD` | 管理员密码 | — |
| `APP_COOKIE_SECURE` | Cookie 启用 Secure 标记 | `0` |
| `APP_TRUST_PROXY` | 信任 X-Forwarded-For | `0` |
| `APP_AUTH_DISABLED` | 关闭鉴权（仅调试） | `0` |

> **平台说明：** Docker 镜像按 `linux/amd64` 构建，适用于 x86_64 Linux 服务器。Apple Silicon / ARM 需要 Docker 的 amd64 模拟支持。

## 生产部署建议

- 程序监听 `127.0.0.1:8000`，前置 Caddy 或 Nginx 处理 HTTPS 反向代理
- 设置 `APP_COOKIE_SECURE=1` 启用安全 Cookie
- 设置 `APP_TRUST_PROXY=1` 获取真实客户端 IP
- 使用 volume 持久化 `/app/data`（Docker）或 `data/` 目录

## 项目结构

```
mongoose-svelte/
├── src/                          # C 后端源码
│   ├── main.c                    # 入口
│   ├── auth/                     # 登录鉴权
│   ├── account/                  # 账号存储与 Token 校验
│   ├── proxy/                    # 代理池管理
│   ├── mail/                     # Rapid-Inbox 邮件对接
│   ├── http_client/              # libcurl 请求与浏览器画像
│   ├── identity/                 # 注册身份生成器
│   ├── flow/                     # 流程状态机与 curl-impersonate 执行器
│   ├── registration/             # 注册任务调度
│   ├── oauth/                    # OAuth Provider
│   └── upload/                   # 账号上传
├── web/                          # Svelte + TypeScript 前端
│   └── src/
│       ├── components/           # 通用 UI 组件
│       └── pages/                # 页面组件
├── third_party/mongoose/         # 内置 Mongoose 网络库
├── tools/pack_assets.py          # 静态资源打包脚本
├── docker/                       # Docker 入口脚本
├── Dockerfile
├── docker-compose.yml
└── Makefile
```

## API 文档

所有 `/api/*` 接口（除 `/api/auth/*`）和 WebSocket `/ws` 均需有效登录会话。

### 认证

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/auth/me` | 查看当前登录状态 |
| POST | `/api/auth/login` | 管理员登录 |
| POST | `/api/auth/logout` | 退出登录 |

### 系统

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/status` | 服务状态与系统资源 |
| WS | `/ws` | 订阅系统状态推送 |

### 代理池

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/proxies` | 查看代理列表 |
| POST | `/api/proxies/import` | 批量导入代理 |
| POST | `/api/proxies/test` | 批量测试代理 |
| POST | `/api/proxies/delete` | 删除代理 |
| GET | `/api/proxies/mihomo` | 查看 Clash/mihomo 代理运行时配置 |
| POST | `/api/proxies/mihomo` | 保存 Clash/mihomo 代理运行时配置 |
| POST | `/api/proxies/mihomo/start` | 生成订阅代理组配置并启用 mihomo 代理 |
| POST | `/api/proxies/mihomo/stop` | 停止托管 mihomo 并切回代理池 |
| GET | `/api/proxies/mihomo/nodes` | 读取订阅组中的可选节点 |
| POST | `/api/proxies/mihomo/select` | 切换手动指定的订阅节点 |
| POST | `/api/proxies/mihomo/sample` | 通过 mihomo 入口采样出口 IP |

### 邮件

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/mail/config` | 查看邮件配置 |
| POST | `/api/mail/config` | 保存邮件配置，支持 `backend=rapid_inbox|otprelay` 与 `transport=http|ws` |
| POST | `/api/mail/domains` | 添加域名规则 |
| POST | `/api/mail/domains/delete` | 删除域名规则 |
| POST | `/api/mail/fetch` | 读取验证码/邮件 |

### 账号

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/accounts/summary` | 账号统计概览 |
| GET | `/api/accounts` | 分页查询账号列表 |
| GET | `/api/accounts/detail` | 账号详情（含 Token） |
| POST | `/api/accounts/action` | 执行 OAuth/刷新/上传/删除 |

### 注册工作台

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/registration/status` | 工作台状态 |
| POST | `/api/registration/start` | 创建注册任务 |
| POST | `/api/registration/stop` | 停止任务 |
| GET | `/api/registration/tasks` | 任务列表 |
| GET | `/api/registration/task` | 任务详情与日志 |
| WS | `/ws` | 订阅任务日志推流 |

`POST /api/registration/start` 使用 `workflow=register_then_current_codex` 时可传 `current_session_oauth_fallback=false` 或 `current_session_oauth_fallback_mode=none` 关闭失败兜底；开启时可用 `current_session_oauth_fallback_mode` 选择策略：`single` 单路 OAuth、`double` 双 OAuth 抢码、`single_timeout_retry` 单路 OAuth 超过 `current_session_oauth_retry_after_seconds` 秒未收到验证码后立即触发第二次 OAuth（第二次邮箱验证码超时固定 30 秒）。遇到 `phone_binding_required` 仍会直接结束。

注册后执行 OAuth 的任务可传 `discard_oauth_failed_accounts=true`，OAuth 最终失败时会移除本次新注册入库的账号；账号池 OAuth 任务不会删除既有账号。也可传 `save_oauth_failed_accounts=false` 表达同一语义。

开启 `auto_upload_oauth_success=true` 后，可传 `auto_upload_service_mode=random` 让任务创建时随机绑定一个已启用的 Aether 上传服务，或传 `auto_upload_service_mode=fixed` + `auto_upload_service_id` 固定使用某个上传服务；`auto_upload_service_mode=all` 保留上传到全部启用服务的旧行为。

启用 Mihomo 代理模式后，发布注册任务可传 `mihomo_node` 指定本任务使用的订阅节点；留空时系统会从当前订阅节点中随机绑定一个。该选择只作用于当前任务，不会切换代理池页面的全局手动节点；如果指定节点不存在或未参与当前节点组，任务创建会直接返回 `400`。

## 代理格式

支持以下格式，每行一个：

```
http://127.0.0.1:8080
http://user:pass@127.0.0.1:8080
socks5://127.0.0.1:1080
socks5h://user:pass@example.com:1080
```

## Clash / mihomo 代理运行时

代理池页面支持将业务请求切换到外接或托管的 mihomo 入口。托管模式可使用订阅链接，也可直接粘贴 Clash/mihomo YAML 订阅文本；系统会生成 `data/mihomo/config.yaml`，并通过 `proxy-providers` 读取订阅。节点模式默认为 `load-balance` + `round-robin`，也可以切换为 `select` 手动指定订阅中的某个节点；节点过滤与排除过滤会写入 provider，用于限制参与均衡或可选的节点集合。业务侧仍然只使用普通 HTTP 代理入口，默认是：

```
http://127.0.0.1:7890
```

托管配置还会预置一组注册任务专用 Mihomo 入站端口，每个任务会绑定自己的策略组。注册任务指定 `mihomo_node` 时使用该节点；未指定时随机选择一个订阅节点，因此任务级节点选择不会和全局入口或其他任务互相抢节点。

Docker 镜像内置 `mihomo` 二进制。非 Docker 部署时，请确保 `mihomo` 在 `PATH` 中，或在代理池页面填写实际核心路径。

## 许可证

本项目基于 [GNU Affero General Public License v3.0](LICENSE) 开源。

## 贡献指南

欢迎贡献代码！请阅读 [CONTRIBUTING.md](CONTRIBUTING.md) 了解详情。

## 安全问题

如果发现安全漏洞，请参阅 [SECURITY.md](SECURITY.md) 了解报告流程。
