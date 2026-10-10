# NodePure

[English](README_EN.md) · [贡献指南](CONTRIBUTING.md) · [安全说明](SECURITY.md)

通过独立 Mihomo 实例批量检测代理节点的出口 IP、归属信息、HTTP 延迟和网站连通性。Go 后端内嵌网页，无需 Node.js、CDN 或前端构建步骤。

**结果的边界：** 当前没有接入商业风险数据库，风险分数、原生性、Anycast 均显示“未知/未测量”。ISP 名称只能提供住宅/机房的推测线索。ChatGPT、Claude、YouTube 结果是网页 HTTP 连通性，不代表 API 权限、账号可用性、播放区域或流媒体解锁。403/451 可能包含验证页，429 表示限流；结果具有时间性，不作账号或节点质量保证。

## 功能

- Clash YAML、Base64 订阅及 SS、Trojan、VMess、VLESS、Hysteria2、HTTP(S)、SOCKS5 URI；常用 TLS、SNI、WS、gRPC、Reality 参数。
- 每个节点使用独立、需要认证的回环监听端口；配置不改变系统代理、路由或 DNS。
- 全局探测并发预算、有限任务队列、取消和截止时间；重连可重放 SSE，快照恢复漏收结果。
- 任务按浏览器会话隔离；JSON/SSE 不包含节点密码或原始配置；仅显式 Clash 导出包含凭据。
- CSV 导出、分页和筛选；纯净度评分筛选不会接纳未知结果。
- 订阅获取默认拒绝本机、内网、保留地址，并检查 DNS、重定向和响应大小。

## 本机运行

需要 Go **1.26+** 以及 [Mihomo 官方发行版](https://github.com/MetaCubeX/mihomo/releases)。本项目已用 Mihomo v1.19.32 完成隔离集成测试。自行安装对应操作系统/架构的内核到 `bin/mihomo`（Windows 为 `bin/mihomo.exe`），或设置 `MIHOMO_BIN`。Linux 上需要执行权限。NodePure 不捆绑 Mihomo，请遵守其 GPL-3.0 许可证。

```sh
git clone https://github.com/2089887529/NodePure.git
cd NodePure
go build -trimpath -o nodepure ./cmd/server
./nodepure
```

Windows PowerShell 使用 `go build -trimpath -o nodepure.exe ./cmd/server` 和 `./nodepure.exe`。默认只监听 `http://127.0.0.1:8099`，本机模式自动签发浏览器会话。

缺少内核时不会下载未经校验的可执行文件。可选自动下载仅支持固定 v1.19.32：设置 `MIHOMO_SHA256` 为对应官方压缩包的、经可信渠道核对的 SHA-256。名称为 `mihomo-<os>-<arch>-v1.19.32.gz`，Windows 为 `.zip`。哈希校验、大小限制、原子替换和下载互斥均开启；不要用尚未验证的下载文件自己计算哈希后冒充可信校验。

输入订阅或粘贴配置后开始检测。任务和凭据只存于进程内存，任务完成一小时后清理；重启会丢失任务及登录会话。临时内核目录采用限制权限，任务结束时删除。不要把真实订阅或导出的 Clash 文件提交到 Git。

## 局域网和自托管

面向可信个人/管理员使用，不是开放给匿名用户的公共代理检测平台。节点本身可指定服务器及协议选项；订阅下载的 SSRF 限制不等于对用户提交的全部代理配置进行沙箱隔离。公共多租户服务需要另行实现租户身份、配额和操作系统级网络/文件隔离。

监听非回环地址必须配置密码哈希文件。下面通过隐藏输入将密码直接传给生成器，不放入命令参数、环境变量或历史记录；生成器不会覆盖已有文件。

```sh
python3 -c 'import getpass,sys; sys.stdout.write(getpass.getpass())' | ./nodepure --set-password password.hash
NODEPURE_HOST=0.0.0.0 NODEPURE_PASSWORD_HASH_FILE=./password.hash ./nodepure
```

Windows PowerShell：

```powershell
python -c 'import getpass,sys; sys.stdout.write(getpass.getpass())' | ./nodepure.exe --set-password password.hash
$env:NODEPURE_HOST = '0.0.0.0'
$env:NODEPURE_PASSWORD_HASH_FILE = './password.hash'
./nodepure.exe
```

密码要求 12–72 **UTF-8 字节**，请使用 ASCII 密码以避免旧版 PowerShell 管道编码差异。保护哈希文件的访问权限。仅通过 SSH 隧道、私有网络或 HTTPS 反向代理访问，勿把明文登录端口直接暴露互联网。反向代理需保留 `Host` 和 `Origin`，设置 `NODEPURE_PUBLIC_ORIGIN=https://你的域名`，并关闭 SSE 缓冲、给予超过 30 秒的读取超时。公开来源配置会启用 Secure Cookie 和精确 HTTPS 同源检查，勿信任外部转发头（见 [SECURITY.md](SECURITY.md)）。

| 环境变量 | 默认值 / 含义 |
| --- | --- |
| `NODEPURE_HOST`, `NODEPURE_PORT` | `127.0.0.1`, `8099` |
| `MIHOMO_BIN` | `./bin/mihomo`，Windows 自动加 `.exe` |
| `MIHOMO_SHA256` | 空；可选固定版本压缩包可信校验值 |
| `NODEPURE_PASSWORD_HASH_FILE` | 空；非回环监听必填 |
| `NODEPURE_ALLOWED_HOSTS` | 逗号分隔的精确域名，不含协议或端口 |
| `NODEPURE_PUBLIC_ORIGIN` | 空；HTTPS 反向代理的完整来源，如 `https://nodes.example.com` |
| `SUBSCRIPTION_ALLOWLIST` | 空；按主机名明确允许访问私有订阅地址，慎重设置 |
| `MAX_CONCURRENCY` | 20，范围 1–64，全局节点并发 |
| `MAX_NODES` | 500，范围 1–1000，含无效条目 |
| `MAX_TASKS` | 50，范围 1–200 |
| `MAX_ACTIVE_TASKS`, `QUEUE_SIZE` | 2 / 4，范围 1–4 / 1–20 |

输入/订阅限制 2 MiB，任务含排队最多 20 分钟。元数据查询只走 HTTPS；相同出口 IP 缓存 10 分钟、失败短暂缓存，查询并发 2、启动频率每秒最多 2 次。浏览器本地存储只保留主题及最后任务 ID。

## Docker

将经过核对的 **Linux** Mihomo 放入 `bin/mihomo`，`chmod 755 bin/mihomo`。Compose 默认仅映射宿主机回环端口，容器以 UID 10001 运行、只读文件系统、限制内存及进程数。密码保存在命名卷，不纳入构建。

```sh
docker compose build
python3 -c 'import getpass,sys; sys.stdout.write(getpass.getpass())' | docker compose --profile tools run --rm -T password
docker compose up -d nodepure
```

随后访问 `http://127.0.0.1:8099` 并登录。通过 SSH 隧道访问远程部署。修改密码时停止目标 NodePure、备份原哈希并更换卷中的文件；现有会话须通过重启撤销。回滚使用旧源码重新构建镜像，保留密码卷；无需更改系统代理。

## API 与开发

会话接口 `GET /api/auth/session`；登录 `POST /api/auth/login`；检测 `POST /api/check`（`url` 或 `content`，可选 `concurrency`）；任务 `GET /api/task/:id`；列表 `GET /api/tasks?page=1&limit=20`；SSE `GET /api/stream/:id`（`Last-Event-ID` 或 `?after=`）；取消 `POST /api/task/:id/cancel`；删除 `DELETE /api/task/:id`；导出 `GET /api/export/csv/:id`、`POST /api/export/clash`。修改请求须有 `X-NodePure: 1`。保存并携带会话 Cookie，任务只能由原会话访问。

```sh
go test ./...
go test -race ./...
go vet ./...
node --test web/test/*.test.cjs
NODEPURE_TEST_MIHOMO=/absolute/path/to/mihomo go test ./pkg/core -run TestRealMihomoLifecycle -v
```

GitHub Actions 检查 Go 测试、竞态、格式、静态分析、前端测试和多平台编译；手动 Release workflow 构建二进制与 SHA-256 清单为工作流附件，审查后再创建正式 Release。真实内核测试没有提供环境变量时明确跳过。

## 许可证

NodePure 使用 [MIT](LICENSE)。Mihomo 为独立外部程序，许可证见 [其仓库](https://github.com/MetaCubeX/mihomo/blob/Meta/LICENSE)。第三方 Go 依赖保留各自许可证。本仓库没有承诺商业风险评分或官方 AI 服务解锁能力。
