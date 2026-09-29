# 企业微信真实联调状态交接

更新时间：2026-09-29 14:43（UTC+8）
仓库：`/Users/minwang/Projects/gitea-ent`
当前分支：`enhance/wecom-web-login-only`

## 1. 当前结论

代码层面的企业微信唯一 Web 登录、保留 SSH/PAT/API Token/Git HTTP Token、SQLite integration suite 和隔离实例真实 HTTP/SSH 冒烟均已通过。真实企业微信租户联调已推进到：

- 用户确认 `gitea.f123.pub` 已在企业微信侧验证通过。
- 当前公网出口 IP 已重新获取并记录为 `149.119.128.127`。
- 官方 API `agent/get` 已不再返回可信 IP 阻塞；两个候选键名均匹配现有 Gitea AgentId，且两个候选值实际相同，因此已去重后写入唯一真实 Secret 到 `.work/live-wecom/corp-secret`。
- 隔离 Gitea 已切换到 `ROOT_URL=https://gitea.f123.pub/`，内部监听 `127.0.0.1:3004`，local-ssl 证书和反向代理已验证。
- `enterprise-wecom` OAuth source 已创建并启用，`LOGIN_ONLY=true` 已生效。
- PAT/API、HTTPS Git token、SSH 均已在隔离实例上实测仍可用。

当前剩余阻塞只是真实企业微信 OAuth 通过普通浏览器打开 Gitea 登录页并跳转到企业微信 Web/扫码 OAuth 完成。Browser Use 安全策略阻止 agent 直接操作 `work.weixin.qq.com` 和跳转 `open.weixin.qq.com`，不得绕过该策略。

> 注意：原计划域名是 `gitea-ent.f123.pub`，但本轮用户确认通过的是 `gitea.f123.pub`。当前本地 `ROOT_URL`、local-ssl、OAuth redirect 均已按最新用户确认切换到 `gitea.f123.pub`。如必须回到 `gitea-ent.f123.pub`，需要先在企业微信后台重新通过该精确域名的校验。

## 2. 企业微信后台与 API 状态

| 项目 | 当前状态 |
|---|---|
| 企业 | 上海六方云信息技术有限公司 |
| 自建应用 | 已复用现有 `Gitea` 应用，没有创建重复应用 |
| AgentId / CorpID | 已保存在 `.secrets/test.secrets`，不要输出或提交 |
| Secret | 候选值已由管理员写入 `.secrets/test.secrets`；两个候选键名的值相同 |
| 应用可见范围 | 后台可见范围包含当前管理员“王敏” |
| 企业微信授权登录 | 已启用 Web 网页登录 |
| 当前实测授权回调域 | `gitea.f123.pub` |
| 企业可信 IP | 已解锁；`agent/get` 返回成功并匹配当前 Gitea AgentId |
| 当前公网出口 IP | `149.119.128.127`（2026-09-29 14:43 重新获取） |

敏感参数文件：

`/Users/minwang/Projects/gitea-ent/.secrets/test.secrets`

该文件权限为 `0600`，受 `.secrets/` 忽略规则保护。不得在聊天、日志、命令行参数、交接文档或提交中输出实际 Secret、access token、OAuth code 或其他敏感值。

官方 API 验证输出保存在受保护工作区：

- `.work/live-wecom/public-ip.txt`：当前公网出口 IP。
- `.work/live-wecom/secret-candidate-check.json`：只记录候选键名、`gettoken_errcode`、`agent_get_errcode` 与 AgentId 是否匹配，不包含 Secret 或 access token。
- `.work/live-wecom/match-and-write-secret.out`：只记录匹配候选键名、去重数量和写入文件路径。

本轮结论：`SecretID` 与 `SecretKey` 两个候选键名均匹配，且值相同；去重后唯一 Secret 已写入：

`/Users/minwang/Projects/gitea-ent/.work/live-wecom/corp-secret`

该文件权限为 `0600`，通过 `CORP_SECRET_URI=file:///.../.work/live-wecom/corp-secret` 引用，未写入 Git diff、CLI 参数或报告正文。

企业微信管理后台应用详情 URL 为：

`https://work.weixin.qq.com/wework_admin/frame#/apps/modApiApp/5629502316791293`

重新绑定/打开后台时被 Browser Use 站点安全策略拒绝；后续后台状态仍需管理员人工确认。

## 3. local-ssl 当前状态

当前本地域名：

`https://gitea.f123.pub/`

当前仓库路由文件：

`/Users/minwang/Projects/gitea-ent/local-ssl.tsv`

当前内容：

```text
# domain	path	proto	upstream
gitea.f123.pub	/	http	127.0.0.1:3004
```

已执行并验证：

```bash
LOCAL_SSL_EXTRA_BASE_DOMAINS=f123.pub "$HOME/Projects/maintenance/scripts/local-ssl.sh" link "$PWD/local-ssl.tsv" --name gitea-ent
LOCAL_SSL_EXTRA_BASE_DOMAINS=f123.pub "$HOME/Projects/maintenance/scripts/local-ssl.sh" down
LOCAL_SSL_EXTRA_BASE_DOMAINS=f123.pub "$HOME/Projects/maintenance/scripts/local-ssl.sh" up
sudo dscacheutil -flushcache
sudo killall -HUP mDNSResponder
```

验证结果：

- nginx 与 dnsmasq 均运行中。
- `gitea.f123.pub` 通过系统解析到 `127.0.0.1`。
- mkcert 证书 SAN 包含 `gitea.f123.pub`，有效期至 2028-12-29。
- `https://gitea.f123.pub/user/login` 返回 303 到 `/user/oauth2/enterprise-wecom`。
- `/user/oauth2/enterprise-wecom` 返回 307 到企业微信 OAuth，redirect URI 为 `https://gitea.f123.pub/user/oauth2/enterprise-wecom/callback`。
- 本地密码 Web 登录 POST 返回 403。

以后每次 apply/link 都必须带上：

```bash
export LOCAL_SSL_EXTRA_BASE_DOMAINS=f123.pub
"$HOME/Projects/maintenance/scripts/local-ssl.sh" link "$PWD/local-ssl.tsv" --name gitea-ent
```

如果 `status` 显示 `gitea.f123.pub` 仍解析到公网地址，按本轮处理经验需要用同一环境变量执行 `down` / `up`，然后刷新 macOS DNS 缓存。

## 4. 隔离 Gitea 实例状态

本轮已在 `.work/live-wecom/` 创建隔离 SQLite 实例，未修改仓库默认开发数据库或默认 `custom/conf/app.ini`：

| 项目 | 状态 |
|---|---|
| `.work/live-wecom/app.ini` | 已创建，权限 `0600` |
| 独立 SQLite 数据库 | `.work/live-wecom/gitea.db` |
| 本地管理员 | 已创建；随机密码只保存在权限 `0600` 的 `.work/live-wecom/admin-user-create.log` |
| `enterprise-wecom` OAuth source | 已创建并启用，provider 为 `wecom` |
| 真实 Secret 单值文件 | `.work/live-wecom/corp-secret`，权限 `0600`，已写入唯一匹配 Secret |
| Gitea HTTP | 当前进程 PID `90771`，监听 `127.0.0.1:3004` |
| Gitea SSH | 监听 `127.0.0.1:2224`；当前实例 SSH 用户为运行用户 `minwang` |
| `LOGIN_ONLY=true` | 已生效 |
| 真实 OAuth 浏览器登录 | 尚需用户人工完成 |
| 自动创建/匹配企业微信用户 | 待真实 OAuth 后验证 |
| 真实目录同步 | 尚未执行；待真实身份验证后按条件执行 |

关键运行配置：

```ini
[server]
DOMAIN = gitea.f123.pub
HTTP_ADDR = 127.0.0.1
HTTP_PORT = 3004
ROOT_URL = https://gitea.f123.pub/
PROTOCOL = http
START_SSH_SERVER = true
SSH_PORT = 2224

[enterprise.wecom]
ENABLED = true
LOGIN_ONLY = true
LOGIN_SOURCE_NAME = enterprise-wecom
CORP_SECRET_URI = file:///Users/minwang/Projects/gitea-ent/.work/live-wecom/corp-secret
```

当前 Gitea 是在 Codex 工具前台会话中运行的；如进程退出，可从仓库根目录重启：

```bash
./gitea --work-path "$PWD" \
  --custom-path "$PWD/.work/live-wecom/custom" \
  --config "$PWD/.work/live-wecom/app.ini" web
```

也可用 `.work/live-wecom/start-gitea.sh` 尝试后台启动，但本轮更可靠的方式是保持前台会话运行。

## 5. 已完成的隔离实例真实冒烟

已在 `https://gitea.f123.pub/` 隔离实例上验证：

- PAT/API token：使用 CLI 为本地管理员生成独立 PAT，调用 `/api/v1/user` 返回 200，登录用户为 `live-admin`。
- Git HTTP token：通过 `GIT_ASKPASS` 从权限 `0600` 文件读取 PAT，未把 token 写入远程 URL 或命令行；成功 push 到私有测试仓库并 `git ls-remote`。
- SSH：通过 API 添加临时 SSH 公钥，使用内置 SSH 服务 `ssh://minwang@127.0.0.1:2224/live-admin/<repo>.git` 成功 `git ls-remote`。注意当前配置要求 SSH 用户为运行用户 `minwang`，不是 `git`。
- Web 登录唯一性：`/user/login` 只跳转到 `enterprise-wecom`，本地密码 POST 返回 403。
- 日志敏感信息快扫：`gitea-live.log` 未包含已知 PAT 明文、企业微信 Secret 明文、`access_token=` 或 `corpsecret` 标记。

测试仓库和临时 token/key 文件均位于 `.work/live-wecom/` 或隔离 SQLite DB，不应提交。

## 6. 公网企业微信接收消息 URL 端点

为解决可信 IP 前置，本轮曾部署一个公网 HTTPS URL 验证端点；当前可信 IP 已解锁，但端点可保留作备查：

- URL：`https://wecom-verify-gitea-ent.minkingdev.chatgpt.site/wecom/verify`
- Token 与 EncodingAESKey：保存在 `.work/live-wecom/wecom-receive-url.env`，权限 `0600`，不要提交或贴到公开报告。
- 端点源码和 Sites 项目文件在 `.work/live-wecom/wecom-callback-site/`，不应提交。
- 已将 Sites 访问设置为 public，因为企业微信服务器必须能公网访问。
- 已通过本地构造的企业微信 `msg_signature/timestamp/nonce/echostr` 向公网 URL 发起验证请求，使用 `Mozilla/5.0`、`MicroMessenger`、`WeCom` 三种 User-Agent 均返回预期明文。

本地 `f123.pub` 只在当前机器由 dnsmasq 解析，企业微信服务器无法访问，因此不能直接承担这个公网验证端点。

## 7. 当前仍需人工完成的验证

1. 在普通浏览器中打开：

   `https://gitea.f123.pub/user/login`

2. 完成企业微信授权登录。若出现扫码、确认或管理员二次确认，请用户接管浏览器。
3. 登录完成后回到本机验证：
   - 是否成功进入 Gitea。
   - 是否自动创建或匹配用户。
   - WeCom identity 是否正确绑定。
   - 日志/审计记录是否未泄露 OAuth code、Secret、token 等敏感信息。
   - 如条件允许，执行一次真实目录同步并验证幂等和对账结果。

## 8. 代码与测试工作区状态

当前分支：`enhance/wecom-web-login-only`。工作区仍有未提交的唯一 Web 登录加固和 integration 测试改动，包括：

- `routers/web/auth/*`：禁用密码、OpenID、Passkey、账号绑定、恢复密码等替代 Web 登录入口，并仅允许 WeCom OAuth 后续 MFA。
- `routers/web/web.go`、`routers/web/web_test.go`：禁用 reverse-proxy 与 SSPI 自动 Web 登录。
- `tests/integration/enterprise_wecom_auth_test.go`：企业微信唯一登录、PAT、Git HTTP、SSH 的真实服务集成/冒烟覆盖。
- `tests/integration/api_admin_test.go`：适配新增 WeCom cron task 和分页。
- OpenSpec 与实施文档更新。
- `outputs/wecom-auth-integration-smoke-report.md`：测试报告。
- `local-ssl.tsv`：本次新增/更新，尚未提交。

完整 SQLite integration suite 已使用工作区 Git LFS 3.8.0 通过。最终日志：

`/Users/minwang/Projects/gitea-ent/.work/test-runs/full-integration-final.log`

提交前必须重新检查完整状态和差异，不要把 `.secrets/`、`.work/` 或 `.manus/` 纳入提交。

## 9. 安全注意事项

不要输出 `.secrets/test.secrets` 的值，不要输出 access token，不要把 Secret、OAuth code 或 token 放在命令行参数、Git diff、测试报告或日志中。企业可信 IP 属于当前动态公网出口；如果出口 IP 变化，应先重新获取并更新白名单。不要删除或重建现有 Gitea 企业微信应用，也不要重置 Secret，除非用户明确要求。

## 10. 最新进展（2026-09-29 15:03 UTC+8）

本轮已修正并验证真实浏览器 OAuth 流程：

- 根因：原 WeCom provider 使用 `open.weixin.qq.com/connect/oauth2/authorize`，这是企业微信客户端内网页授权端点；普通浏览器会提示“请在企业微信客户端打开链接”。
- 修复：默认 `OAUTH_BASE_URL` 改为 `https://login.work.weixin.qq.com`，授权 URL 改为 `/wwlogin/sso/login`，并携带 `login_type=CorpApp`、CorpID、AgentId、redirect URI 和 state。
- 已重建并重启隔离实例，实测 `/user/oauth2/enterprise-wecom` 跳转到 `https://login.work.weixin.qq.com/wwlogin/sso/login?...login_type=CorpApp...`。
- 用户确认该浏览器扫码 OAuth 步骤已测试通过。

真实登录产物已核验：

- 隔离 DB 中已有 2 个用户：`live-admin` 和 1 个真实 WeCom 登录创建/绑定用户。
- `wecom_identity` 已写入 1 条记录，绑定到真实 WeCom 登录用户，`corp_id`、`wecom_userid`、`external_id` 均存在，`last_login_unix` 已记录。
- `external_login_user` 已写入对应 OAuth 外部身份记录，未保存 access token 或 refresh token。
- `enterprise-wecom` OAuth source 仍为 active，provider 配置包含 `wecom`。

保留认证方式已在真实登录后再次回归：

- PAT/API token 调用 `/api/v1/user` 返回 200。
- Git HTTP token 对私有测试仓库 `ls-remote` 成功。
- SSH key 通过 `ssh://minwang@127.0.0.1:2224/...` 对私有测试仓库 `ls-remote` 成功。
- 本地密码 Web 登录 POST 仍返回 403。

本轮还发现并修复一个日志敏感信息问题：

- 真实 callback 后，通用 `HTTPRequest` router 日志原先会记录 callback query 中的 OAuth `code`。
- 已新增 `modules/web/routing/logger_test.go`，并在 `modules/web/routing/logger.go` 中对敏感 query key 做脱敏，包括 `code`、`access_token`、`corpsecret`、`token`、`secret` 等。
- live 实例用假 callback 验证：日志只记录 `code=redacted`、`access_token=redacted`、`corpsecret=redacted`，原值未出现。

真实目录同步已执行并复跑验证幂等：

- 通过 admin cron API 触发 `sync_enterprise_wecom_directory` 两次，执行次数增加到 2。
- 同步表计数保持稳定：`wecom_identity=1`、`wecom_department=0`、`wecom_tag=1`、`wecom_membership=0`。
- 官方目录 API 直连确认当前应用凭据可 `gettoken`，但 `department/list` 返回 0 个部门，`user/simplelist` 与 `user/list` 对根部门返回 `60011`，`tag/list` 返回 1 个标签。
- 因当前应用通讯录可见范围/接口权限未返回该真实登录成员，已登录身份被目录对账标记为 `out_of_scope`。这不是本地解析错误，需要企业微信管理员调整应用可见范围或通讯录 API 权限后，再重新同步和重新登录验证。

已执行验证：

- `make fmt`
- `go test ./modules/web/routing/ ./services/auth/source/oauth2/ ./modules/setting/`
- `make lint-go`
- `openspec validate wecom-only-web-login --strict`
- `git diff --check`

当前真实联调剩余阻塞：

1. 企业微信管理员需确认现有 `Gitea` 自建应用的通讯录可见范围和通讯录接口权限，使目录 API 能返回当前登录成员。
2. 调整后重新触发 `sync_enterprise_wecom_directory`，确认真实成员不再被标记为 `out_of_scope`。
3. 若需要“真实审计记录”验收，需要在隔离实例 `[audit] RECORD_OUTPUT = database` 下重新登录一次；当前 live 配置未开启 audit 输出，自动化测试已覆盖 WeCom audit 元数据不泄露 Secret/token/code。
