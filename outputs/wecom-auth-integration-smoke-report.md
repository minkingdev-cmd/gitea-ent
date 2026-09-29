# 企业微信 Web 登录与保留认证方式测试报告

测试日期：2026-09-29
测试分支：`enhance/wecom-web-login-only`
测试数据库：SQLite
自动化最终结论：**通过**
真实联调当前结论：**已完成可信 IP、Secret、local-ssl、隔离实例与保留认证方式验证；真实企业微信 OAuth 登录等待用户在企业微信中人工完成**

## 覆盖范围

### 企业微信 Web 登录

新增并执行 `TestEnterpriseWeComLoginOnlyIntegration`：

- 未登录用户访问登录页时仅重定向至配置的企业微信 OAuth source。
- 完整执行企业微信授权发起、state 校验、mock 企业微信 API callback、用户自动创建、身份绑定和 Web session 建立。
- 验证 callback 后可访问登录用户设置页。
- 验证企业微信身份记录已写入数据库。
- 验证本地密码、注册、OpenID、Passkey、账号绑定密码登录/注册、密码找回/重置、账号激活、非企业微信 MFA pending session 和非企业微信 OAuth source 均返回 403。
- 验证 Reverse Proxy header 不会在 login-only 模式下自动建立 Web session。

企业微信 API 使用本地 mock server，未使用真实企业租户凭据。

### 保留的认证方式

新增并执行 `TestEnterpriseWeComLoginOnlySmoke`，通过真实监听端口验证：

- PAT Bearer token 调用 `/api/v1/user`：200。
- Git HTTP Basic + token 读取私有仓库 refs：200。
- SSH key 建立 SSH shell：认证成功。
- 同一运行实例中本地密码 Web 登录：403。
- 同一运行实例中登录页：303 重定向至唯一企业微信 source。

同时执行既有回归测试：

- `TestAPIAuth`：通过。
- `TestAPIDeniesPermissionBasedOnTokenScope`：通过。
- `TestGitSmartHTTP`：通过。
- `TestSSHShellWelcome`：通过。

## 完整 Integration Suite

最终使用以下环境执行完整 SQLite integration suite：

```text
Git LFS 3.8.0
GOTEST_FLAGS=-count=1
make test-integration
```

结果：

```text
PASS
exit code: 0
elapsed: 2078s（约 34 分 38 秒）
```

完整日志保存在 `.work/test-runs/full-integration-final.log`。

## 测试中发现并修复的问题

### Cron API 测试预期过时

新增企业微信目录同步任务后，cron task 总数由 30 变为 31。原测试还固定断言 30，而且默认分页只返回 30 条。

修复：

- 请求 `/api/v1/admin/cron?limit=50`。
- 总数和结果长度均断言为 31。
- 精确复跑 `TestAPICron`：通过。

### 本机 Git LFS 版本过旧

系统 Git LFS 3.3.0 执行 `TestGitLFSSSH` 时回退至 HTTP transport，导致 pure-SSH 路由断言失败。该失败与企业微信认证代码无调用关系。

处理：

- 未修改系统安装。
- 从 Git LFS 官方发布包下载 3.8.0 至工作区 `.work/tools/`。
- 使用 3.8.0 精确复跑 `TestGitLFSSSH`：通过。
- 使用同一 3.8.0 客户端重跑完整 integration suite：通过。

Git LFS 官方当前建议使用 3.7.1 或更高版本。

## 最终静态与单元验证

- `make fmt`：通过。
- 认证相关 Go 包测试：通过。
- `make lint-go`：0 issues。
- `openspec validate wecom-only-web-login --strict`：通过。
- `git diff --check`：通过。

## 真实企业微信联调补充（2026-09-29 14:43 UTC+8）

### 已新增验证

- 用户确认企业微信侧已通过 `gitea.f123.pub` 验证；本轮已将隔离 Gitea `ROOT_URL` 与 local-ssl 路由从 `gitea-ent.f123.pub` 切换到 `gitea.f123.pub`。
- 重新获取公网出口 IP：`149.119.128.127`，记录到 `.work/live-wecom/public-ip.txt`。
- 使用 `.secrets/test.secrets` 中候选参数调用官方 API：两个候选键名 `gettoken` 均成功，`agent/get` 均返回成功并匹配现有 Gitea AgentId；两个候选值实际相同，去重后唯一 Secret 已写入 `.work/live-wecom/corp-secret`。未输出 Secret 或 access token。
- 已部署并验证公网企业微信接收消息 URL 验证端点：`https://wecom-verify-gitea-ent.minkingdev.chatgpt.site/wecom/verify`。当前可信 IP 已解锁，该端点保留作备查。
- local-ssl 已重新 apply/link，并在 dnsmasq reload 未生效时执行 down/up；`gitea.f123.pub` 本机解析到 `127.0.0.1`，证书 SAN 包含该域名。
- 已创建隔离 SQLite Gitea 实例于 `.work/live-wecom/`，内部监听 `127.0.0.1:3004`，`ROOT_URL=https://gitea.f123.pub/`。
- 已创建并启用名称为 `enterprise-wecom`、provider 为 `wecom` 的 OAuth source；真实 Secret 不落库，运行时通过 `CORP_SECRET_URI=file:///.../.work/live-wecom/corp-secret` 引用。
- 已启动隔离实例并验证：
  - `/user/login` 返回 303 到 `/user/oauth2/enterprise-wecom`。
  - `/user/oauth2/enterprise-wecom` 返回 307 到企业微信 OAuth，回调地址为 `https://gitea.f123.pub/user/oauth2/enterprise-wecom/callback`。
  - 本地密码 Web 登录 POST 返回 403。
- 已在隔离实例上验证保留认证方式仍可用：
  - PAT/API token 调用 `/api/v1/user` 返回 200。
  - Git HTTP token 成功 push 并 `ls-remote` 私有测试仓库。
  - SSH key 使用 `ssh://minwang@127.0.0.1:2224/...` 成功 `ls-remote`。
- 已扫描当前 Gitea 运行日志，未发现已知 PAT 明文、企业微信 Secret 明文、`access_token=` 或 `corpsecret` 标记。

### 仍未完成的真实项

- Browser Use 安全策略阻止 agent 直接访问 `work.weixin.qq.com` 和 `open.weixin.qq.com`；真实企业微信 OAuth 登录应在普通浏览器打开 `https://gitea.f123.pub/user/login`，由 Gitea 跳转到企业微信 Web/扫码 OAuth。
- 真实 OAuth 完成后仍需验证自动建号/匹配、WeCom identity 绑定、审计记录是否不泄露 OAuth code/Secret/token。
- 如条件允许，执行一次真实目录同步并验证幂等和对账结果。

## 真实企业微信联调补充（2026-09-29 15:03 UTC+8）

### 本轮真实通过项

- 修正浏览器 OAuth 流程：WeCom provider 不再使用客户端内授权 `open.weixin.qq.com/connect/oauth2/authorize`，改为普通浏览器 Web/扫码 OAuth `login.work.weixin.qq.com/wwlogin/sso/login`，并携带 `login_type=CorpApp`。
- 用户已确认浏览器扫码 OAuth 登录步骤通过。
- 隔离 DB 已出现真实 WeCom 登录用户；`wecom_identity` 与 `external_login_user` 均已绑定到该用户，且外部登录记录未保存 access token/refresh token。
- PAT/API、Git HTTP token、SSH key 在真实登录后仍可用。
- 本地密码 Web 登录 POST 仍为 403。
- 发现并修复 router 请求日志泄露 OAuth callback `code` 的问题；live 假 callback 验证敏感 query 值被记录为 `redacted`。

### 目录同步结果

- 已通过 admin cron API 触发真实 `sync_enterprise_wecom_directory` 两次，结果幂等。
- 当前同步计数：`wecom_identity=1`、`wecom_department=0`、`wecom_tag=1`、`wecom_membership=0`。
- 官方 API 直连确认：`gettoken=0`，`department/list=0` 但部门数量为 0；根部门 `user/simplelist` 和 `user/list` 返回 `60011`；`tag/list=0` 且标签数量为 1。
- 因目录 API 当前没有返回真实登录成员，身份被对账标记为 `out_of_scope`。需要企业微信管理员调整应用通讯录可见范围/接口权限后复测。

### 本轮新增验证命令

- `make fmt`
- `go test ./modules/web/routing/ ./services/auth/source/oauth2/ ./modules/setting/`
- `make lint-go`
- `openspec validate wecom-only-web-login --strict`
- `git diff --check`

### 仍未完成项

- 当前 live 配置未开启 `[audit].RECORD_OUTPUT = database`，因此真实 DB 中没有 WeCom audit 事件；自动化测试已验证 audit 元数据不泄露 Secret/token/code。若要做真实审计记录验收，需要开启 audit 输出并在管理员修复通讯录可见范围后重新登录一次。
