# Enterprise WeCom 合并前阻塞项代码修复方案

日期：2026-09-29
目标变更：`openspec/changes/wecom-only-web-login`
范围：只解决当前四个合并阻塞项，不扩展 repo action、feature grant 或 merge gate。

## 1. 总体设计

本轮采用以下原则：

1. **配置是 WeCom 应用凭据的唯一来源**：CorpID、AgentID、secret 不重复持久化到 OAuth source。
2. **登录源必须唯一且可识别**：配置显式指定一个 OAuth source name，避免“任意 provider=wecom 的 source 都可登录”。
3. **三层防护**：provider 列表过滤、Web 路由拒绝、业务 service 防御性拒绝。
4. **login-only 启动失败优于运行后锁死**：仅在 `ENABLED=true && LOGIN_ONLY=true` 时要求唯一配置源有效；canary 模式不阻塞启动。
5. **复用 Gitea cron**：目录同步使用 `services/cron.RegisterTaskFatal`，直接获得管理页、手动触发、执行计数、最后运行时间和多实例全局锁。
6. **错误边界不携带敏感 URL**：WeCom client 对上只返回结构化、安全错误，不返回底层 `url.Error`。

建议新增配置：

```ini
[enterprise.wecom]
ENABLED = false
LOGIN_ONLY = true
LOGIN_SOURCE_NAME = enterprise-wecom
CORP_ID =
AGENT_ID =
CORP_SECRET_URI =
HTTP_TIMEOUT = 15s
```

同步调度改用标准 cron 配置：

```ini
[cron.sync_enterprise_wecom_directory]
ENABLED = true
RUN_AT_START = false
NOTICE_ON_SUCCESS = false
SCHEDULE = @every 10m
```

当前尚未合并，因此建议移除 `[enterprise.wecom].SYNC_INTERVAL`，避免与 cron `SCHEDULE` 形成两个事实来源。

---

## 2. 阻塞项一：敏感信息可能进入日志或页面

## 2.1 问题边界

当前 WeCom API 使用 query 参数传递：

- `corpsecret`
- `access_token`
- OAuth `code`

`http.Client.Do` 返回的 `*url.Error` 通常包含完整 URL。当前 `getJSON` 原样返回该错误，OAuth callback 又可能把 error description 写入日志和 Flash 页面。

仅调用现有 `util.SanitizeErrorCredentialURLs` 不足以解决问题，因为它只清理 URL userinfo，不清理 query 参数。

## 2.2 代码修改

### A. `services/enterprisewecom/client.go`

新增安全错误类型，不保存底层 URL：

```go
var ErrWeComUnavailable = errors.New("wecom service unavailable")

type APIError struct {
    Operation  string
    StatusCode int
    ErrorCode  int
}

func (e *APIError) Error() string {
    switch {
    case e.ErrorCode != 0:
        return fmt.Sprintf("wecom %s failed with error code %d", e.Operation, e.ErrorCode)
    case e.StatusCode != 0:
        return fmt.Sprintf("wecom %s failed with HTTP status %d", e.Operation, e.StatusCode)
    default:
        return fmt.Sprintf("wecom %s failed", e.Operation)
    }
}
```

将 `getJSON` 改为接收不含 secret 的 operation：

```go
func (c *Client) getJSON(
    ctx context.Context,
    operation string,
    path string,
    values url.Values,
    out any,
) error
```

错误处理要求：

```go
resp, err := c.httpClient.Do(req)
if err != nil {
    if errors.Is(err, context.Canceled) {
        return context.Canceled
    }
    if errors.Is(err, context.DeadlineExceeded) {
        return fmt.Errorf("%w: %s timed out", ErrWeComUnavailable, operation)
    }
    return fmt.Errorf("%w: %s request failed", ErrWeComUnavailable, operation)
}
```

关键约束：

- 不 wrap 原始 `*url.Error`，否则 `%+v` 或后续 unwrap 仍可能暴露 URL。
- 不返回 `req.URL.String()`。
- WeCom JSON `errmsg` 不进入面向用户错误；对上只保留 `errcode`。
- JSON decode error只报告 operation，不附响应体。
- HTTP client 设置有限超时，建议默认 15 秒。

### B. `services/auth/source/oauth2/providers_wecom.go`

`Authorize` 不再使用 `context.Background()`；由于 Goth `Session.Authorize` 没有 context 参数，给单次 callback 请求创建有限超时 context：

```go
ctx, cancel := context.WithTimeout(context.Background(), setting.EnterpriseWeCom.HTTPTimeout)
defer cancel()
```

更理想的后续改造是让 Gitea OAuth callback plumbing 传播 request context，但不建议在本轮扩大通用 OAuth2 改造范围。

### C. `routers/web/auth/oauth.go`

重构 callback error 展示顺序：

1. 先根据 path param 获取 auth source。
2. 判断是否为配置指定的 WeCom source。
3. 对 WeCom callback：
   - 不遍历并展示全部 query/form 参数；
   - 不展示 provider `error_description`；
   - 页面只显示统一的本地化错误；
   - 审计只记录固定 reason code；
   - 服务端日志只记录固定 reason、source ID、request ID，不记录原始 error。
4. 非 WeCom provider 保持现有行为，减少上游冲突。

建议增加：

```go
func handleWeComCallbackError(ctx *context.Context, source *auth.Source, reason string) {
    wecom_service.RecordCallbackLoginDeny(ctx, source, reason)
    log.Info("Denied Enterprise WeCom callback [source_id=%d, reason=%s]", source.ID, reason)
    ctx.Flash.Error(ctx.Tr("auth.oauth.signin.error.general", "Enterprise WeCom login failed"))
    ctx.Redirect(setting.AppSubURL + "/user/login")
}
```

不要把 `err.Error()` 传给 Flash。

### D. `options/locale/locale_en-US.json`

只新增英文 locale，例如：

```json
"auth.oauth.signin.error.wecom": "Enterprise WeCom sign-in failed. Please try again or contact the administrator."
```

遵守仓库规则，不编辑其他 locale。

## 2.3 测试

### `services/enterprisewecom/client_test.go`

新增：

- `TestClientTransportErrorDoesNotExposeSecret`
- `TestClientTimeoutDoesNotExposeRequestURL`
- `TestClientProviderErrorExposesCodeOnly`

使用自定义 `RoundTripper` 返回带完整敏感 URL 的 `url.Error`，断言错误字符串不包含：

- CorpSecret 值；
- access token 值；
- authorization code 值；
- `corpsecret=`、`access_token=`、`code=`。

自定义 `RoundTripper` 不需要监听本地端口，可在当前设备执行。

### `routers/web/auth/auth_test.go`

新增：

- `TestWeComCallbackErrorDoesNotExposeProviderParameters`
- `TestWeComCallbackInternalErrorUsesGenericMessage`

断言 response/Flash 和 audit metadata 均不包含敏感值。

## 2.4 验收标准

- 故意构造 DNS、timeout、TLS 和 provider JSON error 时，日志、Flash、审计均无 secret/token/code。
- `errors.Is(err, context.Canceled)` 仍成立。
- 用户只看到统一错误，不看到内部 URL 或 provider 原始描述。

---

## 3. 阻塞项二：`ENABLED=false` 未真正禁用 WeCom 登录

## 3.1 目标语义

| 配置 | WeCom source 展示 | 发起登录 | callback | 同步 |
| --- | --- | --- | --- | --- |
| `ENABLED=false` | 不展示 | 拒绝 | 拒绝 | 不执行 |
| `ENABLED=true, LOGIN_ONLY=false` | 仅展示配置指定 source | 允许 | 允许 | 按 cron 配置 |
| `ENABLED=true, LOGIN_ONLY=true` | 只展示配置指定 source | 允许 | 允许 | 按 cron 配置 |

`LOGIN_ONLY` 只决定是否关闭其他 Web 登录方法，不能决定 WeCom 自身是否启用。

## 3.2 代码修改

### A. `modules/setting/enterprise_wecom.go`

增加：

```go
LoginSourceName string
HTTPTimeout     time.Duration
```

默认值：

```go
LoginSourceName: "enterprise-wecom",
HTTPTimeout:     15 * time.Second,
```

配置校验：

- `ENABLED=true` 时要求 `LOGIN_SOURCE_NAME`、CorpID、AgentID、secret 非空。
- `HTTP_TIMEOUT > 0`。
- `LOGIN_SOURCE_NAME` 经过 trim，且符合现有 auth source name 长度约束。

增加语义明确的 helper：

```go
func EnterpriseWeComEnabled() bool
func EnterpriseWeComLoginOnly() bool
```

### B. `services/auth/source/oauth2/providers_wecom.go`

把 router 内私有判断提升为 OAuth2 package 的统一方法：

```go
func IsWeComSource(source *auth.Source) bool
func IsConfiguredWeComSource(source *auth.Source) bool
```

`IsConfiguredWeComSource` 必须同时验证：

- source 非 nil；
- source type 为 OAuth2；
- `source.Cfg.(*oauth2.Source).Provider == "wecom"`；
- `source.Name == setting.EnterpriseWeCom.LoginSourceName`。

### C. `services/auth/source/oauth2/providers.go`

在 `GetOAuth2Providers` 构造结果时：

```go
if IsWeComSource(source) {
    if !setting.EnterpriseWeCom.Enabled || !IsConfiguredWeComSource(source) {
        continue
    }
}
```

这样所有登录/注册页面获得一致列表，不在 router 中重复过滤数组。

### D. `routers/web/auth/oauth.go`

`SignInOAuth` 和 `SignInOAuthCallback` 在读取 source 后统一调用：

```go
func allowWeComWebLogin(source *auth.Source) bool {
    return setting.EnterpriseWeCom.Enabled && oauth2.IsConfiguredWeComSource(source)
}
```

规则：

- source 是 WeCom，但未启用或不是配置指定 source：返回 404，避免暴露禁用 source。
- login-only 下 source 不是配置指定 WeCom：返回 403。
- 两个入口必须使用同一 helper，不能只保护按钮入口而遗漏 callback。

### E. `services/enterprisewecom/login.go` 与 `sync.go`

增加 service 边界防御：

```go
if !setting.EnterpriseWeCom.Enabled {
    return nil, ErrWeComDisabled
}
```

`SyncDirectory` 同样拒绝 disabled 状态，避免测试、cron 或未来 API 绕过 Web 层。

## 3.3 测试

新增表驱动测试：

- `TestGetOAuth2ProvidersWeComVisibility`
- `TestSignInOAuthRejectsDisabledWeCom`
- `TestSignInOAuthCallbackRejectsDisabledWeCom`
- `TestSignInOAuthRejectsUnconfiguredWeComSource`
- `TestAuthenticateOAuthLoginRejectsWhenDisabled`
- `TestSyncDirectorySkipsWhenDisabled`

覆盖 enabled/login-only/source-name 的组合，不依赖外部网络。

## 3.4 验收标准

- `ENABLED=false` 时，数据库即使存在活跃 WeCom source，也不能从页面、直达 URL 或 callback 登录。
- 只有 `LOGIN_SOURCE_NAME` 指定的 source 可用。
- 非 WeCom OAuth 在 `LOGIN_ONLY=false` 时保持上游行为。

---

## 4. 阻塞项三：login-only 可能锁死全部 Web 管理员

## 4.1 方案选择

不在启动时自动写入 login source，避免隐式生产数据修复和配置/数据库双向覆盖。采用：

> **显式预创建 auth source + 启动预检 + 运行时变更保护 + 两阶段上线。**

## 4.2 启动预检

### `services/auth/source/oauth2/init.go`

把 `initOAuth2Sources` 拆成可测试步骤：

```go
func loadOAuth2Sources(ctx context.Context) ([]*auth.Source, error)
func validateEnterpriseWeComSource(sources []*auth.Source) error
func registerOAuth2Sources(sources []*auth.Source) error
```

预检需要读取全部 OAuth2 source，以便区分“不存在”和“存在但 inactive”；注册阶段仍只注册 active source。

校验策略：

1. `ENABLED=false`：跳过 WeCom preflight。
2. `ENABLED=true, LOGIN_ONLY=false`：
   - 找不到配置 source 时记录 warning，不阻止启动；
   - source 存在但注册失败时记录 error，其他登录方式继续可用。
3. `ENABLED=true, LOGIN_ONLY=true`：以下任一情况直接让 `oauth2.Init` 返回错误，应用不开始提供 Web 服务：
   - `LOGIN_SOURCE_NAME` 不存在；
   - source 非 active；
   - source type 不是 OAuth2；
   - provider 不是 `wecom`；
   - provider 本地初始化失败；
   - 配置 source 重复或数据库状态异常。

启动预检只做本地配置和 provider 构造检查，不调用企业微信远端 API，避免 WeCom 短暂故障导致 Gitea 无法启动。

建议错误文本只包含 source name 和缺失字段名，不包含凭据值。

## 4.3 运行时认证源变更保护

如果 login-only 已开启，管理员不应在运行中把唯一 source 禁用、改名或改成其他 provider。

建议在 `services/auth/source.go` 的 `UpdateSource` / `DeleteSource` 前调用 OAuth2 package 校验：

```go
func ValidateConfiguredWeComSourceMutation(oldSource, newSource *auth.Source) error
```

拒绝：

- 删除配置 source；
- `IsActive: true -> false`；
- 修改 source name；
- provider 从 `wecom` 改为其他类型。

错误提示要求管理员先把 `LOGIN_ONLY=false` 并重启，再变更认证源。

CLI 和 Web admin 都复用 service，因此不只保护 UI。

## 4.4 管理 UI 调整

当前 WeCom 凭据来自 `[enterprise.wecom]`，OAuth source 只保存名称、active、provider 等元数据。

修改：

- `templates/admin/auth/source/oauth.tmpl`
- `templates/admin/auth/edit.tmpl`
- 必要的认证源前端逻辑

当 provider 为 `wecom` 时：

- 隐藏或禁用 ClientID/ClientSecret 输入；
- 显示说明：“CorpID、AgentID 和 secret 由 `[enterprise.wecom]` 管理”；
- server 端 `parseOAuth2Config` 对 WeCom 强制清空 `ClientID`、`ClientSecret`，防止通过伪造表单重复保存 secret。

这是 UI 变更，PR 需要提供 before/after screenshot。

## 4.5 两阶段上线流程

部署文档增加明确顺序：

1. 配置 CorpID、AgentID、secret URI、`LOGIN_SOURCE_NAME`，保持 `ENABLED=false`。
2. 启动 Gitea，管理员创建同名 active OAuth2 source，provider 选择 WeCom。
3. 设置 `ENABLED=true, LOGIN_ONLY=false`，重启并验证 WeCom 登录；此时密码登录仍可作为部署回退。
4. 验证 callback domain、稳定 userid、审计事件和 source 状态。
5. 设置 `LOGIN_ONLY=true`，重启；启动 preflight 必须通过。
6. 回滚时先把 `LOGIN_ONLY=false` 或 `ENABLED=false`，再重启。

## 4.6 测试

### `services/auth/source/oauth2/init_test.go`

新增纯校验测试：

- `TestValidateEnterpriseWeComSourceDisabled`
- `TestValidateEnterpriseWeComSourceCanaryWithoutSource`
- `TestValidateEnterpriseWeComSourceLoginOnlyMissing`
- `TestValidateEnterpriseWeComSourceLoginOnlyInactive`
- `TestValidateEnterpriseWeComSourceWrongProvider`
- `TestValidateEnterpriseWeComSourceValid`

### `services/auth/source_test.go`

新增：

- login-only 下不能删除 source；
- 不能禁用、改名、换 provider；
- login-only 关闭后允许维护。

### `routers/web/auth/auth_test.go`

新增：

- 0 个配置 source 时不会渲染空登录页；该状态应在启动预检前被拒绝；
- 1 个配置 source 时自动跳转；
- 其他 WeCom source 被隐藏且直达 URL 被拒绝。

## 4.7 验收标准

- login-only 配置错误时进程明确启动失败，而不是启动成无法登录的页面。
- canary 模式允许保留原登录方式验证 WeCom。
- 运行中不能误删或禁用唯一 source。
- 回滚步骤不依赖数据库手工修改。

---

## 5. 阻塞项四：目录同步未接入执行路径

## 5.1 复用现有 cron

### A. `services/cron/tasks_basic.go`

新增：

```go
func registerEnterpriseWeComDirectorySync() {
    RegisterTaskFatal("sync_enterprise_wecom_directory", &BaseConfig{
        Enabled:    setting.EnterpriseWeCom.Enabled,
        RunAtStart: false,
        Schedule:   "@every 10m",
    }, func(ctx context.Context, _ *user_model.User, _ *BaseConfig) error {
        client := enterprisewecom.NewClientFromSettings()
        return enterprisewecom.SyncDirectory(ctx, client)
    })
}
```

在 `initBasicTasks` 中注册该任务。建议任务始终出现在 cron 列表中，但默认 `Enabled` 跟随 Enterprise WeCom；`[cron.sync_enterprise_wecom_directory]` 可以进一步覆盖 schedule 和 notice 设置。

现有 `Task.RunWithUser` 已使用 `globallock.TryLock`，多实例部署不需要再实现一套分布式锁。

### B. `services/enterprisewecom/client.go`

新增：

```go
func NewClientFromSettings() *Client
```

集中设置 CorpID、AgentID、secret、API base URL、HTTP timeout，避免 cron、provider 和未来 API 分别拼配置。

将目录 client 接口改为传播 context：

```go
type DirectoryClient interface {
    ListDepartments(ctx context.Context) ([]DepartmentInfo, error)
    ListMembers(ctx context.Context, departmentID int64) ([]MemberInfo, error)
    ListTags(ctx context.Context) ([]TagInfo, error)
    ListTagMembers(ctx context.Context, tagID int64) ([]string, error)
}
```

删除目录方法内全部 `context.Background()`。

### C. access token 缓存

为 `Client` 增加 mutex 保护的内存缓存：

```go
type Client struct {
    cfg Config
    mu sync.Mutex
    accessToken string
    expiresAt time.Time
}
```

刷新规则：

- 当前时间早于 `expiresAt - 2m` 时复用；
- 过期或空值时单次刷新；
- 不持久化 token；
- 不记录 token；
- 并发请求只允许一次刷新。

这不是独立功能扩展，而是避免一次目录同步为每个部门/标签重复调用 `/gettoken`。

### D. 管理员手动触发

不新增 WeCom 专属 API。现有 admin cron API 和管理页面已经支持：

- 查看任务；
- 查看 `LastRun`、`ExecTimes`；
- 由管理员手动执行指定 cron task。

只需新增任务 locale：

```json
"admin.dashboard.sync_enterprise_wecom_directory": "Synchronize Enterprise WeCom directory"
```

因此本轮没有 Swagger 变化，不运行 `make generate-swagger`。

### E. `custom/conf/app.example.ini`

新增标准 cron 配置示例，并从 `[enterprise.wecom]` 删除 `SYNC_INTERVAL`。

## 5.2 本轮同步语义

为了关闭“未接线”阻塞项，本轮至少保证：

- Enabled 且 cron enabled 时按 schedule 调用；
- disabled 时任务不访问 WeCom；
- shutdown/cancel 能传递到 HTTP 请求；
- 单实例和多实例不会重复并发执行同名任务；
- 执行成功/失败有现有 cron 状态和 WeCom audit 记录。

完整快照对账、离职状态和陈旧 membership 清理仍应在归档前完成；建议与本阻塞项同一批实现，具体事务设计如下：

```text
fetch remote snapshot outside DB transaction
        |
        v
validate complete snapshot
        |
        v
db.WithTx:
  upsert current departments/tags/identities/memberships
  mark missing bound identities out_of_scope
  delete stale memberships
  delete or mark stale departments/tags
        |
        v
commit -> sync finish(success)
rollback -> sync finish(error)
```

不要在数据库事务期间执行远端 HTTP 请求。

## 5.3 测试

新增：

- `TestEnterpriseWeComCronDisabledWhenIntegrationDisabled`
- `TestEnterpriseWeComCronInvokesSync`
- `TestDirectoryClientPropagatesCancellation`
- `TestClientReusesAccessToken`
- `TestClientRefreshesExpiredAccessToken`
- `TestSyncDirectoryDoesNotPersistPartialSnapshot`
- `TestSyncDirectoryMarksMissingIdentityOutOfScope`
- `TestSyncDirectoryRemovesStaleMembership`
- `TestSyncDirectoryTagOnlyMemberCreatesIdentitySnapshot`

HTTP client 测试优先使用自定义 `RoundTripper`，避免本地监听端口限制。

## 5.4 验收标准

- `SYNC_INTERVAL` 不再是未消费配置。
- cron 管理页可见任务，管理员可通过现有入口手动执行。
- shutdown context 可终止同步。
- 同一任务多实例不会并发执行。
- 一次同步只获取一次有效 access token。
- 同步失败不留下半批次数据。

---

## 6. 文件级修改清单

| 文件 | 修改内容 |
| --- | --- |
| `modules/setting/enterprise_wecom.go` | 增加 source name、HTTP timeout；删除或停止使用 SyncInterval；强化校验 |
| `modules/setting/enterprise_wecom_test.go` | 新配置默认值和非法配置测试 |
| `services/enterprisewecom/client.go` | 安全错误、HTTP timeout、context、token cache、settings factory |
| `services/enterprisewecom/client_test.go` | transport error 脱敏、timeout、token cache 测试 |
| `services/enterprisewecom/login.go` | disabled 防御性拒绝 |
| `services/enterprisewecom/sync.go` | disabled guard、context 传播、事务对账 |
| `services/enterprisewecom/sync_test.go` | cron 调用前的 service 行为、回滚和 stale 数据测试 |
| `services/auth/source/oauth2/providers_wecom.go` | 统一 source 识别 helper、有限 callback timeout |
| `services/auth/source/oauth2/providers.go` | disabled 和非配置 source 过滤 |
| `services/auth/source/oauth2/init.go` | login-only startup preflight |
| `services/auth/source/oauth2/init_test.go` | preflight 表驱动测试 |
| `routers/web/auth/oauth.go` | source gate、callback error 安全展示 |
| `routers/web/auth/auth.go` | 删除重复 provider 过滤，使用统一 provider 列表结果 |
| `routers/web/auth/auth_test.go` | disabled、source mismatch、zero/one/multiple source、错误不泄漏测试 |
| `services/auth/source.go` | 配置 source 删除/禁用/改名保护 |
| `services/auth/source_test.go` | source mutation guard 测试 |
| `services/cron/tasks_basic.go` | 注册 WeCom 目录同步任务 |
| `services/cron/*_test.go` | 任务注册和执行测试 |
| `templates/admin/auth/source/oauth.tmpl` | WeCom source 不输入重复凭据 |
| `templates/admin/auth/edit.tmpl` | WeCom source 编辑态禁用重复凭据字段 |
| `routers/web/admin/auths.go` | WeCom source 强制清空 OAuth ClientID/Secret |
| `options/locale/locale_en-US.json` | 登录失败和 cron task 英文文案 |
| `custom/conf/app.example.ini` | source name、timeout、cron 配置、两阶段部署说明 |
| `docs/enterprise-authz/implementation-plan.md` | 修正完成状态、补充启动预检与 rollout/runbook |
| `openspec/changes/wecom-only-web-login/design.md` | 记录唯一 source、三层防护、cron 和安全错误决策 |
| `openspec/changes/wecom-only-web-login/specs/identity/wecom-web-login/spec.md` | 增加 disabled、错误脱敏、错误配置 fail-fast 和同步调度场景 |
| `openspec/changes/wecom-only-web-login/tasks.md` | 重新打开四个阻塞项并记录新增测试 |

预计不需要：

- 新 DB migration；
- Swagger 生成；
- 前端 JS 业务逻辑大改。

如果快照对账需要新增 `sync_generation` 字段，则必须新增下一编号 migration，不能依赖模型自动同步。也可以直接使用已有 `last_sync_unix` 作为本次 batch marker，从而避免 schema 变化，但必须保证同一次同步使用唯一且固定的 batch timestamp。

---

## 7. 推荐实现顺序与提交切分

### 批次 1：错误安全边界

建议提交标题：

```text
fix(auth): redact sensitive WeCom callback errors
```

包括阻塞项一和对应测试。

### 批次 2：启停与唯一 source

建议提交标题：

```text
fix(auth): enforce configured WeCom login source
```

包括阻塞项二、三的 source helper、路由 gate、startup preflight、mutation guard 和测试。

### 批次 3：同步运行接线

建议提交标题：

```text
enhance(auth): schedule Enterprise WeCom directory sync
```

包括 cron、context、HTTP timeout、token cache、同步对账及测试。

### 批次 4：部署文档和状态

建议提交标题：

```text
docs(auth): document safe WeCom rollout and recovery
```

更新配置示例、实施计划和 OpenSpec task 状态。

若实际创建提交，必须遵循仓库要求添加：

```text
Assisted-by: Manus:<实际模型版本>
```

不要使用 `Co-authored-by`。

---

## 8. 验证命令

实现后按顺序运行：

```bash
make fmt

go test -run '^TestName$' ./modules/setting/
go test -run '^TestName$' ./services/enterprisewecom/
go test -run '^TestName$' ./services/auth/source/oauth2/
go test -run '^TestName$' ./services/auth/
go test -run '^TestName$' ./routers/web/auth/
go test -run '^TestName$' ./services/cron/

make lint-go
```

然后在允许 loopback listener 的 CI 或开发环境运行相关包完整测试和 integration tests。

如果修改模板：

```bash
make lint-templates
```

本方案不新增 API，因此无需 `make generate-swagger`；如果实现时决定新增 WeCom 专属管理 API，则必须补 Swagger 并运行：

```bash
make generate-swagger
make swagger-validate
```

最终再执行：

```bash
openspec validate wecom-only-web-login --strict
```

只有四个阻塞项、完整 HTTP 测试和部署 smoke test 均通过后，才将 OpenSpec 任务重新标为完成并归档。
