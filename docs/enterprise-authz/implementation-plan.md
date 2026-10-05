# Gitea Enterprise Authorization Implementation Plan

## 目的

本文档把 [`requirements.md`](requirements.md) 中的企业授权需求收敛成可执行的实施方案。方案目标是在保持浅 fork、降低上游合并冲突的前提下，复用 Gitea 现有权限、分支保护、required checks、Actions 和审计日志能力，补齐企业微信唯一 Web 登录、企业微信用户标识、企业级 repo 授权、功能授权、默认治理模板和合并门禁。

后续 OpenSpec proposal 拆分与实施顺序见 [`proposal-roadmap.md`](proposal-roadmap.md)。

## 设计原则

1. **兼容优先**：未启用企业授权增强时，行为尽量保持上游 Gitea 语义。
2. **叠加而非替换**：新增企业授权 overlay，不直接替换 `AccessMode`、repo unit、team、branch protection 等核心模型。
3. **身份边界清晰**：企业微信只接管 Web 登录和用户标识来源；SSH key、PAT、Git HTTP token 继续沿用 Gitea 原有认证机制。
4. **集中决策**：所有 repo 授权写路径，包括 Web、API、Git HTTP/SSH、file editor、receive hook、auto merge，最终调用统一授权或合并门禁判断。
5. **显式迁移**：新增表、字段、默认角色、默认权限和策略模板都通过 `modelmigration` 显式落库，不依赖启动时隐式修复生产数据。
6. **可审计**：权限变更、策略变更和合并决策必须记录审计事件；合并门禁保存策略快照，便于事后解释。
7. **可回滚到安全状态**：升级失败或企业授权关闭时，系统应退回到原生 Gitea 权限，或进入只读保护状态，而不是意外放权。

## 当前代码基础

当前仓库已有以下可复用基础：

| 能力 | 现有位置 | 复用方式 |
| --- | --- | --- |
| repo 基础权限 | `models/perm/access`、`models/perm/access_mode.go` | 作为旧权限兼容层和默认 action 映射来源。 |
| repo unit 权限 | `models/unit`、`repo_model.RepoUnit`、`organization.TeamUnit` | 继续控制 Issues、PR、Wiki、Packages、Actions 等模块可见性和读写。 |
| 团队权限 | `models/organization/team.go` | 自定义角色绑定优先扩展 subject binding，不改团队核心模型。 |
| 分支保护 | `models/git/protected_branch.go` | 继续承载 protected branch、required approvals、status checks、CODEOWNERS、protected files。 |
| 合并检查 | `services/pull/check.go`、`services/pull/merge.go` | 抽出统一 merge gate evaluator 后由这些入口调用。 |
| required checks | `services/pull/commit_status.go`、commit status API | 外部系统以 commit status/check context 方式接入。 |
| 强制 scoped workflow | `models/actions/scoped_workflow.go` | 可作为 required workflow / required check 的 Gitea Actions 侧实现。 |
| 审计日志 | `models/audit`、`services/audit` | 扩展 action 和 metadata，不另建平行审计体系，除非后续有性能或合规隔离要求。 |
| OAuth2 登录源 | `services/auth/source/oauth2`、`models/auth/source.go` | 新增企业微信 provider 或 source 类型，复用 auth source 生命周期和外部账号绑定。 |
| 外部账号绑定 | `models/user/external_login_user.go`、OAuth2 sign-in sync | 存储企业微信 `userid` 到 Gitea 用户的绑定关系；必要时补充企业微信专属同步状态表。 |
| Web 登录开关 | `modules/setting/service.go`、`routers/web/auth/auth.go`、`templates/user/auth/signin_inner.tmpl` | 复用 `ENABLE_PASSWORD_SIGNIN_FORM`、`ENABLE_BASIC_AUTHENTICATION`、OpenID、Passkey 等开关，企业模式下强制只展示企业微信登录。 |
| 单 OAuth2 自动跳转 | `routers/web/auth/auth.go:performAutoLoginOAuth2` | 企业模式下只有一个启用的企业微信登录源时，`/user/login` 自动跳转企业微信。 |
| 企业微信登录基线 | `services/enterprisewecom`、`tests/integration/enterprise_wecom_auth_test.go` | 已验证 login-only 下本地密码、注册、OpenID、Passkey、反向代理、SSPI 和非 WeCom OAuth Web 登录被拦截，同时 SSH key、PAT/API token、Git HTTP token 保持原生 Gitea 行为。 |
| 企业微信授权映射 Phase 2 | `models/enterprisewecom`、`services/enterprisewecom`、`routers/api/v1/enterprisewecom` | 采用 additive generated mapping 和 managed-membership 表，在显式配置的既有组织内自动派生团队并对账；保留只读 GET、审计和 Swagger，人工 CRUD、dry-run/apply API 已弃用且拒绝执行。 |

## 当前实施补充：自动化、超级管理员与组织仓库治理

`enterprise-wecom-admin-ui-super-admin` 将 Phase 2 的人工维护式映射升级为自动化治理，`harden-wecom-governance-ops` 进一步统一发布事务、目标组织与来源边界。上线、暂停、callback gate 和恢复以 [`wecom-governance-ops-runbook.md`](wecom-governance-ops-runbook.md) 为准：

- **定时自动化范围**：`sync_enterprise_wecom_directory` 先在发布事务外取得完整通讯录与管理员权限候选，再把目录、身份、authority、generated mapping/team/team-admin、受管成员关系、管理员晋升及 success 证据统一提交。跨实例 writer 使用数据库 lease、fencing 和 published revision 协调；取数失败、取消、失效 lease 或后期数据库错误保留上一份完整有效状态，失败 run 的已应用计数为零。
- **生成规则**：企微部门生成 `dept-{department_id}-{normalized_name}` 团队，企微标签生成 `tag-{tag_id}-{normalized_name}` 能力团队；部门/标签成员只从已绑定且 active 的企微身份投影到 Gitea 用户；缺失、歧义、未绑定、离职/不可见成员记录为 skipped/unresolved，不做宽泛兜底授权。
- **团队管理员来源**：团队管理员状态只来自企微 API 元数据，例如部门详情 `department_leader` 与成员详情 `is_leader_in_dept`。Gitea 当前 `team_user` 没有单成员“团队管理员”列，因此实现会把企微 leader 持久化为 `GeneratedTeamAdmin`、纳入对应受管团队的 managed membership、展示/审计其派生状态；不会把 leader 加入 Owners 团队或把整队提升为 owner 来模拟本地团队管理员。标签 API 本身不提供管理员信号时，标签团队标记为 unresolved/system-managed，不允许本地管理员手工补一个团队管理员。
- **超级管理员来源**：系统超级管理员优先由企微管理员变更回调和管理员列表 API 自动识别；对于当前自建应用模式，使用企微通讯录标签 `超管` 作为自动权限来源，并通过 `tag/list` + `tag/get` 在登录和定时任务中同步该标签的显式成员。本地用户名、本地用户 ID、环境变量或手工填写的企微 `userid` 都不是可信来源。`auth_type=1` 或 `超管` 标签显式成员会被映射为受保护的 Gitea site admin；`auth_type=0` 消息权限用户不会获得本地 root 权限。
- **受保护账号**：普通 site admin 不能编辑、删除、重命名、模拟登录、修改 SSH key/徽章/邮箱或把受保护超级管理员移出组织；受保护管理员也不能自删、自禁用、自降级。
- **organization 创建策略**：只有企微派生的系统超级管理员可以创建 organization；普通成员和非企微超级管理员的普通 site admin 均禁止创建，即使本地 Gitea `AllowCreateOrganization` 或 site-admin 身份原本允许。系统不自动删除或修复既有 organization。
- **组织仓库审批**：普通成员不能直接创建组织仓库，只能向目标 organization 提交组织仓库请求；发起申请不要求 requester 已经是该 Gitea organization 的本地成员或 owner-team 成员。提交后跳转到用户设置中的 organization 页面展示“我的组织仓库申请”及 pending/approved/rejected 状态，避免被误解为已创建但不可见的仓库。企微派生系统超级管理员审批后创建 Private 组织仓库，记录 requester 为仓库 creator，并授予 requester 等效的管理权限。拒绝不会创建仓库，审批/拒绝均写入审计。
- **个人仓库配额**：普通成员可在自己命名空间创建个人 Private 仓库，无需审批；`PERSONAL_REPO_QUOTA` 默认 10，达到配额后拒绝新增并审计，`0` 禁止新增。下调不删除既有仓库，组织仓库不计入个人配额，更严格的原生限制继续生效。
- **Private 默认与授权守卫**：企业微信治理启用时，受管创建路径强制 Private；仓库 collaborator/team 授权变更仅允许仓库记录 creator、owner-level 权限用户或企微派生系统超级管理员执行，普通 site admin 身份本身不足以授权。
- **管理后台与只读 UI 边界**：企业微信治理启用时，`/-/admin*` 管理后台入口和直接 URL 均需要通过企微派生系统超级管理员鉴权；本地 Gitea site-admin 身份本身不再足以看到或访问管理后台。`/-/admin/enterprise/wecom*` 继续使用现有 Gitea admin layout，面向企微派生系统超级管理员展示定时任务、最近运行、生成 mapping/team/team-admin、管理员权限快照、organization 创建治理状态、审批队列与审计入口；页面不提供 mapping/team/team-admin 的本地创建、编辑、dry-run 或 apply 操作。
- **暂停与回滚**：单独关闭 cron/callback 不会停止登录 authority-only writer，也不保证在途任务终止；需确定停写时按 runbook 停止全部实例。`ENABLED=false` 会恢复原生管理员 guard，不只是暂停任务。旧二进制不能绕过新来源与协调边界混跑；二进制回退及完整备份恢复按 runbook 审批执行，不手工改成员关系或凭据。

### 迁移判断

- **DB migration：需要**。已通过 `modelmigration` 增加企微管理员权限快照、生成 mapping/team/team-admin 状态、对账运行历史、组织仓库请求、仓库 creator/governance metadata 等 additive 表，不修改 SSH key、PAT、Git HTTP token、既有用户、既有组织或既有仓库 schema 语义。
- **OpenFGA：不需要**。本仓库仍使用 Gitea 本地用户、团队和仓库权限模型表达授权，不引入 OpenFGA relation/tuple。
- **Keycloak：不需要**。企业微信仅作为 Web 登录和目录/权限来源，不改变 Keycloak realm、client、mapper、claim 或用户属性。
- **Swagger：仅 API 合约变化时生成**。当前产品 UI 为 server-rendered 只读页面；保留的 mapping API 已转换为 generated 状态读取与手动 mutation 拒绝语义时才需要重新生成 Swagger。

## 总体架构

新增企业身份和授权层位于现有 Gitea 账号、权限模型之上：

```text
Web Login
  -> WeCom OAuth code flow
  -> verify corp / agent / state
  -> resolve WeCom userid
  -> bind or create Gitea user
  -> create normal Gitea web session

API / Git Operation / Merge Operation
  -> existing Gitea authentication
     - web session from WeCom login
     - SSH key / PAT / Git HTTP token unchanged
  -> existing Gitea repo/unit permission loading
  -> enterprise authz evaluator
  -> feature grant evaluator
  -> action-specific guard or merge gate evaluator
  -> audit event / merge gate snapshot
```

建议新增包：

```text
models/enterpriseauthz
models/enterprisewecom
services/enterpriseauthz
services/enterprisewecom
routers/api/v1/enterpriseauthz
routers/api/v1/enterprisewecom
routers/web/admin/enterpriseauthz
routers/web/admin/enterprisewecom
routers/web/org/setting/enterpriseauthz
routers/web/repo/setting/enterpriseauthz
```

说明：

- 使用 `enterpriseauthz` 前缀，避免和上游未来的 `authz`、`roles`、`policy` 包冲突。
- 第一阶段先落企业微信唯一 Web 登录和身份绑定，再叠加企业授权 overlay。
- API 和 Web 不直接拼 SQL 或业务规则，统一调用 `services/enterprisewecom` 和 `services/enterpriseauthz`。
- SSH key、PAT、Git HTTP token 的认证链路不调用企业微信 OAuth，不新增企业微信专属拦截器。

## 配置开关

新增配置项建议：

```ini
[enterprise.wecom]
ENABLED = false
CORP_ID =
AGENT_ID =
MANAGED_ORG_ID = 0
PERSONAL_REPO_QUOTA = 10
CORP_SECRET_URI =
; CORP_SECRET =            # 仅用于本地应急/测试，生产优先使用 CORP_SECRET_URI
LOGIN_ONLY = true
LOGIN_SOURCE_NAME = enterprise-wecom
AUTO_CREATE_USER = true
USERNAME_TEMPLATE = {userid}
SYNC_DEPARTMENTS = true
SYNC_TAGS = true
SUPER_ADMIN_TAG_NAME = 超管
; 弃用兼容项，值被忽略，不控制自动化发布
APPLY_AUTHZ_MAPPINGS_ON_SYNC = false
ADMIN_CALLBACK_ENABLED = false
ADMIN_CALLBACK_TOKEN_URI =
ADMIN_CALLBACK_AES_KEY_URI =
ADMIN_CALLBACK_RECEIVER_ID =
HTTP_TIMEOUT = 15s
API_BASE_URL = https://qyapi.weixin.qq.com
OAUTH_BASE_URL = https://login.work.weixin.qq.com

[cron.sync_enterprise_wecom_directory]
ENABLED = false
RUN_AT_START = false
NOTICE_ON_SUCCESS = false
SCHEDULE = @every 10m

[enterprise.authz]
ENABLED = false
ENFORCE = false
FAIL_CLOSED_ON_ERROR = true
```

企业微信配置语义：

| 配置 | 说明 |
| --- | --- |
| `enterprise.wecom.ENABLED=false` | 不启用企业微信登录和同步。 |
| `CORP_ID` / `AGENT_ID` | 企业微信企业 ID 和应用 agentid。 |
| `MANAGED_ORG_ID` | 默认 `0` 表示治理未就绪；必须显式配置既有 organization 的稳定 ID，不按数量/名称猜测。个人 ID、已删除目标、调用 override 或已有生成状态的跨组织切换会拒绝发布；组织改名不改变目标。目标错误不阻断合法 Web 登录的 authority-only 刷新。 |
| `PERSONAL_REPO_QUOTA` | 默认 `10`，非负整数；`0` 禁止新增个人仓库，负数/非法值拒绝加载。下调不删除旧仓库，组织仓库不计入个人配额。 |
| `CORP_SECRET_URI` / `CORP_SECRET` | 企业微信应用 secret。生产优先使用 `CORP_SECRET_URI` 安全引用，`CORP_SECRET` 仅用于本地应急或测试。 |
| `LOGIN_ONLY=true` | 企业模式下 Web 登录只允许企业微信；本地密码、注册、OpenID、Passkey、其它 OAuth2 登录源应关闭或隐藏。 |
| `LOGIN_SOURCE_NAME` | 唯一允许用于企业微信 Web 登录的 active OAuth2 source 名称。 |
| `AUTO_CREATE_USER=true` | 企业微信成员首次登录时自动创建 Gitea 用户；用户名从 `USERNAME_TEMPLATE` 派生并做冲突处理。 |
| `SYNC_DEPARTMENTS` / `SYNC_TAGS` | 是否同步企业微信部门和标签，用作授权映射来源。 |
| `SUPER_ADMIN_TAG_NAME` | 当前自建应用的可信管理员标签，默认 `超管`；仅显式 userlist，缺失、歧义或取数失败不能当作空 authority。 |
| `APPLY_AUTHZ_MAPPINGS_ON_SYNC` | 弃用兼容项，读取时告警且忽略；`false` 不暂停完整自动化发布，`true` 不启用独立 post-sync apply。 |
| `ADMIN_CALLBACK_ENABLED` | 默认 `false`；只有 runbook 的真实应用模式、官方 fixture 和 URL 验证 gate 完成后才启用，不以单元测试替代真实联调。 |
| `ADMIN_CALLBACK_TOKEN_URI` / `ADMIN_CALLBACK_TOKEN` | callback 专用 token 安全引用/本地测试值，不复用 OAuth secret。 |
| `ADMIN_CALLBACK_AES_KEY_URI` / `ADMIN_CALLBACK_AES_KEY` | EncodingAESKey 安全引用/本地测试值；启用时必须为 43 字符并解码为 32 字节。 |
| `ADMIN_CALLBACK_RECEIVER_ID` | 启用时显式配置协议要求的 corp/suite 接收方，不可缺省放宽校验。 |
| `HTTP_TIMEOUT` | 单次企业微信 HTTP 请求超时。 |
| `API_BASE_URL` / `OAUTH_BASE_URL` | 企业微信 API 与浏览器 Web/扫码 OAuth 登录地址；仅在内网代理、私有网关或测试端点下覆盖默认值。 |

安全上线顺序：先在 `ENABLED=false` 下配置凭据并创建与 `LOGIN_SOURCE_NAME` 同名的 active WeCom OAuth2 source；再以 `ENABLED=true, LOGIN_ONLY=false` 灰度验证；最后开启 `LOGIN_ONLY=true`。login-only 启动预检失败时，应先回退 `LOGIN_ONLY=false`，不得通过手工修改认证数据绕过检查。

上述示例让 cron/callback 保持暂停；自动化首次完整发布、恢复计划任务和紧急管理员恢复遵循 runbook，不使用弃用 apply flag 或人工 mapping API。

企业授权配置语义：

| 配置 | 说明 |
| --- | --- |
| `enterprise.authz.ENABLED=false` | 只使用原生 Gitea 权限。企业授权 API 可隐藏或只读。 |
| `ENABLED=true, ENFORCE=false` | shadow mode，只记录决策和审计，不阻断请求。用于灰度验证。 |
| `ENABLED=true, ENFORCE=true` | 正式执行企业授权决策。 |
| `FAIL_CLOSED_ON_ERROR=true` | evaluator 出错时写操作拒绝，读操作按原生权限降级或拒绝，具体由 action 风险等级决定。 |

企业模式下推荐同步设置：

```ini
[service]
DISABLE_REGISTRATION = true
ALLOW_ONLY_EXTERNAL_REGISTRATION = true
ENABLE_PASSWORD_SIGNIN_FORM = false
ENABLE_BASIC_AUTHENTICATION = true
ENABLE_PASSKEY_AUTHENTICATION = false

[openid]
ENABLE_OPENID_SIGNIN = false
ENABLE_OPENID_SIGNUP = false

[oauth2_client]
ENABLE_AUTO_REGISTRATION = true
```

说明：`ENABLE_BASIC_AUTHENTICATION` 保持 `true` 是为了不改变 Git HTTP token / Basic token 认证语义；若未来要禁用密码 Basic auth，必须作为独立安全策略评估，不能混入企业微信登录改造。

## 企业微信登录与身份策略

### 适用边界

企业微信接入只覆盖 Web 登录和用户标识：

- `/user/login`、OAuth callback、Web session 创建必须走企业微信。
- Gitea 内部 `user` 仍是 repo 权限、团队成员、审计、SSH key、PAT、Git HTTP token 的归属主体。
- SSH key、PAT、Git HTTP token 的创建、校验、吊销、审计继续走原生 Gitea 逻辑，不新增企业微信 OAuth 校验，不改变 token 格式和 Git 协议认证路径。
- 如果账号被 Gitea 原生逻辑禁用、锁定或限制，所有认证方式继续遵循原有账号状态判断；本方案不额外定义 token 失效规则。

### Web 登录流程

```text
GET /user/login
  -> 企业模式检查
  -> 若唯一启用企业微信 source，自动跳转企业微信授权链接
  -> 企业微信回调 code/state
  -> 校验 state、corp_id、agent_id、可信回调域
  -> 调用企业微信接口解析 userid
  -> 查找 external_login_user 或 enterprise_wecom_identity
  -> 首次登录时创建或绑定 Gitea user
  -> 写登录审计
  -> 创建 Gitea web session
```

企业微信网页授权使用 authorization code 流程：构造授权链接获取 `code`，再用 `code` 换取成员身份。企业微信官方文档说明 `snsapi_base` 可静默获取成员基础身份，回调后可根据 `code` 获取成员 `userid`；获取访问用户身份接口为 `GET https://qyapi.weixin.qq.com/cgi-bin/auth/getuserinfo?access_token=ACCESS_TOKEN&code=CODE`。

### 用户标识规则

| 字段 | 用途 | 规则 |
| --- | --- | --- |
| `corp_id` | 企业边界 | 必须匹配配置的 `CORP_ID`，避免跨企业账号串联。 |
| `userid` | 外部身份主键 | 作为企业微信成员在本企业内的稳定标识；不使用邮箱作为主键。 |
| `external_id` | Gitea 外部登录绑定 | 建议使用 `wecom:{corp_id}:{userid}`，避免和其它 OAuth2 source 冲突。 |
| `login_name` | Gitea 用户名 | 默认从 `userid` 派生；冲突时按确定性后缀处理，不允许抢占既有本地用户。 |
| `email` | 展示/通知 | 可选字段，缺失或变更不影响绑定关系。 |

### 企业微信通讯录同步

同步目标是授权映射，不是替换 Gitea 用户系统：

1. 定时同步企业微信部门列表、部门成员、标签成员。
2. 将企业微信部门和标签映射到 Gitea 组织、团队或企业角色绑定。
3. 对不在可见范围、离职或禁用成员，更新企业微信身份状态；是否禁用 Gitea 用户应作为可配置策略，默认只阻止新的 Web 登录，不主动删除 SSH key、PAT 或 Git HTTP token。
4. 通讯录字段按最小化原则保存，只保存授权判断必需字段；手机号、二维码等敏感字段不入库。

企业微信官方通讯录接口提供部门成员、部门成员详情、部门列表、标签成员等能力；接口返回范围受应用可见范围限制，部门列表接口也明确只能拉取 token 对应应用权限范围内的部门列表。

### 非企业微信登录拦截

企业模式开启且 `LOGIN_ONLY=true` 时：

| 登录方式 | 行为 |
| --- | --- |
| 本地用户名密码 Web 登录 | 表单隐藏；POST `/user/login` 返回 403。 |
| 本地注册 | 禁用。 |
| 密码找回、密码重置、账号激活 | 禁用，不能作为建立 Web session 的旁路。 |
| OAuth 账号绑定中的本地密码登录或注册 | 禁用；企业微信使用专用身份绑定流程。 |
| OpenID 登录/注册 | 禁用。 |
| Passkey Web 登录 | 禁用。 |
| 非企业微信 OAuth2 source | 不展示，不允许发起登录。 |
| Reverse proxy Web auth / SSPI | 禁用，不能自动建立 Web session。 |
| TOTP、scratch code、WebAuthn 二次验证 | 仅允许继续由企业微信 OAuth 发起的 pending login。 |
| SSH key | 保持原逻辑。 |
| PAT | 保持原逻辑。 |
| Git HTTP token | 保持原逻辑。 |

### 紧急运维

“仅允许企业微信 Web 登录”不保留 Web 本地管理员后门。紧急恢复应通过离线运维手段完成，例如配置回滚、数据库修复、CLI 管理命令或临时关闭 `enterprise.wecom.LOGIN_ONLY`，并记录操作审计或变更单。

## 数据模型

企业授权后续表建议统一使用 `enterprise_` 前缀。首批 `wecom-only-web-login` 已先落地企业微信身份和目录快照基础表，使用较短的 `wecom_` 前缀以保持改动浅层且聚焦登录边界；Phase 2 已通过 `modelmigration` 增加 `enterprise_wecom_authz_mapping` 和 `enterprise_wecom_managed_membership`，不修改 `org_user` / `team_user` schema。

### `wecom_identity`

保存企业微信成员与 Gitea 用户的绑定和同步状态。

| 字段 | 说明 |
| --- | --- |
| `id` | 主键。 |
| `user_id` | Gitea 用户 ID，用于关联本地主体。 |
| `corp_id` | 企业微信 CorpID。 |
| `wecom_userid` | 企业微信成员 UserID。 |
| `external_id` | `wecom:{corp_id}:{wecom_userid}`，和 `external_login_user` 对齐。 |
| `login_source_id` | 对应 Gitea OAuth2 登录源 ID。 |
| `name` | 展示名，可为空。 |
| `email` | 邮箱，可为空，不作为绑定主键。 |
| `status` | `active`、`inactive`、`left`、`out_of_scope`。 |
| `last_login_unix` | 最近一次企业微信 Web 登录时间。 |
| `last_sync_unix` | 最近一次通讯录同步时间。 |
| `created_unix` / `updated_unix` | 时间戳。 |

约束：`corp_id + wecom_userid` 唯一；不得用邮箱做唯一身份；不得保存企业微信 secret、access token 或用户敏感信息明文。

### `wecom_department`

保存企业微信部门快照，用于授权映射。

| 字段 | 说明 |
| --- | --- |
| `corp_id` | 企业微信 CorpID。 |
| `department_id` | 企业微信部门 ID。 |
| `parent_id` | 父部门 ID。 |
| `name` | 部门名称。 |
| `order` | 企业微信返回的排序值。 |
| `last_sync_unix` | 最近同步时间。 |

### `wecom_tag`

保存企业微信标签快照，用于授权映射。

| 字段 | 说明 |
| --- | --- |
| `corp_id` | 企业微信 CorpID。 |
| `tag_id` | 企业微信标签 ID。 |
| `name` | 标签名称。 |
| `last_sync_unix` | 最近同步时间。 |

### `wecom_membership`

保存企业微信成员与部门、标签的关系快照。

| 字段 | 说明 |
| --- | --- |
| `corp_id` | 企业微信 CorpID。 |
| `wecom_userid` | 企业微信成员 UserID。 |
| `kind` | `department` 或 `tag`。 |
| `target_id` | 部门 ID 或标签 ID。 |
| `last_sync_unix` | 最近同步时间。 |

### `enterprise_wecom_authz_mapping`

保存企业微信部门、标签或用户到 Gitea 组织/团队的映射；当前产品路径在 `MANAGED_ORG_ID` 对应组织自动派生 generated 状态，不提供人工维护。当前 Phase 2 不引入 repo role overlay 或外部 PDP。

| 字段 | 说明 |
| --- | --- |
| `corp_id` | 企业微信 CorpID。 |
| `agent_id` | 应用 AgentID；与 CorpID、来源、source/target 一起构成唯一边界。 |
| `origin` | `generated` 或 `legacy`，默认 `legacy`；历史迁移仅根据一致且唯一的 generated source/target/run 证据分类，不按名称或 `created_by=0` 收编。 |
| `source_type` | `user`、`department`、`tag`。 |
| `source_id` | `wecom_userid`、部门 ID 或标签 ID，统一保存为字符串。 |
| `target_type` | `org` 或 `team`。 |
| `org_id` | Gitea 组织 ID；team target 会校验 team 属于该 org。 |
| `team_id` | Gitea 团队 ID；org target 为 `0`。 |
| `is_active` | 是否参与 reconciliation；由自动化来源状态维护，DELETE API 不再 disable。 |
| `created_by` | 操作者。 |
| `created_unix` / `updated_unix` | 时间戳。 |

GET 仅返回当前配置 CorpID/AgentID/ManagedOrgID 内 `origin=generated` 的行，沿用原响应字段；legacy 与其他应用行不被读取、自动收编或修改。人工 mutation API 在权限检查后固定拒绝。完整发布应幂等：同一来源重复运行不得重复添加组织或团队成员；来源/目标冲突须停止并单独评审迁移，不自动搬迁权限。

### `enterprise_wecom_managed_membership`

记录哪些 Gitea org/team membership 是由企业微信映射创建，作为安全删除边界。

| 字段 | 说明 |
| --- | --- |
| `mapping_id` | 产生该 membership 的映射 ID。 |
| `user_id` | Gitea 用户 ID，仍是本地授权主体。 |
| `target_type` | `org` 或 `team`。 |
| `org_id` | Gitea 组织 ID。 |
| `team_id` | Gitea 团队 ID；org target 为 `0`。 |
| `last_apply_unix` | 最近一次 apply 时间。 |
| `last_seen_apply_id` | 最近一次 reconciliation 批次标识。 |

删除策略只删除有 managed-membership 记录且不再被任何 active mapping 需要的 membership；手工添加的团队成员不会被企业微信 reconciliation 删除；同一用户被多个 mapping 命中时，只要仍有一个 active mapping 需要该 membership，就保留实际团队成员关系。

### `enterprise_role_definition`

定义内置角色和自定义角色。

| 字段 | 说明 |
| --- | --- |
| `id` | 主键。 |
| `scope_type` | `system`、`org`、`repo`。 |
| `scope_id` | 作用域 ID；系统级为 0。 |
| `name` / `lower_name` | 角色名。 |
| `description` | 描述。 |
| `base_role_id` | 可选，表示基于哪个角色扩展。 |
| `is_builtin` | 是否内置角色。 |
| `created_unix` / `updated_unix` | 时间戳。 |

### `enterprise_role_permission`

角色到权限 action 的映射。

| 字段 | 说明 |
| --- | --- |
| `role_id` | 角色 ID。 |
| `action` | 如 `repo.read_code`、`repo.merge_pull_request`。 |
| `effect` | `allow` 或 `deny`；第一阶段可只支持 `allow`。 |
| `condition_json` | 可选条件，例如 branch、path、feature key。 |

### `enterprise_subject_role_binding`

把 Gitea 用户、团队、组织、系统主体或企业微信映射主体绑定到角色。

| 字段 | 说明 |
| --- | --- |
| `scope_type` / `scope_id` | 绑定生效范围。 |
| `subject_type` | `user`、`team`、`org`、`site_admin`、`wecom_user`、`wecom_department`、`wecom_tag`。 |
| `subject_id` | 主体 ID。 |
| `role_id` | 角色 ID。 |
| `created_by` | 操作者。 |
| `created_unix` / `updated_unix` | 时间戳。 |

### `enterprise_feature_definition`

当前 `add-enterprise-feature-grants` 的固定版本化目录；不开放任意定义 CRUD。

| 字段 | 说明 |
| --- | --- |
| `key` / `description` | 唯一稳定 key 与功能说明，固定 13 项。 |
| `supported_scopes_json` | 仅 global/org/repo；内部 global 映射 system。 |
| `default_state` / `capability_kind` | 七个 native_gate 默认 enabled，六个 policy_only 默认 disabled。 |
| `config_schema_version` / `catalog_version` | 配置 schema 与 immutable seed 版本。 |
| `policy_revision` | 可变策略版本，独立于 seed/catalog 版本。 |
| `created_unix` / `updated_unix` | 时间戳。 |

### `enterprise_feature_grant`

| 字段 | 说明 |
| --- | --- |
| `feature_key` | 固定功能 key。 |
| `scope_type` / `scope_id` | 内部 system（ID=0）、org、repo；拒绝 team/user/branch/role。 |
| `state` | disabled、enabled、required、inherited。 |
| `config_json` | canonical 空配置或经校验 check_contexts，不存凭据/URL/命令字段。 |
| `revision` | expected_revision CAS；reset 保留 inherited 行，避免 ABA。 |
| `created_by` / `updated_by` | 当前本地操作者。 |
| `created_unix` / `updated_unix` | 时间戳。 |

唯一键为 `(feature_key, scope_type, scope_id)`。grant/revision/policy revision 与成功审计原子提交，不允许管理事务 fail-open。正式 migration 363 后 DB version 364，含 hook task 可信来源、repository InternalUsage 与 `enterprise_cargo_index_source` 唯一 `(index_repo_id, source_repo_id)` pair；不自动补 unit 或覆盖管理员 grant。

### `enterprise_policy_template`

保存默认治理模板。

| 字段 | 说明 |
| --- | --- |
| `scope_type` / `scope_id` | `global` 或 `org`。 |
| `name` / `lower_name` | 模板名。 |
| `template_json` | 角色、分支保护、required checks、功能授权、敏感路径规则。 |
| `is_default` | 是否默认应用。 |
| `version` | 策略版本。 |
| `created_unix` / `updated_unix` | 时间戳。 |

### `enterprise_policy_template_binding`

记录模板应用到组织或仓库的关系。

| 字段 | 说明 |
| --- | --- |
| `template_id` | 模板 ID。 |
| `target_type` / `target_id` | `org` 或 `repo`。 |
| `applied_version` | 应用的模板版本。 |
| `applied_by` | 操作者。 |
| `applied_unix` | 应用时间。 |

### `enterprise_protected_path_rule`

保存全局、组织和仓库级敏感路径规则。

| 字段 | 说明 |
| --- | --- |
| `scope_type` / `scope_id` | `global`、`org`、`repo`。 |
| `pattern` | glob 模式。 |
| `required_role` | 如 `Security Maintainer`。 |
| `required_check_contexts` | JSON 数组。 |
| `created_unix` / `updated_unix` | 时间戳。 |

### `enterprise_merge_gate_evaluation`

保存合并门禁决策快照。

| 字段 | 说明 |
| --- | --- |
| `repo_id` | 仓库 ID。 |
| `pull_id` / `issue_id` | PR 对应 ID。 |
| `head_sha` / `base_sha` | 评估时的 commit。 |
| `actor_id` | 发起合并的用户。 |
| `decision` | `allow`、`deny`、`bypass`。 |
| `reason_json` | 未满足项、通过项、bypass 原因。 |
| `policy_snapshot_json` | 角色、feature grant、branch protection、required checks 的快照。 |
| `created_unix` | 评估时间。 |

## 权限 action 模型

### 原生权限兼容映射

| Gitea 原生权限 | 默认映射 action |
| --- | --- |
| `AccessModeRead` + code unit read | `repo.view_metadata`、`repo.read_code`、`repo.clone` |
| `AccessModeWrite` + code unit write | `repo.create_branch`、`repo.push_branch`、`repo.create_pull_request` |
| `AccessModeWrite` + PR unit write | `repo.review_pull_request` |
| `AccessModeAdmin` | `repo.manage_branch_protection`、`repo.manage_webhook`、`repo.manage_ci` |
| `AccessModeOwner` | `repo.manage_secret`、`repo.manage_feature_grant`、`repo.transfer`、`repo.archive`、`repo.delete` |
| site admin | `platform.admin`，并可按配置映射到所有 repo action |

兼容策略：

1. `enterprise.authz.ENABLED=false` 时，只使用原生权限。
2. `ENABLED=true` 时，先加载原生权限作为基础 capability，再叠加企业角色绑定。
3. 自定义角色可增加细粒度权限，但不应绕过 repo 可见性、账号状态、禁用功能、分支保护和安全门禁。
4. 高风险 action 即使拥有角色权限，也必须满足动作特定 guard，例如删除仓库确认、secret 不泄露、保护分支直推限制。

### 内置角色默认权限

| 角色 | 默认 action |
| --- | --- |
| Guest | `repo.view_metadata`；Issue/Wiki 是否可见由 repo unit 和 feature grant 决定。 |
| Reporter | Guest + `repo.read_code`、`repo.clone`、读取 PR/CI 结果。 |
| Developer | Reporter + `repo.create_branch`、`repo.push_branch`、`repo.create_pull_request`。 |
| Reviewer | Reporter + `repo.review_pull_request`。 |
| Maintainer | Developer + Reviewer + `repo.merge_pull_request`、`repo.manage_webhook`、部分 `repo.manage_ci`。 |
| Security Maintainer | Reporter + `repo.review_pull_request`、`repo.manage_codeowners`、`repo.manage_ci`、安全扫描和敏感路径策略管理。 |
| Owner | repo 全部 action。 |
| Platform Admin | 全局模板、全局功能授权、平台审计和系统集成管理；repo 内动作仍记录跨组织审计。 |

## 功能授权模型

本节以当前 `add-enterprise-feature-grants` 合同为准；模板、敏感路径和完整 merge gate 仍是后续独立范围。详细 13-key 清单、真实协议/worker、API 与运维风险见 [功能授权手册](feature-grants-runbook.md)。

### 状态与作用域

仅 `global → 当前 owner 为组织时的 org → repo`，个人仓库跳过 org；没有 team/user/branch/role override。缺记录/inherited 不贡献本层配置，default 仅兜底且不锁下级；无锁用最近显式状态/完整配置。自根向下首个显式 disabled/required 锁获胜，下级不得开启 disabled 或关闭 required。旧下级冲突原样保留并明确投影，不按更新时间选胜者。required contexts 取有效 required 层并集并保留最近非冲突显式补充；inherited 必须空配置。

### 与原生配置及执行的关系

| 功能 | 本轮真实边界 |
| --- | --- |
| Issues/PR/Wiki/Packages | 最终 unit intent、内容/协议/聚合/shared service；disabled 阻止对应业务，required 防关闭，不提升 unit/资源权限。 |
| Webhooks | 管理、test/redelivery、入队与发送；repo-origin 的 org/system hook 同样尊重真实 repo 策略。 |
| CI secret management | 管理读取/新增/更新/复制受控；受权删除/吊销与正常 runner 消费保留。 |
| Required status checks | checks old/new、删除及优先级完整意图防降级；不改 checks 的其他字段可原生编辑。 |
| 六个外部 CI/扫描/AI key | policy_only 授权与 contexts 输出，不执行任务、不造 status、不新增 merge deny，不代表 Gitea Actions 总开关。 |

required 不补建 unit/hook/secret/check rule/adapter；查看 native_available/pending，不冒充已满足。普通 repo rename/transfer 保留稳定 ID grant，按新 owner 立即重算；marked Cargo index 禁止 owner transfer，rename 保留稳定用途与来源；repo/org 删除只清理对应 live grant，保留历史。disabled 无 feature DB 查询，shadow 不改变原生 deny/allow 或副作用，enforce 默认 fail-closed；显式 infra-only fallback 不得覆盖明确 deny 或管理事务。

Cargo Git index 的实际关联来源在每次更新/rebuild 的 Git commit 前永久追加，包删除/unlink 不清除；读取按全部历史来源 repo 的当前 packages 策略与当前 owner 解析，来源删除/未知拒绝。旧索引由真实系统 authority 离线核实完整 Git 历史，通过 `--confirm-index-purpose` 加完整可重复 `--source-repo-id` 或互斥 `--confirm-no-linked-history` 明确认领；不得仅看现存包、按名称猜用途或 rewrite 历史。未标记同名仓库 disabled 保留上游 lookup 而不赋 marker，enabled 不认作索引。

DB 配置/授权先锁资源后统一排序锁 definition，并在首副作用前校验完整最终 intent；PR 单项配置隐式创建 unit 也必须进入复合检查。清理仅原生受权删除/停用/吊销，以及固定派生索引身份的窄内部维护能力；不存在客户端 system/cleanup 通用旁路。

## 统一授权 evaluator

建议服务接口：

```go
type Subject struct {
    UserID int64
    TeamIDs []int64
    IsSiteAdmin bool
}

type Resource struct {
    RepoID int64
    OwnerID int64
    Branch string
    Path string
}

type Condition struct {
    FeatureKey string
    Ref string
    ChangedPaths []string
    RequestSource string
}

type Decision struct {
    Allowed bool
    Reason string
    MatchedRoles []string
    MissingActions []string
    FeatureState string
    AuditMetadata map[string]any
}
```

第一阶段可以不暴露完整泛型 API，但内部应按上述结构组织，避免在各路由里复制判断。

## 合并门禁 evaluator

新增 `services/enterpriseauthz/mergegate` 或同包子模块，统一评估 PR 是否可合并。

### 输入

- doer / subject。
- PR、base repo、head repo、base branch、head SHA。
- 原生 repo permission。
- branch protection rule。
- enterprise roles 和 feature grants。
- required status contexts。
- CODEOWNERS 结果。
- changed paths 和敏感路径规则。
- AI review / 安全扫描 / 质量门禁 status context。

### 输出

```text
Decision: allow | deny | bypass
BlockingReasons:
  - missing_action: repo.merge_pull_request
  - missing_required_check: security/gitleaks
  - missing_codeowner_review
  - sensitive_path_requires_security_maintainer
  - feature_required_check_not_satisfied: feature.ai_review
PolicySnapshot:
  roles
  feature grants
  branch protection
  required checks
  sensitive path rules
```

### 接入点

| 入口 | 接入方式 |
| --- | --- |
| Web merge button | `routers/web/repo/pull.go` 调用 evaluator 决定 merge box 状态。 |
| Web merge POST | `routers/web/repo/pull.go:MergePullRequest` 在实际 merge 前强制调用。 |
| API merge | `routers/api/v1/repo/pull.go:MergePullRequest` 强制调用。 |
| Auto merge | scheduled merge 触发前调用同一 evaluator。 |
| Force merge | evaluator 标记 `bypass`，并保存 bypass 原因，不直接跳过所有检查。 |

## 敏感路径保护

默认路径从需求文档迁入全局模板，而不是硬编码在业务代码中。首批默认规则：

```text
.woodpecker.yml
.woodpecker/**
Dockerfile
Dockerfile.*
docker-compose.yml
compose.yml
k8s/**
helm/**
charts/**
migrations/**
sql/**
terraform/**
ansible/**
secrets.example
.env.example
.github/**
```

命中敏感路径时：

1. 必须满足 CODEOWNERS 或 Security Maintainer 审批。
2. 必须满足 required checks。
3. 若 `feature.ai_review` 为 `required` 或配置为 blocking，则 AI review status 必须通过。
4. 结果写入 `enterprise_merge_gate_evaluation.reason_json`。

## API 方案

新增 API 必须复用 Gitea token、session 和现有 repo/org/admin assignment。

### Phase 2 授权映射上线顺序

1. 按 runbook 停止全部旧 writer，取得一致完整备份；在隔离副本验证 additive 迁移、mapping `agent_id`/`origin`、协调与 receipt、历史证据分类及来源冲突。
2. 部署同一新版本并显式配置 `MANAGED_ORG_ID`、完整目录和可信 authority 来源；cron 与 callback 保持关闭，弃用 `APPLY_AUTHZ_MAPPINGS_ON_SYNC` 不作为启停开关。
3. 在预生产验证完整发布及失败注入：目录/identity/authority/generated/native/managed 状态原子提交，失败保持上次完整状态与零已应用计数；inactive、left、out-of-scope、unbound identity 不新增授权。
4. 验证只读 generated GET、legacy mutation 固定 410 与 token/admin scope/企微 authority guard，确认 SSH key、PAT/API token、Git HTTP token 与 Web login-only 回归通过。
5. 完成 gate 后恢复 cron，观察首次成功 run/revision 与实际计数；callback 必须另外完成真实应用模式 fixture 和 URL 验证，不能以本地测试代替。

暂停、登录回退、离线管理员恢复、二进制回退和成套备份恢复按 runbook 执行。已发布的 Gitea membership 是普通本地状态；不通过人工 mapping API、弃用 flag、手工 SQL 或删除新字段绕过协调与审计。

### 企业微信身份 API

| API | 权限 |
| --- | --- |
| `GET /api/v1/enterprise/wecom/status` | site admin 或 platform admin。 |
| `POST /api/v1/enterprise/wecom/sync` | site admin、platform admin 或系统任务 token。 |
| `GET /api/v1/enterprise/wecom/identities` | site admin 或 platform admin。 |
| `GET /api/v1/enterprise/wecom/mappings` | token + admin scope + `reqSiteAdmin`；读取当前 CorpID/AgentID/ManagedOrgID 的 active generated mappings，`include_inactive=true` 不扩大作用域。 |
| `POST /api/v1/enterprise/wecom/mappings` | 同一 guard；deprecated，权限通过后固定 410 `manual_mapping_unavailable`。 |
| `GET /api/v1/enterprise/wecom/mappings/{id}` | 同一 guard；读取作用域内单条 generated mapping（可含 inactive）；legacy/其他作用域或不存在 ID 为 404。 |
| `PATCH /api/v1/enterprise/wecom/mappings/{id}` | 同一 guard；deprecated，权限通过后固定 410，不查 ID、不绑定 body。 |
| `DELETE /api/v1/enterprise/wecom/mappings/{id}` | 同一 guard；deprecated，权限通过后固定 410，不 disable 或删除。 |
| `POST /api/v1/enterprise/wecom/mappings/dry-run` | 同一 guard；deprecated，权限通过后固定 410，不运行 planner。 |
| `POST /api/v1/enterprise/wecom/mappings/apply` | 同一 guard；deprecated，权限通过后固定 410，不修改 mapping/成员。 |

mapping group 保留 `tokenRequiresScopes(Admin)`、`reqToken()`、`reqSiteAdmin()`；治理启用时后台 guard 还要求当前应用 active、bound management authority，本地 site-admin 不能绕过。无 token 为 401，缺 scope/普通用户/无企微 authority 的本地 admin 为 403。无有效目标时 list 为 `[]`、detail 为 404；治理关闭时 GET 为 404。人工接口即使空/坏 body 或不存在 ID 也在权限通过后返回 410 并记录安全拒绝审计；Swagger 只声明真实 401/403/410，无成功响应和请求 body 契约。

企业微信 OAuth callback 属于 Web 登录入口，不作为公开管理 API 暴露；callback 必须校验 `state`，并拒绝非配置企业和非成员身份。

### 系统级 API

| API | 权限 |
| --- | --- |
| `GET /api/v1/enterprise/authz/roles` | site admin 或 platform admin。 |
| `POST /api/v1/enterprise/authz/roles` | site admin 或 platform admin。 |
| `GET /api/v1/enterprise/authz/features` | admin read scope + 当前可信系统管理 authority；企业 Platform Admin 角色不能委派 authority。 |
| `GET/PUT/DELETE /api/v1/enterprise/authz/features/{key}/grants/global` | admin read/write scope + 当前可信系统管理 authority。 |
| `GET /api/v1/enterprise/authz/audit` | site admin、platform admin、auditor。 |

### 组织级 API

| API | 权限 |
| --- | --- |
| `GET /api/v1/orgs/{org}/enterprise/authz/roles` | org owner 或授权管理员。 |
| `POST /api/v1/orgs/{org}/enterprise/authz/roles` | org owner。 |
| `GET /api/v1/orgs/{org}/enterprise/authz/features` | organization read scope + 当前 org owner 或可信系统管理 authority。 |
| `GET/PUT/DELETE /api/v1/orgs/{org}/enterprise/authz/features/{key}` | organization read/write scope + 同一 org authority；repo action 不委派 org authority。 |
| `POST /api/v1/orgs/{org}/enterprise/authz/templates/apply` | org owner。 |

### 仓库级 API

| API | 权限 |
| --- | --- |
| `GET /api/v1/repos/{owner}/{repo}/enterprise/authz/effective-permissions` | repo admin 或查询自己。 |
| `GET /api/v1/repos/{owner}/{repo}/enterprise/authz/features[/{key}]` | 已认证原生 reader + repository read scope/credential ceiling，仅无敏感 effective 投影。 |
| `GET /api/v1/repos/{owner}/{repo}/enterprise/authz/features/{key}/grant` | repository read scope + 当前 repo 授权管理 authority，返回 raw 管理投影。 |
| `PUT/DELETE /api/v1/repos/{owner}/{repo}/enterprise/authz/features/{key}` | repository write scope/credential ceiling + 当前 repo 授权管理 authority + `repo.manage_feature_grant`，shadow 同样检查。 |
| `POST /api/v1/repos/{owner}/{repo}/enterprise/authz/templates/apply` | Owner 或 `repo.manage_feature_grant`。 |
| `GET /api/v1/repos/{owner}/{repo}/enterprise/merge-gate/{index}` | repo reader + PR reader。 |

所有新增或变更 API 必须更新 swagger：

```bash
make generate-swagger
make swagger-validate
```

## 前端管理入口

| 页面 | 能力 | 入口权限 key |
| --- | --- | --- |
| Site Admin / Enterprise Authorization | 全局角色、全局功能、全局模板、平台审计 | `platform.admin` 或 `platform.authz.manage` |
| Org Settings / Authorization | 组织角色、组织功能、组织模板 | `org.authz.manage` |
| Repo Settings / Authorization | 仓库角色绑定、功能授权、模板应用 | `repo.manage_feature_grant` |
| Repo Settings / Branches | 分支保护和敏感路径规则 | `repo.manage_branch_protection`、`repo.manage_codeowners` |
| Pull Request merge box | 展示 merge gate 阻断原因 | `repo.read_code` + PR read |

前端入口必须和后端 API 权限一致：后端允许但无入口、前端展示但后端 403，都视为缺陷，除非对应能力明确列为 API-only。

## 审计日志

复用 `models/audit.Event`。新增 action 建议：

```text
enterprise:wecom:login:success
enterprise:wecom:login:deny
enterprise:wecom:identity:bind
enterprise:wecom:identity:update
enterprise:wecom:sync:start
enterprise:wecom:sync:finish
enterprise:wecom:mapping:update
enterprise:role:create
enterprise:role:update
enterprise:role:delete
enterprise:role:binding:add
enterprise:role:binding:remove
enterprise:feature:grant:update
enterprise:template:create
enterprise:template:update
enterprise:template:apply
enterprise:protected_path:create
enterprise:protected_path:update
enterprise:protected_path:delete
enterprise:merge_gate:evaluate
enterprise:merge_gate:bypass
```

审计 metadata 至少包含：

```text
before
 after
decision
reason
request_id
policy_snapshot_id 或 merge_gate_evaluation_id
```

secret、token、私钥和外部系统凭据不得写入 metadata 明文。

## Git 和写路径接入点

企业微信不改变 Git 认证方式。下表覆盖的是 repo action 授权和合并门禁，不是 SSH/PAT/Git HTTP token 的登录替换。

| 操作 | 必须覆盖的入口 |
| --- | --- |
| clone/fetch | Git HTTP、SSH。 |
| push 普通分支 | Git HTTP receive、SSH receive、API/file editor 创建 commit。 |
| push 保护分支 | receive hook、branch protection、file editor、API branch/file endpoints。 |
| 创建 PR | Web、API、fork PR。 |
| review PR | Web、API review endpoints。 |
| merge PR | Web、API、auto merge。 |
| secret/webhook/CI 设置 | Web settings、API、Actions settings。 |
| 迁移仓库 | Web migrate、API migrate、batch migration。 |

第一阶段优先覆盖高风险写路径：merge、protected branch push、secret、webhook、branch protection、feature grant。

## 默认模板应用

### 新建组织

1. 创建组织原生 owners team。
2. 应用全局默认组织模板。
3. 创建组织级内置角色定义或引用系统内置角色。
4. 写审计事件。

### 新建仓库

1. 创建仓库后加载全局和组织默认仓库模板。
2. 设置默认 visibility、repo units、branch protection、required checks、敏感路径规则。
3. 建立默认角色绑定。
4. 写 `enterprise_policy_template_binding`。
5. 写审计事件。

### GitHub 迁移后

1. 完成 Git history、branch、tag、LFS、issue/PR 等迁移。
2. 应用组织或仓库模板。
3. 配置 Woodpecker webhook 或外部 CI status context。
4. 输出迁移校验报告。
5. 若模板应用失败，仓库进入安全只读状态，并在报告中标记。

## 分阶段实施

### Phase 0：企业微信接入基线验证

- [ ] 确认企业微信应用类型、可信回调域、`CORP_ID`、`AGENT_ID`、secret 管理方式。
- [ ] 验证企业微信网页授权能返回稳定 `userid`。
- [ ] 验证应用可见范围可以读取所需部门、成员和标签数据。
- [ ] 确认关闭 Web 密码、注册、账号恢复、账号激活、账号绑定登录、OpenID、Passkey、reverse-proxy、SSPI 和其它 OAuth2 登录，不改变 SSH key、PAT、Git HTTP token 行为。
- [ ] 补充 OpenSpec 或等价变更任务清单。

### Phase 1：企业微信唯一 Web 登录和身份绑定

- [ ] 新增企业微信登录源/provider 或专用 auth source。
- [ ] 新增 `[enterprise.wecom]` 配置读取和校验。
- [ ] 实现企业微信 OAuth code flow、callback、state 校验、corp/agent 校验。
- [ ] 新增 `enterprise_wecom_identity` 及必要 migration。
- [ ] 首次企业微信登录自动创建或绑定 Gitea user。
- [ ] 企业模式下隐藏并拒绝全部非企业微信 Web 登录入口，仅允许企业微信登录后的本地 MFA 续接。
- [ ] 增加 SSH key、PAT、Git HTTP token 不受企业微信登录改造影响的回归测试。

### Phase 2：企业微信通讯录同步和授权映射

- [ ] 新增 `enterprise_wecom_department`、`enterprise_wecom_tag`、`enterprise_wecom_membership`、`enterprise_wecom_authz_mapping`。
- [ ] 实现部门、成员、标签同步任务和手动同步 API。
- [ ] 实现企业微信用户/部门/标签到 Gitea 组织、团队、企业角色的幂等映射。
- [ ] 明确离职、禁用、不可见成员策略：默认阻止新的 Web 登录，不主动删除 SSH key、PAT 或 Git HTTP token。
- [ ] 增加同步幂等、映射应用、未授权用户拒绝 Web 登录测试。

### Phase 3：角色和 repo action overlay

- [ ] 新增 `enterprise_role_definition`、`enterprise_role_permission`、`enterprise_subject_role_binding`。
- [ ] 新增内置角色 seed migration。
- [ ] 实现 repo action evaluator，支持企业微信映射主体参与角色解析。
- [ ] 在 merge、branch protection、webhook、secret 等高风险入口接入 evaluator。
- [ ] 增加 403 负例、默认管理员正例、自定义角色正例测试。

### Phase 4：功能授权

- [ ] 新增 `enterprise_feature_definition`、`enterprise_feature_grant`。
- [ ] 实现 feature state 继承解析。
- [ ] 接入七个 native_gate 的真实业务/配置/worker/protocol；六个外部 CI/扫描/AI key 仅 policy_only 输出，不执行任务或新增 merge gate。
- [ ] 禁止仓库关闭上级 `required` 功能。
- [ ] 增加 API、service 和集成测试。

### Phase 5：合并门禁和敏感路径

- [ ] 新增 `enterprise_protected_path_rule`。
- [ ] 新增 `enterprise_merge_gate_evaluation`。
- [ ] 抽出 merge gate evaluator。
- [ ] 统一 Web merge、API merge、auto merge、force merge 路径。
- [ ] 保存策略快照和审计事件。
- [ ] 覆盖 required checks、CODEOWNERS、敏感路径、AI review blocking 测试。

### Phase 6：默认治理模板

- [ ] 新增 `enterprise_policy_template`、`enterprise_policy_template_binding`。
- [ ] 支持全局和组织默认模板。
- [ ] 新建仓库自动应用模板。
- [ ] GitHub 迁移后应用模板和输出校验报告。
- [ ] 增加 migration、repo creation、migration integration 测试。

### Phase 7：管理界面和运营完善

- [ ] 增加 site admin、org settings、repo settings 管理页面。
- [ ] 增加企业微信身份、同步状态和生成映射只读页面，不提供本地 mapping CRUD/dry-run/apply。
- [ ] 增加 merge gate 结果展示。
- [ ] 增加审计日志过滤和导出。
- [ ] 补齐前端权限显隐测试和 e2e smoke test。

## 测试策略

| 层级 | 覆盖内容 |
| --- | --- |
| unit test | 企业微信身份解析、action 映射、角色继承、feature grant 继承、merge gate reason。 |
| migration test | 新表、内置角色 seed、默认 feature seed、回放幂等性。 |
| integration test | 企业微信 Web 登录、非企业微信 Web 登录拒绝、API 403/200、自定义角色授权、模板应用、merge gate 阻断。 |
| Git path test | clone/fetch、push 普通分支、push protected branch；验证 SSH key、PAT、Git HTTP token 机制未被企业微信登录改造破坏。 |
| e2e smoke | settings 页面入口显隐、merge box 阻断原因展示。 |
| audit test | 权限变更、feature grant、merge gate evaluate/bypass 事件。 |

单测优先；只有跨 Web/API/Git path 的能力使用 integration 或 e2e。

## 权限闭环矩阵

本仓库不是注解式权限框架，也不引入 OpenFGA。下表中的“后端防护”使用当前 Gitea middleware/service/check 名称表达；“OpenFGA/外部关系”列固定为“不适用”。

| 入口/API | 后端防护 | OpenFGA/外部关系 | 默认授权角色 | 前端入口 key |
| --- | --- | --- | --- | --- |
| Web 登录页 | 企业模式自动跳转企业微信；密码登录 POST 403 | 不适用 | 企业微信活跃成员 | `auth.login.wecom` |
| 企业微信 OAuth callback | state/corp/agent/userid 校验 + 账号绑定 | 不适用 | 企业微信活跃成员 | 无 |
| 本地 Web 密码登录/注册/OpenID/Passkey | 企业模式禁用或隐藏 | 不适用 | 无 | 隐藏对应入口 |
| SSH key 登录 | 原生 SSH auth，不新增企业微信校验 | 不适用 | 原生 Gitea 用户权限 | 无 |
| PAT/API token | 原生 token auth，不新增企业微信校验 | 不适用 | 原生 Gitea token scope/用户权限 | 无 |
| Git HTTP token | 原生 Git HTTP token/Basic token auth，不新增企业微信校验 | 不适用 | 原生 Gitea 用户权限 | 无 |
| 企业微信同步 | site admin/platform admin guard 或系统任务 token | 不适用 | Platform Admin、system job | `enterprise.wecom.sync` |
| 企业微信生成映射读取/人工接口拒绝 | token + admin scope + `reqSiteAdmin`；治理启用时 active bound management authority | 不适用 | 企微派生系统超级管理员；人工 mutation 固定 410 | 无本地维护入口 |
| 查看仓库元数据 | repo assignment + visibility + `repo.view_metadata` | 不适用 | Guest+ | `repo.metadata.read` |
| 浏览代码/commit/branch/tag | `Permission.CanRead(unit.TypeCode)` + `repo.read_code` | 不适用 | Reporter+ | `repo.code.read` |
| clone/fetch | Git HTTP/SSH auth + `repo.clone` | 不适用 | Reporter+ | 无 |
| 创建普通分支 | `reqRepoWriter(unit.TypeCode)` + `repo.create_branch` | 不适用 | Developer+ | `repo.branch.create` |
| push 普通分支 | receive hook + `repo.push_branch` | 不适用 | Developer+ | 无 |
| push 保护分支 | branch protection + `repo.push_protected_branch` | 不适用 | Owner、Platform Admin、显式授权用户 | `repo.branch.protected_push` |
| 创建 PR | Pull Requests unit + `repo.create_pull_request` | 不适用 | Developer+ | `repo.pr.create` |
| 提交 review | review endpoint + `repo.review_pull_request` | 不适用 | Reviewer+ | `repo.pr.review` |
| 合并 PR | merge gate + `repo.merge_pull_request` | 不适用 | Maintainer+ | `repo.pr.merge` |
| 管理分支保护 | `repo.manage_branch_protection` | 不适用 | Owner、Security Maintainer | `repo.branch_protection.manage` |
| 管理 CODEOWNERS/敏感路径 | `repo.manage_codeowners` | 不适用 | Owner、Security Maintainer | `repo.codeowners.manage` |
| 管理 webhook | `repo.manage_webhook` + webhooks enabled | 不适用 | Maintainer+、Owner | `repo.webhook.manage` |
| 管理 CI/required checks | `repo.manage_ci` | 不适用 | Maintainer+、Security Maintainer | `repo.ci.manage` |
| 管理 repo secret | `repo.manage_secret` | 不适用 | Owner | `repo.secret.manage` |
| 管理功能授权 | `repo.manage_feature_grant` | 不适用 | Owner、Platform Admin | `repo.feature_grant.manage` |
| 仓库迁移 | `repo.migrate` + feature grant | 不适用 | Owner、Platform Admin | `repo.migration.manage` |
| 转移仓库 | `repo.transfer` + danger-zone guard | 不适用 | Owner、Platform Admin | `repo.transfer` |
| 归档仓库 | `repo.archive` + danger-zone guard | 不适用 | Owner、Platform Admin | `repo.archive` |
| 删除仓库 | `repo.delete` + danger-zone guard + confirmation | 不适用 | Owner、Platform Admin | `repo.delete` |
| 全局角色/模板/功能 | site admin/platform admin guard | 不适用 | Platform Admin | `platform.authz.manage` |
| 组织角色/模板/功能 | org owner + enterprise org action | 不适用 | Org Owner | `org.authz.manage` |

## Migration 判断

| 类型 | 是否需要 | 说明 |
| --- | --- | --- |
| DB/modelmigration | 需要 | 新增企业微信身份/部门/标签/映射表、enterprise 表、内置角色、默认 feature、模板和 merge gate 快照。 |
| OpenFGA | 不需要 | 当前仓库未使用 OpenFGA；为保持浅 fork，不引入外部 PDP。 |
| Keycloak | 不需要 | 当前方案直接对接企业微信，不引入 Keycloak，也不改外部 IdP scope、mapper 或 token claim。 |
| Swagger | 需要 | 新增或修改 API 后必须 `make generate-swagger` 和 `make swagger-validate`。 |
| 前端 locale | 需要时 | UI 文案只编辑 `options/locale/locale_en-US.json`。 |
| 配置文档 | 需要 | 新增 `[enterprise.wecom]`、`[enterprise.authz]` 后更新 `custom/conf/app.example.ini` 和配置文档。 |

## 验收标准

第一阶段完成后：

- Web 登录只能通过企业微信完成。
- 企业微信 `userid` 可以稳定绑定到 Gitea 用户。
- 本地 Web 密码登录、注册、OpenID、Passkey、其它 OAuth2 登录源被隐藏或拒绝。
- SSH key、PAT、Git HTTP token 的原有机制仍可按 Gitea 逻辑使用。
- 企业微信登录成功、拒绝、身份绑定写审计日志。

第三阶段完成后：

- 可以定义 repo 自定义角色。
- 可以给用户或团队绑定 repo 角色。
- 关键写入口通过企业 action evaluator 做 allow/deny。
- 未授权用户访问写 API 返回 403。
- 默认 Owner/管理员仍可完成原有管理动作。
- 自定义角色授权后可访问对应动作。
- 相关权限变更写审计日志。
- SQLite 下有单元测试或集成测试覆盖核心判断。

第五阶段完成后：

- Web/API/auto merge 使用同一 merge gate evaluator。
- required checks、CODEOWNERS、敏感路径和 feature-required checks 均可阻断合并。
- merge gate 保存结构化评估结果和策略快照。
- force merge/bypass 被审计且说明原因。

第七阶段完成后：

- 管理界面提供企业微信生成映射只读查询；常用角色、功能授权、模板、敏感路径和审计查询仍按后续阶段范围实施，不恢复人工 mapping 维护。
- GitHub 迁移后可自动应用治理模板并输出校验报告。
- Woodpecker、SonarQube、Semgrep、Gitleaks、Trivy、AI Review Bot 均能以 required check 方式参与门禁。

## 企业微信官方参考

- 企业微信网页授权“构造网页授权链接”：`https://developer.work.weixin.qq.com/document/path/91022`。
- 企业微信网页授权“获取访问用户身份”：`https://developer.work.weixin.qq.com/document/path/91023`。
- 企业微信通讯录“获取部门成员”：`https://developer.work.weixin.qq.com/document/path/90200`。
- 企业微信通讯录“获取部门成员详情”：`https://developer.work.weixin.qq.com/document/path/90201`。
- 企业微信通讯录“获取部门列表”：`https://developer.work.weixin.qq.com/document/path/90208`。
- 企业微信标签“获取标签成员”：`https://developer.work.weixin.qq.com/document/path/90213`。

## 待确认问题

1. 企业微信应用使用自建应用、代开发应用还是第三方应用；不同模式的授权、token 和通讯录权限不同。
2. 首次登录是否允许自动创建用户，还是必须由同步任务预创建。
3. 企业微信用户离职或离开应用可见范围时，是否只禁止新的 Web 登录，还是同步禁用 Gitea 用户。
4. 是否允许通过配置临时关闭 `enterprise.wecom.LOGIN_ONLY` 做紧急恢复；默认不保留 Web 本地管理员后门。
5. 是否需要把企业授权作为长期 feature flag，还是在稳定后默认开启。
6. 自定义角色是否支持 `deny`，还是第一阶段只支持 additive `allow`。
7. site admin 是否默认绕过所有 repo gate，还是只能 bypass 管理类动作，不能绕过安全扫描和签名要求。
8. AI review 的 status context 命名规范，例如 `review/ai` 是否固定。
9. Woodpecker 历史只读展示是新增聚合页，还是先使用外链。
10. 管理界面是否第一阶段必须交付，还是先提供 API 和 migration。

## 2026-10-01：Proposal 2 shadow 基础实施边界

`add-enterprise-authz-foundation-shadow` 已接入角色/绑定、19-action evaluator、受原生 authority 保护的 API 与真实入口旁观。system/org/repo 为作用域，user/team/org 为主体，只支持 additive allow；八个内置角色不可变，迁移不回填绑定。当前角色授权只产生候选判断，不让尚无原生写权限的用户写仓库，也不会绕过 unit、凭据 scope、分支保护或企微安全守卫。

上文第三阶段的 action enforce/403 和第五阶段的 merge gate 验收仍属于后续独立提案，不因本次 shadow 实施完成而自动完成。feature grant、策略模板、offboarding 和授权 UI 同样未实现。本次无 Windows 服务端验收，callback 持续关闭，采用合法登录刷新与定时完整同步。

配置/管理/查询/容量/关闭与成套恢复见 [shadow 运维手册](authz-shadow-runbook.md)。当前验证结果及未通过项统一记在本 change 的 `verification.md`，不以本文替代测试或生产上线 gate；没有提交、推送或归档。

## 2026-10-05：Proposal 4 当前实施与上线前置条件

当前实现提供固定 13-key global/org/repo 功能策略、四态上级锁、strict config、CAS/reset、受权 API/安全投影、真实 native_gate 与原子审计；不增加功能 UI。迁移 363 后 DB version 364，feature catalog v1；已有 action catalog v2 和前序历史解释保持独立。实施完成度与 Linux SQLite/PostgreSQL 实跑证据由 `openspec/changes/add-enterprise-feature-grants/tasks.md` / `verification.md` 管理，上文长期阶段清单不替代本 change 验收。

新 Cargo 索引写 InternalUsage=cargo-index；旧同名仓库不按名字自动认领。enabled preflight 的 cargo_index_purpose_unresolved 必须经用途/稳定 ID 核实、disabled 离线维护及审计 DB CLI 认领，实际普通代码仓库则原生受权重命名解除冲突。旧 mail 队列没有可信 IssueID，必须停全部生产者/实例/worker，备份并仅隔离 mail 队列，禁止删 common 共享目录；旧 hook 不能恢复可信来源则 enforce fail-closed。完整操作与积压处置风险见 [功能授权手册](feature-grants-runbook.md)。

同版 shadow/disabled 回退保留政策/历史；旧 binary 不降 schema，必须 DB+Git/Wiki+storage+queue+配置完整匹配恢复。没有生产部署、队列处置或完整恢复实跑证据时不得宣称完成；前序 change 验收文档不改写。
