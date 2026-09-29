# Gitea Enterprise Authorization Implementation Plan

## 目的

本文档把 [`requirements.md`](requirements.md) 中的企业授权需求收敛成可执行的实施方案。方案目标是在保持浅 fork、降低上游合并冲突的前提下，复用 Gitea 现有权限、分支保护、required checks、Actions 和审计日志能力，补齐企业微信唯一 Web 登录、企业微信用户标识、企业级 repo 授权、功能授权、默认治理模板和合并门禁。

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
CORP_SECRET_URI =
; CORP_SECRET =            # 仅用于本地应急/测试，生产优先使用 CORP_SECRET_URI
LOGIN_ONLY = true
LOGIN_SOURCE_NAME = enterprise-wecom
AUTO_CREATE_USER = true
USERNAME_TEMPLATE = {userid}
SYNC_DEPARTMENTS = true
SYNC_TAGS = true
HTTP_TIMEOUT = 15s
API_BASE_URL = https://qyapi.weixin.qq.com
OAUTH_BASE_URL = https://login.work.weixin.qq.com

[cron.sync_enterprise_wecom_directory]
ENABLED = true
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
| `CORP_SECRET_URI` / `CORP_SECRET` | 企业微信应用 secret。生产优先使用 `CORP_SECRET_URI` 安全引用，`CORP_SECRET` 仅用于本地应急或测试。 |
| `LOGIN_ONLY=true` | 企业模式下 Web 登录只允许企业微信；本地密码、注册、OpenID、Passkey、其它 OAuth2 登录源应关闭或隐藏。 |
| `LOGIN_SOURCE_NAME` | 唯一允许用于企业微信 Web 登录的 active OAuth2 source 名称。 |
| `AUTO_CREATE_USER=true` | 企业微信成员首次登录时自动创建 Gitea 用户；用户名从 `USERNAME_TEMPLATE` 派生并做冲突处理。 |
| `SYNC_DEPARTMENTS` / `SYNC_TAGS` | 是否同步企业微信部门和标签，用作授权映射来源。 |
| `HTTP_TIMEOUT` | 单次企业微信 HTTP 请求超时。 |
| `API_BASE_URL` / `OAUTH_BASE_URL` | 企业微信 API 与浏览器 Web/扫码 OAuth 登录地址；仅在内网代理、私有网关或测试端点下覆盖默认值。 |

安全上线顺序：先在 `ENABLED=false` 下配置凭据并创建与 `LOGIN_SOURCE_NAME` 同名的 active WeCom OAuth2 source；再以 `ENABLED=true, LOGIN_ONLY=false` 灰度验证；最后开启 `LOGIN_ONLY=true`。login-only 启动预检失败时，应先回退 `LOGIN_ONLY=false`，不得通过手工修改认证数据绕过检查。

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

企业授权后续表建议统一使用 `enterprise_` 前缀。首批 `wecom-only-web-login` 已先落地企业微信身份和目录快照基础表，使用较短的 `wecom_` 前缀以保持改动浅层且聚焦登录边界；后续若扩展为完整授权映射，可在 migration 中补充 `enterprise_*` 表或兼容视图。


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

把企业微信部门、标签或用户映射到 Gitea 授权目标。

| 字段 | 说明 |
| --- | --- |
| `corp_id` | 企业微信 CorpID。 |
| `wecom_subject_type` | `user`、`department`、`tag`。 |
| `wecom_subject_id` | `wecom_userid`、部门 ID 或标签 ID。 |
| `target_type` | `org`、`team`、`enterprise_role`、`repo_role`。 |
| `target_id` | Gitea 目标 ID。 |
| `scope_type` / `scope_id` | 映射生效范围，支持 `global`、`org`、`repo`。 |
| `created_by` | 操作者。 |
| `created_unix` / `updated_unix` | 时间戳。 |

映射应用应幂等：同一同步批次重复执行不得重复添加团队成员或角色绑定。

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

登记平台能力。

| 字段 | 说明 |
| --- | --- |
| `key` | 如 `feature.ai_review`。 |
| `description` | 功能说明。 |
| `supported_scopes` | JSON，允许的作用域。 |
| `default_state` | 默认状态。 |
| `created_unix` / `updated_unix` | 时间戳。 |

### `enterprise_feature_grant`

记录功能授权状态。

| 字段 | 说明 |
| --- | --- |
| `feature_key` | 功能 key。 |
| `scope_type` / `scope_id` | `global`、`org`、`repo`、`team`、`user`、`branch`。 |
| `state` | `disabled`、`enabled`、`required`、`inherited`。 |
| `config_json` | 功能特定配置，如 required check context。 |
| `created_by` | 操作者。 |
| `created_unix` / `updated_unix` | 时间戳。 |

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

### 状态优先级

功能状态从上到下解析：

```text
global -> org -> repo -> team/user/branch override
```

建议规则：

1. 任一上级为 `disabled` 时，下级不能自行开启，除非该 feature 显式允许 lower-scope override。
2. 任一上级为 `required` 时，下级不能关闭，只能补充配置。
3. `enabled` 表示允许使用，但不强制作为合并门禁。
4. `inherited` 表示继续向上查找。
5. 未配置时使用 `enterprise_feature_definition.default_state`。

### 与 repo unit 的关系

| 功能 | 与现有 repo unit 的关系 |
| --- | --- |
| `feature.issues` | 控制 Issues unit 是否可开启；最终读写仍走 Issues unit 权限。 |
| `feature.pull_requests` | 控制 Pull Requests unit 是否可开启；合并仍走 merge gate。 |
| `feature.packages` | 控制 Packages unit 是否可开启。 |
| `feature.wiki` | 控制 Wiki unit 是否可开启。 |
| `feature.woodpecker_ci` | 不替换 Gitea Actions；以 webhook/status check/外链形式接入。 |
| `feature.required_status_checks` | 决定是否允许管理 required checks，以及是否强制模板检查。 |
| `feature.ai_review` | 决定是否触发 AI 审计、是否作为 required check、读取范围。 |
| `feature.protected_file_patterns` | 决定敏感路径规则是否生效。 |

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


### 企业微信身份 API

| API | 权限 |
| --- | --- |
| `GET /api/v1/enterprise/wecom/status` | site admin 或 platform admin。 |
| `POST /api/v1/enterprise/wecom/sync` | site admin、platform admin 或系统任务 token。 |
| `GET /api/v1/enterprise/wecom/identities` | site admin 或 platform admin。 |
| `GET /api/v1/enterprise/wecom/mappings` | site admin 或 platform admin。 |
| `PUT /api/v1/enterprise/wecom/mappings` | platform admin。 |

企业微信 OAuth callback 属于 Web 登录入口，不作为公开管理 API 暴露；callback 必须校验 `state`，并拒绝非配置企业和非成员身份。

### 系统级 API

| API | 权限 |
| --- | --- |
| `GET /api/v1/enterprise/authz/roles` | site admin 或 platform admin。 |
| `POST /api/v1/enterprise/authz/roles` | site admin 或 platform admin。 |
| `GET /api/v1/enterprise/authz/features` | site admin 或 platform admin。 |
| `PUT /api/v1/enterprise/authz/features/{key}/grants/global` | platform admin。 |
| `GET /api/v1/enterprise/authz/audit` | site admin、platform admin、auditor。 |

### 组织级 API

| API | 权限 |
| --- | --- |
| `GET /api/v1/orgs/{org}/enterprise/authz/roles` | org owner 或授权管理员。 |
| `POST /api/v1/orgs/{org}/enterprise/authz/roles` | org owner。 |
| `GET /api/v1/orgs/{org}/enterprise/authz/features` | org owner 或授权管理员。 |
| `PUT /api/v1/orgs/{org}/enterprise/authz/features/{key}` | org owner 或 `repo.manage_feature_grant` 等价组织权限。 |
| `POST /api/v1/orgs/{org}/enterprise/authz/templates/apply` | org owner。 |

### 仓库级 API

| API | 权限 |
| --- | --- |
| `GET /api/v1/repos/{owner}/{repo}/enterprise/authz/effective-permissions` | repo admin 或查询自己。 |
| `GET /api/v1/repos/{owner}/{repo}/enterprise/authz/features` | repo admin。 |
| `PUT /api/v1/repos/{owner}/{repo}/enterprise/authz/features/{key}` | `repo.manage_feature_grant`。 |
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
- [ ] 接入 Issues、PR、Wiki、Packages、Webhooks、Actions/CI、AI review 等首批功能。
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
- [ ] 增加企业微信身份、同步状态、映射管理页面。
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
| 企业微信授权映射管理 | site admin/platform admin guard | 不适用 | Platform Admin | `enterprise.wecom.mapping.manage` |
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

- 管理界面可以完成企业微信身份映射、常用角色、功能授权、模板、敏感路径和审计查询操作。
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
