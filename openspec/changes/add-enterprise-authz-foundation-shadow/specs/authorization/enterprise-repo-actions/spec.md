## Purpose

建立企业 repo action、角色与主体绑定的可解释授权基础，在保持 Gitea 原生认证及请求结果不变的前提下，对真实操作进行 shadow 评估和审计，为后续独立的 enforce 变更提供策略与兼容性证据。

服务端部署与验收永久仅面向 Linux，不包含 Windows 服务端或原生 SSPI 运行验收；Windows 客户端访问 Linux 服务端不受限制。

## ADDED Requirements

### Requirement: Enterprise authorization has disabled and shadow modes only

系统 MUST 提供 `[enterprise.authz]` 配置 `ENABLED=false`、`ENFORCE=false`、`FAIL_CLOSED_ON_ERROR=true`。本阶段 MUST 拒绝任何 `ENFORCE=true` 配置；`FAIL_CLOSED_ON_ERROR` MUST 保留为后续 enforce 配置而不在 shadow 中拒绝原生操作。企业授权启用时 MUST 要求数据库审计可用，不能静默启用没有审计的 shadow。

#### Scenario: Disabled mode does not evaluate or persist decisions

- **WHEN** `ENABLED=false` 且 `ENFORCE=false`，用户执行原有 repo 操作
- **THEN** 系统不查询企业角色、不运行 shadow evaluator、不写企业决策，原生认证、权限、响应和副作用保持不变；仅删除 user/team/org/repo 时允许同事务清理 live 策略引用，不删除留存决策

#### Scenario: Enforce is not available in this release

- **WHEN** 配置 `ENFORCE=true`，无论 `ENABLED` 值为何
- **THEN** 系统拒绝配置加载并报告安全配置原因，不静默进入 enforce 或 shadow

#### Scenario: Shadow requires audit recording

- **WHEN** `ENABLED=true`、`ENFORCE=false`，但数据库审计未启用
- **THEN** 启动预检拒绝该配置并说明需启用数据库审计，不改动已有权限或凭据

### Requirement: Repository actions use a validated stable vocabulary

系统 MUST 注册 `repo.view_metadata`、`repo.read_code`、`repo.clone`、`repo.create_branch`、`repo.push_branch`、`repo.push_protected_branch`、`repo.create_pull_request`、`repo.review_pull_request`、`repo.merge_pull_request`、`repo.manage_branch_protection`、`repo.manage_codeowners`、`repo.manage_webhook`、`repo.manage_ci`、`repo.manage_secret`、`repo.manage_feature_grant`、`repo.migrate`、`repo.transfer`、`repo.archive`、`repo.delete`。每个 action MUST 有稳定 key、说明、相关 unit、风险和适用上下文。管理角色写入 MUST 拒绝未知 action 或非 `allow` effect。

#### Scenario: Unknown action is rejected without partial writes

- **WHEN** 创建或更新角色的权限集包含拼写错误、未知 action 或 `deny` effect
- **THEN** 系统返回 422，不保存部分角色或权限，不将未知 action 当作 allow

#### Scenario: Action catalog does not imply a feature implementation

- **WHEN** 查询 `repo.manage_feature_grant` 的目录或进行 action 诊断
- **THEN** 系统可以表达 action 授权，但不因此创建 feature grant、开启功能或修改 repo unit

### Requirement: Built-in and custom roles are explicitly scoped

系统 MUST 提供不可直接修改或删除的 Guest、Reporter、Developer、Reviewer、Maintainer、Security Maintainer、Owner、Platform Admin 内置角色，并允许有权管理员在 system/org/repo 作用域创建、读取、更新、删除自定义角色。自定义角色 MUST 使用显式 allow 权限集；从内置或可见自定义角色复制 MUST 保存独立权限快照，而非隐式继承后续更新。Platform Admin MUST 仅可由系统级管理员绑定，MUST NOT 修改 Gitea `IsAdmin` 或企业微信 authority。

#### Scenario: Scoped administrator creates a custom role

- **WHEN** 有权管理员在其管理范围内复制 Reporter 并添加 `repo.review_pull_request`
- **THEN** 系统原子保存自定义角色和完整权限集，记录版本及管理审计，原角色和原生 Gitea 权限不变

#### Scenario: Built-in role and privileged binding are protected

- **WHEN** 管理员尝试编辑内置 Owner，或组织/仓库管理员尝试绑定 Platform Admin
- **THEN** 系统分别返回 409 或 403，不修改角色、绑定或本地管理员状态

#### Scenario: Deleting a referenced role is explicit

- **WHEN** 删除仍被绑定引用的自定义角色
- **THEN** 系统返回 409，要求先显式解除绑定，不静默级联撤销策略

### Requirement: Subject bindings respect membership and resource boundaries

系统 MUST 支持 `user`、`team`、`org` 主体与 system/org/repo 生效作用域；repo MUST 是资源作用域而不是登录主体。org 主体 MUST 解析为当前本地组织成员，team 主体 MUST 解析为当前本地团队成员并校验团队组织及仓库关系。绑定 MUST 校验对象存在、主体类型、作用域合法性和角色可见性；system 角色可在下级绑定，org 角色只可在本组织及其仓库绑定，repo 角色只可在本仓库绑定。相同绑定重复写入 MUST 幂等。

#### Scenario: User team and organization bindings compose

- **WHEN** 用户有直接 user 绑定，且属于目标仓库关联团队及其所属组织，另有适用的 team/org 绑定
- **THEN** evaluator 合并三类匹配角色并返回来源，不改动 collaborator、access、team_user 或 org_user

#### Scenario: Cross-organization or repository-principal binding is rejected

- **WHEN** 请求在组织 A 的仓库绑定组织 B 的角色或 team，或使用 `subject_type=repo`
- **THEN** 系统返回 422 且无策略变更，不用 repo ID 代替 actor ID

#### Scenario: Membership removal and ownership transfer do not leak inherited roles

- **WHEN** 用户已移出组织/团队，或仓库已转移到另一个 owner
- **THEN** 后续评估不再命中失效成员或旧 owner 绑定；旧 owner 下的 repo 绑定暂停生效直到新 owner 显式重新绑定，历史决策保持可解释

### Requirement: Native repository permissions map to default actions without replacing them

系统 MUST 基于调用者当前凭据约束下的原生 repo 与 unit 权限映射默认 action，MUST 区分 Read/Write/Admin/Owner，MUST NOT 只依赖最高 AccessMode 忽略 code/PR unit。Read + code read 映射读代码和 clone；Write + code write 映射普通分支动作；PR 创建需要 code read 和 PR write，review 需要 PR write，merge 需要 code write 和 PR read；Admin 映射保护规则、CODEOWNERS、webhook 和 CI 管理；Owner 映射全部 repo action，但仍受资源/unit 前提约束。较低原生权限 MUST NOT 自动获得保护分支直推及 Owner 管理动作。

#### Scenario: Code-hidden team does not gain clone from repository mode

- **WHEN** 用户的仓库最高权限为 Write，但 code unit 不可读，PR unit 可写
- **THEN** 原生 action 集不包含 `repo.read_code`、`repo.clone` 或代码写动作，决策说明 unit 不满足

#### Scenario: Native administrator is not conflated with owner

- **WHEN** 用户只有原生 Admin 且没有匹配的企业角色
- **THEN** 映射可包含管理分支保护和 webhook，但不自动包含 secret、feature grant、transfer、archive、delete 或保护分支直推

#### Scenario: Credential-scoped permissions are preserved

- **WHEN** actor 使用受限 PAT、Actions task token 或 deploy key 进入既有仓库入口
- **THEN** 评估使用该凭据实际允许的资源/unit/context；不会通过裸 user ID 加载更宽权限或把 synthetic actor 当作普通用户命中企业绑定

### Requirement: Evaluator composes allow-only roles within native safety boundaries

系统 MUST 将本地 Subject、目标 Resource、Action 和受信 Condition 解析为确定性 Decision，合并原生映射和匹配角色的 allow 权限。企业角色 MUST NOT 绕过账号有效性、仓库可见性、对应 repo unit 的基础可见性、凭据 scope 或现有守卫；action allow MUST 明确是候选授权而非 branch protection、required checks、CODEOWNERS 或完整 merge gate 通过。输出 MUST 包含 allow/deny/error、stable reason、matched roles/bindings、missing actions、原生与角色来源及安全前提结果。

#### Scenario: Role adds an action for a native reader

- **WHEN** 活跃用户有原生 code/PR 可见性、匹配 Reviewer 角色，并评估 `repo.review_pull_request`
- **THEN** evaluator 可返回候选 allow，注明角色来源，真实 review 是否允许仍由既有原生 guard 决定

#### Scenario: Role cannot reveal an inaccessible private repository

- **WHEN** 用户绑定 Owner 角色但原生没有目标私有仓库可见性
- **THEN** evaluator 返回 deny 与 `native_visibility_denied`，API 不泄露仓库或策略细节，真实访问仍按原生规则拒绝

#### Scenario: Missing action and storage error are distinct

- **WHEN** 有效主体缺少 action，或 evaluator 在读取权限数据时发生存储错误
- **THEN** 前者返回 deny 与 missing action，后者返回 error 与安全原因码；错误不能伪装成空角色、deny 或成功 allow

### Requirement: Conditions have bounded deterministic semantics

角色权限 MUST 支持可选 `branch_pattern`、`path_pattern`、`request_sources` 条件，多个字段按 AND，同一字段多个候选按 OR；路径条件 MUST 对当前动作全部受影响路径成立。条件 MUST 使用受信入口上下文，MUST 拒绝未知字段、无效模式及超限输入，不执行脚本、任意表达式或外部请求。缺少所需分支/路径上下文 MUST 不匹配并给出 `condition_unresolved`，MUST NOT 等价无条件 allow。

#### Scenario: Branch and source conditions both have to match

- **WHEN** 权限限定 `release/*` 和 API 来源，请求来自 Web 或操作 `main`
- **THEN** 该条权限不贡献 action，解释中记录条件不匹配，不影响其他匹配权限

#### Scenario: Partial or unavailable path information does not broaden a grant

- **WHEN** 条件限定 `docs/**`，操作同时修改 `docs/a.md` 与 `src/a.go`，或入口没有完整路径集
- **THEN** 前者不匹配，后者为 condition unresolved；不得因为一个路径命中或空列表而授予该 action

### Requirement: Real operation paths produce observation-only shadow decisions

shadow MUST 接入实际 repo metadata/code 读取、Git HTTP/SSH clone/fetch、普通/保护分支写入（含 Web/API file editor 与 receive hook）、PR 创建/review/merge（含 auto/force）、保护规则/CODEOWNERS、webhook/CI/secret 管理、迁移、转移、归档、删除入口。尚无产品操作的 feature grant action MUST 明确标记为仅诊断，不虚构生产成功记录。观测 MUST 不改变原生响应、鉴权、凭据、事务结果、分支保护或副作用，并避免 Web/API/service 重复计数。原生拒绝 MUST 在 actor/resource 已安全解析时记录；认证失败或不可见资源 MUST NOT 为观测额外读取或泄露对象。

#### Scenario: Candidate denial does not block a native success

- **WHEN** 原生允许仓库 Admin 删除仓库，而 shadow 映射/角色不包含 `repo.delete`
- **THEN** 删除依照原生规则执行，决策记录 candidate deny、missing action、native outcome 和 mismatch，不返回企业授权 403

#### Scenario: Candidate allowance does not override native protection

- **WHEN** shadow 允许 merge 或 protected push，而原生分支保护或既有企业微信守卫拒绝
- **THEN** 原生拒绝原样保留，决策区分 candidate allow 与 native deny，不绕过保护或执行写入

#### Scenario: Background and protocol paths use the actual actor

- **WHEN** 同一类操作通过 auto merge、Web/API 或 Git HTTP/SSH 触发
- **THEN** 系统记录真实本地 actor 或明确的受限系统凭据、入口来源和目标资源，不为完成观测新增企业微信身份查询

### Requirement: Pre-target repository migration failures have safe non-repository audit evidence

shadow 开启时，系统 MUST 为真实迁移 handler/task 创建路径中、本地 actor 已可信解析（或明确无用户的系统调用）且本地目标仓库 DB 创建尚未提交 的失败保存独立安全审计。用户请求 MUST 使用用户作用域；明确无用户 actor 的系统调用 MAY 使用系统作用域。系统 MUST NOT 创建伪造 repo 决策、候选结果或 mismatch，MUST NOT 以远端仓库 ID 或客户端 actor/source 代替本地身份。字段 MUST 限于受信 operation ID、本地安全 ID、固定入口/阶段/原因/native outcome 及既有审计时间/origin/IP/安全 impersonator ID；MUST NOT 保存 URL、仓库名、凭据、请求正文、原始错误或策略快照。每操作 MUST 至多记录一条，不同操作 MUST 不合并。disabled MUST 不新增此审计；新证据失败、取消、超时 MUST 仅产生有界安全告警及计数，不改变原生结果或业务事务。

#### Scenario: Source policy rejects migration before a target exists

- **WHEN** 已认证 API/Web 用户的迁移被原生来源策略拒绝，目标尚不存在
- **THEN** 原生响应保持不变，安全失败事件记录本地用户 ID、固定来源/校验阶段和 `source_policy_denied`，不含来源地址或 repo 决策

#### Scenario: Target creation or task preparation fails

- **WHEN** 原生 owner/站点检查、请求校验、task 准备/创建或目标创建失败，目标仓库 DB 创建尚未提交
- **THEN** 仅保存一次安全阶段/原因摘要；失败 owner 检查不泄露目标 owner ID；目标创建提交后的失败不计作前置失败

#### Scenario: Target database creation commits before Git initialization fails

- **WHEN** 目标仓库 DB 创建已在最外层事务提交，但后续 Git 初始化或清理失败使创建 helper 返回错误
- **THEN** 受信创建提交标记阻止前置失败审计，不以 helper 的错误返回或缺少返回对象推断目标从未创建；外层回滚不设置该标记，不增加仓库查询或改变原生清理

#### Scenario: Pre-target audit storage fails without changing native behavior

- **WHEN** 新增失败审计的数据库不可用、事务冲突、超时或取消
- **THEN** 原生迁移失败响应和副作用不变，不写半套或虚假成功证据，安全缺口日志/计数不包含原始故障或来源 URL

### Requirement: Shadow evidence is queryable auditable and bounded

每次已安全解析且可评估的观测 MUST 保存决策记录与对应审计关联，包括本地 actor/repo ID、action、来源、request/operation ID、candidate decision、reason、missing actions、native outcome、策略版本/权限快照和时间。重试去重 MUST 仅针对同一 observation ID，不能合并不同操作。策略变更审计 MUST 与变更原子提交；shadow 证据 MUST 与业务事务隔离。决策查询 MUST 支持受权范围内分页及 actor/repo/action/decision/time 过滤，并与审计保留期限一致地清理。

#### Scenario: Decision remains explainable after policy changes

- **WHEN** 产生决策后角色、成员关系、绑定或仓库发生变化
- **THEN** 有权查询者仍可通过当时的安全快照解释决策，不用当前角色内容覆盖历史含义

#### Scenario: Operation rollback does not erase its shadow evidence

- **WHEN** 原生 repo 写事务回滚
- **THEN** shadow 记录在独立事务保存 native failure，不错误标记 native success，也不阻止业务回滚

#### Scenario: Evidence persistence fails at runtime

- **WHEN** shadow 存储或审计写入失败、超时、取消
- **THEN** 原生请求结果不变，系统输出有界安全告警及可检测的观测缺口，不保存只有部分关联的成功证据或伪造审计

#### Scenario: Retention cleans both kinds of evidence

- **WHEN** 审计留存周期清理运行，或配置为永久保留
- **THEN** 决策与对应审计按同一时间规则清理，永久保留时不删除；有权分页查询不返回未授权范围记录

### Requirement: Administrative APIs use existing authority rather than shadow grants

企业授权 API MUST 复用 Gitea token 认证和原生 scope：系统管理需 admin scope 与当前系统管理 guard，org/repo 管理需对应 organization/repository scope 与原生管理权限，按原生 HTTP 方法规则区分 read/write scope。企业微信治理启用时 MUST 继续遵守 active bound super-admin、组织 owner 和仓库 creator/owner/super-admin 的既有守卫；shadow 角色 MUST NOT 作为管理授权依据。诊断自己的权限需原生仓库可见性，查询他人或完整决策需相应管理权限。未启用 authz 时所有新增 API MUST 在认证/权限检查后返回 404，MUST NOT 修改策略。

#### Scenario: Missing authentication or authority is rejected

- **WHEN** 无 token、缺所需 scope、普通用户或非企微超管的普通 site admin 调用相应管理 API
- **THEN** 按原生 guard 返回 401/403，且无角色、绑定或 audit 查询越权，不用 shadow allow 放行

#### Scenario: Authorized administrator and self-query work

- **WHEN** 合法系统/组织/仓库管理员管理其范围策略，或原生 repo reader 查询自己
- **THEN** 管理员可完成获授权的 CRUD/查询；reader 只得到自己的有效 action 和脱敏解释，不能查询他人绑定或历史决策

#### Scenario: Identifier and filter tampering do not cross scopes

- **WHEN** 有权管理仓库 A 的用户提交仓库 B 的 role/binding/decision ID 或扩大查询 filter
- **THEN** 系统对不在已授权范围的对象返回 404，不读取或修改仓库 B 的策略，不依赖客户端 scope 字段限界

### Requirement: Concurrent policy mutations are atomic and auditable

角色及其权限集 MUST 原子更新，绑定增删 MUST 原子写入相应管理审计。角色更新和删除 MUST 使用版本前提以避免丢失更新；评估 MUST 使用同一一致策略快照，不混合更新前后权限。API MUST 对无效输入、版本冲突、对象不存在及安全存储故障提供明确 422/409/404/500，MUST NOT 回传原始错误或部分成功。

#### Scenario: Concurrent role updates do not silently overwrite

- **WHEN** 两个客户端用相同旧版本更新一个自定义角色
- **THEN** 至多一个提交，另一个返回 409；评估只能看到完整旧版或新版权限，审计与实际提交一致

#### Scenario: Management audit failure rolls back the policy mutation

- **WHEN** 角色或绑定写入成功但管理审计持久化失败
- **THEN** 管理事务回滚并返回安全 500，后续 evaluator 仍看到旧策略，不能以 shadow 不阻断为由吞掉管理错误

### Requirement: Evidence and diagnostics never contain credentials or private payloads

决策、审计、API、日志 MUST 仅使用白名单字段和安全原因码，MUST NOT 保存 secret、token、SSH 私钥、OAuth code、企业微信私密字段、HTTP body、原始错误或代码/文件 diff。路径条件证据 MUST 使用命中结果、计数或安全摘要，不保存原始私密路径集。自查解释 MUST 裁剪不属于当前用户的角色、绑定及策略管理信息。

#### Scenario: Sensitive fault input is sanitized everywhere

- **WHEN** 故障输入含 token、secret、OAuth code、callback URL、电话、邮箱或私密文件路径
- **THEN** 全部记录与响应只出现白名单 ID、reason 和安全摘要，不含上述明文或原始错误

### Requirement: Explicit migration preserves native authorization and supports rollback

系统 MUST 通过版本化 migration 创建企业角色、权限、绑定及决策存储并 seed 内置角色，MUST NOT 通过启动时隐式修复替代 migration。升级 MUST 不改动 native access、collaborator、org/team membership、用户管理员标志、SSH key 或 token；默认不创建企业绑定。关闭 authz MUST 恢复本变更前请求路径并保留策略与历史证据，二进制/DB 回退 MUST 有备份与版本匹配要求。

#### Scenario: Existing installation upgrades without regranting permissions

- **WHEN** 对含既有仓库、团队、凭据与企微状态的数据库执行 migration
- **THEN** 只增加 schema/内置角色，不回填猜测的角色绑定、不丢失原生权限，迁移中断重试不重复 seed

#### Scenario: Operator disables shadow

- **WHEN** 运维关闭 `ENABLED` 并完成实例配置重载/重启
- **THEN** 新请求不运行企业 evaluator，既有原生权限仍有效，企业策略和审计证据保留可供恢复

### Requirement: Web and protocol authentication compatibility is unchanged

企业微信 MUST 只负责既有 Web 登录和外部身份，本地 Gitea user MUST 继续作为 repo 权限、团队、审计与凭据归属主体。系统 MUST NOT 新增本地密码、注册、OpenID、Passkey、其他 OAuth、反代或 SSPI Web 登录旁路。SSH key、PAT/API token、Git HTTP token 的创建、认证、scope、吊销、账号状态和原生 action 结果 MUST 保持既有行为，MUST NOT 为 shadow 新增企业微信 OAuth 校验或额外撤销凭据。

#### Scenario: Forbidden Web sign-in paths remain forbidden

- **WHEN** 企业微信 LOGIN_ONLY 启用，尝试既有被禁止的 Web 登录路径
- **THEN** 系统按原有规则拒绝，企业角色或 authz 开关不生成 Web session，也不改变合法企微及其 MFA 续接

#### Scenario: Protocol credentials keep native behavior in both modes

- **WHEN** 正常、禁用或受限用户使用 SSH/PAT/Git HTTP token，在 disabled 或 shadow 中访问仓库或触发既有拒绝
- **THEN** 认证、scope、吊销及请求结果与变更前一致，仅 shadow 可增加安全观测，不调用企业微信 OAuth、不修改凭据
