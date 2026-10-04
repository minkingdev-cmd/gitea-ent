## Context

动机与能力范围见 `proposal.md`；行为合同见 `specs/authorization/enterprise-repo-actions/spec.md`。设计依据为 `docs/enterprise-authz/requirements.md`、`implementation-plan.md` 和 `proposal-roadmap.md` Proposal 2，以及实际代码：

- `models/perm/access/repo_permission.go` 的 `GetDoerRepoPermission` 区分普通用户、Actions task user 与 deploy key；`Permission` 的 unit 权限不能被单一 `AccessMode` 取代。
- `services/repository/governance.go` 已提供 creator/真实 owner/企微超管授权变更 guard，不能以 `IsAdmin` 或 shadow 角色替换。
- `models/audit` / `services/audit` 已支持作用域、凭据引用、metadata、保留清理及 `WithRequiredPersistence`；`[audit] RECORD_OUTPUT` 默认 disabled。
- migration 位于根目录 `modelmigration/`，不是 `models/migrations`；2026-09-30 实施时确认已有 `v28/v360.go`，下一编号为 `v28/v361.go`。
- 用户已确认：user/team/org 为主体、repo 为作用域、allow-only 叠加，且不可绕过原生仓库可见性、unit 与守卫。

本 change 属于新增授权子系统的架构级规划，OpenSpec 是唯一设计与任务来源。前置治理 change 的真实 callback 证据仍是独立启用门槛；Windows 服务端回归已按用户确认永久移出验收范围，不再等待 runner。不以本次文档生成代替运行验证。

2026-09-30 实施准入更新：用户确认采用登录管理员权限刷新 + 定时目录/团队/管理员完整同步，callback 保持关闭。真实 callback 协议缺口保留为其独立启用 gate，不阻断本次 shadow 实施；不因此保证登录刷新失败或 cron 失败时仍是最新状态。用户明确服务端永久仅部署 Linux，Windows 服务端支持与原生回归不属于本项目目标；Windows 客户端访问 Linux 服务端不受此限制。前置验证缺口按上述范围取得明确豁免，不虚假勾选前置 change。

## Goals / Non-Goals

**Goals:**

- 让 action 目录、角色、绑定、条件、评估、观测和查询组成完整 API-only 产品路径，避免只有模型或诊断 demo。
- 将候选 action 授权与真实原生结果分开；任何观测错误不参与原生鉴权或业务事务。
- 提供一致、可重放解释的策略快照和受权查询，保留明确的管理权限、迁移与回滚边界。

**Non-Goals:**

- 不提供 enforce 执行路径、explicit deny、任意策略表达式、外部 PDP、角色赋予的真实仓库可见性或 token 扩权。
- 不做角色动态继承、企微角色自动生成、feature grant、merge gate、offboarding、管理 UI 或新的平台级管理 action。
- `repo.manage_ci` 仅表达 CI/required-check 设置管理，不授权执行 CI 或访问其 secret；Security Maintainer 不隐式实现扫描策略服务。

## Decisions

### 1. 禁止半启用 enforce，配置与企业微信解耦

默认值为 `ENABLED=false, ENFORCE=false, FAIL_CLOSED_ON_ERROR=true`。严格解析布尔值，所有 `ENFORCE=true` 均在配置加载阶段拒绝并使用稳定安全原因码；不能“先接入一个 enforce 分支以后再完善”。`FAIL_CLOSED_ON_ERROR` 在本版本不改变 shadow 或管理 CRUD 的错误处理。

authz 不要求企业微信启用：在非企微部署仍可观察原生 Gitea；企微开启时继续使用既有更严格管理 guard。authz enabled 要求 `[audit] RECORD_OUTPUT=database`，并校验 schema/内置角色完整。不能自动打开审计、临时 seed 或查询 provider 修复配置。

替代方案：忽略 `ENFORCE` 或启用不完整 enforce 会掩盖操作意图；shadow 没有审计却启动不满足验收，因此采用显式拒绝。运行时 DB 故障与启动配置错误区分，前者不能阻断原生请求。

### 2. 单向依赖与三层接口

```text
routers / repo-pull-Git services
  -> enterpriseauthz management / Evaluate / Observe
     -> native authority resolver + credential-aware access models
     -> enterpriseauthz models + audit service
        -> db / setting / action-condition value types
```

- `models/enterpriseauthz` 只负责数据与一致查询；`services/enterpriseauthz` 负责验证、管理、评估和证据提交；routers 只做原生认证/scope/资源赋值及 DTO。
- `Evaluate` 返回 typed candidate Decision 与 error，不写原生状态。`Observe` 是无授权返回值的有界旁观者，业务代码不能读取其 allow/deny 来决定执行。管理 CRUD 与显式诊断 API 则返回真实存储错误。
- evaluator 不导入 repository/pull service，以免被观察 service 与 evaluator 循环依赖。仓库管理权限沿用 `CheckEnterpriseRepoAuthorizationChange` 的规则；将必要 native-only authority 判定抽取为下层共享 helper，保留既有 guard 包装与审计行为，不复制或削弱规则。
- 原生读权限仍由 `GetDoerRepoPermission` 及路由已有凭据 scope 解析；禁止观察器按裸 user ID 回读 `GetIndividualUserRepoPermission` 扩权。

替代方案：在每个路由复制 evaluator/guard 容易漂移；把企业调用塞进 access model 会反向依赖 service 并污染 disabled 热路径。

### 3. additive 数据与并发版本

| 表 | 关键字段与约束 |
| --- | --- |
| `enterprise_role_definition` | ID、scope_type/system-org-repo、scope_id（system=0）、key/lower_name、description、is_builtin、revision、created_by、时间；scope + lower_name 唯一，内置 key 唯一 |
| `enterprise_role_permission` | role_id、action、effect（只允许 allow）、规范化 condition_json、condition_hash；role/action/condition_hash 唯一，角色删除显式清权限 |
| `enterprise_subject_role_binding` | ID、subject_type/user-team-org、subject_id、scope_type、scope_id、scope_owner_id、role_id、created_by、时间；subject/scope/role/owner 组合唯一 |
| `enterprise_authz_decision` | observation_id 唯一、operation/request_id、actor_id、repo_id、owner_id、action、request_source、candidate_decision、reason、missing_actions、native_outcome、snapshot_json、timestamp；repo/time、actor/time、action/time、decision/time 索引 |

角色复制是一次性的权限复制，不持久化动态 `base_role_id` 继承；更新/删除需 `expected_revision`，缺失或过期为 409，permission 集和 revision 同事务。管理查询返回 revision；请求省略 permissions 时保持原集合，显式空数组清空，空角色合法但不贡献 action。

role/permissions/bindings 的写与管理审计放同一 `db.WithTx`，使用 required-persistence 状态将审计失败提升为回滚。删除有引用角色为 409；PUT 同一绑定重复执行为 204，不产生重复状态或伪重复变更审计。绑定删除后再次 DELETE 按已授权作用域的不存在对象返回 404。

评估在独立一致读事务获取当前角色权限、绑定、本地 org/team membership 和 owner 快照。PostgreSQL 使用适当一致快照，SQLite 使用读事务；不用跨请求角色缓存，避免首版新增失效协议。角色/绑定引用校验与更新采用同事务锁定，防止并发删除产生悬空绑定。

替代方案：改写 access/team 表会把候选策略变成实际授权；按启动时检测补表/seed 难以追踪历史状态，因此采用显式 migration。

### 4. 主体和作用域不是同一维度

- user 指向非组织、非 synthetic 的本地用户；team 指向当前 team_user 成员且 team 属于目标 owner org、关联目标 repo；org 指向当前 org_user 成员。成员身份由 DB 解析，不能从 API body 接受 TeamIDs/OrgIDs。
- system 绑定仅系统管理员可维护；org 绑定只作用于当前 owner 的仓库；repo 绑定只作用于指定 repo。personal repo 允许 user 绑定，不允许无关 org/team。
- system 角色可下放绑定；org 角色不能出组织；repo 角色不能出仓库。Platform Admin 只允许系统管理 API 的 system 绑定，不授予站点管理 guard 或修改 `IsAdmin`。
- repo 绑定保存当时 `scope_owner_id`。owner 改变时旧绑定不再匹配，包括 system 角色在旧 owner 下的 repo 绑定；新 owner 必须显式重建绑定。系统级 user 绑定本来跨 owner，仍需原生可见性；org/team 绑定每次验证当前关系。
- 评估匹配与管理限界分离：当前原生授权管理员可以列出并解除同 repo 的旧 owner 失效绑定，包括新 owner 不再可见的旧 org 角色引用；不能因此读取旧角色内容或恢复其权限。旧绑定显式解除后才允许删除被引用角色。
- 删除用户/团队/组织/仓库时清理其 live 策略引用，沿用既有删除事务/清理路径；不删除仍处于保留期的历史决策，避免 FK 级联抹除证据。历史使用 ID/安全快照，不依赖对象仍存在。

替代方案：把 repo 视作登录主体或把企微 userid 当 actor 会混淆审计及凭据边界；继承旧 owner 的绑定会带来转移后的授权漂移。

### 5. action 目录与默认兼容映射

action 目录是稳定常量与 metadata，不另建 feature 表。目录给出风险和最小可见性前提；原生 action 映射与企业权限叠加分离，角色可以给 native reader 增加候选写 action，但不能建立新的仓库或 unit 可见性。账号不活跃/被禁用、受限账号、归档写限制、凭据 scope 仍受原生边界约束。

| 原生权限/前提 | 默认候选 action |
| --- | --- |
| 任一原生 repo unit 可见 | `repo.view_metadata` |
| Read 且 code 可读 | `repo.read_code`、`repo.clone` |
| Write 且 code 可写 | `repo.create_branch`、`repo.push_branch` |
| code 可读且 PR 可写 | `repo.create_pull_request` |
| PR 可写 | `repo.review_pull_request` |
| code 可写且 PR 可读 | `repo.merge_pull_request` |
| Admin | `repo.manage_branch_protection`、`repo.manage_codeowners`（需 code 可见）、`repo.manage_webhook`、`repo.manage_ci`（相关 unit 开启且可见） |
| Owner | 全部 repo action，仍要求对应 repo/unit/凭据上下文可达 |

保护分支直推、secret、feature-grant 管理、迁移、transfer/archive/delete 默认仅 Owner；较低权限可由显式角色增加。Gitea site admin 经凭据感知原生 resolver 可得到 Owner 映射，但**管理 API**仍受企微更严格 authority guard。shadow native mismatch 可反映现有 fork 的 Admin danger-zone 行为，不为消除 mismatch 修改原生逻辑。

内置权限集为：

| 内置角色 key | 显式 allow 集 |
| --- | --- |
| `guest` | view_metadata |
| `reporter` | guest + read_code、clone |
| `developer` | reporter + create_branch、push_branch、create_pull_request |
| `reviewer` | reporter + review_pull_request |
| `maintainer` | developer + reviewer + merge_pull_request、manage_webhook、manage_ci |
| `security-maintainer` | reporter + review_pull_request、manage_codeowners、manage_ci |
| `owner` | 所有目录中的 repo action |
| `platform-admin` | 同 owner 的 repo action，仅允许系统级绑定；不产生额外平台管理权限 |

以上简写均带 `repo.` 前缀。内置角色不自动绑定、不反向创建 team/collaborator，不把 future feature/security action 塞入当前权限集。新增 action 后由后续显式 migration/变更更新内置角色，不能用通配符悄悄扩权。

### 6. 受限条件与可解释决策

权限条件使用严格 DTO：`branch_pattern`、`path_pattern` 为候选 glob 数组，`request_sources` 为 `web/api/git_http/ssh/file_editor/receive_hook/auto_merge/system/diagnostic` 子集。使用仓库 `modules/glob` 的语法及 `/` 路径分隔；路径为 Git repo 相对路径，不解析文件系统路径。

设定边界：每条权限每类最多 16 项、单个 pattern 最多 256 字节、条件 JSON 最多 8 KiB；每角色最多 128 条权限；管理 body 最多 1 MiB。路径上下文最多 1024 项，超过或无法得到完整集合时标记 unresolved，不能截断后当完整输入。未知字段、空候选数组、非法 glob、非法来源为 422。

有条件字段间 AND，同字段 OR；path 条件要求所有路径匹配至少一个模式，且已知完整、非空。branch 字段缺失或 branch/path 数据未知时该权限不贡献 action；其他无条件权限仍可匹配。对 branch/path 的解析不执行外部请求、不运行 Git diff 来“补齐”读请求，已有入口没提供数据则诚实记录 unresolved。

`Decision` 包含 candidate `allow/deny/error`、稳定 reason、排序去重的 matched role/binding IDs、missing action、native/role source、安全前提、revision/snapshot。优先判定 unknown_action、subject/context 无效及 native visibility，再合并 action；无授权为 `missing_action`，匹配条件不足为 `condition_not_matched/condition_unresolved`，数据故障为 `policy_read_failed`，不得用空结果替代错误。匿名只使用原生公开读取映射，不匹配企业绑定；synthetic Actions/deploy-key actor 只使用其凭据原生映射。

不计算 required checks、CODEOWNERS approval 或完整 branch gate。返回 `candidate_only=true`、`safety_guards_evaluated=false`；native outcome 由实际路径提供，不通过候选 allow 推导。

替代方案：通用 JSON 表达式、未知条件忽略或 any-path 命中容易引入放权；缺上下文不匹配虽产生保守 mismatch，但可解释且不会改变请求结果。

### 7. 真实入口观测清单与去重

Observe 在 actor/resource 已安全解析后运行；disabled 观察器先判断并零企业 DB 访问；2026-09-30 用户明确允许对象删除时同事务清理 live 策略引用作为原生请求内的唯一例外，不评估、不写决策。独立 audit 留存任务不属于原生请求观察器，按既定留存期限共同清理历史 decision 与 audit，关闭 shadow 不会暂停历史留存；保留期限 0 不删除。在原生业务事务/资源变更前捕获候选与不可变安全快照，在业务事务结束后填充 native outcome 并持久化，删除/转移不能用变更后的资源反推旧状态。观察评估与证据提交的预算不包含业务执行时间；不能在持有业务锁时另开证据写事务。每次 operation 生成受信 operation ID，每个 action/resource 子操作生成 observation ID，router/service 共用上下文，避免重复。以下各入口族都属于本阶段交付，不只提供 Evaluate API：

| action / 操作族 | 观察边界与覆盖 |
| --- | --- |
| metadata / read_code | Web repo/code 与 API repo/contents 读取的安全赋值后边界，不能把所有 repo 路由笼统当成 read_code |
| clone | Git HTTP upload-pack/SSH upload-pack，保留原生 key/token 分派；不记录 pack 内容 |
| create_branch / push_branch / push_protected_branch | Web/API 分支与 file editor、Git HTTP/SSH receive/pre-receive；按目标 ref 的既有保护分类，不更改原保护判断；tag 操作不伪装成分支 action |
| create/review PR | Web/API 相应业务入口，分别使用 target repo 与实际 actor，不把只读 PR 查询当 review |
| merge PR | Web/API/auto/force 的共享 pull service 与必要原生拒绝分支；保留 `services/pull/merge.go` 的原生逻辑与强制路径 |
| branch protection / CODEOWNERS | Web/API 规则管理；file editor 和 receive 仅在已有完整路径识别命中 CODEOWNERS 时附加子 observation，否则条件 unresolved，不新增强制路径检查 |
| webhook / CI / secret | Web/API 设置 service 边界，包括 required-check/Actions 设置；不读取/记录 secret 值或 webhook URL/token |
| migrate | 既有 migration service 已创建本地 target repo 时观测，原 owner/创建审批仍独立生效；分配 ID 前失败不伪造 repo 决策，新增用户/系统作用域的安全失败审计 |
| transfer / archive / delete | repository 共享服务与对应 Web/API 既有拒绝边界；转移候选按原 owner 评估并记录目标 owner 安全 ID，删除保留前置 snapshot |
| manage_feature_grant | 仅目录与诊断；后续 feature grant proposal 提供真实操作，本阶段没有虚构 hook |

原生 guard 已拒绝但 actor/repo 对其可见时，记录 native deny；认证失败、目标不可见、尚未分配 repo ID 的失败不为了观测多查私有对象。`native_outcome` 为 success/denied/failed/unknown：长连接 clone/push 只能确认 guard 的边界时记录 unknown + `native_stage`，不将鉴权成功冒充传输完成。Git hook 子进程通过内部受信上下文传播 credential/reference 与 ID，不能从客户端 query/body 信任 actor/scope。

2026-10-01 用户批准补齐迁移前置失败审计，修正“既有迁移审计已覆盖”的错误假设。仅在 authz shadow 开启且本地 actor 已可信解析（或明确的无用户系统调用）的实际 API/Web handler 与 task 创建路径记录 `enterprise:authz:migration:failure`；disabled 不新增记录。用户请求归属本地用户作用域，只有明确的系统调用且无用户 actor 时才使用 system；不新增角色绑定作用域。目标 owner 只有通过原生检查后才进入安全 ID 摘要。覆盖 owner 检查、站点开关、请求/来源校验、task 准备/创建及目标创建失败；目标仓库 DB 创建在最外层事务提交后即跨过前置失败边界：即使后续 Git 初始化失败、创建 helper 返回错误或清理失败留下仓库，也不能伪装成未创建目标。创建服务仅对受信 migration context 注册 after-commit 标记，不为审计额外查询仓库；外层回滚不标记成功。已有目标后的正常 repo 观测仍按任务 8.8 接入。

新增事件只保存受信 operation ID、本地 actor/已确认 owner ID、固定入口、阶段、原因码、native outcome 和既有审计时间/origin/IP/安全 impersonator ID；不保存来源 URL、仓库名、凭据、HTTP body、原始错误或 candidate/mismatch/snapshot，不创建 DecisionRecord。每个操作最多一条前置失败事件，不合并不同操作；独立事务和 200ms 预算，失败/取消/超时仅输出有界安全告警与缺口计数，不改变原生返回或事务。认证/绑定中间件在可信 handler 之前拒绝的请求不凭空构造 actor 或补查私有对象。无 schema/登录/协议凭据/原生权限调整，复用现有 audit 查询、导出和留存。

对多个 action 或 ref 的批量写入分别观察；候选 deny 不影响任一原生 ref 结果。action native mismatch 只在原生结果确定时计算，error/unknown 不计作普通 deny mismatch。

替代方案：仅上线 diagnostic API 不能验证真实入口；全局 middleware 按 URL 猜 action 会错算读取/写入与 batch/ref，故采用小型 typed adapter。

2026-10-01 PR Web/API 实施补充：创建在 base/target repo 观察；review 状态/Code/Review/DismissReview 文本 mutation 复用 handler/shallow adapter，不进入原生权限分支。终态覆盖最终渲染/转换；Web 200 self-review redirect 及 API 422 self-review/closed PR 显式为 denied，失败不承诺回滚已有原生部分副作用。纯读取、discussion、review requests、viewed-files、reaction/附件管理不伪造评审提交。Issue 类 token 的文本 API 使用仅 review 的内部 action ceiling，不能据此解释为 code/secret 原生 grants。 API bind 原生 422 后，仅固定 marker 路由追加 failed/operation，不重读 body；共用目标验证遵守 SQL repo/PR 限界与同一预算。head 凭据/code 及他人 pending review 的明确权限拒绝通过私有 typed outcome 标记消费为 denied，保持 API 隐私 404 及既有 Web POST 500 错误映射；不能整体将 404 判成 denied，共用 GET helper 不因此产生 mutation。

实际前置拒绝由固定路由元数据和原 guard 包装观察，不改变路由检查顺序、不以 URL 推断 action；仅在原生可见 actor/repo/PR unit 和凭据上限已满足时解析目标。guard 目标使用 SQL 内 current repo/IsPull/type/index 约束的 ID-only Exists，不先加载跨 scope 正文。未解析表单只在 read deadline 可用时做最多 64 KiB 的有界读取；目标提取、DB 查询、评估与证据共享 200ms。无法安全解析只增加缺口，不覆盖原生响应或构造评审决策；disabled 在元数据/解析/DB 前退出。阶段使用 authorization/denied；handler 的最终原生结果仍为 operation。

### 8. 管理 API 和权限矩阵

所有入口 API-only，前端菜单/按钮 key 不适用，不新增 UI。服务层重新验证管理 authority，不能只依靠路由或请求给出的“管理员”字段。全局、组织、仓库端点分别为：

- base：`/api/v1/enterprise/authz`、`/api/v1/orgs/{org}/enterprise/authz`、`/api/v1/repos/{owner}/{repo}/enterprise/authz`。
- 各 base：`GET /roles`、`POST /roles`、`GET/PATCH/DELETE /roles/{id}`、`GET /bindings`、`PUT /bindings`、`DELETE /bindings/{id}`、`GET /decisions`、`GET /decisions/{id}`。scope 从 URL/资源决定，body 不接受另一个 scope。
- 系统 base：`GET /actions` 返回注册目录；不允许修改目录。
- repo base：`GET /effective-permissions` 查询默认 action 集与有条件权限摘要；`POST /evaluate` 使用 action、branch、paths 进行诊断，仅返回候选且 `request_source=diagnostic`，不能伪装成真实入口。可选 `user_id` 仅管理员可用；未知 action/格式错误为 422。

| 入口/API | 原生认证/scope 与后端 guard | 默认可达主体 | 企业角色是否可放行 | 前端入口 |
| --- | --- | --- | --- | --- |
| system roles/bindings/decisions/actions | `reqToken` + Admin read/write scope + `reqSiteAdmin` 及同等 service guard；企微开启要求 active bound management authority | 企微关闭时 native site admin；开启时可信企微超管 | 否，Platform Admin 也不能自行成为 site admin | API-only |
| org roles/bindings/decisions | token + Organization read/write scope + 组织真实 owner；可信系统管理员可代管，企微开启时 site-admin 身份本身不够 | 原生 org owner、可信系统管理员 | 否 | API-only |
| repo roles/bindings/decisions；查询/诊断他人 | token + Repository read/write scope + 原生 repo 可见性 + 既有 creator/真实 owner/超管授权变更 guard；非企微时至少真实 repo Admin 或 site admin | 当前治理认可的 creator、owner、超管；非企微遵循原生 admin | 否 | API-only |
| repo effective-permissions/evaluate 自查 | token + Repository read scope（POST evaluate 仍按原生方法规则要求 write scope）+ 当前 repo 基础可见性 | 原生 reader 及以上 | 不赋予仓库可见性 | API-only |

角色列表可同时显示可见的内置与祖先定义，binding/decision 列表只返回当前授权生效 scope；系统列表仅系统管理员可查询全域并按 filter 缩小。自查不返回其他主体及完整管理快照；只呈现当前用户来源摘要、unit 前提、缺失 action/条件状态。

接口顺序：原生认证/scope/authority → authz enabled → 安全对象 lookup/body validation → service。无 token 401、缺权限 403、disabled/不存在/跨 scope ID 404；422 无效 action/condition/subject，409 revision/内置角色/引用冲突，500 安全存储错误。CRUD 使用 201 create、200 GET/PATCH、204 PUT/DELETE；列表遵循 `page/limit`、最大 limit 100 与 `X-Total-Count`。所有成功/错误、DTO、scope 及 disabled 契约写入 Swagger。决策历史可能包含已删除或曾为私有仓库的策略摘要，因此 list/detail 明确拒绝 public-only token（403），不按组织公开可见性放宽仓库证据限界；该凭据限制同样先于 enabled gate。

替代方案：用 shadow role 管理自身绑定会形成权限自举与越权；新增 UI 超出路线图边界。

### 9. 证据提交、脱敏和可观测性

决策记录是结构化查询/快照，不替代现有审计；审计 metadata 引用 observation/decision ID，保留 actor、凭据安全引用、origin、IP 与原生 scope。写 decision + audit 在**独立**有界事务原子完成，`WithRequiredPersistence` 检查 audit insert。不能使用业务事务 context 写 shadow 证据，也不能让证据事务失败回滚业务。

每次评估/证据提交总预算默认 200ms；使用观察专属 context，保留受信 actor/origin/request ID 但移除业务事务。超时/取消/内部观察故障只给安全日志与计数 `enterprise_authz_observation_failed`，记录 operation ID、reason、action 及已安全解析的 repo ID，不传播错误到原生 caller。诊断/管理请求的证据写失败则返回安全 500，不声明已审计。

snapshot 上限 64 KiB，不超限截断后冒充完整：超限返回 error/`snapshot_limit_exceeded`，用最小错误证据与告警保留缺口。快照含 action catalog version、native unit/credential ceiling、参与评估的 role revision/权限 action-effect-条件指纹与绑定 ID、成员匹配摘要、owner ID、每条权限匹配/不匹配结果及是否命中 action，既能解释 allow，也能解释 missing action 与 condition unresolved；condition fingerprint 代替原始 path/branch pattern，角色后续编辑不改变当时的匹配结论。不含 secret、代码/路径原文、provider payload、原始 `error.Error()` 或完整 URL。request ID 由服务生成或受信内部传播，不直接信任客户端自由字符串。

新增授权 action family 的 message/render/export 都使用白名单 metadata。管理变更 before/after 为 key/ID/revision/action key 安全摘要；role description 等用户自由文本不进入日志/审计模板。复用审计 cleanup 调度，为 decision 按 `[audit] RETENTION_DAYS` 同步清理，0 表示永久保留；分批删除以避免长期锁。

不依赖无界 goroutine/内存 queue。同步短预算可能增加少量延时，但避免进程退出丢失整个队列；200ms 超时带来的缺口必须计数、告警并阻止后续 enforce readiness，而不是把 shadow 当作可靠授权事务。

## Risks / Trade-offs

- [原生 Admin 的实际操作与保守 Owner-only 映射不一致] → 保留 mismatch，明确 candidate_only；不为“对齐日志”改写原生行为。后续 enforce 必须单独评审兼容差异。
- [allow-only 不能收回既有原生权限] → 本阶段明确接受，不能宣称 Reviewer 绑定会让 native writer 失去 push；显式 deny 是未来独立语义变更。
- [大量读/clone/ref 观测增加 DB 压力] → disabled 原生观察器零企业 DB 访问、每操作去重、查询索引、大小/时间上限、沿用留存清理；启用前以真实负载验证 200ms budget 和存储容量。
- [证据不可用但业务继续] → 启动必须启用 audit，运行时缺口告警并暂停 shadow/排障；不能据缺失数据宣布 enforce 就绪。
- [新管理服务与旧 guard 漂移或循环依赖] → 共享 native-only helper、既有 guard 包装保留，增加普通 site admin/creator/owner/超管的正负回归。
- [repo transfer/delete 后证据泄露] → 查询只按当前 authority；无 repo 时仅系统管理员可查留存证据，old-owner 绑定失效，snapshot 不含私密正文。
- [真实 callback 协议尚未验证] → 用户已批准 callback 关闭，采用登录刷新与定时同步；callback 启用仍需独立真实协议验收。Windows 服务端不在永久 Linux-only 范围内，不构成验收依赖。

## Migration Plan

1. 实施前重新核对前置 change、部署平台、当前 migration 编号及预存用户改动；用户已批准 proposal 实施与前述范围豁免。仅支持 Linux 服务端；主验收 PostgreSQL，SQLite 用于快速隔离测试，不扩展为 Windows/MySQL/MSSQL 适配项目。
2. 在根目录 `modelmigration/migrations.go` 注册新的 additive migration，使用实施时下一可用编号（当前 `v28/v361.go`）：创建四表、索引与内置角色/显式权限 seed；按仓库机制支持中断重试且不覆盖已有数据。不猜测回填 user/team/org 绑定。
3. 在备份副本验证旧数据库升级、重复/中断恢复、seed 完整、一致性、原生 access/membership/authority/凭据不变。迁移不访问企业微信、不引入 Flyway/OpenFGA/Keycloak；本仓库文档明确由 `modelmigration` 管理。
4. 所有实例使用同版二进制，先保持 authz disabled，备份 DB/配置并核验 audit、CRUD authority 和原生登录/Git 回归。显式开启数据库 audit，再启用 `ENABLED=true, ENFORCE=false`；callback 开关保持其独立 gate，不随 authz 自动开启。
5. 创建测试作用域自定义角色及 user/team/org 绑定，跑真实入口矩阵，查询候选 allow/deny/error、missing actions、native outcome 与快照；演练策略并发更新、transfer/member-removal、证据失败和清理。只有全部覆盖/缺口解决后才交付 shadow，不开展 enforce。
6. 运维回滚优先关闭 authz 并协调全部实例重启，保留新表/seed/历史，不修改原生授权或凭据。旧二进制可能因较新 schema version 拒绝启动，禁止手改 version；需要二进制回退时停止全部实例并恢复匹配版本的完整 DB/配置备份，按 runbook 审批且记录丢失窗口。
7. 更新配置示例与 `docs/enterprise-authz/` shadow runbook，写清平台默认角色、API 权限、200ms/容量/留存、预检查、关闭与恢复步骤。记录实际验证证据后运行 OpenSpec strict validation；不把任务勾选作为业务验收。
