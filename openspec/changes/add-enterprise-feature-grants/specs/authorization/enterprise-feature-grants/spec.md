## Purpose

为企业 Git 托管提供按全局、组织和仓库解析的功能授权，区分可用、禁用、强制与继承状态，并以受权 API、真实入口检查和审计约束策略变更。该能力保留原生权限和凭据边界，为后续治理模板与合并门禁提供策略输入，而不冒充外部扫描执行或门禁结果。

## ADDED Requirements

### Requirement: Stable feature catalog and supported boundaries

系统 MUST 登记 `feature.issues`、`feature.pull_requests`、`feature.packages`、`feature.wiki`、`feature.webhooks`、`feature.woodpecker_ci`、`feature.sonarqube_quality_gate`、`feature.semgrep_scan`、`feature.gitleaks_scan`、`feature.trivy_scan`、`feature.ai_review`、`feature.ci_secret_management`、`feature.required_status_checks`。目录 MUST 包含稳定 key、说明、支持作用域、默认状态、配置 schema 版本和 `native_gate` / `policy_only` 能力标记。全部 key 本轮只支持 global/org/repo，系统 MUST 拒绝未知 key 和 team/user/branch/role 作用域；MUST NOT 提供任意功能定义 CRUD。原生功能默认 `enabled`，六个外部 CI/扫描/AI 功能默认 `disabled`；默认值只在缺少有效 grant 时兜底，MUST NOT 自身形成不可覆盖的上级锁。

#### Scenario: Complete and honest catalog

- **WHEN** 授权管理员查询功能目录
- **THEN** 返回全部 13 个定义，六个外部集成标记为 policy_only，不宣称扫描、AI 或新合并门禁已经可执行

#### Scenario: Reject unsupported input

- **WHEN** 客户端提交未知 feature、未知状态或 team/user/branch/role scope
- **THEN** 返回 422，授权和审计成功记录不发生变更

### Requirement: Deterministic hierarchy and upper-scope locks

系统 MUST 按 global → 当前 owner 为组织时的 org → repo 解析；个人仓库 MUST 跳过 org。`inherited` 或无记录 MUST 不贡献状态或配置；否则下级可以覆盖上级 `enabled`，但 MUST NOT 覆盖上级显式 `disabled` 或削弱上级 `required`。写入下级 `enabled`/`required` 与上级 disabled 冲突、或下级 disabled 与上级 required 冲突时 MUST 返回 409 `feature_parent_locked`。上级变更允许使既有下级配置失效，但 MUST NOT 改写下级记录；读取 MUST 给出有效状态、锁定来源与冲突，且既有 required/disabled 冲突 MUST 以从根向下遇到的首个锁定状态为准，不按时间或最后一条记录随机选择。

#### Scenario: Normal override and personal repository

- **WHEN** global 为 enabled、组织为 disabled，且个人仓库有 enabled grant
- **THEN** 组织仓库不可开启，个人仓库只使用 global/repo 链，不继承不相关组织的禁用

#### Scenario: Required cannot be weakened

- **WHEN** org 为 required，仓库尝试设置 disabled 或继承后关闭原生功能
- **THEN** grant 更新返回 409 或原生设置操作返回 403，均不提交相应副作用

#### Scenario: Existing contradictory descendant

- **WHEN** repo 曾为 required，global 后被设置为 disabled
- **THEN** repo grant 原样保留，有效状态为 disabled，查询明确展示 global 锁及下级冲突；移除 global 锁后重新解析 repo required

### Requirement: Strict feature configuration and mandatory context inheritance

系统 MUST 对配置拒绝未知/重复字段、null、非法 UTF-8、尾随 JSON、超限大小和非法 check context。原生 unit、Webhook 和 CI secret 功能仅接受空配置；外部集成及 required status checks 接受去重后的 `check_contexts` 字符串列表。配置 MUST NOT 接受 secret、token、URL、任意命令或凭据字段。无锁时最近的显式 grant 配置替换上级配置；required 锁下 MUST 保留所有有效 required 层的 contexts，并只允许下级补充，不允许删除或覆盖上级必选 context。`inherited` MUST 使用空配置，MUST NOT 暗中保留本层覆盖配置。

#### Scenario: Required context cannot be removed

- **WHEN** 上级 required 指定 `security/gitleaks`，下级设置 enabled 且配置 `ci/build`
- **THEN** 有效状态仍 required，有效 contexts 至少包含两者，上级 context 不因下级替换而消失

#### Scenario: Invalid or secret-bearing configuration

- **WHEN** 提交重复 JSON 字段、非列表 contexts、空 context、超限列表或 `access_token` 等字段
- **THEN** 返回 422，不存储内容，也不把请求原文或敏感值写入审计/错误

### Requirement: Scoped management authority and no self-authorization

全局授权读写 MUST 要求当前可信系统管理 authority；企微启用时本地 `IsAdmin` 单独不足以通过。组织授权读写 MUST 要求目标 org owner 或可信系统管理 authority。仓库原始 grant 读写 MUST 要求现有仓库授权管理 authority；写入还 MUST 同时满足当前凭据的写入上限和 `repo.manage_feature_grant` action，disabled/shadow/enforce MUST NOT 被用来跳过管理 API 自身的授权。企业角色中的 platform-admin 或 manage_feature_grant MUST NOT 自动委派 global/org authority，功能状态 MUST NOT 授予 repo 可见性、原生 Admin/Owner、token scope 或自身管理许可。

#### Scenario: Genuine administrator and constrained credential

- **WHEN** 可信系统超管使用具有相应 admin/organization/repository scope 的有效凭据管理对应范围
- **THEN** 可执行授权操作；同一 actor 使用只读、public-only 或范围不符的 token 写入则被拒绝

#### Scenario: Explicit repo role remains bounded

- **WHEN** 具备原生仓库授权管理 authority 的 actor 获得 manage_feature_grant 显式角色
- **THEN** 可以管理该仓库 grant，但不能仅凭 feature action 获得其他仓库、global/org、企业角色/绑定 API 或系统超管 UI 的额外权限；原本独立具备的管理 authority 不受影响

#### Scenario: Stale authority and spoofed scope

- **WHEN** actor 已被撤销管理员资格或客户端伪造 scope/owner/repo ID
- **THEN** 写前复核拒绝请求，不按旧会话、客户端字段或旧诊断结果提交 grant

### Requirement: Explainable API and privacy-separated projections

系统 MUST 提供功能目录、global/org/repo 原始授权管理，以及仓库有效状态查询。读写 MUST 复用 API 的认证和 token scope 机制；企业授权关闭时新 API MUST 返回 404 且不读写功能策略。仓库 reader 的有效查询 MUST 受原生可见性及凭据读上限约束，只返回该仓库的 key、有效状态、来源层级、能力标记、可安全公开的 reason 和版本，不返回上级 scope ID、原始链、操作者、配置或其他仓库信息。管理员投影 MUST 能查看本范围原始 grant、有效链、锁、冲突、配置、native availability 与 pending 状态；有效状态查询 MUST NOT 成为执行许可或外部运行结果。

#### Scenario: Reader cannot inspect global policy

- **WHEN** 只读仓库用户查询其有效功能或尝试读取原始 global/org grant
- **THEN** 有效查询成功但不泄露策略详情，global/org 管理查询返回 403，访问不可见仓库按原生防枚举行为拒绝

#### Scenario: Authentication and missing key

- **WHEN** 未认证请求新 API，或已获管理授权后查询未知 key
- **THEN** 前者按现有 API 返回 401，后者返回 404；禁用企业授权时端点不暴露功能策略

### Requirement: Revision-safe and atomic policy mutation

写入与重置 MUST 要求 `expected_revision`；无记录的首次写入使用 0，已存在记录使用当前 revision，版本不匹配 MUST 返回 409 `revision_conflict`。重置为继承 MUST 保留单调递增的版本标记，不允许删除后重建绕过旧版本检查。语义相同且版本正确的重试 MUST 返回现有结果，不新增版本或重复成功变更审计。grant、操作者/时间/版本和成功变更审计 MUST 原子提交；存储、审计、权限或父级锁校验失败 MUST 整体回滚。并发父子写入与原生配置修改 MUST 有确定的准入顺序，不允许读过期上级后提交违反当前锁的下级变更。

#### Scenario: Concurrent grant changes and stale retry

- **WHEN** 两个客户端以相同 revision 修改同一 grant，或重置后旧客户端再次提交
- **THEN** 至多一个冲突写入成功，其他返回 409，不发生丢失更新、ABA 或部分审计提交

#### Scenario: Audit failure

- **WHEN** 授权内容已准备更新但强制审计持久化失败
- **THEN** 返回安全的存储错误，原 grant、revision 和成功审计保持不变

### Requirement: Mode-aware feature checks and explicit error fallback

企业授权 disabled 模式 MUST 不读取功能策略且保持原生行为；shadow MUST 仅产生候选状态/冲突/错误观测，不改变原生响应、权限、事务或副作用。enforce 下 native_gate 检查 MUST 在受保护读取或业务副作用前使用当前资源和一致策略；明确 disabled/required 违反 MUST 拒绝，Web/API 返回安全 403。基础设施错误默认 MUST fail-closed，Web/API 返回安全 503；显式 `FAIL_CLOSED_ON_ERROR=false` 只允许原生业务检查在可恢复策略/观测设施错误时降级到原生权限，MUST NOT 把显式 deny 变成 allow，MUST NOT 降级管理 grant 的事务与授权。降级 MUST 可被安全日志/指标辨识；不可持久化审计时 MUST NOT 伪造成功证据。

#### Scenario: Shadow and disabled equivalence

- **WHEN** 针对显式 disabled 功能或注入 evaluator/audit 故障，分别运行原生业务的 disabled/shadow 模式
- **THEN** 原生响应及副作用不变，shadow 故障仅表现为安全的候选错误/降级观测

#### Scenario: Deny is not fail-open

- **WHEN** enforce、fail-open 配置下有效状态明确为 disabled
- **THEN** 请求仍被拒绝；只有可恢复基础设施错误才能回退原生检查，且不通过角色扩权

### Requirement: Native units and content operations respect feature policy

enforce 下 Issues、Pull Requests、Wiki 与仓库 Packages unit 的最终设置 MUST 拒绝开启 disabled 功能、关闭 required 功能或通过复合更新旁路。对应内容读写、列表、搜索/聚合结果、下载/导出、外部 issue/wiki 跳转及后台/延迟操作 MUST 使用实际资源的有效策略，禁用内容 MUST 不通过旁路泄露。Issue 与 PR MUST 按业务类型独立判断，不因共用存储而互相误禁。enabled/required MUST 继续要求原生 unit、全局配置和资源权限；required MUST NOT 自动创建 unit、历史数据或提升权限。既有原生功能未开启时 MUST 返回 native unavailable/pending，不把 required 解释为已启用或已满足。

#### Scenario: Composite settings cannot bypass required

- **WHEN** 仓库通过 Web/API 的一次设置更新尝试关闭 required Wiki，并同时修改其他 unit
- **THEN** 整次设置更新在副作用前被拒绝，不部分写入其他字段或后台任务

#### Scenario: Disabled Issue and independent PR

- **WHEN** Issues disabled 而 PR enabled，用户通过详情、搜索、feed 或 comment API 访问内容
- **THEN** Issue 内容被拒绝或从聚合结果过滤，合法 PR 仍走原生权限与 PR 策略，不因共享 issue 表被错误拒绝

#### Scenario: Required does not invent native availability

- **WHEN** 全局 required Wiki，但某旧仓库尚无 Wiki unit 或原生服务器已禁用 Wiki
- **THEN** 查询报告 required 与 native unavailable/pending，实际访问仍不能越过原生配置，grant 更新不自动创建或修改该仓库 unit

### Requirement: Package registry honors account and repository resource scope

Package registry MUST 使用真实 package owner 解析 global/org；关联 repo 的包还 MUST 解析该 repo grant，个人 owner 未关联包仅使用 global。enforce disabled MUST 拒绝相应 registry 的新增上传、追加文件、下载和列表展示；各协议 MUST 保留原生认证和安全的协议错误格式。包关联/重新关联/脱离 repo MUST 校验变更前后作用域，MUST NOT 通过取消关联或另一个可见 repo 绕过禁用。原生受权的删除/清理 MUST 可继续，不自动删包、不扩展原有访问权。

#### Scenario: Unlinked package has no fictional repository

- **WHEN** 组织上传尚未关联 repo 的包，组织 feature.packages 为 disabled
- **THEN** 上传在文件/版本副作用前被拒绝，不虚构 repo ID，也不因未关联而绕过 org 禁用

#### Scenario: Disabled linked package and cleanup

- **WHEN** 下载禁用仓库关联包、尝试解除其关联以绕过限制，或合法管理员删除该包
- **THEN** 下载和绕过关联操作被拒绝，原生受权删除可执行且不授予普通用户删除权限

#### Scenario: Trusted Cargo index and inseparable derived summaries

- **WHEN** a Cargo registry Git index is accessed through HTTP/SSH, or an inseparable registry index contains a package associated with a disabled repository
- **THEN** the trusted repository purpose, actual owner and associated repositories MUST determine Packages policy; forbidden summaries MUST NOT be disclosed through index files or Git history
- **AND** an ordinary code repository named `_cargo-index` MUST NOT be treated as a registry index merely by its name

### Requirement: Webhook management and delivery use current feature state

enforce disabled 的 feature.webhooks MUST 阻止相应范围的 webhook 创建、修改以启用、test/redelivery、任务入队与实际发送；repo 事件触发的 org/system hook MUST 同时尊重事件 repo 的策略，纯 org 事件按 global/org 解析，纯系统事件按 global 解析。队列 MUST 在发送前重新解析，不沿用旧准入；策略拒绝 MUST 记为 skipped/denied 而非 delivered success。原生受权的停用/删除 MUST 允许用于风险收敛；required MUST 不强制每个 hook active 或自动创建 hook，也 MUST 不阻止撤销泄密 hook。MUST NOT 仅通过 URL 猜测 Woodpecker 或对 policy_only feature 假造执行控制。

#### Scenario: Queued task loses permission

- **WHEN** webhook 入队后上级禁用该功能，worker 随后执行或管理员重放任务
- **THEN** 不发送网络请求，不记录 delivered success；停用/删除该 hook 仍受原生权限保护且可执行

### Requirement: CI secret and required-check controls preserve safety

enforce disabled 的 CI secret management MUST 阻止相应范围的新增、更新、复制和管理读取 secret，MUST 保留原生受权的删除/吊销；MUST NOT 撤销已签发凭据、读取或重新发放明文 secret、阻断已授权 runner 的正常 secret 消费。required 表示管理能力不可被下级关闭，MUST NOT 表示必须创建 secret。required status checks disabled MUST 禁止新增或改变检查配置，但 MUST 允许不改变 checks 的其他原生分支保护编辑；MUST NOT 将禁用 feature 转换为关闭/删除既有保护。required MUST 拒绝关闭既有 checks、删除含 checks 的规则或移除强制 contexts；原生 branch protection 与已有 merge action 守卫 MUST 始终保留，MUST NOT 新增外部 feature 对 merge 的完整阻断。

#### Scenario: Secret cleanup and runner compatibility

- **WHEN** secret management 被禁用，管理员新增 secret、吊销 secret，或既有合法 runner 消费 secret
- **THEN** 新增被拒绝，吊销可按原生权限执行，runner 消费仍按原生 scope 和任务权限，不受此管理开关误禁

#### Scenario: Required checks cannot disappear through rule deletion

- **WHEN** effective required status checks 为 required，用户删除含 checks 的保护规则或移除上级指定 context
- **THEN** 在修改前返回 403，规则与 contexts 不变；合法增加检查可继续，但仍需原生及企业 action 权限

### Requirement: External integration policy is not execution or merge approval

六个 policy_only 功能 MUST 提供同样的四态继承、管理权限、版本与审计，以及确定的 contexts 输出；MUST NOT 执行扫描/AI、创建 integration、发放 token、提交伪造 commit status 或因 required 直接产生新的 merge deny。客户端 MUST 能区分 policy_required、native availability 和 integration enforcement 未实现。Woodpecker MUST NOT 代表 Gitea Actions 整体开关，外部 feature disabled MUST NOT 丢弃真实状态回调或删除既有 required checks；本轮 MUST NOT 登记不存在于路线图的 migration/protected-file/Actions feature。

#### Scenario: Global mandatory Gitleaks without scanner

- **WHEN** global 将 feature.gitleaks_scan 设置为 required，并提供合法 check context
- **THEN** 下级无法禁用、有效策略输出必选 context 且标明 policy_only，不宣称扫描已执行，也不在本轮新增合并门禁

### Requirement: Audit and action catalog distinguish real feature operations

系统 MUST 将 `repo.manage_feature_grant` 更新为真实可观测管理 action，并准确声明其执行支持，MUST NOT 让诊断成为许可。授权变化审计 MUST 包含本地 actor、scope、feature、before/after state、revision、reason 和安全配置摘要；原生入口观测 MUST 区分 candidate/actual decision、mode、策略版本、来源、infra fallback 与真实终态。grant 写入审计与业务数据 MUST 同事务；repo 之外的 global/org 操作 MUST 使用真实 scope 而非伪造 repo 决策。历史 action/决策记录 MUST 可读；现有 UI MUST 保持系统超管 authority 且不新增 feature 开关，仅更正能力说明。

#### Scenario: Real mutation and historical diagnostics

- **WHEN** 查看一次成功仓库 feature grant 变更、历史仅诊断记录和现有 action 目录
- **THEN** 目录准确表示当前真实管理能力，历史记录保留其原 candidate/diagnostic 语义，两者不混淆为运行时功能开启或外部执行成功

### Requirement: Migration lifecycle and safe rollback

系统 MUST 使用正式版本化 DB migration 创建功能表、唯一约束、seed 和所需版本元数据；MUST NOT 依赖每次启动修表或手改 DB。升级及新安装 MUST 得到同一目录，重复迁移 MUST 不覆盖管理员 grant 或原生 unit；启用企业授权时缺表/seed/schema 不一致 MUST 被启动预检拒绝。repo/org 删除 MUST 清理对应 grant，repo rename/transfer MUST 保持 repo ID grant 并按当前 owner 重算继承，转移后禁止沿用旧 org 的许可。回退 shadow/disabled MUST 保留策略和历史记录，MUST NOT 要求删除表或降 schema；旧 binary 回退 MUST 使用匹配完整备份而非宣称能直接读取新 schema。

#### Scenario: Upgrade and replay preserve policy

- **WHEN** 从当前授权 schema 升级后设置 grant，再重复运行正式迁移或重启
- **THEN** 13 个定义及索引完整、授权和 revision 不被覆盖，原生 unit、token、SSH key 和旧决策记录不变

#### Scenario: Ownership change and cleanup

- **WHEN** repo 转入禁用某功能的另一组织，或 repo/org 被删除
- **THEN** 后续请求使用新 owner 的继承链且不复用旧缓存/队列许可，删除后相应资源 grant 被清理而不影响其他 scope 或历史审计

可信 Cargo 索引 MUST 通过正式迁移的永久来源记录保留完整 Git 历史贡献仓库 ID；取消关联、包删除和 cleanup MUST NOT 删除来源。历史来源不存在或当前策略禁用时，enforce MUST 拒绝不可分割索引的读取、搜索与新复制；shadow MUST 仅观测。认领 MUST 明确声明完整历史来源（重复 source-repo-id）或无关联历史，并原子记录真实系统管理员审计。可信用途索引 MUST 拒绝 owner transfer，普通仓库 rename/transfer 保持原生行为；索引 rename MUST 保持用途和来源 ID。合法 Cargo cleanup 的跨进程证明 MUST 精确绑定存活准入、owner、actor、credential、ref 和 old/new commit，MUST 一次性且仅豁免索引读门禁，MUST NOT 跳过原生/action 准入。

#### Scenario: Explicit adoption of legacy Cargo index

- **WHEN** an enabled preflight finds Cargo packages and an unmarked legacy `_cargo-index` for their owner
- **THEN** preflight MUST reject unresolved purpose instead of automatically guessing a marker
- **AND** a versioned schema migration MUST provide the purpose column; an explicit repository-ID confirmation by genuine system management authority MUST atomically adopt the purpose and audit it, including in disabled maintenance mode, without modifying ordinary repository purpose implicitly

### Requirement: Identity authentication and deployment compatibility

系统 MUST 保留唯一合法企微 Web 登录及 MFA 续接，MUST NOT 重开本地密码、注册、OpenID、Passkey、其他 OAuth、反代或 SSPI Web 登录旁路。SSH key、PAT/API token、Git HTTP token 的签发、认证、scope、吊销机制 MUST 不变，本地 user MUST 仍是权限与审计主体。enforce 的功能检查可以收紧对应业务访问，但 MUST NOT 新增代码 clone/普通 push 功能门禁，MUST NOT 把 Git author 或客户端 actor 字段当成身份。企微 callback MUST 保持关闭，身份更新保持登录刷新与定时完整同步；服务端 MUST 仅在 Linux 部署和验收，不限制 Windows 客户端访问。

#### Scenario: Authentication regression

- **WHEN** 分别执行非法 Web 登录、合法企微/MFA 登录、SSH clone、PAT API 与 Git HTTP token clone/普通 push，并切换三种 authz mode
- **THEN** 非法登录持续拒绝，合法认证和原生 scope/吊销边界保持不变，仅相关 enforce 功能业务访问按策略收紧，不因本提案禁用 Git 基础访问
