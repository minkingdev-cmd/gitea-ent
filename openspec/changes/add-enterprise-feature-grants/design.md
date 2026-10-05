## Context

动机与产品边界见 [proposal.md](proposal.md)，行为合同见 [功能授权规范](specs/authorization/enterprise-feature-grants/spec.md)。本设计以 2026-10-05 当前工作区为基线，而非假定上游 Gitea 已有同类能力。

- `modules/enterpriseauthz/action.go` 的 `repo.manage_feature_grant` 目前 `Observed=false`、`EnforceSupported=false`，已有 Owner/platform-admin action 集，但没有真实功能管理入口。
- `services/enterpriseauthz/management.go`、`models/perm/access/enterprise_authority.go` 已提供 system/org/repo 管理 authority；企微模式比本地 `IsAdmin` 更严格。`role.go` 已有 revision、事务复核及 required audit 模式。
- `services/enterpriseauthz/execution.go` 的准入受资源、actor、凭据和 intent 约束，不是可跨请求复用的许可；disabled/shadow 不执行 enforce 准入。新 grant 管理 API 不能只调用该接口就认为三种模式均已受保护。
- `services/repository/setting.go`、`services/webhook/management.go`、`services/pull/protection_management.go` 已存在高风险设置写边界，可叠加功能检查；content、package owner、webhook worker 等需要补充独立资源判定。
- 当前正式迁移在 `modelmigration/migrations.go`，最新 entry 为 362，迁移后 DB version 为 363；下一版本实施时重新确认，不能改写已交付迁移。新安装还需覆盖 `modelmigration/enterprise_authz_install.go` 路径。
- 前序三个授权 change 已有完成任务与验收文档，但尚未折叠进主 specs。本提案新增单一 capability，不修改旧验收证据，也不为推进本 change 自动归档前序 change。

## Goals / Non-Goals

**Goals:**

- 用可单测的纯解析器定义状态与配置语义；DB 查询、管理 authority、原生配置、执行准入分层，不让路由复制继承算法。
- 实现 API → scope/credential → authority/action → 事务/revision/父级锁 → 审计闭环，并让原生入口真实消费同一解析结果。
- 对目录的每个 key 明确当前 enforcement coverage；原生可用性与治理要求分离，便于后续 merge gate/template 消费而不伪造已满足状态。

**Non-Goals:**

- 不引入策略服务、OpenFGA、Keycloak、Flyway，不改变现有登录、Git token、SSH、repo unit 权限模型。
- 不把 Woodpecker 当成 Gitea Actions 总开关，不将 scanner/AI 运行与功能授权混为一体，不借本 change 实施完整 merge gate。
- 不新增管理页面或扩大旧页面的 authority；仅同步已有 catalog 帮助文本。完整 feature UI 属于后续独立 change。

## Decisions

### 1. 两张表、固定目录、正式 seed

新增 `enterprise_feature_definition`：`id`、唯一 `key`、`description`、`supported_scopes_json`、`default_state`、`capability_kind`、`config_schema_version`、`catalog_version`、`policy_revision`、时间戳。定义是代码版本化目录，不开放定义 CRUD；`policy_revision` 可变，不与 immutable catalog seed revision 混淆。

新增 `enterprise_feature_grant`：`id`、`feature_key`、`scope_type`、`scope_id`、`state`、`config_json`、`revision`、`created_by`、`updated_by`、时间戳。唯一键 `(feature_key, scope_type, scope_id)`，global ID 固定为 0；org ID 必须对应组织，repo ID 必须存在。DB/model 层保护唯一性，service 层保护语义，不能靠软检查消除竞态。

外部 API 使用 `global`，内部映射既有 `ScopeSystem`，不把新字符串 global 混进旧角色 scope。原生七项默认 enabled；外部六项默认 disabled。无初始 grant、无既有 unit 重写、无迁移后批量开启功能。scope 删除清理 grant，但不删历史审计；重置 grant 保留 inherited 行与 revision，避免 ABA。

选择固定目录是为了让 metadata、验证和真实接线一起版本化。替代方案：仅内存目录不能完整满足定义表/seed 验收；允许管理员自由创建 key 会产生无实现的授权项与配置注入面，均不采用。

### 2. 锁定优先的纯函数解析

输入为已验证 definition、global/org/repo 三层记录及其 revision。首先查找从根向下的首个显式 disabled/required 锁；没有锁时使用最近的非 inherited 状态，最后才回落 definition.default_state。default_state 不形成上级锁。祖先 required + 后代 enabled 仍为 required；祖先 disabled + 后代 required 仍为 disabled。

- 修改下级状态时拒绝新增与祖先锁冲突的显式状态；允许 inherited 用于清除本层覆盖。父级修改不扫描/重写所有后代，解析时把旧冲突标记为 ignored/conflict。
- 无 required 锁时配置按最近显式 grant 完整替换，空配置也表示替换，而不是沿用旧字段。
- required 锁下，将最近非冲突显式配置与有效 required 层 contexts 求并集；disabled 锁后不贡献执行配置，后代冲突 required 的 contexts 不进入必选集。
- `inherited` 只允许 `{}`。原生 unit/webhooks/secret 只允许 `{}`；其余只支持 `check_contexts`，最多 64 项，每项 UTF-8 1–128 bytes、无控制字符和首尾空白；排序去重，配置最大 16 KiB，请求总大小沿用既有 authz body 上限。未知/重复字段、null、非法 UTF-8 和尾随 JSON 一律拒绝。

输出为 effective state、state source、locked by、conflicts、canonical config、实际参与链及 canonical hash。reader 只看到无敏感细节投影。hash 绑定 definition catalog/schema version、policy revision、当前 owner、参与 grant revision，不能作为准入 ticket。第一版不做跨请求缓存；每次调用从同一 DB snapshot 读取，避免多实例失效复杂性和转移后的旧 owner 缓存。

替代方案：最后更新时间优先不确定且可绕过祖先；先修改 repo unit 再解析会让回滚污染原生配置；通用 JSON merge 难以保证上级必选项，均不采用。

### 3. 权限矩阵与 API 合同

所有管理 API 先执行既有认证与 token scope，再从服务端路径对象解析 scope，进入 service 再复核当前 actor/authority。不接受 body 中的 actor、owner、scope ID。组织凭据只在组织 API 范围内使用，不借 repo credential resolver 隐式升级。

| 入口/API | 后端权限与凭据 | 默认可管理主体 | 前端边界 |
| --- | --- | --- | --- |
| `GET /api/v1/enterprise/authz/features` | admin read scope + 当前 system authority | 可信系统超管；企微关闭时沿用原生 site admin | 无新入口，旧页面仍系统超管 |
| `GET/PUT/DELETE /api/v1/enterprise/authz/features/{key}/grants/global` | admin read/write scope + 当前 system authority | 同上 | 无 feature 控件 |
| `GET /api/v1/orgs/{org}/enterprise/authz/features` 与 `GET/PUT/DELETE .../features/{key}` | organization read/write scope + 当前 org management authority | org owner 或可信系统超管 | 无新组织页面 |
| `GET /api/v1/repos/{owner}/{repo}/enterprise/authz/features` 与 `GET .../features/{key}` | repository read scope + 凭据 read ceiling + 原生 repo 可见性；匿名不开放新策略 API | 有效原生 reader，包括 public repo 的已认证 reader | 无新仓库页面 |
| `GET .../features/{key}/grant` | repository read scope + 现有 repo management authority | 现有企微仓库授权管理员；企微关闭时原生 Admin | 仅 API 原始投影 |
| `PUT/DELETE .../features/{key}` | repository write scope + 原生/企微 management authority + 当前 `repo.manage_feature_grant` + 写 credential ceiling | 原生 Owner/可信管理员及满足前两项的显式 action 角色 | 不委派旧角色/绑定 UI |

global/org raw 查询显示本范围及合法祖先的策略，但不提供下级枚举。repo GET effective 使用 reader 投影，raw `/grant` 显示安全详细链、冲突和 native availability。合法 key 尚无本层 grant 时返回 inherited/空配置/revision=0，不伪造持久化行。列表最大 100 项分页；未知 key 的 GET/DELETE 在鉴权后返回 404，PUT 返回 422。

PUT body 固定 `{state, config, expected_revision}`，字段必填，首次 revision=0；返回 200 的完整本范围 grant+effective 管理投影。DELETE 用 query `expected_revision`，将已有行变为 inherited/空配置并递增版本，返回 204；不存在且 expected_revision=0 的重置无副作用，其他过期版本返回 409。语义无变且 revision 正确时 PUT 返回现存数据、DELETE 204，不重复增加 revision/审计。

错误保持 401（认证）、403（权限/业务功能拒绝）、404（authz disabled/资源不存在/查询 key 不存在）、409（revision_conflict / feature_parent_locked）、422（非法策略/写入未知 key）。grant transaction/storage/audit 错误沿用安全 500 `policy_storage_failed`；原生 enforce 可恢复设施错误默认 503。错误不回显 config 原文。

`repo.manage_feature_grant` 成为真实 Observed/EnforceSupported action，但不能仅靠模式相关的 BeginExecution 做 grant 管理鉴权：shadow 下也必须验证该 action 与管理 authority。global/org 沿用专用 authority，不把 repo action 升格成平台权限。内置 action 集不需扩权；动态角色与凭据均不能自行授予可见性/管理 authority。只同步 catalog 描述和旧 UI 硬编码帮助，不增加 feature 读写按钮。

### 4. 管理变更事务与并发线性化

沿用 `db.WithTx`、scope 锁与 `audit.WithRequiredPersistence`，锁定资源/authority 后，再按 feature key 排序锁 definition 行；definition 行提供每个 key 全局共享写锁，即使 global grant 尚不存在，也能序列化父子写入。锁顺序与既有 role/unit/lifecycle 事务统一，禁止持有 definition 锁后反向获取资源写锁。

事务内重新检查 actor、当前 repo owner、管理 authority、action/凭据、expected_revision、祖先链及 config；写 grant CAS、增加 definition.policy_revision、保存脱敏审计，再共同提交。任何失败整体回滚；幂等无变更不增加版本。不要无条件嵌套现有执行准入的独立 read tx，避免与它的“不在业务事务中 BeginExecution”约束冲突；准备阶段沿用现有准入，事务内的功能 revalidation 使用独立纯解析/已有 ctx，而不是再次创建准入 ticket。

DB 型原生配置变更在相同资源/feature 锁下检查最终 intent，再整体写入，父级 grant 与下级关闭功能不能同时成功违反当前 required。非 DB/Git/外部网络路径使用写前一致 snapshot 的准入线性化点；已准入的在途操作不承诺被后续策略撤销物理取消，但延迟/queued 操作启动必须重新解析当前 owner/策略。不给跨 Git/DB/对象存储虚假的原子性保证。

共享 definition 行会序列化同 key 的策略与配置写入，但这些低频管理操作可接受；内容读使用 snapshot，不获取该写锁。若未来需要高吞吐再优化，不能先用 TTL 缓存牺牲撤销语义。

### 5. 原生接线矩阵与必选含义

| Feature | 本轮真实接线 | disabled / required 边界 |
| --- | --- | --- |
| issues | repo unit 最终 intent；Web/API 内容、comment、搜索/聚合、feed/export、外部 tracker 跳转；实际 Issue service 和后台任务 | disabled 不可读写；required 禁止关闭 unit，不自动创建数据 |
| pull_requests | unit 最终 intent；PR 创建/评审/详情、AGit、延迟/auto/force/manual merge 的实际执行边界及聚合 | 与 Issue 按业务类型分开；原有 action/branch protection 不变，只新增 PR 功能可用性检查，不计算完整 merge gate |
| wiki | unit 最终 intent；Web/API/read/write/export/external wiki；Wiki Git HTTP/SSH 服务 | 仅 Wiki repo 操作受约束；主代码 repo clone/普通 push 不受影响；协议返回原生格式安全拒绝 |
| packages | repo Packages unit 设置/展示；真实 package owner 的 global/org 检查与关联 repo 检查；各 registry auth/download/list/upload/append/association service | 未关联包不伪造 repo；关联变化校验前后；delete/cleanup 保留原生权限；unit required 不强制创建包 |
| webhooks | repo/org/system hook 创建/更新/test/redelivery、Prepare/入队、Deliver/worker；repo payload 携带真实 repo 上下文 | disabled 不发送，队列重判，不把 skip 记 success；停用/删除可做；required 不强迫每个 hook active |
| ci_secret_management | repo/org secret 的 API/Web 管理与 shared service；global 用作所有范围上限 | disabled 禁止管理读/新增/更新/复制，允许受权 delete/revoke；required 不要求创建 secret；不改 runner 正常消费和凭据 |
| required_status_checks | branch protection 创建/更新/删除及批量/priority 意图影响；现有 ManageCI/ManageBranchProtection 准入 | disabled 不允许改变 checks，也不关闭既有 checks；required 防关闭/删规则/移除 mandatory contexts；其他字段更新按原生权限 |
| woodpecker_ci / sonarqube_quality_gate / semgrep_scan / gitleaks_scan / trivy_scan / ai_review | 固定目录、grant API、effective resolver、config/context 输出、audit | policy_only；不拦截现有外部状态回调、不运行外部任务、不创造新的 merge deny、不等同 Gitea Actions |

unit 检查面向更新后的完整集合，而非 `deleteUnitTypes` 的中间删除（该 service 为更新先删后插）；支持 old unit/config → intended unit/config 的规范化比较。enforce 前检查 compound 设置的全部受保护 intent，再一起写入，不能改一半才报错。

`required` 表示能力不可下级关闭；缺少原生 unit、全局服务关闭、没有 hook/secret/checks 或外部 adapter 缺失时，报告 pending/native unavailable，不自动补建资源。unit 实际读取始终执行原生权限；上级设置 required 不向所有 repo 批量插入 unit。required checks 保存的 context 要求只约束已被管理的原生规则防降级，不自动造新规则或向未配置仓库新增 merge 阻断，此类收敛属于后续 template/gate。

组织 scope 用于 owner-registry、org hook、org secret；个人 scope 使用 global，系统 hook 使用 global。repo-origin 事件即使由 org/system hook 发送，也附加 repo 策略；hook task 必须保存/恢复可信来源上下文，不能从 payload 自报 repo ID 授权。批量列表和搜索先过滤再分页/计数，不能泄露禁用内容的摘要、数量或 feed 通知。清理允许列表只能执行原生已有删除/停用/吊销，不能绕过 native/action authority。

实施切片首先完善 action-to-hook 与 feature-to-hook 清单，包括 router/service/worker/protocol/model 写入调用者；matrix 不是仅 diagnostic 的替代品。内部删除、仓库创建、转移、导入/镜像和 repair 必须明确属于原生配置初始化、合规受检业务或固定维护，不能用 `system` 来源字符串做通用旁路。

### 6. 模式、诊断、审计与故障

沿用 `[enterprise.authz] ENABLED/ENFORCE/FAIL_CLOSED_ON_ERROR`，不引入第二套 feature enforce 开关。配置文档和 `app.example.ini` 补充含义，不改变默认值；enabled 启动 preflight 增加功能表、index/definition seed/schema 检查。

- disabled：不做 feature DB 读取，原生业务保持原样；新管理 API 404。
- shadow：可以管理受权策略，也记录候选功能状态；真实业务只走原生行为，候选 feature deny/error 不拒绝原生请求。
- enforce：native_gate 的 explicit deny 一律拒绝；基础设施错误默认 fail-closed，显式 fail-open 只对原生业务回退，不能给管理写事务降级。policy_only 没有运行阻断，不冒充其 enforce 已实现。

扩展现有决策 snapshot 的版本化 JSON 包含 feature key/state、chain hash、锁/conflict、安全配置摘要、capability 和 native availability；既有 decision/table 查询 DTO 对历史缺字段兼容。已有 repo action 的准入关联同 operation；没有 repo action 或资源仅 global/org 的功能事件走 feature-specific scoped audit，不编造 repo/action。feature deny、native deny、infra error、policy_only required、业务终态分别记录。无法落库时仅安全日志/指标报告，不能声称 audit 已保存。

管理审计使用 `enterprise:feature:grant:update/reset`，包括 before/after state/config hash、scope、actor、版本；审计禁止 secret、URL、OAuth code/token、原始通讯录信息。目录“真实可操作”与诊断“candidate_only”仍区分，现有系统超管 UI authority 不变。

### 7. 验证策略与依赖

依赖当前工作区 foundation shadow 与 high-risk enforce 实际实现；hardening 尚有任务未勾选，不把 callback 打开作为本提案前提。若实际前序基线缺失，则先补齐该依赖，不将新 grant 管理降成无 action 的 CRUD。

- 纯 unit：13-key metadata、全状态矩阵、ancestor conflict、personal owner、default fallback、contexts 替换/并集、严格 JSON 和预算；优先表驱动，一次覆盖边界。
- model/service：正式迁移/新安装/重放、CAS/reset ABA、scope/actor spoof、真实 authority、父子并发与设置竞态、required audit 故障整体回滚、transfer/delete、snapshot 当前 owner。
- integration：真实 API 路由与 token scope；每类 native_gate 的 Web/API/service、Wiki Git、package protocols、webhook queue、AGit/auto merge；复合 intent 和故障模式矩阵；不得用目录诊断替代接线验证。
- compatibility：非法 Web 登录、企微/MFA、SSH/PAT/Git HTTP token scope/revocation，main Git clone/普通 push、旧 shadow/enforce 回归、受限 runner secret 消费。Linux SQLite 与 Linux PostgreSQL 为部署验收，不要求 Windows 服务端。

只改帮助文本时沿用现有 UI smoke，不开发 feature 页面；如实际有模板/locale 改动则定向 lint 与权限/XSS 回归。每个 requirement 在验收报告中对应实际测试/结果；规划任务保持未勾选直到实施验证。

## Risks / Trade-offs

- [上级 required 与已关闭原生 unit 不一致] → 不静默改变配置，详细查询报告 pending；上线前盘点、手工受权设置，后续模板负责规模化收敛。
- [把外部 required 当作扫描通过或已 enforce] → 显式 policy_only 和 pending，测试无新增 merge deny、无伪造 status、无服务调用。
- [旁路包括 Wiki Git、package owner、org/system hook、AGit 与后台任务] → 按真实资源接线，写前和队列启动复核，不靠隐藏 UI 保护。
- [parent/child 与 unit 写竞态、转移旧缓存] → 共享 definition 锁、资源先锁、current-owner snapshot、无跨请求缓存、真实并发测试。
- [严格模式误封运营清理] → 删除/停用/吊销窄允许列表且保留原生 action authority；不允许“cleanup”任意标签绕过。
- [fail-open 审计不能持久化] → 安全日志/指标明确降级，管理策略始终 fail-closed，不把候选 allow 写成业务成功。
- [广泛读取门禁导致性能/浅 fork 风险] → 公共 service 和按批量资源读取解析，native gate 小钩子；不在底层 model 引用 services，不逐行 N+1，不深改数据基础模型。

## Migration Plan

1. 在 Linux 测试环境备份匹配 binary/config/DB/Git/Wiki/package storage，记录 DB/schema/catalog version；实施前确认下一 migration ID。正式 migration 创建两张表/唯一索引/目录版本，新安装路径使用同一版本化 seed；不覆盖 grant，不自动补 unit。
2. 同一新版部署 disabled，核对原生行为与原有 authz 回归；启用 shadow 后 preflight 必须完整通过，再经受权 API 配置试点策略、查看冲突/pending 和 webhook/包范围。
3. 验证试点真实接口/队列/protocol 的候选记录、原生 availability 与明确清理路径，完成 Linux SQLite/PG、当前 owner 并发及审计故障测试后，经运维明确批准切 enforce。本提案创建不代表已批准上线。
4. enforce 失败优先同 binary 切 shadow/disabled，保留表、grant、revision 和审计；配置/功能 disabled 不删除数据，也不自动恢复被管理员主动修改的原生 unit/checks。
5. 不支持直接降 schema 或用旧 binary 忽略新 seed；必须恢复匹配的整套备份并验证版本/资源。多实例混用旧/新 binary 不作为受支持 rollout：停止旧节点、迁移后统一新版本，再按原开关回退。
6. 更新功能授权 runbook、既有 shadow/enforce runbook、implementation-plan 和 roadmap，记录各 key coverage、pending 语义、API 示例、恢复实证及未做的外部集成。未经授权不 commit/push/deploy/归档/同步主 specs。

### 实施补充：Cargo 索引用途与遗留队列

正式 migration 363（DB version 364）同时增加 `repository.internal_usage`（默认空）和可信 HookTask 来源列。新 Cargo 索引仅由内部 CreateRepoOptions 设 `cargo-index`；不向 API/form 暴露用途写入。lookup 使用 owner + 用途、Stable ID，rename 不失效。用途未知的普通代码仓库不接 Packages Git 门禁。

历史 `_cargo-index` 没有可信来源，不能用名称/描述/Git内容静默标记。启用预检发现拥有 Cargo 包的 owner 存在同名未标记仓库时拒绝启动；运营须停业务、备份后，在新版 disabled 维护模式、DB 审计开启条件下，通过 `admin enterprise-features adopt-cargo-index --repo-id --actor-id --confirm-index-purpose`，并逐项提供所有 Git 历史贡献仓库的 `--source-repo-id`（可重复）或明确 `--confirm-no-linked-history` 明确认领，事务内复核真实系统 authority、owner、唯一用途并原子审计。若同名其实普通代码仓库，则解决名称冲突，不认领它。不得使用手工 SQL 或启动自动猜测代替受控迁移。

Git 历史和各 registry 静态 derived index 不可逐项安全过滤；正式 `enterprise_cargo_index_source` 表永久保留贡献仓库 Stable ID；关联/取消关联、包删除和 cleanup 都不删除历史来源。旧索引认领时必须由真实系统管理员确认完整历史来源，不把当前包列表当历史。若任何贡献来源被删除或其当前 owner/仓库策略禁用，或实际关联包被禁用，拒绝整个不可分割索引，而非泄露其名称/摘要。合法删除后的索引维护使用固定 owner/type/name 的内部能力，不能由客户端或任意来源标签自授予。跨进程 receive hook 只接受签名 ticket 与仍存活且匹配 owner/actor/credential/ref/old/new 的服务端一次性执行证明；该证明仅豁免 cleanup 的索引读门禁，不能绕过原生/action 权限。可信索引禁止 owner transfer，普通代码仓库仍使用原生转移；rename 保持 Stable ID。

升级前 mail 队列无可信业务类别/IssueID，无法仅隔离旧 Issue 邮件且不误禁认证邮件。严格 rollout 必须停全部实例生产者与 worker、备份并隔离既存 mail 队列，再运行新版；不可直接删除与其他队列共用的 common storage。新邮件携带服务端 IssueID 并在发送前复核。此运维前置条件必须显式记录，不能宣称旧消息 scope 可被安全猜测恢复。
