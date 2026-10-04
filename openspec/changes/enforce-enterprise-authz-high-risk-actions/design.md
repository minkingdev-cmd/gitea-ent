## Context

动机与产品范围见 `proposal.md`；验收合同见两份 delta specs。2026-10-04 的工作树为干净基线，OpenSpec CLI 1.9.0；foundation 与 management-ui 均为完成但尚未归档的 change。以下是实际代码约束，而非将要实现的结果：

- `modules/setting/enterprise_authz.go` 拒绝所有 ENFORCE=true；`models/enterpriseauthz/readiness.go` 检查四表和内置 seed 的精确动作集合。
- `services/enterpriseauthz/evaluate.go` 使用一致读，返回 candidate_only=true、safety_guards_evaluated=false。`native.go` 使用原生 action 与角色 allow 并集：code writer 默认有 merge，Admin 默认有保护规则/CODEOWNERS/webhook/CI，保护分支/secret/danger-zone 为保守 Owner-only。
- `observe.go` 的 200ms 有界独立证据事务不阻断原生请求，也不能在业务事务中启动 observation。`operation.go`、`hook_operation.go` 的 owned/ticket 与历史恢复只负责归因/去重，不是执行许可证。
- `routers/private/hook_pre_receive.go` 当前按 ref 处理并执行原生保护规则；`cmd/hook.go` 的内部 push early-return 不执行所有 receive hooks。
- `services/repository/files/enterprise_authz.go` 已观察 CODEOWNERS，但递归删除/部分 patch 路径会保持 incomplete；Git receive 或 merge 的真实差异必须补齐，不能把现有旁观接线当 enforce 已完整。
- `services/issue/pull.go:IsCodeOwnerFile` 当前识别 `CODEOWNERS`、`docs/CODEOWNERS`、`.gitea/CODEOWNERS`。保护分支已有 protected/unprotected file patterns；没有本次可直接启用的新 enterprise_protected_path_rule 产品。
- 原生 collaborator/team 管理分别在 `services/repository/collaboration.go`、`repo_team.go`，org team 权限/unit/includes-all 变更在 `services/org/team.go`；部分 helper 不收 actor 且在事务内调用。
- `modelmigration/v28/v361.go` 已创建 foundation schema/seed。决策 DTO/UI 目前硬编码候选语义，`presentation.go` 对快照 CatalogVersion 做当前版本精确校验，目录升级会使旧历史无法读取，必须同时修正。

## Goals / Non-Goals

**Goals:**

- 每个高风险实际 mutation 都有可返回拒绝的执行准入，而非 void observer；尽量复用 evaluator/适配上下文，不复制角色解析或深改 Git/PR 模型。
- 把“允许 action”“原生 guard/业务结果”“有可持久化准入证据”分开表达，错误和降级可运营、可测试。
- 对共同入口、跨进程、延迟执行和复合请求给出明确身份、目标和幂等边界；未通过的 action 没有业务副作用。

**Non-Goals:**

- 不替换原生访问阈值，不让只有 reader 权限的角色持有者执行原生 Admin 操作；不引入 deny、PDP、平台管理员角色即站点管理员的转换。
- 不新增受保护路径策略数据库/功能授权/质量门禁，也不把管理 required checks 变成运行检查系统。
- 不建设新的管理页面；仅扩展现有后端输出、历史筛选/详情及模式提示。无实时配置按钮、凭据回收、callback 启用或 Windows 服务端要求。

## Decisions

### 1. 三模式与固定 enforce 集

保留三个配置键与默认值，放开 ENABLED=true,ENFORCE=true；disabled+enforce 拒绝。`FAIL_CLOSED_ON_ERROR` 仅控制本次执行准入的可恢复基础设施故障；shadow/管理 API 不因此改变错误语义。配置启动必须先通过数据库审计、schema/seed 及内部可信传播所需预检，fail-open 不豁免启动检查。

catalog 增加 `repo.manage_access`，高风险、mutating、无特定 unit；目录输出追加 `enforce_supported` 元数据。固定集为 merge、protected push、branch protection、CODEOWNERS、webhook、CI、secret、manage_access、transfer、archive、delete。低风险及 migrate 保留 shadow；feature grant 继续 Observed=false。不提供 per-route/per-user 半启用开关。

替代方案：只取消 `enforce_not_supported` 或逐步开放开关会使未覆盖共享入口成为旁路；按 Risk=high 全部自动 enforce 会把 migrate/feature grant 偷渡进范围，因此用显式目录集合和覆盖测试。

### 2. 新增执行 guard，observer 继续仅观察

在 `services/enterpriseauthz` 新增可返回 typed rejection 的统一执行准入。接口接收受信 `EvaluateInput`/操作意图与必需 actions，返回当前决策集合和受信 admission handle；命名由实现遵循项目惯例。禁止把 `Observation` 私有字段、diagnostic DTO 或 ticket 当 authorization cache。

流程：

1. 完成原生认证、scope、资源安全解析及当前 actor 状态；无权限资源不为 authz 读取更多数据。
2. 在实际目标 mutation lock/明确准入边界内，解析 owner/ref/SHA/差异/全部操作意图；重新获取当前 actor 与凭据感知的 native permission，并在一致策略快照内评估全部必需 actions。
3. 原生操作权限及动作安全守卫仍执行；企业 action 只增加必要条件，不替换 `CanDoerManageRepoDangerZone`、org team 管理资格、force、受治理团队、branch protection 或账号状态等检查。通过可信系统管理员路径时复用 `HasSystemManagementAuthority`；企微开启不能仅用旧 IsAdmin 提供默认全 action。
4. 缺任何 action 则 typed 403；基础设施故障按配置处理；允许集合的准入证据与对应审计独立原子提交后，才进入业务 mutation。
5. 真实业务结束后独立更新执行终态；不能在持有业务事务的情况下开阻塞证据写事务。副作用前证据提交不代表整个操作成功。

准入线性化点是写边界内创建的一致权限/政策快照：在此点前提交的撤销必须读取到；点后撤销不取消已准入进行中的操作。不能复用前置 handler 的 native permission 或只在 evaluator 中刷新 actor/repo 却留下旧 permission。延迟/跨进程执行重新建立此边界，不跨请求持久化 allow。资源意图或 ref/head/base/owner 在检查后变化则在执行锁内重建准入，不把旧 handle 用于新目标。

复合请求在 router/shared service 收集 actions，统一准入后才开始业务写入；嵌套 helper 仅接受绑定 actor/repo/owner/intent 的私有 handle，仍验证目标一致，不能凭字符串 bypass。业务自己的多步成功/失败语义不被改成新分布式事务；必须保证企业授权拒绝发生在这些步骤之前。

默认准入总预算为固定 1s，覆盖准备、权限一致读与准入证据；shadow 仍 200ms。需要收集的条件上下文 paths 上限沿用 1024，批量 team 授权目标上限固定 1000 个现有 repo；超限安全拒绝并要求拆分，不截断、不无界 goroutine。保留固定原因码及指标，不引入额外可导致不一致的入口级预算配置。

替代方案：仅路由 middleware 漏掉共享/后台/协议入口；强行让角色替代所有 native guard 会改变已确认权限模型；只把 observer nil 当 deny 又会混淆 disabled/故障和候选结果，均不采用。

### 3. 错误处理合同

| 状况 | fail-closed=true | 显式 false | 原因/记录 |
| --- | --- | --- | --- |
| missing_action、条件不匹配/unresolved | Web/API 403，Git 拒绝 | 同样拒绝 | deny，missing actions |
| 原生认证/scope/可见性/安全守卫拒绝 | 保留原生隐私与错误 | 同样拒绝 | 仅在安全目标边界记录 |
| 无效/缺失受信 actor/ceiling、伪造 ticket、路径/批量超限或不完整 | 安全拒绝 | 同样拒绝 | invalid_execution_context，不降级 |
| policy/权限准备的授权基础设施 DB 故障、1s 预算耗尽 | 副作用前安全 503/Git 拒绝 | 仅恢复原生路径 | error 或 fallback，固定原因 |
| 前置 decision 或关联 audit 写入故障 | 副作用前安全 503/Git 拒绝 | 仅恢复原生路径 | evidence_persist_failed，不造半套记录 |
| 客户端取消 | 停止，不 mutation | 同样停止 | cancellation，不当作 fail-open |
| 执行后证据终态更新失败 | 保留真实业务响应/结果 | 同样 | unknown + 安全缺口告警，不能宣称回滚 |

若已有任一明确 action deny，不能用其他 action 的 DB 错误将整组降级为 allow。原生安全守卫自身错误保持原生安全失败，不包含在“授权基础设施错误”可降级集合。fail-open 不是角色授权兜底：只能按未叠加角色的原生权限/守卫运行；可恢复时记录 fallback，证据全不可用则指标/脱敏日志报告，不能宣称有可靠审计行。默认 true；运维使用 false 必须明确登记降级窗口与恢复动作。

### 4. 入口/API → 执行 guard → action → 默认授权 → UI 边界

下表列实现定位和完整闭环；本项目是 Go/Gitea，自有关系表及 modelmigration，而非通用 guard skill 示例中的 Java 注解/OpenFGA/Flyway/Keycloak。

| 入口与共享边界 | 必需 action | 原生默认来源/显式角色 | 保留原生前提与 UI |
| --- | --- | --- | --- |
| Web/API merge、`services/pull/merge.go`、auto、MergedManually | merge；实际改 CODEOWNERS 加 manage_codeowners | code write+PR read；Owner；匹配 maintainer/自定义角色 | 原 merge/force/checks/锁；原 merge 按钮和 auto 配置，无新入口 |
| Git HTTP/SSH receive、pre-receive；Web/API/editor/patch/branch/fork sync/PR head update | 实际保护目标 push_protected_branch；有 CODEOWNERS 差异加 manage_codeowners | protected push 仅 Owner 或显式角色；CODEOWNERS 原 Admin/Owner 或角色 | write credential+code、保护/签名/文件规则；原 editor/branch UI |
| Web/API 保护规则 CRUD/priority；protected/unprotected file patterns | manage_branch_protection；required checks 有效变化另加 manage_ci | Admin/Owner；CI 亦可匹配 maintainer/security-maintainer/自定义 | 原规则合法性/治理；原 settings，GET 不当 mutation |
| repo webhook CRUD（`services/webhook`） | manage_webhook | Admin/Owner、maintainer/自定义 | 原禁用 webhook/URL/对象 scope；原 webhook 页 |
| repo Actions secret 写入/删除（`services/secret`） | manage_secret | Owner、显式自定义 | 原 Actions unit/scope，不能读取 secret 内容；原 secrets 页 |
| repo CI unit/token permissions/variables/runner/workflow enable-disable | manage_ci | Admin/Owner、maintainer/security-maintainer/自定义 | 原权限/runner/workflow scope；非管理 workflow 操作不接此 action |
| repo collaborator Web/API；`collaboration.go`、`repo_team.go`；org team unit/authority/includes-all 变更 | manage_access（全部受影响 repo） | Owner；内置企业 Owner/Platform Admin；显式自定义 | 原 org owner/config/team/企微生成治理仍须满足；原 collaboration/team UI |
| transfer start/accept/reject/cancel；`services/repository/transfer.go` | transfer | Owner 或显式自定义 | 当前执行人/旧 owner/目标团队/配额/接收资格，原 transfer UI |
| Web/API archive/unarchive | archive | Owner 或显式自定义 | 原 danger-zone/mirror 等 guard，原 archive UI |
| Web/API delete、`services/repository/delete.go` 前置调用 | delete | Owner 或显式自定义 | 原确认/治理/清理，原 delete UI |
| authz role/binding API 与现有管理 UI/搜索/详情/诊断 | 不由 manage_access 或企业角色赋权 | 原 API authority；UI 当前系统超管 | session/CSRF/token scope 不变，无 enforce 按钮 |

“默认来源”仅表示 evaluator action 来源，非 native guard 替代。平台超管按当前可信系统 authority 与原生资格获得对应默认能力；Platform Admin 企业角色不会改变 IsAdmin。maintainer/security-maintainer 不新增 manage_access seed。action-aware UI 提示/按钮必须复用后端相同准入合同，不能用前端隐藏代替服务端阻断；已有 settings 的 native gate 不为角色候选 allow 放宽。

### 5. Merge、Git 和 CODEOWNERS 的实际执行

merge 在共享 service 与持有实际 merge lock 的边界重新检查，auto 保存 doer 而非 allow；manual 记录在 merged 状态 mutation 前检查。最终影响 CODEOWNERS 的 diff 与目标 branch/head/base 来自受信 Git 状态，在写入前同时检查 merge/manage_codeowners。内部 merge push 是 merge 的机械结果，不额外要求独立保护分支直推 action，保持原生 force 语义；这不是新增 merge gate。

外部 receive 的新准入在 pre-receive 完成：先完整解析各 branch old/new refs 与保护规则，读取 quarantine 中的实际对象差异，检查所有受控 refs，之后才允许 Git 写 refs。一个受控 ref 拒绝则整个 receive 拒绝；tag/wiki/refs-for 仍按原生语义，不自动当 branch。CODEOWNERS 在普通 branch receive 也检查，原生读写/保护守卫均保留。

Web/API/editor、patch、递归删除、rename、PR head update/fork sync 等内部写 service 必须在 push 前建立 guard，不能依赖 `EnvIsInternal` 的 hook。CODEOWNERS 识别沿用 `IsCodeOwnerFile` 的三个固定路径，基于完整 old/new 差异作精确路径查询（可关闭 rename 展开，以旧路径删除/新路径新增完整覆盖两端），包括递归删除；不依据文件内容、git author 或请求字段推导 actor。不必为了识别 CODEOWNERS 收集整仓全部 diff 路径，避免把超过1024文件但未涉及受控动作的普通 push 变成新增拒绝。仅当实际受控 action 需要路径条件上下文时收集完整集合，上限1024；无法安全准备所需集合不能截断后宣称完整。fail-open 的 DB 错误不豁免必要的 policy-file 识别。

现有 HMAC ticket 用于 source/actor/repo/credential 归因及跨进程关联，保留上限与签名检查；owned 只去重证据。外部 receive 必须建立当次准入，旧 shadow ticket 不包含许可。内部 push 的私有 admission handle 绑定 operation、repo/owner、actor/credential、exact target/commit intent，只有 server 代码能构造；不能把 ticket 24h 生命周期当准入有效期。post-receive 仅更新终态，不能在那里首次拒绝。

### 6. 仓库授权变更与受信系统维护

新增 manage_access 默认 native Owner，保留 Admin 能靠显式角色通过 action 后仍受原生 org/config/治理 guard 限制。单 repo collaborator/关联操作在 service mutation 前检查；org team 的权限/unit/includes-all、批量关联及删除造成授权关系改变时，计算变更前后所有受影响现有 repos，统一准入后写一个原生业务事务。非授权字段更新不检查 manage_access。目标集合超 1000 安全拒绝，不能分页执行一半。

企业微信生成团队同步、成员/身份同步、系统清理、自动新仓库初始化及既有迁移维护不是虚构人类 actor：实现必须逐一盘点调用者，设置包内私有 typed maintenance context，仅白名单固定调用点可用，记录具体 operation kind、repo IDs 和原生系统归因。nil actor、字符串 system、用户提供 header 不构成豁免；新未知 caller 默认拒绝并补受信适配。租借系统上下文执行用户可控授予请求禁止。维护特例不委派企业 API/UI 权限，成员变化仍影响下一次角色解析。

初始 branch 写入使用 Create/Generate 包内固定 typed marker，绑定真实 creator、当前 owner/default branch 与零 refs/branch 状态，强数据库 system audit 在首次 ref 写前提交。Pull mirror 只允许 SyncPullMirror 的锁内私有 typed intent：复核当前 mirror/repo/owner 与 IsMirror，在 fetch/prune/LFS/wiki 首写前独立提交 repository:mirror:sync 系统审计；未知 direct caller、伪 system 或目标改变拒绝。此为既有固定维护合同，不新增用户 action，迁移仍 shadow。

### 7. Evidence schema、seed、查询和 UI

增加 additive migration，实施时选下一可用编号，不改 v361。建议在 `enterprise_authz_decision` 追加 `decision_mode`（shadow/enforce）、`authorization_decision`（not_enforced/allow/deny/error/fallback）、`authorization_reason`、`execution_started`，并在关联审计白名单中记录同一语义。旧行 backfill 为 shadow/not_enforced，旧执行信息不可推断为新准入；旧快照/ID/关联/时间保留。当前 `native_outcome=unknown` 配合 execution_started=false 表示未执行，不新增与原生结果混淆的“native deny”；执行开始/终态在真实边界更新。

同一次准入 decision 集合与各关联 audit 原子保存，失败没有半套。副作用开始前持久化 allow，结束后更新 native outcome/stage；授权 deny/error 的执行未开始。只按同 observation ID 去重，不跨重试/目标复用 allow；复合 actions 共享 operation 但每 action 独立记录。后置更新可保留 unknown 并产生缺口，不用候选 allow 推断成功。保留 deleted repo 历史和现有清理周期。

CatalogVersion 升至 2；迁移只向内置 owner/platform-admin 补 `{}` allow manage_access，修订预检精确集合与内置 revision 合同，不覆盖其他 seed 或用户自定义复制快照，不自动绑定角色。内置 revision 继续 1，catalog_version 描述目录兼容演进；历史 definition revision=1 由 catalog_version=1 区分，不能回读现角色内容覆盖。

DTO/API 追加上述字段、mode/authorization 过滤与目录 enforce_supported，保留原字段、scope 校验和最大页100。旧 catalog v1 采用明确兼容白名单解码，新 v2 使用新目录；未知版本安全失败，不直接接受任意 JSON。`CandidateOnly` 保留为候选 evaluator 部分的语义，enforce 的真实授权由独立字段表达，诊断始终 candidate-only/safety_guards_evaluated=false，不把整条执行证据标作纯 shadow。

UI 只扩展原列表/筛选/详情的文本和状态；mode 与最终授权不从全局当前配置推断，不能让旧 shadow 行变成 enforce。mismatch 只在确有原生执行结果可比较的 shadow 上显示；授权直接拒绝显示未执行，allow+unknown 不显示成功。仅 `locale_en-US.json`，沿用后端展示合同/主题/键盘行为。不用客户端硬编码 action/权限或新增低权限入口。

替代方案：只把 mode 放日志无法保证受权历史解释；只修改 JSON 没正式 migration 会让旧行语义不确定；catalog 严格等于当前值会丢历史可读性；均不采用。

## Risks / Trade-offs

- [并集无法撤销已有原生 action] → 文档明确本次不是 deny 模型；不把条件角色或缺角色宣称能限制原生 code writer merge/Admin webhook。
- [部分候选 allow 仍被 native guard 拒绝] → 有意兼容边界，原生低权限角色不自动升级；明确正例必须同时满足原生权限。若未来需 action 取代 native 阈值，另起 proposal。
- [目录与 seed 升级影响旧二进制] → catalog v1/v2 安全读兼容；旧 foundation exact-seed 预检与新 seed 不兼容，禁止仅换回旧二进制带新 DB。
- [准入后业务失败/非 DB Git 副作用] → 保留真实失败与 unknown，不承诺授权/业务/审计三者一个事务，也不伪造回滚。
- [跨 service/internal hook/系统 caller 旁路] → 共享执行 guard、私有匹配 handle、逐 caller 白名单和真实 bypass 负例；observer owned 永不豁免执行。
- [fail-open/历史证据不可用] → 默认 true，安全告警与降级窗口；失去审计时明确缺口并回 shadow 排障，不宣布 enforce readiness。
- [昂贵 diff/大 org 批量] → 1s 总预算、路径1024/repo1000 上限；超限拒绝不静默放行，Linux/PostgreSQL 测真实时延与锁竞争。
- [前置 change main specs 缺失] → 本轮只写 delta；未来 sync/archive 按 foundation、UI、enforce 顺序，保留前置 verification，不回写其“当时已交付”语义。

## Migration Plan

1. 实施前核对 foundation/UI verification、全部实际 caller 与 mode×action 矩阵，补记录本次未验证项；不假设本机 macOS 能替代 Linux 服务端运行验收。
2. 备份数据库、匹配二进制/assets 与配置，记录原生权限/凭据/企微状态和证据 ID 边界。注册新 additive migration：证据列/历史标记、仅 owner/platform-admin seed，验证重复/中断恢复及 SQLite/PostgreSQL，无绑定/原生数据回填。
3. 部署完整新二进制+资源，保持 ENFORCE=false、callback=false；新版 shadow 添加 manage_access 观测和模式输出，针对本次高风险候选/native mismatch 做真实策略审查，不凭诊断模拟直接上线。
4. 显式治理现有差异：原 Admin secret/delete、保护 push、repo team 委派等可能需要安全授权角色；依赖已存在 native 可见性/操作权限，由有权管理员显式维护，不用 migration 猜测批量绑定。排查待接收 transfer actor 和 auto merge 当前资格。
5. 在独立 Linux 验证环境完成全部矩阵、故障和回退演练；首次启用 enforce 使用 fail-closed=true，实例统一配置重启，避免混跑 shadow/enforce 的节点形成旁路。监测拒绝原因、error/fallback、未知终态、时延及证据缺口。
6. 操作回退优先同版本 ENFORCE=false 转 shadow；必要时 ENABLED=false,ENFORCE=false 恢复原生路径，保留策略/历史。检查队列/当前 mutation 边界，不用回退取消或重放已提交业务。callback 仍关闭，LOGIN_ONLY 不改。
7. 二进制回退必须使用识别新 schema/seed 的兼容版本；确需旧 foundation 二进制则通过经验证的完整备份恢复 DB+资源+配置，并单独保全备份后新增历史。不得删除 manage_access seed、降 schema 或手工覆盖旧 migration 伪装兼容。演练不得接触生产状态。
8. 验证完成后记录真实命令/退出码、Linux/DB 环境、覆盖与限制，再按用户明确请求处理主 specs 同步/归档；本次 proposal 不执行上述部署步骤。

### 首次安装 seed 的获批补充

仅当 version 表不存在且数据库元信息确认没有任何表，首次安装在单一事务创建当前授权 schema、内置 seed 与当前 version。无有效 version 的已有/部分数据库拒绝并要求按备份恢复；已有库缺 seed 不自动修补，不复用旧 migration 作动态 seed。该补充已获用户批准，并由 SQLite/PostgreSQL 真实中断回滚/重跑验证。

### 仓库 runner 注册的获批机器凭据合同

仓库级 registration token 没有人类发行者身份字段。用户批准：注册准入在当前一致快照验证已认证 token 的 ID/原值、active、未删除、精确 repo 及 scope；只授予该仓库注册操作的 NativeOnly manage_ci，actor=0/source=system 且关联机器准入审计。不匹配企业角色、不借 token 创建者身份、不将 nil actor 或任意 system 字符串视为豁免。org/global registration token 不属于本 change 仓库 action 边界。token 无效/吊销/目标变更不可 fail-open，DB故障仍按固定执行分类处理。
