## Context

动机与用户确认的 bypass 边界见 `proposal.md`，验收合同见本 change 的两份 delta specs。已核实的基线：

- `services/pull/check.go:CheckPullMergeable` 先检查原生 merge 准入，manual 会提前返回，auto 排队可跳过未完成保护项，force 当前可整体跳过 `ErrNotReadyToMerge`。
- `services/pull/merge.go:CheckPullBranchProtections` 聚合 status、approvals、CODEOWNERS、outdated branch、protected files，但只返回首个失败；无原生 branch rule 时直接通过。
- `services/pull/merge_execution.go` 已有锁内 actor/PR 刷新和 `beginPullGitExecution`；真实 Git mutation 前的 `Admission` 是接线位置，不另造绕过现有 action/CODEOWNERS 写权限的执行通道。
- `models/pull/automerge.go` 的队列保存 DoerID 等业务参数，不保存原始凭据上限；`services/automerge` worker 当前重建 read/write=true 的观察上下文。门禁需要补齐持久 attribution，不能把它误称为现成的凭据再校验；排队与实际合并语义不同，也不能简单让所有等待项都拒绝排队。
- `services/pull/commit_status.go` 在 base repo 上按当前 head 查询最新 status，原生 contexts 支持 patterns 与 required scoped workflows；无 branch rule 时不返回原生要求。企业 contexts 因而要独立消费，不能只追加到原生 nil-rule 分支。
- `modules/enterpriseauthz/feature.go` 已有 13-key、上级首锁、required contexts 并集；外部 key 仍为 `policy_only`。当前 action catalog version 为 2；最新登记 migration 为 363，迁移后 DB version 为 364。实施时重新核对，不固定未来 migration 编号。
- `services/enterpriseauthz/management.go` 已区分 system/org/repo authority，企微环境不能仅凭 IsAdmin。main specs 尚无授权能力，前置 change 仍未归档；本轮不改写这些 change 的验证证据。

## Goals / Non-Goals

**Goals:**

- 用一个可测试的事实集和决策核心服务预览、排队、准入与识别，入口只负责受信 attribution、权限/隐私与错误映射。
- 保持 `cmd → routers → services → models → modules` 依赖方向；门禁核心不反向导入 pull service。
- 对策略版本、Git refs、证据和异步终态建立明确的一致性边界，避免“查询 allow = 执行已获准”。
- 敏感规则管理、默认角色、reader API 和 merge box 与后端权限闭环，明确没有规则管理 UI。

**Non-Goals:**

- 不重写 Git/PR/Issue 核心模型，不替换已有 action evaluator 或 branch protection。
- 不新增 scanner/AI runner、供应商认证协议、status 签名证明或发布模板；原生 status writer 的授权仍是外部结果信任边界。
- 不将直接 push 变成 PR merge，也不在事后识别时伪装能够撤销 Git 写入。
- 不扩大前序仅系统超管授权管理 UI 的 authority，不引入其他项目的 Flyway/OpenFGA/Keycloak 或 Python/Alembic 工作流。

## Decisions

### 1. 共享事实采集、纯决策与执行协调分离

选择 `modules/enterpriseauthz` 放类型/原因目录/规则规范化/纯评估；`models/enterpriseauthz` 放两表及 CAS/查询；`services/enterpriseauthz` 的专用 mergegate 文件放策略/actor/角色/feature 采集及证据服务。`services/pull` 的 adapter 负责 Git diff、原生 approvals/CODEOWNERS/status/signing/mergeability 等 pull 专属事实，调用纯核心，不让 authz service 导入 pull。

事实采集返回类型化值和 error，不能沿用“读失败返回 false，再误报缺审批”的 helper 结果；必要时为原生 helper 增加返回 error 的底层版本，保留旧调用兼容。先验证对象可见性，再采集安全事实；没有权限时不为收集完整原因读取隐藏资源。其余可安全获得的独立原因全部收集；必要事实未知时 error 优先于 deny，完整性不明不能输出 allow/bypass。

结果包含 `schema_version`、`mode`、`phase`、`candidate_decision`、`admission_decision`、`preview_only`、`facts_fingerprint`、head/base、checks/reasons、`bypass_requested`/`bypass_used` 与执行终态。阶段：preview、schedule、admission、manual_recognition；终态：not_started、started、success、failed、unknown。这些不是第五种授权决策。所有原因以 code/source/安全参数建模，排序按类别、来源、稳定 ID/context；用户展示不依赖调用顺序。

不选择在每个 router 增加判断：会漏 shared service、worker 与锁后状态；不选择让 authz 导入 pull：会制造循环依赖；不选择彻底替换原生检查：浅 fork 成本高且容易改变签名/merge-style 语义。

### 2. 独立开关、严格门禁错误语义

新增 `[enterprise.merge_gate] ENABLED=false, ENFORCE=false`，布尔值严格解析。enabled 要求 authz enabled；enforce 要求 gate enabled 与 authz enforce；任何启用模式要求 DB audit、两表、索引、action seed 与版本校验通过。

- gate disabled：完全保留当前行为，不查询/写 gate 数据；清理 live 规则引用例外，不清理历史证据。
- gate shadow：候选门禁不影响既有 action/feature enforce 或原生 force/排队；影子证据失败只安全记录，不阻断原有 merge。
- gate enforce：对本 gate 的 policy/context/evidence error 固定 fail-closed；不借用 `EnterpriseAuthz.FailClosedOnError=false`。即使前序 action 服务降级，gate 仍要求当前 merge action 和所有 mandatory guards 成功。

规则 CRUD 是安全管理操作：gate/authz enabled 才提供，shadow 也严格鉴权、CAS 和原子审计，不允许因 shadow 放松管理 authority。

独立开关避免升级即收紧既有 force；不把 feature grants 的外部 `policy_only` 改为“原生已执行”，新增 gate 消费状态是独立能力。

### 3. 敏感路径两表模型及生命周期

`enterprise_protected_path_rule`：ID；scope_type（存储 system 对应 API global）/scope_id；创建时 owner_id；path_pattern；可选 branch_pattern；required_role_id；required_check_contexts_json；enabled；deleted；revision；created_by/updated_by；created_unix/updated_unix。索引 scope_type/scope_id/deleted/enabled、required_role_id。删除标记禁用并递增 revision，ID 永不复用；不建策略层级覆盖关系。无默认规则 seed，路径建议留在 runbook 示例，后续模板独立管理。

每条规则要求一个 scope 可见的 role ID：system 规则只能引用 system role；org 可引用 system/本 org；repo 可引用 system/当前 owner org/本 repo 的有效 role。API 验证角色可见性不泄露越界对象；活动引用拒绝删除。转移后保留 repo ID 规则，旧 owner 限定的 repo 规则/角色引用不静默消失，也不继续授权：标为 owner/role unresolved 并阻断，要求新 owner 明确更新 revision。删除 repo/org 时同事务删除 live 下级规则，已有 evaluation/audit 留存；角色名更新不改 ID。

规则管理复用现有 scope 锁与当前 authority；update/delete 要 expected_revision，创建为 0，semantic no-op 保持 revision 和 audit 次数。mutation 与 audit 同事务，删除墓碑防 ABA。global/org/repo 并发操作按 system → org → repo → rule ID 排序；role 删除先取得同序 scope/reference 锁，防止查过引用后并发新增。

复用 `modules/glob.Compile(pattern, '/')`，不引入第二种敏感 glob 方言；branch 取短名、path 为仓库相对路径，严格拒绝越界/控制字符。配置 16 KiB、pattern 256 字节、contexts 64 个且单项 128 字节（遵循现有 context 校验），effective 活动规则最多 256 条；超限阻断，不静默忽略第 257 条。角色配置只存 ID，不存任意表达式或代码。

`enterprise_merge_gate_evaluation`：ID/operation_id/attempt_id/phase（唯一关联阶段）；repo_id/pull_id/issue_id/actor_id/scheduled_merge_id；source/mode；head_sha/base_sha/merged_sha；candidate/admission decision；reason_json/policy_snapshot_json/schema_version/facts_hash；bypass_requested/used/reason；execution_state/terminal_revision；created/updated time。索引 repo/pull/created、operation/attempt/phase、scheduled_merge_id、待对账 execution_state。schedule 快照内保存规范化 credential attribution（凭据类型、非敏感 ID/引用、原准入 scope/资源上限），不存 token。immutable 快照与 monotonic terminal CAS 分离在同表字段；终态封存，不用 upsert 覆盖旧策略。JSON 快照上限 64 KiB，完整 diff 上限复用 1024 paths，超限给出安全 error，不截断 allow。

不在 PR/Issue 新增外键/策略字段，不拿该表当缓存或长期许可。repo/pull/user 删除后历史 ID 与已封存快照保留，不再据此加载被删对象。默认不增加自动历史清理任务；留存与访问限制沿用企业审计规范。

### 4. 敏感审批用可信 base 策略与当前角色

adapter 在真实 merge lock 内取得 head/base/merge-base，完整读取 diff，rename/copy 的 old/new、删除与 CODEOWNERS 本身均参与。不能使用 UI 分页 diff、`ChangedProtectedFiles` 文本缓存或客户端 file list 代替完整路径。

各命中规则按 AND 累加；规则内部审批为 OR：全部命中路径的 CODEOWNERS 有批准，或至少一位指定 role 的 reviewer 当前有批准；contexts 另按 AND。CODEOWNERS 使用 base branch 可信版本，不能让 PR 先修改 CODEOWNERS 给自己审批。敏感规则不沿用原生“无 owner/仅作者即豁免”行为：无有效独立 owner 则必须指定 role 批准。原生 CODEOWNERS gate 单独评估，角色分支不能消除它。

企业敏感审批最新 approve 必须关联当前 head，非 stale/dismissed，reviewer 当前活跃且 code/PR 可见、非 PR 作者。指定 role 按稳定 ID 和当前 user/team/org 绑定、成员关系、生效作用域解析，不以角色名或 manage_codeowners action 猜身份。role 条件不代表此人可跳过 native review 准入。当前 head 新提交即需要重评敏感批准，原生 approvals/stale 配置则保持原语义。

未解决 conversation 从原生 review root/thread 的 resolution 状态计算，不统计普通 Issue 评论为未解决讨论；无 branch protection 也执行该企业门禁。草稿、open dependency 等属于 mandatory 状态，不能 force 忽略。

### 5. Context 来源与外部信任边界

必选集合为原生 `EffectiveRequiredContexts` + 有效 required-status feature contexts + 六个外部 required feature contexts + 命中路径 contexts。复用 feature resolver，不重新实现首锁/上级 required 并集；记录每个 context 的来源。native patterns 保持匹配语义且匹配缺失仍阻断；新增 feature/path contexts 精确匹配、大小写敏感，不因含 glob 字符扩成 pattern。

`enabled` 外部 feature 不强制运行；需要 blocking 时将具体 context 配入原生 required checks 或路径规则，不新增不明 `blocking` 字段。required 外部 feature/required-status 空 context 报 `required_context_unconfigured`，required-status native pending 报未就绪；required 与外部 catalog 的 native_available=false 不等同失败，gate_consumed/status 才描述实际状态。

查询只使用 base repo ID + 当前 head SHA 的 latest-per-context status（fork/AGit 同样规范化）。原生 success/skipped 通过且 warning 为失败，企业 feature/path 仅 success 通过（skipped 为已知失败）；missing/pending/failure/error/unknown 逐项报告；旧成功覆盖失败不可行。无 pb 时仍加载企业要求；原生 scope workflow 的 nil-rule 行为不在本轮偷偷改变。status description 和 URL 不用于授权判断，不放入 reader snapshot；若显示原生链接必须沿用 Actions unit 过滤、URL 安全策略。

外部身份保证限于现有 status API 的 authenticated writer 权限，并将 creator/status ID 放入受权审计。context 名不是 scanner 身份证明，有状态写权限的人可伪造同名状态；本轮不加供应商签名/issuer pinning，runbook 明确该风险和最小化 bot 凭据。不能宣称已验证扫描内容、全局强认证或外部任务成功。

### 6. Bypass action、有限类别与默认授权

升级 action catalog 到新版本（当前预计 3，实施时复核）。`repo.manage_sensitive_paths` 相关 code unit；`repo.bypass_merge_gate` 相关 code/PR；均 high-risk、mutating、可诊断、可审计。仅给内置 Owner/Platform Admin seed 默认权限；原生 Owner/当前可信系统管理 authority 可按现有原生映射获得对应权限，Admin 不默认获得，维护者/安全维护者仅能由有 authority 的管理员显式授予。自定义角色与旧历史 version 1/2 不重解释。

force 前提为 merge action + bypass action + 当前原生 `CanBypassBranchProtection`/无 pb 时的原生 admin 资格 + 凭据上限 + 理由 + 选择类别。Web/API 增加可选 `bypass_reason`、`bypass_categories`；旧 `force_merge` 保留，gate enforce 下无新字段为 422，shadow/disabled 旧请求不受影响。只许规范列出的七类；选择是精确类别，decision 快照保存实际命中项，不能泛化“跳过全部”。用户勾选 required_check 同时豁免该类所有来源项（包括上级 required），这是有审计的特权例外，不修改 grant 锁；sensitive_path_check 必须另选。

不可豁免 protected files、outdated branch、签名、draft、依赖/讨论、visibility/credential、merge action/feature、Git 可合并性及所有 error。签名/pre-receive 原生校验仍执行；hook context 只携带受信一次性本次准入关联，不接受客户端 evaluation ID。无 blocker 时 force 请求审计为 requested/not_used，保持 allow。auto 排队和执行禁止新 bypass，后台手动识别无理由来源不自动 bypass。

不选择借用 repo.merge 或原生管理员直接 force：无法独立撤销与审计；不选择所有检查不可豁免：不满足用户确认的有限 bypass 需求。

### 7. 写前准入、并发切点与终态对账

保持现有 PR global lock 和 Git execution admission，统一在 `Merge`/`MergedManually` 的真实写边界调用 adapter + gate；direct service 不能跳过。锁内刷新 actor、permission、PR/current owner、head/base、规则/feature/roles/native facts。策略读与 evaluation/audit 用一致 DB 准入事务；策略管理沿用同一 scope 锁顺序，使 admission 与策略变更有确定先后。变更后的下一次 admission 必须见到新版本。

原生 reviews/status/conversation 可并发更新且并非都受 PR lock 保护，不能仅因“持有 PR lock”声称全局冻结。最终 admission 使用一致事实快照并记录 facts hash、status/review IDs、policy revision 与准入时间切点；写前比较当前 head/base/Git refs 及关键事实 fingerprint，变化则重采集评估（最多两次，继续变化报 409 state_changed）。snapshot/final validation 是决策切点：之后的新状态不撤销已开始的一次执行，但下一次必须消费；测试证明旧预览/排队结果不能跨此切点使用，不承诺跨数据库与 Git 的分布式事务。

Git ref 更新必须使用与已评估 base/head 相符的预期 old ref，拒绝或重新评估并发 ref 改动；不能将检查前 base push 进其他 ref。重写 commit 的 signing/style 和原生 hook 继续校验；内部 merge push 不额外要求独立 protected-direct-push action，沿用现有受信 hook operation ticket 边界，但必须关联本次 gate admission。异常/超时/取消一律不制造 allow。

拒绝记录独立提交，不随业务 rollback 消失；enforce 准入 snapshot 与 audit 同事务成功后才调用 Git mutation。实际 Git 不属于 DB 事务：终态 CAS 更新、审计关联与现有 operation finish 合作，不把预检成功记为 merge 成功。crash/终态写失败保留 started/unknown，扩展现有启动/运维检查对账 Git refs、PR merged commit 与 operation ID；对账只修证据，不自动再次 push、不自动把不满足治理的 PR 标记 merged。失败路径的分支清理/通知/索引任务只在对应实际结果成立时触发。

### 8. Auto 排队与 manual 识别分阶段

schedule 阶段要求账号/凭据、原生可排队资格、merge action、PR feature 和不可排队结构性条件满足；reviews/status/讨论等待可存队列，但结果显示 waiting/not_admitted。队列业务写入与 schedule evaluation/attribution 在同一事务提交，记录 pull_auto_merge.ID，replace 生成新关联、取消使旧关联不再有效。worker 必须先查当前队列 ID 对应的可信 attribution；PAT 按非敏感 ID 复核仍存在、所属 actor/原资源、当前 scope，再和原 ceiling 取交集，不储存 bearer 或借裸 actor ID 提升为无限会话权限。session 排队视为当时受权用户委托后台执行，后续重新校验当前账号/authority/原资源 ceiling，不要求保留旧 session token。未知 synthetic 凭据来源或无可证明 attribution 的历史队列 fail-closed，并提示有权用户重新排队；shadow 可记录新 attribution，旧队列仍保持原行为。该关联放新增 evaluation 表，不扩 PR/Issue/原生 AutoMerge 模型。

related status/review/conversation/规则/feature 变化驱动重新评估；保持已有队列去重与退避，加入缺失触发源。新企业条件不满足时不取消成假成功，持久 action/feature deny 暂停并展示原因，不热循环；用户显式取消保持现有语义。

manual marker 和自动发现使用 `manual_recognition` phase。核实原始 PR head、可信目标分支和 actual merged commit，恢复 merge 前范围；不能用合并后 merge-base 的零 diff 掩盖敏感路径。该 phase 不再机械要求“尚未合并的 Git 可合并性”，而要求可证明已合并的关联事实，其他权限/治理条件不变。无法找真实 pusher 时 fail-closed，不 fallback Owner。后台识别不可 bypass；主动 marker 可在真实原生资格下显式提供理由/类别。识别被拒绝只是 PR 状态不更新，不能宣称先前 push 被阻止。

### 9. API、权限矩阵与展示

新增 API 统一放在既有 `/enterprise/authz` 管理族下，PR 查询采用路线图 `/enterprise/merge-gate/{index}`。所有新 API 在 gate/authz disabled 时 404。Swagger 必须描述身份/参数/缺权/状态冲突/存储错误，不信任 body 中 scope/owner/actor。

| 入口 | 路径（`/api/v1` 下） | 权限与凭据 | 默认/显式角色与前端 |
| --- | --- | --- | --- |
| global rules CRUD | `/admin/enterprise/authz/protected-path-rules[/{id}]` | 当前可信系统管理 authority；read/write:admin | system authority；无新规则 UI |
| org rules CRUD | `/orgs/{org}/enterprise/authz/protected-path-rules[/{id}]` | org owner/可信系统 authority；read/write:organization | 原生 authority；无新规则 UI |
| repo rules CRUD | `/repos/{owner}/{repo}/enterprise/authz/protected-path-rules[/{id}]` | 当前 repo 策略管理 authority；read/write:repository；写加 manage_sensitive_paths | Owner/可信超管默认，满足 authority 的显式授权者；无新规则 UI |
| PR gate preview | `/repos/{owner}/{repo}/enterprise/merge-gate/{index}` | 必须登录、code/PR reader、read:repository | 原生 reader；merge box safe reasons |
| PR evaluation history | `/repos/{owner}/{repo}/enterprise/merge-gate/{index}/evaluations[/{id}]` | repo 策略管理 authority 与 read:repository；只读本 repo/PR | 当前管理 authority；API-only |
| ordinary merge | 现有 Web/API merge | 原生 merge、write:repository、merge action、gate | 既有允许用户；merge button |
| force/manual bypass | 现有 merge 增量字段 | ordinary 前提 + native bypass + bypass action + 理由/清单 | Owner/可信超管默认、显式有权角色；bypass 表单 |

rules GET 分页返回 `X-Total-Count`，POST 创建 201，PATCH 更新 200，DELETE 墓碑 204；DELETE revision 用 query 参数避免删除请求 body 兼容问题。history 分页，ID 对 repo/PR 二次限定，不能凭 evaluation ID 访问他仓库。未知对象 404、未登录 401、缺权 403、非法参数 422、revision/state 冲突 409、基础设施/证据故障 503。gate preview 本身即使候选 deny/error 返回 200 的类型化结果；实际 merge mandatory 拒绝 403、治理未满足 409，保留原生 API v1 成功响应与既有签名/merge错误映射。

reader DTO 从当前 actor 的 preview 投影，只返回安全 code/state/source category/current SHA，明确 preview_only 和 mode。若 user 只读则反映其权限不足，不能拿 reader preview 为别人合并。raw 快照/上级配置/ID/自由文本 bypass 理由仅经 management authority 暴露；同一 repo 的 full snapshot 不应展开上级不相关策略。preview GET 不写 evaluation/success audit，不引入按查看频率膨胀的历史。

使用现有 Go template + 小范围 TS 更新 merge box，不引入新 UI 框架。服务端原因目录提供 code/message_key/tone，模板按 locale 翻译，JSON 可返回相同 descriptor；只改 `locale_en-US.json`，不写 JS 业务 label 映射。不确定/error 显示不可判定；关闭门禁保持旧页面，shadow 明示候选而非实际阻断。force 理由和分类表单须可键盘操作、文本转义、CSRF，提交时按钮态不替代后端复检。不增全局/组织/仓库规则编辑页是明确非目标，受权 API/runbook 已提供真实管理路径。

## Risks / Trade-offs

- [status writer 可伪造同名结果] → 明示原生信任边界，bot 最小 scope、保护 token、记录 status creator，不宣称供应商认证或扫描内容验证。
- [强制审批/checks、空配置和 owner 转移导致阻断] → 先 shadow 排查；reason 区分未配置/未就绪/失效角色；规则 API/CAS 与独立 bypass 作显式恢复，不自动改 grant。
- [DB/Git 没有原子事务] → 写前强制证据、ref 预期值、独立终态与重启对账；不把 unknown 变假成功，不重推。
- [原生 boolean helper 隐藏读取故障] → 只对门禁必要 helper 增加 typed error 返回及回归测试，不重写整个 review 模型。
- [增加规则/全 diff 成本] → 单次准入批量读取 contexts/reviews/roles，遵循有界完整性；preview 的请求内缓存不得跨写前准入。
- [旧 API force 客户端不提供新理由] → 仅 gate enforce 收紧，文档及 Swagger 标明迁移字段，disabled/shadow 回归旧行为。
- [前置 delta 尚未成为主 specs] → 不在本次暗中同步/归档；之后先按依赖顺序 sync，再合并本 delta，不丢失 feature grants 已实现语义。

## Migration Plan

1. apply 前核实依赖实现与 verification、当前 migration/catalog；Linux 环境先完成备份，在 SQLite/PostgreSQL 隔离副本验证 additive 两表/index/Owner-Platform Admin seed、重复迁移与历史 version 1/2 DTO。不更新旧 migration 或 version 表来伪造升级。
2. 部署 gate disabled 的完整实现，schema 迁移不自动启用门禁；保留 feature/authz 配置、callback 关闭。全入口关闭模式回归通过再启用 shadow，明确原有 authz enforce 不因此关闭。
3. 管理员通过受权 API 配置敏感规则与有效 feature contexts，验证角色可见性、空 contexts/native pending 与外部 status writer；不自动 seed 推荐路径或供应商 integration。
4. shadow 观察普通、fork/AGit、auto、force、manual 的候选原因/终态和旧队列 attribution；故障、并发、重启对账、reader 隔离通过后显式启用 gate enforce。
5. 上线验收记录配置指纹、Linux/SQLite/PostgreSQL 命令和外部 status 合同证据，逐入口确认 reject 前零业务副作用与 bypass 审计；不将本地 macOS 测试当 Linux 服务端验收。
6. 回退优先 gate enforce=false（仍 shadow）或 gate disabled，记录管理变更与影响；这撤销新增治理强阻断，必须明确审批和风险。保留两表/历史、新 binary 的 additive schema；二进制降级只从完整备份恢复，禁止修改 DB version、删除快照或重写迁移。直接 push 的现有 protection/action 守卫不随 gate 回退关闭。
