## Purpose

为企业 PR 提供一致、可解释的合并门禁，将当前合并授权、原生保护、审批、敏感路径与外部状态统一为可追溯的决策。门禁支持安全预览、实际写前再评估与有限 bypass，不替代凭据认证、原生 Git 守卫或外部扫描执行。

## ADDED Requirements

### Requirement: Merge gate has explicit independent rollout modes

系统 MUST 提供默认关闭的 merge gate 开关与独立 enforce 开关；门禁启用 MUST 要求企业授权启用及数据库审计可用，门禁 enforce MUST 另要求企业 action enforce。非法组合 MUST 拒绝启动。关闭门禁 MUST 不查询门禁规则或生成门禁决策，既有 action/feature/原生行为保持不变；shadow MUST 仅计算候选结果，不改变原有合并、force 或排队行为。门禁 enforce MUST 对明确拒绝、上下文/策略/证据故障 fail-closed，即使 action 的基础设施 fail-open 已启用。

#### Scenario: Invalid deployment configuration

- **WHEN** 门禁 enforce 开启但门禁或企业 action enforce 未开启，或审计/所需 schema/seed 不可用
- **THEN** 启动失败并给出安全原因，不运行部分门禁或自动修复生产策略

#### Scenario: Disabled and shadow preserve existing behavior

- **WHEN** 同一 PR 在门禁关闭和 shadow 下命中新的敏感路径或外部检查阻断
- **THEN** 关闭不读取门禁数据，shadow 仅产生候选解释，既有原生及企业 action/feature 实际结果不变

### Requirement: Unified evaluation distinguishes preview admission and execution

所有合并入口 MUST 使用同一门禁行为合同，返回有序、稳定的所有已确定通过项/阻断项与错误项，而非仅首个失败。决策 MUST 区分 `allow`、`deny`、`bypass`、`error`，以及预览、排队、写前准入和执行结果；`allow` MUST NOT 等价“已经合并”。输入 MUST 来自当前受信 PR/仓库/Git 状态、actor 和凭据，不接受客户端提交的权限、diff、审批或状态作为真相。预览 MUST NOT 创建实际 merge 成功证据或可复用执行许可。

#### Scenario: Multiple blockers are explainable

- **WHEN** PR 同时缺少审批、必选 status 与敏感路径批准
- **THEN** 同一评估返回三个可区分的稳定原因及其来源，不将缺失项或未知项展示为通过

#### Scenario: Diagnostic allow is not an execution ticket

- **WHEN** 客户端提交旧预览的 allow、evaluation ID 或伪造 head/status
- **THEN** 实际合并重新获取受信状态并评估，不按客户端结论执行

### Requirement: Mandatory safety guards cannot be bypassed

enforce MUST 同时满足当前活跃账号、仓库及 code/PR 可见性、凭据 scope/资源上限、原生 merge 准入和 `repo.merge_pull_request` action、PR 功能可用性。原生分支 merge whitelist、归档/只读限制、PR 已关闭或已合并、draft、Git 冲突/检查中、禁止的 merge style、签名守卫、未完成依赖和未解决 review conversation MUST 被检查且不可 bypass。所有仍未解决的原生 PR review conversation MUST 阻断，不受是否已有 branch protection 规则限制。企业角色或可信超管 MUST NOT 单独绕过这些条件。

#### Scenario: Bypass cannot repair an unsafe merge

- **WHEN** 具有 bypass action 的 actor 请求合并，但凭据只读、PR 功能 disabled、merge action 缺失、PR draft 或 Git 冲突
- **THEN** 拒绝合并，不写 Git ref 或 PR 合并状态，不删除分支或发送成功通知

#### Scenario: Unresolved conversation blocks unprotected branches

- **WHEN** 无分支保护规则的 PR 存在未解决 review conversation，其他条件满足
- **THEN** 普通、force 与 auto 实际合并均被阻断；讨论解决后才可重新评估通过

### Requirement: Native branch protection is preserved and explained

门禁 MUST 保留当前匹配的原生分支规则、required approvals、拒绝评审/官方 review request、CODEOWNERS、分支新鲜度、protected files、required scoped workflows 和 status checks 语义，不因重构而放宽原生普通合并要求。原生 CODEOWNERS 的配置开关、团队解析和 stale approval 行为 MUST 保留；企业敏感路径审批另按本规范的当前 head 严格规则处理。无法取得必要事实 MUST 为 error，不以默认空规则或 zero approvals 当作通过。

#### Scenario: Existing protected branch remains protected

- **WHEN** 企业敏感路径规则为空且原生保护要求两次审批或 CODEOWNERS
- **THEN** 未满足时门禁仍拒绝，并区分原生审批、CODEOWNERS、请求修改及 protected files 的原因

#### Scenario: Native guard read failure

- **WHEN** 加载分支保护、CODEOWNERS、评审或工作流要求失败
- **THEN** 返回安全 error，enforce 不合并，不伪造无保护分支或空必选列表

### Requirement: Required contexts consume current commit status without executing providers

门禁 MUST 合并原生有效 required contexts、有效 `feature.required_status_checks` 的 required contexts、六个外部 feature 的 required contexts 及命中敏感路径的 contexts，保留来源并去重。feature 和敏感路径 contexts MUST 精确匹配大小写，原生 pattern contexts MUST 保留现有匹配语义。六个外部 feature 为 enabled MUST 不自动变成 required；其 configured contexts 可被原生 required checks 或敏感路径规则显式引用为 blocking。disabled MUST 不新增该 feature 的强制检查，也 MUST NOT 撤销独立原生/路径要求。required feature 的有效 contexts 为空或 required-status 原生配置 pending MUST 阻断并报告配置未就绪。

所有要求 MUST 对当前 PR head SHA、base repository 的最新 status 判断。原生要求 MUST 保留 success/skipped 通过及 warning 失败语义；企业 feature/path 要求 MUST 仅接受 success，skipped MUST 作为已知未成功状态阻断；missing/pending/failure/error/未知状态 MUST 阻断，旧 SHA、其他仓库或历史 success MUST NOT 满足。无原生分支保护规则时企业 required checks MUST 仍生效。外部结果 MUST 通过现有认证授权的 commit status 接口接入，MUST NOT 运行扫描/AI、制造成功 status、自动创建 integration 或下发供应商 token。

#### Scenario: External check is missing or overwritten

- **WHEN** required `security/gitleaks` 没有当前 head 的 status，或最新 status 从 success 变成 failure
- **THEN** 普通与 auto merge 被阻断；历史 success 不兜底，显示 missing 或 failure

#### Scenario: Required context survives inheritance and absent branch protection

- **WHEN** org required AI review 指定 `ai/review`，repo 试图替换 contexts，且目标分支无原生保护
- **THEN** 有效上级 context 仍是必选，缺失/失败阻断实际合并，不因没有原生规则跳过

#### Scenario: Enabled is not required and empty required is not success

- **WHEN** 外部 feature 为 enabled 且无其他独立 requirement，或变为 required 但有效 context 为空
- **THEN** 前者不隐式阻断，后者报告配置未就绪且不能默认通过

#### Scenario: Skipped status preserves native compatibility only

- **WHEN** 当前 head 的同一 context 为 skipped，且同时被原生与企业 feature/path 要求引用
- **THEN** 原生要求按现有语义通过，企业要求仍阻断；最新 success 才满足企业要求

### Requirement: Protected path rules are cumulative and safely managed

系统 MUST 提供 global/org/repo 规则管理，规则包含稳定 ID、路径 glob、可选目标 branch glob、指定审批角色 ID、required contexts、启停与单调 revision。global、当前 owner org 和 repo 的启用规则 MUST 累加，每个命中规则均须满足；下级 MUST NOT 覆盖、关闭或编辑上级规则。个人仓库 MUST 跳过 org；仓库转移后 MUST 使用新 owner 上级规则，旧组织角色引用 MUST 不继续授权。缺失/越界的活动规则角色 MUST 导致可解释阻断或错误，不能静默略过。

原始规则读写 MUST 要求当前对应 scope 的管理 authority、适配 admin/org/repository 的凭据 scope；repo 写入 MUST 另要求 `repo.manage_sensitive_paths`。写入 MUST 拒绝未知/重复字段、非法模式、非法角色/作用域、secret/命令/URL 字段及超限输入。变更 MUST 使用 expected revision，规则与审计原子提交；相同语义的有效版本重试 MUST 幂等，旧 revision MUST 返回 409。删除 MUST 保留防 ABA 的版本墓碑与历史解释，活动引用角色的删除 MUST 返回 409。

#### Scenario: Lower scope cannot weaken an upper rule

- **WHEN** global 和 repo 各有一个命中规则，repo 管理员试图关闭 global 规则或只满足其中一个
- **THEN** 越权写入被拒绝，合并仍要求两个规则，不按最近层覆盖

#### Scenario: Atomic revision and audit protection

- **WHEN** 两个管理员使用同一 revision 更新规则，或变更审计持久化失败
- **THEN** 冲突写入返回 409，审计故障整体回滚；不存在丢失更新、删除重建 ABA 或部分成功记录

#### Scenario: Ownership and role deletion

- **WHEN** 仓库转移到新组织，或管理员删除被活动路径规则引用的角色
- **THEN** 新合并按新上级规则及角色可见性判断，旧组织角色不能满足审批；角色删除返回 409，要求先显式处理引用

### Requirement: Sensitive approvals cover complete trusted changes

路径匹配 MUST 使用当前可信 base/head 的完整 PR diff，包括新增、删除、rename/copy 两端路径和 CODEOWNERS 自身变化；路径截断、非法编码、缺失 Git 对象或无法完成匹配 MUST NOT 当作“未命中”。每个命中规则 MUST 要求其所有命中路径的 CODEOWNERS 有效批准，或至少一位当前匹配指定角色的 reviewer 有效批准；规则 checks MUST 另外满足，角色批准 MUST NOT 替代原生 CODEOWNERS 门禁。

企业敏感审批 MUST 使用当前 head 的最新非 dismissed、非 stale approve，reviewer 当前有效且有 code/PR 可见性，MUST NOT 接受 PR 作者自批或已退组/解绑的角色。CODEOWNERS MUST 从可信 base 策略读取；没有 owner 或唯一 owner 为作者 MUST NOT 令企业敏感规则自动通过。重命名角色名称 MUST 不改变稳定 ID 引用，`repo.manage_codeowners` action MUST NOT 被等同为指定角色身份。

#### Scenario: Rename cannot escape protection

- **WHEN** 敏感文件被移到非敏感路径，或从非敏感路径复制到敏感路径
- **THEN** 两端参与匹配，命中规则的审批和 checks 仍必须满足

#### Scenario: Stale self or revoked approval

- **WHEN** 敏感路径只有作者批准、旧 head 批准、被撤销的审批或 reviewer 已失去指定角色
- **THEN** 规则仍阻断，不复用旧权限或旧审批；新的有效独立审批才可满足

### Requirement: Bypass is explicit permissioned and narrowly scoped

enforce 下 force/bypass MUST 要求当前 `repo.merge_pull_request` 与独立 `repo.bypass_merge_gate`，同时满足原生 force/bypass 资格、有效凭据、非空规范化理由及显式选择的原因类别。理由 MUST 为有效 UTF-8、去首尾空白后 1–1024 字节、无控制字符，MUST NOT 执行或未经转义展示。仅 `required_approvals`、`rejected_review`、`official_review_request`、`codeowners_review`、`required_check`、`sensitive_path_approval`、`sensitive_path_check` 可被选为豁免类别；其他原因以及任何 error MUST NOT 豁免。native protected files、outdated branch、签名及前述 mandatory guards MUST 不可豁免。未选择的阻断 MUST 继续阻断，auto merge 的排队和执行 MUST 拒绝 bypass。

请求、理由、权限来源、豁免前后决策与实际豁免项 MUST 在副作用前持久化。存在未豁免项时 MUST 返回 deny；无实际阻断时 MUST 保持 allow 并记录 bypass 请求未消费，不虚构豁免。disabled/shadow MUST 保持旧 force 行为，并对缺少新理由/action 仅产生候选结论。

#### Scenario: Force without authority or reason

- **WHEN** 原生管理员只有 merge action、没有 bypass action，或 force 请求缺少理由/选择项
- **THEN** enforce 分别返回 403 或 422，不因原生管理员、旧 force 标志或旧会话直接跳过门禁

#### Scenario: Selected checks alone are bypassed

- **WHEN** actor 满足所有 bypass 前提，选择豁免 required_check，但同时缺少敏感路径批准
- **THEN** required_check 被标记为豁免，敏感批准仍阻断，最终 deny 且保留请求审计

#### Scenario: Auto merge cannot inherit bypass

- **WHEN** auto merge 排队请求携带 force、bypass 理由或类别，或旧队列试图执行 bypass
- **THEN** enforce 拒绝，不把 bypass 写成长期队列许可

### Requirement: Every actual merge revalidates at the write boundary

Web/API、shared service、auto worker MUST 在实际 Git ref 或 PR merged 状态 mutation 前重新读取 actor、凭据、当前 owner/PR/head/base、角色/feature/path rules、branch protection、reviews/conversations 与最新 statuses，在受保护准入边界重新评估和持久化证据。预览与排队之后的权限/策略/审批/状态变更 MUST 在下一次实际准入使用；head/base/ref 不符合已评估上下文 MUST 拒绝或重新评估，不更新错误分支。后续更新 MUST 不反向改写已完成准入快照，准入的时间切点 MUST 可解释。

auto 排队 MAY 等待审批/checks/讨论解决，但 MUST 已满足 actor、merge action、功能与原生排队资格，等待 MUST NOT 是 merge allow；执行时 MUST 满足全部非 bypass 条件。队列 MUST 与可信的原始凭据类型/非敏感引用和资源/scope 上限关联，不储存 bearer token；enforce MUST 拒绝未知历史 attribution，不仅凭 doer ID 扩权。PAT 排队执行 MUST 同时满足原 ceiling 与当前仍有效的 token/账号/权限；session 排队 MUST 按受权用户的后台委托重新验证当前账号/权限与原资源 ceiling。持久明确拒绝 MUST 不热循环，相关状态变化后才重试；每次尝试 MUST 有独立可关联的证据。

#### Scenario: Queue time allow becomes execution deny

- **WHEN** PR 排队后撤销 actor 权限、改 feature 为 disabled、移除审批或写入失败 status
- **THEN** 实际 worker 不合并，保存当前阻断原因；旧队列、旧 head 和旧 allow 不授权执行

#### Scenario: Direct service call cannot skip the gate

- **WHEN** 调用者绕过 Web/API 预检直接调用合并服务
- **THEN** 服务仍在写前执行同一门禁；deny/error 后无 Git、merged 状态、分支清理或成功通知副作用

#### Scenario: Scheduled credential is revoked or unattributed

- **WHEN** PAT 排队后被撤销/收窄 scope，或 enforce 下旧队列没有可证明的凭据归因
- **THEN** worker 拒绝实际合并并给出安全原因，不把裸 doer ID 当作无限权限；用户须以有效权限重新排队

### Requirement: Manual merge recognition is honest about already written Git state

手动标记与自动识别 MUST 在 PR 合并状态写入前使用同一策略来源、权限、敏感路径/审批/checks 合同并记录 `manual_recognition`，按已识别的原始 PR head、目标 base 和实际 merged commit 验证历史范围，不把合并后的零 diff 当作未触及敏感路径。识别 MUST 用可信的已合并关联事实替代“尚未合并的 Git 可合并性”检查，MUST NOT 因此跳过其他权限/治理条件。无法可靠确定范围或真实 pusher MUST fail-closed，不用仓库 Owner 代替未知 actor。用户主动标记的 bypass MUST 遵循独立权限/理由/清单，后台识别 MUST 不自动 bypass。

该路径 MUST 明示 Git ref 已经写入，MUST NOT 声称阻止或回滚先前的直接 push；直接 push 保持既有保护分支/receive 规则。本提案 MUST NOT 给所有直接 Git push 新增 PR 门禁或保证管理员本地手工合并一定被事前阻止。

#### Scenario: Already pushed but governance failed

- **WHEN** 后台识别到手工合并提交，但缺少检查或无法确认真实 pusher
- **THEN** 不写 PR merged 状态，记录识别阻断/错误与 Git 已存在事实，不伪造 Git push 被门禁拒绝

### Requirement: Evaluation evidence is durable bounded and outcome aware

实际准入/拒绝/error/bypass MUST 保存可关联的 evaluation：repo/PR/issue/actor/source、mode/phase、head/base/merged SHA、策略 schema/版本/摘要、结构化通过项/阻断/错误/豁免项、bypass 理由与 action 来源、实际准入及执行终态。快照 MUST 限定大小，不含 token、secret、代码内容或未经筛选的 status description/URL；超限 MUST 给出 error，不截断后 allow。拒绝证据 MUST 不随业务事务回滚而丢失。

enforce 的准入及强制审计 MUST 在首个业务副作用前原子持久化，故障 MUST 503 且不合并；Git 写入成功而终态更新失败 MUST 留下可对账的已准入记录，并报告终态 unknown/待对账，MUST NOT 将已发生的写入报告为“未执行”。重试/重启 MUST 保留历史与幂等阶段关联，不重复声称一次合并多次成功。执行快照封存后 MUST 不因策略更新、资源删除或角色重命名被覆盖。

#### Scenario: Admission audit failure blocks Git mutation

- **WHEN** allow 或 bypass 准入快照/审计无法提交
- **THEN** enforce 返回 503，不更新 Git ref 或 PR 合并状态；不能因 FAIL_CLOSED_ON_ERROR=false 放行

#### Scenario: Git success followed by terminal evidence failure

- **WHEN** Git 已合并但终态记录更新失败或进程重启
- **THEN** 原准入记录可恢复对账，展示 unknown/待对账而非假失败或假成功，不自动重做合并

### Requirement: Readers receive safe explanations not management snapshots

系统 MUST 提供当前 PR 门禁查询和 merge box 解释，检查认证、repo code/PR 可见性及凭据读 scope；不可见对象 MUST 保持防枚举响应。reader MUST 仅获得本 PR 的安全原因、检查状态、当前 SHA、mode、phase 和预览标记，不获得原始 global/org 规则、scope/role/binding ID、其他路径策略、完整历史或 bypass 自由文本。完整规则/历史快照 MUST 要求对应管理 authority。读预览 MUST 不持久化实际准入或成功审计。

业务原因 MUST 有服务端定义的稳定 code 与统一展示语义，未知/error MUST 展示为不可确定而非通过。merge/bypass 按钮与服务端权限 MUST 对齐，bypass 表单只展示可豁免类别；隐藏按钮 MUST NOT 代替服务端检查。无新增全量规则管理 UI；规则 CRUD 通过受权 API 交付。

#### Scenario: Reader sees blockers without raw upper policy

- **WHEN** 有 PR/code 读权限但无管理 authority 的用户查询或查看 PR
- **THEN** 获得该 PR 安全解释，原始策略/完整历史请求被拒绝，不泄露上级 ID、配置或理由全文

#### Scenario: Button state cannot authorize stale execution

- **WHEN** 页面显示可合并或 bypass 按钮后策略变化，或客户端绕过按钮提交
- **THEN** 服务端按当前权限与门禁重新检查，页面旧状态不提升授权

### Requirement: Authentication deployment and external execution boundaries remain unchanged

系统 MUST 保持企微唯一合法 Web 登录与 MFA 续接，MUST NOT 开放密码/注册/OpenID/Passkey/其他 OAuth/反代/SSPI 等旁路；SSH key、PAT/API token、Git HTTP token 的签发、认证、scope 与吊销 MUST 不变。callback MUST 保持关闭，合法登录刷新及完整定时同步 MUST 保持。服务端部署/验收 MUST 仅面向 Linux，不要求 Windows 服务端，不影响 Windows 客户端。MUST NOT 执行外部 scanner/AI、发放云 token、自动配置供应商或应用治理模板。

#### Scenario: Credentials and forbidden login regressions

- **WHEN** 开关门禁后测试合法企微/MFA、被禁止的 Web 登录，以及 SSH/PAT/Git HTTP token 的既有操作
- **THEN** 认证和 scope 结果不变，禁止入口仍拒绝；只有显式启用门禁后的 PR 合并治理结果可能收紧
