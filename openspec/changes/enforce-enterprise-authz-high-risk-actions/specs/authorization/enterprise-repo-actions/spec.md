## RENAMED Requirements

- FROM: `### Requirement: Enterprise authorization has disabled and shadow modes only`
- TO: `### Requirement: Enterprise authorization supports disabled shadow and high-risk enforce modes`

## MODIFIED Requirements

### Requirement: Enterprise authorization supports disabled shadow and high-risk enforce modes

系统 MUST 提供 `[enterprise.authz]` 配置 `ENABLED=false`、`ENFORCE=false`、`FAIL_CLOSED_ON_ERROR=true`。`ENABLED=false,ENFORCE=false` MUST 为 disabled；`ENABLED=true,ENFORCE=false` MUST 为 shadow；`ENABLED=true,ENFORCE=true` MUST 仅对本规范列明的高风险 action enforce，其他 action 继续 shadow。`ENABLED=false,ENFORCE=true` 与非法布尔值 MUST 拒绝配置加载。企业授权启用时 MUST 要求数据库审计与对应 schema/内置角色可用，不自动修复或静默降级启动。

#### Scenario: Disabled mode does not evaluate or persist decisions

- **WHEN** `ENABLED=false` 且 `ENFORCE=false`，用户执行原有 repo 操作
- **THEN** 系统不查询企业角色、不运行 evaluator、不写企业决策，原生认证、权限、响应和副作用保持不变；仅删除 user/team/org/repo 时允许同事务清理 live 策略引用，不删除留存决策

#### Scenario: Invalid mode combinations are rejected

- **WHEN** `ENABLED=false,ENFORCE=true` 或任一布尔配置非法
- **THEN** 系统拒绝配置加载并报告稳定安全原因，不静默进入 enforce 或 shadow

#### Scenario: Shadow requires audit recording

- **WHEN** `ENABLED=true,ENFORCE=false`，但数据库审计未启用
- **THEN** 启动预检拒绝该配置并说明需启用数据库审计，不改动已有权限或凭据

#### Scenario: Enforcement requires complete readiness

- **WHEN** `ENABLED=true,ENFORCE=true`，但所需决策存储、内置 seed 或审计存储缺失
- **THEN** 启动失败；FAIL_CLOSED_ON_ERROR=false 也不能绕过预检，不能运行部分 enforce

### Requirement: Repository actions use a validated stable vocabulary

系统 MUST 注册 `repo.view_metadata`、`repo.read_code`、`repo.clone`、`repo.create_branch`、`repo.push_branch`、`repo.push_protected_branch`、`repo.create_pull_request`、`repo.review_pull_request`、`repo.merge_pull_request`、`repo.manage_branch_protection`、`repo.manage_codeowners`、`repo.manage_webhook`、`repo.manage_ci`、`repo.manage_secret`、`repo.manage_feature_grant`、`repo.migrate`、`repo.transfer`、`repo.archive`、`repo.delete`、`repo.manage_access`。每个 action MUST 有稳定 key、说明、相关 unit、风险和适用上下文；目录 MUST 明示 enforce 支持范围。管理角色写入 MUST 拒绝未知 action 或非 `allow` effect。`repo.manage_access` MUST 只表示原生 collaborator/team 仓库授权变更，MUST NOT 表示企业角色/绑定管理或 feature grant 管理。

#### Scenario: Unknown action is rejected without partial writes

- **WHEN** 创建或更新角色的权限集包含拼写错误、未知 action 或 `deny` effect
- **THEN** 系统返回 422，不保存部分角色或权限，不将未知 action 当作 allow

#### Scenario: Action catalog does not imply a feature implementation

- **WHEN** 查询 `repo.manage_feature_grant` 的目录或进行 action 诊断
- **THEN** 系统可以表达 action 授权，但不因此创建 feature grant、开启功能或修改 repo unit；其仍为仅目录/诊断，不进入 enforce 集

#### Scenario: Access management is independently grantable

- **WHEN** 有权管理员定义仅包含 `repo.manage_access` 的自定义角色
- **THEN** catalog/角色校验/诊断使用同一 action；它不自动授予 secret、feature grant、企业角色管理 API 或系统超管 UI authority

### Requirement: Native repository permissions map to default actions without replacing them

系统 MUST 基于调用者当前凭据约束下的原生 repo 与 unit 权限映射默认 action，MUST 区分 Read/Write/Admin/Owner，MUST NOT 只依赖最高 AccessMode 忽略 code/PR unit。Read + code read 映射读代码和 clone；Write + code write 映射普通分支动作；PR 创建需要 code read 和 PR write，review 需要 PR write，merge 需要 code write 和 PR read；Admin 映射保护规则、CODEOWNERS、webhook 和 CI 管理；Owner 映射全部 repo action，但仍受资源/unit 前提约束。较低原生权限 MUST NOT 自动获得保护分支直推及 Owner 管理动作；新增 `repo.manage_access` 的原生默认映射 MUST 仅属于 Owner，Admin 必须另有显式匹配角色方可通过该企业 action 检查。内置 Owner/Platform Admin MUST 增加 manage_access；其他内置角色及复制出的既有自定义角色 MUST NOT 被隐式扩权。角色 allow 与原生映射按并集合成，MUST NOT 替代实际操作的原生权限及安全检查，也不提供 explicit deny。

#### Scenario: Code-hidden team does not gain clone from repository mode

- **WHEN** 用户的仓库最高权限为 Write，但 code unit 不可读，PR unit 可写
- **THEN** 原生 action 集不包含 `repo.read_code`、`repo.clone` 或代码写动作，决策说明 unit 不满足

#### Scenario: Native administrator is not conflated with owner

- **WHEN** 用户只有原生 Admin 且没有匹配的企业角色
- **THEN** 映射可包含管理分支保护和 webhook，但不自动包含 secret、feature grant、transfer、archive、delete、manage_access 或保护分支直推

#### Scenario: Credential-scoped permissions are preserved

- **WHEN** actor 使用受限 PAT、Actions task token 或 deploy key 进入既有仓库入口
- **THEN** 评估使用该凭据实际允许的资源/unit/context；不会通过裸 user ID 加载更宽权限或把 synthetic actor 当作普通用户命中企业绑定

#### Scenario: Existing native allowances are not revoked by an unrelated role

- **WHEN** 原生 code writer 可 merge，并绑定了缺少 merge 的角色，或其一个带条件角色未匹配
- **THEN** 原生映射仍可贡献 merge action；角色缺权不是 explicit deny，系统不宣称此模型能撤销原生既有 capability

### Requirement: Shadow evidence is queryable auditable and bounded

每次已安全解析且可评估的观测 MUST 保存决策记录与对应审计关联，包括本地 actor/repo ID、action、来源、request/operation ID、candidate decision、reason、missing actions、native outcome、策略版本/权限快照和时间。重试去重 MUST 仅针对同一 observation ID，不能合并不同操作。策略变更审计 MUST 与变更原子提交；shadow 证据 MUST 与业务事务隔离。决策查询 MUST 支持受权范围内分页及 actor/repo/action/decision/time 过滤，并与审计保留期限一致地清理。新证据 MUST 另存 mode 与实际授权结果，包括 enforce allow/deny/error/fallback；candidate 结果 MUST NOT 被重命名为原生结果。旧证据 MUST 明确为 shadow，旧 catalog 快照 MUST 保持可读；查询 authority 和留存边界 MUST 不扩大。

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

#### Scenario: Enforced denial is not a native permission mismatch

- **WHEN** 原生 Admin 可执行 delete，但 enforce 因缺少 `repo.delete` 拒绝
- **THEN** 保存候选 deny、实际企业授权 deny、拒绝阶段及未执行标识，不把企业拒绝伪造为已运行的原生拒绝或 shadow mismatch

### Requirement: Web and protocol authentication compatibility is unchanged

企业微信 MUST 只负责既有 Web 登录和外部身份，本地 Gitea user MUST 继续作为 repo 权限、团队、审计与凭据归属主体。系统 MUST NOT 新增本地密码、注册、OpenID、Passkey、其他 OAuth、反代或 SSPI Web 登录旁路。SSH key、PAT/API token、Git HTTP token 的创建、认证、scope、吊销和账号状态 MUST 保持既有机制，MUST NOT 新增企业微信 OAuth 校验或额外撤销凭据。disabled/shadow 的原生 action 结果 MUST 保持既有行为；enforce 下只有本规范的高风险 action 授权结果允许收紧，低风险动作及未列入 enforce 的 migrate MUST 保持原生结果。受限 Actions/deploy actor MUST 保持 NativeOnly，不匹配人类角色。服务端 MUST 仅部署/验收 Linux，callback MUST 保持关闭。

#### Scenario: Forbidden Web sign-in paths remain forbidden

- **WHEN** 企业微信 LOGIN_ONLY 启用，尝试既有被禁止的 Web 登录路径
- **THEN** 系统按原有规则拒绝，企业角色或 authz 开关不生成 Web session，也不改变合法企微及其 MFA 续接

#### Scenario: Protocol credentials keep native behavior in both modes

- **WHEN** 正常、禁用或受限用户使用 SSH/PAT/Git HTTP token，在 disabled 或 shadow 中访问仓库或触发既有拒绝
- **THEN** 认证、scope、吊销及请求结果与变更前一致，仅 shadow 可增加安全观测，不调用企业微信 OAuth、不修改凭据

#### Scenario: Enforcement changes authorization rather than authentication

- **WHEN** 有效 SSH/PAT/Git HTTP 凭据通过认证但缺少保护分支 action
- **THEN** 认证机制与凭据不变，具体写操作被安全拒绝；read-only token/deploy key 仍先受原生限制，Owner/Platform Admin 角色不能把其变为 write 凭据

## ADDED Requirements

### Requirement: High-risk actions are checked before product side effects

enforce MUST 在实际写边界校验以下 action：merge、push_protected_branch、manage_branch_protection、manage_codeowners、manage_webhook、manage_secret、manage_ci、manage_access、transfer、archive、delete。系统 MUST 同时满足当前 actor/凭据的原生准入、安全守卫与企业 action allow，MUST NOT 只在路由/按钮或事后 observation 中检查。原生 Owner 与可信超管 MUST 保持其原生 action 能力并被审计，超管资格 MUST 使用当前可信 authority，MUST NOT 仅信任会话旧值或 IsAdmin 标记。不可见/不存在资源 MUST 保持原生隐私响应，MUST NOT 为补证据读取越权对象；可见资源的企业缺权 MUST 返回 Web/API 403 与安全固定原因。allow MUST 不代表完整 merge gate 通过。

#### Scenario: Native permission alone is insufficient for an owner-only action

- **WHEN** 原生 Admin 可以调用 repo secret/delete 操作，但没有对应原生 action 映射或匹配企业角色
- **THEN** enforce 返回 403，无 secret/删除副作用；同请求在 disabled/shadow 仍执行原生行为

#### Scenario: Explicit grant does not elevate the native operating authority

- **WHEN** Admin 获得限定 repo 的 delete action，或原生 reader 获得同一 action
- **THEN** 前者只有同时满足原生 danger-zone/治理前提时才允许；后者不能靠角色获得原生 Admin/Owner，不因候选 allow 执行删除

#### Scenario: Default owner and current enterprise super administrator remain operable

- **WHEN** 原生 Owner 或当前有效、已绑定的企微超管持有效写凭据执行其原生允许的高风险动作
- **THEN** 默认 action 检查允许，原生动作特定守卫继续执行并保存真实证据；被撤销超管 authority 的旧会话不享有该路径

### Requirement: Merge enforcement includes delayed force and manual paths

merge MUST 覆盖 Web/API、普通/force/manual 及 auto merge 的实际执行路径。排队 MAY 保存发起人，但 MUST NOT 保存可在未来复用的 allow；后台执行 MUST 重新读取当前 actor、角色/成员、repo/凭据约束并检查 merge action。force/manual MUST NOT 绕过新增 action 检查，既有分支保护、review、checks、SHA/锁与原生 force 语义 MUST 保留。仅记录手动合并也 MUST 在状态/通知更新前检查。若最终写入修改 CODEOWNERS，MUST 同时检查 manage_codeowners；合并造成的目标分支写入 MUST NOT 被误当作独立保护分支直推。

#### Scenario: Queued merge loses its grant before execution

- **WHEN** auto merge 排队后 actor 的原生 code 写权限或有效成员资格被撤销，执行时没有满足原生准入及 merge action 的当前授权
- **THEN** 不合并、不发送合并成功通知，记录当前拒绝原因而非排队时的旧 allow

#### Scenario: Force permission and action allowance are independently required

- **WHEN** actor 在普通/force 两条入口执行相同目标的 merge
- **THEN** 两条路径均执行当前 merge action 检查；force 仍要求原生 force 资格，action allow 不额外放宽检查，旧资格或旧候选结果不能作为 bypass

#### Scenario: A merge modifies CODEOWNERS

- **WHEN** PR 最终合并差异包含新增、修改、重命名或删除有效 CODEOWNERS 文件
- **THEN** 要求 merge 与 manage_codeowners 均 allow，缺任何一个均在 ref 或 PR 状态副作用前拒绝

### Requirement: Protected pushes and policy files cannot bypass enforcement

保护分支写入 MUST 覆盖 Git HTTP/SSH receive、多 ref 创建/更新/删除、Web/API 分支及文件写入、patch/cherry-pick/revert、PR 分支更新和 fork sync 等共享写路径。CODEOWNERS 新增/修改/删除及重命名两端 MUST 在任意分支写入及合并的真实 diff 上触发 manage_codeowners。递归删除、binary 或不完整路径不能跳过识别；所需上下文无法安全完成时 MUST 拒绝，不因 fail-open 放宽。相同逻辑操作允许去重证据，但 MUST NOT 复用旧 allow 作为跨操作授权。tag/wiki/AGit PR 创建 MUST 不伪造保护分支直推；Git 拒绝 MUST 传递安全原因，MUST NOT 要求 Git 客户端显示 HTTP 403。

#### Scenario: One receive includes an unauthorized protected ref

- **WHEN** 一次 receive 同时更新普通分支与缺少 action 的保护分支
- **THEN** pre-receive 在 ref 写入前拒绝该 receive，不留下已更新的部分 refs；每个被检查目标都有独立可关联结果

#### Scenario: Rename or deletion targets a policy file

- **WHEN** Web/API editor、SSH/Git HTTP push 或 merge 重命名/删除有效 CODEOWNERS，或递归删除其父目录
- **THEN** 使用完整实际差异检查 manage_codeowners；普通分支 write action 不足以放行，不能只检查请求中的新文件名

#### Scenario: Observation ownership is not execution authority

- **WHEN** 内部 push 标记观察 owned、内部 hook early-return、ticket 过期/伪造或策略在原观测后改变
- **THEN** 不把 observation/ticket 作为 allow；内部写入必须已有匹配实际目标的执行 guard，外部 receive 必须当次重新检查，缺受信上下文安全拒绝

### Requirement: Management mutations require all applicable repository actions

branch protection 的 CRUD/优先级/敏感文件规则 MUST 检查 manage_branch_protection；required checks 的有效变更 MUST 额外检查 manage_ci。repo webhook CRUD、secret 写入/删除、CI unit/token permissions/variables/runner 管理/workflow enable-disable MUST 检查对应 action。组织/用户/系统 scope 的共享 helper MUST NOT 被误作 repo action；secret 值读取和 webhook 投递/test/replay、workflow dispatch/run/cancel MUST NOT 被伪造为本规范管理 mutation。一个请求包含多个高风险变化时 MUST 在首个业务副作用前检查所有所需 action；不得先写 CI 再因 archive 缺权返回 403。

#### Scenario: Required checks produce two action admissions

- **WHEN** 当前受权 actor 修改保护规则的 required checks
- **THEN** 同一操作对 manage_branch_protection 和 manage_ci 均建立准入证据，只有二者及原生 guard 都通过才提交；不宣称仅删除角色中的 manage_ci 就能撤销原生 Admin 已有的 CI capability

#### Scenario: Compound repository edit is denied without partial writes

- **WHEN** 一个 API Edit 同时变更 CI 与 archive，而 archive action 缺失
- **THEN** 首个更新前拒绝，原 CI/archive 状态均不变，各 action 结果使用同一操作关联

### Requirement: Native access delegation uses a dedicated guarded action

原生 collaborator 增删/权限变更、team-repo 关联增删与影响仓库授权的 team 权限/unit/includes-all 变更及 team 删除 MUST 在每个受影响现有 repo 检查 manage_access；批量修改 MUST 在提交前完成全部检查，缺权不能部分授权。原生组织/team/企微受管理团队限制 MUST 保留，MUST NOT 以角色允许改写自动生成来源。普通团队成员维护/目录同步不是本次新 action 产品入口；由其改变可用角色成员的效果 MUST 在后续 action 检查中读取当前状态。正常企业角色管理继续使用原管理 authority，MUST NOT 由 manage_access 或 Platform Admin 角色自行取得。

#### Scenario: Repository administrator delegates access without a grant

- **WHEN** 原生 Admin 可新增 collaborator 或关联 team，但没有 manage_access
- **THEN** enforce 返回 403，access/collaboration/team_repo 及相应通知无变更；显式 action allow 仍要满足原生 owner/组织配置/团队治理守卫

#### Scenario: Team-wide access change includes a denied repository

- **WHEN** 用户修改 team 的仓库权限或 includes-all，影响多个 repo，其中一个缺少 manage_access
- **THEN** 整次授权变更拒绝，无部分 team units/关联/access 重算提交，不能通过 org 入口绕过 repo enforcement

### Requirement: Lifecycle actions preserve actor and ownership boundaries

transfer 的发起/接收/拒绝/取消 MUST 对实际当前执行人及旧 owner 资源检查 transfer；archive/unarchive MUST 检查 archive；delete MUST 在对象/磁盘删除及通知前检查 delete。转移接收 MUST NOT 以最初申请人替代当前 actor，MUST 重新检查目标 owner、当前政策和接收资格。转移后旧 scope_owner_id 绑定 MUST 保持失效，决策及审计 MUST 保留旧 owner 快照；删除后的历史 MUST 保留。非用户维护/同步/清理入口 MUST 有受信的具体来源和审计边界，MUST NOT 仅因 source=system 或 actor=nil 绕过检查。

#### Scenario: Transfer receiver has no current action

- **WHEN** 接收者符合原生接收资格，但没有当前 repo 的 transfer action
- **THEN** 拒绝接收，owner/team/access 不改变；申请人的旧 allow 不给接收者扩权

#### Scenario: Delete removes live resources but not history

- **WHEN** 当前 actor 同时通过 delete action 与原生删除确认/治理检查，删除成功
- **THEN** live 策略引用按既有方式清理，保留删除前 ID/owner 与执行证据供受权查询，不回读已删除资源解释结果

### Requirement: Infrastructure errors have explicit safe enforcement semantics

enforce 的缺 action、条件不匹配/unresolved、原生 guard deny、无效身份/凭据/受信上下文 MUST 拒绝，MUST NOT 被 `FAIL_CLOSED_ON_ERROR=false` 放行。可恢复的策略读取、预算耗尽、决策/审计持久化基础设施错误在 `true` 时 MUST 在业务副作用前安全拒绝，Web/API 返回 503；在显式 `false` 时 MUST 标记 fallback 并仅继续原生授权路径。缺上下文/路径集合不完整、客户端取消 MUST NOT 作为可 fail-open 的基础设施错误。enforce allow 的决策与关联审计 MUST 在副作用前原子持久化；证据无法保存时 MUST 无伪造成功并输出有界安全日志/指标。副作用已经完成后终态更新故障 MUST NOT 返回可误导客户端重试的授权失败或宣称业务回滚。

#### Scenario: Explicit denial is unchanged by fail-open

- **WHEN** evaluator 返回 missing_action 或 condition_unresolved，FAIL_CLOSED_ON_ERROR=false
- **THEN** 返回 403 或安全 Git 拒绝，无业务副作用，不标记基础设施 fallback

#### Scenario: Evaluator or admission evidence fails in default mode

- **WHEN** enforce 且 FAIL_CLOSED_ON_ERROR=true，当前策略读取或前置 decision/audit 写入失败/超时
- **THEN** Web/API 安全 503 或 Git 安全拒绝，无 mutation；可保存时保留 error，否则报告证据缺口，不把 error 当作普通 deny

#### Scenario: Explicit operational fallback never uses stale or elevated grants

- **WHEN** FAIL_CLOSED_ON_ERROR=false 且仅发生允许降级的授权基础设施故障
- **THEN** 原生认证/权限/治理/保护规则完整决定结果，角色不扩权；证据可用时记录 fallback，全部不可用时仅有安全告警/指标，不能承诺不存在的审计行

#### Scenario: Final evidence fails after a successful mutation

- **WHEN** 前置授权证据已提交，真实业务成功，但终态更新失败
- **THEN** 保留授权 allow 与未确认终态、报告缺口，不把 allow/unknown 显示为 success，不用错误响应诱发非幂等操作重试

### Requirement: Enforcement uses current policy and bounded trusted context

高风险执行 MUST 使用当前可信 actor、repo owner、原生凭据上限、角色 revision、绑定与成员一致快照，MUST NOT 跨请求缓存 allow。长任务、排队和跨进程写入 MUST 在实际执行边界重新检查；branch/head/base/owner/动作意图发生变化时 MUST 重新解析，不把旧决定用于新目标。执行检查 MUST 有限时与有界资源/路径集合，大小超限不能截断后当完整输入。与动作执行发生并发时 MUST 有明确的授权准入线性化边界：在准入前已提交的撤销必须生效，准入后进行中的动作不承诺即时取消；多个必需 action MUST 使用一致前提。

#### Scenario: Policy changes before the write boundary

- **WHEN** 表单/请求早期 allow 后角色被撤销，或 repo 已转移/目标 branch 与 SHA 已变更
- **THEN** 实际写边界重新检查当前目标及政策；没有其他 action 来源时拒绝，不能使用旧 session、诊断或 request ticket 放行

#### Scenario: Oversized context is not silently accepted

- **WHEN** 实际 diff/批量目标超过安全上限或权限检查预算耗尽
- **THEN** 超限上下文安全拒绝，基础设施预算错误按配置处理；不截取首项/首批当作完整集，不启动无界后台授权

### Requirement: Repository runner registration uses a narrowly scoped machine credential

仓库级 runner registration token 的注册执行 MUST 验证已认证 token 在当前权限快照中的 ID、原值、active/未删除与精确 repo scope。系统 MUST 仅将该机器凭据映射为该仓库注册操作的 NativeOnly `repo.manage_ci`，以 actor=0/source=system 保存前置准入决策与关联机器审计；MUST NOT 读取人类企业角色、借用 token 创建者身份，或把一般 nil actor/system 字符串作为豁免。org/global token MUST 保留非 repo 的原生注册边界。无效、吊销或目标变化 MUST 安全拒绝，MUST NOT fail-open。

#### Scenario: Repository registration is scoped and current

- **WHEN** 已通过原生认证的仓库级 registration token 注册 runner
- **THEN** 系统重新读取当前 token/scope，并仅对该仓库注册建立 NativeOnly manage_ci 准入和机器审计，首个 CreateRunner 副作用前完成证据

#### Scenario: Revoked or forged machine context is denied

- **WHEN** token 被吊销、scope 改变、原值不符，或普通调用者仅提供 nil actor/system 来源
- **THEN** 系统拒绝且无 runner 写入，不从人类角色或发行者身份恢复权限
