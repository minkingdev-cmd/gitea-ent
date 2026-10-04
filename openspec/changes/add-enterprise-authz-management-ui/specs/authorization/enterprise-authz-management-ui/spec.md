## Purpose

为企业授权基础提供完整的 Gitea 内置可视化维护能力，让当前可信系统超级管理员在同一站点管理入口维护系统、组织和仓库策略并解释真实 shadow 记录，同时不开放普通 owner/admin 的 UI 权限、不改变原生认证及候选授权边界。

## ADDED Requirements

### Requirement: Every UI surface is restricted to current system super administrators

系统 MUST 仅向当前可信系统超级管理员提供企业授权 UI，包括菜单、页面、角色与绑定写入、诊断、历史详情、作用域/主体搜索及异步请求。超级管理员 MUST 沿用既有系统管理 authority：企微启用时须为有效原生管理员且具有当前企业应用 active、已绑定管理 authority；企微关闭时沿用有效原生站点管理员，不增加本地超管选择器或企微启用时的回退。系统 MUST 每请求检查当前账号状态与 authority，MUST NOT 仅靠菜单隐藏、缓存 session 管理员标志或企业 Owner/Platform Admin 角色授权。

#### Scenario: Trusted super administrator opens the management workspace

- **WHEN** 有合法 Web session 的当前可信系统超管访问企业授权管理页
- **THEN** 系统提供 system/org/repo 范围内完整维护、诊断和查询能力

#### Scenario: Other native owners or enterprise roles cannot use any UI endpoint

- **WHEN** 普通用户、组织 owner、仓库 creator/owner/admin，或仅绑定企业 Owner/Platform Admin 的用户访问新增页面、搜索或提交请求
- **THEN** 系统拒绝且不读取企业策略、历史或候选对象，不提供菜单，不产生策略写入

#### Scenario: Ordinary site administrator is not a WeCom super administrator

- **WHEN** 企微启用且仅具有 IsAdmin 的账号缺少当前应用 active、已绑定管理 authority，或仅有 message-only/其他应用 authority
- **THEN** 新增 UI 的读取与写入均被拒绝，不用 IsAdmin 或企业角色绕过

#### Scenario: Authority changes take effect without a new login

- **WHEN** 已登录超管的账号被禁用、限制或管理 authority 被撤销后再次请求企业授权页面或提交旧表单
- **THEN** 系统按当前数据拒绝，不依赖原 session 继续放行

### Requirement: The UI uses existing Web sessions without weakening token APIs

系统 MUST 使用既有 Web 登录/session 和同源 CSRF 防护，MUST NOT 要求输入 PAT 或将任何访问令牌写入 HTML、URL、浏览器持久存储。全部 mutation 与 POST 诊断 MUST 校验 CSRF；GET MUST 无策略变更副作用。既有 token API 的认证、scope 和 authority MUST 保持不变，不因 UI 将其改为 session 可用或全局仅超管 API。

#### Scenario: Super administrator maintains policy without a PAT

- **WHEN** 合法超管通过内置表单提交角色或绑定维护
- **THEN** 系统使用当前 Web 身份和合法 CSRF 完成操作，不生成、要求或暴露 PAT

#### Scenario: Missing session or forged CSRF is rejected

- **WHEN** 请求缺少合法 session，或写入/诊断请求缺少、伪造 CSRF token，或通过 GET 请求执行修改
- **THEN** 按原生登录/CSRF/方法规则拒绝，不查询诊断数据或变更策略

#### Scenario: Existing API authorities remain independent

- **WHEN** 原有合法 org/repo 管理者使用具备必要 scope 的 PAT 调用既有企业授权 API
- **THEN** 原 API 继续按原合同授权；其可用性不授予该账号内置 UI 访问权

### Requirement: Scope navigation and object selection preserve resource boundaries

系统 MUST 在站点管理下提供统一企业授权入口和明确的 system/org/repo 作用域切换，MUST 始终显示当前范围及目标标识，MUST 由 URL 与服务端资源确定提交范围而不接受 body 扩大范围。作用域与 user/team/org 选择 MUST 有受权、分页、有界搜索，不接受 repo 主体。组织/仓库 settings MUST NOT 向非超管增加维护入口；不存在、跨当前范围的角色/绑定/decision ID MUST 返回 404，不将搜索结果或表单筛选当后端校验。

#### Scenario: Super administrator switches among all three scopes

- **WHEN** 超管从系统范围切换到实际组织或仓库
- **THEN** 列表、表单、提交和详情均显示并使用所选范围，祖先角色定义标明来源，不将系统角色列表误当目标绑定

#### Scenario: Manipulated scope or object identifier is rejected

- **WHEN** 在仓库 A 表单提交仓库 B 的角色/绑定/decision ID、无关组织 team 或篡改隐藏 scope 字段
- **THEN** 按当前范围的合法角色来源/主体合同拒绝，不读取或修改不适用对象

#### Scenario: Target is renamed transferred or deleted during editing

- **WHEN** 表单显示后目标 owner/存在性或 team-repo 关系改变
- **THEN** 系统使用最新对象校验，显示可处理错误或当前状态，不用旧显示名或 owner 快照扩权

### Requirement: Role management covers complete CRUD and safe copying

系统 MUST 提供角色列表/详情、创建、独立复制、编辑和删除；明确内置/自定义、定义 scope、revision、action 及条件。内置角色 MUST 不可编辑/删除；祖先自定义角色 MUST 不得在子范围修改原定义，可复制为当前范围独立角色。编辑/删除 MUST 传递原 expected_revision；冲突 MUST 明确提示并保留未提交编辑，不自动以最新版本重试覆盖。引用中删除及同范围重名 MUST 有明确失败反馈。

#### Scenario: Custom role is created copied edited and deleted

- **WHEN** 超管完成创建/复制/编辑/解除引用后删除流程
- **THEN** 界面反映真实持久化结果，权限为完整显式 allow 集，复制不联动原角色，管理审计与提交原子一致

#### Scenario: Immutable or referenced role cannot be deleted

- **WHEN** 超管尝试修改内置角色、在子范围改祖先定义或删除仍有绑定的角色
- **THEN** 页面只读/禁用相应控件，直接提交仍由后端拒绝，解释复制或先解除绑定的正确操作

#### Scenario: Concurrent editor cannot overwrite a newer revision

- **WHEN** 两个界面基于同一 revision 编辑，另一提交已成功
- **THEN** 后提交得到版本冲突，不显示假成功，不静默重试；用户可查看最新定义后显式重新编辑

### Requirement: Permission forms use the authoritative action and condition contracts

系统 MUST 从后端 action 目录构建权限选项并展示 unit/风险/适用边界，只允许 allow。表单 MUST 支持 branch_pattern、path_pattern 和 request_sources 的结构化编辑及完整 round-trip；字段间 AND、同字段 OR、all-path 与缺上下文 unresolved MUST 有清晰帮助。同一 action MUST 允许多条不同条件的权限并准确回显；完全相同的重复权限 MUST 拒绝而非静默合并。空权限集 MUST 可显式保存；空条件 MUST 表示无条件，不能把未修改、空集和无效 JSON 混淆。未知 action、完全相同的重复权限（action＋规范化 condition）、未知 condition/source、非法 glob 或超限输入 MUST 有安全验证反馈，不保存部分权限。

#### Scenario: Conditional permission is edited without losing fields

- **WHEN** 超管保存并重新打开包含分支、路径和入口来源限制的权限
- **THEN** 页面准确还原全部条件与语义；取消或无修改提交不扩大为无条件 allow

#### Scenario: Feature grant is not represented as an implemented operation

- **WHEN** 页面展示 repo.manage_feature_grant 或其他 action 的能力说明
- **THEN** feature grant 明确仅目录/诊断，不出现开启 repo 功能或强制授权成功的控件

### Requirement: Binding management is complete and membership safe

系统 MUST 展示当前范围绑定并支持合法 user/team/org 主体与可用角色的绑定、解除；重复绑定 MUST 幂等。绑定 MUST 由后端重新校验主体/角色/组织/仓库关系及 Platform Admin 仅系统级绑定合同。旧 scope_owner_id 失效绑定 MUST 明示“当前不生效”，只能通过明确解除/重新绑定处理，MUST NOT 自动修复或改写 native membership、access、IsAdmin 或企微自动生成映射。

#### Scenario: Native subject binding is created and removed

- **WHEN** 超管选择合法本地主体和可用角色进行绑定及解除
- **THEN** 列表更新为实际提交结果并保留管理审计，不更改原生成员/凭据数据

#### Scenario: Transfer invalidates old-owner bindings

- **WHEN** 所选仓库已转移，旧 owner 范围绑定仍存在
- **THEN** 页面明确其不生效及需要显式重新绑定，不冒充当前有效授权或自动回填

### Requirement: Diagnostics remain candidate-only and non-mutating

系统 MUST 提供选定可见仓库、本地用户、action、branch 和有界完整 paths 的诊断，以及有效权限查看。诊断 MUST 固定来源 diagnostic，展示原生/企业来源、条件匹配/不匹配/unresolved、missing actions 和安全 reason；MUST 显示 candidate_only 与未计算完整 branch/merge 安全守卫。诊断 MUST NOT 执行 Git、改变绑定/权限或伪造真实 Web/SSH/receive 记录，MUST NOT 将用户诊断当作其特定 PAT/SSH/deploy 凭据的真实结果。

#### Scenario: Administrator evaluates an action for another user

- **WHEN** 超管为有效本地用户选择 repo/action 并提交诊断
- **THEN** 显示候选结果及限制，而不是“实际已授权/保护检查通过”；不产生真实操作决策或写入原生仓库

#### Scenario: Paths are unknown or not wholly matching

- **WHEN** 条件需要完整路径而输入缺失，或路径集中有一项不匹配
- **THEN** 页面分别展示 unresolved 或不匹配，不用 any-path 扩大授权

### Requirement: Decision history is bounded explainable and privacy safe

系统 MUST 提供受权的 actor/repo/action/candidate/time 筛选、每页最多 100 的分页和详情；呈现 operation/observation ID、候选/原生结果、stage、reason、missing actions、mismatch 和当时安全快照。unknown MUST NOT 冒充原生 success 或计算确定 mismatch；历史 MUST 不用当前角色覆盖。已删除仓库证据 MUST 可在系统范围由超管查询，MUST 不要求读取已删除 repo。页面 MUST 仅展示白名单安全字段，不包含 token/secret/原始错误、HTTP body、代码/diff 或私密路径原文。

#### Scenario: Administrator compares a candidate allowance with native denial

- **WHEN** 超管打开真实观察的候选 allow、原生 denied 记录
- **THEN** 页面清楚区分结果、stage 与 mismatch 并使用当时角色 revision/条件摘要解释，不显示“操作成功”

#### Scenario: History remains queryable after repository deletion

- **WHEN** 超管在系统历史查询已删除 repo ID 的保留期记录
- **THEN** 展示安全历史及已删除标识，不依赖不存在的 repo 页面或重算当前策略

#### Scenario: Sensitive or malformed evidence is not rendered verbatim

- **WHEN** 输入或记录含 HTML/script、secret/token、私密 paths 或不合合同的 snapshot
- **THEN** 文本被转义且仅白名单安全内容进入页面；坏证据返回安全失败，不渲染原始 JSON 或内部错误

### Requirement: Disabled mode and authority failures do not expose a fallback UI

authz disabled 时系统 MUST 隐藏新增菜单；直接访问 MUST 在既有登录/超管校验后返回 404，不读取企业策略。authority 查询失败 MUST 拒绝而不授予回退权限，并返回安全错误。界面 MUST 不提供修改 ENABLED/ENFORCE/callback 的按钮，不通过 GET 自动启用、seed、绑定或修复策略。

#### Scenario: Disabled direct URL is rejected without policy reads

- **WHEN** authz 关闭时合法超管访问新增页面或异步请求
- **THEN** 返回 404，不查询角色、绑定、decision；非超管仍先被认证/权限规则拒绝

#### Scenario: Authority storage fails

- **WHEN** 当前超管 authority 查询失败
- **THEN** 新增页面/写入拒绝并显示安全错误，不把查询失败当成允许或暴露原始错误

### Requirement: The interface is accessible localized and operationally truthful

系统 MUST 沿用 Gitea 内置页面/主题/locale，提供明确导航、可聚焦表单标签、键盘操作、非仅颜色的状态和安全确认。列表 MUST 有 loading/空列表/存储失败/无匹配状态及真实分页；提交失败 MUST 保留可安全恢复的未提交编辑但不在浏览器持久存储敏感数据。成功 MUST 在真实事务提交后显示，重复点击不得产生半套权限或假成功。action、状态、原因和选项 MUST 来自后端合同及服务端本地化显示，不在 JS 中独立推导业务授权。

#### Scenario: Form failure is actionable without losing edits

- **WHEN** 请求返回 422、409 或安全 500
- **THEN** 用户能识别失败及处理方式，未提交编辑可继续，页面不显示成功或静默覆盖

#### Scenario: Dark theme and keyboard operation preserve meaning

- **WHEN** 用户切换 Gitea 暗色主题或只用键盘维护角色和查看决策
- **THEN** 导航、标签、焦点与状态文本仍可用，不依赖颜色表达 allow/deny 或失效状态

### Requirement: Authentication and shadow compatibility remain unchanged

新增 UI MUST NOT 开放本地密码、注册、OpenID、Passkey、其他 OAuth、反代或 SSPI 登录旁路；合法企微及 MFA 续接 MUST 保持原有行为。SSH key、PAT/API token、Git HTTP token 和受限 Actions/deploy actor 的行为 MUST 不变。服务端 MUST 仅部署/验收 Linux；callback MUST 保持关闭，身份更新仍为合法登录刷新与定时完整同步；UI MUST 不实现 enforce、feature grant、完整 merge gate 或企微手工 mapping 维护。

#### Scenario: UI is not an alternative sign-in path

- **WHEN** LOGIN_ONLY 环境中的未登录用户从新增 URL 或表单尝试本地/其他 Web 登录
- **THEN** 原有登录拒绝继续生效，UI 不创建新 session 或本地超管后门

#### Scenario: Credentials and native requests keep their previous behavior

- **WHEN** 原 SSH/PAT/Git HTTP/Actions/deploy actor 认证或执行 repo 操作
- **THEN** UI 不改变认证、scope、吊销、权限、原生响应或 shadow-only 行为，不新增企微 OAuth 校验

### Requirement: Management flows use names rather than manual business identifiers

界面 MUST 以受权分页的名称搜索选择组织、仓库、用户、团队和角色，不提供可见业务 ID 输入；ID MUST 仅作为隐藏提交值。系统 MUST 回显真实已选对象及来源，支持清除/更换，输入文字或改变对象类型后 MUST 清除过期选择，未明确选择的非空文字 MUST NOT 沿用旧 ID 提交。搜索、初始回显和错误恢复 MUST 保持原超管/对象关系校验，不能信任浏览器提交的名称。

#### Scenario: Administrator completes maintenance without looking up identifiers

- **WHEN** 超管切换范围、选择主体和角色、执行诊断或筛选历史
- **THEN** 全流程按名称选择，成功及失败后回显选择，键盘可达，无需知道数据库 ID

#### Scenario: Edited search text cannot retain a stale selection

- **WHEN** 用户改写已选对象的搜索文字、清除选择或改变主体/范围类型
- **THEN** 旧隐藏 ID 立即失效，非空未选择输入阻止提交，后端仍独立验证目标

#### Scenario: History filters remain usable for retained deleted-object evidence

- **WHEN** 超管查询当前受权范围内已删除对象的历史
- **THEN** 可从历史对象候选选择“已删除对象”，技术编号仅辅助区分，不要求输入编号；列表不伪造历史名称或重算策略

#### Scenario: Date controls do not require Unix timestamp entry

- **WHEN** 超管按时间范围筛选决策
- **THEN** 通过浏览器本地时区日期控件输入并显示自动检测的时区，提交标准时间点；回显与分页保持同一时刻，不采用服务器时区；非法、不存在的夏令时日期或反向范围安全拒绝，旧数值链接仍兼容。页面时间自动按浏览器本地时区渲染；终端展示遵循终端本地时区，不强制 UTC

#### Scenario: Browser timezone differs from server timezone

- **WHEN** 上海或纽约的浏览器打开同一个冬季或夏季时间点，编辑本地时间并筛选或翻页
- **THEN** 展示对应浏览器本地时间及时区，标准查询时间点不变；纽约夏令时跳过的时间不被静默归一化，未修改的重复时段保留原时间点
