## Context

动机与用户确认见 proposal。基础 change `add-enterprise-authz-foundation-shadow` 在当前工作树已完成 57/57，具备 `services/enterpriseauthz` 的管理、诊断、历史和独立审计事务；API 为 token-only，既有组织 owner/仓库治理管理者可按各 scope 合同访问，不代表 UI 权限。

源码依据：

- `models/perm/access/enterprise_authority.go:HasSystemManagementAuthority`：企微关闭时使用原生 IsAdmin；开启时叠加当前 CorpID/AgentID 的 active bound management authority。
- `services/enterpriseauthz/management.go:CheckManagementAuthority`：重新加载 actor，校验有效性、synthetic actor 与 scope；现有各 scope service 不能直接承担“所有 UI 只限超管”的更严格要求。
- `routers/web/web.go`、`templates/admin/layout_head.tmpl`、`templates/admin/navbar.tmpl`：站点 admin/session/布局框架可复用，当前 `/-/admin/enterprise/wecom` 是自动化只读状态，不能混入手工 mapping 编辑。
- `services/enterpriseauthz/{role,binding,diagnostic,query}.go` 与 `routers/api/v1/enterpriseauthz/dto.go`：版本、条件、绑定、分页、历史白名单已存在；API DTO 转换当前为 router 私有，Web 不能跨 router 层直接调用。
- `docs/guidelines-frontend.md`：Go 模板、原生轻量 feature 模块及 fetch/fetch-action；复杂局部交互可用现有 Vue，不引入新 SPA/组件库。locale 只编辑 `locale_en-US.json`。

当前阶段只创建规划 artifacts，不修改生产代码、不运行数据库迁移、不提交或归档旧 change。

## Goals / Non-Goals

**Goals:**

- 一个完整的站点管理工作区，承载三作用域的所有既有维护能力；URL、菜单、按钮、helper 请求与 service facade 均只有当前系统超管可达。
- 薄 Web 适配复用业务规则，提供无 PAT 的 session/CSRF 工作流、准确错误与版本冲突处理。
- 将目录/候选诊断/真实历史安全语义呈现为可操作页面，具备可访问性和权限回归证据。

**Non-Goals:**

- 不把原 token API 权限收紧到全域仅超管，也不新增组织/仓库 owner UI。用户指定的是新增内置页限制；原 API 合同保持独立。
- 不增加 authz 启停/enforce 配置按钮、新角色/主体/action、外部 PDP、schema、seed、企微手工映射、审计导出系统或新登录入口。
- 不把角色候选 allow 宣称为实际仓库写权限、完整分支/merge gate、某个具体 PAT/SSH 凭据的行为模拟。

## Decisions

### 1. 集中于站点管理，不散落在 owner 设置页

选择 `/-/admin/enterprise/authz` 作为统一入口，复用 admin 导航和布局。工作区顶部显示 shadow-only、当前作用域/对象；通过有界搜索选择 system/org/repo，子页为角色、主体绑定、权限诊断、决策历史。诊断只对选定仓库可用；system/org 提示先选仓库，不虚构非 repo action 评估。

推荐资源路径：根入口跳转系统角色页；`/scopes/system`、`/scopes/org/{orgID}`、`/scopes/repo/{repoID}` 下提供 `/roles`、角色表单/详情与 mutation、`/bindings` 与 bind/unbind、`/decisions` 与详情；repo 另提供 `/effective-permissions`、POST `/evaluate`。`/selectors/{kind}` 是同一受权 Web 范围的用户/组织/仓库/team/角色候选接口，参数与页大小严格有界。ID 稳定用于提交，当前名字用于安全显示；所有链接尊重 AppSubURL。

选择集中工作区而非三个分散设置页，避免普通 org/repo 管理者看到不可用入口，也减少路由/权限重复。独立前端已由用户排除。跨范围 ID 仍按目标 service 校验；系统超管可显式切换到其他 scope，不能以一次表单扩大目标范围。

### 2. 双层超管准入，先权限后数据

路由顺序为既有 Web/session/管理员前置检查 → 当前系统超管校验 → authz enabled → scope/目标/表单加载 → UI service facade → 既有目标 scope service。

新增 UI facade 在每个读取/搜索/写入/诊断/详情路径重新调用系统 scope 的 `CheckManagementAuthority`，再调用原业务 service；菜单使用同一系统 authority 合同，而非独立 IsAdmin/企业角色判断。权限查询失败安全拒绝，记录固定原因，不使用回退。账号和 authority 每请求重新读取，不缓存跨请求结果；测试撤销后旧 session/表单下一请求被拒绝。实施须核对原 Web 认证方法，只接受合法当前 Web session，不以 header PAT/Basic 或 synthetic actor 替代。

超管定义不新增：企微启用时普通 IsAdmin、unbound/inactive/message-only/其他应用 authority 全部拒绝；企微关闭时沿用原生有效管理员。组织/仓库 creator/owner/admin、企业 Owner/Platform Admin 都不能获得 UI；企业角色也不能提升真实系统 authority。

不能只放在 `adminReq` 或前端显隐：基础 service 允许部分 owner，单靠该检查会让 Web helper 成为越权旁路。目标资源可见性、主体关系和 role scope 的原业务校验仍保留。

### 3. Session 表单与 Web helper，不改 token API

GET 展示页面、列表和候选；全部 mutation 与诊断使用 POST 并由新增 UI 专属 session synchronizer token 校验，并继续既有跨来源保护。简单表单采用正常服务端表单和成功后 PRG，重复提交使用已有幂等/版本合同；需要原地保留编辑的条件构建器、选择器和诊断用同源 Web helper，使用项目 fetch/fetch-action，不在 JS 直连 reqToken API、不创建 PAT。

helper 在上述同一准入组内，返回受限 DTO/安全 reason，不开放跨域或公开搜索。URL scope 决定对象；请求中 actor/caller/request_source/owner 不能覆盖当前 session/目标。失败不会 redirect 成假成功；JSON helper 使用 403/404/409/422/500，未登录页面沿原 Web 登录流程，POST/helper 按原生认证规则失败。禁止 GET 变更及外部 redirect 目标。

选择薄 Web handler/facade 而非将既有 `/api/v1` 改为 session-ready，避免污染 PAT scope 与原 API 合同。权限/诊断 guard service 不能依赖 browser 委托布尔值。

### 4. 完整维护与冲突可恢复

角色页按来源范围、内置/自定义和 revision 展示；内置/祖先定义只读但可复制到当前 scope。编辑包含 name/description、后端 action 目录勾选、每条权限的 action 与 branch/path/source 条件（同一 action 可有多条不同条件，只拒绝规范化后完全相同的权限），显式区别“不修改权限”“清空权限”“无条件”。UI 预检仅改善反馈，最终 validation 由现有 service 决定；保存/删除携带原 expected_revision，不自动读新 revision 重试。

409 区分 revision conflict、内置不可变、引用中删除、名称冲突，提供重新加载/复制/先解除引用的正确反馈。更新失败保留页面内未提交草稿，不写 localStorage/sessionStorage；CSRF 过期/authority 撤销不保留可执行授权状态。删除/解绑需明确对象确认，不用批量默认解除引用。

绑定列表与 user/team/org 选择遵循原 scope/角色可见性和 team/org/current owner 合同。必要的只读 view model 解析当前 owner/对象状态展示旧 owner 失效原因；不修复数据、不自动恢复绑定、不创建 membership。诊断本地普通用户，不假装代表某个指定 token/key 的 credential ceiling；actor 来自用户选择但 caller 固定当前超管。

### 5. 安全展示与业务枚举由后端拥有

复用 action catalog 的 key/unit/risk/Observed，诊断与 decision DTO 只呈现既有白名单字段。必要时抽取最小共享安全转换层供 API 和 Web 使用，不让 Web import API router，也不复制 raw snapshot JSON 渲染逻辑；抽取必须保持原 API 序列化合同及错误测试。

状态、source、stage、reason、condition result 与候选项由服务端 view model 提供稳定 code、locale message/label 和显示语义；沿用 Gitea 翻译，不让 JS 自行推导业务意义。未知显示值采用安全中性提示，坏持久化证据仍安全失败，不以 fallback 掩盖存储问题。风险等级与“仅诊断”采用文字而非仅颜色；role 名称/描述、对象名和条件一律模板转义，禁止 unsafe HTML。

action allow 显示“候选允许”，native outcome 独立显示，unknown 不计算确定 mismatch。历史使用记录时 revision/snapshot，system 历史可按已删除 repo ID 查询，不用当前 role 替换，不为历史补读已删除对象。敏感诊断 paths 只用于当前表单/请求，不写 audit、日志、持久浏览器存储或错误正文；维护的权限条件可由有权超管读取编辑，不等同保存真实操作私密路径。

### 6. 最小依赖的原生页面体验

优先 Go 模板/原生表单与少量 TS feature；复用现有样式/组件，不引入 React、新 SPA 或外部 UI 库。动态 condition builder 可按实际复杂度使用现有 Vue，但不混 Fomantic JS。导航与Tab有当前选中状态，表格可读、暗色主题可用，表单label/错误关联、focus、keyboard、确认行为可测试。

列表使用现有 pagination 最大 100，不抓全库再浏览器过滤；选择器页大小上限 100、单页明确下一页，名称搜索有长度界限、SQL 参数化。重复点击禁用仅改善 UX，后台仍原子/幂等。空结果、存储失败与未配置选定仓库是不同状态。禁止为 disabled 导航读取企业表；仅系统 authority 必要查询允许。

### 7. 审计、配置与迁移不扩张

角色与绑定 mutation 继续原同事务管理 audit，不增第二条伪成功审计。查询/诊断不伪造实际 repo 决策；沿用现有 diagnostic/audit 的安全行为。UI 不修改 audit retention/200ms/snapshot 预算，不显示凭据值，不改变企微 callback/同步。

不需 schema/seed、额外配置、新默认授权或 OpenFGA/Keycloak。UI 开关仅复用 EnterpriseAuthz.Enabled；关闭时先认证/超管，再404，导航隐藏，无策略查询。此处迁移判断是明确“不需要”，不是省略迁移任务；若实施发现新持久化需求必须先变更本提案。

## 权限矩阵

| 页面/请求 | 路由及 facade 检查 | scope/业务 service | 默认可达角色 | 前端入口 |
| --- | --- | --- | --- | --- |
| 工作区/作用域与主体选择器 | Web session + 当前系统超管 + enabled | 受权有界 scope/主体 lookup | 当前可信系统超管 | admin 企业授权菜单与作用域栏 |
| system/org/repo 角色与绑定读写 | 同一准入，写入叠加 CSRF | URL scope 的原 management service，revision/引用/主体校验 | 同上，不向 owner/admin 委派 UI | Roles/Bindings Tab、CRUD/复制/绑定/解除按钮 |
| repo 有效权限与诊断 | 同一准入，POST 诊断叠加 CSRF | 原 DiagnosticInput，caller 固定，source diagnostic | 同上，无普通 reader 自查 UI | Diagnostic Tab，仅 repo 上下文启用 |
| 决策列表/详情 | 同一准入 | 原 scoped history、system 已删除 repo 查询 | 同上 | Decisions Tab、筛选/分页/详情 |
| 原 `/api/v1/.../enterprise/authz` | 原 reqToken + scope + authority | 原 service 不变 | 原 API 合同中的合法主体 | 不作为新增浏览器直连接口 |

本仓库没有本变更所需的 OpenFGA relation、Keycloak role 或学校/平台等外部权限体系，不引入其注解/迁移。前端入口 key 是本仓库导航状态及 server-provided capability 标识，不作为授权依据。

## Risks / Trade-offs

- [把 site admin 与企微超管混淆] → 同一系统 authority helper、router/facade 双校验，覆盖普通 IsAdmin/unbound/message-only/其他应用与旧 session 撤销。
- [UI owner-only guard 复用造成越权] → 新 UI 限定系统超管，原目标 scope service 继续二次校验；不只隐藏按钮。
- [Web session 侵入 token API] → 独立同源 Web helper、CSRF 与固定 caller；原 reqToken API 回归保持。
- [新 UI 表单扩大条件/覆盖新 revision] → 完整 round-trip、nil/empty 区分、原 expected_revision、不自动覆盖、409 可恢复。
- [真实历史/私密路径通过 HTML 或 helper 泄露] → 共享白名单、安全reason、escape、无 raw JSON/unsafe HTML、限定搜索与隐私注入回归。
- [管理审计失败却 UI 成功] → 原 required persistence 事务，成功仅真实提交后显示；注入 audit/DB 错误断言策略回滚及安全500。
- [未归档前置导致依赖被漏带] → 实施前核对 foundation 生产模型/migration/模块，保留其未提交文件，不归档/提交/推送或修改旧验收结论。
- [新页面缺外语/暗色适配] → locale 唯一源、原生主题、语义定位E2E与截图；不手改其他 locale。

## Migration Plan

1. 核对前置基础 change 与当前系统 authority、依赖目录和原生登录/CSRF行为；不创建平行 Superpowers 计划，不自动修改其他 change。
2. 测试先行接入超管准入/禁用/选择器、完整角色绑定、诊断与历史，并以真实 Web session/CSRF 的页面和helper验证。
3. 仅随现有 Linux 服务端发布模板/前端资源与后端 handler；没有 schema/seed/version 修改。保留现有 authz、audit、企微配置，更新运维 UI 文档。
4. 上线用合法超管验证完整维护，再验证非超管直接URL/helper/POST拒绝。角色/绑定是实际策略数据，即使 shadow-only 也须维护审计。
5. 回退到已有 foundation 版本及匹配前端资源，仅移除 UI；不删除已维护策略/历史、不降 schema、不改原 API 权限。需要撤销某次策略变更时通过受权业务操作/版本控制显式处理，不能恢复部分数据库表冒充 UI 回退。

## 实施核对修正

- 2026-10-03：上游已移除 CSRF token，仅保留 `http.NewCrossOriginProtection`。新增 UI 使用同 session/用户绑定的随机 token，全部 POST 校验，叠加上游跨来源保护；不改其他页面、token API 或 DB。
- 用户确认同一 action 可配置多条不同条件，Web 只拒绝 action＋规范化 condition 完全重复，不改原 API 去重合同。

### 名称优先交互修正（2026-10-03 用户确认）

作用域、user/team/org、角色及历史 actor/repo 筛选统一为受权有界的名称选择器；不再提供可见业务 ID 输入。稳定 ID 仅放隐藏字段，已选名称与来源由后端解析，不接受 body label 作为对象证据。允许清除/更换；编辑文字、改变主体类型/作用域立即清除旧 ID，未选择的非空文字不能提交。支持键盘、加载/空/错误与分页，不抓全量候选。失败草稿与页面刷新回显真实已选名称。

历史时间按浏览器所在时区自动渲染，日期控件也按浏览器本地时区解释；页面显示自动检测的时区。浏览器将输入转换为标准 Unix 时间点，服务端只接受严格有界的标准查询值，不把无时区字符串解释为服务器时间。回显与分页从同一标准时间点转换，不重复偏移；夏令时跳过的不存在时间拒绝，未修改的重叠时间保留原时间点。旧数值查询链接保持兼容，界面不要求输入 Unix 时间。终端展示使用终端本地时区，不固定 UTC；本变更不新增 CLI。历史候选从当前受权记录范围分页取对象，已删除仓库/用户仍可选择，以“已删除对象”与辅助技术编号区分，不伪造原名称。列表显示当前对象名称（明确不是历史名称），技术编号保留详情辅助信息；历史 revision/snapshot 不重算。没有新增 DB/seed/config/action，原 API 与超管准入不变。
