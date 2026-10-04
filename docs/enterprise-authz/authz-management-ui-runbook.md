# 企业授权内置管理页

## 范围与入口

本页属于独立 change `add-enterprise-authz-management-ui`，在已完成的 foundation shadow 基础上增加 UI；不改写原 API-only 验收记录。

- 入口：站点管理 → 身份与访问 → 企业授权，URL `/-/admin/enterprise/authz`（部署子路径自动保留）。
- 所有页面、搜索、详情和 POST 仅允许当前可信系统超级管理员；组织 owner、仓库 creator/owner/admin、企业 Owner/Platform Admin 都不能获得 UI 权限。
- 企微开启时：有效原生站点管理员＋当前 CorpID/AgentID 下 active、已绑定的 management authority。普通 IsAdmin、message-only、其他应用 authority、失效绑定均拒绝。
- 企微关闭时：沿用有效原生站点管理员。被禁用、限制、撤销 authority 的旧 session/表单下一请求不能继续维护。
- `EnterpriseAuthz.Enabled=false` 时入口隐藏；已认证且受权者访问返回404，不读取企业策略。没有 UI 启停/enforce 按钮。
- 有效权限和诊断始终仅为 candidate；真实历史区分记录时的 shadow/enforce 与企业准入结果。角色不能绕过仓库可见性、repo unit、分支保护、合并守卫或其他原生检查。

## 维护流程

1. 选择系统、组织或仓库范围；通过有界受权名称搜索选择对象，稳定 ID 仅用于隐藏提交。范围和对象在每页顶部显示，提交以 URL 为准。
2. **角色**：查看来源、内置/只读和 revision；八个内置角色及祖先定义不能直接修改，可以复制到当前范围成为独立角色。
3. **权限条件**：每条权限选择后端 action 目录中的 action，只允许 allow。同一 action 可以有多条不同条件；完全相同的规范化权限拒绝，不静默合并。
4. branch/path/source 字段之间 AND，同字段候选 OR；所有受影响路径均须匹配。缺必要上下文是 unresolved，不是自动允许。每字段最多16项、每项256字节，每角色最多128条。
5. 条件每行一个；包含 CR/LF 或首字符双引号的合法 pattern 用单行 JSON string 转义表示。原样保留转义可完整回显，不会把一个含换行 pattern 拆成多个 OR 条件。
6. “保持当前权限不变”不改权限集合；“替换为下面权限”显式提交当前集合，删掉所有条目会清空权限。空条件表示无条件。
7. **绑定**：选择 user/team/org 和可用角色，明确绑定目标。服务端仍验证主体、祖先角色、组织/team-repo 关系；Platform Admin 仅系统级绑定。重复绑定幂等，不改变 membership/access/IsAdmin/企微映射。
8. 绑定列表标记当前状态。仓库转移后旧 owner 绑定不自动生效；主体删除、失效账号、team-repo 关系变化等分别说明。明确解除并重新绑定，不做自动修复。
9. 删除角色必须确认并携带原 revision；引用中的角色须先显式解绑。解绑对话框显示主体和角色，取消不发送修改。

选择器显示真实名称和来源，支持清除/更换、键盘及分页。改写搜索文字或改变对象类型立即清除旧选择；未明确选择的文字不能提交旧 ID。错误恢复仍按当前权限和对象关系重新校验。

## 冲突、失败与安全

- 编辑提交保留原 `expected_revision`。409 说明版本竞争、同名、内置只读或仍有引用；未提交草稿保留在当前错误页，不自动替换新 revision 或自动重试覆盖。
- 可以复制草稿或明确重新加载当前角色；重新加载会丢弃草稿。页面关闭后不保存到 localStorage/sessionStorage。
- 500 表示业务存储或同事务审计失败，策略整次回滚，不显示假成功。排查数据库/audit 可用性后重新加载验证，不以部分 SQL 写入修复。
- 所有维护/诊断 POST 需要真实 Web session 和 UI 专属随机 session CSRF token，并叠加上游跨来源保护。页面/搜索缓存 `no-store`。
- 当前上游已经移除通用 CSRF token；新增 token 只用于本 UI，不改其他页面或 token API。表单只接受 `application/x-www-form-urlencoded`，不支持文件/multipart/JSON 上传；请求和条件有后端大小限制。
- token、凭据、原始存储错误、raw snapshot JSON、实际代码/diff/私密操作路径不出现在页面或 helper。角色条件是有权维护者正在维护的策略，不等同于真实操作路径。

## 权限诊断与真实历史

- 有效权限与 action 诊断只对选定仓库及本地用户执行；系统/组织页提示先选仓库。caller 固定当前超管，source 固定 diagnostic。
- 按名称选择本地用户，输入 branch 和完整 paths 后显示 native actions、role actions、缺失 action、匹配/未匹配/unresolved、角色名称和 revision；技术编号仅在辅助详情中显示。
- “候选允许”不代表真实操作一定通过；完整分支/merge safety guards 未评估，不模拟某个特定 PAT、SSH key 或 deploy credential。诊断不执行 Git、不写真实操作决策。
- 诊断 paths 只用于本请求，结果不回显；失败保留用户/action/branch 等可恢复字段，但不持久保存 paths。
- 历史按 actor/repo 名称、action/candidate、记录时模式、企业授权结果及本地日期时间筛选，最多100条/页。详情使用记录时的安全 snapshot、revision 和 condition hash，不用当前角色重算。
- operation/observation 分开显示，包含协议64hex observation；native unknown/failed 不宣称确定 mismatch。系统历史可从受权历史候选中选择已删除仓库（辅助编号仅用于区分）查询，详情标记已删除仓库。

页面时间自动按浏览器本地时区展示，日期控件同样使用该时区，页面显示检测到的时区。后台及 URL 查询保存标准时间点，旧 Unix 数值链接仍可打开，刷新/分页不会再次偏移。不需要手动输入时区或 Unix 秒。夏令时跳过的不存在时间会提示无效，未编辑的重复时段保留原时间点。关闭 JavaScript 时日期编辑禁用，已有标准筛选保留，避免误用服务器时区。终端时间显示沿用终端本地时区，不固定 UTC。

当前用户/仓库/角色名称只用于辨认，明确不是历史名称；历史 revision/snapshot 保持记录时证据。

## UI 与原 API 的区别

新增 UI 是全局仅超管的 session 工作区。原 `/api/v1/.../enterprise/authz` 继续原 reqToken/scope/目标 authority 合同；合法 org/repo owner 使用合适 PAT 仍可调用原 API，UI 不对普通 owner 开放，也不要求超管输入 PAT。

## 初始 UI 交付的发布与仅 UI 回退

- 服务端仅 Linux；发布后端和匹配模板/前端资源，沿用已验收 foundation 的 schema、八个 seed、配置与审计机制。
- 本 UI 不新增 schema/migration、seed、默认权限、config、action、OpenFGA/Keycloak，也不更改生产 callback 关闭、登录刷新或定时完整同步。
- 回退使用已安装的匹配 foundation 版本二进制和资源，只移除新增 UI。**不降 schema，不删除策略/历史，不恢复部分策略表，不改开关或 API 权限。**
- 策略本身已真实维护，即使 shadow-only 也需要保留；撤销某次策略变更必须通过受权业务操作与 revision 控制显式完成。
- 启用前仍执行 foundation 原有 readiness/migration 验收，不能用 UI 或手工回填掩盖缺失 seed。

## Enforce 历史的追加合同

`enforce-enterprise-authz-high-risk-actions` 在既有列表/详情追加四个 API 字段：`decision_mode`、`authorization_decision`、`authorization_reason`、`execution_started`。此扩展不改变原 UI/API authority、token scope、CSRF、登录或名称选择器，不增加配置开关。

- 模式来自当时记录，不读取当前全局配置；升级前记录归为 `shadow/not_enforced`。Catalog v1/v2 的安全历史都可读取，未知版本或非法 mode/result/reason 返回安全失败，不展示 raw snapshot。
- `shadow` 仅观察；`enforce` 的 `allow` 表示准入，**不是操作成功**。`deny/error` 明示未执行，原生结果为 `unknown`，不伪造原生拒绝。
- `fallback` 明示按原生守卫继续，不能从候选权限推断角色已放行。`execution_started=true` 只说明执行开始，真实终态仍由 `native_outcome` 表示；`allow + unknown` 仍是未确认结果。
- 只有可比较的 shadow 原生 success/denied 计算 mismatch；enforce、unknown、failed 不计算确定 mismatch。旧 shadow 的执行开始信息没有记录，不能从默认 false 推断未运行。
- 原 API 追加 `mode=shadow|enforce` 和 `authorization=not_enforced|allow|deny|error|fallback` 筛选；非法、空值或重复 API 筛选拒绝。UI 空值表示不限，其他非法值和重复字段拒绝，分页保留筛选。已删除 repo 历史仍仅在系统受权范围读取。

上节记录的是初始 UI-only 交付，不适用于新版 enforcement 的二进制/schema/seed 回退。新版需保留 additive 证据字段及 catalog v2 seed；不得仅回退到旧 foundation 二进制或手改 seed 来伪装兼容。完整 enforcement 配置、回退和 Linux 验收由对应 change 的运维手册/verification 管理。

仓库 runner 注册 credential 的机器证据使用 actor0/source system/NativeOnly，仅限定 manage_ci，不归因 token 发行者或虚构人工 Owner。历史详情明确标记机器 credential，选择器用“anonymous or machine”表示 actor0；recorded native mode 仅说明凭据限定能力，不是人工管理 authority，内部 token reference 不展示。
