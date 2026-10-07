## 1. 基线与验收映射

- [x] 1.1 读取适用 AGENTS、开发/测试文档与三个前置 change 的 artifacts/verification，核实真实代码、catalog/migration 版本及依赖状态，保留用户预存改动。
- [x] 1.2 将两份 delta 的全部 Requirement/Scenario 映射到以下切片与验证项，确认仅 Linux 服务端、无外部执行/模板/新认证/规则管理 UI，不另建平行设计文档。
- [x] 1.3 盘点 Web/API/shared service/auto/force/manual/后台识别和内部 merge push 的调用关系，标出每个写前边界、原生 helper 故障语义与已有测试扩展位置。

## 2. 类型、规范化与纯门禁核心

- [x] 2.1 先增加失败单测，再实现 mode/phase/decision/execution-state、typed facts、稳定原因与展示目录；覆盖全部原因聚合、确定排序、未知事实 error 优先及 preview 非执行票据。
- [x] 2.2 先增加规则规范化单测，再实现 path/branch glob、role ID、contexts、enabled/revision 输入校验，拒绝重复/未知字段、非法编码/控制字符/越界及超限输入。
- [x] 2.3 增加 disabled/shadow/enforce × 普通/force/schedule/admission/manual 的纯决策表，mandatory guards 与显式 bypass 类别分开；无 blocker 的 bypass_requested 保持 allow/not_used。
- [x] 2.4 扩展 contexts 单测及纯评估：native patterns 保持原语义，feature/path exact match、来源去重、最新状态、missing/pending/failure/error/unknown 阻断；空 required 配置不默认通过。
- [x] 2.5 针对新核心运行定向单测，确认 error、不完整 diff、超限规则/快照不被截断成 allow，且独立 fail-open 配置不能放宽 gate enforce。

## 3. 两表迁移、action seed 与历史兼容

- [x] 3.1 先补迁移/模型失败测试，再增加 additive `modelmigration/` 两表与注册、scope/reference/PR/history/operation-attempt-phase/待对账索引；不修改既有 migration 或 PR/Issue 核心模型。
- [x] 3.2 增加两个新 action 的 catalog 版本、元数据/条件校验、native mapping、Owner/Platform Admin seed 迁移与 readiness；Admin/Maintainer/Security Maintainer 不默认授予，既有自定义角色/绑定不扩权。
- [x] 3.3 扩展 version 1/2 历史 DTO 与新版本 catalog/decision 查询测试，保证旧记录仍按原版本解释，诊断 allow 不代替 bypass 或管理 authority。
- [x] 3.4 实现 rule tombstone/CAS/no-op 与 evaluation immutable snapshot/terminal CAS 模型；测试重复操作、终态封存、防 ABA、分页及超限完整性。
- [x] 3.5 在隔离 SQLite/PostgreSQL 数据库验证迁移重复运行、索引/seed 缺失检测、历史保留和失败恢复；记录真实 migration/DB version，不手工改 version 表。

## 4. 配置与启动预检

- [x] 4.1 先补配置单测，再实现 `[enterprise.merge_gate]` 默认关闭和严格 ENABLED/ENFORCE 组合校验；依赖 authz enabled/enforce、DB audit/两表/索引/seed 的 readiness。
- [x] 4.2 更新 `custom/conf/app.example.ini` 与仓库配置文档，明确 gate strict fail-closed 独立于 action FAIL_CLOSED_ON_ERROR；不改变企微/callback 配置。
- [x] 4.3 验证 disabled 零门禁查询/证据，shadow 候选失败不改变既有 action/feature enforce、原生 force/排队结果；管理 CRUD 在 shadow 仍严格授权。

## 5. 规则管理、权限与生命周期

- [x] 5.1 先补 authority/credential 失败测试，再实现 global/org/repo 规则服务：当前 scope authority、repo manage_sensitive_paths、原生 code visibility 与相应读写 token scope；避免仅凭 IsAdmin/旧 session/裸角色放行。
- [x] 5.2 实现 global → 当前 owner org → repo 活动规则累加、个人仓库跳过 org、branch 匹配及稳定 role 可见性；测试多规则 AND、无下级覆盖、越界/失效角色和 effective 规则超限。
- [x] 5.3 实现排序 scope/reference 锁、expected_revision/no-op/delete 墓碑、规则与变更审计同事务；并发同版本/父子更新、审计故障和删除重建必须拒绝或回滚。
- [x] 5.4 对接角色删除引用检查与并发新引用保护；repo/org 删除清理 live 策略而保留历史，owner 转移使旧 owner 规则/角色显式 unresolved 并要求新 authority 修复。
- [x] 5.5 定向验证 403 负例、真实 Owner/当前可信超管正例、满足原生 authority 的自定义角色正例，以及原生 Admin 未授新 action、readonly/public-only/错误 scope/跨仓库请求负例。

## 6. 原生事实、完整 diff 与敏感审批

- [x] 6.1 先扩展原生 merge 测试，再实现 pull adapter 的 actor/permission/PR/current owner/head/base/native facts；保留 merge whitelist/style/signing/protected files/outdated/审批/CODEOWNERS 原语义。
- [x] 6.2 为必要 boolean-only helper 增加可区分读取故障的 typed 底层结果，保留旧调用兼容；测试 branch/CODEOWNERS/review/workflow 读错误不能变成空要求或假缺审批。
- [x] 6.3 实现受信完整 Git diff（包括新增/删除/rename/copy 两端与 CODEOWNERS 修改）、base CODEOWNERS 与路径完整性标记；测试 fork/AGit、超限、分页伪装、缺对象和非法路径。
- [x] 6.4 实现逐命中规则的“所有命中路径 CODEOWNERS 批准 OR 当前指定 role 批准”与独立 contexts；验证原生 CODEOWNERS 不能被 role 分支豁免，无 owner/仅作者不自动满足敏感审批。
- [x] 6.5 验证敏感审批必须当前 head、最新 approve、非 stale/dismissed、有效且非作者 reviewer、当前 user/team/org 角色与 code/PR 可见性；角色改名不改 ID 语义，解绑/退组/新 head 使旧审批失效。
- [x] 6.6 实现 draft/closed/merged/conflict/checking/dependency/未解决 review conversation mandatory 原因，conversation 区分 review thread 与普通评论；测试无 pb 的 unresolved 仍阻断，解决后可重评。

## 7. Feature-required 与外部 statuses

- [x] 7.1 复用现有 feature resolver 采集有效四态/首锁/required contexts，并和 native scoped workflow、命中路径要求合并；不改 13-key catalog 或 policy_only 外部执行边界。
- [x] 7.2 按 base repo + 当前 head 取得 latest-per-context status，保留安全 ID/creator 来源；测试旧 SHA/他仓库/旧 success 不满足最新 failure，native pattern 与新增 exact 大小写语义保持分离。
- [x] 7.3 覆盖六个外部 key 的 required 阻断、enabled 非隐式 required、disabled 不撤销独立要求、上级 required 不被下级削弱、空 required context 与 required-status native pending。
- [x] 7.4 验证无原生 branch protection 时企业 required checks 仍阻断，且无 scanner/AI 调用、status 造假、provider credential 或 integration 自动创建副作用；保留原有 status callback 认证及写权限。

## 8. 实际准入、快照审计与恢复

- [x] 8.1 先补 direct-service 写前拒绝测试，再将 adapter/gate 接入 PR lock、现有 Git execution Admission 与 shared Merge/MergedManually；刷新 actor/credential/owner/Git refs 和当前完整事实，不能仅在路由检查。
- [x] 8.2 实现一致策略快照、facts fingerprint 最终复核、有界重采集和预期 ref 更新；用确定性并发屏障验证 head/base/规则/feature/角色/状态/讨论变更在准入前被消费，避免依赖 sleep 或旧缓存。
- [x] 8.3 将 admission/deny/error/bypass 快照与强制审计原子持久化，deny 独立事务留存；故障时 503 且 Git/PR merged/分支清理/成功通知零副作用。
- [x] 8.4 连接现有 hook operation ticket 与本次 admission，不把客户端 evaluation ID 变凭据；测试失效/跨请求 ticket、内部 merge push 不额外要求 direct protected-push action，原生 signing/pre-receive 不被跳过。
- [x] 8.5 实现 operation/attempt/phase 幂等关联与 terminal CAS；注入 Git 失败、Git 成功后 DB/审计故障、取消/超时/进程重启，保留 started/unknown 并实现对账，不重 push 或假成功。
- [x] 8.6 定向核验结果快照只含受控事实/版本/摘要，64 KiB 超限 fail-closed，不含 token、secret、代码、原始 status description/URL；资源/角色删除重命名不覆盖历史。

## 9. Force、auto 与 manual 完整接线

- [x] 9.1 扩展 Web/API form、DTO 与 service options 的 bypass_reason/categories，保持旧 force_merge 字段；enforce 校验独立 bypass action、native bypass、理由与七类显式选择，其他条件/error 不可豁免。
- [x] 9.2 覆盖无 action、无/非法理由、未知类别、部分豁免仍 deny、无 blocker not_used、上级 required 特权豁免审计及 mandatory 不可豁免；验证 disabled/shadow 旧 force 客户端行为不变。
- [x] 9.3 将 auto schedule 与 worker execution 分阶段接入，等待项不冒充 merge allow；evaluation 表与队列同事务保存 queue ID/actor/credential attribution，replace/cancel 隔离旧关联，验证 PAT 撤销/收窄后的交集 ceiling、session 后台委托和未知历史队列 fail-closed，不存 bearer token、不由裸 doer ID 扩权。
- [x] 9.4 auto 排队及实际执行拒绝 bypass；对接 status/review/conversation/rule/feature 变化触发、去重/退避、持久 deny 暂停与取消语义，验证排队后撤权/禁功能/新失败状态不能执行。
- [x] 9.5 manual marker 与后台识别接入 manual_recognition：可靠原始 head/base/merged commit/真实 pusher 与非零历史 diff；后台无 bypass、未知 pusher 无 Owner fallback，主动 marker 的 bypass 遵循新合同。
- [x] 9.6 分别验证 Web/API/worker/shared service/force/manual 成功及拒绝路径与实际 Git/PR 状态、分支清理/通知；事后拒绝不伪造阻止先前直接 push。

## 10. API、隐私与 PR merge box

- [x] 10.1 增加 design 权限矩阵中的三作用域规则 CRUD、PR preview 与受权 evaluation history 路由，绑定 path scope、认证/凭据/authority 和 CSRF（Web），实现分页/X-Total-Count 与稳定错误码。
- [x] 10.2 增加安全 reader/管理 DTO 投影及版本校验：reader 仅本 PR 安全原因，不含上级原始配置/ID/历史/自由文本理由；history/evaluation ID 必须限定 repo/PR，preview GET 不写实际准入审计。
- [x] 10.3 扩展 PR merge box 的 typed reason/descriptor 展示、ordinary/bypass 按钮及必填理由/选择项表单，disabled 保留旧 UI，shadow 明示候选，unknown/error 不显示通过；只改 locale_en-US，不引入新框架或规则管理页。
- [x] 10.4 补 API 401/403/404/409/422/503、readonly/跨 scope/private repo/旧 session 权限测试；补 locale/转义/CSRF、键盘语义、按钮显隐与绕过客户端提交的服务端拒绝测试。
- [x] 10.5 更新 Swagger request/response/历史 schema 与旧 merge API 可选字段和成功响应兼容，执行 generate-swagger、swagger-validate/check，并验证 API/模板显示同一原因语义。

## 11. 全矩阵、协议与 Linux 验证

- [x] 11.1 建立并运行 gate disabled/shadow/enforce × Web/API/auto/force/manual/shared service × Owner/可信超管/Admin/自定义角色/只读/受限凭据矩阵；覆盖普通/merge/rebase/squash/fast-forward、fork/AGit 与原生签名/保护回归。
- [x] 11.2 回归企微合法登录/MFA、密码/注册/OpenID/Passkey/其他 OAuth/反代/SSPI 等禁止 Web 路径；验证 callback 关闭与合法登录刷新/完整定时同步保持，不做 Windows 服务端验收。
- [x] 11.3 回归真实 SSH key、PAT/API token、Git HTTP token 的签发/认证/scope/吊销与 clone/fetch/普通/保护 push，确认门禁不替代认证或扩大原有 credential ceiling，直接 push 仍按已有 receive 守卫。
- [x] 11.4 运行有界纯单测、规则/modelmigration/API/service 集成与少量 merge box e2e，优先扩展现有测试；integration 目标小于 2 秒、e2e 小于 4 秒，使用确定性条件。
- [x] 11.5 在 Linux SQLite/PostgreSQL 环境跑迁移、全入口真实 merge/Git、故障/并发/重启对账与外部 status 协议验证；如环境不可用逐项记录未验收，不用 macOS 或 mock 代替 Linux/真实外部 scanner 结论。
- [x] 11.6 Go 编辑后运行 make fmt，按改动运行 lint-go/lint-js/lint-css/lint-templates、相关 build/tests；仅 go.mod 变更才 make tidy，执行 OpenSpec strict validation 并审查最终 diff 无无关改动。

## 12. 运维文档与交付证据

- [x] 12.1 增加 merge gate runbook：配置、启用顺序、三作用域 CAS API、角色引用与 owner 转移修复、context 来源/空配置、force 字段迁移及独立有限 bypass，不硬编码或自动套用默认路径。
- [x] 12.2 文档明确原生 status writer 可伪造同名结果的信任边界、bot 最小权限、无外部执行/云 token/供应商签名证明；manual 只是事后识别，不保证阻止直接 push。
- [x] 12.3 记录 crash/unknown 终态对账、审计/策略故障、shadow→enforce 验收与配置回退风险；保留历史/两表，不改 DB version 或以删表方式降级。
- [x] 12.4 在 verification.md 逐 Requirement/Scenario 记录测试命令/真实输出、权限矩阵、两表/action migration 与 Linux SQLite/PostgreSQL 证据，明确所有未验证项；真实通过后才勾选任务。
- [x] 12.5 仅同步已验证的 implementation-plan/roadmap 状态，保持前序证据与未来范围；最终核对所有要求无 stub/mock/不可达路径，运行 `openspec validate add-enterprise-merge-gate --strict`。不未经授权提交、推送、部署、同步 main specs 或归档；未来 sync 先按依赖顺序建立授权 main spec。
