## 1. 实施准入与覆盖基线

- [x] 1.1 重新读取本 change 的 proposal/design/delta spec、仓库 instructions 和企业授权文档；记录完整验收矩阵，不修改预存用户变更，不建立并行设计/计划。
- [x] 1.2 核对 `harden-wecom-governance-ops` 的准入依赖：callback 保持关闭，登录刷新 + 定时完整同步替代通知触发；服务端永久仅面向 Linux，移除 Windows 原生验收门槛。记录范围调整与真实验证状态，不自动勾选前置任务。
  - 2026-09-30：用户确认登录管理员权限刷新 + 定时完整同步，callback 保持关闭；其真实协议验证只保留为独立启用 gate。用户明确服务端永久仅部署 Linux，Windows 服务端支持与原生回归排除，不影响 Windows 客户端使用 Web/SSH/Git HTTP。前置任务 1.2/9.1 未被冒充完成；本 change 的实施准入范围豁免已确认。
- [x] 1.3 盘点 design 第 7 节全部 Web/API/Git HTTP/SSH/file editor/receive hook/auto/force 入口，定位原生认证、resource/actor、事务、拒绝与成功边界；建立 action 到生产调用点及测试的对照表，标明 feature grant 仅诊断与无 repo ID 的迁移失败边界。
- [x] 1.4 先扩展最少的现有测试，建立 disabled/shadow 原生结果一致、code unit 隐藏、Admin/Owner 分离、凭据限权和现有企微管理 guard 的失败断言；采用测试先行逐片实现，不一次性写完后补测试。

## 2. 配置与 action 合同

- [x] 2.1 在 `modules/setting` 增加 authz 三开关的严格解析与 disabled/shadow 校验，任意 `ENFORCE=true` 拒绝；启用时检查数据库 audit，不依赖企微启用、不自动开审计或修复角色。
- [x] 2.2 测试缺省、合法/非法布尔、ENABLED/ENFORCE 组合、FAIL_CLOSED 两值、审计未启用和企微开/关；确认 disabled 路径不加载企业角色。
- [x] 2.3 建立 19 个稳定 repo action key 及 metadata（unit/可见性前提、风险、适用 context），只允许 allow effect；action 目录版本与内置角色使用显式 key，不用 wildcard。
- [x] 2.4 测试未知 action/effect、目录唯一性、unit 前提和 feature-grant 仅目录/诊断语义，更新 `custom/conf/app.example.ini` 默认及 shadow-only 注释。

## 3. 模型、显式 migration 与生命周期

- [x] 3.1 新增 `models/enterpriseauthz` 四表及唯一/查询索引，定义 scope、subject、role revision、scope_owner_id、observation ID 和受限快照字段；Go 新文件使用当年 copyright。
- [x] 3.2 在根目录 `modelmigration/` 使用实施时下一可用版本注册 additive migration，创建四表并 seed 八个内置角色及完整显式 allow 集；不回填绑定、不改 native access/membership/admin/SSH/token。
- [x] 3.3 增加模型与迁移测试：旧数据库升级、索引/seed 完整、重复/中断恢复、同名角色作用域唯一、相同绑定/observation 幂等、旧原生权限与企微状态逐项不变。
- [x] 3.4 实现 native user/team/org/repo 删除时 live 策略引用清理，保留留存期历史决策；repo 转移后按旧 scope_owner_id 排除旧绑定，不额外改动原生转移行为。
- [x] 3.5 验证成员撤除、team-repo 关系删除、owner 转移、源对象删除后的绑定失效与历史可解释性；在 PostgreSQL 验证 migration/唯一约束，SQLite 提供快速测试。

## 4. 角色/绑定管理与原生权限闭环

- [x] 4.1 抽取最小 native-only 管理 authority helper，复用 site-admin/企微 active bound authority、组织真实 owner、仓库 creator/真实 owner/超管规则；保留现有 repository guard 包装和审计，避免 service 循环依赖。
- [x] 4.2 实现 system/org/repo 自定义角色 CRUD 与复制快照；内置不可变、同 scope lower_name 唯一、原子权限替换、expected_revision 更新/删除、引用中删除 409。
- [x] 4.3 实现 user/team/org 主体绑定与解除，校验角色作用域、主体类型/存在性、team/org/current owner 边界；PUT 幂等，Platform Admin 仅系统级管理绑定，不改变 IsAdmin 或企微 authority。
- [x] 4.4 将管理变更与白名单 before/after 管理 audit 同事务提交，校验 required persistence；锁定引用并传播事务 context，避免并发删除悬空绑定和角色更新丢失。
- [x] 4.5 测试 creator/owner/可信超管/非企微原生 admin 正例，以及普通用户、普通 site admin、跨 scope ID、Platform Admin 自举、内置 mutation、错误 subject 的负例；shadow 角色不能放行管理 service。
- [x] 4.6 增加并发及故障注入测试：同 revision 竞争一个成功/一个冲突、角色更新与绑定/删除竞争、审计写失败整次回滚、不出现半套权限或假成功审计。

## 5. evaluator、原生映射与条件

- [x] 5.1 实现凭据感知 native Permission 到默认 action 的映射，区分 code/PR/Actions unit、Read/Write/Admin/Owner、公开匿名和受限 synthetic actor；不按裸 user ID 扩权。
- [x] 5.2 实现一致读策略快照与当前 user/team/org 解析、scope/owner 匹配和 allow-only 叠加；不使用跨请求缓存、不写 native access 或创建可见性。
- [x] 5.3 实现严格条件 DTO 与 glob 校验：字段间 AND、候选 OR、all-path、完整非空路径集、受信 request source、未知字段/无效模式/大小上限；缺 context 只贡献 unresolved，不补外部请求。
- [x] 5.4 实现确定性 allow/deny/error、reason、matched roles/bindings、missing action、native/role 来源、revision/安全快照；标识 candidate_only 与 safety_guards_evaluated=false，错误不降级为空角色。
- [x] 5.5 编写表驱动单测覆盖八个角色、原生 unit/AccessMode 组合、重复绑定、直接/团队/组织叠加、不可见私仓、禁用/受限/匿名用户和 synthetic credentials；确认 allow-only 不撤销原生 writer 的权限。
- [x] 5.6 测试 branch/source AND、all-path 混合路径、空/未知/超限上下文、未知 action/condition、稳定排序/原因、policy-read 故障和角色并发更新的一致快照。

## 6. 决策证据、审计查询与留存

- [x] 6.1 实现独立于业务事务的 decision+audit 原子持久化和安全关联；观测前捕获 candidate/资源快照、业务事务后填 native outcome，不在业务锁内追加证据事务。
- [x] 6.2 实现 operation/observation ID 的受信生成传播与去重，保留 native success/denied/failed/unknown 与 native_stage；仅确定结果计算 mismatch，不将 credential guard 成功冒充传输完成。
- [x] 6.3 实现 200ms 观察评估/证据预算、64 KiB snapshot 上限、有界错误日志/计数；超时/取消/内部失败只报告缺口、不改变原生返回，显式诊断/管理错误如实返回。
- [x] 6.4 新增 audit action/message/export 的白名单字段与安全原因，使用条件指纹/匹配摘要，不输出 raw error、secret/token/code/provider 字段、HTTP body 或私密路径原文。
- [x] 6.5 实现作用域约束的 decision list/detail、actor/repo/action/decision/time filters、分页最大 100 与 X-Total-Count；复用 audit retention cleanup 同步分批清理决策，0 保留全部。
- [x] 6.6 测试业务回滚后证据存在、证据事务失败无半关联、同 observation 去重/不同操作不合并、超时/取消/快照超限、日志计数告警、角色变更后历史解释、留存和已删除 repo 仅系统管理员可查。
- [x] 6.7 用含 secret/token/OAuth code/callback URL/手机号/邮箱/私密路径的故障输入检查日志、audit、decision、API 所有出口，不通过禁用 lint 或吞错规避脱敏断言。

## 7. API-only 管理与诊断

- [x] 7.1 增加 system/org/repo authz 路由与 structs/Swagger DTO，覆盖 action catalog、role CRUD、binding list/PUT/DELETE、decision list/detail；scope 由 URL/资源决定，不接受 body 扩大范围。
- [x] 7.2 接入 tokenRequiresScopes/reqToken/原生 authority 与 authz enabled gate，service 再校验 authority；明确 401/403/404/409/422/500 与 201/200/204，disabled 在原生权限检查后 404。
- [x] 7.3 实现 repo effective-permissions 自查和 POST evaluate 诊断，按 HTTP 方法使用 read/write token scope；查询他人需管理权限，request_source 固定 diagnostic，解释裁剪其他主体和完整策略快照。
- [x] 7.4 增加真实路由测试：无 token/不足 scope、普通 reader 自查、管理角色各正例、普通 site admin 拒绝、跨 scope ID/filter、body actor/scope 欺骗、超限输入、disabled、revision/引用冲突与存储错误；无 UI 或新登录入口。
- [x] 7.5 更新各 route 的 Swagger 注解与 DTO 注册，运行 `make generate-swagger`、`make swagger-validate`、`make lint-swagger`，核对方法、分页、权限、错误与 candidate-only 契约一致。

## 8. 真实操作观察切片

- [x] 8.1 实现不返回授权布尔值的 Observe adapter，disabled 快速退出；共享受信上下文、原生 permission/凭据 ceiling 与 observation ID，不读取客户端自由 actor/source，不以 URL 推断 action。
- [x] 8.2 接入 Web/API repo metadata/code 读取；扩展现有读测试，验证真实记录、private/code-hidden 拒绝不泄露、disabled 无企业 DB 访问、shadow 响应不变。
- [x] 8.3 接入 Git HTTP/SSH upload-pack clone/fetch；覆盖用户 key、PAT、Git HTTP token 与 deploy key，验证凭据引用、source、native unknown/stage 与实际认证结果一致。
- [x] 8.4 接入 Web/API 分支与 file editor、Git HTTP/SSH receive/pre-receive 的普通/保护分支 action；覆盖多 ref、失败 ref、受限 key/token、CODEOWNERS 子 observation、路径未解析及去重，不把 tag 当 branch。
- [x] 8.5 接入 Web/API PR 创建与 review；复用现有测试确认 native guard/status/body/副作用不变，actor 与 target repo 正确，企业 Reviewer 不能绕过原生拒绝。
- [x] 8.6 接入 Web/API/auto/force merge 的共享 service 及安全可见原生拒绝分支；验证 candidate allow/native deny 与 candidate deny/native allow，所有原有分支保护/required-check/bypass 语义不变。
- [x] 8.7 接入分支保护/CODEOWNERS、webhook、CI/required-check/Actions 设置、secret 管理；覆盖 Web/API 正负例和审计脱敏，不引入 feature grant 或读取 secret 值。
- [x] 8.8 接入 migration target 已有 ID 的观测、transfer/archive/delete shared services 与可安全观测的拒绝分支；测试转移/删除前 snapshot、回滚及异步边界，不伪造未创建 repo 的决策。
- [x] 8.9 在每类入口注入 evaluator/decision/audit 故障，对比 disabled/shadow 的响应、权限、事务与副作用；复核 action-to-hook 清单，除明确后续 feature grant 外不留仅 diagnostic 的实现缺口。
- [x] 8.10 按 2026-10-01 用户批准补齐目标创建前的迁移失败安全审计：API/Web/task 实际路径、用户/系统归属、安全原因/阶段、去重/预算/独立事务、disabled/存储故障不改原生结果；不伪造 repo 决策、不记录 URL/凭据/原始错误，复用查询/导出/留存并验证。

## 9. 兼容回归与运维文档

- [x] 9.1 扩展或运行既有 EnterpriseWeCom LOGIN_ONLY 集成/smoke：本地密码、注册、OpenID、Passkey、其他 OAuth、反代和跨平台 SSPI 前置拒绝与合法企微 MFA 续接在 authz disabled/shadow 两模式一致；验收只针对 Linux 服务端，不执行或要求 Windows 原生回归。
- [x] 9.2 回归正常/禁用/受限用户 SSH key、PAT/API token、Git HTTP token 创建、认证、scope、吊销与原生 repo action 结果；shadow 不调用企微 OAuth、不撤销凭据、不扩权 Actions/deploy key。
- [x] 9.3 回归既有超管保护、只读企微 UI、组织审批/private/quota、受管 team 与 collaborator/team 授权变更 guard；新增角色管理不能改写 native membership 或管理员状态。
- [x] 9.4 新增 `docs/enterprise-authz/authz-shadow-runbook.md`，说明配置预检、audit 依赖、默认角色/API 权限、诊断与真实记录区别、容量/200ms/留存、缺口告警、升级/关闭及完整备份回退演练。
- [x] 9.5 更新企业授权 implementation/config 文档的当前进度与候选授权边界，不把未来 enforce/feature/merge gate 宣称已完成；保留 roadmap 的既有用户修改，仅在获授权范围同步实际变化。

## 10. 最终验证与交付

- [x] 10.1 运行新增/受影响包的最快针对性测试：`go test -run '^TestName$' ./modulepath/`，以及针对真实入口的 integration 测试；以确定条件同步并发测试，不用 sleep 掩盖竞争。
- [x] 10.2 在 PostgreSQL 验证迁移重试、角色引用锁/版本竞争、一致读快照、管理审计回滚、独立 shadow 事务、查询索引/留存；SQLite 单测为快速补充，不宣称未测试的其他 DB 兼容。
- [x] 10.3 实际运行 `make fmt`、`make lint-go`、Swagger 检查与改动 Markdown lint；如改 go.mod 运行 `make tidy`，若意外涉及 JS/CSS/templates 执行相应 lint，不运行无关破坏性清理。
- [x] 10.4 逐条核对 delta spec、19-action 目录、八角色、三主体/三 scope、权限矩阵和全部真实入口；审查最终 diff，无 placeholder/mock/enforce 分支、生产不可达、敏感字段或无关修改，记录实际验证及不能验证项。
- [x] 10.5 运行 `openspec validate add-enterprise-authz-foundation-shadow --strict` 并记录证据，完成配置关闭与恢复演练；仅在真实验证后勾选实施任务，不提交、推送或归档，除非用户另行要求。
