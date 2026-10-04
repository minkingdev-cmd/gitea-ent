## 1. 基线、调用者与验收清单

- [x] 1.1 核对 foundation/UI 的当前源码、delta specs、verification、migration 与 Linux 验收证据；记录 main specs 尚未同步及依赖归档顺序，不修改前置交付记录。
- [x] 1.2 在本 change 建立当前 entrypoint-matrix：列 Web/API/service/HTTP/SSH/internal/auto/system 的 actor、credential ceiling、目标意图、native guard、锁/首个副作用/终态、所需 actions 与现有测试。
- [x] 1.3 盘点 collaborator/team bulk/permissions/unit/includes-all/删除调用链及无 actor 调用者，列明受信系统白名单与全部受影响现有 repo 集合；明确普通成员维护/目录同步不是新增产品授权入口。
- [x] 1.4 建立 mode×action×角色/凭据×故障矩阵；区分实际可达的企业 deny 与原生 deny，明确 merge/Admin settings 的并集不能撤销已有 native capability，排除不可能的负例。

## 2. Catalog、配置与版本化迁移

- [x] 2.1 先扩展 catalog/native/config 测试：manage_access、11-action enforce 固定集、默认 disabled、非法布尔及 disabled+enforce 拒绝、shadow/enforce 的审计与预检要求。
- [x] 2.2 实现 catalog v2、manage_access（native Owner-only）、enforce_supported 与配置三模式；保持低风险/migrate shadow、feature grant 仅诊断，maintainer/security-maintainer 不新增授权委派能力。
- [x] 2.3 新增下一可用 `modelmigration/` migration：决策 mode/实际授权/原因/执行标志、旧记录 shadow 标记，以及仅内置 owner/platform-admin 的 manage_access seed；不修改 v361、原生权限/成员/凭据或回填绑定。
- [x] 2.4 更新 readiness/fixtures，验证新安装、已有库升级、重复与中断恢复、旧策略/历史 ID 和内容保留；分别实跑 SQLite 与 PostgreSQL migration 测试。
- [x] 2.5 补 catalog v1/v2 历史安全解码测试与实现，未知版本拒绝；记录内置 revision=1/catalog_version 的兼容合同，验证旧二进制 exact-seed 回退限制。

## 3. 执行准入、错误和证据

- [x] 3.1 写统一执行 guard 的 RED 测试：disabled 零策略读、shadow 不阻断、enforce deny/allow、Owner/当前超管、显式角色与 native guard 交集、NativeOnly 与受限凭据不扩权。
- [x] 3.2 实现多 action 一致快照准入，当前 actor/repo/owner/成员/权限与 credential ceiling 不使用旧 handler permission；绑定实际 intent 的私有 handle，observer/diagnostic/owned 不充当许可。
- [x] 3.3 实现 1s 总预算、paths1024/repo1000 上限与取消；测试撤销准入前生效、准入后已进行操作不承诺即时取消、目标 owner/ref/SHA 变化需要重建，不跨请求缓存 allow。
- [x] 3.4 写并实现缺权403、基础设施默认503、显式 false 仅原生 fallback 的分类；测试明确 deny 优先、无效身份/上下文/ticket/不完整差异/超限/取消永不 fail-open，原生 guard 自身错误不降级。
- [x] 3.5 实现准入 decision+关联 audit 原子独立写与真实终态更新；测试 deny/error 未执行、先证据后 mutation、业务回滚不删证据、后置证据失败不改变真实成功响应或虚构回滚。
- [x] 3.6 实现 operation/action/target 去重及安全缺口指标/告警；测试不同重试/ref/目标不复用授权，全存储故障不伪造审计，凭据/路径/diff/body/原始错误不出现在记录和响应。

## 4. Merge 实际执行闭环

- [x] 4.1 扩展真实 Web/API 普通 merge 用例并接共享 service 写边界，验证 action 允许仍保留 checks/review/保护/SHA/native guard，拒绝无 ref/PR 状态/通知副作用。
- [x] 4.2 接 auto 排队/后台执行，在实际执行重新加载 doer 当前资格/政策与受信来源，不保存长期 allow；覆盖排队后 native 权限/绑定/成员撤销、终态与安全错误。
- [x] 4.3 接 force/manual 与 `MergedManually` 状态 mutation，覆盖原 force 资格/守卫不可扩权、manual 无许可不写状态，证据不是“排队即成功”。
- [x] 4.4 在受信最终合并 diff 识别 CODEOWNERS，统一 merge+manage_codeowners 准入；测试新增/修改/rename/delete 与失败无副作用，内部 merge push 不另要求保护分支直推权限。

## 5. Git、文件与分支防旁路

- [x] 5.1 写真实 SSH/Git HTTP 多 ref protected push RED 测试（创建/更新/删除与普通 branch/tag 混合），实现 pre-receive 全部受控 refs 的副作用前准入，拒绝不留下部分 refs。
- [x] 5.2 用 quarantine 的实际 old/new diff 接外部 receive CODEOWNERS action；覆盖三个受支持路径、rename 两端、删除、binary 和普通分支修改，git author 不替换 actor。
- [x] 5.3 实现 HTTP/SSH→private hook 的可信 actor/ceiling/source 归因与执行边界；测试 ticket 伪造/过期/错 repo/旧 shadow/owned 不授予 allow，策略变更后当次重新检查。
- [x] 5.4 接 Web/API editor/批量 file/上传/递归删除、patch/cherry-pick/revert 的 push 前 guard；补完整真实 diff，覆盖 CODEOWNERS 与 protected 目标，内部 hook early-return 不能绕过。
- [x] 5.5 接 branch create/delete/rename、PR head update、fork sync 等其余内部高风险 ref mutation；测试普通 branch、tag/wiki/AGit 创建保持原生，实际受控差异不能借非 merge 入口绕过。
- [x] 5.6 覆盖超限/无法解析差异/取消/Git 子进程失败、原生保护/签名/文件守卫拒绝；验证预算、操作关联/去重及 post-receive 只记真实终态，不事后补授权。

## 6. Settings 与 CI/secret/webhook

- [x] 6.1 扩展 Web/API branch protection CRUD/priority/敏感文件规则测试并接 guard；required checks 的有效修改统一要求 protection+CI，非变更不伪造 CI action。
- [x] 6.2 接 repo webhook CRUD，并覆盖 native 禁用/URL/对象限制、scope、可见性与真实提交；org/user/system helper、test/replay/投递不冒充 repo 管理变更。
- [x] 6.3 接 repo secret 写入/删除并覆盖 Admin 缺 action 403、Owner/显式授权正例、unit/scope/native 限制，日志/decision/UI 不读取或泄露 secret。
- [x] 6.4 接 CI unit/token permissions、变量、runner 注册/编辑/删除/开关与 workflow enable-disable；覆盖正确 repo scope/native guard，dispatch/run/cancel 不是 manage_ci mutation。
- [x] 6.5 在 Web/API 复合 Edit/设置请求首个业务写入前收集并准入全部高风险 actions；测试 CI+archive 等缺一项时全部状态/通知不变，bind/validation/native 隐私错误不回归。

## 7. Manage access 与系统维护

- [x] 7.1 接 Web/API collaborator 添加/修改/删除，shared service 携带真实 actor/ceiling；覆盖无 manage_access403、native Owner/自定义角色正例、reader 角色不升 Admin 与企微治理负例。
- [x] 7.2 接 Web/API team-repo 增删、bulk 关联，以及 org team permissions/unit/includes-all/删除引起的授权变更；先对全部受影响 repo 一致准入，再提交原事务，任一拒绝无部分写入/重算/通知。
- [x] 7.3 为明确维护调用点实现私有 typed context 和审计归因，覆盖企微生成团队/同步、维护清理、新仓库初始化/迁移；nil actor/system 字符串/header/未知 caller 不构成豁免。
- [x] 7.4 验证默认 seed 只给 owner/platform-admin 新 action，旧自定义复制角色不变；manage_access 和企业 Platform Admin 不授予 role/binding API 或管理 UI authority。

## 8. 生命周期与转移

- [x] 8.1 接 transfer start/accept/reject/cancel，准入当前 actor/旧 owner/目标 intent；覆盖接收者缺 action、申请后政策/成员变更、目标团队/配额/治理原生失败与旧绑定转移后失效。
- [x] 8.2 接 Web/API archive/unarchive，在状态/Actions schedule 等首个副作用前检查；覆盖 Owner/角色与 native mirror/danger-zone，保留真实事务与失败语义。
- [x] 8.3 接 Web/API/shared delete 的删除及通知前边界，系统清理走明确受信适配；验证拒绝无磁盘/对象/通知变更，成功清 live 引用但保留历史，业务回滚与证据更新故障不误报。

## 9. 兼容 API 与既有管理 UI

- [x] 9.1 扩展 catalog/decision DTO、mode/authorization filters 与白名单解析，保持旧字段、token scope、范围校验与每页最多100；诊断永为 candidate-only，历史支持 catalog v1/v2。
- [x] 9.2 扩展原管理 UI 的列表/筛选/详情和后端展示合同：shadow/enforce/fallback、实际准入、未执行与 unknown；不新增开关/入口或浏览器授权逻辑，仅更新 locale_en-US.json。
- [x] 9.3 扩展 UI/API 集成及必要 E2E：超管正例、非超管/过期 authority/角色伪权403、CSRF、篡改 filter/id404、名称选择、旧/删除 repo 历史、坏快照/XSS、暗色主题与键盘。
- [x] 9.4 验证原业务按钮/提示与后端准入一致，native settings 可达边界不为角色放宽；action 信息从后端目录获取，界面不将候选 allow/授权 allow 显示为业务成功。
- [x] 9.5 执行 make generate-swagger、make swagger-validate 及相关 API 合同测试，记录追加字段/过滤与403/503说明，不改变认证协议。

## 10. 兼容回归、上线与最终验证

- [x] 10.1 扩展并实跑禁止 Web 登录路径（本地密码/注册/OpenID/Passkey/其他OAuth/反代/SSPI）的确定性回归，以及合法企微/MFA续接；Linux 服务端验收，callback 持续关闭。
- [x] 10.2 实跑 SSH/PAT/API token/Git HTTP 的创建/认证/scope/吊销/账号状态回归、Actions/deploy NativeOnly 与 read-only 负例；disabled/shadow 比对原生结果，enforce 仅收紧规定高风险授权，不调用企微OAuth。
- [x] 10.3 对全部入口族实跑 allow/企业deny（适用且实际可达）/native deny/业务失败/证据故障/预算及并发矩阵；SQLite 快速测试与 Linux/PostgreSQL 事务/真实 HTTP/SSH/Git 验证分别记录，不以 macOS 或 mock 替代 Linux验收。
- [x] 10.4 更新 app.example.ini 与企业授权文档，新增 enforce runbook：原生并集限制、差异审查/显式授权、准入与证据字段、503/403/Git原因、降级窗口、统一实例配置和观测指标；保留旧交付时间线。
- [x] 10.5 在独立验证环境演练同新版 enforce→shadow→disabled 回退、schema/seed/历史保留、pending transfer/auto 重新检查及二进制兼容/备份恢复；不得降schema、手改seed、改生产配置或打开callback。
- [x] 10.6 Go修改运行 make fmt、make lint-go；UI修改运行相应 lint-js/lint-css/lint-templates；只按适用变更运行 build/Swagger/测试，失败修原因不弱化测试，Go新文件加入实施年份版权。
- [x] 10.7 逐 requirement 核对 spec/入口矩阵/任务与实际验证，审查最终 diff，无漏接/placeholder/无关修改；记录命令、退出码、测试环境、UI截图、真实限制与恢复证据于本 change verification。
- [x] 10.8 运行 openspec validate enforce-enterprise-authz-high-risk-actions --strict 与最终 status；仅验证实施通过后勾选任务，主 specs 同步/归档须先处理 foundation/UI 依赖且另获用户授权，不提交/推送/发布。
