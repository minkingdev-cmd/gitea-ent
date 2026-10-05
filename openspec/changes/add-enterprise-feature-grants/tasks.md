## 1. 基线与真实入口清单

- [x] 1.1 复核 foundation/shadow、high-risk enforce 与现有管理 UI 的代码及验收证据；确认下一正式 migration ID，记录当前 Linux/schema/catalog 基线，不修改前序迁移/验收文档。
- [x] 1.2 建立 feature-to-hook 清单，盘点 Web/API/service/worker/Git/package protocol、搜索/feed/export、AGit/auto merge、repo unit 及生命周期调用者；为每类维护/初始化来源记录明确边界，不允许通用 system 旁路。
- [x] 1.3 将本 change 全部 Requirement 映射到下列切片及预期验证，确认仅 13-key/global-org-repo、无 UI/外部执行/完整 merge gate/认证改造，实施时每切片先测试再接线再定向验证。

## 2. 功能目录、模型与正式迁移

- [x] 2.1 添加完整 13-key 定义与 native_gate/policy_only metadata、四态及 supported scopes，更新 manage_feature_grant 的真实能力标记并扩展目录测试；不扩大内置角色 action 集。
- [x] 2.2 添加两张功能表、scope/key/state 校验、唯一约束、grant revision 与 definition policy_revision；覆盖 invalid scope/resource、重复键与 revision 操作模型测试。
- [x] 2.3 在 modelmigration 添加新版本正式 migration/seed，同步新安装路径；覆盖旧 DB 升级、空库安装、重放、非覆盖管理员 grant/unit/旧决策和唯一索引测试，不使用 startup-only 修表。
- [x] 2.4 扩展 enabled preflight 的表/索引/完整目录/schema 校验；测试缺表、缺 seed、seed drift 拒绝与 disabled 不读功能表；补充 app.example.ini 和已有开关含义，默认值不变。

- [x] 2.5 经批准增加可信 Cargo 索引用途正式 schema/new-install 迁移、服务内部创建与 Stable ID lookup、旧索引受控 authority+确认 CLI 认领与 enabled preflight；覆盖普通同名仓库、rename、唯一用途及原子审计，不按名称自动认领。

## 3. 纯解析器与配置合同

- [x] 3.1 用表驱动失败测试覆盖全四态 global/org/repo 组合、personal owner、缺记录/default fallback、第一祖先锁、父级修改后的下级冲突及 inherited 清除，再实现确定性解析器。
- [x] 3.2 实现严格 config/request 解析与 canonical contexts，覆盖重复/未知/null/非法 UTF-8/尾随 JSON、大小/项数/字符限制、secret/URL/命令字段拒绝和脱敏错误。
- [x] 3.3 实现无锁最近配置替换与 required contexts 并集；覆盖空配置/inherited、被 disabled 锁遮蔽的下级 required、必选 contexts 不丢失、稳定 hash/schema version 测试。
- [x] 3.4 实现真实 current-owner 的一致 snapshot 查询及 reader/admin 投影；覆盖 native unavailable/pending、chain/conflict 明细、reader 无 config/上级 ID/actor 泄露，不添加跨请求缓存。

## 4. 管理 service、权限与并发

- [x] 4.1 实现 global/org/repo 真实 authority、相应 credential scope/ceiling 和 repo manage_feature_grant 检查；覆盖非企微/企微超管、org owner、repo Owner、具备既有 authority 的自定义 action 角色、假超管/失效 actor/只读/public-only/跨 scope 负例。
- [x] 4.2 实现 PUT/CAS 与 DELETE inherited-reset service、expected_revision=0 创建、单调版本及同版本无变幂等；覆盖 stale writer、reset/recreate ABA、no-op 不增 revision/成功审计测试。
- [x] 4.3 统一资源/authority → 排序 feature-definition 的事务锁顺序，事务内复核 owner/authority/action/父级锁，再更新 grant 与 policy_revision；用真实双连接测试父子写入和创建唯一键竞态。
- [x] 4.4 实现 grant 数据与 required audit 原子提交及安全事件；注入 DB/audit/authority 故障确认 grant/revision/审计回滚，grant 管理不得使用 fail-open。

## 5. API、DTO 与 Swagger

- [x] 5.1 按设计权限矩阵添加 global 目录和 grants API、org list/single API、repo effective list/single 与 raw-grant API；严格输入、分页、服务端 scope 解析、405/401/403/404/409/422/安全存储错误保持一致。
- [x] 5.2 添加真实路由集成测试，覆盖管理员/组织 owner/仓库 authority 正例、自定义 action 正例、scope 不足/非管理 reader/匿名/失效身份/伪造字段负例，以及 disabled 404、shadow 不跳过 grant 管理权限。
- [x] 5.3 覆盖 reader/admin DTO 隔离、原始 absent grant revision=0、inherited reset/no-op、unknown key 查询与写入、source/conflict/pending/policy_only 返回值及旧 decision DTO 兼容。
- [x] 5.4 补充 Swagger 注释、请求/响应和错误合同，运行 make generate-swagger 与 make swagger-validate，校验对应 Swagger/OpenAPI 生成物，无 API 仅文档占位。

## 6. 原生模式检查与 repo unit 配置

- [x] 6.1 实现共用 feature 业务 guard 与真实 action 准入的组合：disabled 无查询、shadow 只观测、enforce explicit deny、fail-closed 设施错误和显式 native fail-open；测试候选/实际结果及非事务准入边界。
- [x] 6.2 接入完整 repo unit/config 最终 intent（Issues/PR/Wiki/Packages），不是先删后插的中间状态；测试 disabled 无法开启、required 无法关闭、其他字段更新、复合设置拒绝零副作用和无自动补 unit。
- [x] 6.3 将配置事务与 feature-definition 锁统一；用真实并发 parent required/disabled 更新与下级 unit 更新测试准入顺序，确认无部分提交或死锁，并覆盖 repo 创建/导入/镜像初始化的真实调用路径。

## 7. Issue、PR 与 Wiki 真实业务

- [x] 7.1 接入 Issue Web/API/detail/comment/write 与 shared services；按 IsPull 等真实业务类型独立选 key，测试 Issue disabled/PR enabled 及反向组合、原生 permission/unit 不扩权。
- [x] 7.2 接入 PR Web/API/create/review/AGit 与实际 auto/force/manual merge/后台执行；覆盖排队后禁用、当前 repo owner 变化及 deny 前零数据库/Git 副作用，不新增外部 scan merge gate。
- [x] 7.3 接入 Wiki Web/API/read/write/export/external 跳转和 Wiki Git HTTP/SSH；覆盖 disabled/required/native unavailable，真实协议拒绝与主代码 Git 操作不受误禁。
- [x] 7.4 接入 Issue/PR/Wiki 列表、搜索、feed/export/通知及后台入口的批量过滤，在分页/计数前检查；覆盖禁用内容无摘要/数量泄露及无逐行 N+1 回归，完成相应真实 Web/API/service 验证。

## 8. Package registry 与 Webhook

- [x] 8.1 实现 package 真实 owner global/org 和关联 repo 解析；接入上传/追加文件的共享写 service 与关联/重新关联/脱离变更，覆盖个人/组织未关联包、旧新关联 scope 和禁用前零持久化副作用。
- [x] 8.2 接入 registry 各协议的下载/列表与仓库 Packages 展示，不改原生认证/scope；按 protocol 清单验证覆盖，共享 guard 用 unit 验证、协议适配用少量真实集成测试；保留合法删除/cleanup，防脱离 repo 绕过。
- [x] 8.3 接入 repo/org/system webhook 管理与 test/redelivery/入队，保留原生受权停用/删除；覆盖 repo-origin 的 org/system hook 不能绕过 repo 禁用及纯 org/system 事件真实 scope。
- [x] 8.4 在真实 worker/Deliver 发送前恢复可信来源并重判 owner/策略，覆盖入队后撤权、转移、重放和 DB 设施故障；断言实际不发送且 skipped/denied 不记 delivered success，不假造 Woodpecker 接线。

## 9. Secret、required checks 与外部策略输出

- [x] 9.1 接入 repo/org CI secret 的 Web/API 管理与 shared service，覆盖 disabled 新增/更新/复制/管理读负例、合法删除/吊销正例、required 不强制创建以及 runner 正常消费不变。
- [x] 9.2 接入 branch protection 完整 old/new checks intent、删除/批量/priority 变更；覆盖 disabled 不改检查且不解除保护、required 禁关闭/删规则/删 mandatory contexts、合法加强、其他字段可改与 native/action guard 保留。
- [x] 9.3 为六个 external policy_only keys 验证四态、全局 mandatory Gitleaks、contexts 输出与继承/审计；断言无外部扫描/AI/token 下发/status 伪造/新增 merge deny，不把 Woodpecker 当 Actions，不丢弃外部 status 回调。

## 10. 生命周期、审计兼容与旧 UI 说明

- [x] 10.1 接入 repo/org 删除的 grant 清理及 repo rename/transfer 的 stable ID/current-owner 解析；覆盖删除不影响其他 scope/历史审计与转移后旧 org/缓存/队列许可不可复用。
- [x] 10.2 扩展 feature-specific scoped audit 与版本化决策 snapshot，区分 candidate/actual、native deny、feature deny、policy_only、infra fallback 和真实终态；global/org 不伪造 repo/action，历史缺字段保持可查询。
- [x] 10.3 同步 manage_feature_grant catalog/DTO 和现有 UI 帮助说明；维持系统超管 authority、不加 feature 开关，复用旧 UI smoke 并测试 XSS/字段脱敏；如需 locale 仅改 locale_en-US.json。

## 11. 兼容、安全故障与上线验证

- [x] 11.1 回归禁止的本地密码/注册/OpenID/Passkey/其他 OAuth/反代/SSPI Web 登录、合法企微/MFA；确认 callback 保持关闭、登录刷新/定时完整同步、本地 user subject 及现有组织仓库治理不变。
- [x] 11.2 回归 SSH/PAT/API token/Git HTTP token 认证、scope、吊销和普通代码 clone/push；单独验证 Wiki Git 的业务收紧不误禁主 Git，受限 Actions/deploy actor/runner 的原生权限和 secret 消费不变。
- [x] 11.3 对每类 native_gate 注入解析/DB/audit/cancel/timeout 故障，对比 disabled/shadow 原生响应与副作用，验证 enforce fail-closed、显式 infra-only fail-open、显式 deny 不降级及管理写入不可降级。
- [x] 11.4 在 Linux SQLite 与 Linux PostgreSQL 运行正式迁移/新安装、定向 unit/service/API/protocol/worker/并发集成及前序 EnterpriseAuthz 回归，记录真实命令/退出码；尽量扩展现有快速测试，用确定条件同步而不是 sleep。
- [x] 11.5 演练同新版 disabled/shadow/enforce 切换、保存授权历史及匹配完整备份恢复；验证旧 binary 不直接降 schema、多实例版本一致、原生 unit/checks 不被开关自动改写，不把本地演练宣称为生产部署。
- [x] 11.6 运行 make fmt、make lint-go、适用 JS/CSS/templates lint、Swagger 生成/验证与 git diff --check；只有修改 go.mod 才 make tidy，确认无无关变更及未经授权的跨仓/runtime/Git 写操作。
- [x] 11.7 更新功能授权 runbook、shadow/enforce 手册、implementation-plan/roadmap，包含 API/权限矩阵、migration/seed、required pending、13-key coverage、清理允许列表、故障/恢复与后续 UI/template/gate 边界。
- [x] 11.8 逐 Requirement 对照真实接线和验证证据，记录 verification.md，复查无占位/仅诊断冒充执行；运行 openspec validate add-enterprise-feature-grants --strict 与最终状态检查，获授权前不 commit/push/deploy/同步主 specs/归档。
