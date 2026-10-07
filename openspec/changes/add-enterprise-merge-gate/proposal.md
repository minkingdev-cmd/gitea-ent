## Why

当前企业 action enforce 与 feature grants 已接入真实业务，但 PR 合并判断仍分散在路由、分支保护与 worker 中，缺少统一的敏感路径审批、外部必选检查消费和可追溯决策快照。本提案落实企业授权路线图 Proposal 5，把“有权合并”和“当前 PR 满足合并条件”分开，形成一致、可解释的合并门禁。

## What Changes

- 新增统一 merge gate，聚合当前 actor/凭据、`repo.merge_pull_request`、PR 功能可用性、分支保护、审批、CODEOWNERS、required checks、敏感路径、draft/依赖阻断/未解决讨论及原生 Git/签名守卫。
- 新增 global/org/repo 敏感路径规则及受权 API，按当前仓库 owner 解析上级规则，多规则累加；命中路径必须满足对应 CODEOWNERS 或指定角色审批，并满足规则指定的 checks。不硬编码默认敏感路径，也不自动应用治理模板。
- 消费现有 feature-required contexts 与 Woodpecker、SonarQube、Semgrep、Gitleaks、Trivy、AI Review 的原生 commit status；缺失、pending、失败或错误不能冒充通过，不在进程内执行扫描/推理或下发供应商 token。
- 统一 Web/API/shared service/auto merge 的预览与实际写前评估，覆盖 force、手动标记和后台识别；预览、排队与旧 head 的 allow 均不是执行票据。
- 根据用户确认，增加独立 `repo.bypass_merge_gate` action、必填理由与有限豁免清单，仅可豁免审批、CODEOWNERS、required checks、敏感路径条件；必须同时满足原生 bypass 资格。auto merge 禁止 bypass，账号/凭据/merge action/功能禁用/分支准入/Git 冲突等不可豁免。
- 增加 `repo.manage_sensitive_paths` action、版本化规则管理及原子变更审计；新增 `enterprise_protected_path_rule`、`enterprise_merge_gate_evaluation`，区分候选决策、实际准入与执行终态。
- 提供 PR merge box 阻断解释、bypass 理由输入和安全 reader API；原始规则与完整历史快照仍受管理 authority 约束，不借 action 扩大管理员 UI 或上级策略可见性。
- 默认门禁关闭，支持 shadow 与显式 enforce。**BREAKING（仅启用 merge gate enforce 时）**：新增治理条件可拒绝原本可执行的 merge；force 必须具备独立 action 并提供理由，不再整体跳过治理条件。门禁错误与证据失败严格 fail-closed，不继承 action 基础设施 fail-open。
- SSH key、PAT/API token、Git HTTP token 的创建、签发、认证、scope 和吊销不变；仅 PR 合并授权可收紧。直接 Git push 继续受既有 receive/保护分支守卫，事后识别不宣称能阻止已经发生的 push。
- 不实现外部任务调度、供应商凭据、策略模板、offboarding、新登录路径或敏感路径直推子系统；仅 Linux 服务端部署与验收，企微唯一 Web 登录/MFA、关闭 callback、合法登录刷新与完整定时同步不变。

## Capabilities

### New Capabilities

- `repository/enterprise-merge-gate`：统一评估、敏感路径、外部 checks 消费、有限 bypass、真实执行边界、快照审计和安全展示。

### Modified Capabilities

- `authorization/enterprise-repo-actions`：扩展稳定 action 目录，增加敏感路径管理与独立门禁 bypass 的授权、默认角色 seed 和历史版本兼容。

该授权能力尚在 foundation/enforce change 的 delta 中，未同步到 main specs；本提案承接磁盘上的最新合同，不修改前序 artifacts。正式 sync/archive 必须先按依赖顺序建立其 main spec。feature grants 的 13-key、继承和 `policy_only` 合同不改；本能力作为新增消费者，不宣称外部执行已经实现。

## Impact

- 依赖已交付的 `add-enterprise-authz-foundation-shadow`、`enforce-enterprise-authz-high-risk-actions`、`add-enterprise-feature-grants`；实施前核实代码、迁移与验证证据，任务全勾选不等于生产验收。后台身份治理与未完成 callback 启用工作不纳入本提案。
- 主要影响 `models/enterpriseauthz`、`modules/enterpriseauthz`、`services/enterpriseauthz`、`services/pull`、`services/automerge`、Web/API 路由、DTO/Swagger、PR merge 模板、locale 和审计记录；保持浅 fork，不给 PR/Issue 核心模型增加策略字段。
- 使用 Gitea `modelmigration/` additive 迁移建立两表、索引及新 action seed；不改旧 migration，不引入 Flyway、OpenFGA 或 Keycloak。默认角色扩展仅 Owner/Platform Admin；既有自定义角色不隐式扩权。
- 需要独立配置/启动预检、Linux SQLite/PostgreSQL 验证、故障/并发/协议回归与上线回退手册。本轮只创建本 change 的规划 artifacts，不执行迁移、部署、实施、提交、推送、主 spec 同步或归档。
