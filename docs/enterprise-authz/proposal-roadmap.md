# Enterprise Authorization Proposal Roadmap

## 目的

本文把当前企业微信治理盘点结果拆解为一组可独立评审、实施和验收的 OpenSpec proposal。目标是避免把企业内部使用所需的身份、组织、授权、门禁、模板和 UI 能力塞进一个过大的 change，而是按可上线边界逐步推进。

当前代码基线已经具备：企业微信唯一 Web 登录、企业微信身份绑定、通讯录同步、自动生成团队和成员关系、企业微信超管保护、组织仓库申请审批、私有仓库治理和部分仓库授权变更防护。后续 proposals 应优先补齐生产化运维边界，再进入细粒度授权和合并门禁。

## 拆分原则

1. **先稳固现有能力，再新增权限模型**：先修正配置、API 契约、callback、runbook 和失败语义，降低生产风险。
2. **一份 proposal 对应一个可上线边界**：每个 proposal 都应能独立验收，不依赖“大批量未完成能力”。
3. **shadow 先于 enforce**：新的企业授权 evaluator 先记录决策，不阻断请求；验证无误后再接入高风险入口。
4. **保持浅 fork**：优先叠加企业治理层，不深改 Git 存储、PR 基础模型、issue 基础模型或原生 token 认证机制。
5. **兼容边界必须显式写入 spec**：除 offboarding proposal 外，SSH key、PAT/API token、Git HTTP token 行为必须保持 Gitea 原语义。
6. **UI 后置**：先保证模型、service、API、审计和测试可靠，再建设管理界面。

## 推荐依赖关系

```text
harden-wecom-governance-ops
  └─ add-enterprise-authz-foundation-shadow
       └─ enforce-enterprise-authz-high-risk-actions
            ├─ add-enterprise-feature-grants
            ├─ add-enterprise-merge-gate
            │    └─ add-enterprise-policy-templates
            └─ add-enterprise-authz-admin-ui

add-enterprise-offboarding-policy  # 可选，需单独确认 token/SSH 语义变更
```

## Proposal 1：`harden-wecom-governance-ops`

### `harden-wecom-governance-ops`：目标

把已有企业微信治理能力收敛成可生产运行的稳定版本，不引入新的企业角色或合并门禁。

### `harden-wecom-governance-ops`：范围

- 增加显式 managed organization 配置，例如 `MANAGED_ORG_NAME` 或 `MANAGED_ORG_ID`，避免依赖“系统里只有一个组织”。
- 将个人仓库 quota 从硬编码 `10` 改为配置项。
- 增加企业微信 administrator callback Web/API 路由，完成签名校验、企业和应用边界校验，只接受支持的管理员变更事件。
- 清理或修正 Enterprise WeCom mapping API 与 Swagger：既然产品不支持手工维护 mapping，mutating API 应移除、隐藏或明确标记为不可用。
- 强化自动化 pipeline 的失败语义：目录同步、管理员权限刷新、生成状态和成员对账失败时不得清空上一份有效授权状态，不得提交部分授权变更。
- 增加运营 runbook：企业微信登录故障、超管身份异常、cron 失败、回滚 `LOGIN_ONLY`、离线恢复管理员。
- 补齐审计事件中的安全原因码，不记录 secret、access token、OAuth code 或私密通讯录字段。

### `harden-wecom-governance-ops`：非范围

- 不实现 repo action evaluator。
- 不实现 feature grant。
- 不实现 merge gate。
- 不改变 SSH key、PAT/API token、Git HTTP token 认证语义。

### `harden-wecom-governance-ops`：建议能力路径

- `identity/wecom-governance-ops`
- `organization/wecom-team-governance`
- `repository/single-org-repo-governance`

### `harden-wecom-governance-ops`：验收要点

- 未配置 managed org 时，自动化给出明确错误或保持禁用，不隐式选择错误组织。
- 企业微信 callback 只有签名和边界校验通过时才触发 authority refresh。
- mapping mutating API 与文档/Swagger 行为一致。
- 失败的自动化 run 不会删除已有有效 team membership 或 protected admin 状态。
- 有完整上线、回滚和故障恢复文档。

## Proposal 2：`add-enterprise-authz-foundation-shadow`

### `add-enterprise-authz-foundation-shadow`：目标

建立企业授权基础模型和 evaluator，但只运行 shadow mode，不阻断真实请求。

### `add-enterprise-authz-foundation-shadow`：范围

- 新增 `[enterprise.authz]` 配置：`ENABLED`、`ENFORCE`、`FAIL_CLOSED_ON_ERROR`。
- 定义 repo action vocabulary，例如：
  - `repo.view_metadata`
  - `repo.read_code`
  - `repo.clone`
  - `repo.create_branch`
  - `repo.push_branch`
  - `repo.push_protected_branch`
  - `repo.create_pull_request`
  - `repo.review_pull_request`
  - `repo.merge_pull_request`
  - `repo.manage_branch_protection`
  - `repo.manage_codeowners`
  - `repo.manage_webhook`
  - `repo.manage_ci`
  - `repo.manage_secret`
  - `repo.manage_feature_grant`
  - `repo.transfer`
  - `repo.archive`
  - `repo.delete`
- 新增企业角色和绑定模型：
  - `enterprise_role_definition`
  - `enterprise_role_permission`
  - `enterprise_subject_role_binding`
- 实现 evaluator：

```text
Subject + Resource + Action + Condition => Decision
```

- 将 Gitea 原生 Read / Write / Admin / Owner 映射为默认企业 action 集。
- 在 shadow mode 记录 allow / deny / missing action / reason，不改变请求结果。
- 写审计日志和可查询的决策记录。

### `add-enterprise-authz-foundation-shadow`：非范围

- 不阻断请求。
- 不实现 feature grant。
- 不改 merge 流程。
- 不实现 UI。

### `add-enterprise-authz-foundation-shadow`：建议能力路径

- `authorization/enterprise-repo-actions`

### `add-enterprise-authz-foundation-shadow`：验收要点

- 可以定义内置和自定义 repo 角色。
- 可以给 user/team/org/repo subject 绑定角色。
- evaluator 可以解析 Gitea 原生权限和企业角色叠加结果。
- shadow decision 可审计、可查询、可解释。
- 未启用企业授权时行为接近上游 Gitea。

## Proposal 3：`enforce-enterprise-authz-high-risk-actions`

### `enforce-enterprise-authz-high-risk-actions`：目标

在高风险写入口正式启用企业授权阻断。

### `enforce-enterprise-authz-high-risk-actions`：依赖

- `add-enterprise-authz-foundation-shadow`

### `enforce-enterprise-authz-high-risk-actions`：范围

首批接入入口：

- PR merge。
- protected branch push。
- branch protection 管理。
- CODEOWNERS / 敏感路径规则管理。
- webhook 管理。
- secret 管理。
- CI / required checks 管理。
- collaborator 和 team 授权变更。
- repo transfer / archive / delete。

### `enforce-enterprise-authz-high-risk-actions`：非范围

- 不覆盖所有低风险读路径。
- 不改变 Web 登录或 Git token 认证方式。
- 不实现完整 merge gate；这里只校验 actor 是否有对应 action。

### `enforce-enterprise-authz-high-risk-actions`：建议能力路径

- `authorization/enterprise-repo-actions`

### `enforce-enterprise-authz-high-risk-actions`：验收要点

- 未授权用户在高风险入口收到 403。
- 默认 Owner、企业超管、显式授权角色可继续完成对应动作。
- 审计日志包含 actor、repo、action、decision 和 reason。
- SSH/PAT/Git HTTP token 仍按原认证机制进入系统，只在具体 repo action 上被授权层判断。

## Proposal 4：`add-enterprise-feature-grants`

### `add-enterprise-feature-grants`：目标

实现平台功能授权，仅控制 global、org、repo 三层的可用、必选或禁用；个人仓库跳过 org，不引入 team/user/branch/role 作用域。

### `add-enterprise-feature-grants`：范围

- 新增：
  - `enterprise_feature_definition`
  - `enterprise_feature_grant`
- 支持状态：
  - `disabled`
  - `enabled`
  - `required`
  - `inherited`
- 支持继承解析：global -> org -> repo。
- 首批 feature keys：
  - `feature.issues`
  - `feature.pull_requests`
  - `feature.packages`
  - `feature.wiki`
  - `feature.webhooks`
  - `feature.woodpecker_ci`
  - `feature.sonarqube_quality_gate`
  - `feature.semgrep_scan`
  - `feature.gitleaks_scan`
  - `feature.trivy_scan`
  - `feature.ai_review`
  - `feature.ci_secret_management`
  - `feature.required_status_checks`
- 上级显式 disabled 不可下级开启，required 不可下级关闭；首个根向下锁获胜，旧冲突保留并投影。
- 七个 native_gate 默认 enabled；六个外部 key 默认 disabled 且仅 policy_only 输出，不执行 scanner/AI/status 或新增 merge gate。
- 提供真实 global/org/repo API、authority/action/credential 校验、reader/raw 隔离、CAS/reset 和原子审计；迁移 363 后 DB version 364，不重写原生 unit。

### `add-enterprise-feature-grants`：非范围

- 不实现完整 merge gate、外部 scanner/AI 执行、integration/token 自动创建；native_gate 仍须真实阻断对应 disabled 业务与 required 原生配置降级。
- 不实现 UI。

### `add-enterprise-feature-grants`：建议能力路径

- `authorization/enterprise-feature-grants`

### `add-enterprise-feature-grants`：验收要点

- feature state 可按作用域继承和覆盖。
- 上级 `required` 无法被下级关闭。
- 写操作有授权检查和审计。
- 未启用企业授权增强时，不影响 Gitea 原生 repo unit 行为。

## Proposal 5：`add-enterprise-merge-gate`

### `add-enterprise-merge-gate`：目标

实现统一 PR 合并门禁，将权限、分支保护、审批、required checks、敏感路径和外部安全/质量结果集中评估。

### `add-enterprise-merge-gate`：依赖

- 推荐依赖 `add-enterprise-authz-foundation-shadow`。
- 如果需要强阻断 merge action，依赖 `enforce-enterprise-authz-high-risk-actions`。

### `add-enterprise-merge-gate`：范围

- 新增：
  - `enterprise_protected_path_rule`
  - `enterprise_merge_gate_evaluation`
- 抽出统一 merge gate evaluator。
- 覆盖：
  - Web merge。
  - API merge。
  - auto merge。
  - force / bypass merge。
- 判断维度：
  - `repo.merge_pull_request`。
  - branch protection。
  - required approvals。
  - CODEOWNERS。
  - required checks。
  - sensitive paths。
  - feature-required checks。
  - AI review / security scan blocking status。
  - draft / blocked / unresolved conversation 状态。
- 保存结构化 evaluation、reason 和策略快照。

### 外部状态接入

外部系统优先通过 commit status / check context 接入：

- Woodpecker。
- SonarQube。
- Semgrep。
- Gitleaks。
- Trivy。
- AI Review Bot。

### `add-enterprise-merge-gate`：非范围

- 不在 Gitea 进程内执行扫描或 AI 推理。
- 不把云厂商 token 下发给仓库或普通 CI。
- 不实现策略模板自动应用。

### `add-enterprise-merge-gate`：建议能力路径

- `repository/enterprise-merge-gate`

### `add-enterprise-merge-gate`：验收要点

- Web/API/auto merge 使用同一个 evaluator。
- 所有阻断原因可解释并可审计。
- required checks、CODEOWNERS、敏感路径和 AI/security blocking 均可阻断合并。
- bypass 行为必须有权限校验、理由和审计。

## Proposal 6：`add-enterprise-policy-templates`

### `add-enterprise-policy-templates`：目标

让组织、仓库和迁移仓库自动套用企业默认治理模板。

### `add-enterprise-policy-templates`：依赖

- `add-enterprise-feature-grants`
- 推荐依赖 `add-enterprise-merge-gate`

### `add-enterprise-policy-templates`：范围

- 新增：
  - `enterprise_policy_template`
  - `enterprise_policy_template_binding`
- 支持全局默认组织模板和组织默认仓库模板。
- 新建仓库自动应用：
  - private visibility。
  - 默认 team/role 绑定。
  - branch protection。
  - required checks。
  - sensitive path rules。
  - feature grants。
- GitHub 迁移后自动应用模板并输出校验报告。
- 模板应用失败时，仓库进入安全状态或明确报告未完成项。

### `add-enterprise-policy-templates`：非范围

- 不实现 GitHub 迁移本身的完整增强，只接入迁移后的模板应用点。
- 不实现 UI。

### `add-enterprise-policy-templates`：建议能力路径

- `governance/enterprise-policy-templates`

### `add-enterprise-policy-templates`：验收要点

- 新建组织、新建仓库、迁移仓库都能记录模板绑定。
- 模板应用幂等。
- 模板失败不会静默放权。
- 模板应用写审计。

## Proposal 7：`add-enterprise-offboarding-policy`

### `add-enterprise-offboarding-policy`：目标

明确企业微信离职、禁用或离开应用可见范围后，本地 Gitea 用户、SSH key、PAT/API token、Git HTTP token 的处理策略。

### 是否必做

可选，但如果企业要求“离职即断 Git 访问”，应单独实施，不能隐式塞进登录或 mapping 逻辑中。

### `add-enterprise-offboarding-policy`：范围

- 新增显式配置，例如：

```ini
[enterprise.wecom.offboarding]
DISABLE_GITEA_USER_ON_LEFT = true
REVOKE_PAT_ON_LEFT = true
DISABLE_SSH_KEYS_ON_LEFT = true
REVOKE_OAUTH_GRANTS_ON_LEFT = true
```

- 区分状态：
  - `inactive`
  - `left`
  - `out_of_scope`
- 对每类状态定义是否禁用 Web 登录、是否移除受管 membership、是否禁用 Gitea user、是否吊销 token/key。
- 每个自动禁用/吊销动作必须审计。
- 提供 dry-run / report 能力，避免误杀。

### 风险

这个 proposal 会改变当前明确保留的 SSH/PAT/Git HTTP token 兼容边界，必须由业务和运维明确批准。

### `add-enterprise-offboarding-policy`：建议能力路径

- `identity/enterprise-offboarding-policy`

### `add-enterprise-offboarding-policy`：验收要点

- 离职策略可配置、可审计、可 dry-run。
- 被吊销的 token/key 不记录明文。
- 误配置时可恢复，且恢复流程有 runbook。

## Proposal 8：`add-enterprise-authz-admin-ui`

### `add-enterprise-authz-admin-ui`：目标

补齐企业授权管理界面和可观测性入口。

### `add-enterprise-authz-admin-ui`：依赖

- 至少依赖已落地的模型和 service。
- 推荐在 feature grants、merge gate 和 policy templates 之后实施。

### `add-enterprise-authz-admin-ui`：范围

- Site Admin / Enterprise Authorization：全局角色、功能、模板、审计。
- Org Settings / Authorization：组织角色、组织 feature grants、默认仓库模板。
- Repo Settings / Authorization：仓库角色绑定、feature grants、模板应用结果。
- Pull Request merge box：展示 merge gate 阻断原因。
- Audit log 过滤和导出。

### `add-enterprise-authz-admin-ui`：非范围

- 不在 UI 中绕过后端权限。
- 不提供企业微信受管 team 的本地手工维护入口。

### `add-enterprise-authz-admin-ui`：建议能力路径

- `ui/enterprise-authz-admin`

### `add-enterprise-authz-admin-ui`：验收要点

- 前端入口权限和后端 API 权限一致。
- UI 展示不会泄露 secret、token、私密通讯录字段。
- merge box 阻断原因对普通 repo reader 可解释，但不暴露敏感策略细节。

## Proposal 编写规范

每个 proposal 创建时应使用：

```bash
openspec new change "<proposal-id>"
```

建议每个 change 至少包含：

- `proposal.md`：说明 Why、What Changes、Capabilities、Impact。
- `design.md`：记录架构决策、边界、替代方案和迁移判断。
- `tasks.md`：按可验证切片拆分任务。
- `specs/<capability-path>/spec.md`：用 RFC 2119 风格写 MUST / SHOULD / MAY 场景。

每个涉及企业授权的 spec 都应包含负向要求：

- 未明确变更时，SSH key 认证 MUST 保持 Gitea 原行为。
- 未明确变更时，PAT/API token MUST 保持 Gitea 原行为。
- 未明确变更时，Git HTTP token authentication MUST 保持 Gitea 原行为。
- 企业微信身份 MUST NOT 取代本地 Gitea user 作为 repo 权限和审计主体。

## 推荐第一步

优先创建并实施：

```bash
openspec new change "harden-wecom-governance-ops"
```

原因：该 change 风险最低、最贴近当前代码状态，并且能把现有企业微信治理能力整理成可生产运行基础。完成后，再推进 shadow authz，能够降低后续权限模型误判和上线回滚风险。

## 2026-10-01：Proposal 2 实施更新

本轮按 `add-enterprise-authz-foundation-shadow` 接入企业 action/allow-only 角色及绑定、原生凭据感知 evaluator、受权 API、真实操作 shadow 证据与安全审计。repo 是资源作用域，不是主体；候选 allow/deny 不是正式授权，更不是完整 merge gate。目标创建前迁移失败只记安全用户/系统审计，不伪造仓库决策。

回归与恢复证据见该 change 的 `verification.md`，运维步骤见 [shadow 运维手册](authz-shadow-runbook.md)。路线图中 enforce、feature grant、merge gate、模板、offboarding 和管理 UI 保持后续范围，不能以此次实施替代其独立 proposal 与验收。

企微 callback 保持关闭，登录刷新及定时完整同步为当前方案；服务端永久只部署和验收 Linux，Windows 客户端访问不受影响。本次更新保留以上路线图原文，不将未来阶段提前勾选，也不提交、推送或归档。

## 2026-10-05：Proposal 4 实施边界更新

`add-enterprise-feature-grants` 当前实现包含 13-key 固定目录、global/org/repo 四态确定性锁、strict contexts、版本 CAS、真实受权管理与安全 effective 投影，以及七项 native_gate 的 Web/API/service/worker/Git/registry 配置与内容约束。required 不自动补原生资源，native availability/pending 不等于治理通过；六个 policy_only key 不执行外部集成或新增 merge deny。没有新功能 UI，也不自动完成后续模板/完整 merge gate/offboarding 提案。

运维步骤见 [功能授权手册](feature-grants-runbook.md)：Linux 正式 migration 363 / DB version 364、Cargo 稳定用途标记、`enterprise_cargo_index_source` 唯一 pair 与永久历史来源，以及旧索引受审计显式认领（完整 Git 历史核实、可重复 `--source-repo-id` 或互斥 `--confirm-no-linked-history`），旧 mail queue 全实例停机和仅 mail 隔离、旧 hook 来源缺失 fail-closed，以及成套 DB+Git/storage+queue 备份恢复。Git commit 前追加 Cargo 实际来源，删除/unlink 不清理；索引读取按全部来源当前 repo 策略，来源删除/未知拒绝。marked index 禁止 owner transfer，rename 保留稳定 ID；未标记同名仓库仅 disabled 保留上游 lookup，不赋 marker。旧二进制不得降 schema，不按仓库名称或仅现存包认领索引、不 rewrite 历史，不删 common 共享队列目录。

本更新不宣称生产部署/完整恢复已经执行；实跑与未验证项以本 change verification 为准，前序 change 历史验收保留。


## 2026-10-06：Proposal 5 工作区实施与验收完成（未合并/上线）

`add-enterprise-merge-gate` 已接入独立开关、三作用域累计敏感规则/CAS API、catalog3 两个独立 action、完整 diff/base CODEOWNERS/current-head 审批与 native/feature/path status、shared Merge/manual 写前门禁和有限 bypass 字段/表单。队列记录原始凭据上限及 queue ID，worker 当前 facts 重评；receive 历史保留真实 pusher/非零历史范围；内部 ticket 绑定本次 admission，终态使用同 operation receipt 并只修证据对账。规则管理仍 API-only，没有外部 scanner/AI 执行或模板/offboarding UI。

当前逐 Requirement/Scenario 证据见该 change 的 `verification.md` / `tasks.md`，运维语义见 [merge gate 手册](merge-gate-runbook.md)。最新串行验证通过：完整后端244个测试包、前端167项、Linux SQLite/PostgreSQL 各108入口/角色/模式矩阵和15策略/签名/hook矩阵、真实fork/AGit、故障/取消/超时/独立进程重启对账、迁移及协议套件，PG最终写前11类事实屏障，以及3项对最新Linux服务的Chromium整页E2E。构建、格式/lint、Swagger兼容与strict验证通过；E2E最慢5.5秒，尚未稳定达到4秒性能目标。测试临时服务已清理，不影响现有服务。工作区开发/验收完成不等于已合并或生产上线；生产enforce仍须运维显式审批、统一实例配置和上线观察。

原生 status skipped 兼容而企业 feature/path 仅 success；有 writer 权限者可伪造同名 context，不能宣称供应商身份或扫描内容认证。回退保留两表/历史，不能改 DB version 或删表降级。保留前序 proposal 的原文和证据，callback 持续关闭；未提交、推送、部署、同步 main specs 或归档。
