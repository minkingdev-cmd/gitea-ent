# Gitea Enterprise Authorization Implementation Plan

## 目的

本文档把 [`requirements.md`](requirements.md) 中的企业授权需求收敛成可执行的实施方案。方案目标是在保持浅 fork、降低上游合并冲突的前提下，复用 Gitea 现有权限、分支保护、required checks、Actions 和审计日志能力，补齐企业级 repo 授权、功能授权、默认治理模板和合并门禁。

## 设计原则

1. **兼容优先**：未启用企业授权增强时，行为尽量保持上游 Gitea 语义。
2. **叠加而非替换**：新增企业授权 overlay，不直接替换 `AccessMode`、repo unit、team、branch protection 等核心模型。
3. **集中决策**：所有 Web、API、Git HTTP/SSH、file editor、receive hook、auto merge 路径最终调用统一授权或合并门禁判断。
4. **显式迁移**：新增表、字段、默认角色、默认权限和策略模板都通过 `modelmigration` 显式落库，不依赖启动时隐式修复生产数据。
5. **可审计**：权限变更、策略变更和合并决策必须记录审计事件；合并门禁保存策略快照，便于事后解释。
6. **可回滚到安全状态**：升级失败或企业授权关闭时，系统应退回到原生 Gitea 权限，或进入只读保护状态，而不是意外放权。

## 当前代码基础

当前仓库已有以下可复用基础：

| 能力 | 现有位置 | 复用方式 |
| --- | --- | --- |
| repo 基础权限 | `models/perm/access`、`models/perm/access_mode.go` | 作为旧权限兼容层和默认 action 映射来源。 |
| repo unit 权限 | `models/unit`、`repo_model.RepoUnit`、`organization.TeamUnit` | 继续控制 Issues、PR、Wiki、Packages、Actions 等模块可见性和读写。 |
| 团队权限 | `models/organization/team.go` | 自定义角色绑定优先扩展 subject binding，不改团队核心模型。 |
| 分支保护 | `models/git/protected_branch.go` | 继续承载 protected branch、required approvals、status checks、CODEOWNERS、protected files。 |
| 合并检查 | `services/pull/check.go`、`services/pull/merge.go` | 抽出统一 merge gate evaluator 后由这些入口调用。 |
| required checks | `services/pull/commit_status.go`、commit status API | 外部系统以 commit status/check context 方式接入。 |
| 强制 scoped workflow | `models/actions/scoped_workflow.go` | 可作为 required workflow / required check 的 Gitea Actions 侧实现。 |
| 审计日志 | `models/audit`、`services/audit` | 扩展 action 和 metadata，不另建平行审计体系，除非后续有性能或合规隔离要求。 |

## 总体架构

新增企业授权层位于现有权限模型之上：

```text
Request / Git Operation / Merge Operation
  -> existing authentication
  -> existing Gitea repo/unit permission loading
  -> enterprise authz evaluator
  -> feature grant evaluator
  -> action-specific guard or merge gate evaluator
  -> audit event / merge gate snapshot
```

建议新增包：

```text
models/enterpriseauthz
services/enterpriseauthz
routers/api/v1/enterpriseauthz
routers/web/admin/enterpriseauthz
routers/web/org/setting/enterpriseauthz
routers/web/repo/setting/enterpriseauthz
```

说明：

- 使用 `enterpriseauthz` 前缀，避免和上游未来的 `authz`、`roles`、`policy` 包冲突。
- 第一阶段可以只新增 model 和 service；Web UI 分阶段补齐。
- API 和 Web 不直接拼 SQL 或业务规则，统一调用 `services/enterpriseauthz`。

## 配置开关

新增配置项建议：

```ini
[enterprise.authz]
ENABLED = false
ENFORCE = false
FAIL_CLOSED_ON_ERROR = true
```

语义：

| 配置 | 说明 |
| --- | --- |
| `ENABLED=false` | 只使用原生 Gitea 权限。企业授权 API 可隐藏或只读。 |
| `ENABLED=true, ENFORCE=false` | shadow mode，只记录决策和审计，不阻断请求。用于灰度验证。 |
| `ENABLED=true, ENFORCE=true` | 正式执行企业授权决策。 |
| `FAIL_CLOSED_ON_ERROR=true` | evaluator 出错时写操作拒绝，读操作按原生权限降级或拒绝，具体由 action 风险等级决定。 |

## 数据模型

新增表建议统一使用 `enterprise_` 前缀。

### `enterprise_role_definition`

定义内置角色和自定义角色。

| 字段 | 说明 |
| --- | --- |
| `id` | 主键。 |
| `scope_type` | `system`、`org`、`repo`。 |
| `scope_id` | 作用域 ID；系统级为 0。 |
| `name` / `lower_name` | 角色名。 |
| `description` | 描述。 |
| `base_role_id` | 可选，表示基于哪个角色扩展。 |
| `is_builtin` | 是否内置角色。 |
| `created_unix` / `updated_unix` | 时间戳。 |

### `enterprise_role_permission`

角色到权限 action 的映射。

| 字段 | 说明 |
| --- | --- |
| `role_id` | 角色 ID。 |
| `action` | 如 `repo.read_code`、`repo.merge_pull_request`。 |
| `effect` | `allow` 或 `deny`；第一阶段可只支持 `allow`。 |
| `condition_json` | 可选条件，例如 branch、path、feature key。 |

### `enterprise_subject_role_binding`

把用户、团队、组织或系统主体绑定到角色。

| 字段 | 说明 |
| --- | --- |
| `scope_type` / `scope_id` | 绑定生效范围。 |
| `subject_type` | `user`、`team`、`org`、`site_admin`。 |
| `subject_id` | 主体 ID。 |
| `role_id` | 角色 ID。 |
| `created_by` | 操作者。 |
| `created_unix` / `updated_unix` | 时间戳。 |

### `enterprise_feature_definition`

登记平台能力。

| 字段 | 说明 |
| --- | --- |
| `key` | 如 `feature.ai_review`。 |
| `description` | 功能说明。 |
| `supported_scopes` | JSON，允许的作用域。 |
| `default_state` | 默认状态。 |
| `created_unix` / `updated_unix` | 时间戳。 |

### `enterprise_feature_grant`

记录功能授权状态。

| 字段 | 说明 |
| --- | --- |
| `feature_key` | 功能 key。 |
| `scope_type` / `scope_id` | `global`、`org`、`repo`、`team`、`user`、`branch`。 |
| `state` | `disabled`、`enabled`、`required`、`inherited`。 |
| `config_json` | 功能特定配置，如 required check context。 |
| `created_by` | 操作者。 |
| `created_unix` / `updated_unix` | 时间戳。 |

### `enterprise_policy_template`

保存默认治理模板。

| 字段 | 说明 |
| --- | --- |
| `scope_type` / `scope_id` | `global` 或 `org`。 |
| `name` / `lower_name` | 模板名。 |
| `template_json` | 角色、分支保护、required checks、功能授权、敏感路径规则。 |
| `is_default` | 是否默认应用。 |
| `version` | 策略版本。 |
| `created_unix` / `updated_unix` | 时间戳。 |

### `enterprise_policy_template_binding`

记录模板应用到组织或仓库的关系。

| 字段 | 说明 |
| --- | --- |
| `template_id` | 模板 ID。 |
| `target_type` / `target_id` | `org` 或 `repo`。 |
| `applied_version` | 应用的模板版本。 |
| `applied_by` | 操作者。 |
| `applied_unix` | 应用时间。 |

### `enterprise_protected_path_rule`

保存全局、组织和仓库级敏感路径规则。

| 字段 | 说明 |
| --- | --- |
| `scope_type` / `scope_id` | `global`、`org`、`repo`。 |
| `pattern` | glob 模式。 |
| `required_role` | 如 `Security Maintainer`。 |
| `required_check_contexts` | JSON 数组。 |
| `created_unix` / `updated_unix` | 时间戳。 |

### `enterprise_merge_gate_evaluation`

保存合并门禁决策快照。

| 字段 | 说明 |
| --- | --- |
| `repo_id` | 仓库 ID。 |
| `pull_id` / `issue_id` | PR 对应 ID。 |
| `head_sha` / `base_sha` | 评估时的 commit。 |
| `actor_id` | 发起合并的用户。 |
| `decision` | `allow`、`deny`、`bypass`。 |
| `reason_json` | 未满足项、通过项、bypass 原因。 |
| `policy_snapshot_json` | 角色、feature grant、branch protection、required checks 的快照。 |
| `created_unix` | 评估时间。 |

## 权限 action 模型

### 原生权限兼容映射

| Gitea 原生权限 | 默认映射 action |
| --- | --- |
| `AccessModeRead` + code unit read | `repo.view_metadata`、`repo.read_code`、`repo.clone` |
| `AccessModeWrite` + code unit write | `repo.create_branch`、`repo.push_branch`、`repo.create_pull_request` |
| `AccessModeWrite` + PR unit write | `repo.review_pull_request` |
| `AccessModeAdmin` | `repo.manage_branch_protection`、`repo.manage_webhook`、`repo.manage_ci` |
| `AccessModeOwner` | `repo.manage_secret`、`repo.manage_feature_grant`、`repo.transfer`、`repo.archive`、`repo.delete` |
| site admin | `platform.admin`，并可按配置映射到所有 repo action |

兼容策略：

1. `enterprise.authz.ENABLED=false` 时，只使用原生权限。
2. `ENABLED=true` 时，先加载原生权限作为基础 capability，再叠加企业角色绑定。
3. 自定义角色可增加细粒度权限，但不应绕过 repo 可见性、账号状态、禁用功能、分支保护和安全门禁。
4. 高风险 action 即使拥有角色权限，也必须满足动作特定 guard，例如删除仓库确认、secret 不泄露、保护分支直推限制。

### 内置角色默认权限

| 角色 | 默认 action |
| --- | --- |
| Guest | `repo.view_metadata`；Issue/Wiki 是否可见由 repo unit 和 feature grant 决定。 |
| Reporter | Guest + `repo.read_code`、`repo.clone`、读取 PR/CI 结果。 |
| Developer | Reporter + `repo.create_branch`、`repo.push_branch`、`repo.create_pull_request`。 |
| Reviewer | Reporter + `repo.review_pull_request`。 |
| Maintainer | Developer + Reviewer + `repo.merge_pull_request`、`repo.manage_webhook`、部分 `repo.manage_ci`。 |
| Security Maintainer | Reporter + `repo.review_pull_request`、`repo.manage_codeowners`、`repo.manage_ci`、安全扫描和敏感路径策略管理。 |
| Owner | repo 全部 action。 |
| Platform Admin | 全局模板、全局功能授权、平台审计和系统集成管理；repo 内动作仍记录跨组织审计。 |

## 功能授权模型

### 状态优先级

功能状态从上到下解析：

```text
global -> org -> repo -> team/user/branch override
```

建议规则：

1. 任一上级为 `disabled` 时，下级不能自行开启，除非该 feature 显式允许 lower-scope override。
2. 任一上级为 `required` 时，下级不能关闭，只能补充配置。
3. `enabled` 表示允许使用，但不强制作为合并门禁。
4. `inherited` 表示继续向上查找。
5. 未配置时使用 `enterprise_feature_definition.default_state`。

### 与 repo unit 的关系

| 功能 | 与现有 repo unit 的关系 |
| --- | --- |
| `feature.issues` | 控制 Issues unit 是否可开启；最终读写仍走 Issues unit 权限。 |
| `feature.pull_requests` | 控制 Pull Requests unit 是否可开启；合并仍走 merge gate。 |
| `feature.packages` | 控制 Packages unit 是否可开启。 |
| `feature.wiki` | 控制 Wiki unit 是否可开启。 |
| `feature.woodpecker_ci` | 不替换 Gitea Actions；以 webhook/status check/外链形式接入。 |
| `feature.required_status_checks` | 决定是否允许管理 required checks，以及是否强制模板检查。 |
| `feature.ai_review` | 决定是否触发 AI 审计、是否作为 required check、读取范围。 |
| `feature.protected_file_patterns` | 决定敏感路径规则是否生效。 |

## 统一授权 evaluator

建议服务接口：

```go
type Subject struct {
    UserID int64
    TeamIDs []int64
    IsSiteAdmin bool
}

type Resource struct {
    RepoID int64
    OwnerID int64
    Branch string
    Path string
}

type Condition struct {
    FeatureKey string
    Ref string
    ChangedPaths []string
    RequestSource string
}

type Decision struct {
    Allowed bool
    Reason string
    MatchedRoles []string
    MissingActions []string
    FeatureState string
    AuditMetadata map[string]any
}
```

第一阶段可以不暴露完整泛型 API，但内部应按上述结构组织，避免在各路由里复制判断。

## 合并门禁 evaluator

新增 `services/enterpriseauthz/mergegate` 或同包子模块，统一评估 PR 是否可合并。

### 输入

- doer / subject。
- PR、base repo、head repo、base branch、head SHA。
- 原生 repo permission。
- branch protection rule。
- enterprise roles 和 feature grants。
- required status contexts。
- CODEOWNERS 结果。
- changed paths 和敏感路径规则。
- AI review / 安全扫描 / 质量门禁 status context。

### 输出

```text
Decision: allow | deny | bypass
BlockingReasons:
  - missing_action: repo.merge_pull_request
  - missing_required_check: security/gitleaks
  - missing_codeowner_review
  - sensitive_path_requires_security_maintainer
  - feature_required_check_not_satisfied: feature.ai_review
PolicySnapshot:
  roles
  feature grants
  branch protection
  required checks
  sensitive path rules
```

### 接入点

| 入口 | 接入方式 |
| --- | --- |
| Web merge button | `routers/web/repo/pull.go` 调用 evaluator 决定 merge box 状态。 |
| Web merge POST | `routers/web/repo/pull.go:MergePullRequest` 在实际 merge 前强制调用。 |
| API merge | `routers/api/v1/repo/pull.go:MergePullRequest` 强制调用。 |
| Auto merge | scheduled merge 触发前调用同一 evaluator。 |
| Force merge | evaluator 标记 `bypass`，并保存 bypass 原因，不直接跳过所有检查。 |

## 敏感路径保护

默认路径从需求文档迁入全局模板，而不是硬编码在业务代码中。首批默认规则：

```text
.woodpecker.yml
.woodpecker/**
Dockerfile
Dockerfile.*
docker-compose.yml
compose.yml
k8s/**
helm/**
charts/**
migrations/**
sql/**
terraform/**
ansible/**
secrets.example
.env.example
.github/**
```

命中敏感路径时：

1. 必须满足 CODEOWNERS 或 Security Maintainer 审批。
2. 必须满足 required checks。
3. 若 `feature.ai_review` 为 `required` 或配置为 blocking，则 AI review status 必须通过。
4. 结果写入 `enterprise_merge_gate_evaluation.reason_json`。

## API 方案

新增 API 必须复用 Gitea token、session 和现有 repo/org/admin assignment。

### 系统级 API

| API | 权限 |
| --- | --- |
| `GET /api/v1/enterprise/authz/roles` | site admin 或 platform admin。 |
| `POST /api/v1/enterprise/authz/roles` | site admin 或 platform admin。 |
| `GET /api/v1/enterprise/authz/features` | site admin 或 platform admin。 |
| `PUT /api/v1/enterprise/authz/features/{key}/grants/global` | platform admin。 |
| `GET /api/v1/enterprise/authz/audit` | site admin、platform admin、auditor。 |

### 组织级 API

| API | 权限 |
| --- | --- |
| `GET /api/v1/orgs/{org}/enterprise/authz/roles` | org owner 或授权管理员。 |
| `POST /api/v1/orgs/{org}/enterprise/authz/roles` | org owner。 |
| `GET /api/v1/orgs/{org}/enterprise/authz/features` | org owner 或授权管理员。 |
| `PUT /api/v1/orgs/{org}/enterprise/authz/features/{key}` | org owner 或 `repo.manage_feature_grant` 等价组织权限。 |
| `POST /api/v1/orgs/{org}/enterprise/authz/templates/apply` | org owner。 |

### 仓库级 API

| API | 权限 |
| --- | --- |
| `GET /api/v1/repos/{owner}/{repo}/enterprise/authz/effective-permissions` | repo admin 或查询自己。 |
| `GET /api/v1/repos/{owner}/{repo}/enterprise/authz/features` | repo admin。 |
| `PUT /api/v1/repos/{owner}/{repo}/enterprise/authz/features/{key}` | `repo.manage_feature_grant`。 |
| `POST /api/v1/repos/{owner}/{repo}/enterprise/authz/templates/apply` | Owner 或 `repo.manage_feature_grant`。 |
| `GET /api/v1/repos/{owner}/{repo}/enterprise/merge-gate/{index}` | repo reader + PR reader。 |

所有新增或变更 API 必须更新 swagger：

```bash
make generate-swagger
make swagger-validate
```

## 前端管理入口

| 页面 | 能力 | 入口权限 key |
| --- | --- | --- |
| Site Admin / Enterprise Authorization | 全局角色、全局功能、全局模板、平台审计 | `platform.admin` 或 `platform.authz.manage` |
| Org Settings / Authorization | 组织角色、组织功能、组织模板 | `org.authz.manage` |
| Repo Settings / Authorization | 仓库角色绑定、功能授权、模板应用 | `repo.manage_feature_grant` |
| Repo Settings / Branches | 分支保护和敏感路径规则 | `repo.manage_branch_protection`、`repo.manage_codeowners` |
| Pull Request merge box | 展示 merge gate 阻断原因 | `repo.read_code` + PR read |

前端入口必须和后端 API 权限一致：后端允许但无入口、前端展示但后端 403，都视为缺陷，除非对应能力明确列为 API-only。

## 审计日志

复用 `models/audit.Event`。新增 action 建议：

```text
enterprise:role:create
enterprise:role:update
enterprise:role:delete
enterprise:role:binding:add
enterprise:role:binding:remove
enterprise:feature:grant:update
enterprise:template:create
enterprise:template:update
enterprise:template:apply
enterprise:protected_path:create
enterprise:protected_path:update
enterprise:protected_path:delete
enterprise:merge_gate:evaluate
enterprise:merge_gate:bypass
```

审计 metadata 至少包含：

```text
before
 after
decision
reason
request_id
policy_snapshot_id 或 merge_gate_evaluation_id
```

secret、token、私钥和外部系统凭据不得写入 metadata 明文。

## Git 和写路径接入点

| 操作 | 必须覆盖的入口 |
| --- | --- |
| clone/fetch | Git HTTP、SSH。 |
| push 普通分支 | Git HTTP receive、SSH receive、API/file editor 创建 commit。 |
| push 保护分支 | receive hook、branch protection、file editor、API branch/file endpoints。 |
| 创建 PR | Web、API、fork PR。 |
| review PR | Web、API review endpoints。 |
| merge PR | Web、API、auto merge。 |
| secret/webhook/CI 设置 | Web settings、API、Actions settings。 |
| 迁移仓库 | Web migrate、API migrate、batch migration。 |

第一阶段优先覆盖高风险写路径：merge、protected branch push、secret、webhook、branch protection、feature grant。

## 默认模板应用

### 新建组织

1. 创建组织原生 owners team。
2. 应用全局默认组织模板。
3. 创建组织级内置角色定义或引用系统内置角色。
4. 写审计事件。

### 新建仓库

1. 创建仓库后加载全局和组织默认仓库模板。
2. 设置默认 visibility、repo units、branch protection、required checks、敏感路径规则。
3. 建立默认角色绑定。
4. 写 `enterprise_policy_template_binding`。
5. 写审计事件。

### GitHub 迁移后

1. 完成 Git history、branch、tag、LFS、issue/PR 等迁移。
2. 应用组织或仓库模板。
3. 配置 Woodpecker webhook 或外部 CI status context。
4. 输出迁移校验报告。
5. 若模板应用失败，仓库进入安全只读状态，并在报告中标记。

## 分阶段实施

### Phase 0：设计和基线验证

- [ ] 确认配置开关和 package 命名。
- [ ] 确认内置角色和 action 列表。
- [ ] 补充 OpenSpec 或等价变更任务清单。
- [ ] 列出所有必须覆盖的 Web/API/Git 写入口。

### Phase 1：角色和 repo action overlay

- [ ] 新增 `enterprise_role_definition`、`enterprise_role_permission`、`enterprise_subject_role_binding`。
- [ ] 新增内置角色 seed migration。
- [ ] 实现 repo action evaluator。
- [ ] 在 merge、branch protection、webhook、secret 等高风险入口接入 evaluator。
- [ ] 增加 403 负例、默认管理员正例、自定义角色正例测试。

### Phase 2：功能授权

- [ ] 新增 `enterprise_feature_definition`、`enterprise_feature_grant`。
- [ ] 实现 feature state 继承解析。
- [ ] 接入 Issues、PR、Wiki、Packages、Webhooks、Actions/CI、AI review 等首批功能。
- [ ] 禁止仓库关闭上级 `required` 功能。
- [ ] 增加 API、service 和集成测试。

### Phase 3：合并门禁和敏感路径

- [ ] 新增 `enterprise_protected_path_rule`。
- [ ] 新增 `enterprise_merge_gate_evaluation`。
- [ ] 抽出 merge gate evaluator。
- [ ] 统一 Web merge、API merge、auto merge、force merge 路径。
- [ ] 保存策略快照和审计事件。
- [ ] 覆盖 required checks、CODEOWNERS、敏感路径、AI review blocking 测试。

### Phase 4：默认治理模板

- [ ] 新增 `enterprise_policy_template`、`enterprise_policy_template_binding`。
- [ ] 支持全局和组织默认模板。
- [ ] 新建仓库自动应用模板。
- [ ] GitHub 迁移后应用模板和输出校验报告。
- [ ] 增加 migration、repo creation、migration integration 测试。

### Phase 5：管理界面和运营完善

- [ ] 增加 site admin、org settings、repo settings 管理页面。
- [ ] 增加 merge gate 结果展示。
- [ ] 增加审计日志过滤和导出。
- [ ] 补齐前端权限显隐测试和 e2e smoke test。

## 测试策略

| 层级 | 覆盖内容 |
| --- | --- |
| unit test | action 映射、角色继承、feature grant 继承、merge gate reason。 |
| migration test | 新表、内置角色 seed、默认 feature seed、回放幂等性。 |
| integration test | API 403/200、自定义角色授权、模板应用、merge gate 阻断。 |
| Git path test | clone/fetch、push 普通分支、push protected branch。 |
| e2e smoke | settings 页面入口显隐、merge box 阻断原因展示。 |
| audit test | 权限变更、feature grant、merge gate evaluate/bypass 事件。 |

单测优先；只有跨 Web/API/Git path 的能力使用 integration 或 e2e。

## 权限闭环矩阵

本仓库不是注解式权限框架，也不引入 OpenFGA。下表中的“后端防护”使用当前 Gitea middleware/service/check 名称表达；“OpenFGA/外部关系”列固定为“不适用”。

| 入口/API | 后端防护 | OpenFGA/外部关系 | 默认授权角色 | 前端入口 key |
| --- | --- | --- | --- | --- |
| 查看仓库元数据 | repo assignment + visibility + `repo.view_metadata` | 不适用 | Guest+ | `repo.metadata.read` |
| 浏览代码/commit/branch/tag | `Permission.CanRead(unit.TypeCode)` + `repo.read_code` | 不适用 | Reporter+ | `repo.code.read` |
| clone/fetch | Git HTTP/SSH auth + `repo.clone` | 不适用 | Reporter+ | 无 |
| 创建普通分支 | `reqRepoWriter(unit.TypeCode)` + `repo.create_branch` | 不适用 | Developer+ | `repo.branch.create` |
| push 普通分支 | receive hook + `repo.push_branch` | 不适用 | Developer+ | 无 |
| push 保护分支 | branch protection + `repo.push_protected_branch` | 不适用 | Owner、Platform Admin、显式授权用户 | `repo.branch.protected_push` |
| 创建 PR | Pull Requests unit + `repo.create_pull_request` | 不适用 | Developer+ | `repo.pr.create` |
| 提交 review | review endpoint + `repo.review_pull_request` | 不适用 | Reviewer+ | `repo.pr.review` |
| 合并 PR | merge gate + `repo.merge_pull_request` | 不适用 | Maintainer+ | `repo.pr.merge` |
| 管理分支保护 | `repo.manage_branch_protection` | 不适用 | Owner、Security Maintainer | `repo.branch_protection.manage` |
| 管理 CODEOWNERS/敏感路径 | `repo.manage_codeowners` | 不适用 | Owner、Security Maintainer | `repo.codeowners.manage` |
| 管理 webhook | `repo.manage_webhook` + webhooks enabled | 不适用 | Maintainer+、Owner | `repo.webhook.manage` |
| 管理 CI/required checks | `repo.manage_ci` | 不适用 | Maintainer+、Security Maintainer | `repo.ci.manage` |
| 管理 repo secret | `repo.manage_secret` | 不适用 | Owner | `repo.secret.manage` |
| 管理功能授权 | `repo.manage_feature_grant` | 不适用 | Owner、Platform Admin | `repo.feature_grant.manage` |
| 仓库迁移 | `repo.migrate` + feature grant | 不适用 | Owner、Platform Admin | `repo.migration.manage` |
| 转移仓库 | `repo.transfer` + danger-zone guard | 不适用 | Owner、Platform Admin | `repo.transfer` |
| 归档仓库 | `repo.archive` + danger-zone guard | 不适用 | Owner、Platform Admin | `repo.archive` |
| 删除仓库 | `repo.delete` + danger-zone guard + confirmation | 不适用 | Owner、Platform Admin | `repo.delete` |
| 全局角色/模板/功能 | site admin/platform admin guard | 不适用 | Platform Admin | `platform.authz.manage` |
| 组织角色/模板/功能 | org owner + enterprise org action | 不适用 | Org Owner | `org.authz.manage` |

## Migration 判断

| 类型 | 是否需要 | 说明 |
| --- | --- | --- |
| DB/modelmigration | 需要 | 新增 enterprise 表、内置角色、默认 feature、模板和 merge gate 快照。 |
| OpenFGA | 不需要 | 当前仓库未使用 OpenFGA；为保持浅 fork，不引入外部 PDP。 |
| Keycloak | 不需要 | 当前方案不改外部 IdP、scope、mapper 或 token claim。 |
| Swagger | 需要 | 新增或修改 API 后必须 `make generate-swagger` 和 `make swagger-validate`。 |
| 前端 locale | 需要时 | UI 文案只编辑 `options/locale/locale_en-US.json`。 |
| 配置文档 | 需要 | 新增 `[enterprise.authz]` 后更新 `custom/conf/app.example.ini` 和配置文档。 |

## 验收标准

第一阶段完成后：

- 可以定义 repo 自定义角色。
- 可以给用户或团队绑定 repo 角色。
- 关键写入口通过企业 action evaluator 做 allow/deny。
- 未授权用户访问写 API 返回 403。
- 默认 Owner/管理员仍可完成原有管理动作。
- 自定义角色授权后可访问对应动作。
- 相关权限变更写审计日志。
- SQLite 下有单元测试或集成测试覆盖核心判断。

第三阶段完成后：

- Web/API/auto merge 使用同一 merge gate evaluator。
- required checks、CODEOWNERS、敏感路径和 feature-required checks 均可阻断合并。
- merge gate 保存结构化评估结果和策略快照。
- force merge/bypass 被审计且说明原因。

第五阶段完成后：

- 管理界面可以完成常用角色、功能授权、模板、敏感路径和审计查询操作。
- GitHub 迁移后可自动应用治理模板并输出校验报告。
- Woodpecker、SonarQube、Semgrep、Gitleaks、Trivy、AI Review Bot 均能以 required check 方式参与门禁。

## 待确认问题

1. 是否需要把企业授权作为长期 feature flag，还是在稳定后默认开启。
2. 自定义角色是否支持 `deny`，还是第一阶段只支持 additive `allow`。
3. site admin 是否默认绕过所有 repo gate，还是只能 bypass 管理类动作，不能绕过安全扫描和签名要求。
4. AI review 的 status context 命名规范，例如 `review/ai` 是否固定。
5. Woodpecker 历史只读展示是新增聚合页，还是先使用外链。
6. 管理界面是否第一阶段必须交付，还是先提供 API 和 migration。
