# Gitea Enterprise Authorization Requirements

## 背景

本仓库是基于 `go-gitea/gitea` fork 的内部改造版本，目标是在零软件授权预算前提下，建设一个可在内网部署的企业级 Git 服务。系统需要承接 GitHub 仓库迁移，并和现有 Woodpecker CI、代码质量检查、代码审查、AI 代码审计能力集成。

本需求文档聚焦两类授权能力：

1. **Repo 授权**：控制用户、团队、组织对仓库及仓库内关键动作的访问能力。
2. **功能授权**：控制某个用户、团队、组织或仓库是否可使用某项平台能力。

云厂商 AI token 管理、模型供应商选择、具体推理链路不属于本文件重点；AI 服务在本文件中被视为一个需要授权开启和纳入合并门禁的外部能力。

## 目标

- 在 Gitea 原生能力基础上增强 repo 级授权，使权限不再只依赖简单的 Read、Write、Admin。
- 增加功能授权模型，使平台功能可以按全局、组织、团队、用户、仓库维度开启、禁用或强制。
- 为新建组织和仓库提供默认授权模板、默认分支保护、默认质量门禁和默认敏感路径保护。
- 支持 GitHub 仓库迁移后的权限重建、仓库治理和 CI 接入。
- 支持 Woodpecker、SonarQube、Semgrep、Gitleaks、Trivy、AI 审计结果作为 required checks 或合并条件。
- 保持 Gitea 上游可合并性，避免深度修改 Git 存储、PR 基础模型和 issue 基础模型。

## 非目标

- 不自研完整 GitLab 替代品。
- 不在 Gitea 进程内直接执行 AI 推理。
- 不把云厂商 AI token 下发到普通流水线、仓库 secret 或开发者本地。
- 不实现同一个 Git 仓库内的路径级读取隔离。需要路径级保密时，应拆分仓库。
- 不把旧 Woodpecker 历史强行导入 Gitea 原生数据模型；历史可以通过只读聚合或外链展示。
- 不修改 Gitea 的 Git 对象存储格式。

## 授权范围

### Repo 授权动作

系统至少需要支持以下 repo 权限动作：

| 权限动作 | 说明 |
| --- | --- |
| `repo.view_metadata` | 查看仓库基础信息。 |
| `repo.read_code` | 浏览代码、提交、分支、tag。 |
| `repo.clone` | 通过 HTTP/SSH clone 或 fetch。 |
| `repo.create_branch` | 创建普通分支。 |
| `repo.push_branch` | 推送非保护分支。 |
| `repo.push_protected_branch` | 推送保护分支。默认仅平台管理员或明确授权人员拥有。 |
| `repo.create_pull_request` | 创建 PR。 |
| `repo.review_pull_request` | 提交 review、approve 或 request changes。 |
| `repo.merge_pull_request` | 合并 PR。 |
| `repo.manage_branch_protection` | 管理分支保护规则。 |
| `repo.manage_codeowners` | 管理 CODEOWNERS 或等价审批规则。 |
| `repo.manage_webhook` | 管理 webhook。 |
| `repo.manage_ci` | 启停 CI、配置 required checks、管理流水线相关设置。 |
| `repo.manage_secret` | 管理仓库 secret。 |
| `repo.manage_feature_grant` | 管理仓库功能授权。 |
| `repo.migrate` | 从 GitHub 或其他 forge 迁移仓库。 |
| `repo.transfer` | 转移仓库归属。 |
| `repo.archive` | 归档仓库。 |
| `repo.delete` | 删除仓库。 |

### 默认角色

系统应内置以下默认角色，并允许站点管理员或组织管理员基于这些角色创建自定义角色。

| 角色 | 默认能力 |
| --- | --- |
| Guest | 可看 issue、wiki 或项目管理信息；默认不可读代码。 |
| Reporter | 可读代码、clone、查看 PR、issue、CI 结果。 |
| Developer | Reporter 权限，加上创建分支、push 普通分支、创建 PR。 |
| Reviewer | Reporter 权限，加上 review PR；默认不可直接 push。 |
| Maintainer | Developer 和 Reviewer 权限，加上合并 PR、管理普通 webhook、管理部分 CI 设置。 |
| Owner | 仓库全部管理权限，包括权限、secret、迁移、转移、归档和删除。 |
| Security Maintainer | 可管理安全扫描、敏感路径保护、密钥扫描、AI 审计策略。 |
| Platform Admin | 跨组织平台管理员，负责全局模板、功能授权、系统集成。 |

## 功能授权范围

功能授权用于控制平台能力是否可用、是否必选、是否可由仓库管理员关闭。

| 功能 Key | 说明 | 授权维度 |
| --- | --- | --- |
| `feature.issues` | Issue 功能。 | global、org、repo |
| `feature.pull_requests` | PR 功能。 | global、org、repo |
| `feature.packages` | Package registry。 | global、org、repo |
| `feature.wiki` | Wiki。 | global、org、repo |
| `feature.webhooks` | Webhook。 | global、org、repo、role |
| `feature.repository_migration` | 仓库迁移。 | global、org、team、user |
| `feature.woodpecker_ci` | Woodpecker CI 集成。 | global、org、repo |
| `feature.sonarqube_quality_gate` | SonarQube 质量门禁。 | global、org、repo |
| `feature.semgrep_scan` | Semgrep 安全扫描。 | global、org、repo |
| `feature.gitleaks_scan` | Gitleaks 密钥扫描。 | global、org、repo；应支持全局强制 |
| `feature.trivy_scan` | Trivy 镜像或依赖扫描。 | global、org、repo |
| `feature.ai_review` | AI 代码审计。 | global、org、repo、branch |
| `feature.ci_secret_management` | CI secret 管理。 | global、org、repo、role |
| `feature.protected_file_patterns` | 敏感路径保护。 | global、org、repo |
| `feature.required_status_checks` | required checks 管理。 | global、org、repo |

功能授权状态至少包含：

- `disabled`：禁用，仓库不可开启。
- `enabled`：开启，仓库可使用。
- `required`：强制开启，仓库不可关闭。
- `inherited`：继承上级范围配置。

## 授权判断模型

授权判断应统一抽象为：

```text
Subject + Resource + Action + Condition => Decision
```

示例：

```text
Subject:
  user:minwang
  teams: platform, backend

Resource:
  repo:eduplus/backend
  branch:main
  path:.woodpecker.yml

Action:
  repo.merge_pull_request

Condition:
  required_checks_passed = true
  codeowner_approved = true
  sensitive_paths_approved = true
  ai_review_passed = true
```

系统判断顺序建议为：

1. 用户是否已认证，账号是否有效。
2. 用户是否具备目标 repo 的基础权限。
3. 当前动作是否被功能授权允许。
4. 目标分支是否受保护。
5. 变更路径是否命中敏感路径。
6. 是否满足 CODEOWNERS 或等价审批规则。
7. required checks 是否通过。
8. 是否满足功能特定门禁，例如质量门禁、安全扫描、AI 审计。
9. 是否需要二次确认或更高角色审批，例如 repo 删除、secret 修改、保护分支直推。

## 默认治理模板

系统应支持全局模板和组织模板。创建组织或仓库时自动应用模板，并允许在权限范围内覆盖。

默认模板至少包含：

- 默认仓库可见性：private。
- 默认角色绑定。
- 默认分支保护规则。
- 默认 required checks。
- 默认敏感路径保护。
- 默认 CODEOWNERS 模板。
- 默认功能授权状态。
- 默认迁移策略。

示例：

```yaml
default_repo_policy:
  visibility: private
  roles:
    developer:
      - repo.read_code
      - repo.clone
      - repo.create_branch
      - repo.push_branch
      - repo.create_pull_request
    maintainer:
      - repo.merge_pull_request
      - repo.manage_webhook
      - repo.manage_ci

features:
  woodpecker_ci: required
  sonarqube_quality_gate: required
  semgrep_scan: required
  gitleaks_scan: required
  trivy_scan: enabled
  ai_review: enabled

branch_protection:
  main:
    require_pull_request: true
    required_approvals: 1
    require_codeowners: true
    required_checks:
      - ci/build
      - ci/test
      - quality/sonarqube
      - security/semgrep
      - security/gitleaks
      - review/ai
```

## 敏感路径保护

以下路径默认视为敏感路径，变更时需要更严格的审批和检查：

```text
.woodpecker.yml
.woodpecker/
Dockerfile
Dockerfile.*
docker-compose.yml
compose.yml
k8s/
helm/
charts/
migrations/
sql/
terraform/
ansible/
secrets.example
.env.example
.github/
```

命中敏感路径时，默认要求：

- CODEOWNERS 或 Security Maintainer 审批。
- CI 构建通过。
- 质量检查通过。
- 密钥扫描通过。
- 若仓库启用 AI 审计门禁，则 AI 审计通过。

## 合并门禁

PR 合并前必须统一执行 `canMerge` 判断。

最低要求：

1. 用户具备 `repo.merge_pull_request`。
2. 目标分支允许通过 PR 合并。
3. 审批数量满足分支保护要求。
4. CODEOWNERS 要求已满足。
5. required checks 全部通过。
6. 敏感路径审批要求已满足。
7. 强制功能门禁已满足。
8. PR 未处于 blocked、draft 或 unresolved conversation 状态。

required checks 应能接入以下外部系统：

- Woodpecker：构建、测试、部署前检查。
- SonarQube：质量门禁。
- Semgrep：静态安全扫描。
- Gitleaks：密钥扫描。
- Trivy：依赖、容器镜像或 IaC 扫描。
- AI Review Bot：AI 代码审计。

## GitHub 迁移需求

迁移能力需要支持：

- 批量发现 GitHub org/user 下的仓库。
- 迁移 Git history、branch、tag。
- 迁移 LFS 对象。
- 尽力迁移 issues、pull requests、labels、milestones、releases、wiki。
- 迁移后自动套用组织或仓库模板。
- 迁移后自动配置 Woodpecker webhook 或集成关系。
- 迁移后自动设置默认分支保护、required checks 和敏感路径保护。
- 迁移后输出校验报告。

迁移校验至少包含：

- 分支数量一致性。
- tag 数量一致性。
- 默认分支最新 commit 一致性。
- LFS 对象校验结果。
- issue/PR/release/wiki 迁移结果统计。
- 未迁移或部分迁移项目列表。

## Woodpecker 历史处理

系统应支持继续保留旧 Woodpecker 实例作为只读历史来源。

要求：

- 新仓库接入新 Woodpecker forge 配置。
- `.woodpecker.yml` 尽量原样复用。
- 旧 Woodpecker pipeline 历史不强制导入 Gitea 数据库。
- Gitea Enterprise 可以通过外链或只读聚合页面展示旧历史。
- 旧历史展示需要遵循 repo 读权限，未授权用户不可查看相关流水线信息。

## AI 审计功能授权

AI 审计作为功能授权项，不作为所有仓库的默认硬依赖。

最低要求：

- 可按全局、组织、仓库、分支配置是否启用 AI 审计。
- 可配置 AI 审计是否作为 required check。
- 可限制只有 Maintainer、Security Maintainer 或 Owner 可以手动触发 AI 审计。
- 可限制 AI 审计读取范围，例如仅 PR diff。
- AI 审计结果应回写 PR 评论和 commit status。
- AI 审计失败时是否阻塞合并由功能授权配置决定。

## 审计日志

以下动作必须记录审计日志：

- 用户登录、登出、认证失败。
- repo 权限变更。
- 角色定义变更。
- 团队成员变更。
- 功能授权变更。
- 分支保护变更。
- required checks 变更。
- CODEOWNERS 或敏感路径规则变更。
- webhook 变更。
- secret 创建、更新、删除；日志不得记录 secret 明文。
- 仓库迁移、转移、归档、删除。
- 手动触发 CI、质量检查、安全扫描或 AI 审计。
- 合并被允许或被拒绝的关键决策结果。

审计日志应至少包含：

```text
time
actor
actor_ip
action
resource_type
resource_id
before摘要
after摘要
decision
reason
request_id
```

## 管理界面需求

### 站点管理员

站点管理员需要能够管理：

- 全局角色定义。
- 全局功能授权。
- 全局默认组织模板。
- 全局默认仓库模板。
- 全局敏感路径规则。
- 全局 required checks 模板。
- 平台级审计日志。

### 组织管理员

组织管理员需要能够管理：

- 组织内团队和成员。
- 组织级角色绑定。
- 组织级功能授权。
- 组织级默认仓库模板。
- 组织级分支保护模板。
- 组织级敏感路径规则。

### 仓库 Owner

仓库 Owner 需要能够管理：

- 仓库成员和角色。
- 仓库功能授权，但不能关闭上级强制功能。
- 仓库分支保护。
- 仓库 required checks。
- 仓库敏感路径规则。
- 仓库 webhook 和 secret，前提是具备对应权限。

## 数据模型需求

建议新增或扩展以下模型，具体命名可在设计阶段调整：

```text
role_definition
role_permission
subject_role_binding
feature_definition
feature_grant
policy_template
policy_template_binding
protected_path_rule
authorization_audit_log
merge_gate_evaluation
```

设计要求：

- 支持全局、组织、仓库、团队、用户多级作用域。
- 支持继承和覆盖。
- 支持配置快照，便于审计某次 merge 决策使用了哪版策略。
- 支持迁移脚本，不能依赖启动时隐式修复生产数据。

## API 需求

需要提供 API 支持自动化管理：

- 查询角色定义。
- 创建、更新、删除自定义角色。
- 查询用户对 repo 的有效权限。
- 查询功能授权状态。
- 更新功能授权状态。
- 应用组织或仓库模板。
- 查询 merge gate 评估结果。
- 查询审计日志。
- 批量迁移仓库。

API 必须复用 Gitea 现有认证机制，并在每个写操作上执行授权检查。

## 兼容性要求

- 现有 Gitea repo Read、Write、Admin 语义需要提供兼容映射。
- 未启用企业授权增强时，默认行为应尽量接近上游 Gitea。
- 已存在仓库升级后不能丢失权限。
- 新权限模型需要提供迁移脚本。
- 迁移后应能回滚到安全的只读状态。

## 验收标准

第一阶段完成时，应满足：

- 可以定义 repo 自定义角色。
- 可以给用户或团队绑定 repo 角色。
- 可以按组织和仓库配置功能授权。
- 可以配置并继承默认仓库策略模板。
- 可以在合并 PR 前统一评估 required checks、CODEOWNERS、敏感路径和功能门禁。
- 可以记录关键授权和合并决策审计日志。
- 可以通过迁移脚本从原生 Gitea 权限平滑升级。
- 至少有 SQLite 下的单元测试或集成测试覆盖核心授权判断。

第二阶段完成时，应满足：

- GitHub 仓库迁移后可自动套用权限模板和功能模板。
- Woodpecker、SonarQube、Semgrep、Gitleaks、Trivy、AI Review Bot 的状态可以作为 required checks。
- 旧 Woodpecker 历史可以通过只读方式展示或跳转，并遵循 repo 读权限。
- 管理界面可以完成常用角色、功能授权、模板和审计日志操作。

## 实施约束

- 优先做浅 Fork，尽量减少与上游冲突。
- 优先新增企业授权控制层，不直接深改 Git 存储和 PR 基础模型。
- 需要迁移数据库结构时，必须增加显式 migration。
- 涉及 API 变更时必须更新 Swagger。
- 涉及前端页面时需要遵循本仓库前端开发规范。
- 所有 secret、token、私钥、kubeconfig 均不得写入仓库。
