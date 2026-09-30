## Why

已有企业微信登录、超管保护和团队治理需要先补齐生产运维边界，再承载后续企业授权增强。当前组织目标隐式推断、个人仓库配额硬编码、callback 缺少 HTTP 信任边界、mapping Swagger 与实际行为不符，且分阶段提交可能让失败 run 改变上一份有效授权状态。

## What Changes

- **BREAKING**：自动团队治理改用显式 `[enterprise.wecom] MANAGED_ORG_ID`，不再自动选择唯一组织；未配置、目标不存在或与已管理状态冲突时停止自动化并给出安全原因码，不影响企业微信 Web 登录可用性。
- 增加 `PERSONAL_REPO_QUOTA`，默认保持 10，允许 0 表示禁止新增个人仓库，负数和非法值拒绝；不删除既有仓库、不改变组织仓库审批规则。
- 增加默认关闭的管理员 callback HTTP 入口，提供 GET URL 验证和 POST 加密事件接收；只有验签、解密、接收方、企业、应用、事件和防重放检查通过后，才受理 authority refresh。通知本身不能授予管理员身份。
- 保留 legacy mapping 写路径作为明确不可用的兼容入口，统一返回 410；清理成功写入契约与请求绑定，修正 Swagger。只读查询面向当前企业应用的 generated 状态，既有人工 mapping 不自动转为可信生成来源。
- 将目录、影响授权的 identity 状态、管理员 authority、派生状态、团队/成员关系及管理员晋升纳入完整授权发布边界；任何阶段失败或取消均保留上一份有效状态。cron、callback 和登录刷新共享并发保护，run history 和失败审计独立保留。
- 增加稳定安全原因码和统一脱敏策略，以及上线、回滚 `LOGIN_ONLY`、登录故障、超管异常、cron 故障和离线管理员恢复 runbook。
- 不实现 repo action evaluator、企业角色、feature grant、merge gate、策略模板、新管理控制台或 offboarding。
- SSH key、PAT/API token 和 Git HTTP token 的创建、验证、吊销、scope 与账号状态语义均不变；本地 Gitea user 继续作为授权与审计主体。
- 数据库部署与验收仅面向 PostgreSQL（2026-09-30 用户确认）；无需适配或验收 MySQL/MSSQL。SQLite 仅保留既有快速测试用途，不删除 Gitea 原有数据库支持代码。

## Capabilities

### New Capabilities

- `identity/wecom-governance-ops`：安全 callback 接入、完整授权发布与并发控制、原因码/脱敏、上线回滚与故障恢复及认证兼容边界。

### Modified Capabilities

- `identity/wecom-admin-ui-super-admin`：明确自动化全流程失败不得提交部分授权，authority 不可用时不得继续发布，并保持只读管理界面与超管保护边界。
- `identity/wecom-directory-authz-mapping`：移除人工维护和人工 dry-run/apply 的产品契约，保留只读 generated 查询与 410 兼容入口，明确生成来源隔离。
- `organization/wecom-team-governance`：使用显式受管组织，禁止自动推断或迁移团队到其他组织。
- `repository/single-org-repo-governance`：个人仓库 quota 可配置，默认与原先 10 个限制一致，统一创建路径校验。

## Impact

- 配置：`modules/setting/enterprise_wecom.go`、配置测试及 `custom/conf/app.example.ini`。
- 服务与数据：`services/enterprisewecom/`、`models/enterprisewecom/`、`modelmigration/`、`services/cron/tasks_basic.go`；新增发布协调/版本、callback receipt、mapping 来源和 run 原因字段通过显式迁移交付，不修改原生 token/SSH 表。
- 路由与契约：新增独立 Web callback 入口；调整 `routers/api/v1/enterprisewecom/`、API 路由、`modules/structs/`、Swagger 注册及生成文件。callback 是 provider-to-server 协议，不是无认证管理员操作 API。
- 仓库创建：`services/repository/governance.go` 和所有调用其治理检查的 Web/API/service 创建路径。
- 文档与测试：`docs/enterprise-authz/` runbook、配置与旧 mapping 说明、service/settings/migration/integration 测试；沿用既有只读 Gitea admin 页面，不新增 UI 操作或布局。
- 不引入 OpenFGA、Keycloak 或第三方应用授权生命周期；当前自建应用仍使用企微 `超管` 标签显式成员来源。callback 事件可用性与字段需在部署应用类型下验证，不把第三方事件自动宣称为自建应用可用。
