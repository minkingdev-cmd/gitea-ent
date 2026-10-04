## Why

现有 Gitea Read / Write / Admin / Owner 与企业微信团队治理不能表达可解释的细粒度 repo action，也缺少在正式阻断前验证新授权策略的决策证据。本变更按企业授权路线图 Proposal 2 建立角色、绑定、统一 evaluator 和真实请求 shadow 观测基础，为后续高风险 action enforce 提供可审核基线。

## What Changes

- 新增 `[enterprise.authz]` 的 `ENABLED=false`、`ENFORCE=false`、`FAIL_CLOSED_ON_ERROR=true`。本阶段只允许 disabled/shadow；`ENFORCE=true` 拒绝配置加载，不提供隐藏的阻断路径。shadow 错误不改变原生请求结果。
- 建立稳定的 repo action vocabulary（含读代码、clone、分支、PR、保护规则、CODEOWNERS、webhook、CI、secret、功能授权管理、迁移、转移、归档、删除），并声明每个 action 的 unit 与适用边界。
- 增加内置及自定义 repo 角色、allow-only 条件权限和主体角色绑定；支持 user/team/org 主体与 system/org/repo 作用域。用户已确认 repo 是资源作用域而非登录主体，不支持显式 deny。
- 按原生仓库和 unit 权限解析兼容 action 集，再叠加企业角色；不修改原生权限数据，不让角色绕过账号状态、仓库可见性、unit 可见性或现有安全守卫。
- 提供受原生权限保护的 API-only 角色与绑定管理、有效权限/指定 action 诊断、分页决策查询；企业角色不能自行授予这些管理 API 的访问权。
- 在真实 repo 读写入口添加只观察的适配，输出 allow/deny/error、missing actions、稳定 reason、原生结果与策略快照；复用现有审计体系并保存可查询决策记录，明确持久化失败及留存清理语义。
- 补齐本地目标仓库创建前迁移失败的用户/系统作用域安全审计；不伪造 repo 决策，不保存来源 URL 或凭据，审计故障不改变原生结果。
- 新增显式 additive migration、默认角色 seed、配置说明、上线/回滚 runbook 和兼容性测试。
- 不实现 feature grant、merge gate、策略模板、授权管理 UI、offboarding 或任何 action 强制阻断；不改变 Web 登录策略、SSH key、PAT/API token、Git HTTP token 的创建、认证、scope、吊销及原生授权结果。企业微信身份不替代本地 Gitea user。

## Capabilities

### New Capabilities

- `authorization/enterprise-repo-actions`：角色/绑定模型与管理、原生 action 映射、条件化 evaluator、真实请求 shadow 观测、解释性决策与审计查询及 disabled 兼容边界。

### Modified Capabilities

无。既有企业微信登录、团队治理、受保护管理员和仓库治理要求保持不变；新增 API 复用其 guard，不修改正式 specs。

## Impact

- 新增 `models/enterpriseauthz`、`services/enterpriseauthz`、`routers/api/v1/enterpriseauthz`，扩展 `modules/setting`、`modules/structs`、API 路由与 Swagger；只在既有 repo/Web/API/Git service 边界添加观察调用，避免反向包依赖或修改 PR/Git 核心模型。
- DB：在根目录 `modelmigration/` 注册 migration，创建三个角色/绑定表和一个决策表；复用 `models/audit` / `services/audit`。不引入 OpenFGA、Keycloak 或外部 PDP，不需其迁移，也不新增云凭据。
- 文档与验证：更新配置示例和企业授权说明，新增 shadow runbook；覆盖模型、evaluator、API 权限、真实入口结果不变、审计脱敏、SQLite 快速测试与 PostgreSQL 事务/迁移验证。
- 依赖：路线图前置 `harden-wecom-governance-ops`。2026-09-30 用户批准采用登录刷新 + 定时完整同步、callback 保持关闭，其真实协议验证只作为独立启用 gate，不阻断 shadow 实施。服务端永久仅部署 Linux，Windows 原生回归已移出验收范围，不再作为待解决依赖；范围调整不代表执行过 Windows 测试。
- 用户已请求应用本提案；不提交或推送，保留已有企业授权文档的未提交修改。Windows 服务端支持与原生回归永久排除，Windows 客户端访问 Linux 服务端不受影响。
