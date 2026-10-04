## Why

`add-enterprise-authz-foundation-shadow` 已交付候选授权与真实入口观测，但候选 deny/error 不阻断高风险操作。按企业授权路线图 Proposal 3，需要把已验证的 action 决策接入实际写边界，并补齐原生仓库授权变更的 action 与可区分 shadow/enforce 的审计证据。

## What Changes

- 增加正式 enforce 模式，默认仍 disabled；shadow 保持原生结果。配置、启动预检、运行时错误与恢复流程必须明确，不能部分入口启用后宣称完整上线。
- **BREAKING（仅显式启用 enforce 时）**：在 PR merge（含 auto/force/manual）、保护分支写入、CODEOWNERS 修改、分支保护/敏感路径与 required checks 管理、repo webhook/secret/CI 管理、collaborator/team 仓库授权变更、transfer/archive/unarchive/delete 入口，在业务副作用前拒绝缺少对应 action 的请求。Web/API 的企业 action deny 返回 403；Git 协议返回安全的 receive 拒绝。
- 沿用原生 action 映射与显式 allow 角色的并集；企业角色不授予仓库可见性、不自动提升原生 Admin/Owner、不绕过原生操作权限或安全守卫。原生 Owner、当前可信企业超管及满足原生前提的显式授权人员可继续执行对应操作。
- 新增独立 `repo.manage_access` action，保护原生 collaborator/team 仓库授权变更；不借用 `repo.manage_feature_grant`，不让它委派企业角色管理 API/UI authority。
- 默认 fail-closed；明确区分缺权与 evaluator/上下文/证据错误。显式 fail-open 只在可恢复的授权基础设施错误上退回原生权限，不把 deny 变成 allow，也不使用企业角色兜底扩权。
- 记录 mode、实际授权结果、错误/降级原因、actor/repo/action 与原生执行终态；沿用受权查询和仅系统超管 UI，历史 shadow 仍可读，诊断仍不是执行许可。不新增 enforce UI 开关或低权限管理入口。
- SSH key、PAT/API token、Git HTTP token 的签发、认证、scope、吊销机制不变；enforce 下仅上述 repo action 的授权结果可能收紧。Git author、客户端字段与旧 hook ticket 都不能代替当前 actor/凭据或有效授权。
- 不实现 feature grant、完整 merge gate、新敏感路径策略子系统、低风险读写全覆盖、offboarding 或 `repo.migrate` enforce。敏感路径规则管理指现有 branch protection 的 protected/unprotected file patterns；其执行守卫原样保留。Linux 服务端限定、唯一合法企微 Web 登录、MFA 续接、callback 关闭与合法登录刷新/定时完整同步保持不变。

## Capabilities

### New Capabilities

无；沿用既有授权能力路径，不另建重叠 evaluator 合同。

### Modified Capabilities

- `authorization/enterprise-repo-actions`：从 disabled/shadow-only 扩展到高风险 enforce，增加 manage_access、错误语义、真实入口阻断及模式化证据。
- `authorization/enterprise-authz-management-ui`：现有历史查询区分 shadow/enforce/fallback，保持候选诊断和仅系统超管边界。

两项能力目前分别位于已完成但尚未归档的 foundation/UI change delta；本提案以其磁盘 artifact 和实现为基线。正式 sync/archive 必须先按依赖顺序建立两项 main specs，不在本轮修改或归档前置提案。

## Impact

- 复用 `modules/enterpriseauthz`、`services/enterpriseauthz`、`models/enterpriseauthz`，涉及配置/启动、Web/API/receive、文件修改、pull、repo/settings、org/team 和生命周期共享服务；保持浅 fork。
- 需要 additive `modelmigration/` migration：扩展决策证据字段、标记既有记录为 shadow、补齐内置 Owner/Platform Admin 的 manage_access seed；不改旧 migration、不回填主体绑定或原生权限。OpenFGA、Keycloak 不适用。
- 扩展既有 catalog/decision API 的兼容输出与 Swagger、管理 UI 展示；默认角色权限只向 Owner/Platform Admin 增加 manage_access，maintainer/security-maintainer 不自动获得授权委派能力。
- 依赖 foundation 的完整入口验证与当前可信企微 authority。UI 展示变更同时依赖已完成 management-ui；实施前核对真实代码、migration 和 verification，不把任务勾选当运行验证。`harden-wecom-governance-ops` 仍有未完任务，不把它的 callback gate 算入本变更。
- 增加模式×入口×角色/凭据×故障矩阵、Linux/SQLite/PostgreSQL 真实验证、部署与回退 runbook。仅创建本提案的 planning artifacts，不实施、修改运行配置、迁移、提交或发布。
