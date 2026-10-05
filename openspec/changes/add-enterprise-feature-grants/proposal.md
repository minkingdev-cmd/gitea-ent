## Why

当前企业授权已具备角色/action、shadow 观测和高风险 enforce，但无法按组织或仓库控制平台功能的可用性，也不能防止仓库关闭上级强制功能。本提案落实企业授权路线图 Proposal 4，为后续合并门禁和治理模板提供可解释、可审计的功能策略基础。

## What Changes

- 新增功能定义与功能授权模型，支持 `disabled`、`enabled`、`required`、`inherited`，仅覆盖 `global → org → repo`；个人仓库跳过 org。
- 登记路线图的 13 个 feature keys：Issues、PR、Packages、Wiki、Webhooks、Woodpecker CI、SonarQube、Semgrep、Gitleaks、Trivy、AI review、CI secret 管理和 required status checks。目录明确区分真实入口约束与仅策略输出，不将登记功能等同于已部署外部集成。
- 上级 `disabled` 不允许下级重新开启，上级 `required` 不允许下级关闭；继承结果包含来源、锁定原因、配置和策略版本。冲突策略明确报错或给出确定性安全结果，不按记录更新时间选胜者。
- 提供全局、组织、仓库授权管理 API 及受权的有效状态查询；仓库授权写入同时检查现有管理 authority、凭据上限和 `repo.manage_feature_grant`，不允许功能授权自举或替代原生权限。
- **BREAKING（仅显式启用 enterprise authz enforce）**：原生功能入口、repo unit 设置、Webhook 执行、CI secret 和 required checks 管理增加功能约束；拒绝在副作用前发生，禁用不删除历史数据。默认 seed 不改变现有 Gitea 功能配置，disabled/shadow 不阻断原生业务。
- 外部 CI/扫描/AI keys 本轮仅输出授权状态与经校验的 check context 配置；不执行扫描、推理、自动建 webhook 或新增合并阻断。`required` 是策略要求，不能被展示为扫描已运行或门禁已通过。
- 授权写入采用并发版本检查、事务和强制审计；补齐正式 DB migration、seed/preflight、故障降级、生命周期与回滚文档及 Linux 验证任务。
- 不新增功能管理 UI、team/user/branch/role 作用域、迁移授权、敏感路径子系统、策略模板或 offboarding。现有系统超管 UI 的 authority 不放宽，仅同步 action 能力说明。
- SSH key、PAT/API token、Git HTTP token 的认证、签发、scope 和吊销机制不变；enforce 下相关功能的业务访问可收紧，代码 clone/普通 push 不新增功能门禁。Gitea 本地 user 仍是授权与审计主体；企微唯一 Web 登录、合法 MFA 续接、callback 关闭、登录刷新与定时完整同步保持不变。

## Capabilities

### New Capabilities

- `authorization/enterprise-feature-grants`：功能目录、继承/冲突解析、管理 API 与权限、原生入口约束、策略输出、审计、迁移及兼容边界。

### Modified Capabilities

无正式主 spec 变更。角色/action 与管理 UI 的前序 change 尚未归档到主 specs；本能力显式承接其 `repo.manage_feature_grant` 由仅目录/诊断到真实管理操作的边界，不改写前序规划或验收证据。

## Impact

- 依赖当前工作区已交付的 `add-enterprise-authz-foundation-shadow`、`enforce-enterprise-authz-high-risk-actions`，复用现有 authority、凭据上限、决策记录和审计服务；实施前复核实际基线，任务勾选不替代验证。
- 主要影响 `models/enterpriseauthz`、`modules/enterpriseauthz`、`services/enterpriseauthz`、`modelmigration`、API 路由/DTO/Swagger，以及 repository unit、Issue/PR/Wiki、Packages、Webhook、secret、branch protection 的真实入口。
- 增加两张企业表和版本化 seed，不引入 OpenFGA、Keycloak、Flyway 或外部扫描服务依赖，不深改 Git/PR/Issue 基础模型，不实施 Windows 服务端适配。
- 本轮仅构建规划文档；不实施、部署、提交、推送、同步主 specs 或归档。

## 实施中经确认的范围补充

经用户批准，为 Cargo registry 自动生成的 Git 索引增加服务端可信 `repository.internal_usage=cargo-index` 用途标记及正式迁移。新索引由内部创建路径设置；旧索引必须由真实系统管理 authority 经明确仓库 ID 和用途确认的受控 CLI 认领，不能仅因 `_cargo-index` 名称自动标记或误禁普通代码仓库。enabled 预检拒绝未解决的历史索引冲突；用途随 stable ID 保持，HTTP/SSH 与 derived index 摘要均受 Packages 策略约束。本轮已进入实施，不代表 commit/push/deploy/归档授权。
