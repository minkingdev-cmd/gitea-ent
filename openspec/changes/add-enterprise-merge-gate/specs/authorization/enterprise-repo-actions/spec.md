## MODIFIED Requirements

### Requirement: Repository actions use a validated stable vocabulary

系统 MUST 注册 `repo.view_metadata`、`repo.read_code`、`repo.clone`、`repo.create_branch`、`repo.push_branch`、`repo.push_protected_branch`、`repo.create_pull_request`、`repo.review_pull_request`、`repo.merge_pull_request`、`repo.manage_branch_protection`、`repo.manage_codeowners`、`repo.manage_webhook`、`repo.manage_ci`、`repo.manage_secret`、`repo.manage_feature_grant`、`repo.migrate`、`repo.transfer`、`repo.archive`、`repo.delete`、`repo.manage_access`、`repo.manage_sensitive_paths`、`repo.bypass_merge_gate`。每个 action MUST 有稳定 key、说明、相关 unit、风险和适用上下文；目录 MUST 明示 enforce 支持范围。管理角色写入 MUST 拒绝未知 action 或非 `allow` effect。`repo.manage_access` MUST 只表示原生 collaborator/team 仓库授权变更，MUST NOT 表示企业角色/绑定管理或 feature grant 管理。新 action MUST 独立可授权，MUST NOT 借 merge、manage_codeowners 或 manage_feature_grant 代替；目录和诊断 MUST NOT 等同产品操作、管理 authority 或完整门禁通过。

#### Scenario: Unknown action is rejected without partial writes

- **WHEN** 创建或更新角色的权限集包含拼写错误、未知 action 或 `deny` effect
- **THEN** 系统返回 422，不保存部分角色或权限，不将未知 action 当作 allow

#### Scenario: Action catalog does not imply a feature implementation

- **WHEN** 查询 `repo.manage_feature_grant` 的目录或进行 action 诊断
- **THEN** 目录/诊断本身不创建 grant、开启功能或修改 unit；真实管理操作继续遵循已交付的 feature grant authority、凭据、版本和审计合同

#### Scenario: Access management is independently grantable

- **WHEN** 有权管理员定义仅包含 `repo.manage_access` 的自定义角色
- **THEN** catalog/角色校验/诊断使用同一 action；它不自动授予 secret、feature grant、企业角色管理 API 或系统超管 UI authority

#### Scenario: Gate actions do not alias existing grants

- **WHEN** 自定义角色只具有 merge 或 manage_codeowners，或只新授予 manage_sensitive_paths
- **THEN** 不自动获得 bypass，路径管理也不授予 merge、global/org authority 或角色委派能力

## ADDED Requirements

### Requirement: Merge gate actions preserve default authority and history boundaries

两个新 action MUST 为高风险、可审计且受当前可信凭据/资源/条件约束的操作。原生 Owner 与当前可信系统管理 authority MUST 在对应资源/unit 前提下获得默认 action；原生 Admin 及 Maintainer/Security Maintainer MUST NOT 自动获得两个新 action。内置 Owner/Platform Admin MUST 通过版本化迁移补齐权限；既有复制的自定义角色、主体绑定、IsAdmin 与企微 authority MUST NOT 随迁移被扩权。

`repo.manage_sensitive_paths` MUST 只在仓库原生策略管理 authority 与写凭据均满足时允许实际写入；global/org 仍使用独立管理 authority。`repo.bypass_merge_gate` MUST 与 merge action、原生 bypass 资格、理由/清单及不可豁免守卫组合，在门禁 enforce 下阻断缺权。新 action MUST 不改变前序高风险 enforce 集或其它业务 fail-open 合同。旧版本目录/历史决策 MUST 按记录版本可读，MUST NOT 因目录升级被认定无效或重解释为新授权。

#### Scenario: Admin needs explicit delegation and native eligibility

- **WHEN** 原生 Admin 无新增 action，随后获得显式包含新 action 的自定义角色
- **THEN** 前者被拒绝；后者只有在相应原生准入、凭据和其他门禁条件均满足时可管理路径或请求 bypass，不能仅凭角色升级原生权限

#### Scenario: Trusted owner and stale administrator

- **WHEN** 原生 Owner 或当前可信系统超管操作，或旧会话的超管 authority 已被撤销
- **THEN** 前者按默认 action 与完整守卫处理，后者不按旧 IsAdmin/session 信息放行

#### Scenario: Migration preserves old records and custom roles

- **WHEN** 升级目录 seed 后查询 catalog version 1/2 的历史记录与既有复制角色
- **THEN** 历史仍按原版本解释，只有内置 Owner/Platform Admin 的新默认权限被补齐，自定义角色/成员关系不变
