## MODIFIED Requirements

### Requirement: Teams are generated from Enterprise WeCom API data

系统 MUST 根据企业微信目录/标签快照和确定性策略，在显式配置的 `[enterprise.wecom] MANAGED_ORG_ID` 对应既有 Gitea organization 中生成团队。系统 MUST NOT 根据组织数量、名称猜测或调用者覆盖选择目标，MUST NOT 隐式创建目标组织或搬迁既有受管团队。未配置、目标无效或与既有受管组织冲突时 MUST 在修改授权前停止自动化并报告原因；Web 登录不依赖该目标配置。

#### Scenario: Department generates Gitea team

- **WHEN** 同步部门匹配派生策略且受管组织有效
- **THEN** 系统只在配置组织下生成或更新对应团队

#### Scenario: Tag generates Gitea team

- **WHEN** 同步标签匹配 capability-team 派生策略且受管组织有效
- **THEN** 系统只在配置组织下生成或更新对应团队

#### Scenario: Missing team derivation target is reported

- **WHEN** 部门或标签不能派生有效团队名称或组织目标
- **THEN** 系统记录安全 skip/error 原因，不创建宽泛兜底团队；致命目标错误阻止整次授权发布

#### Scenario: Managed organization is missing even when only one exists

- **WHEN** 未配置 `MANAGED_ORG_ID`，无论系统存在零个、一个或多个组织
- **THEN** 自动化以 `managed_org_unconfigured` 停止，不调用唯一组织推断、不改变既有授权

#### Scenario: Configured organization is invalid

- **WHEN** 配置 ID 不存在、指向个人用户，或内部调用指定不同目标
- **THEN** 自动化拒绝发布，记录安全原因，不创建组织或写入任何生成权限

#### Scenario: Multiple organizations exist

- **WHEN** 配置目标有效且存在其他组织
- **THEN** 自动化只对配置目标生效，不扫描选择或更新其他组织

#### Scenario: Managed organization changes after deployment

- **WHEN** 配置组织与已有当前应用的受管团队组织不一致
- **THEN** 自动化以 `managed_org_conflict` 停止，保留旧状态并要求单独批准的迁移，不搬迁或删除旧团队
