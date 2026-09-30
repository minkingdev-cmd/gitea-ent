## MODIFIED Requirements

### Requirement: Personal repositories are private and quota-limited

系统 MUST 允许普通成员在本人命名空间内无需审批地创建 Private 个人仓库，但必须受 `[enterprise.wecom] PERSONAL_REPO_QUOTA` 非负整数限制。默认 quota MUST 为 10；0 MUST 禁止新增个人仓库，非法或负值 MUST 被配置校验拒绝。各受管 Web/API/admin/service 创建路径 MUST 使用同一有效限制并防止并发创建超额。quota 调整 MUST NOT 删除既有仓库、改变组织仓库审批或把组织仓库计入个人 quota；企业治理关闭时 MUST 保持原生限制行为。

#### Scenario: Ordinary member creates personal private repository under quota

- **WHEN** 普通成员个人仓库数量低于配置 quota 并在本人命名空间创建仓库
- **THEN** 系统无需审批创建 Private 仓库

#### Scenario: Personal repository quota blocks creation

- **WHEN** 普通成员个人仓库数量已达到或超过配置 quota 并尝试新增
- **THEN** 系统拒绝创建并记录包含有效 quota、计数和原因码的安全审计

#### Scenario: Personal repository creation cannot target another user namespace

- **WHEN** 用户试图在其他用户命名空间创建个人仓库
- **THEN** 系统拒绝，既有更严格的 Gitea 安全规则继续生效

#### Scenario: Organization repositories do not count against personal quota

- **WHEN** 系统计数个人仓库额度
- **THEN** 只计入该用户命名空间的仓库，不计其创建或审批的组织仓库

#### Scenario: Default limit remains compatible

- **WHEN** 未配置 `PERSONAL_REPO_QUOTA`
- **THEN** 限制仍为 10，各创建路径按相同规则处理

#### Scenario: Zero quota and lowered quota preserve existing repositories

- **WHEN** quota 为 0 或下调至小于当前已拥有仓库数量
- **THEN** 系统拒绝后续新增，不删除、隐藏或改变既有仓库权限

#### Scenario: Concurrent creation cannot exceed quota

- **WHEN** 同一用户剩余一个额度且并发请求新增个人仓库
- **THEN** 最多一个请求成功持久化，失败或回滚的创建不永久消耗额度

#### Scenario: Native quota is not weakened

- **WHEN** 原生 Gitea 仓库限制比企业 quota 更严格，或企业治理已关闭
- **THEN** 原生限制继续生效，企业 quota 不作为绕过更严格限制的机制
