## MODIFIED Requirements

### Requirement: WeCom authorization synchronization is scheduled and automatic

系统 MUST 定时同步企业微信目录与管理员 authority，派生 generated mapping/team/team-admin 并对账 Gitea 成员关系，无需管理员人工维护 mapping。一次完整运行 MUST 在目录/authority 完整性和目标校验后原子发布所有授权相关状态；任何阶段失败、取消或不支持 authority 来源时 MUST 不提交部分目录、identity、authority、派生、团队、成员或本地管理员晋升，并记录独立的安全运行结果。

#### Scenario: Scheduled sync derives and applies mappings

- **WHEN** 配置的企业微信计划运行成功
- **THEN** 系统完整同步目录、刷新 authority、派生 mapping/team/team-admin、对账成员关系，在同一发布单元提交后保留成功 run 与审计

#### Scenario: Failed sync does not apply partial authorization

- **WHEN** 目录、authority、派生、团队/成员对账、管理员晋升或最终提交任一失败
- **THEN** 所有本次授权写入回滚，上次有效状态不变，失败 run 记录安全阶段和原因码

#### Scenario: Manual mapping maintenance is not exposed

- **WHEN** 系统超管打开企业微信 admin UI
- **THEN** 页面只显示运行状态与 generated 数据，不提供 create/update/disable/dry-run/apply 控件

#### Scenario: Legacy manual mutation route is rejected if reachable

- **WHEN** 请求通过 legacy/direct 路径人工创建、修改、停用、dry-run 或 apply mapping
- **THEN** 权限校验后返回明确不可用结果，不更改 mapping 或成员关系

#### Scenario: Unsupported authority blocks publication

- **WHEN** authority API/配置标签来源不支持、缺失或无法提供完整有效快照
- **THEN** 运行不继续派生/发布候选权限，报告 unsupported/failed 原因并保留上一份有效管理员和团队状态，不授予本地兜底超管
