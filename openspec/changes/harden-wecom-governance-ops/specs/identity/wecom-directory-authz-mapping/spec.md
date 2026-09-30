## REMOVED Requirements

### Requirement: Site administrators can manage WeCom authorization mappings

**Reason**：产品已采用自动 generated 治理；手工 mapping CRUD 与只读 UI/410 实际行为冲突。
**Migration**：管理员改用 generated 状态查询与 cron 自动化；既有写路径继续返回 410，不自动转化或删除旧人工 mapping 和成员关系。旧客户端不得依赖 create/update/delete/dry-run/apply 成功响应。

## ADDED Requirements

### Requirement: Mapping APIs expose generated read-only state and explicit legacy rejection

系统 MUST 保留当前 mapping list/get 路径作为只读 generated 查询，保持既有读取字段，并限定到当前配置企业应用的受管组织。访问 MUST 经过原生 token 和 admin scope 校验，治理启用时还 MUST 确认 active bound WeCom 管理权限；治理关闭时 MUST 不披露企业快照。Legacy create/update/delete/dry-run/apply 路径 MUST 在权限校验后统一返回 410，无论请求体为空、格式错误或 mapping ID 不存在，都不得进入绑定、规划或写入业务。Swagger MUST 将这些路径标为 deprecated，仅描述真实拒绝结果，不再声明成功 mutation。

#### Scenario: Super administrator reads generated mappings

- **WHEN** active bound WeCom 管理员以符合原生 admin scope 的 token 读取当前企业应用 generated mappings
- **THEN** 系统返回 200 和原有读取字段，不混入人工 mapping 或其他企业应用/组织状态

#### Scenario: Inaccessible mapping cannot be fetched by ID

- **WHEN** 合法管理员读取不存在、非生成来源或其他企业应用作用域的 mapping ID
- **THEN** 系统返回 404，不披露跨作用域记录

#### Scenario: Ordinary user or local administrator lacks management authority

- **WHEN** 无企业微信管理权限的用户或普通本地 site admin 查询 mapping
- **THEN** 系统返回 403，不披露 generated 状态、不改变 token 验证机制

#### Scenario: Mapping state is not exposed when governance is disabled

- **WHEN** 企业微信治理关闭且合法本地管理员访问 mapping 查询
- **THEN** 系统返回 404，不读取或披露旧企业快照；其他原生管理 API 保持既有行为

#### Scenario: All legacy operations return Gone without binding

- **WHEN** 合法管理员调用 POST create/dry-run/apply、PATCH update 或 DELETE disable，包括空/非法请求体和不存在 ID
- **THEN** 系统返回 410 与 `manual_mapping_unavailable` 安全消息，不先返回 body validation 错误、不改变 mapping/成员关系、不执行内部 dry-run

#### Scenario: Authentication and scope denial take precedence

- **WHEN** legacy mutation 请求没有有效凭证、admin scope 或必需的管理权限
- **THEN** 原生认证或授权 guard 先拒绝请求，不通过 legacy handler 绕过权限验证

#### Scenario: Swagger matches unavailable workflow

- **WHEN** 客户端查阅 mapping mutation 的生成 Swagger
- **THEN** operations 标为 deprecated，描述 410 与真实认证/授权错误，不声明 200/201/204/422 mutation 成功或请求绑定契约

## MODIFIED Requirements

### Requirement: Mapping reconciliation is idempotent and supports dry-run

系统 MUST 为内部自动化提供可规划的对账结果并保证重复应用幂等；dry-run planner MUST 保持无写入，MUST NOT 向用户暴露人工 dry-run/apply 操作。生产自动化 MUST 只应用当前企业应用、受管组织和明确 generated 来源的 mapping，整个选定发布单元失败不得提交部分授权。

#### Scenario: Dry-run reports planned membership changes

- **WHEN** 内部自动化规划当前作用域的 generated mappings
- **THEN** 系统提供新增、删除、跳过、保护和错误项，不改变成员关系

#### Scenario: Applying the same mapping twice is idempotent

- **WHEN** 自动化在来源与目标不变时重复应用同一 generated 集合
- **THEN** 第二次没有重复成员关系或额外权限变更

#### Scenario: Failed reconciliation does not apply a partial snapshot

- **WHEN** 任一选定 mapping 对账、写入或发布提交失败
- **THEN** 本次所有授权变更回滚，上次有效授权保持不变

#### Scenario: Legacy mappings are not consumed by internal apply

- **WHEN** 同一企业存在旧人工 mapping 或其他应用的 generated mapping
- **THEN** 内部自动化不应用、停用或删除其记录与既有成员关系

### Requirement: Directory sync can trigger mapping reconciliation safely

系统 MUST 在一次完整目录和 authority 候选验证成功后，通过同一授权发布单元完成 generated mapping 对账，MUST NOT 从失败、部分同步或单独目录提交的中间态授权。旧 `APPLY_AUTHZ_MAPPINGS_ON_SYNC` 设置 MUST NOT 开启第二条绕过发布协调的人工 mapping apply 路径。

#### Scenario: Successful directory sync triggers mapping reconciliation when enabled

- **WHEN** 企业微信完整自动化启用且目录/authority 候选、目标和派生校验成功
- **THEN** 系统在同一次原子发布中对账当前 generated mappings

#### Scenario: Failed directory sync does not change mapped authorization

- **WHEN** 同步失败、取消，或后续 authority/派生/对账失败
- **THEN** 系统不应用该候选 mapping，保留上次完整目录和有效授权

#### Scenario: Legacy post-sync flag cannot bypass automation

- **WHEN** 旧配置设置 `APPLY_AUTHZ_MAPPINGS_ON_SYNC = true`
- **THEN** 系统给出弃用提示，生产调用仍使用统一 generated 自动化入口，不启动额外人工 mapping apply

### Requirement: Mapping changes and applications are audited without sensitive data

系统 MUST 记录生成 mapping 变化、内部规划应用和 legacy 维护拒绝的安全审计，MUST NOT 保存 secret、access/suite token、OAuth code、原始 callback URL 或私密资料。

#### Scenario: Mapping configuration change is audited

- **WHEN** 自动化创建、更新或停用 generated mapping，或请求尝试人工维护
- **THEN** 审计记录系统/请求 actor、mapping 标识、来源与目标类型、结果和非敏感原因；人工维护只记录拒绝，不产生配置写入

#### Scenario: Mapping application is audited

- **WHEN** 完整自动化发布 generated mappings
- **THEN** 审计记录系统主体、run、结果和实际已提交计数，失败不能报告成功应用

#### Scenario: Sensitive values are not stored in audit metadata

- **WHEN** mapping 管理或对账记录日志和审计
- **THEN** 不包含 secret、token、OAuth code、原始 callback URL、手机号或私密 profile 字段
