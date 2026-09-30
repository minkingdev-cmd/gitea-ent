## Purpose

将既有企业微信身份、管理员和团队治理收敛为可安全上线、可诊断和可恢复的生产运维契约。明确外部 callback 信任边界、授权发布的原子性和并发安全、审计脱敏与故障恢复，同时保持 Gitea 原生 Git 与 token 认证语义。

## ADDED Requirements

### Requirement: Administrator callback is disabled by default and authenticated by provider protocol

系统 MUST 默认关闭 administrator callback，仅在显式启用且 callback 密钥与接收方配置有效时接收加密协议请求。系统 MUST 对 GET 验证与 POST 通知执行签名、解密和接收方校验；POST 还 MUST 校验受信明文中的企业、应用和支持的管理员事件。缺失边界字段 MUST 拒绝，不得用请求参数、未签名外层字段或本地默认值补齐。

#### Scenario: Callback is disabled

- **WHEN** callback 未启用或企业微信治理关闭时访问 callback 路径
- **THEN** 系统返回 404，既不刷新权限也不接受异步任务

#### Scenario: Provider verifies callback URL

- **WHEN** GET 的 `msg_signature`、`timestamp`、`nonce` 和 `echostr` 验证通过，解密接收方与配置一致
- **THEN** 系统以 200 原样返回解密 challenge 文本，不刷新 authority、不创建 Web 会话

#### Scenario: Valid administrator notification is accepted

- **WHEN** POST 签名、密文、接收方和时间窗口有效，受信事件明确匹配配置企业应用且为 `change_app_admin`
- **THEN** 系统持久受理一次 authority refresh，并以 200 返回协议确认文本 `success`

#### Scenario: Invalid signature or boundary is rejected

- **WHEN** callback 的签名、接收方、企业、应用校验失败或必需的受信边界字段缺失
- **THEN** 系统返回 403 安全错误，不调用 provider authority API，不改变授权状态，并记录脱敏原因码

#### Scenario: Malformed and oversized callbacks are rejected

- **WHEN** callback 参数重复或格式非法、XML/密文/padding/长度无效，或请求体超过允许大小
- **THEN** 系统分别返回 400 或 413，不 panic、不调度刷新、不回显原始数据

#### Scenario: Unsupported event or deployment mode is rejected

- **WHEN** 已通过协议验证的事件不在支持白名单内，或应用类型没有受支持的管理员通知协议
- **THEN** 系统返回 400 与安全原因码，不把普通消息、标签通知或第三方事件冒充该应用的管理员事件

### Requirement: Callback retries and replay cannot produce duplicate or stale grants

系统 MUST 以受信内容识别重复事件，在时间窗口内保证持久受理幂等；过期或过度未来的请求 MUST 拒绝。确认成功 MUST 代表任务已持久受理或之前已成功受理，不得仅启动进程内 goroutine 后确认。authority 来源必须通过当前 API 重新读取，MUST NOT 直接使用通知中的新旧管理员字段授予权限。

#### Scenario: Provider retries accepted event

- **WHEN** 同一合法事件在允许窗口内被重复投递，包括服务重启后或不同实例上的重试
- **THEN** 系统返回相同成功确认，不重复创建刷新任务或授权变更

#### Scenario: Expired or future notification arrives

- **WHEN** callback 时间戳超出允许过去窗口或未来偏差
- **THEN** 系统返回 403 和 `callback_timestamp_invalid`，不刷新 authority

#### Scenario: Receipt cannot be persisted

- **WHEN** 合法事件无法持久受理
- **THEN** 系统返回 503 供 provider 重试，不记录成功受理，也不修改权限

#### Scenario: Refresh after receipt fails

- **WHEN** 已受理 callback 的 authority API 或发布步骤失败
- **THEN** 系统保留上一份有效管理员状态，记录失败并对可重试错误执行有界重试；重试耗尽可由运维状态与审计识别

#### Scenario: Callback does not directly grant administrator authority

- **WHEN** callback 内容声称某成员是新管理员，但刷新得到的 authority 没有其管理权限
- **THEN** 系统不授予该成员受保护超管身份或站点管理员权限

### Requirement: Governance publishes a complete state atomically

一次完整自动化运行 MUST 将目录快照、影响权限判断的 identity 状态、authority、generated mapping/team/team-admin、受管成员关系和对应本地管理员晋升作为一个授权发布单元。任何 fetch、校验、派生、对账、写入或取消失败 MUST 保留上一份完整有效状态；unsupported/incomplete authority MUST NOT 被当作可发布的成功结果。callback/登录 authority-only 刷新 MUST 对 authority 与本地晋升执行同样原子保护。

#### Scenario: Directory changes would invalidate current protected administrator

- **WHEN** 本次候选目录不再包含受保护管理员，但后续 authority fetch 失败
- **THEN** 上一次 identity、authority 和保护判断保持不变，不因已写候选目录而失去管理员保护

#### Scenario: Late generated team or membership write fails

- **WHEN** 前几个团队已规划变更，但后续团队创建、mapping 写入或成员删除失败
- **THEN** 系统不提交本次任一团队、mapping、成员关系或管理员晋升，不把计划数量报告为已应用数量

#### Scenario: Authority promotion or transaction commit fails

- **WHEN** authority 候选快照已准备，但本地管理员晋升或最终提交失败
- **THEN** 系统保留旧 authority、本地管理员标志和完整有效授权版本

#### Scenario: Complete empty source differs from failed source

- **WHEN** provider 成功返回经过完整性验证的空目录或空 authority 集合
- **THEN** 系统按既有有效来源删除规则更新受管状态；权限不足、解析失败、缺失必需数据或 authority 标签缺失不能被当成成功空集合

#### Scenario: Cancelled run is recoverable

- **WHEN** 运行被取消或进程在提交前退出
- **THEN** 本次未提交授权不生效，运行状态最终可识别为失败或中断，后续运行可以安全重试

### Requirement: All authorization writers share concurrency and scope protection

cron、callback、登录刷新及内部同步/应用入口 MUST 共享企业应用作用域的发布协调，保证较旧候选结果不能覆盖较新有效状态。自动化 MUST 只修改明确归属当前企业应用和受管组织的生成状态，MUST NOT 收编、应用或删除 legacy 人工 mapping、人工成员关系或其他应用组织的状态。

#### Scenario: Callback and cron overlap

- **WHEN** callback、登录刷新与 cron 同时准备 authority 或完整授权候选
- **THEN** 同一企业应用发布有明确顺序；过期候选不提交，并记录可重试冲突或跳过原因

#### Scenario: Writer crashes or loses ownership

- **WHEN** 一个实例持有运行协调权后退出，或协调权已被其他实例接管
- **THEN** 后续实例可恢复运行，旧实例不能提交其失效候选

#### Scenario: Legacy manual mapping exists

- **WHEN** 自动化遇到此前人工创建的 mapping 或无法唯一确定生成来源的记录
- **THEN** 系统不将其作为新授权来源，不删除其既有关系；来源冲突阻断发布并提示运维复核

### Requirement: Operation outcomes use safe reason codes and retained run evidence

系统 MUST 为配置、callback 验证/受理、authority fetch、派生、应用、提交、取消和拒绝事件记录稳定原因码、阶段、关联 run/receipt、结果和安全计数。失败记录 MUST 独立于授权回滚而保留。日志、审计、run history 和返回错误 MUST NOT 包含 secret、AES key、access/suite token、OAuth code、原始 callback URL/密文/明文、手机号、邮箱或私密通讯录字段。

#### Scenario: Provider error embeds credentials

- **WHEN** 上游错误字符串包含 token、OAuth code、callback 查询串或私密资料
- **THEN** 系统持久化与返回的内容只保留白名单原因码和安全摘要，不保存或转发原始错误字符串

#### Scenario: Failed authorization transaction is rolled back

- **WHEN** 自动化发布事务失败
- **THEN** 失败 run/receipt 与安全审计仍可查询，标识失败阶段和原因，已应用计数为 0，旧成功版本不变

#### Scenario: Operational evidence storage fails

- **WHEN** 受理或运行记录不可持久化，或失败终态记录写入失败
- **THEN** 系统不虚报成功，返回或记录可识别的运维存储错误，并允许后续恢复未结束记录

### Requirement: Deployment and recovery procedures preserve governance boundaries

系统 MUST 提供本仓库内的上线、回滚与故障 runbook，覆盖配置预检、既有生成状态/人工 mapping 盘点、登录故障、超管异常、cron/callback 失败、暂停自动化、`LOGIN_ONLY` 回滚和离线管理员恢复。正常企业模式 MUST NOT 新增本地密码 Web 后门或手工超管选择器。

#### Scenario: Operator prepares production deployment

- **WHEN** 运维按 runbook 上线
- **THEN** 可核验显式组织、quota、authority 来源与应用类型、callback 密钥和签名样例、数据库迁移/备份、首次成功运行和认证兼容结果

#### Scenario: Login-only rollback does not restore admin access by itself

- **WHEN** 运维临时关闭 `LOGIN_ONLY` 排查登录故障
- **THEN** runbook 明确说明这不等于关闭企业后台超管 guard；需要经审批的离线恢复与配置回退，并记录操作和恢复严格模式的步骤

#### Scenario: Operator recovers administrator offline

- **WHEN** 运维执行批准的离线管理员恢复
- **THEN** runbook 提供受控停机、备份、现有管理 CLI 恢复、验证及重新启用治理流程，不要求手工伪造 authority 或修改 token/SSH 状态

### Requirement: Native authentication compatibility and forbidden Web paths remain unchanged

本变更 MUST NOT 替换本地 Gitea user、改变 SSH key/PAT/API token/Git HTTP token 的创建、认证、scope、吊销或账号状态规则，也 MUST NOT 新增企业微信专属 Git/token 校验或自动注销这些凭证。启用 `LOGIN_ONLY` 时既有非企业微信 Web 登录拒绝行为 MUST 保持。

#### Scenario: Native credentials continue to work

- **WHEN** 用户在配置变更、失败自动化或合法 callback 后使用既有 SSH key、PAT/API token 或 Git HTTP token
- **THEN** 原生认证与 scope/账号状态检查继续生效，不要求企业微信 OAuth 或 callback

#### Scenario: Disabled and restricted accounts keep native rules

- **WHEN** 禁用或受限用户尝试原生 Git/token 认证
- **THEN** 系统仍按 Gitea 既有账号状态规则处理，不增加企业微信来源的 token 撤销策略

#### Scenario: Forbidden Web authentication stays forbidden

- **WHEN** `LOGIN_ONLY` 下请求本地密码、注册、OpenID、Passkey、其他 OAuth、反向代理或 SSPI Web 登录
- **THEN** 原有拒绝行为保持，callback 不能建立或绕过 Web 会话；仅保留已有企微 OAuth 后的合法 MFA 续接
