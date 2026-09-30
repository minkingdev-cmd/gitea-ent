# 企业微信治理上线与故障恢复手册

本手册对应 `harden-wecom-governance-ops`，替代旧说明中的人工 mapping CRUD、dry-run/apply 和 post-sync apply 上线流程。适用于本仓库版本及 PostgreSQL 部署（2026-09-30 用户确认，不要求 MySQL/MSSQL）；命令、迁移版本及部署服务名须在批准的变更单中填写并复核。本文提供操作步骤，不表示已完成真实 provider 联调或生产恢复演练。

## 1. 上线门槛与盘点

1. 记录部署二进制版本、数据库类型/schema 版本、配置路径、所有实例与任务运行节点、应用类型、`CORP_ID` / `AGENT_ID`、变更负责人和恢复负责人。禁止旧版本 writer 与新版本 cron、callback worker、登录 authority refresh 混跑；滚动升级不得让旧 writer 绕过新协调。
2. 确认 `LOGIN_SOURCE_NAME` 对应 active 企业微信 OAuth2 source，企业/应用与配置一致，网络、HTTPS、代理和本机时钟正常。当前自建应用 authority 来自 `SUPER_ADMIN_TAG_NAME`（默认 `超管`）标签的**显式 userlist**；标签中部门不自动成为超管。核验目录与标签 API 权限、应用可见范围和超管用户的 active 本地绑定。不能用本地用户名、`is_admin` 或 callback 声称的新管理员代替可信来源。
3. 从只读数据库导出或备份副本盘点：既有 generated mapping/team/team-admin 的真实组织 ID、mapping 来源/应用归属、受管成员、人工成员/人工 mapping、其他应用行、受保护用户和本地管理员、未结束 run/receipt。列表 GET 只展示当前作用域 generated 数据，不能用它证明没有 legacy 数据。盘点输出应仅含本地 ID、来源类别、状态和计数，私密联系人信息不进入工单。
4. 配置的组织必须已存在且是 organization。记录其稳定 ID；重命名无需换 ID。不得根据唯一组织、名称猜测目标或自动搬迁团队。历史来源只能按 generated source/target/run 一致且唯一的证据迁移；不按名称或 `CreatedBy=0` 收编。`mapping_origin_conflict` / `managed_org_conflict` 必须停止上线，经单独批准的迁移处理；不可手工删权限、伪造 origin/authority 以通过 gate。
5. 检查个人 namespace 的仓库数量与 quota 调整影响；下调不会删除旧仓库，也不修改组织仓库审批及更严格的原生限制。测试额度并发、失败回滚及新建、fork、模板、迁移/adopt 路径。

### 配置检查表

以下名称均属于 `[enterprise.wecom]`。真实凭据不写入仓库、工单、命令历史或日志。

| 配置 | 要求 |
| --- | --- |
| `ENABLED` | 企业治理总开关；关闭会回到原生管理员 guard，不只是暂停 cron |
| `LOGIN_ONLY` | 严格 Web 登录开关；正常运行保持 `true` |
| `LOGIN_SOURCE_NAME`、`CORP_ID`、`AGENT_ID` | 与真实 OAuth source/企业应用精确一致 |
| `CORP_SECRET_URI` / `CORP_SECRET` | 使用部署支持的 secret URI；URI 与 inline 优先级沿用 `loadSecret` |
| `MANAGED_ORG_ID` | 默认 `0` 表示未就绪；正整数且对应既有组织；目标错误不阻断企微 Web 登录 |
| `PERSONAL_REPO_QUOTA` | 默认 `10`；非负整数；`0` 禁止新增个人仓库；负数/非法文本拒绝 |
| `SUPER_ADMIN_TAG_NAME` | 自建应用可信超管标签名称；缺失、歧义、抓取失败不得视为空快照 |
| `SYNC_DEPARTMENTS`、`SYNC_TAGS` | 根据部署启用完整目录来源；不要以关闭一个来源掩盖不完整快照 |
| `APPLY_AUTHZ_MAPPINGS_ON_SYNC` | 弃用兼容项，保持 `false`；`true` 不提供独立 apply 路径 |
| `ADMIN_CALLBACK_ENABLED` | 默认 `false`；完成第 3 节真实模式 gate 后才能启用 |
| `ADMIN_CALLBACK_TOKEN_URI` / `ADMIN_CALLBACK_TOKEN` | callback 独立 token，不复用 OAuth secret |
| `ADMIN_CALLBACK_AES_KEY_URI` / `ADMIN_CALLBACK_AES_KEY` | 43 字符 EncodingAESKey，解码为 32 字节；启用时严格验证 |
| `ADMIN_CALLBACK_RECEIVER_ID` | 启用时显式填写协议要求的 corp/suite 接收方，不可缺省放宽校验 |

计划任务配置为 `[cron.sync_enterprise_wecom_directory]`，使用 `ENABLED`、`RUN_AT_START`、`SCHEDULE`；上线期间 `ENABLED=false`、`RUN_AT_START=false`。默认计划为 `@every 10m`。不要通过 legacy mapping API 人工执行计划。

## 2. 停写、备份、迁移与首次发布

1. 执行第 5 节暂停步骤并停止所有旧实例。在阻止新流量且服务完全退出后取得一致备份：完整 DB（包括普通 Gitea 授权关系）、`app.ini`、对应二进制/构建标识、仓库与存储恢复所需快照。加密保存配置和备份，记录 checksum、恢复方法及备份后的写入窗口。
2. 先在备份副本核验本版本 `modelmigration/` additive 迁移：协调/receipt 表、mapping `agent_id` / `origin` / 唯一索引、run stage/reason、历史安全摘要。复核迁移统计和 unresolved/conflict 清单，验证旧用户/团队/成员和 token/SSH 状态未被改写；迁移不得依靠启动 repair 或手工 SQL 作为交付。
3. 所有实例安装同一新版本；配置明确组织及来源，callback 保持关闭，cron 暂停。核对配置启动错误和 deprecated flag warning，严禁将原始 provider 错误复制到日志或工单。
4. 在预生产执行完整自动化与故障注入。首次成功要求目录、authority、generated 和成员、管理员晋升与 published revision 一起提交，run success/实际计数吻合；中途错误、取消、过期 lease、并发 writer 均保留上次完整状态，失败已应用计数为 0。未配置目标不得隐式创建组织，登录 authority-only 刷新仍可工作。
5. 生产仅在上述 gate 完成后恢复 cron。观察一次完整成功 run：当前应用/组织正确、revision 增加、无 legacy/其他应用成员变动、既有只读后台可访问。GET mapping 返回原有字段，仅当前 corp/agent/managed org/generated；`include_inactive=true` 不扩大作用域。无有效组织 list 为 `[]`、detail 为 404；关闭治理读接口为 404。
6. 安全验收：无 token 401、缺 admin scope/普通用户/无企微 authority 的本地 admin 403；合法管理员 legacy POST create/dry-run/apply、PATCH、DELETE（包括空/坏 body、不存在 ID）固定 410 `manual_mapping_unavailable`，只产生拒绝审计，不写 mapping/成员或运行 planner。Swagger mutation deprecated，不含成功响应/请求绑定。
7. 核验 `LOGIN_ONLY=true` 下本地密码、注册、OpenID、Passkey、其他 OAuth、反代、SSPI Web 登录拒绝及合法企微 MFA 续接。核验既有 SSH key、PAT/API token、Git HTTP token 的创建、认证、scope、吊销与禁用/受限账号行为仍按原生规则；callback 不建立 Web session。

## 3. Callback 启用、轮换与 receipt 排障

### 真实应用模式 gate

唯一入口为 `GET/POST <ROOT_URL（含 AppSubURL）>/enterprise/wecom/callback/admin-authority`，不是 OAuth callback，不另配 `/api/v1` alias。使用有效 HTTPS 和正确代理路径；访问日志不得记录 callback query/body，也不得在工单粘贴签名、challenge 或密文。代理/APM 同样关闭该路径 query/body 捕获；生产不得开启含 SQL 参数或通讯录 payload 的 debug 日志。

开启前取得**当前部署应用类型的官方协议依据和脱敏真实加密 fixture**，证明应用能投递 `change_app_admin`，且验证后明文有明确企业和应用字段。执行 URL challenge、签名/receiver/corp/agent/event 正负例、字段缺失、重复 query、时间窗与重新加密重复通知测试。协议示例/golden vector 不能代替真实模式联调；当前自建应用的事件可投递性尚未据此证明。无受支持管理员事件或需要新增 suite 授权基础设施时保持 callback disabled，继续 cron/登录标签 API 刷新，另行提案。

协议验收证据必须包括：

1. 当前应用类型、事件投递条件和官方文档正文/版本；第三方 SDK 的事件常量不能证明当前应用支持投递。
2. 经批准保存在受控位置的真实请求及其来源记录；生产 Token、EncodingAESKey、CorpSecret 和未脱敏 payload 不进入 Git、日志或聊天。
3. 解密后企业、应用、事件及事件时间字段的实际名称和位置，核对 receiver 与 `AuthCorpId` / `AgentID` 等 verifier 必需边界。不能补造真实通知中缺失的字段；脱敏后重新加密的向量须标注加工过程，不冒充原始独立加密证据。

官方材料暂不可访问或 fixture 未提供时，结论是**尚未验证、不可启用**，不是“官方不支持”的断言。若证据确认当前模式无受支持事件，则记录不可启用结论并保留 cron/登录刷新；若真实协议与 adapter 不一致，则先修订协议契约和测试，不能放宽受信边界来接收。

### 受理与故障判断

- GET 成功 200 返回解密 challenge；POST 持久受理后 200 `success`。这只是 receipt 已落库/已受理，不意味着权限已刷新。通知只触发重新读取可信 authority API，不直接采用通知管理员列表。
- 404 `callback_disabled`：企业或 callback 关闭。400 `callback_malformed` / `callback_event_unsupported`：格式/重复字段/不支持事件。403 `callback_signature_invalid` / `callback_receiver_mismatch` / `callback_scope_mismatch` / `callback_timestamp_invalid`：签名、receiver、corp/agent 或时间边界失败（非法时间格式为 400）。413 `callback_body_too_large`：body 超过 1 MiB。503 `callback_configuration_invalid` / `callback_storage_failed` / `callback_queue_unavailable`：配置、持久化或队列失败；不能把失败当成已受理。
- 时间窗允许过去 10 分钟、未来 60 秒；检查 NTP、代理重试延迟，不延长窗口绕过重放保护。GET/POST 均要求单值 query，禁止以外层/query/default agent 补齐受信字段。
- 按 receipt ID、run ID、stage/reason、attempt、next retry、状态排障；不导出原始 payload 或密钥。pending/running 是 DB 事实源，queue 仅唤醒；重启/定时扫描应恢复中断任务。相同已验证内容可在重启、多实例和重新加密投递后去重。
- 可重试 provider/发布竞争错误最多 5 次，退避 1/5/30/120/300 秒；耗尽标 failed、`callback_retry_exhausted` 并保留安全证据。修复上游后允许后续 cron/登录刷新，不调用人工 apply。终结 receipt 至少保留 24 小时，pending/running 不清理。

### 密钥轮换

先关闭接收并按第 5 节停止 worker/所有实例，保存配置备份与待处理计数；通过 secret 管理渠道更新 token/AES key URI 内容和 provider 配置，重启新版本并重新完成 URL 验证与模式 gate 后启用。URI 文件须限服务用户读取；不在 CLI 参数或 diff 中放密钥。不得为兼容旧通知跳过验签、接受双重模糊 receiver 或重写 receipt；已持久受理事件保留最小元数据，恢复后按当前 API 刷新。

## 4. 故障决策

| 现象/安全原因 | 处理与边界 |
| --- | --- |
| 企微 Web 登录失败 | 检查 active OAuth source、corp/agent、AppSubURL/redirect、TLS/网络、凭据期限、时钟及 MFA；仅收集安全原因。组织未配置不应阻断登录，不创建本地 Web 后门 |
| `managed_org_unconfigured` / `managed_org_invalid` / `managed_org_override` | 核对稳定 ID/对象类型/是否被删除及内部调用是否指定不同目标；暂停完整自动化，保留旧状态；不得按组织数量猜测 |
| `managed_org_conflict` / `mapping_origin_conflict` | 核对备份与来源证据，禁止自动迁移或收编；提交独立批准的迁移方案 |
| `authority_source_missing` / `authority_source_ambiguous` / `unsupported_authority_source` / `incomplete_authority_source`（超管标签缺失、歧义或来源不支持/不完整） | 修复配置、API 权限与应用模式，不能当空来源发布；上一份 authority 保留 |
| 标签完整且显式成员为空 | 这是成功空快照，可按既有规则撤除 authority；没有“保留最后管理员”隐式授权。上线前准备第 6 节离线恢复 |
| 超管成员未绑定/inactive/out-of-scope | 检查该成员企微合法登录绑定、身份状态及应用范围；本地 `is_admin` 不替代 active bound authority，不手工造 authority |
| `provider_error`（stage 为 directory/authority）或 `incomplete_directory_source` | 修复网络/来源权限/完整性，不发布候选；失败期间真正撤权也被延迟，应按事故等级控制网络/账号访问，不能声称已撤权 |
| `publish_failed`（按 stage 定位派生、成员、晋升或提交） | 校验 run/revision 与旧状态一致、实际计数 0，检查 DB/目标/ownership/完整性；修复后由统一入口重新完整运行，不逐阶段手工 apply |
| `writer_busy` / `stale_candidate` / `interrupted` / `cancelled` / `timed_out` | 检查所有实例版本与 lease/fencing、执行时长和取消原因；过期候选不得发布，不手工清 lease 让旧 writer 继续 |
| `callback_storage_failed` / `coordination_unavailable` / `evidence_persist_failed` | 检查 DB 写入/容量/连接；不得伪报成功；恢复扫描未结束记录，审计存储失败也必须记录安全告警 |

`scope_mismatch` 表示调用或候选企业/应用与配置不一致，应核对来源，不补默认值放宽边界。Callback receipt 可能以 `authority_source_unsupported` 标记不支持来源；按相同非重试故障处理。原因须与 stage 一起查看，不从原始 provider 文本推断成功。

故障 run/receipt 必须可查询且独立于授权回滚保留。失败保留旧授权也会延迟真正撤权；严重事故应使用既有受控原生账号/网络隔离程序并记录审批，不引入自动注销 token/SSH 的新策略。

## 5. 确定暂停与恢复自动化

1. 将 `[cron.sync_enterprise_wecom_directory] ENABLED=false`、`RUN_AT_START=false`，`[enterprise.wecom] ADMIN_CALLBACK_ENABLED=false` 写入批准的配置发布。禁止手动触发该 cron；配置变更须重启才生效。
2. 在代理层停止该 callback 路径的投递并阻断新的登录刷新流量，停止**全部** Gitea 实例及其 queue worker（按部署的服务管理命令，确认进程已退出）。callback 关闭配置重启后停止接收/后续领取，但不等于已终止在途任务；单独停 cron 不会停止登录 writer。完全停机并确认进程退出才是确定停止所有 writer 的方式。
3. 记录最后 success revision、running run、due receipt、lease 到期时间和实例退出证据，不手动改库终态。恢复时不得清 pending/running receipt；新版本恢复机制处理过期/中断记录。
4. 若只排查目录治理，可在 cron/callback 关闭后恢复同版服务；这**仍允许合法登录的 authority-only 刷新**；callback disabled 时 pending/running receipt 保留并暂停领取，重新启用后恢复。需要保持全静止就继续停机，不把部分暂停称为全部暂停。
5. 修复根因并核验来源/目标/DB 后，同版重启并观察恢复结果；先恢复 cron 完整成功，再按真实 fixture gate 恢复 callback。不要用 `APPLY_AUTHZ_MAPPINGS_ON_SYNC` 或 legacy API 绕过统一协调。

## 6. 登录回退与离线管理员恢复

`LOGIN_ONLY=false` 仅放开严格 Web 登录限制；只要 `ENABLED=true`，后台仍要求当前企业应用的 active bound management authority。仅改 `LOGIN_ONLY` 或 CLI 设置本地 admin 不能绕过企业后台 guard。正常企业模式不提供本地密码后门或手工超管选择器。

经事故审批的恢复流程：

1. 记录原因、临时账号责任人、恢复期限及复核人，执行第 5 节全部停机，完成一致 DB/配置/二进制备份。仅批准的隔离网络/维护窗口可开放临时管理访问。
2. 如需原生管理员入口，批准后临时设 `[enterprise.wecom] ENABLED=false`、`LOGIN_ONLY=false` 并核对原生密码登录配置（如 `ENABLE_PASSWORD_SIGNIN`）。callback 与 cron 继续关闭。回退总开关具有权限边界影响，不能以“仅登录修复”隐瞒。
3. 使用**部署同版二进制**，以服务运行用户、相同 work-path/config 在停机状态先核对 help：

   ```sh
   /path/to/gitea --work-path /path/to/work --config /path/to/app.ini admin user create --help
   /path/to/gitea --work-path /path/to/work --config /path/to/app.ini admin user change-password --help
   /path/to/gitea --work-path /path/to/work --config /path/to/app.ini admin user list --help
   ```

   确认该版本支持以下参数后，按审批选择创建唯一的受控临时管理员，而非随意修改既有账号：

   ```sh
   /path/to/gitea --work-path /path/to/work --config /path/to/app.ini admin user create \
     --username recovery-admin --email recovery-admin@example.invalid \
     --admin --random-password --must-change-password
   ```

   使用实际批准的账号/联系地址。随机密码输出视为 secret，只存安全渠道，不截屏/粘贴工单。**不传 `--access-token`**，不生成临时 PAT、不伪造 authority、不改 token/SSH 数据；已有账户的 password recovery 参数以同版 help 为准，不将密码写到命令历史。
4. 在隔离维护访问中启动回退配置，验证本地 admin 是原生 guard、管理入口及审计正常；SSH/PAT/Git HTTP 仍符合原生规则。修复外部超管标签、应用权限、OAuth source 和合法绑定；必须证明真实来源正确，不把临时账号直接标为企微超管。
5. 再次受控停机，重新启用 `ENABLED=true`，先用批准的企微绑定管理员验证可信 authority 刷新与后台可达，确认组织和完整发布成功；恢复 `LOGIN_ONLY=true` 并核验所有禁止 Web 入口。cron/callback 分别按 gate 恢复。
6. 按原生管理流程处理临时账号（停用/删除或回收权限），记录非敏感操作证据、时间及复核结果。最后检查恢复严格模式、超管保护、revision/receipt 与备份恢复责任；不得永久留临时后门。

## 7. 二进制回退与备份恢复

additive schema 不代表旧二进制可安全使用：mapping AgentID/来源/唯一索引、协调和 receipt 语义可能被旧 writer 忽略。降级不自动降 schema；先在隔离备份副本验证目标版本读取/写入/迁移和认证行为，禁止生产在线盲降或自行 drop 新字段。

无法证明兼容时：完全停机并关闭代理流量 → 备份当前事故现场 → 评估旧备份时间后的仓库、DB、存储业务写入与数据损失，取得恢复审批 → 成套恢复匹配版本的完整 DB/配置/二进制及对应存储 → 在隔离环境校验 schema、仓库与成员权限、账号与原生凭据 → 再按第 6 节管理员及严格模式流程恢复服务。不得只恢复企微表却保留不匹配的普通成员关系；不能恢复时保持停写并上报，不伪称已回退。

## 8. 验收证据与剩余验证

变更单逐项记录：配置预检（不含值）、备份校验/恢复演练、PostgreSQL 迁移/协调/receipt/事务并发验证、first-success run/revision、失败注入无部分授权、GET/410/guard/Swagger、禁止 Web 登录与原生凭据兼容、真实应用 callback fixture/URL 验证、停写/重启恢复、离线管理员恢复和恢复严格模式。未运行项写明未验证及负责人，不以单测或本文替代生产演练。

本地隔离验收已使用当前代码构建的 CLI，实际创建/删除临时管理员、验证企业 guard 和严格密码拒绝，并执行 PostgreSQL 全库备份恢复与 schema/sequence 比对。具体结果见 change 的 `verification.md`；测试 provider 和进程内配置切换不等于真实企微联调或生产停机重启。发布运维仍必须核对生产部署版本 `--help`，并执行经审批的成套恢复演练，不在本手册预填生产通过。

隔离 PostgreSQL 验收可显式设置 `GITEA_TEST_RECOVERY_BIN`（当前代码构建的绝对路径）、`GITEA_TEST_GOVERNANCE_LEASE_RENEWAL=1`，运行 `TestEnterpriseWeComPostgreSQLOfflineRecovery` 与 `TestEnterpriseWeComPublicationLeaseRenewalPostgreSQL`。需在 PATH 提供兼容版本的 `pg_dump`/`pg_restore`，使用 loopback、已核验不存在的专属 `local_debug_gitea_governance_test_` 前缀测试库、public schema 和独立 work path。原生集成测试会重建测试库；严禁指向共享或生产数据库。恢复测试会清理/恢复整个测试库 schema，而不是只恢复企微表；未显式开启的测试跳过不能视为验收通过。
