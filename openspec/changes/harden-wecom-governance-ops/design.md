## Context

动机见 `proposal.md`；范围来自 `docs/enterprise-authz/proposal-roadmap.md` 的 Proposal 1，兼容约束来自 `requirements.md` 与 `openspec/config.yaml`。

核对当前代码后的关键依据：

| 位置 | 当前行为 | 本设计约束 |
| --- | --- | --- |
| `services/enterprisewecom/generated.go:resolveGeneratedTargetOrg` | 未传 OrgID 时枚举组织并要求恰好一个 | 删除隐式推断，配置目标必须唯一且稳定 |
| `services/repository/governance.go` | quota 为常量 10，计数发生在创建前 | 配置化，并在仓库 DB 创建事务内最终检查 |
| `services/enterprisewecom/callback.go` | 信任可构造的 `Validated`，corp/agent 可为空 | HTTP handler 先建立协议信任，service 再执行严格边界检查 |
| `services/enterprisewecom/automation.go` | 目录、authority、派生、团队和成员依次调用，阶段分别提交 | 候选收集与授权发布分离，整次失败不能留中间态 |
| `services/enterprisewecom/authority.go` | authority 事务提交后逐个晋升用户 | authority 与晋升同一事务，不提前审计成功 |
| `services/enterprisewecom/team_governance.go` | 逐团队更新，再调用成员 apply | 所有团队与 apply 都使用同一发布事务 context |
| `services/enterprisewecom/sync.go` | 目录提交会更新 identity 状态，旧 flag 可触发独立 apply | identity 也影响超管判断，不能只回滚 team_user |
| `services/enterprisewecom/client.go:ListAppAdmins` | settings 构造的当前 client 使用 `超管` tag 显式 userlist；SuiteAccessToken 分支另有 API | 不新增第三方应用授权/token 生命周期，不把当前自建来源改成 suite |
| `routers/api/v1/enterprisewecom/mapping.go` | 所有 legacy 操作实际 410，但注释仍声明 2xx/422 | 保留 URL，修正拒绝契约并移除 mutation body bind |
| `services/context/admin_access.go` / `reqSiteAdmin` | 企业模式已要求 active bound management authority | 复用 guard，不重造角色或改变 PAT 认证 |
| `models/db/context.go:WithTx` | 嵌套事务复用传入 context | 复用现有事务能力，禁止 helper 丢失 context 或使用全局 engine |

当前正式 mapping spec 还保留人工 CRUD/dry-run/apply，与后续只读产品契约冲突。因此本 change 对该能力做显式 REMOVED/ADDED/MODIFIED，而非只新增运维 spec 让旧契约继续矛盾。

## Goals / Non-Goals

**Goals:**

- 将外部通知、候选快照和有效授权三个信任层分离，提供故障可恢复的持久证据。
- 收敛所有企业授权写入口的发布协调与事务上下文，避免后期失败或并发覆盖导致部分授权。
- 用 additive 元数据表达作用域和可信生成来源，不改 Gitea user/team/token/SSH 核心 schema。
- 配置、service、路由、Swagger、审计、迁移、runbook 和测试对应同一验收契约。

**Non-Goals:**

- 不新增企业角色、PDP、OpenFGA、Keycloak、merge gate、offboarding 或手工权限控制台。
- 不自动将既有多组织归并为一个组织、不迁移旧团队、不收编人工成员或 mapping。
- 不更改仓库转移策略、管理员降级策略或旧凭证生命周期；有效 authority 成功移除后的保护规则继续按既有语义处理。
- 不新增模板布局、菜单或操作控件。原因摘要通过现有 run `ErrorMessage` 安全摘要和既有日志/审计呈现；因此无需新的 UI prototype。实施证据与生产演练的边界记录在 `verification.md`，不把本地验证视为生产上线批准。

## Decisions

### 1. 显式组织 ID 与配置 quota

选择单一 `MANAGED_ORG_ID` 而非同时支持 name/ID：ID 不受重命名影响，不引入二义性优先级。0/未配置表示目标未就绪，自动化 preflight 返回 `managed_org_unconfigured`；负数/非法文本为配置错误。正整数解析后在运行时用现有 organization lookup 核验类型/存在性，失效目标使运行失败而非让整个登录服务无法启动。

调用者传入的 OrgID 仅能与配置一致；生产 cron、内部 sync、派生、reconcile 不能绕过配置。首次发布写入协调记录的 target ID，后续与当前 generated teams 的真实组织一致性共同检查；发生变化时返回 `managed_org_conflict`。只修改组织名称但 ID 不变可以继续。callback/登录 authority-only 刷新不需要组织目标，从而不会因初次组织配置缺失堵住超管登录与创建组织。

`PERSONAL_REPO_QUOTA = 10` 默认保持原行为，0 禁止新增，负数/非整数配置错误。不提供 -1/unlimited；不删除超额历史仓库。沿用原 namespace counting（包含该 owner 下所有实际仓库，组织仓库不计入），不覆盖更严格的原生限制。

最终 quota 检查与仓库 DB insertion 放在同一创建事务中，按 owner 串行化：在 PostgreSQL 的 owner 行获得事务级写协调后重新计数，再插入仓库；SQLite 快速测试继续使用既有写事务协调。不能只用进程内 mutex 或事务外 Count。覆盖新建、模板生成、fork、迁移/adopt 等实际新增个人 namespace 仓库入口，保留既有文件系统失败清理；DB 回滚/cleanup 后无额外额度计数器残留。不将这次配置化扩展为新 transfer policy。

2026-09-30 用户确认当前系统只部署 PostgreSQL：本 change 的迁移、lease/receipt、发布与 quota 验收只要求 PostgreSQL，不要求 MySQL/MSSQL 适配。保留 SQLite 既有测试以及 Gitea 通用数据库分支；数据库范围调整不豁免 callback 协议、认证或恢复演练。

备选：继续唯一组织推断或同时配置名称 → 容易错误目标或改名失效；只替换 quota 常量 → 并发可突破边界，不能满足配置限制。

### 2. 单一 callback 路由，不复用 OAuth callback

新增 `GET/POST /enterprise/wecom/callback/admin-authority` Web 路由，部署 URL 使用 Gitea `AppSubURL`。不再同时新增 API v1 alias，避免两套安全中间件/Swagger 契约；roadmap 的 Web/API 入口采用 Web 形式。OAuth state flow、Web session 建立、PAT 和 admin management API 不受此路由替代。

拟新增 `[enterprise.wecom]` 配置：

| 配置 | 默认/约束 |
| --- | --- |
| `MANAGED_ORG_ID` | 0；运行 preflight 验证，登录不依赖 |
| `PERSONAL_REPO_QUOTA` | 10；非负整数 |
| `ADMIN_CALLBACK_ENABLED` | false；企业治理关闭时不生效 |
| `ADMIN_CALLBACK_TOKEN_URI` / `ADMIN_CALLBACK_TOKEN` | 使用既有 `loadSecret` URI/inline 优先级，不复用 OAuth secret |
| `ADMIN_CALLBACK_AES_KEY_URI` / `ADMIN_CALLBACK_AES_KEY` | 同上；43 字符 EncodingAESKey 解码后 32 字节，启用时严格验证 |
| `ADMIN_CALLBACK_RECEIVER_ID` | 启用时显式必填，按部署协议配置 corp/suite 接收方，不能用缺失值放宽比较 |

请求防护策略先采用固定、可测试的内部边界：请求体最大 1 MiB；query 参数单值必填；允许过去 10 分钟、未来 60 秒（注入时钟测试，不 sleep）；GET/POST 同样验签和接收方校验。SHA-1 排序签名和 AES-CBC 解密仅用于遵循 provider 协议，不作为新自创安全方案。签名恒时比较；严格验证 base64、块长度、完整 PKCS#7 padding、消息长度和 receiver trailer，拒绝 XML 歧义/重复关键字段，不解析外部实体；错误仅返回安全摘要。

POST 验证顺序：请求大小/参数 → 时间窗口 → 密文签名 → 解密与 receiver → 事件解析 → 受信 corp/agent 与配置精确匹配 → `change_app_admin` 白名单 → receipt 持久化。以解密后的 `AuthCorpId`/协议实际企业字段和 `AgentID`/协议实际应用字段建立边界；适配器只接受已核验的字段格式。外层 `AgentID`、query/header、`Validated=true` 或默认 corp/agent 都不能替代受信字段；缺失任一必需业务边界返回 403。通知仅触发重新读取当前 authority API，不采用 `NewAdminUserID` 等声明直接 grant。

callback 路由不要求浏览器 session、PAT 或通用 CSRF token，因为调用者是 provider；CSRF 例外只限此路径且签名是必需认证，不能扩大到管理操作。GET 成功 200 + challenge，POST 持久受理后 200 + `success`；404 disabled、400 malformed/unsupported event、403 签名/边界/时间错误、413 body 超限、503 receipt 存储失败。限制请求速率与错误审计放大，不能记录完整 URL/query/body。

协议依据：企业微信团队 [Go 加解密示例](https://github.com/sbzhu/weworkapi_golang/blob/master/wxbizmsgcrypt/wxbizmsgcrypt.go)和 [URL 验证样例](https://github.com/sbzhu/weworkapi_php/blob/master/callback/Sample.php)可用于 golden vector。示例是协议参考而非安全实现直接复制（特别是 padding/长度边界）。2026-09-30 核对时官方文档站不可读取，尚未核实当前部署模式的 `change_app_admin` 字段和可投递性；本设计不宣称自建应用可收到该事件。启用前必须用官方应用模式文档与脱敏真实加密 fixture 证明该严格适配器可用；无支持事件时 callback 保持关闭，cron/登录的既有标签 API 刷新仍工作。若模式需额外 suite 授权基础设施，另建 proposal，不在此处隐式扩展。

备选：公开 REST `Validated` 字段 → 无信任边界；同步 HTTP 内跑完整外部 API → 容易超时重试；双 Web/API alias → 安全规则重复且没有实际需求。

### 3. 持久 receipt + 重试刷新，不靠临时 goroutine

新增 additive callback receipt 表：作用域 corp/agent、事件类型、内容摘要、唯一去重键、状态（pending/running/success/failed）、关联 run、attempt、next retry、安全 reason 和时间戳。仅保存处理所需非敏感元数据，不保存原始通知、旧新管理员列表或密钥。去重键基于验证后规范化事件内容与业务时间戳摘要，不依赖可变投递 nonce，保证重新加密的同一通知仍能识别。

receipt 与 pending 状态落库是 HTTP `success` 的前提；复用 Gitea queue 唤醒 worker，但 DB receipt 是事实来源：启动和定时调度扫描 due pending/中断任务，保证 persist 后 wake-up 前退出也不会丢任务。并发插入靠唯一约束；合法窗口内重复 receipt 直接确认。已终结 receipt 至少保留 24 小时（超过接收窗口），清理只删除终结记录，不删除 pending/running。

worker 在处理时重新读取 configured authority source，按同一发布协调执行 authority-only 事务。provider 暂时错误/并发冲突有界重试 5 次、退避 1/5/30/120/300 秒，不用原始事件 grant；unsupported/边界错误不重试。耗尽后 failed receipt + run/audit 可查询；下一次 cron/登录刷新仍可修复，不新增人工 mapping apply 按钮。worker/queue 关闭时中断状态可恢复，密钥轮换停止接收后更新配置并重新验证 URL，不能绕过旧事件签名。

### 4. 收集候选后短事务原子发布，所有 writer 统一协调

选择“外部 fetch 不持有 DB 事务 + 完整 DB 事务发布”，而非长事务内调用 provider 或失败后补偿回滚：本仓库已有事务 context 可复用，补偿不能恢复 identity/保护与并发结果，长事务则持锁等待网络。

完整运行：

```text
preflight + persist running record
  -> claim application lease/fencing generation
  -> collect complete directory and authority candidates outside DB transaction
  -> validate completeness and supported source
  -> begin short publish transaction
       -> verify lease token, base revision and managed org
       -> persist directory + authority-related identity status
       -> persist authority + local admin promotions
       -> derive scoped generated mappings/teams/team-admins
       -> reconcile scoped membership and safety checks
       -> update published revision + success run / receipt + safe mutation audits
     commit
  -> post-commit queue/cache notifications
```

新增协调表按 `(corp_id, agent_id)` 唯一记录：published revision/target org、lease owner、fencing generation、lease expiry。claim 使用 DB 条件更新，收集阶段租期有界并续租；在发布事务内条件更新锁定当前 token/revision 并再次确认未过期，失败则不写授权。该行写锁与发布事务一起持有至 commit，防止新 lease holder 在旧事务之后覆盖错误版本。按一致顺序获得协调锁后更新 user/team/成员行；缓存/queue 外部副作用只在 commit 后发布。进程 mutex 只能优化，不能取代 DB 跨实例协调。

所有 writer（cron、callback worker、登录 authority refresh、内部 `SyncDirectory`/apply）必须从协调入口进入。将现有 service 拆分为 fetch/validate 与 transaction-context persist helper；helper 不发 HTTP、不使用 Background/global engine、不单独提交/发 success。取消时授权事务回滚，终态记录使用从运行根 context 派生的有界清理 context，不再依赖已取消请求。run IDs 使用现有安全随机 ID 能力而非秒级时间拼接。

完整 cron 发布把身份状态一起纳入事务；否则候选目录先把 protected user 标为 out-of-scope，即使 authority 刷新失败也会改变实际保护判断。登录仍按原流程建立自身身份，但 authority refresh 的快照与晋升必须整体提交；失败不能改变既有其他用户的 authority/protection。authority-only 刷新不派生团队，也不跨过组织配置 gate。

明确错误分类：抓取失败/权限不足/解析缺字段、同名超管标签歧义、配置标签缺失和 unsupported 均不得解释为空快照；完整成功的空 userlist/目录则继续按既有来源移除与 last-owner/protected 规则处理。不要新增保留“最后一位已撤销管理员”的隐式授权；真正清空 authority 后需要离线恢复。unbound/inactive 用户、无 leader metadata 等既有非敏感 skip/unresolved 仍可发布，但数据库/来源完整性/目标/ownership 错误是整个 run 的致命错误。

失败 run 单独完成（独立于回滚事务），保存 stage/reason 与 attempted summary；实际 applied counters 为 0。成功 run/receipt 终态与授权 commit 同步落库，防止权限成功但 run failed。若终态持久化失败则回滚发布；失败证据自身保存失败需要安全日志和启动时恢复 running 状态，不能伪报成功。

### 5. generated 来源与 legacy mapping 契约收敛

为 `AuthzMapping` 增加 origin（默认 legacy）和 AgentID 作用域，生成行必须带 generated 来源。唯一约束纳入 AgentID，避免同 corp 不同 app 的定义相互复用。迁移只根据已有 generated mapping/team 与 source/target/run 元数据一致且唯一的证据回填来源/AgentID，不根据名称或 `CreatedBy=0` 猜测。冲突保持 legacy/unresolved，并在 preflight 阻断受影响自动化；不自动 deactivate 或删旧成员关系。

内部 planner、managed membership 的清理与读取都由 scoped generated mapping IDs 驱动，禁止现有按 CorpID 全量 List 直接进入 apply。既有人工或其他来源记录保留但不参与新授权；runbook 提供明确盘点与单独批准的处理路径。旧 `APPLY_AUTHZ_MAPPINGS_ON_SYNC` 作为弃用配置兼容读取并给出安全 warning，不开启第二条 apply 路径；生产调用统一完整自动化。

读取路径保留 `GET /api/v1/enterprise/wecom/mappings` 与 `/{id}`、现有响应字段和 include_inactive 语义（仅针对作用域内 generated 行）；无有效受管目标时 list 返回空列表，ID lookup 返回 404。企业治理关闭返回 404。不要把 legacy mapping 暴露成 generated 状态。

Legacy POST create/dry-run/apply、PATCH update、DELETE disable 保留 URL；复用现有 `reqToken()`、admin scope 与 `reqSiteAdmin()`，移除 JSON body bind，让 guard 后 handler 固定 410 `manual_mapping_unavailable`。保留的路由不查 ID、解析 body 或调用 planner。Swagger operation 保留但 deprecated，响应只写真实 410/认证授权错误，删除无消费者的 mutation request/response definitions，既有 GET fields 不破坏。不可通过改 token auth 来实现“只读”。

备选：直接删除写路由 → 404/405 兼容行为漂移；只从 Swagger 隐藏 → 真实行为仍不清楚；重新开放人工 CRUD → 与已确认产品治理来源冲突。

### 6. 原因码与权限矩阵

原因字段使用服务端稳定 code，safe summary 由白名单映射生成，不从 `error.Error()` 插值。常用 code：

- 目标/来源：`managed_org_unconfigured`、`managed_org_invalid`、`managed_org_conflict`、`mapping_origin_conflict`、`unsupported_authority_source`、`authority_source_missing`。
- callback：`callback_signature_invalid`、`callback_payload_invalid`、`callback_receiver_mismatch`、`callback_corp_mismatch`、`callback_agent_mismatch`、`callback_event_unsupported`、`callback_timestamp_invalid`、`callback_receipt_persist_failed`。
- 运行：`directory_fetch_failed`、`authority_fetch_failed`、`generation_failed`、`membership_apply_failed`、`promotion_failed`、`publish_conflict`、`publish_failed`、`run_cancelled`、`run_interrupted`、`run_busy`、`run_record_persist_failed`。
- 拒绝：`manual_mapping_unavailable`、`personal_repo_quota_exceeded`。

沿用现有 audit action family，callback acceptance/deny 无等价动作时添加最小必要动作。run/receipt 显式保存 stage/reason；既有 `ErrorMessage` 只写 safe summary 以适配现有只读页面。审计以 run/receipt、作用域、actor/target 本地 ID、计数为主；源对象标识只在明确需要的既有安全契约中保留，不写联系人姓名/邮箱/手机号或 callback 原文。敏感错误测试检查日志、API、audit、run、receipt，而不只检查一个出口。

| 入口/API | 后端 guard | relation/scope/role | 默认授权主体 | 前端入口 |
| --- | --- | --- | --- | --- |
| GET/POST callback | 专用 signature/decrypt/receiver/corp/agent/time/event | provider 签名；无 user role/新 scope | 仅验证通过的 provider | 无，非管理员 UI 操作 |
| GET mapping list/detail | reqToken + admin scope + reqSiteAdmin + scope filter | 原生 admin scope；active bound WeCom management | 既有企微派生超管 | 无新增入口；既有只读页面保留 |
| legacy mutation | 同上，随后固定 410 | 同上 | 任何角色均无维护权限 | 无控件 |
| cron/callback worker/internal publish | 配置 preflight + lease/fencing + tx | 系统服务主体；无通用用户 bypass | 系统任务 | 既有 cron/run/audit 只读入口 |
| 登录 authority refresh | 既有企微登录验证 + shared authority publisher | 仅支持的当前应用来源 | 通过企微登录流程的系统刷新 | 既有登录页 |
| 个人仓库新增 | 既有 user/repo guards + own namespace + quota + private | 原生 repo 权限，不新增企业角色 | 普通用户；原生更严格限制仍有效 | 既有新建/fork/迁移流程 |

DB migration：需要，采用本仓库 `modelmigration/`（不是其他项目的 Flyway）。OpenFGA/Keycloak：均不需要。自定义企业角色正例：不适用；原生 scoped token 和普通管理员拒绝正/负例必须覆盖。

## Risks / Trade-offs

- [显式 org 是配置兼容变化] → 上线前记录既有目标 ID；未配置安全停自动化，不阻塞登录或自动选择。
- [保留上次有效状态会延迟真正撤权] → 失败明确可观测，成功空快照仍可撤除，runbook 定义事故处置；不新增 token 撤销策略。
- [事件在当前自建模式可能不可投递] → callback 默认关闭，严格 adapter 不接收伪造替代事件；实际协议验证作为启用 gate，继续支持现有 cron/标签来源。
- [DB 原子性不自动覆盖缓存、queue、审计副作用] → 查清 service 调用链，把外部副作用后置，成功审计在授权事务或 commit 后可靠完成；注入后期错误验证无假成功。
- [PostgreSQL 协调和 quota 锁存在死锁/性能成本] → 固定锁顺序、短事务、有限重试；在真实 PostgreSQL 验证条件更新/唯一约束，SQLite 作为快速测试补充。网络不得在事务中等待。
- [历史 mapping 来源无法可靠判定] → 保守回填、冲突阻断，保留旧权限而不收编；另行审批数据修复，不以启动时自动 repair 代替 migration。
- [run/audit 历史原始错误可能已含敏感信息] → 迁移用统一安全 legacy 摘要替换不能证明安全的 ErrorMessage/LastError/error payload，不把旧内容复制到新日志；记录处理计数。
- [异步 receipt 扩大数据生命周期] → 唯一去重、最小 metadata、终结记录保留有界、pending/running 可恢复；queue 非事实源。

## Migration Plan

1. 停止 cron、关闭 callback 接收和 worker，备份 DB、app.ini 与当前部署版本；盘点现有 generated org、manual mappings、protected users、本地管理员与 run 状态。滚动部署不得混跑绕过新协调的旧 writer。
2. 增加协调表、receipt 表、mapping origin/AgentID/索引、run stage/reason 和必要历史脱敏的 `modelmigration`，用真实旧结构测试。旧权限关系不搬迁、不收编、不删除；既有 `is_admin` 和 token/SSH 表不回填改变。
3. 配置已存在的 `MANAGED_ORG_ID`；quota 默认 10；保持 callback off。设置 preflight 必要来源/密钥，核对旧 flag 弃用行为与冲突清单。
4. 在预生产执行完整首次运行和故障注入，核验实际授权版本、超管保护、成员关系与安全 run/audit；验证 forbidden Web paths 和原生 SSH/PAT/Git HTTP 行为。生产恢复 cron 前确认新版本所有 writer 一致。
5. 按真实应用模式验证 provider encrypted fixture/URL challenge，配置 HTTPS callback（含 AppSubURL），通过 signature/receiver/corp/agent/event/replay 正负例后才开启接收。无受支持管理员事件的部署保持关闭，不据此开启新的来源。
6. 回滚优先暂停 cron/callback/worker，保留已提交普通 Gitea 状态。`LOGIN_ONLY=false` 只解除严格 Web 登录入口，不绕过 enterprise admin guard；经事故审批再临时关闭 `ENABLED` 并重启，使既有本地 admin guard 回归原生。临时恢复必须同时核对原生密码登录配置，不把临时模式作为永久后门。
7. 离线恢复按运维单停服务/备份，用已验证的 `gitea admin user create --admin --random-password` 等既有 CLI 建立受控临时管理员（实际参数以部署版本 `--help` 为准），不生成额外 token、不手工造 authority。恢复外部超管标签/绑定与受管 org 后，核验成功刷新，再重新启用企业严格模式并处理临时账号。
8. 二进制降级不自动降 schema；旧版本未必支持新 mapping AgentID/索引和来源规则，必须先在备份环境验证。无法证明兼容时恢复匹配版本的完整 DB 备份并评估其后业务写入，不盲目在线回退。

## Verification Strategy

- 优先扩展已有 settings、automation、authority、generated、team_governance、reconcile、repository governance 测试；先失败测试再实现，各 slice 验证后推进。
- 关键失败矩阵：目录 fetch/解析、authority fetch/unsupported/缺标签、派生、第二个团队写入、成员删除/添加、晋升、commit、cancel、run 终态写入。断言旧 directory/identity/protection/generated/native/managed 状态全量不变，而非只检查一个 membership。
- callback：官方加密 vector + 真实模式 fixture；query duplicate/缺失、receiver/corp/agent 缺失/错、padding/长度/签名篡改、不支持事件、重放、重新加密重复、多实例 receipt 争用、restart recovery、retry exhausted 与无凭据调用。无效请求断言 provider client 调用次数为 0。
- mapping：GET fields/scope/404、admin scope/管理 authority 拒绝、每个 legacy method 在合法/空/坏 body 和不存在 ID 下 410，Swagger 无成功 mutation，内部 planner 无写入且不读 legacy。
- quota：0/default/custom/invalid、达限/降限/并发/失败恢复、组织不计数、跨 namespace/native 限制、实际 Web/API/创建派生入口。
- 兼容复用 `TestEnterpriseWeComLoginOnlyIntegration`、`TestEnterpriseWeComLoginOnlySmoke` 与现有 admin UI visibility，并按断言实际覆盖补充凭据创建/吊销、禁用/受限账号规则。单位/集成测试不调用真实企业微信服务。
- 执行 `make fmt`、相关 `make lint-go`、API 修改后 `make generate-swagger` / `make swagger-validate` / `make lint-swagger`，以及针对改动文件的 Markdown lint。仅修改 English locale 时按仓库约定执行。
- proposal 阶段只运行 artifact/delta/Markdown 校验；实际业务测试、provider 联调、DB 演练是实施验收，不在本轮虚报完成。
