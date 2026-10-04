## 1. 实施基线与协议准备

- [x] 1.1 重新核对 proposal、5 份 delta specs、design 与仓库 instructions；记录受管组织、authority 来源、legacy mapping 兼容边界和全部生产写入口，不修改预存用户变更。
- [ ] 1.2 核验部署应用类型的官方管理员通知协议，取得脱敏加密 fixture 和真实边界字段证据，建立 golden vectors；无受支持事件的环境必须记录 callback 不可启用，不能冒充自建事件或扩展 suite 授权生命周期。
  - 2026-09-30：官方页访问被浏览器安全策略阻止，真实样本未提供；补齐 runbook 的证据清单与保密要求。当前仅能判定尚未验证、不可启用，不把它写成官方不支持。
- [x] 1.3 在现有 automation/authority/reconcile 测试中先增加后期失败导致部分写入、目录影响 protected identity、unsupported 来源继续运行的失败用例，记录可复现断言。

## 2. 显式组织与 quota 配置

- [x] 2.1 增加 `MANAGED_ORG_ID` 与 `PERSONAL_REPO_QUOTA` 读取/严格校验；扩展 settings 测试覆盖默认 0/10、quota 0/custom、非法/负数和禁用模式。
- [x] 2.2 将 generated target resolver 改为配置 ID；校验 organization 类型/存在性、调用覆盖和已管理 target 冲突，不再推断唯一组织，不阻断 authority-only 刷新或登录。
- [x] 2.3 扩展 generated/automation 测试：零/一/多组织未配置都拒绝、正确目标独占、删除目标/个人 ID 拒绝、改名 ID 稳定、修改目标冲突且旧状态不变。
- [x] 2.4 替换个人 quota 常量并实现所有新增个人 namespace 仓库路径的共同 DB 事务最终检查和 owner 写协调；保留 private/原生更严格限制及文件系统失败清理，不改变 transfer policy。
- [x] 2.5 扩展 repository governance 与真实创建路径测试：default/custom/zero/达限/下调、组织不计数、跨 namespace、同时争用最后额度、失败清理释放额度与治理关闭回归原生。
- [x] 2.6 更新 `custom/conf/app.example.ini` 的 org/quota 默认值、计数/0 语义、首次组织创建顺序和配置兼容变化说明。

## 3. additive 状态迁移与作用域来源

- [x] 3.1 在 `models/enterprisewecom` 增加企业应用协调表和 callback receipt 表、唯一作用域/去重约束、状态/时间/安全原因字段及相应 model tests。
- [x] 3.2 为 mapping 增加 origin/AgentID 与对应唯一索引，为 run 增加 stage/reason/发布关联字段；generated writers 显式写来源，managed membership 仍经 mapping ID 追踪。
- [x] 3.3 增加显式 `modelmigration`：创建 additive schema、保守回填有唯一 generated source/target/run 证据的来源，冲突留待复核，不按名称/actor 猜测、不收编人工记录、不改 token/SSH/原生权限 schema。
- [x] 3.4 迁移历史不可信 run/generated/authority 错误内容为安全 legacy 摘要，保留状态/计数而不复制可能敏感的原始错误；为有潜在敏感 metadata 的既有治理审计执行限定白名单处理。
- [x] 3.5 增加旧结构/数据 migration 测试，验证 generated 唯一回填、人工与歧义保持隔离、索引升级、历史脱敏、已有成员关系和管理员标志不变；按仓库迁移机制验证 PostgreSQL 重入安全（SQLite 快速测试作为补充）。

## 4. 完整授权发布与并发协调

- [x] 4.1 将目录和 authority 服务拆分为 fetch/validate 候选与 transaction-context persist helper；校验错误/权限不足/缺字段/标签缺失/同名歧义与完整空来源的区别，外部网络不进入发布事务。
- [x] 4.2 实现 DB 条件 claim/lease/revision/fencing 与固定锁顺序，处理续租、过期接管、取消和中断；用随机唯一 run ID 替代秒级 ID。
- [x] 4.3 在同一 `db.WithTx` 发布目录、identity、authority 与本地晋升、generated 状态、所有团队与 native/managed 成员关系，传播 context 并将内部错误视为整次失败。
- [x] 4.4 限定 planner/apply/清理为当前 corp/agent/org 的 generated mapping IDs，排除 legacy 人工和其他应用记录；保留 shared/manual membership、last-owner 与 active protected admin 规则。
- [x] 4.5 审核 org/team/user service 的缓存、queue 与审计副作用，后置非事务副作用，保证回滚不留下可见成功通知或污染缓存。
- [x] 4.6 将成功 run 终态和发布版本放入授权事务；失败 run 用独立有界清理 context 保存，applied counters 为 0；实现运行/receipt 中断恢复与证据保存失败报告。
- [x] 4.7 接入 cron、登录 authority-only refresh、callback worker 和内部 sync/apply 到统一 coordinator；旧 `APPLY_AUTHZ_MAPPINGS_ON_SYNC` 只读弃用提示，不再开旁路 apply。
- [x] 4.8 扩展故障注入矩阵：目录、authority、unsupported、派生、第二个团队写入、成员移除/新增、晋升、commit、cancel、run 保存失败；逐项断言旧 directory/identity/authority/protection/generated/team/native/managed 状态完整保留。
- [x] 4.9 增加并发/恢复测试：cron 与 callback/登录争用、过期候选不覆盖、失租 writer 不提交、重启接管、完整空来源成功移除和非敏感 unresolved 可成功发布；重复完整运行幂等。

## 5. 安全 callback HTTP 与持久处理

- [x] 5.1 增加默认关闭的 `ADMIN_CALLBACK_*` 配置、URI/inline secret 加载与启用校验；测试缺失 token/receiver、AES key 长度/解码、disabled 模式与密钥不泄露。
- [x] 5.2 实现协议 verifier 与严格事件 adapter：单值 query、1 MiB 上限、10 分钟过去/60 秒未来窗口、恒时签名比较、AES 解密/padding/长度/receiver、受信 corp/agent、`change_app_admin` 白名单；不接受外层字段或 `Validated` 代替校验。
- [x] 5.3 新增 GET/POST `/enterprise/wecom/callback/admin-authority`（含 AppSubURL），严格限定 provider 签名认证与 CSRF 例外，落实 200 challenge/success、404/400/403/413/503，不创建 Web session，不新增 API alias。
- [x] 5.4 实现 receipt 持久去重与队列唤醒、启动/定时 due 扫描、跨实例唯一受理；HTTP 确认之前必须落库，仅存安全摘要，终结 receipt 保留 24 小时且不清 pending/running。
- [x] 5.5 实现 authority-only worker 的有界重试（5 次退避）、终态失败与中断恢复，使用当前 API 重新获取管理权限，不从通知直接 grant；接入关闭/密钥轮换与清理生命周期。
- [x] 5.6 增加 verifier/handler 单元与真实路由测试：golden vector、缺字段/重复 query、签名/密文/padding/长度篡改、错 receiver/corp/agent、边界字段缺失、其他事件、过期/未来时间、超大 body、disabled 和无效请求 provider 调用次数为 0。
- [x] 5.7 增加 receipt/worker 测试：同一事件重新加密重试、跨实例重复、落库失败 503、persist 后 wake-up 前退出、重试成功/耗尽、旧通知不直接授权、cleanup 及 restart recovery。

## 6. mapping 只读契约与 Swagger

- [x] 6.1 mapping GET list/detail 只读当前 scope 的 generated 状态，保留原 response fields/include_inactive；无有效 target 返回空 list/404、治理 disabled 返回 404，继续使用原生 token/admin scope/active bound authority guard。
- [x] 6.2 Legacy POST create/dry-run/apply、PATCH update、DELETE disable 移除 body bind/lookup/planner，guard 后固定 410 `manual_mapping_unavailable`，写安全拒绝审计。
- [x] 6.3 修正 Swagger operation 为 deprecated，移除成功 mutation/无效 body 绑定契约和无消费者的定义；保留 GET 的真实字段与响应说明。
- [x] 6.4 增加 API 契约测试：读取 scope/字段/ID 404、普通用户/普通 site admin 403、无 token/不足 scope 原生拒绝、每种 legacy method 的正常/空/坏 body/不存在 ID 均 410、数据库与 planner 无副作用。
- [x] 6.5 运行 `make generate-swagger`、`make swagger-validate` 和 `make lint-swagger`，核对生成文件与路由的 410/deprecated、GET schema 和认证错误一致。

## 7. 审计原因与脱敏闭环

- [x] 7.1 定义白名单 stage/reason 与安全摘要，覆盖目标、callback、authority、pipeline、来源冲突、quota、拒绝、取消/中断和运维证据失败；禁止将原始 `error.Error()` 写入 run/receipt/audit/API/log。
- [x] 7.2 复用既有审计 action family，新增必要 callback 受理/拒绝动作；记录 actor、本地 target、run/receipt、scope、结果与实际提交计数，不提前记录成功。
- [x] 7.3 用带 secret/AES key/access token/suite token/OAuth code/callback URL/电话/邮箱的故障输入验证所有返回、日志、audit、run 和 receipt 出口脱敏，验证授权回滚后失败证据仍存在。

## 8. 上线与故障恢复文档

- [x] 8.1 新增 `docs/enterprise-authz/wecom-governance-ops-runbook.md`，覆盖 app/组织/quota/来源预检、迁移备份、legacy 盘点、首次成功发布与安全验收、禁止新旧 writer 混跑。
- [x] 8.2 写明 callback URL/HTTPS/AppSubURL、官方模式 fixture gate、key URI 管理/轮换、重放/重试/receipt 排障与无管理员事件时保持 callback disabled 的策略。
- [x] 8.3 写明企微登录故障、超管 tag 缺失/空/未绑定/失效、cron/authority/对账失败、旧有效状态保留与权限撤除风险，以及暂停 cron/callback/worker 的确定步骤。
- [x] 8.4 写明 `LOGIN_ONLY` 回滚不解除 admin guard、经审批临时 `ENABLED` 回退、离线停机/备份/既有 CLI 管理员恢复、验证和重新启用严格模式；用部署版本 CLI help 核对命令，不手工伪造 authority 或改 token/SSH。
- [x] 8.5 记录 additive schema 的二进制回退限制和匹配 DB 备份恢复流程；更新相关企业授权说明与配置文档，删除过时人工 mapping 成功契约，不修改无关路线图内容。

## 9. 端到端兼容与最终验收

- [ ] 9.1 运行并按缺口扩展 `TestEnterpriseWeComLoginOnlyIntegration` / `TestEnterpriseWeComLoginOnlySmoke`：Linux 服务端的本地密码、注册、OpenID、Passkey、其他 OAuth、反代 Web 登录拒绝及跨平台 SSPI verifier 前置拒绝，合法企微 MFA 续接，callback 不生成会话；不要求 Windows 服务端原生执行。
  - 2026-09-30：补齐 SSPI verifier 初始化前拒绝、active source/Negotiate HTTP 与 Cookie 续用测试，PostgreSQL 集成通过；Windows 原生执行仍待可用 runner，不以跨平台静态检查替代。
  - 范围更新：用户明确服务端永久仅部署 Linux，上述 Windows runner 缺口已移出验收范围，不再构成阻塞。本次只同步范围，不将历史 macOS 测试改称 Linux 原生执行，也不自动勾选任务。
- [x] 9.2 验证正常/禁用/受限用户的 SSH key、PAT/API token、Git HTTP token 创建/认证/scope/吊销仍遵循原生规则，合法 callback 和失败 run 不额外撤销凭据；仓库访问继续使用 Gitea subjects。
- [x] 9.3 运行现有 admin UI visibility/组织审批/受管 team guard 回归测试，确认普通 site admin 拒绝、企微管理超管正例、只读入口无人工操作；本 change 不新增自定义企业角色或 UI prototype。
- [x] 9.4 在真实 PostgreSQL 测试环境验证迁移、lease/receipt 唯一性、发布事务和 quota 并发；保留 SQLite 快速测试，不要求 MySQL/MSSQL 适配或验收（2026-09-30 用户确认）。
- [x] 9.5 执行针对修改范围的单测/集成测试、`make fmt`、`make lint-go`、Swagger 检查及改动 Markdown lint；若改 go.mod 再 `make tidy`，如触及 templates/TS/CSS 则执行对应 lint。
- [x] 9.6 逐项对照 5 份 delta specs 与 roadmap 验收点，审查最终 diff/敏感字段/生产调用可达性和 runbook 恢复演练，记录证据；运行 `openspec validate harden-wecom-governance-ops --strict`，不将 artifact 完成当作业务验收。
