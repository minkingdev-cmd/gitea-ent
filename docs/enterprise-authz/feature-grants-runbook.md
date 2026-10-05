# 企业功能授权运维手册

## 1. 当前边界

本文对应 `add-enterprise-feature-grants` 当前实现；不是生产发布、生产恢复或外部集成已部署的证明。实际运行环境、命令、退出码及未验证项目由该 change 的 `verification.md` 记录。服务端仅部署和验收 Linux；不限制 Windows 客户端访问。

功能授权叠加在原生认证、token scope、资源可见性、repo unit、既有企业 action 和分支保护之上，不能替代它们或自举管理权限。企微唯一 Web 登录、合法 MFA、登录刷新及定时完整同步保持不变，`ADMIN_CALLBACK_ENABLED=false`；SSH key、PAT/API token、Git HTTP token 的认证、签发、scope 与吊销不变。普通代码 clone/push 不新增功能门禁；Wiki Git 与受信用途 Cargo 索引按对应业务策略处理。

没有新的功能管理 UI、team/user/branch/role 功能作用域、治理模板、敏感路径子系统或完整 merge gate。现有授权管理 UI 的系统超管 authority 不放宽。

## 2. 目录、继承与配置

功能目录版本为 1，全部只支持 `global → org → repo`；个人仓库跳过 org，组织仓库每次使用当前 owner。全局在内部映射 `ScopeSystem`，外部 API 仍使用 `global`。

| key | 默认状态 | 能力与本轮边界 |
| --- | --- | --- |
| `feature.issues` | enabled | native_gate：内部/外部 tracker、内容与列表/搜索/通知/导出、设置与 shared service |
| `feature.pull_requests` | enabled | native_gate：PR 详情/创建/评审、AGit、实际及延迟 merge、聚合与最终 unit 设置 |
| `feature.packages` | enabled | native_gate：真实 owner 和关联 repo、registry 读写/列表/索引、关联与 unit 设置 |
| `feature.wiki` | enabled | native_gate：内部/外部 Wiki、读写/导出与 Wiki Git HTTP/SSH、unit 设置 |
| `feature.webhooks` | enabled | native_gate：repo/org/system 管理、test/redelivery、入队与 worker 发送 |
| `feature.ci_secret_management` | enabled | native_gate：secret 管理读取/新增/更新/复制；不改变 runner 正常消费 |
| `feature.required_status_checks` | enabled | native_gate：分支保护 checks 的完整变更/删除/优先级意图；既有保护继续执行 |
| `feature.woodpecker_ci` | disabled | policy_only：授权与 check contexts 输出，不代表 Gitea Actions 开关 |
| `feature.sonarqube_quality_gate` | disabled | policy_only：授权与 check contexts 输出 |
| `feature.semgrep_scan` | disabled | policy_only：授权与 check contexts 输出 |
| `feature.gitleaks_scan` | disabled | policy_only：授权与 check contexts 输出 |
| `feature.trivy_scan` | disabled | policy_only：授权与 check contexts 输出 |
| `feature.ai_review` | disabled | policy_only：授权与 check contexts 输出 |

六个 policy_only key 不执行扫描/AI，不创建 webhook/integration/token，不伪造 commit status，不丢弃真实外部 status 回调，也不因 required 新增 merge deny。`policy_required` 不是扫描已执行、通过或集成已可用。

- `inherited` 与缺少记录不贡献本层状态/配置；没有显式 grant 时回落目录默认值，默认 disabled 不形成上级锁。
- 从根向下遇到的第一个显式 `disabled` 或 `required` 锁定有效状态。disabled 不许下级开启；required 不许下级关闭。无锁时最近显式状态覆盖上级 enabled。
- 父级变更不改写旧下级记录；旧冲突在 effective 查询中标记为 ignored/conflict，移除父级锁后重新解析。写入新增父级冲突返回 409 `feature_parent_locked`。
- 无 required 锁时，最近显式配置完整替换上级配置，空配置也是替换。required 锁下保留有效 required 层 contexts 的并集，下级只能补充；被 disabled 锁遮蔽的冲突配置不贡献执行要求。
- 原生 unit/Webhook/secret 只接受 `{}`；required status checks 与六个外部 key 仅支持 `check_contexts`。inherited 必须 `{}`。拒绝未知/重复字段、null、非法 UTF-8、尾随 JSON、凭据/URL/命令字段；配置最多 16 KiB，contexts 原始列表最多 64 项，每项 1–128 UTF-8 bytes、无控制字符或首尾空白，排序去重。

required 不补建 unit、hook、secret、check rule 或外部 adapter，不提升权限。查看 `native_available` 和 `pending`，再盘点实际原生资源；不得仅凭 required 宣布治理要求已满足。unit 关闭、原生全局禁用或资源缺失必须按已有受权路径收敛，不靠 mode 切换自动恢复。

## 3. API、权限与投影

以下均为 `/api/v1` 下的端点，要求认证。管理 authority 由当前数据库身份与 URL 目标重判，不接受 body 的 actor/owner/scope ID。

| 端点 | 方法与投影 | 必须满足 |
| --- | --- | --- |
| `/enterprise/authz/features` | GET，固定目录 | admin read scope + 当前可信系统管理 authority |
| `/enterprise/authz/features/{key}/grants/global` | GET/PUT/DELETE，global raw 管理投影 | admin read/write scope + 当前可信系统管理 authority |
| `/orgs/{org}/enterprise/authz/features` | GET，org 管理列表 | organization read scope + 目标 org owner 或可信系统管理 authority |
| `/orgs/{org}/enterprise/authz/features/{key}` | GET/PUT/DELETE，org raw 管理投影 | organization read/write scope + 同一 org authority |
| `/repos/{owner}/{repo}/enterprise/authz/features` | GET，effective reader 列表 | repository read scope + 凭据 read ceiling + 原生 repo 可见性 |
| `/repos/{owner}/{repo}/enterprise/authz/features/{key}` | GET，effective reader；PUT/DELETE，管理变更 | 读同上；写还需当前 repo 授权管理 authority、写 credential ceiling 与 `repo.manage_feature_grant` |
| `/repos/{owner}/{repo}/enterprise/authz/features/{key}/grant` | GET，repo raw 管理投影 | repository read scope + 当前 repo 授权管理 authority |

企微启用时本地 `IsAdmin` 单独不足以取得系统 authority；企微关闭时沿用原生 site admin。repo 管理 authority 在企微模式沿用既有仓库授权管理员规则，非企微模式沿用原生 Admin；有 action 但无 authority 仍被拒绝。企业 Platform Admin 角色或 repo action 不委派 global/org 管理权限。shadow 可以管理策略，但不能跳过管理 API 自身的 authority/action/凭据检查；只读、public-only 或跨 scope token 不得写 grant。

reader 只看到 key、有效状态、来源层级、locked/conflict、能力类型、native availability/pending 与配置 schema 版本；不返回 contexts、祖先 ID、raw chain、操作者或其他仓库信息。管理投影额外显示本范围 grant/revision、有效配置与合法祖先 chain/锁/冲突、chain hash 和 policy revision。hash 不是执行票据；查询结果不是执行许可或外部运行结果。

列表支持 `page`/`limit`（最多 100），带 `X-Total-Count`。尚无本层记录时显示 inherited、`config={}`、revision=0，不伪造持久化行。

PUT 固定必填 body：

```json
{"state":"required","config":{"check_contexts":["security/gitleaks"]},"expected_revision":0}
```

该示例适用于 `feature.gitleaks_scan` 等允许 contexts 的 key，不适用于 Wiki/Issues 等空配置 key。首次写入 expected_revision=0；更新读取并提交当前 revision，200 返回完整本范围管理投影。DELETE 使用 `?expected_revision=N`，204 将已有行重置为 inherited/空配置并递增版本，不删除版本标记；不存在且 N=0 无副作用。相同版本、语义不变的重试不增版本，也不重复成功变更审计；旧版本返回 409 `revision_conflict`。

认证 401；权限/功能拒绝 403；企业授权关闭/不存在/未知查询 key 404；revision/parent lock 409；非法输入/写入未知 key 422；管理存储/强制审计失败安全 500 `policy_storage_failed`。原生功能设施故障默认安全 503；各 Git/registry 协议保留原生安全错误格式。错误不回显配置正文。

## 4. 模式、原子性与清理边界

沿用 `[enterprise.authz]` 三个开关，不新增 feature enforce 开关：

| 模式 | 配置 | 结果 |
| --- | --- | --- |
| disabled | ENABLED=false，ENFORCE=false | 原生业务不查询 feature DB；新策略 API 404，保留策略/历史 |
| shadow | ENABLED=true，ENFORCE=false | 原生响应与副作用不因候选 deny/error 改变；记录安全候选观测 |
| enforce | ENABLED=true，ENFORCE=true | native_gate 在读取/首副作用或队列发送前检查当前策略 |

聚合列表、计数、统计和搜索使用固定标签的 `enterprise_feature_query_candidate_total{feature_key,result}`；`result` 仅为 `would_deny`、`would_allow`、`error`。候选探针保留真实原生权限与筛选条件，在分页前以一次 EXISTS（外部索引为同条件最多 1 个命中的元数据查询）判断，不逐行评估、不记录对象 ID/内容、不把候选结果用于原生过滤。每个探针继承调用方取消并最多 1 秒，失败只记 error，不改变原生响应、count、权限或事务。已有事务无法安全建立独立快照时诚实记录 error，不修改调用方 session context。此聚合指标不是逐对象许可或成功审计证据，也不替代执行入口的强制审计。准入/配额使用的 raw 生命周期统计、清理 capability 查询不作为用户聚合读取观测。


默认 `FAIL_CLOSED_ON_ERROR=true`。显式 false 仅允许原生业务对可恢复策略/观测设施故障回退到已确认的原生权限；明确 disabled/required 违反、不可信上下文、取消及原生拒绝不能 fail-open，grant 管理写事务也不能降级。无法持久化证据时只保留安全日志/指标，不宣称已完整审计。

PostgreSQL 业务事务中的策略/审计观测使用 savepoint 和事务内 `statement_timeout`，不放宽原有更短限制；成功恢复原值，失败回滚到 savepoint，嵌套调用恢复准确的 SQL context。观测 deadline 不直接取消 `lib/pq` 的整个业务连接，原生请求自身的取消仍生效。只读权限快照中的审计是 `policy_probe`、`actual_decision=not_executed`，不是执行许可；实际 Merge 等消费者必须在首副作用前重新通过可持久化的准入。无法恢复的业务事务不能使用 fail-open 假装提交成功。

grant/CAS/policy revision/成功审计同事务；原生 DB 配置按真实最终 units/deletes 或 old/new checks 校验，先锁资源、再按统一 key 顺序锁 definition，复合设置任一功能拒绝不部分提交其他字段。不要按中间“先删后插”误判关闭，也不要只看 API 的 `Has*`；PR 单项配置可以隐式创建 unit。非 DB/Git/网络副作用只承诺当前一致准入点，后续撤权不追溯取消已准入操作；后台/延迟执行仍须重判。

清理仅保留原生已经授权的 package 删除/cleanup、hook 删除或纯停用、secret 删除/吊销；不是角色扩权或任意 `system`/`cleanup` 字符串旁路。required 不阻止泄密 hook/secret 的撤销。required checks 禁止删掉/削弱既有检查，disabled 不意味着关闭已有保护；不改变 checks 的其他保护字段可按原生/action 权限更新。

registry 覆盖各原生协议的上传/追加/下载/列表与派生索引；未关联包用真实 owner global/org，个人 owner 仅 global，关联包额外检查 repo，关联/重新关联/脱离要校验前后资源。派生索引维护仅有内部固定 package 名称/类型/版本、真实 owner 和受信调用链绑定的窄能力，用于删除后重建；不允许用户包借 `IsInternal` 或伪造维护标记上传新业务内容。含隐藏包的普通派生索引访问不能借清理能力泄露。

## 5. Linux schema 与上线前阻断项

正式 migration **363** 后 DB version 为 **364**。升级与新安装使用同一 13-key seed，创建 `enterprise_feature_definition`、`enterprise_feature_grant` 唯一约束与版本字段，增加 hook task 可信来源字段、repository `InternalUsage` 用途标记及 `enterprise_cargo_index_source` 表；后者以 `(index_repo_id, source_repo_id)` 为唯一 pair，保存 Cargo Git 索引的永久来源。seed 不覆盖管理员 grant，不重写旧原生 unit、token、SSH key 或历史决策。不靠启动修表、手改 DB/version 或重放旧迁移补数据。

enabled 启动预检要求表/完整 schema/索引/目录与版本一致，数据库审计已配置；缺表、缺 seed/drift 或 Cargo 用途待核实应停在预检，不临时放宽检查。disabled 不读取功能策略，适用于受控维护，但不能作为未清理旧队列就启动业务的捷径。

### Cargo 索引用途认领

新建 Cargo registry 索引自动写入 `InternalUsage="cargo-index"`。访问/维护按稳定 repo ID 的用途判断，rename 后用途及来源仍保留；**已标记索引禁止转移 owner**，避免用途重复及旧 owner 历史泄露。普通代码仓库即使叫 `_cargo-index` 也不因此取得派生索引维护能力或受 Cargo 业务门禁。未标记同名仓库在 `ENABLED=false` 时保留上游 lookup，但不自动赋 marker；enabled 下拒绝将它当作 Cargo 索引使用。若它实际是普通代码仓库，应按原生授权重命名解除 registry 名称冲突。

Cargo 每次更新/rebuild 在 Git commit 前，将实际关联来源 repo ID 永久追加到 `enterprise_cargo_index_source`；package 删除或 unlink 不清理来源，因为旧提交仍可能包含该来源的包名称/摘要。marked index 的读取检查永久来源中每个 repo 的**当前**有效 packages 策略及当前 owner；任何来源 disabled 时拒绝不可分割 Git 索引，来源 repo 删除或不可识别时安全拒绝。不得通过删除/解除包关联、清理来源表或 rewrite Git 历史规避该边界。

旧 owner 已有 Cargo 包，且存在未标记的 `_cargo-index` 仓库时，enabled preflight 返回 `cargo_index_purpose_unresolved`；同 owner 多个已标记索引返回 `cargo_index_purpose_conflict`。迁移不能按名称自动认领，操作者必须核对 repo ID、当前 owner、Git 内容、实际 registry 用途和历史，确认它仅用于 Cargo 索引，且已盘点完整 Git 历史中的全部曾关联来源；只核对现存 package 不足以认领。若实为普通代码仓库，使用原生受权重命名路径解除名称冲突，**不要**运行认领命令。

所有服务/worker 停机后，保留 `[audit] RECORD_OUTPUT=database`，用同版配置设 `[enterprise.authz] ENABLED=false, ENFORCE=false` 进入离线维护；同版 CLI 不要求启动 Web 服务：

```sh
/path/to/gitea --work-path /path/to/work --config /path/to/app.ini admin enterprise-features adopt-cargo-index \
  --repo-id N --actor-id SYSTEM_AUTHORITY --confirm-index-purpose \
  --source-repo-id SOURCE_A --source-repo-id SOURCE_B
```

`--source-repo-id` 可重复，必须列出完整 Git 历史中全部曾关联来源的稳定 repo ID，而非仅当前包关联。若操作者明确核实**全部 Git 历史从未含任何关联仓库包**，才可使用以下互斥形式：

```sh
/path/to/gitea --work-path /path/to/work --config /path/to/app.ini admin enterprise-features adopt-cargo-index \
  --repo-id N --actor-id SYSTEM_AUTHORITY --confirm-index-purpose --confirm-no-linked-history
```

必须且只能选择来源清单或 `--confirm-no-linked-history`；两者都不提供或同时提供均不是有效认领。历史用途/来源无法核实时保持停机并上报，不猜测 ID、不假认领，也不 rewrite 历史。

`N` 为已核实稳定仓库 ID；`SYSTEM_AUTHORITY` 替换为当前确有可信系统管理 authority 的本地用户 ID，不是角色名称、负数系统 actor 或任意管理员会话。`--confirm-index-purpose` 同时确认真实用途与完整历史来源核实。CLI 在事务内复核 authority/current owner、用途唯一性及来源，并原子写入 marker/永久来源和审计；不是开放 feature API，也不直接手写 marker。无明确确认、权限或审计条件则不能认领。完成后恢复 shadow 配置重新跑 enabled preflight，再批准恢复服务。

### 旧 Webhook 与邮件队列

旧 hook task 缺可信来源且不能从真实 hook/task 恢复 scope 时，enforce fail-closed（`webhook_source_unavailable`），不得从 payload 自报 repo ID 或 URL 猜测作用域；记录 skipped/denied，不标 delivered success。先盘点待发送/重放任务，使用受权的新事件重新生成可信来源，不靠 fail-open 绕过来源缺失。

**旧 mail queue 消息没有可信 IssueID，不能可靠区分 Issue/PR 邮件与其他邮件。升级不自动修复该身份缺口。** 启用功能 enforce 前必须执行下一节的全实例停机与 mail queue 隔离，否则旧邮件可能绕过发送前 Issue/PR 策略检查。

## 6. 邮件队列隔离步骤

mail 是 `CreateSimpleQueue` 的 managed name，`[queue.mail]` 覆盖 `[queue]`；真实队列名为 `mail + QUEUE_NAME`，默认 suffix `_queue`，因此默认 `mail_queue`。必须读取实际部署配置，不照抄默认值。

| backend | 精确隔离边界 |
| --- | --- |
| level（默认） | 默认 DATADIR=`<AppDataPath>/queues/common`，多个队列共用 LevelDB；设置 leveldb:// CONN_STR 时以实际路径为准。先备份整个 DB，仅处理 mail 队列自己的命名空间，其他 queue 不变。当前没有已交付的离线 mail 隔离 CLI；不能外部猜 key prefix 删除。没有经验证的 backend 工具/过程时保持停机，不得启用 enforce 或宣称已完成隔离。 |
| Redis | CONN_STR 确定 server/DB，mail 使用实际 QueueFullName 的独立 list，不是整个 DB 或通用 prefix。停全部客户端并备份后，用唯一隔离目标的 RENAMENX 迁移该 list，确认成功和原 key 不存在；不 DEL、不覆盖已有隔离 key、不碰其他 key。不存在原 key 应核对是否确实空队列，而不是误选 DB。 |
| channel/dummy | 无持久化恢复；停机前暂停生产者，明确确认内存待发消息的隔离/丢弃与业务影响，不能把进程重启当成安全重放。 |

1. 阻断入口/调度，停止所有旧/新实例、所有邮件生产者和 mail worker，确认没有共享队列客户端及在途发送；只停一个 Web 实例不够。记录时间、队列 backend、实际 mail 队列配置及业务负责人。
2. 备份同时间点完整 DB/Git/Wiki/LFS/附件/Packages、配置/二进制/assets 与全部队列状态；保存摘要、限制访问，登记旧待发邮件可能不再自动投递的业务影响。
3. 按实际 backend 精确定位 **mail 队列及它自己的辅助状态**，先备份再隔离旧内容。不要删除 common/shared queue 目录、Redis DB/prefix 或其他通知/索引/webhook 队列；不能从默认目录名推定部署配置。
4. 在确认隔离的 mail 队列上启动统一新版，先 disabled/shadow 回归，再经审批 enforce。新 Issue/PR 邮件带服务端 IssueID，发送前重新读取当前 repo owner/feature；策略明确拒绝不发送。
5. 旧消息保持离线隔离，不直接回灌新版 worker。需要补发时由负责人审核影响，使用当前受权业务生成带可信关联的新通知；无法重建来源的旧邮件不得宣称可安全重放。一般账户邮件的积压同样应由负责人处理，不伪造旧消息类型。

queue 的部署-specific 路径/键和隔离命令应由运维在实施记录中逐项填写；本文不提供泛删队列命令。该停机与积压处置是实际上线前置风险，不是已完成的自动迁移或生产演练。

## 7. 统一发布、生命周期与恢复

1. 完成上述 Cargo 用途盘点、旧 mail 隔离和旧 hook 盘点。停所有生产者、实例和 worker，取得备份/停机/恢复审批，在隔离 Linux SQLite/PostgreSQL 验证正式迁移、新安装、故障、并发与真实协议路径。
2. 用服务用户运行匹配新版的正式 `gitea ... migrate`，核对 DB version 364、目录/唯一索引及原生数据不被重写。所有实例统一二进制/配置，不混跑旧版或不同 mode。
3. 同版 disabled 回归原生认证/读写，再 shadow 通过完整 preflight。经受权 API 配置试点，检查上级锁、冲突、当前 owner、contexts、native availability/pending 与安全观测；查询 allow 不替代真实业务验证。
4. 明确批准后统一 enforce；监控 feature disabled/required、安全 503、基础设施回退、审计缺口与队列 skipped/denied。不要在未记录原因/负责人/截止时间时关闭 fail-closed。
5. 普通 repo rename/transfer 保留稳定 ID grant，但转移后每次按新 owner 重算继承；已标记 Cargo index 只允许保持稳定 ID 的 rename，禁止 owner transfer；永久来源不随来源包删除/unlink 清理；repo/org 删除清理对应 live grant，不删除其他 scope 或历史审计。排队任务不能复用转移/撤权前的许可。
6. 出现问题优先同版退 shadow，必要时 disabled，统一停写切换并重启；保留 grant/revision/历史和 queue 隔离现场，不自动恢复管理员已修改的 unit/checks。
7. 旧 binary 不得直接降 schema、修改 version 或 drop 新表。真正退旧版须完整恢复匹配时间点的 **DB + Git/Wiki + LFS/附件/Packages 等存储 + queue + 配置/二进制/assets**，保全事故后新数据，评估 RPO/RTO 并审批。只恢复 feature 表、只有旧启动探针或没有完整存储/queue 不构成旧版恢复验证。

本手册不代表执行了生产部署、停机、队列隔离、Cargo 认领或完整恢复。未执行层必须在本 change 的 verification 中明确保留缺口；不更改前序 change 的历史验收证据。
