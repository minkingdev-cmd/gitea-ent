# add-enterprise-feature-grants 验收记录

## 完成状态

45/45 tasks 已完成，15 条 Requirement 已逐项映射。以下通过结果仅指列出的真实命令与本地 Linux 验收，不代表生产发布或所有上游测试通过。

## 基线与验收口径

- 日期：2026-10-05；工作目录：`/Users/minwang/Projects/gitea-ent`；按用户要求直接在 `master` 实施。
- 起点：`2ec34fa160ae01e7978174749c4b4e910cf1f961`，既有 migration 362 / DB version 363；本轮增加 migration 363 / DB version 364。不修改旧 migration 或前序 change 的验收记录。
- 目录版本 1：13 个 global/org/repo key，7 个 native_gate 默认 enabled，6 个 policy_only 默认 disabled；内置角色 action 集不扩大。
- 验收服务端：Linux arm64，SQLite、隔离的 PostgreSQL 17.9；交叉编译使用 Go 1.27.1。macOS 测试仅作辅助，不替代 Linux 验收。不要求 Windows 服务端验收。
- 下述日志均在本仓库 `tmp/feature-grants/`，不提交运行数据、测试凭据或备份。编译缓存、工具与持久验收资产均在本仓库；Linux runtime 使用仓库挂载及隔离 tmpfs，最终辅助单测也指定仓库 TMPDIR。此前辅助 Go 测试使用框架自动清理的系统临时目录；不修改其他仓库或既有服务，容器/网络仅操作本轮创建的测试资源。

## Requirement → 实现 → 验证

| Requirement | 真实实现与边界 | 主要验收 |
| --- | --- | --- |
| Stable feature catalog and supported boundaries | `modules/enterpriseauthz/feature.go` 固定目录、四态和能力；无任意 definition CRUD/额外 scope | `TestFeatureCatalog`、`TestFeatureModelConstraints`、`TestFeatureReadiness`；正式 seed 测试 |
| Deterministic hierarchy and upper-scope locks | 纯解析器 global→当前 org→repo；个人跳 org；第一显式锁；父改不重写子记录 | `TestFeatureHierarchy`、`TestFeatureCurrentOwnerAndHash`、父子双连接集成 |
| Strict feature configuration and mandatory context inheritance | 严格 JSON、16KiB、64 项/128 bytes、canonical contexts；required union 与稳定 hash | `TestFeatureConfig`、`TestRequiredFeatureContexts`、API 非法字段/配置负例 |
| Scoped management authority and no self-authorization | `services/enterpriseauthz/feature.go` 当前 authority、credential ceiling、repo action；全部模式下管理权限仍强制 | `TestFeatureManagementAuthorityAndCeiling`、`TestEnterpriseFeatureGrantAPI`、既有管理 scope/伪超管回归 |
| Explainable API and privacy-separated projections | global/org/raw grants、repo effective API；reader/admin DTO 分离；disabled 404；严格分页/方法/状态码 | API package 全套、真实 grant API；旧 decision privacy/XSS/history 回归；Swagger 生成/校验 |
| Revision-safe and atomic policy mutation | grant CAS、inherited tombstone 防 ABA、no-op；资源→排序 definition 锁；成功审计同事务 | `TestFeatureManagementAndReset`、`TestFeatureAuditFailureRollsBackRevision`、ConcurrentParentAndChild/UnitAndParent/GrantCreationCAS |
| Mode-aware feature checks and explicit error fallback | disabled 不查；shadow 候选；enforce 显式 deny 不降级；可恢复设施错误才 fail-open；审计 savepoint/真实终态 | `TestFeatureNativeFailureMatrix` 覆盖七 key；terminal rollback、shadow unit；PG audit 锁、nested shadow 锁和选择性 INSERT 故障下真实 Merge |
| Native units and content operations respect feature policy | Issue/PR 按实际 IsPull；完整最终 unit intent；Wiki HTTP/SSH；聚合分页/count 前过滤；required 不创建 unit | CompoundUnitIntent/ImplicitPullUnitIntent、真实 AGit 与 Wiki Git、域测试、Bleve 查询/候选过滤 |
| Package registry honors account and repository resource scope | owner global/org + 关联 repo；关联前后检查；协议读取/派生索引；窄 cleanup；可信 Cargo 用途/永久历史来源 | Package service/model/protocol 回归；generic/Arch cleanup；真实 Cargo yank→拒绝 unyank；Cargo content/复制/历史/普通同名仓库/one-shot proof |
| Webhook management and delivery use current feature state | DB 持久可信 event/source；repo-origin org/system 不能旁路；Deliver/Replay 重判当前 owner；拒绝不记成功 | `TestEnterpriseFeatureWebhookDeliveryRechecksSource` 六类真实持久队列/零 HTTP；worker 故障与管理停用/删除测试 |
| CI secret and required-check controls preserve safety | secret 管理门禁但保留删除/runner 消费；checks old/new/delete/priority 不可削弱；不修改既有 merge guard | SecretManagementRoutes/RequiredChecksRoutes；secret/pull unit suites；旧 runner/deploy/action 回归 |
| External integration policy is not execution or merge approval | 六 key 只输出授权、contexts、policy_required；无扫描/AI/token/status/新 merge deny；Woodpecker 非 Actions | 目录/继承/contexts/API；实际 Merge/native branch protection 回归；代码差异复核 |
| Audit and action catalog distinguish real feature operations | manage_feature_grant 真实能力；Version1 可选 feature snapshot；真实 scope；candidate/actual/phase；旧 UI 只更正文案 | 审计/CAS/历史 DTO、原生失败及 rollback；旧 UI HTTP smoke/XSS/privacy；聚合 fixed-label metric 测试 |
| Migration lifecycle and safe rollback | 正式升级/新安装/唯一索引/preflight；ID 稳定与当前 owner；删除 grant 不删历史；Cargo 认领 CLI 不按名称猜 | Linux 两 DB migration/new-install/replay；Cargo marker/adoption/transfer/source tests；三模式完整备份恢复及旧 binary 拒绝新 schema 演练 |
| Identity authentication and deployment compatibility | 无认证/sync/callback 放宽；原生 credential/action 始终保留；普通代码 Git 无新业务门禁 | 前序 EnterpriseAuthz 认证/吊销/MFA/mock-directory 回归；真实 HTTP/SSH clone/fetch/push、AGit/Wiki Git；Linux 双 DB 全授权集成 |

## Feature-to-hook 与维护边界

| key | Web/API、共享 service、异步或协议消费点 | 允许保留的维护/原生行为 |
| --- | --- | --- |
| issues | detail/comment/write、tracker 跳转、issue service、项目/时间跟踪、依赖两端读取、mail/feed/通知、列表/搜索/导出 | 禁用 Issue 不误禁 PR；内部 merge 依赖仍作为真实 blocker，不因隐藏而解除 |
| pull_requests | detail/create/review、shared issue IsPull、AGit refs/for、manual/force/auto merge、持久 auto-merge worker | 普通 code push/clone、旧 action/branch protection 不放宽；队列执行时重判 |
| wiki | Web/API 页面/历史/raw/export/外部跳转、wiki service、migrate、Git upload/receive pack HTTP/SSH | 不把 `.wiki.git` 门禁套到主代码仓库；required 不自动初始化 Wiki |
| packages | owner/repo 模型与共享写/下载、关联/脱离、repo unit、所有 registry route、不可分割派生索引、Cargo Git/content/search/copy | 原生受权删除；内部精确绑定 owner/type/name/version 的索引重建；Cargo cleanup live proof 一次性，只豁免必要索引读取 |
| webhooks | repo/org/system 管理与 test、prepare/save enqueue、Replay、真实 Deliver worker，业务 event 同时检查 Issue/PR/Wiki/Package key | 原生受权删除/纯停用；code push 不误当 Issue/PR；旧不可识别来源不能猜测为受信业务 |
| ci_secret_management | repo/org secret Web/API/shared create/update/copy/read | 原生受权删除/吊销；runner 正常消费既有 secret，required 不要求创建 |
| required_status_checks | 分支保护完整 old/new/删除/批量/priority intent | 不改变 checks 的其他字段可编辑；disabled 不删除或关闭既有保护；mandatory contexts 只允许加强 |
| woodpecker_ci / sonarqube_quality_gate / semgrep_scan / gitleaks_scan / trivy_scan / ai_review | 共用 grant API、四态/上下文/版本/审计、有效 policy_only DTO | 不执行外部集成、不授予 token、不假造 status、不新增 merge gate、不丢弃外部真实 status callback |

Registry 盘点：Alpine、Arch、Cargo、Chef、Composer、Conan、Conda、Container、CRAN、Debian、Generic、Go proxy、Helm、Maven、npm、NuGet、Pub、PyPI、RPM、RubyGems、Swift、Terraform、Vagrant。共享 guard 及各协议的自建列表/静态索引路径已复核；并非声称每个协议均执行过完整外部客户端端到端流程。

聚合 shadow 不逐行审计或读策略：与原生权限/搜索条件相同的未分页 EXISTS/最多一命中元数据探针，仅产生固定标签 `would_allow/would_deny/error` metric；已有业务事务不另开独立快照，诚实记 error，保持 native。Quota/raw cleanup 统计不因用户可见性过滤降低原生约束。

## 可复跑命令与结果

所有命令先设置 `GOCACHE=$PWD/tmp/go-cache`；编译 Linux 增加 `CGO_ENABLED=0 GOOS=linux GOARCH=arm64`。本地脚本只负责隔离 runtime/PG 和挂载测试资产；不属于生产启动或 migration 工具。

| 验证 | 命令/选择器 | 证据 |
| --- | --- | --- |
| Linux 最新编译 | `sh tmp/feature-grants/linux/run.sh build` | `linux/build-final-verified.log`，退出 0；实际 gitea 与 test binary |
| Linux SQLite 全授权集成 | `sh tmp/feature-grants/linux/run.sh sqlite '^TestEnterprise(Authz\|Feature)\|^TestCargoIndexFeatureContentRoutes$'` | `linux/sqlite-final-verified.log`，退出 0 |
| Linux PostgreSQL 全授权集成 | 同选择器，mode `pg-linux` | `linux/pg-final-verified.log`，退出 0；打印真实 PostgreSQL 17.9 版本；独立 DB/网络，结束后删除本轮测试资源 |
| Linux 正式迁移/安装 | root migration test binary `^TestEnterpriseAuthz`、v28 binary `^TestEnterpriseFeatureMigration$`，分别 SQLite/PG | `linux/migration-{sqlite,pg}-final.log`、`linux/migration-v28-{sqlite,pg}-final.log`，均退出 0 |
| Linux authz service / auto-merge worker | cross-build `services/enterpriseauthz` / `services/automerge`；`FEATURE_GRANTS_BINARY=./… sh …/run.sh sqlite '^Test'` 或 queue selectors | `linux/authz-service-final-verified.log`、`linux/automerge-acceptance.log`，均退出 0 |
| Linux db/model/pull/webhook/secrets/纯解析器定向 | cross-build 各 package；`FEATURE_GRANTS_BINARY` 指定 binary，`^Test(Feature\|ProtectedBranchFeature\|IssueAndPull\|Webhook\|Secret\|Cargo\|Native\|ObserveFeature\|Enterprise\|Savepoint\|NestedSavepoint\|ReadOnlyMarker\|PostCommit\|PostRollback)` | `linux/models-db-acceptance.log` 等六份日志，均退出 0；最新 db helper 另见 `linux/models-db-final-verified.log` |
| 辅助完整核心单测与索引 | `go test -tags 'sqlite sqlite_unlock_notify' ./modules/enterpriseauthz ./models/enterpriseauthz ./models/db ./services/enterpriseauthz ./services/pull ./services/automerge ./routers/api/v1/enterpriseauthz ./models/activities ./models/issues ./models/packages ./modules/indexer/issues/... ./modules/indexer/code/...` | `core-final-verified.log`（最新核心七包）及 `core-acceptance.log`（聚合/索引全套），退出 0 |
| Issue/Wiki 域与 package/worker/control 域 | 相应 model/service/router suites；仓库 service 排除独立确认的外部 DNS 环境失败测试 | `issues-wiki/final-stable-domain-tests.log`、`packages-webhooks/domain-last.log`、`secrets-checks/domain-suite-final.log`，退出 0 |
| 格式/lint/Swagger | `make fmt`、`make lint-go`、`make lint-templates`、`make generate-swagger swagger-validate` | `fmt-final.log`、`lint-final-verified.log`（Linux target 0 issues）、`lint-templates-acceptance.log`（591 files/0 errors）、`swagger-acceptance.log`（Swagger 2 valid/OpenAPI 3 generated） |
| 完整模式/备份恢复 | `python3 tmp/feature-grants/rehearsal/run.py` | `rehearsal/run11.log`、`rehearsal/old-refusal11.log`，均退出 0；matching-full-backup.tar、SHA256 manifest；同版 Linux fresh install、真实 Git/Wiki/Issue/package/checks/queue 数据 |
| 双 Linux 实例版本与共享策略 | `python3 tmp/feature-grants/rehearsal/multi-version.py` | `rehearsal/multi-version3.log`，退出 0；同时在线、同 binary/config SHA256、实际共享 PG schema 364、跨节点 revision 1→2 |
| OpenSpec / 最终差异 | `openspec validate add-enterprise-feature-grants --strict`、`git diff --check`、JSON parse | 最终命令输出；tasks 与本记录同步，无自动 commit/push/deploy/归档/主 specs 同步 |

### 有效的失败 → 修复验证

- Cargo 原名称判断会误禁普通代码仓库，故新增正式用途及永久来源；实际 Git 历史/unlink/delete/copy/search 与 cleanup proof 的负例驱动完整接线，不靠名字或 ticket 字符串旁路。
- fresh minimal schema 升级的唯一约束真实失败后修正迁移顺序/冻结模型；没有跳过 constraint。
- PR 单项设置的隐式 unit 和复合更新用最终 intent 验证；真实父子/配置双连接竞态锁在当前 owner 与定义之后重判。
- 聚合 shadow 仅过滤 enforce 时缺少候选观测：RED→GREEN 补同条件、未分页、无逐对象 N+1 的候选 metric，保留原生 AllPublic/visibility/关键词条件。
- PG readonly 许可探针直接 INSERT 导致 outer transaction abort：真实选择性 INSERT 与表锁故障测试（`linux/pg-fault-final.log`），含成功/失败/嵌套退出后 timeout 恢复为 7s、取消后 outer SQL 可继续；只读探针标 `policy_probe/actual_decision=not_executed`，实际 Merge 必须在首副作用前重新持久准入，选择性只拒 feature audit INSERT 的真实 Merge 断言零 DB/Git 副作用。
- 可选观测 SQL 超时不能污染 native session deadline：savepoint 保存原始 session context，rollback/release 用原生事务 context，恢复准确的 immediate binding；嵌套取消单测先 RED（ErrObservationTransactionUnavailable）再 GREEN，保留 native commit 与 post-commit effect。真实 PG 表锁先 RED：lib/pq watchCancel 会将观测 deadline 取消的连接标坏，导致 savepoint 无法恢复。改用 savepoint 内 PostgreSQL statement_timeout（保留更短原生限制，成功恢复原值，失败 rollback 自动恢复），SQL 仍受原生 request context 取消，避免可选观测取消销毁业务连接。表锁通过独立连接同步获得，没有 sleep。
- 无法恢复的事务、原生请求取消和明确 deny 仍拒绝，不因 fail-open 假造 commit 或成功审计。

## 模式切换、备份与真实部署边界

本地演练由同版 Linux binary 完成 disabled→enforce→shadow，随后停所有本轮服务/producer/worker，再备份 binary/config/assets/完整 runtime（SQLite、Git/Wiki、LFS/attachments、真实包文件与 LevelDB queue）。逐文件 SHA256 验证恢复到另一隔离目录；同版 enforce 重新启动，原生 unit/checks、grant/revision、既有审计/decision 全行保持，Wiki 仍拒绝、Issue 和真实包下载可用。API 的 `HasWiki=false` 是可见性投影，不当作 DB unit 被重写。

完整恢复的两个先后运行 runtime 的 binary SHA256 相同，恢复资产通过 manifest 验证。另执行两个同时在线 Linux 实例共享隔离 PostgreSQL 的 smoke：逐实例 binary/config SHA256 相同、DB version 364、13-key 目录通过 enabled preflight，跨节点 PUT/GET 观察 revision 1→2 和完整策略投影一致、无需重启。该 smoke 使用原生 DB issue indexer 和内存 channel queue，仅验证版本/配置一致与共享策略可见性，不宣称持久队列集群、混版本滚动或生产部署验收。不做混版本滚动测试或 schema downgrade。旧基线 Linux binary 另行从起点 commit 编译，对新 version 364 DB 实际执行 migrate 返回非零并明确报新版 DB 错误（旧版要求 363），前后完整 SQL logical dump 相同；不允许把 version 改小后启动；回退旧版本必须取它匹配的完整离线备份。生产多实例仍须按 runbook 停全部 producer/worker、核对每台版本/config/shared data，不能由此本地演练推断生产已完成。

## 未宣称已验证或已部署的事项

- 没有 commit、push、PR、生产部署、线上 migration/恢复、生产 Cargo 索引认领、主 specs 同步或 change 归档。
- 老邮件队列缺少可信业务 ID，不能安全推断来源。runbook 要求升级前停全部实例并按精确队列实例隔离旧项；未对生产队列做任何操作。不可用无来源旧消息假造已获新功能许可。
- 真实外部企微 tenant/生产 MFA/全目录同步不在本机接入；已运行既有认证/同步合同回归，未修改登录/sync 机制。opt-in 浏览器测试未开启；已有 UI HTTP smoke/privacy/XSS 覆盖，且本轮无新增 UI。
- Bleve 使用真实本地索引；ES/Meili 的编译、请求/条件及共享测试不等同于运行 live ES/Meili 集群。
- 未运行整仓所有上游测试。`TestMigrateWhiteBlocklist` 在本机外部 DNS 将 gitlab.com 解析为 198.18.0.148，原生 SSRF 检查正确拒绝；独立复现，未弱化规则或测试以伪造通过。
- 六个 policy_only 的外部执行/治理模板/完整 merge gate 和未来管理 UI 本来就不在本 proposal 范围内，不列为已实现能力。
