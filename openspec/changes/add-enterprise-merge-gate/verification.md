# Merge gate 实施记录

> 最新结论见文末“2026-10-06：完整 Linux 验收与交付收口”。中间失败、Docker 阻塞和未完成列表均保留为历史，不代表最终状态。

## 边界与基线

- 用户授权直接在当前 master 工作区实施，不提交/推送/部署/归档。开始时只有本 change 未跟踪文件；保留这些规划文件。
- 前置 foundation、high-risk enforce、feature grants 的代码、任务和 verification 已核对；catalog=2，最新 migration=363，DB version=364。生产启用与真实外部企微/MFA并未由前置验证声称完成。
- 仅 Linux 服务端；不改认证/凭据、不启动外部 scanner、不配置供应商、不改现有运行服务。新规则 UI 不在范围，规则 API 与 PR merge box 在范围。
- 使用 OpenSpec tasks 作为唯一实施清单；本记录保留运行命令、发现和验收映射，不创建平行 Superpowers 计划，不提交中间代码。

## 验收映射

| Requirement | 实施任务 | 预期验证 |
| --- | --- | --- |
| 独立模式 | 4.1–4.3 | 配置/readiness、disabled 零读取、shadow 行为等价 |
| 统一阶段与原因 | 2.1、2.3、8.1、10.2 | 确定性聚合、error 优先、预览非票据 |
| mandatory 守卫 | 6.1、6.6、8.1、9.2 | 权限/凭据/PR/Git/conversation 负例与零副作用 |
| 原生分支保护 | 6.1–6.2、11.1 | approvals/CODEOWNERS/style/signing/scoped checks 回归 |
| required contexts | 2.4、7.1–7.4 | 最新当前 head/base repo、缺失/失败、无 pb、继承与空配置 |
| 累加敏感规则管理 | 2.2、3.4、5.1–5.5、10.1 | scope/role/CAS/原子审计/转移/引用/隐私 |
| 完整 diff 与审批 | 6.3–6.5 | rename/copy/删除、base CODEOWNERS、当前 head/角色 |
| 独立有限 bypass | 2.3、9.1–9.2、10.3–10.4 | 权限/理由/类别、部分豁免、mandatory 不可豁免 |
| 每次实际重评 | 8.1–8.4、9.3–9.4 | direct service、refs/fingerprint、撤权/失败/PAT吊销 |
| 手工识别边界 | 9.5–9.6 | 历史 diff/pusher、未知拒绝、先前 Git 写入事实 |
| 持久证据与终态 | 3.4、8.3–8.6 | 写前审计故障、CAS、重启/unknown 对账、大小边界 |
| reader 与展示 | 10.1–10.5 | API/模板同语义、原始策略隔离、CSRF/XSS/键盘 |
| 认证及部署兼容 | 11.2–11.3、11.5 | 企微/MFA/禁止路径、SSH/PAT/HTTP、Linux双DB |
| action 稳定目录 | 3.2–3.3、5.5 | 新key独立、高风险、default/显式角色、历史v1/v2 |
| action authority/history | 3.2–3.5、5.1、9.2 | Owner/可信超管、Admin缺权、迁移不扩自定义角色 |

## 入口盘点

- `CheckPullMergeable` 当前 manual 提前返回、auto schedule 跳过未完保护项、force 整体忽略 ErrNotReadyToMerge；新 gate 不可沿用这些 shortcuts 作为实际准入。
- `Merge` 的 PR working lock → nativeGuard → doMergeAndPush → beginPullGitExecution/Admission → hook ticket 为实际 Git 写边界；`MergedManually`/后台识别为 PR 状态写边界。
- Web/API 路由预检和 merge box 不能取代 shared service；automerge schedule 与 worker 分阶段。队列只有 DoerID，无原始凭据 ceiling，需要新的 evaluation metadata 关联。
- 原生 status 在 base repo/current head 上读取；无 pb 时跳过 native contexts。feature contexts 必须独立消费。
- 原生 approvals/CODEOWNERS 布尔 helper 会吞读取错误；adapter 需要 typed errors，不以 false/空列表伪装成功或仅缺审批。

## 验证状态

用户已确认原生 skipped 兼容、企业 feature/path 仅 success。下文按实施时间保留原始检查点；早期“尚未接线”等结论仅描述当时状态，最新状态见最后追加章节与 tasks.md。当前 shared Merge/manual、auto schedule/worker、hook admission、终态对账及 merge box 已接线，但完整 Linux/协议/并发/恢复矩阵尚未验收，不能生产启用 enforce。strict validation、交叉编译和单测不代替这些验收。

### 实际运行命令与结果（2026-10-05 至 2026-10-06）

所有本轮缓存、日志、Linux 二进制及临时数据库工作区均位于仓库忽略目录 `tmp/merge-gate`、`tmp/go-cache`。未提交、推送、部署或改动原有运行容器。以下 Go 命令使用 `GOCACHE="$PWD/tmp/go-cache"`。

| 验证 | 实际命令/输出 | 结论与边界 |
| --- | --- | --- |
| 核心、配置、模型、服务、路由 | `go test -tags 'sqlite sqlite_unlock_notify' -count=1 ./modules/enterpriseauthz ./modules/setting ./models/enterpriseauthz ./models/issues ./modelmigration ./modelmigration/v28 ./services/enterpriseauthz ./services/pull ./services/issue ./services/repository ./routers/api/v1/enterpriseauthz` | 11 个包均 `ok`；日志 `tmp/merge-gate/final-packages.log`。这些宿主单测不冒充 Linux 全入口验收 |
| 原生状态语义证据 | `go test -count=1 -run '^TestCombine$' ./modules/commitstatus`；`go test -tags 'sqlite sqlite_unlock_notify' -count=1 -run '^TestCreateCommitStatus_DistinctWorkflowFilesSameName$' ./services/actions` | 均 `ok`，证实 skipped 可参与原生成功汇总，同名 workflows 的 ContextHash 需分别保留 |
| Linux 服务端编译 | `CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -buildvcs=false -tags 'sqlite sqlite_unlock_notify' -o tmp/merge-gate/linux/gitea .` | exit 0；仅编译，不代表新增实际准入已实现 |
| Linux 双 DB migration/存储 | 交叉编译 `./modelmigration/v28` 测试二进制后，`tmp/merge-gate/linux/run.sh sqlite migrations.test '^TestEnterpriseMergeGateMigration'` 和相同命令 `pg` 模式 | SQLite：migration 0.19s、storage/recovery 0.16s；PostgreSQL：0.20s、0.29s，全部 PASS。检查重复迁移、索引/seed 缺失、正常重跑修复、冲突回滚、规则 CAS、唯一操作与终态 CAS。这里的 recovery 是迁移恢复，不是进程重启对账 |
| Linux 双 DB 规则 API/会话根 | 交叉编译 `./tests/integration`，两种模式运行 `tmp/merge-gate/linux/run.sh <sqlite或pg> integration.test '^TestEnterpriseMergeGate'` | 两 DB 均 PASS：conversation roots、repo/global/org CRUD；日志 `latest-rules-sqlite.log`、`latest-rules-pg.log`。单项 0.15–0.30s |
| Linux PostgreSQL 并发屏障 | 上述 PG integration run 包含 `TestEnterpriseMergeGatePGRuleAndRepositoryCreationLockOrder`、`...RepositoryDeletionLockOrder`、`...RuleAndConfigurationLockOrder`、`...ConcurrentRevisionAndRoleReference` | 4 项 PASS：0.30/0.16/0.17/0.15s；规则、创建、删除、配置统一 PR feature 前置顺序；同 revision 仅一成功，新引用/角色删除无孤儿。SQLite 明确 SKIP PG row-lock 测试，不据此声称 SQLite 并发证明 |
| Linux 完整 Git 路径原语 | 交叉编译 `./services/pull`，`tmp/merge-gate/linux/run.sh sqlite pull.test '^TestMergeGate.*Paths|^TestMergeGatePathRecords$'` | 最后一轮 parser 0.00s、真实 Git rename/copy 双端、delete/CODEOWNERS、gitlink（配置 ignoreSubmodules=all）、非法或缺对象 SHA 0.01s，PASS；日志 `tmp/merge-gate/paths-linux.log`。不使用 UI diff。fork/AGit/manual 历史原始 head 与实际准入尚未验收 |
| API schema | `CGO_ENABLED=0 make generate-swagger`、`CGO_ENABLED=0 make swagger-validate` | exit 0，Swagger 2.0 valid；OpenAPI 3 已再生。二次生成 SHA-256 相同；对比 HEAD 的既有 paths/schemas 全部语义相同，只新增 6 个路径和规则 schema |
| 格式、静态检查 | `make fmt`、`make lint-go`（本轮缓存目录） | 已运行，Linux lint `0 issues`；macOS linker 的 `-bind_at_load` 弃用 warning 不当作服务端验收。不涉及 JS/CSS/模板 UI，相关 lint 不适用；未改 go.mod，不运行 tidy |
| 差异与 OpenSpec | `git diff --check`；`openspec validate add-enterprise-merge-gate --strict` | exit 0；change valid。strict validation 不是实现完成证明 |

`make swagger-check` 实际失败（exit 2）：它要求生成文件与 HEAD 无差异并提示提交结果；当前明确不提交，因此新增 API 的正确生成文件必然有差异。没有禁用或弱化检查，也不谎称通过；已另行验证 schema valid、再生可重复及旧合同不变。

### 本轮 RED → GREEN 与复核修复

- pure core/规则规范化/配置、新 action、模型 CAS/readiness、管理服务/API 的新行为均有失败测试再实现；本轮相关日志保留在忽略测试目录。
- `TestMergeGateUnresolvedReviewConversation` 使用真实 `MarkConversation(root)`，先复现回复仍为 0 导致误阻断；再补同 path/line 的不同 ReviewID 独立 root，复现跨 review 隐藏未解决会话。最终查询按 published review/root 分组，两轮均 RED→GREEN，并在 Linux 两 DB 验证。
- PG 规则写/删除屏障先复现反序事务的 `policy_storage_failed`，修复 feature→owner→repo 顺序；创建/转移锁顺序单测 RED→GREEN，再运行真实 Linux PG 同 owner 创建与规则写屏障。未用 sleep 制造测试时序。
- `TestMergeGateSameNameWorkflowIdentities` 先缺少 ContextHash，再覆盖同名 workflow 的 failure/error＋success；保留不同 identity 后不再丢弃失败。pending 不能遮蔽其他 identity 的 failure，warning 是已知 failure 而非未知读取错误，均有定向 RED→GREEN。
- `TestMergeGateCodeOwnersReadsPreserveErrors` 验证新增 typed parser 保留 user/org/team 故障；旧 best-effort parser 保持兼容。原生 CODEOWNERS 布尔 service adapter 和可信 base 文件读取仍待接线，不能据此勾选完整 6.2。
- 只读复核发现 `diff.ignoreSubmodules=all` 可隐藏 gitlink 更新；真实 Git 测试先返回空 paths（RED），collector 显式使用 `--ignore-submodules=none`，确保 submodule 路径不被仓库配置省略。最终 Linux 真 Git 回归重跑 PASS；该修复之后的 core/pull 单测、make fmt、make lint-go（0 issues）与 Linux 服务端编译均 exit 0。

### 已验证的规则管理权限矩阵

| 主体/凭据 | 已验证结果 |
| --- | --- |
| 当前 Owner、可信系统管理 authority | 对应 scope CRUD 成功，正确 token scope；global/org/repo 均覆盖 |
| 满足原生资格且显式获得 manage_sensitive_paths 的自定义角色 | 无 binding 拒绝；添加 binding 后允许；解绑不扩大权限 |
| 原生 Admin、普通读者、未获新 action | 403，不因旧角色默认放行 |
| readonly/public-only/错误 token scope | 写拒绝；原始规则读也拒绝 public-only；错误 scope 403 |
| 跨 scope/仓库 ID、未知对象、disabled gate | 隐藏 404；不泄露其他 scope 规则 |
| 无认证、停用用户、数据库撤销 admin | 401/403；旧 token 不保留失效管理权限 |
| 无效字段/重复字段/超限/旧 revision | 422/409；no-op 不增加 revision/audit；审计故障回滚并返回 503 |

此矩阵仅针对已实现的规则管理，不冒充 force、worker、manual 或 SSH/Git HTTP 全协议验收。

### 已确认的原生兼容性决策

spec 的原生保护 Requirement 要求保留现有 status checks 语义；required contexts Requirement 又要求所有来源“只认成功”。现有 `CommitStatusStates.Combine()` 将 skipped 计为 success，warning 则为 failure。因此原生 skipped 是否沿用成功语义，需要显式确认，不能悄悄以 unknown/error 改变原生行为。

用户于 2026-10-06 明确选择原生 skipped 兼容、企业 feature/path 仅 success。已同步 delta spec/design，并增加来源区分测试；测试先观察原生 skipped 被误报 unknown 的 RED。真实 status collector/preview 已接线；实际 admission 仍需后续实施/验证，不据此声称本 change 完成。同名不同 ContextHash 则分别取最新再 AND，避免成功覆盖失败；原生 patterns 与企业 exact 均保留独立 identity。

### 精确未完成范围

- task 3.4：规则墓碑/CAS/no-op、evaluation immutable/terminal CAS 与受权 history 分页已完成；模型与 Linux 双 DB API 已验证。历史 actor 的撤销管理员/企微失效管理绑定负例另有 RED/GREEN。
- task 4.3：真实 disabled/shadow 普通、force、排队等价仍未验收；目前只证明纯核心/策略读取的 disabled 零读取与严格管理 CRUD。
- task 6：已有完整 Git 路径、typed review/CODEOWNERS/whitelist、native mandatory facts、可信 base CODEOWNERS 与当前 reviewer-role collector。preview 已使用当前 Git refs 的完整路径和 protected-files/divergence，不再使用对应 DB 缓存；fork/AGit 已由真实 refs 的 Linux 双 DB preview 验证；实际写前刷新、并发一致性、native signing/策略完整快照与 manual 历史矩阵仍待验收。
- task 7：feature/native/path contexts 和 base repo + 当前 Git head 的 latest status collector 已接入 preview；无 pb 的企业 required、native skipped/feature-path success-only、旧 SHA/其他 repo/同名不同 identity 已验证。实际 merge/worker 消费、status 写协议完整负例仍待验收。
- tasks 8–9：实际 Merge/MergedManually 写前准入、最终 fingerprint、有界重采、强制审计、hook ticket 关联、Git 成功后的终态与重启对账、force 新字段、队列持久凭据归因与撤销重校验、manual pusher/history、触发/取消均未完成。
- task 10：三作用域规则 CRUD、PR preview、manager history 与安全 DTO/API 已实现；reader 不返回 context/策略 ID/自由文本理由，preview 不新增 feature 或 merge admission 审计。merge box、locale/CSRF/键盘 UI、旧 merge API bypass 字段及整体版本/权限矩阵仍未完成；不勾选混合整体任务。无 UI 截图或 e2e 成功结论。
- task 11：没有完整入口/模式/权限矩阵，也没有企微真实登录/MFA、禁止认证路径或真实 SSH/PAT/Git HTTP 吊销/写协议新回归，更无外部 scanner 结果。
- task 12：有 runbook 与本轮真实证据；完整上线、shadow→enforce 和 crash recovery 验收仍缺失。不更新前序 change 证据，不同步 main specs、不归档。

## 逐 Scenario 验收索引（36 项）

这是完整范围映射，不把纯核心验证冒充真实入口验收。每项未接线/未运行的部分均保留，不能据此勾选整体交付。

| Scenario | Tasks | 当前证据/剩余验收 |
| --- | --- | --- |
| Unknown action is rejected without partial writes | 3.2–3.3、5.5 | catalog 3 与 version 1/2/未知 action 单测已验证 |
| Action catalog does not imply a feature implementation | 3.2–3.3、5.5 | catalog 3 与 version 1/2/未知 action 单测已验证 |
| Access management is independently grantable | 3.2–3.3、5.5 | catalog 3 与 version 1/2/未知 action 单测已验证 |
| Gate actions do not alias existing grants | 3.2–3.3、5.5 | catalog 3 与 version 1/2/未知 action 单测已验证 |
| Admin needs explicit delegation and native eligibility | 3.2–3.5、5.1、9.2 | seed/history/custom-role/管理权限已验证；真实 bypass 权限待接线 |
| Trusted owner and stale administrator | 3.2–3.5、5.1、9.2 | seed/history/custom-role/管理权限已验证；真实 bypass 权限待接线 |
| Migration preserves old records and custom roles | 3.2–3.5、5.1、9.2 | seed/history/custom-role/管理权限已验证；真实 bypass 权限待接线 |
| Invalid deployment configuration | 4.1–4.3 | 配置/readiness 已验证；真实 disabled/shadow merge 等价待接线 |
| Disabled and shadow preserve existing behavior | 4.1–4.3 | 配置/readiness 已验证；真实 disabled/shadow merge 等价待接线 |
| Multiple blockers are explainable | 2.1–2.3、8.1、10.2 | 纯聚合与真实只读 preview 已验证；实际准入票据待接线 |
| Diagnostic allow is not an execution ticket | 2.1–2.3、8.1、10.2 | 纯聚合与真实只读 preview 已验证；实际准入票据待接线 |
| Bypass cannot repair an unsafe merge | 2.3、6.1、6.6、9.2 | 纯 mandatory/bypass 矩阵与双 DB conversation root 查询已验证；真实 mandatory 守卫待接线 |
| Unresolved conversation blocks unprotected branches | 2.3、6.1、6.6、9.2 | 纯 mandatory/bypass 矩阵与双 DB conversation root 查询已验证；真实 mandatory 守卫待接线 |
| Existing protected branch remains protected | 6.1–6.2、11.1 | review/CODEOWNERS 底层 typed 读取已验证；完整 native adapter 与真实 merge 回归待完成 |
| Native guard read failure | 6.1–6.2、11.1 | review/CODEOWNERS 底层 typed 读取已验证；完整 native adapter 与真实 merge 回归待完成 |
| External check is missing or overwritten | 2.4、7.1–7.4 | 纯核心、真实 status/feature collector 与 preview 已验证；实际 Merge/worker 待接线 |
| Skipped status preserves native compatibility only | 2.4、7.1–7.4 | 用户选择已同步；纯核心与真实 status collector 已验证 native success/skipped、feature/path success-only，实际 admission 待接线 |
| Required context survives inheritance and absent branch protection | 2.4、7.1–7.4 | 纯核心、真实 status/feature collector 与 preview 已验证；实际 Merge/worker 待接线 |
| Enabled is not required and empty required is not success | 2.4、7.1–7.4 | 纯核心、真实 status/feature collector 与 preview 已验证；实际 Merge/worker 待接线 |
| Lower scope cannot weaken an upper rule | 2.2、3.4、5.1–5.5 | CRUD/CAS/审计/墓碑/引用/转移与 PG 并发引用已验证；实际敏感审批 AND 待接线 |
| Atomic revision and audit protection | 2.2、3.4、5.1–5.5 | CRUD/CAS/审计/墓碑/引用/转移与 PG 并发引用已验证；实际敏感审批 AND 待接线 |
| Ownership and role deletion | 2.2、3.4、5.1–5.5 | CRUD/CAS/审计/墓碑/引用/转移与 PG 并发引用已验证；实际敏感审批 AND 待接线 |
| Rename cannot escape protection | 6.3–6.5 | 完整 Git 路径/base CODEOWNERS/当前独立 reviewer、fork/AGit preview 已验证；manual 与实际准入矩阵待完成 |
| Stale self or revoked approval | 6.3–6.5 | 完整 Git 路径/base CODEOWNERS/当前独立 reviewer、fork/AGit preview 已验证；manual 与实际准入矩阵待完成 |
| Force without authority or reason | 2.3、9.1–9.2、10.3–10.4 | 纯理由/七类/部分豁免/error/auto 矩阵已验证；真实 force 表单/service 待实现 |
| Selected checks alone are bypassed | 2.3、9.1–9.2、10.3–10.4 | 纯理由/七类/部分豁免/error/auto 矩阵已验证；真实 force 表单/service 待实现 |
| Auto merge cannot inherit bypass | 2.3、9.1–9.2、10.3–10.4 | 纯理由/七类/部分豁免/error/auto 矩阵已验证；真实 force 表单/service 待实现 |
| Queue time allow becomes execution deny | 8.1–8.4、9.3–9.4 | 实际准入/fingerprint/queue 凭据 attribution 尚未实现 |
| Direct service call cannot skip the gate | 8.1–8.4、9.3–9.4 | 实际准入/fingerprint/queue 凭据 attribution 尚未实现 |
| Scheduled credential is revoked or unattributed | 8.1–8.4、9.3–9.4 | 实际准入/fingerprint/queue 凭据 attribution 尚未实现 |
| Already pushed but governance failed | 9.5–9.6 | 尚未实现/验收 |
| Admission audit failure blocks Git mutation | 3.4、8.3–8.6 | 模型 immutable/CAS/超限已验证；写前审计/终态恢复待实现 |
| Git success followed by terminal evidence failure | 3.4、8.3–8.6 | 模型 immutable/CAS/超限已验证；写前审计/终态恢复待实现 |
| Reader sees blockers without raw upper policy | 10.1–10.5 | PR reader/history/管理 DTO 已验证；merge box 与实际服务端 stale execution 仍待接线 |
| Button state cannot authorize stale execution | 10.1–10.5 | PR reader/history/管理 DTO 已验证；merge box 与实际服务端 stale execution 仍待接线 |
| Credentials and forbidden login regressions | 11.2–11.3、11.5 | 本轮全协议回归尚未运行；没有外部 scanner/MFA 真实结果 |

## 本次继续实施的新增证据（2026-10-06）

- `TestMergeGateSkippedIsSourceSpecific`：RED 原生 skipped 误报 unknown → GREEN。原生 success/skipped 通过、warning 失败；企业 feature/path skipped 是已知失败，可属于有限 check bypass，但仅 success 通过。
- `TestMergeGateEmptyNativeContextsAggregateAllStatuses`：RED 使用 glob `*` 漏掉带换行 context 的失败 → GREEN `AllStatuses` 明确聚合全部 latest identities，不改变显式 native patterns/exact 语义。
- `TestMergeGateCodeownerCoverageIsBoundedAndCancellable`、`TestMergeGateSensitiveUsesBaseAndCurrentIndependentApproval`：取消、数量上限、每路径去重、aggregate 2 秒预算；真实 base CODEOWNERS 不受 PR 替换影响；旧 head/stale/dismissed/latest reject/作者不能代替独立批准。`TestMergeGateReviewerUsesCurrentRoleIdentity` 验证角色改名保留 ID、解绑失效。
- native typed whitelist/CODEOWNERS、mandatory facts 与 snapshot body version 的失败路径均经历 RED/GREEN。`TestMergeGateSnapshotBodyVersionMustMatch` 防止 JSON 内版本与模型字段不符、缺少版本/array/null 被接受。
- `TestEnterpriseMergeGatePreviewIsSafeAndNotAdmission`、`TestEnterpriseMergeGateHistoryAPI`：Linux SQLite/PostgreSQL 的 `preview-final-sqlite.log`、`preview-final-pg.log` 均 PASS。验证安全 DTO、当前真实 SHA、401/403/404/422、history repo/PR 隔离；Cargo fixture 对 audit_event/evaluation 均无新增。
- readonly review 找到的 Cargo admission 副作用已复现 RED（audit 数从 1 到 5）；route/临时 repo 改用无副作用 feature read 后 GREEN。history stale IsAdmin、PR-only + DB admin/企微管理 binding 失效均复现 RED，统一 fresh/trusted actor 且同时检查 code/PR 后 GREEN。无管理 authority 降级或凭据提升。
- preview 原生 protected files 曾依赖 DB 缓存；README.md 完整 Git diff 回归 RED 后改用 pinned Git context，双 DB GREEN。`TestMergeGateInvalidNativeFilePatternIsNotEmptyPolicy` RED（非法 `[` 被吞成空规则）→ GREEN（typed error）；旧 native helper 不变。
- 本轮 12 个相关包 `go test -tags 'sqlite sqlite_unlock_notify' -count=1` 均 PASS，见 `preview-final-packages.log`；后续最终复跑及全后端结果另记录，不把该定向包运行称作完整后端套件。
- `make generate-swagger swagger-validate` 默认 CGO 构建因 macOS linker warning 被生成目标拒绝；使用 `CGO_ENABLED=0` 正常生成/验证，见 `preview-swagger-cgo0.log`。这是本机工具告警处理，不禁用 linter/Swagger 校验。`swagger-check` 与 HEAD 一致性仍因未提交的新增 API diff 不通过，不擅自提交。
- 首次全后端/lint 尝试因本轮临时 `.go` 源码备份进入 Go package discovery 失败；备份已改为 `.go.txt`，不修改测试或忽略配置规避。该次 `make test-backend` 的 package list 为空、只输出 root `[no test files]`，**不算全套通过**。缓存拒写告警与最终修复后的重跑结果另据实际输出记录。

以上为已落盘行为与真实测试；实际 Merge/MergedManually 准入、hook gate ticket、queue attribution、force 表单、新 UI 和 crash/unknown 对账仍未实施，不存在生产 enforce 验收结论。

### 最后追加的真实结果与限制

- `preview-final2-sqlite.log` / `preview-final2-pg.log`：Linux gate integration 全部 PASS，PostgreSQL 含 scope/repository/role 并发屏障；原生 `TestPullView_CodeOwner`、`TestPullCreate_CommitStatus` 两 DB 均 PASS。现有 CODEOWNERS 父测试含多个场景，耗时 SQLite 19.97s、PG 7.60s；新 API 单项约 0.2–0.7s。不能把父测试宣称为 sub-2s。
- `preview-final3-packages.log`：12 个相关包全量测试全部 `ok`，包含最后 history 对称权限修复、非法 native file pattern、disabled feature 不撤销 native/path 要求以及最新 failure 覆盖 success 的验证。
- `make test-backend TAGS='sqlite sqlite_unlock_notify' GOTEST_FLAGS='-count=1 -timeout=5m'` 的真正全套重跑 **FAIL exit 2**（`preview-full-backend-retry.log`），242 个测试包 `ok`，失败为 `cmd/TestAdminUserDelete` 的四个子场景与 `services/migrations/TestMigrateWhiteBlocklist`。前者尝试写宿主 `.ssh/authorized_keys.tmp` 被沙箱拒绝；设置仓库内隔离 HOME 后单独 `TestAdminUserDelete` PASS（`cmd-isolated-home.log`），没有修改宿主 SSH 配置或申请越界写入。后者真实 DNS 将 gitlab.com 解析为 `198.18.0.148`，被原生公网迁移策略拒绝；Linux `network=none` 复跑也 FAIL（`migrations-linux.log`），因此不谎称网络环境问题已消除、不放宽公网地址校验或改变该无关测试。全后端不能记为 PASS。
- linter 真正扫描发现本轮 6 处常量 `fmt.Errorf`（perfsprint），已改为 `errors.New`，没有禁用规则；最终 lint 输出依据后续日志记录。最初的临时 `.go` 备份污染已消除，Go package discovery 现返回 392 个包。

前一检查点新增勾选 2.4、3.4、7.1–7.3，当时 25/59 tasks 完成。未把已实现的 preview/history 当成 UI/全权限矩阵完成，也未把可编译或单测通过当成真实 admission 完成。


## 原生事实与敏感审批切片补齐（2026-10-06）

本次新增勾选 **6.2–6.6、10.2**，当前 **31/59 tasks** 完成。这些是 typed facts/完整 diff/敏感审批与安全 DTO 的交付，不表示 tasks 8–9 的实际准入已完成。实际 Merge/MergedManually、auto/force/manual、终态恢复与 UI 仍未接线；不可启用生产 gate enforce。

### 行为与回归证据

- `TestMergeGateSensitiveUsesBaseAndCurrentIndependentApproval` 扩展当前活跃/禁止登录/私库可见性与失效企微管理 authority：先复现 DB `IsAdmin=true` 令不可见 reviewer 仍批准的 RED（`sensitive-current-authority-red.log`），permission 前校验可信 authority 后 GREEN（`sensitive-current-authority-green.log`）。没有提升裸角色、旧会话或凭据。
- 同一 collector 测试复现 malformed trusted base CODEOWNERS 被静默丢弃的 RED（`sensitive-invalid-policy-red.log`）→ GREEN。增加仅供敏感规则使用的严格解析入口，非法 regexp/format/group 为 error，匹配但无有效 owner 的规则保留且不默认批准；原生 best-effort 与 checked parser 的语义保持不变。
- readonly reviewer 找到空 org/team 的 malformed group 漏项。`TestMergeGateSensitiveCodeownersDoNotDropUnownedRules` 与 `TestMergeGateSensitiveRoleApprovalsRemainPerRule` 复现 RED（`sensitive-malformed-group-red.log`），仅 sensitive 模式拒绝空 user/org/team 后 GREEN；已有有效角色批准不能掩盖非法 base 策略。reviewer 只读复核并实际运行新增回归通过，没有修改文件。
- `TestMergeGateCodeownerCoverageIsBoundedAndCancellable` 验证所有命中路径逐项覆盖、无 owner 不通过、额外无效 owner 规则不消失、CODEOWNERS team 成员撤销后缓存对象不能继续批准。新增 team 测试最初使用旧 fixture 名 user3 而真实名称为 org3，修正 fixture 引用并显式断言已解析到 team 后通过；未弱化覆盖或生产权限。
- `TestMergeGateSensitiveRoleApprovalsRemainPerRule` 验证两条命中规则 AND、作者唯一 owner 不豁免、指定角色各自 OR、contexts 独立、新 head 同时使旧批准失效、解绑使批准失效。`TestMergeGateReviewerUsesCurrentRoleIdentity` 另覆盖 user/team/org binding、稳定 role ID 改名及退组撤销。
- `TestMergeGateMandatoryFactsWithoutBranchProtection` 验证无 pb 的 review conversation 阻断与解决后重评、普通评论不阻断、conflict/checking/closed/merged/dependency 原因；这些原因仍不可由有限 bypass 修复。实际 force/auto 服务端阻断由 task 8–9 后续接线，不把 collector 结果冒充真实 merge 拒绝。
- `TestMergeGateNativePolicyAndWorkflowReadsPreserveErrors` 对 protected_branch、action_scoped_workflow_source、enterprise_feature_grant 注入读取故障，返回 error 与空结果而非空要求 allow。现有 whitelist/review/CODEOWNERS typed helper 的故障及旧 wrapper 兼容测试一起运行。
- `TestMergeGateTrustedGitPaths` 增加真实 Git 1025-path diff 超限负例，不接受 UI/分页文件列表、不截断返回路径；现有真实 rename/copy 两端、删除、CODEOWNERS、gitlink、缺对象及 parser 非法路径均保持覆盖。
- `TestEnterpriseMergeGatePreviewForkAndAGit` 通过真实 fork repo + branch、AGit hidden pull ref 验证相同 head/base；不存在的普通 head branch不影响 AGit，删除隐藏 ref 后返回 error，不伪造空 diff allow。
- `TestEnterpriseMergeGateRoleApprovalDoesNotWaiveNativeCodeowners` 创建真实 base CODEOWNERS、当前敏感 role approval 与原生保护：敏感审批通过时 native CODEOWNERS 仍阻断，独立 owner 新批准后原生 blocker 才消失。初次未启动真实内部 hook server 的 fixture 写入失败（`sensitive-native-sqlite.log`）；改用既有 onGiteaRun 后通过，没有禁用 pre-receive hook。
- `TestMergeGateBypassValidation` 追加“去首尾空白后 1024 字节”边界，RED（`bypass-trim-length-red.log`）→ GREEN（`bypass-trim-length-green.log`），仍拒绝原始控制字符/非法 UTF-8/空理由/未知类别。此处仅修正纯核心合同，真实 force 字段仍未接线。

### 实际运行结果

- `TMPDIR="$PWD/tmp/merge-gate/runtime" CGO_ENABLED=0 GOCACHE="$PWD/tmp/go-cache" go test -tags 'sqlite sqlite_unlock_notify' -count=1`：11 个相关包全量 PASS（`sensitive-final3-packages.log`）；最后 sensitive/team fixture 修正后 5 个 affected 包全量 PASS（`sensitive-final5-packages.log`）；最后 bypass core 全包 PASS（`bypass-trim-length-green.log`）。不能称作完整后端套件通过。
- Linux arm64 交叉编译 `./services/pull` 后运行 `tmp/merge-gate/linux/run.sh sqlite pull.test '^TestMergeGate'`：11 项 PASS（`sensitive-final-pull-linux.log`），其中真实完整超限 diff 约 0.08s。
- 最新 Linux integration binary 与 Gitea binary 编译成功。顺序执行 `tmp/merge-gate/linux/run.sh sqlite integration.test '^TestEnterpriseMergeGate'` 与相同 pg 命令：均 PASS（`sensitive-final-integration-sqlite.log`、`sensitive-final-integration-pg.log`）；PG 含真实 policy/lifecycle 并发屏障，新 native-role API 测试约 SQLite 0.70s、PG 0.59s。该 native-role 测试只有 fixture 安装写 Git，门禁查询仍只读，不宣称已验证实际门禁拒绝 Git mutation。
- `make fmt`、`make lint-go` 最终输出 `0 issues.`（`sensitive-final2-fmt.log`、`sensitive-final2-lint.log`）；初次漏设 lint 的 GOBIN 企图安装到宿主 go/bin 被拒，改为仓库内 GOBIN 后成功，不申请越界修改。
- `CGO_ENABLED=0 make generate-swagger swagger-validate` PASS（`sensitive-final-swagger.log`）；之前 `swagger-check` 的 HEAD 一致性限制仍保留，不擅自提交或禁用校验。最终 Go 微调后的 fmt/lint 另记录实际终结状态。
- 完整后端 DNS/公网迁移测试的环境失败仍未解决，见上述 `TestMigrateWhiteBlocklist` 记录；没有修改 DNS、hosts、迁移公网安全策略或无关测试。完整模式/入口/协议/恢复矩阵与 e2e 仍未完成。

最后收口：`sensitive-last-fmt.log` 与 `sensitive-last-lint.log` 的完整命令 exit 0，lint 输出 `0 issues.`；`gate-current-final-packages.log` 的当前 11 个相关包全量测试全部 `ok`，包含最终理由 trim-byte 边界与 CODEOWNERS team 撤销测试。最终 `openspec validate add-enterprise-merge-gate --strict`、`git diff --check` 均 exit 0。OpenSpec apply 状态 ready，31/59 完成、28 项待执行；没有宣称 all_done，未提交/推送/部署/归档。

## 普通 Merge 准入与后续 force 字段切片（2026-10-06）

本检查点新增完成 **7.4、8.6**，当前 **33/59 tasks**。tasks 6.1、8.1–8.5、9.1–9.6 与完整入口/并发/恢复/UI 验收仍未全部完成；以下 ordinary Merge 接线是这些 tasks 的部分推进，不能视作全入口上线完成。

### 实现与 RED/GREEN

- ordinary shared `Merge` 在 PR lock 内预检、实际 Git execution Admission 后再采集 current actor/owner/credential、head/base、完整 diff、native/feature/path facts；拒绝发生在实际 ref mutation 前。固定临时 repo 的原始 tracking head 与评估 base，不用 rebase staging HEAD 代替 PR head。代码还没有完整 facts fingerprint、有界重采集或 manual/auto 接线。
- 原生 CODEOWNERS 按固定 base SHA 读取，保留原生 stale、official/team、自身 owner 与无 owner 旧语义；敏感路径规则继续走独立严格语义。签名 introduced commits 按 fixed base/head 验证；`SignMerge` approved 模式改用 typed approval count，读取故障不是零审批。`pinned-native-red-clean-fixture.log` → `pinned-native-green.log`；`signing-approval-red-fixed-hook.log` 实际出现 `wont sign: approved`，改为传播 storage error 后 `signing-approval-green.log` PASS。最初 COUNT hook 大小写不匹配已修正，未拿该无效注入当有效 RED。
- `TestMergeGateDirectServiceRejectsBeforeGit` RED 的旧路径进入真实 Git push，而不是门禁拒绝（`direct-gate-red.log`）；接线后 `direct-gate-green.log` PASS：无原生 branch protection 的 required Gitleaks 缺失，409、目标 ref 不变、PR 未 merged、deny/not_started evaluation 和强制审计同时保存。Audit disabled 即使 action fail-open 也返回 503，记录不增加。
- `TestMergeGateShadowWithoutActionEnforce` 复现 early return 未采集记录（`shadow-no-action-red.log`）；补 gate guard 与服务端 operation 建立后 `shadow-no-action-green.log` PASS。真实 Merge 本身也建立 operation，不接收客户端 evaluation ID。
- `PersistMergeGateEvaluationTx` 在同一 TX 插入不可变 evaluation、started CAS 与必需 audit；重复 started 不重新执行。终态 CAS 与 append-only audit 同 TX；audit 故障回滚终态，保留 started。`TestMergeGateEvidenceAtomicAndTerminalFailure` 实际注入 INSERT audit 故障并核对 rollback；不是只关闭配置或 mock 成功路径。
- `RefreshMergeGateCredential` 消费当前 PAT/OAuth grant，验证 actor、当前 repository scope/public-only 与原 ceiling 交集。`TestMergeGateCredentialRefreshUsesCurrentIntersection` 覆盖收窄、撤销、错误 actor、原 readonly/native-only、public-only 私库拒绝。OAuth getter 的 missing 是 `(nil,nil)`，新测试 RED 复现 panic（`gate-atomic-credential.log`），显式拒绝后 `gate-atomic-credential-green.log` PASS。尚无 auto 队列持久 attribution/session delegation/同 ID token regeneration 证明，不把该 helper 当作 task 9.3 完成。
- final snapshot 追加 state_changed 后也走有界 seal。`gate-final-snapshot-red.log` 超限返回错误且无法保存有界证据；修复后 `gate-final-snapshot-green.log` PASS：只保留 `snapshot_too_large` error，不截断成 allow，JSON/hash 与 64 KiB 上限一致。snapshot 只保存受控 facts/IDs/版本/摘要；status description/URL、bearer token、代码内容与自由文本 bypass 理由不写入 snapshot。既有生命周期、immutable snapshot 与 history 版本测试保持通过。
- actual terminal audit failure 原先仍发送一次 merge success notification，Linux `gate-audit-notify-red.log` 明确 count=1。终态先于 post-process notification 保存，且故障不由 defer 再次尝试后，Linux `gate-final-integration-sqlite.log` 的 `TestEnterpriseMergeGateActualAuditFailures` PASS：写前故障无 Git/merged/evaluation，Git 成功后的终态 audit 故障返回 503、保留 started/空 merged_sha/零 terminal audit/零成功通知。真实 Git 已成功不能伪造 failed；unknown/started recovery 尚未实现。
- 当前 head repo 被删除的定向测试 RED 复现 typed nil facade 导致 panic（`gate-deleted-head-red.log`）；明确判定空 head 后 `gate-deleted-head-green.log` PASS：409 state_changed、error/not_started 与 audit 留证据，AGit 仍使用可信 base hidden ref。该最新变更尚未 Linux 重跑。
- force 新字段加入共享 Web/API form、自定义 JSON decoder 与 ordinary Merge options；旧字段/旧大小写兼容测试保留。`force-form-red.log` 显示新理由丢失，`force-form-green.log` PASS。服务端 `gate-bypass-action-red.log` 复现缺独立 action 误映射 422，修正为 403 后 `gate-bypass-action-green.log` PASS；`gate-bypass-adapter-matrix-green.log` 覆盖无 blocker requested/not_used、非法理由/控制字符/未知类别、部分豁免仍 deny、选中 required_check 后 bypass、未解决 review conversation 不可豁免。首次扩展的 expected Source 写成 feature key，而真实合同为 `feature`，修正 fixture 断言后通过，未改生产来源语义。

### Linux 实际运行与目前阻塞

- `gate-actual-sqlite.log`、`gate-actual-pg.log`：较早 Linux SQLite/PostgreSQL 的真实 ordinary Merge 与 shadow 两种 action enforce 组合均 PASS；真实 authenticated commit status API 写 success 后合并，provider 不执行、不造假 status，不自动创建 integration。
- 最新 `gate-final-integration-sqlite.log`（Linux arm64，真实 Gitea binary/internal hooks）`^TestEnterpriseMergeGate` 全部 PASS，包含 native status API readonly 403、企业 skipped 仍 409、success 后 succeeded、privacy、shadow、audit-before-push 和 terminal-audit-fault 通知回归，以及规则/preview/history/fork/AGit/生命周期相关 integration。新 actual merge/status 单项 0.85s，audit 子项 0.18/0.43s，shadow 子项 0.44/0.48s。没有 scanner/AI 或供应商凭据调用。
- 用户继续推进时 Docker daemon 已不可连接。`gate-final-integration-pg.log` / `docker-current-info.log` / `docker-default-current-info.log` 记录连接失败；未重启宿主 Docker、改 context 或另开外部服务。已请求用户启动 Docker Desktop。**最新 PostgreSQL 的终态故障、新 force Web/API 真实入口、deleted-head Linux 回归未验收**，不以 macOS 或 cross-build 替代。
- 新 force 集成测试已写入 `TestEnterpriseMergeGateForceRequestFields`，待 Docker 恢复运行。`force-field-red-build.log` 只证明 RED test binary 可编译，并没有真正运行这个路由 RED，不谎称 RED/GREEN 实际入口已通过。因此 9.1/9.2 保持未勾选。

### 当前验证命令与结果

- `continued-packages.log`：`go test -tags 'sqlite sqlite_unlock_notify' -count=1` 的 13 个相关包全量 PASS（models enterpriseauthz/issues/git，modules enterpriseauthz/setting，services asymkey/enterpriseauthz/forms/issue/pull/repository，API enterpriseauthz，modelmigration）。这是开发环境定向包套件，不是全后端或 Linux 新入口验收。
- 默认 `make fmt` / `make generate-swagger` 此次被 Makefile 配置的 mirror.f123.pub DNS 阻断；`GOPROXY=off` 的 package@version 调用也因 Go deprecation metadata 查询失败。未修改宿主 proxy/DNS、Makefile 或 linter 规则。使用仓库忽略目录 `tmp/merge-gate/go-cached-tools` 调度器，读取已有 pinned module 源码、`GOFLAGS=-mod=readonly`、cached Go 1.27.1，分别编译/执行相同 go-swagger v0.36.6 与 golangci-lint v2.13.2；缓存、二进制与生成物写入仓库，不新装宿主工具。此前第一次 cached swagger build 尝试 Go 1.27.0 下载被沙箱拒绝，改为已有 1.27.1 后成功，没有请求越界写入。
- `make fmt GO="$PWD/tmp/merge-gate/go-cached-tools"` PASS（`continued-cached-fmt.log`）；相同 GO 运行 `make lint-go` PASS、`0 issues.`（`continued-cached-lint.log`），真实执行 Linux lint/header，不禁用规则。先前 5 项 lint 已修：无用 ctx 参数、冗余 string 转换与两处可选记录的窄 nilnil 注释；没有降低测试。
- 同一 pinned 工具运行 `make generate-swagger swagger-validate` PASS（`continued-cached-swagger.log`），两份 schema 包含可选 bypass_reason/categories，旧 force_merge 仍 boolean。
- `swagger-check` 的 HEAD 一致性检查仍会发现尚未提交的新增 schema；该结果单独记录，不擅自 commit 或弱化检查。
- 后端完整套件既有 `TestMigrateWhiteBlocklist` DNS/公网策略故障仍未解决，完整套件不宣称 PASS，见前述证据。只读 reviewer 对已实现 ordinary Merge 切片复核未报告额外可确认 Critical/Important，但不替代未完成任务的验证。

仍不可生产启用 enforce：shared MergedManually/manual recognition、queue attribution/auto 触发与停止、hook gate ticket、完整一致性 fingerprint/重采集、unknown/crash recovery、force 新 UI、完整权限/协议/e2e/Linux 双 DB 矩阵待完成。未提交、推送、部署、sync main specs 或 archive。

最后收口：`continued-linux-cross-build.log` 的当前 Linux arm64 integration binary 与 Gitea binary 交叉编译 exit 0；这是编译证据，不是 Docker 运行验收。`continued-final-apply.json` 返回 ready，33/59 完成、26 项未完成。`continued-swagger-check.log` 实际 exit 2，原因为尚未提交的 schema 与 HEAD 有 diff；generation/validation 不因此冒称 check 通过。最终文档说明 enforce 下终态 audit 的 503/started 语义，shadow 仍不改变旧执行结果。


## 全入口接线、恢复与展示后续检查点（2026-10-06）

### 已落盘行为与边界

- shared `Merge` 与 `MergedManually` 在 PR lock 中预检，并在 Git execution Admission/实际 marker 前重新消费当前 actor、原凭据上限、当前 owner/角色/规则/feature/native facts；路由预检同样聚合全部安全原因，不能以第一个 draft/native blocker 取代真实准入。preview 永不产生实际许可或 evaluation。没有新执行通道。
- native status success/skipped 通过，企业 feature/path 仅 success。checking 不满足原生可排队资格；仅 reviews/status/敏感要求/讨论等可等待条件产生 schedule waiting/not_admitted，不把排队记录当执行 allow。
- admission 的最终 fingerprint 有界重采集；变化保持 error/state_changed，shadow 保持 not_enforced，未真正豁免不记 bypass_used。策略 scope 锁、expected old base ref 和内部 hook ticket 都使用本次封存快照。确定性 PG 全事实变更屏障仍待补齐/实跑。
- force 新字段贯通 Web/API form、service options 和 Vue 表单；七类显式选择、独立 bypass action/native 资格/理由均在服务端检查。上级 required 的显式例外会留下 bypass evaluation 与 audit，不修改原 feature grant/revision；mandatory/error 不能豁免。尚未运行最新真实 Web/API force 集成测试。
- schedule 与队列同事务保存 actor/queue ID/原 credential attribution。PAT 撤销、收窄、同 ID token hash 变化、旧无证据队列、replace/cancel 均不能复用旧关联；session 是受限委托。PAT 后续扩权不能扩大原 public-only 上限；org/资源绑定与 cleanup ceiling 同样保留。snapshot 不存 bearer 或原 token hash。
- worker 在 fresh facts 后拒绝新的 role withdrawal/PR feature disabled/失败 status，不改 Git/PR，队列保留；相同 queue/snapshot deny 复用旧拒绝证据，不热循环。status/review 的负向变更、conversation 事务提交、policy/role/feature 事务提交会触发现有 unique queue；rollback 不唤醒，启动 enforce 时分页复核全部旧队列，不局限 24 小时。
- manual capture 使用可信 receive old/new refs、原 pusher 与原凭据；即使 M 后目标分支已有 N，仍从合并前范围计算非零 diff。后台未知 pusher 保存 ActorID=0、error/not_started、git_already_present 的独立证据，不 fallback Owner、不修改 PR、更不声称阻止既往 push；模型禁止这种零 actor 记录进入 allow/start/bypass。
- `SetMerged` 同业务事务写同 operation/snapshot/result SHA 的 marker receipt。ordinary 终态与启动/定时对账都要求同 operation receipt + PR/Git 证明，不能将另一次合并的相同 SHA 归为自己的成功。started/unknown 扫描按 ID 分页，不能被前 100 个 unknown 饿死；对账只修证据，不重 push、不改 PR。
- merge box 展示服务端稳定原因目录，reader 隐藏 context/role/rule 原始 ID 与上级配置。disabled 旧行为、shadow 候选提示、error/unknown 不显示通过，bypass 理由/类别与 manual commit 输入可达，auto 清除 bypass 参数。复用当前 Go Origin/Fetch Metadata 防护，不伪造已不存在的 CSRF token。

### 本检查点新增有效 RED → GREEN

日志均在仓库忽略目录 `tmp/merge-gate/`。这些是相应切片的回归证明，不是完整 Linux 实跑证明。

| 行为 | RED / GREEN 日志 | 实际检查 |
| --- | --- | --- |
| hook 本次准入绑定 | hook 测试及 `continued-final-gate-tests.log` | 未准入、跨 ref/身份/请求、非 started/快照不匹配拒绝，终态不能复用 |
| manual M 后已有 N、原 pusher/credential | `manual-later-tip-red.log` / `manual-later-tip-green.log`，`manual-credential-red.log` / `manual-preview-green.log` | 历史 old base 与非零 diff，manual preview 始终 preview_only/not_admitted |
| 未知 manual pusher 独立证据 | `manual-unknown-valid-red.log` / `manual-unknown-fixed-green.log` | 正确开启 autodetect 后有效 RED；PR 未 merged，Git 已存在事实保留，模型限制 ActorID=0 |
| 原 public-only 不随扩权扩大 | `public-ceiling-red.log` / `public-ceiling-green.log` | token 扩为完整 scope 后仓库变私有，原队列仍无 write |
| policy scope 提交后唤醒 | `policy-wake-red.log` / `scope-wake-red.log` / `continued-final-gate-tests.log` | commit 后仅当前 scope 队列，rollback 零唤醒 |
| review/status 负向变更 | `notifier-red.log` / `notifier-status-red.log` / `notifier-green.log` | reject/failure 均触发重新评估 |
| conversation 提交后唤醒 | `conversation-wake-red.log` / `continued-final-gate-tests.log` | commit 前零 dispatch；rollback 状态和 dispatch 均不变 |
| 持久拒绝暂停及账户变化 | `auto-paused-red.log` / `worker-inactive-red.log` / `continued-final-gate-tests.log` | 不变 snapshot 只一条拒绝，事实变化后新证据；inactive 不能执行 |
| 启动覆盖 24 小时前旧队列 | `old-queue-restart-red.log` / `continued-final-gate-tests.log` | -48h 队列仍重新检查，不靠 sleep |
| 请求层聚合与 mandatory 留证 | `request-precheck-red.log` / `request-precheck-green.log`，`request-schedule-green.log` | draft 与 required 全部解释；waiting 不写实际准入；inactive/invalid style 不只返回原生错误 |
| checking 非排队条件 | `checking-schedule-red.log` / `auto-credential-matrix.log` | 原生拒绝 checking 时不能声明 can_schedule/waiting |
| 相同 SHA 的其他 operation 不构成成功 | `terminal-proof-red.log` / `terminal-proof-green.log`，`reconcile-all-green.log` | 同 operation marker 才能封存 succeeded，其他保持 unknown |
| schedule 凭据读取故障不是明确缺权 | `queue-credential-error-red.log` / `continued-final-gate-tests.log` | malformed scope 为 facts_read_failed/error + 503，独立证据不随业务回滚丢失 |
| admission 凭据读取故障留证 | `admission-credential-error-red.log` / `admission-credential-error-green.log` | 原 early return 误报 evidence_persist_failed 且无记录；现在 error/not_started + 503，不伪造 credential_denied |
| worker 凭据读取故障留证 | `worker-credential-error-red.log` / `worker-credential-error-green.log` | 原 worker 返回裸 scope error，无记录；现有 shared admission 重读、typed 503 与独立 error 证据 |

追加已有行为的回归（不冒称新 RED）：`worker-current-policy-regression.log` 实际 PASS role/feature/status 三项变更且 target ref/PR 不变；`upper-required-bypass-audit.log` PASS 上级 required 豁免记录、强制 audit、原策略 revision 不变。shadow 原守卫回归初次使用空 merge message，在 Git staging 因 empty commit message 失败，不能算授权测试通过；改用非空 message、受限 action ceiling，并明确核对 403/deny record 或 feature_disabled 后，在 `admission-credential-error-green.log` 与后续完整 gate 套件复验。rollout 旧队列测试初次未绑定可信 source 导致 invalid_execution_context，修正真实 server-bound Web source 后 PASS，未改生产守卫。

### 实际执行命令与输出

- `continued-final-gate-tests.log`：11 个门禁相关包定向测试全部 `ok`；含新增模式、hook、fingerprint、manual、恢复、队列原上限、旧队列启动、展示目录与 form 回归。最后追加 admission/worker error 修复之后，`worker-credential-error-green.log` 的 pull/automerge 全部 `^TestMergeGate` 再跑 PASS。包总耗时不冒称单项性能。
- `continued-full-backend-final.log` / `.exit`：仓库隔离 HOME、离线已缓存 modules，`make test-backend TAGS='sqlite sqlite_unlock_notify' GOTEST_FLAGS='-count=1 -timeout=5m -p=4'` 真正全套 **exit 0，244 个测试包 ok、零 FAIL**。cmd 与 services/migrations 均通过，早期宿主 SSH/DNS 两项失败本次未复现；旧失败记录保留。该次先于最后 admission/worker 错误留证增量，最终全套再次运行结果另追加，不冒称这一较早输出覆盖后来的源码。
- `continued-full-frontend.log`：隔离 browser HOME，读取现有 cached Chromium，`PLAYWRIGHT_BROWSERS=chromium pnpm exec vitest`，**54 files / 167 tests PASS**，1.94s；其中 merge box 5 项见 `merge-form-final.log`。没有 Firefox/WebKit 实跑，也不是完整 Gitea 页面 e2e。工具原有 mock interceptor warning 保留，不修改测试器规则。
- `continued-final-lint-js.log`：scoped eslint + vue-tsc exit 0；`continued-final-lint-css.log` exit 0；`continued-final-lint-templates.log` 591 files、0 errors。`continued-final-lint-go.log` 与 `continued-last-fmt-lint.log` 对当时源代码 0 issues。后一次 lint 与非隐藏 repo TMPDIR 中的并行 go build 临时文件扫描发生竞态（typechecking missing b1948，exit 2），**不能把其“0 issues”当通过**；最终切换仓库内隐藏 `.runtime` 并串行 fmt/lint/tests，不改 linter/测试规则。
- `continued-final-build.log`：`make build GO=<cached pinned tools> GOOS=linux GOARCH=arm64 TAGS='sqlite sqlite_unlock_notify' EXECUTABLE=tmp/merge-gate/linux/gitea` exit 0；前端构建通过、文件为 ELF ARM aarch64。最后代码增量后会重新编译；交叉编译绝不是 Linux 测试运行。
- `swagger-final-regenerated.log`：生成两份 schema + Swagger 2.0 validate exit 0；两次 SHA-256 文件完全相同（`swagger-final-before.sha256` / `swagger-final-after.sha256`），各 383 paths。`continued-final-swagger-check.log` 和 `continued-final-openapi-check.log` **真实 exit 2**，只因未提交生成 diff 与 HEAD 不同；未擅自提交/禁用检查，不能写为 check PASS。新字段 optional、旧 force boolean 和成功响应合同未更换。
- `continued-auth-unit-regression.log`：setting/auth/OAuth/enterprisewecom 相关定向单测 `ok`；标为 `[no tests to run]` 的 ldap/pam/smtp/sspi/Web user 包不算覆盖。完整后端套件涵盖这些包有测试的情况，但不能代替真实 Linux 登录/MFA、SSH/PAT/Git HTTP 协议矩阵。
- Docker 重查 `docker-current-error.log` 仍为 Cannot connect to the Docker daemon；不启动/修改宿主 Docker 或现有服务，不把前轮 Linux PASS 自动转移到本轮新增路径。

### 逐 Scenario 对照（与上方 Requirement 映射合用）

“单测 PASS”指上述真实命令或最后收口复跑；“前轮 Linux PASS”保留原日志，仅覆盖当时版本。每行尚待全入口/协议/Linux 的部分不记已验收。

| delta / Scenario | 实现与实际证据 | 仍待验证 |
| --- | --- | --- |
| actions / Unknown action is rejected without partial writes | ActionCatalog、角色严格解析/422 与事务回归；完整后端单测 PASS，前轮规则 API Linux PASS | 最新全入口矩阵 |
| actions / Action catalog does not imply a feature implementation | feature/action 分离，policy_only 无 provider 调用；catalog/feature 单测 PASS | 无供应商执行结论（明确非目标） |
| actions / Access management is independently grantable | 原 catalog/access-management 校验与管理 authority 分离，完整后端单测 PASS | 最新真实协议回归 |
| actions / Gate actions do not alias existing grants | MergeGateActionCatalogHistory、ProtectedPathAdminRequiresDelegation、BypassRequiresIndependentAction PASS | 最新真实 force 入口 |
| actions / Admin needs explicit delegation and native eligibility | shadow 下路径管理缺权/显式授权/撤销，凭据/native 前提不扩权，单测及前轮 Linux CRUD PASS | force native Admin/显式角色矩阵 |
| actions / Trusted owner and stale administrator | 当前 authority/旧 admin/session、history/preview 隔离单测与前轮 Linux API PASS | 最新所有入口 |
| actions / Migration preserves old records and custom roles | migration 364/DB365、catalog3，v1/v2 解释及仅内置 seed；前轮 Linux SQLite/PG migrations PASS | 最新 release 双 DB 回归 |
| gate / Invalid deployment configuration | EnterpriseMergeGate config/readiness 单测与迁移 readiness PASS | Linux 启动验收 |
| gate / Disabled and shadow preserve existing behavior | DisabledEntryPointsDoNotReadStorage、RolloutPreservesNativeQueue、ShadowDoesNotRelaxExistingEnforcement、shadow cancellation fault PASS；前轮 ordinary Linux shadow PASS | 所有 style/入口等价矩阵 |
| gate / Multiple blockers are explainable | pure Evaluation 与 RequestPrecheckAggregatesAndKeepsEvidence PASS，独立拒绝记录 | 最新 HTTP 复跑 |
| gate / Diagnostic allow is not an execution ticket | PreviewNeverUsesBypass、ManualPreviewNeverAdmits、HookRejectsUnadmittedMerge PASS | Linux 真 hook 复跑 |
| gate / Bypass cannot repair an unsafe merge | MandatoryAndModes、mandatory facts/native style/signing 与独立 bypass 单测 PASS | 全入口/各 style 实跑 |
| gate / Unresolved conversation blocks unprotected branches | MandatoryFactsWithoutBranchProtection、ConversationWakeWaitsForCommit PASS；前轮 conversation Linux 双 DB PASS | Linux merge/auto conversation 入口 |
| gate / Existing protected branch remains protected | NativeUsesPinnedCodeownersAndSigning、current guards、models/git typed helper 单测 PASS；前轮 native-role/codeowners Linux PASS | 各 merge style/签名真实 hook 回归 |
| gate / Native guard read failure | NativePolicyAndWorkflowReadsPreserveErrors、InvalidNativeFilePattern、CODEOWNERS checked parser PASS | Linux 故障矩阵 |
| gate / External check is missing or overwritten | current SHA/base repo/latest identity、failure/error/unknown 单测；前轮 authenticated status API→ordinary merge PASS | 最新双 DB /全入口 |
| gate / Required context survives inheritance and absent branch protection | feature required inheritance、多来源 contexts、DirectServiceRejectsBeforeGit PASS；前轮 Linux ordinary PASS | worker/force 全真实路径 |
| gate / Enabled is not required and empty required is not success | FeatureRequirements、NativeRequiredStatusPending、RequiredContexts 单测 PASS | 最新入口矩阵 |
| gate / Skipped status preserves native compatibility only | SkippedIsSourceSpecific 单测；前轮企业 skipped HTTP 状态仍拒绝 merge PASS | 最新双 DB 复跑 |
| gate / Lower scope cannot weaken an upper rule | ProtectedPathCumulativeAndTransfer、多规则 AND、feature 首锁单测；前轮 Linux scope API PASS | 最新准入并发切点 |
| gate / Atomic revision and audit protection | ProtectedPathAtomicAudit/CAS；前轮真实 Linux PG row-lock 屏障 PASS | 当前准入与事实并发屏障 |
| gate / Ownership and role deletion | Reference lock/CAS/转移 unresolved/删除保留历史单测与前轮 Linux PG 生命周期 PASS | 最新归因/转移入口矩阵 |
| gate / Rename cannot escape protection | TrustedGitPaths、完整 NUL diff rename/copy 双端/删除/CODEOWNERS/超限，前轮 Linux Git PASS | 最新 fork/AGit 实际 merge |
| gate / Stale self or revoked approval | SensitiveRoleApprovalsRemainPerRule、ReviewerUsesCurrentRoleIdentity 与 native 分离 PASS | Linux 角色变更准入屏障 |
| gate / Force without authority or reason | shared form/独立 action/理由/七类别服务单测 PASS | TestEnterpriseMergeGateForceRequestFields 最新 Linux 实跑 |
| gate / Selected checks alone are bypassed | global required 豁免 audit/revision不变、部分选择仍 deny、mandatory/error 不可豁免 PASS | Linux Web/API/force 审计 |
| gate / Auto merge cannot inherit bypass | pure schedule/auto matrix、service options、组件 auto 清字段 PASS | 真实 HTTP 绕过客户端字段测试 |
| gate / Queue time allow becomes execution deny | WorkerRejectsChangedAuthorityFeatureAndStatus、WorkerConsumesScheduleAttribution PASS；新 role/feature/failure 均零 Git/PR 副作用 | 最新 Linux worker 真成功/拒绝/cleanup |
| gate / Direct service call cannot skip the gate | DirectServiceRejectsBeforeGit、ManualRejectsUnprovenHistory、mandatory 错误留证 PASS；前轮普通 Linux merge PASS | 最新 manual/auto/shared 成功路径 |
| gate / Scheduled credential is revoked or unattributed | 七类 PAT/旧队列/replace/cancel/error、session attribution、PublicOnly/org ceiling PASS | Linux 真实签发/认证/吊销协议 |
| gate / Already pushed but governance failed | ManualHistoryUsesReceiveOldRef、UnknownManualPusherLeavesHonestEvidence、manual preview PASS，Git 已存在而 PR 保持未 merged | Linux receive→后台识别与主动 marker/bypass |
| gate / Admission audit failure blocks Git mutation | EvidenceAtomicAndTerminalFailure、DirectServiceRejectsBeforeGit，前轮 actual audit-before-push Linux PASS；新增 credential error 两阶段留证 PASS | 当前全入口零清理/零通知矩阵 |
| gate / Git success followed by terminal evidence failure | 前轮 actual terminal-audit fault Linux PASS；同 operation receipt/terminal CAS/unknown pagination 单测 PASS | 最新取消/超时/进程重启真实故障对账 |
| gate / Reader sees blockers without raw upper policy | HistoryIsolation/SafeCapabilities、locale/HTML转义组件 PASS；前轮 preview/history API Linux PASS | 最新完整 HTTP privacy/CSRF 矩阵 |
| gate / Button state cannot authorize stale execution | backend final gate/fingerprint、preview纯读、组件 form/键盘/error/unknown PASS | Linux PostgreSQL 全事实屏障与真实页面提交 |
| gate / Credentials and forbidden login regressions | 认证相关单测/完整后端回归 PASS，callback配置/LOGIN_ONLY无变更、receipt不是认证凭据 | Linux 合法企微/MFA与禁止路径、真实SSH/PAT/GitHTTP |

### 精确待验收与交付状态

- 8.2：head/base/rule/feature/role/status/conversation 全事实的当前准入确定性 PG 屏障；不能用单次 snapshot 变更单测替代真正并发。
- 8.4–8.5：最新 gate-bound ticket 的真实内部 merge push/native signing/pre-receive，以及 Git失败、取消/超时、Git成功后终态 DB/audit 故障、进程重启 receipt 对账；对账单测不是实际进程重启。
- 9.6、10.4、11.1/11.4：完整模式×角色×凭据×入口/style/fork/AGit 实际 Git/PR/cleanup/notify；Web/API全部错误码与隐私/旧session/跨scope、Origin/Fetch Metadata 拒绝及真实 merge box 页面 e2e。已有组件5项不是整页 e2e。
- 11.2–11.3：Linux 企微合法登录/MFA及其他禁止Web路径、callback关闭/合法刷新/完整同步，真实 SSH/PAT/Git HTTP 签发/认证/scope/吊销与 clone/fetch/普通/保护push。未开发 Windows 服务端验收。
- 11.5：当前版本 Linux SQLite/PostgreSQL 上述全部入口、并发、故障和恢复复跑，Docker daemon 不可连接。前轮双DB迁移/规则/preview/current status普通merge的PASS保留，不涵盖本轮新增force/manual/auto/UI/recovery。

无外部 scanner/AI/供应商 token/自动 integration，未测试或声称外部扫描内容可信。门禁代码实接不等于上述矩阵全部验收，生产 enforce 仍不建议启用。未提交、推送、部署、改宿主服务、sync main specs 或 archive。


### 审阅追加：credential SQL 中止与最新串行收口

只读 reviewer 确认 admission 的 credential SQL 错误会使 PostgreSQL 同事务 aborted；仅将 Go error 转为 fact 并继续写记录不够。已核对并复用已有 `db.WithSavepoint` 恢复语义，在 admission 与 schedule 两处 credential 读取隔离 SQL 错误；savepoint 本身无法建立/回滚/释放时仍以 evidence_persist_failed 返回503，不输出 allow。

`TestMergeGateCredentialSQLFailureKeepsIndependentEvidence` 用测试 hook **显式模拟** PostgreSQL “SQL 错误后事务拒绝所有后续语句、ROLLBACK TO SAVEPOINT 才恢复”状态，而非仅返回单个 BeforeProcess error；`credential-aborted-tx-red.log` / `credential-aborted-tx-green.log` 及 `schedule-credential-aborted-tx-red.log` / `credential-savepoint-final-green.log` 为真实有效 RED→GREEN。最后日志的 pull/automerge 全部 TestMergeGate 均 PASS，ordinary/admission 为 error/not_started，schedule 保持 candidate error/not_admitted。该模拟验证代码恢复接线，**不是 PostgreSQL 服务端实跑**。

另新增 Linux PG-only `TestEnterpriseMergeGatePGCredentialSQLFailureEvidence`：当时拟用 credential hook 的 `c.Ctx` 执行 `SELECT 1/0`（这一事务归属假设已被下方实跑推翻），检查 typed503/独立 error evidence/audit 与零 Git/PR mutation。Docker 不可连接，当前尚未运行；仅准备编译，不把测试定义或交叉编译当 PASS。因此 task8.3 暂不勾，必须连同当前真实 PostgreSQL 故障验证收口。

`continued-terminal-backend.log` 是编辑过程的中间全套结果，真实 exit2，仅 automerge/read_error 在修复前读取了旧 worker early-return 编译结果；已有有效 RED 与修复后两包 GREEN，不隐藏该失败。最新串行使用隐藏 repo TMPDIR `.runtime`，在所有源码编辑完成后运行 fmt/lint→完整 backend→build→Linux测试二进制→Swagger，结果待下面追加。没有通过排除包/跳过测试/弱化 linter 解决问题。

本检查点新增完成4.3、6.1、8.1、9.1–9.5、10.1/10.3/10.5、12.3/12.4：**46/59**。保留8.2–8.5、9.6、10.4、11全部与12.5待最终验证，不能宣称 all_done。


最后只读复核当时未发现新增 Critical/Important：两处 credential savepoint 正确，恢复失败仍 fail-closed；但 PG-only 注入的 `c.Ctx` 事务归属仅为静态假设，后被下方真实 PostgreSQL 实跑推翻并撤回，不作为有效故障证据。审阅未编辑/未运行命令，不能替代待执行的 Linux PostgreSQL 验证。


`final-swagger-compatibility.log` 对 HEAD 做结构化旧合同检查：所有既有 paths、operation parameters/responses、definitions 既有 properties/required 均完全不变；MergePullRequestOption 的 force_merge 仍 boolean，新 bypass_reason/categories 不在 required 中，实际 PASS。新增 capabilities/字段只做 additive 扩展，没有把 swagger-check 未提交 diff 当成功。


### 最终当前源码验证结果

`final-current-pipeline.exit` = **0**。串行 `make fmt lint-go`（`final-current-fmt-lint.log`）0 issues → `make test-backend TAGS='sqlite sqlite_unlock_notify' GOTEST_FLAGS='-count=1 -timeout=5m -p=4'`（`final-current-backend.log`/`.exit`）**exit0、244个测试包ok、零FAIL** → `make build`（`final-current-build.log`）→ 当前 Linux arm64 `integration.test` / `pull.test` 编译（`final-current-integration-compile.log`）→ `generate-swagger swagger-validate`（`final-current-swagger.log`）全部真实 exit0，涵盖最后 credential savepoint 与 worker 留证源码。集成二进制包括新 PG-only SQL 中止测试，但尚未执行 Linux 实跑。

backend/build 的 Go 输出有一次尝试写宿主只读 module stat metadata 被沙箱拒绝的 warning；实际无宿主写入、命令继续成功，未因此申请越界或修改 cache/DNS/proxy。使用 `.runtime` 的最终串行 lint 未再发生临时 go-build 目录消失的 typechecking 竞态。前端完整 54files/167tests、scoped JS/type/CSS 与 591模板 lint 的最后通过输出见前文；后续只有Go/文档变更，未改变前端源码。

新增完成11.6，当前 **47/59 tasks**。8.2–8.5、9.6、10.4、11.1–11.5与12.5仍未勾：当前Linux PostgreSQL SQL中止/准入事实屏障、全模式/角色/入口/style、真实认证/Git协议、故障/进程重启及整页e2e验收未完成；12.5已更新 verified roadmap/plan 的部分状态，但最终“所有要求完整交付”核对不能在这些验收之前宣称完成。没有缩减范围或把mock/交叉编译当验收，change仍ready而非all_done。


最终编辑后再次运行 `make fmt lint-go`，`final-post-edit-fmt-lint.log` **exit0/0issues**；SHA-256 核对110个改动/新增Go文件，formatter changed files=[]（`final-post-edit-source-check.log`）。因此完整后端/build/Linux测试二进制的通过证据仍对应当前源码，不是格式操作前的不同代码。最终 strict validation 和 git diff --check 均 exit0；OpenSpec apply 返回 ready、47/59、12项剩余，没有all_done、提交、推送或归档。


## 2026-10-06：Docker 恢复后的 Linux 实跑与最终准入切点

用户确认启动 Docker Desktop 后，已核实 Linux/aarch64 可运行；上方“Docker 不可连接”均为历史检查点，不再是当前阻塞。测试仅使用本仓库隔离数据及临时容器，不修改原有服务。

### 实跑发现与修复

- Linux 首次启动因缺少 `admin.dashboard.reconcile_enterprise_merge_gate` 翻译 fatal（`resumed-pg-credential.log`）。已补 en-US，真实 Linux 启动及门禁套件通过，不绕过 cron 注册或翻译检查。
- 旧 PG credential hook 的 `c.Ctx` 未携带被测事务，`SELECT 1/0` 实际没有注入，测试出现 `expected error, got nil`（`resumed-pg-credential-green.log`，名字不代表通过，exit1）。现改为真实 access_token bigint 参数非法，PostgreSQL 服务端产生 `invalid input syntax`/22P02，AfterProcess 明确捕获服务端错误；savepoint 恢复后独立 error/evaluation audit 可写、503、Git/PR 零写。`resumed-pg-credential-server-green.log` exit0，后续两 DB 套件重新覆盖；SQLite 的 PG-only skip 不当成 PG PASS。
- 凭据现每轮 collector 都刷新并与原 ceiling 相交，SQL error 不因后续成功读取消失。`resumed-credential-recollect-mutation-red.log` 临时恢复“只刷新一次”后撤销/收窄用例均失败；已恢复修复源码，`resumed-final-gate-unit.log`、`resumed-pagination-green.log` 两包全部 TestMergeGate PASS。SQLite helper 明确命名和 nil context guard，不冒称 PG 并发。
- 原生 PB 摘要/版本与有界 review ID/元数据参与 fingerprint，不存审批自由文本。PB 布尔结果不变时版本变化的 RED 为 `resumed-native-fingerprint-red.log`。另发现 FindReviews 被 API.MaxResponseItems 截断；MaxResponseItems=1 的 `resumed-native-pagination-red.log` 有效失败。现改为绝对 Limit(1025)、按 ID 排序，真实 1025 reviews 拒绝而不截断 allow，`resumed-pagination-green.log` exit0。初次修复因复用 err 误写 := 编译失败，已修正，不把编译失败当行为 RED。

### 当前真实验证

- `resumed-final-pipeline.log` / `.exit`：串行 fmt/lint-go 0issues、完整 backend **244 个测试包 ok/零 FAIL**、Linux build、integration/pull Linux 二进制编译、Linux SQLite/PG 全部 TestEnterpriseMergeGate、Linux pull 全部 TestMergeGate、双 DB migration/storage、Swagger generate/validate、strict、diff-check，全部 exit0。这一套覆盖本轮全部生产代码；之后新增/加强的集成与 E2E 测试分别补跑，不把较早测试定义算作最新验证。
- `TestMergeGateFinalFingerprintConsumesConcurrentChanges` 七类真实 collector channel 屏障 PASS；`resumed-fingerprint-mutation-red.log` 临时停用复采后七项均失败，源码已完整恢复。此单测本身不是真实准入事务证明。
- `resumed-admission-pg.log` 的 11 项 PASS 最初命中实际 Merge 的 start=false 前置检查；审阅指出它未覆盖最终写前 gateGuard。现屏障改为第四次 token 读取/第二次 policy 锁 UPDATE，且每条拒绝快照必须包含生成的 `result_sha`，保证已通过预检和临时 commit staging、进入 start=true 最终准入。`resumed-final-admission-pg.log` **11 项 PASS，单项0.27–0.56s**：status、PAT撤销/收窄、approval、conversation、draft、head/base、feature/path rule/role binding。前七类在最终复采切点提交；受政策锁保护的后三类在最终取锁前由真实管理事务先提交，不声称持锁后仍可并发修改。最终拒绝 not_started、PR 未 merged、Git refs 无额外 mutation（head/base 测试自己的 ref 变化单独作为基线）。只读复核未见8.2剩余 material 缺口。
- 真实 `ActualAuditFailures` 两 DB PASS，强制 admission audit 故障返回503、零 Git/PR 写、head分支不清理、成功通知零；terminal audit 故障发生在 Git/PR 真成功后，保留 started 与无终态审计，不伪造“未执行”。credential 真实 SQL 故障及独立拒绝证据也通过。8.3 完成不代表8.5进程重启已经验收。
- `resumed-post-test.exit`=0：在最终屏障及合法登录 authority refresh/完整 publication 回归增强后，fmt/lint-go、最新 Linux integration 编译、SQLite/PG 全部 TestEnterpriseMergeGate 再跑 PASS。后续 protocol 扩展结果另记，不将这一较早输出覆盖到新增协议用例。
- E2E 为仓库真实 Playwright 测试 `tests/e2e/enterprise-merge-gate.test.ts`，显式 `GITEA_TEST_E2E_MERGE_GATE=enforce` 才注册，默认关闭环境不运行此特定合同。隔离 Linux Gitea + SQLite 服务使用正式 migration/admin CLI 初始化；Chromium 实际点击 blocked→current status success→merge，以及有限类别+必填理由→bypass→merge，并经 API 验证 merged=true。`resumed-e2e-final.log` **2 PASS，3.9s/2.9s**；没有 mock preview、不是 Vue 组件测试。宿主 Chromium 首次启动被 MachPort 沙箱拒绝，保留失败日志，按审批运行浏览器成功；不关闭安全检查或假称失败为PASS。Linux 服务是被测后端，macOS 浏览器是客户端，不是 Windows/macOS 服务端验收。
- `resumed-ui-lint.log` exit0：新增 E2E 与 merge form scoped eslint + vue-tsc。已将条件行为拆为两个测试、取消 skip annotation，无 linter 禁用。完整前端167测试的既有通过证据仍适用于未变的生产前端。

新增完成8.2、8.3、11.4，当前 **50/59**。仍缺8.4–8.5、9.6、10.4、11.1–11.3、11.5、12.5的完整验收；不能把 Owner 两项E2E泛化为全部角色、入口/style、CSRF/旧session、真实重启恢复或供应商执行证明。真实协议扩展正在运行。未提交、推送、生产部署、同步主spec或归档。

### 2026-10-06：三模式认证及真实 Git 协议补齐

- `resumed-protocol-private.exit` 为 0；`make fmt lint-go`、Linux arm64 integration 编译以及 Linux SQLite/PostgreSQL `^TestEnterpriseMergeGate` 全部通过。三种 gate 模式均固定 action enforce，未修改生产认证配置。
- 合法企微 OAuth/MFA、禁止密码/注册/OpenID/Passkey/其他 OAuth/反代/SSPI 路径、callback 关闭、登录管理 authority 刷新及完整目录 publication pipeline 回归通过。定时同步验证为同一 pipeline 的 `cron` trigger 调用与持久化状态，不声称连接真实企微供应商或等待实际十分钟定时器。
- 真实 Git HTTP PAT 和 SSH key 完成 clone/fetch、普通 push；readonly PAT push 被拒且不存在目标 ref，受保护分支拒绝后 ref 不变，撤销 token/key 后私有仓库 fetch 被拒。直接 push 未生成 PR gate evaluation。协议子项各小于 2 秒；三模式 wrapper 累计耗时不作为单项耗时。
- 初版 HTTP 吊销 fetch 测试使用公开仓库，因此匿名 fetch 正常成功。`resumed-protocol-sqlite.log` 保留该测试预期错误；改为 private fixture 后才验证凭据吊销，不修改或收紧公开仓库原生匿名读。
- 11.2、11.3 已勾选，当前 52/59。只读复核未发现这两项 material 缺口。
- `resumed-e2e-csrf-keyboard.exit=0`：3 项 Chromium 对隔离 Linux Gitea 通过（2.8/4.3/3.2 秒）。增加真实 Web session 跨站 Origin/Fetch-Metadata 合并请求 403、PR/ref 不变；有限 bypass 通过焦点和 Enter 提交，脚本形式理由未执行。4.3 秒超过 4 秒目标，保留实际耗时而不降低断言。`resumed-ui-corrected-lint.exit=0` 为最新 scoped ESLint 与 vue-tsc。


## 2026-10-06：完整 Linux 验收与交付收口

### 最新代码、修复与有效证据

本节取代历史待验收状态；没有删除失败日志、停用原生守卫、弱化断言或用 mock 替代 Linux/Git。

- `resumed-acceptance2-sqlite.log` 发现 enforce Web 无 session 的 readonly PAT 请求进入 gate 时 actor=nil，导致 500。`CheckPullMergeableForRequest` 在 enforce 首次使用 actor/PR 前返回 typed403；新增 nil/无效 actor/nil PR 单测。当前双 DB 108 项矩阵均通过，disabled/shadow 行为不变。
- 自定义 pre-receive 故障注入最初排序在 `gitea` 前，fixture wrapper 最后成功码覆盖了故障码；改为最后执行的 `zz-gate-acceptance-deny`，未改生产 hook。真实签名拒绝、hook 拒绝/ref 不变及移除故障后的成功均验证。
- 预先取消的请求不会制造准入 allow。取消/超时测试现定位在真实 Git 成功后的 marker 审计边界：返回 terminal_unknown/503，Git/PR 已成功，记录 unknown；真实对账两遍后 succeeded，快照不变，重试无再次 push。超时等待真实 context deadline，不使用 sleep 或伪造成功。
- restart helper 使用独立进程自己的 private hook/active execution proof、正式 DB 动态配置 getter。在 terminal audit INSERT 前 `os.Exit(86)`，父进程确认 Git/PR 已成功、记录 started、无终态审计；两个新进程调用真实 reconcile，仅一次成功审计且 ref 不变。测试只在隔离 fixture 中把 started_unix 置旧以跨过十分钟保护窗，不改生产 DB version，也不声称实测了墙钟 cron 调度。
- 子进程 DB 写入不触发父进程 fixture 的 dirty tracking，曾导致后续测试继承已合并 PR。restart cleanup 重新初始化既有 fixture loader，使下次恢复所有注册表；证据断言先于 cleanup。`resumed-acceptance5-focused.exit=0` 顺序 restart→取消/超时→preview 通过，随后完整双 DB 套件再通过。
- 旧 session 回归使用真实 Web 管理页，不把必须 token 的管理 API 当成 session API。管理权限撤销后旧 session403；private repo outsider404、Owner200 与原始规则/history scope 隔离一起通过。

### 当前串行验收命令及结果

`tmp/merge-gate/resumed-complete-pipeline.sh` / `.log` / `.exit` **exit0**，依次实际运行：

1. `make fmt lint-go`：0 issues。
2. `make test-backend TAGS='sqlite sqlite_unlock_notify' GOTEST_FLAGS='-count=1 -timeout=5m -p=4'`：244 个测试包 ok、零 FAIL。
3. `GOOS=linux GOARCH=arm64 make build TAGS='sqlite sqlite_unlock_notify' EXECUTABLE=tmp/merge-gate/linux/gitea`；当前 integration/pull 二进制编译通过。migration 二进制另由当前 `./modelmigration/v28/` 编译，`resumed-complete-migration-compile.exit=0`。
4. 隔离 Linux/aarch64 SQLite、PostgreSQL 17.9：`sh tmp/merge-gate/linux/run.sh <sqlite|pg> integration.test '^TestEnterpriseMergeGate'`，两边全部通过、零 panic/FAIL；不是 macOS 服务端或 mock DB。PG 使用独立容器、网络及测试库，不影响现有服务。
5. Linux `pull.test '^TestMergeGate'`，双 DB `migrations.test '^TestEnterpriseMergeGateMigration'`，均 exit0。
6. `make generate-swagger swagger-validate`、`openspec validate add-enterprise-merge-gate --strict`、`git diff --check`，均 exit0。另实际结构化对比 HEAD Swagger：既有 operation parameters/responses、schema properties/required 不变，旧 force_merge 仍 boolean，新增 bypass 字段可选。

前端当前证据：`resumed-complete-frontend.exit=0`，Chromium Vitest **54 files / 167 tests**；最新 scoped ESLint、vue-tsc、stylelint exit0。`make lint-templates` 的 `resumed-complete-template-lint.exit=0`，591 模板、0 errors。

`resumed-complete-e2e.exit=0`：用上述最新 Linux 构建重启隔离测试服务，Chromium 三项真实页面 E2E 全通过，包括跨站 session POST403/伪造 bypass422/ref 不变、当前 authenticated status success→普通 merge、有限 bypass 必填理由与 Enter 提交/转义。实际耗时 **4.1/5.5/4.0 秒**，超过小于4秒的性能目标，保留此限制，不减少断言。矩阵单项最大 SQLite0.83s/PG0.90s，styles 单项最大两 DB 均0.86s；恢复/取消测试子项也有界，聚合测试累计耗时不当成单项耗时。

测试服务与匿名 volume 已删除，`resumed-complete-ui-cleanup.exit=0`；PG runner 正常退出自动清理临时容器/网络。原有 feature-grants 与其它现有容器未修改。

### 最终 Requirement / Scenario 补齐

上方逐 Requirement/Scenario 映射继续有效；先前“仍缺”列由以下当前证据补齐，不把测试定义或历史 PASS 当成最新结果。

| 合同与剩余场景 | 当前真实证据 |
| --- | --- |
| 模式/统一阶段/mandatory/native/bypass；Web/API/shared/force/manual/worker 的成功与拒绝 | `EntryRoleMatrix` 两 DB 各108 PASS；6入口×6角色×3模式，检查实际 PR/Git、head删除或保留、成功通知恰一次/拒绝零次；manual 拒绝保留先前已写 Git |
| 原生 style/signing/pre-receive、内部 push 不要求 direct protected-push action | 两 DB 各15 styles PASS（merge/rebase/rebase-merge/squash/fast-forward-only）；保护分支 CanPush=false 的内部 merge 成功，真实签名/hook 不可豁免；当前 hook ticket 精确绑定、跨请求/过期/终态拒绝单测 PASS |
| 完整可信 diff、fork/AGit、preview非票据 | 两 DB `ActualForkAndAGitMerge`、`PreviewForkAndAGit` PASS；真实 fork/hidden ref merge 与缺对象 error；原可信 Git 路径/rename/copy/超限单测随完整 backend 再通过 |
| 最终实际准入消费最新事实与凭据 | 当前 PG 最终 start=true 屏障11 PASS（0.22–0.43s），含 generated result_sha，status/撤销/收窄/approval/conversation/draft/head/base/feature/path rule/role；非仅前置预检 |
| 原子准入审计/error留证/零副作用 | 两 DB `ActualAuditFailures` PASS；PG真实22P02 credential SQL 故障 PASS，503、独立 error evidence、零 Git/PR/cleanup/notify |
| 终态 CAS/取消/超时/重启/幂等 | 两 DB `RestartAfterGitSuccess`（0.80/0.83s）、`RequestCancellationKeepsOutcome` PASS；真实 Git 成功后 started/unknown、同 operation receipt 对账，无重复 push/成功审计；terminal 故障与跨 operation 负例一起覆盖 |
| 管理/reader权限、401/403/404/409/422/503、旧session/private/跨scope、转义/CSRF/键盘 | 两 DB rules/history/preview/force/SQL fault 回归，167前端测试、3项最新真实 E2E；不是只有按钮或 mock preview |
| 累加规则、CAS/角色引用/owner转移/审批当前身份及历史隐私 | 当前完整 backend + Linux scope/生命周期/锁竞争与规则套件 PASS；封存历史/大小/受控投影负例保留 |
| 上级 required、current head/latest status、native skipped兼容/企业success-only | 当前完整 backend + 两 DB authenticated status API→普通/worker实际 merge PASS；六外部feature消费、不执行provider的合同不变 |
| 认证与协议部署边界 | 当前两 DB三模式wrapper PASS：企微合法登录/MFA、禁止Web路径、callback关闭/合法刷新/cron trigger完整pipeline，以及真实私有repo HTTP PAT/SSH clone/fetch/push/scope/revoke；不宣称真实供应商或Windows服务器 |
| action vocab/default/history/migration | 当前完整 backend + Linux双 DB migration/storage PASS；migration364→DB365、catalog3、仅Owner/Platform Admin补两个action，复制角色/绑定与v1/v2历史不扩权 |

权限闭环保持：所有入口受原生 auth/credential/native authority 与当前 merge action/gate 约束，PR merge box 与服务端相同安全 DTO/reason 语义；rules API 的 repo写另要求 manage_sensitive_paths，global/org使用独立authority；force另要求 bypass_merge_gate。Owner/当前可信超管为默认action正例，Admin无新action拒绝，显式自定义角色须有原生准入，readonly/受限凭据不写。没有新增登录入口、全量规则UI、OpenFGA/Keycloak/Flyway；数据库变化只走Gitea additive migration。

只读 reviewer 未发现新的 Critical/Important 或 material 覆盖缺口；review 不是测试执行证据。代码与 artifact 最终核对没有生产 stub/mock/扫描执行/供应商token、TODO-only或不可达替代路径。核心要求全部覆盖；性能目标的上述偏差、真实供应商/墙钟cron未连接及生产上线未执行不伪装为通过。

8.4、8.5、9.6、10.4、11.1、11.5 依据当前证据勾选；文档收口后最终 strict/diff 检查真实 exit0（`resumed-complete-final.exit`），apply 返回 **all_done、59/59、remaining=0**（`resumed-complete-final-apply.json`），12.5 已完成。未提交、推送、合并、生产部署、同步 main specs 或归档；未来 sync/archive 必须按前序授权能力依赖顺序另获授权。
