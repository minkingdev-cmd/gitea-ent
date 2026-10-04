# 实施与验收记录

## 基线与范围

2026-09-30 开始执行；OpenSpec 是唯一计划与行为合同。服务端永久仅面向 Linux，部署数据库 PostgreSQL，SQLite 用于快速测试。callback 保持关闭，登录管理员权限刷新 + 定时完整同步；不新增 Windows 支持、不修改原生凭据、不提交或推送。

已核对 `make help`、开发/后端/测试文档、企业授权 requirements、implementation-plan 和 proposal-roadmap。预存 `implementation-plan.md` 与 `proposal-roadmap.md` 内容校验值分别为 `84a9f45ef63ec4b2474556678bee1dfae7acdf83deb3e1e24b9387bd386c333f`、`6191672d6dbe9f605ae9819988a0f34c98516501743ae6fd56a46aaec6918a75`，保留原修改。

实施时核对当前最后 migration 为 `modelmigration/v28/v360.go`；下一编号使用 v28/v361，而非早期 design 引用的 v1_27。这只是实际目录/编号校正，不改变 additive 范围。

## 完整验收矩阵

以下矩阵是覆盖索引，不代表测试已通过。逐项实际证据后再更新任务。

| Delta requirement | 必须证明的结果 | 任务 |
| --- | --- | --- |
| disabled/shadow 配置 | 严格布尔、禁止 enforce、依赖 audit、disabled 零查询 | 2.1–2.2、8.1–8.2 |
| action vocabulary | 19 个唯一 key、allow-only、unit 前提、feature grant 仅诊断 | 2.3–2.4 |
| 内置与自定义角色 | 八个不可变 seed、三个 scope、复制快照、revision | 3.1–3.3、4.2 |
| 主体绑定 | user/team/org 来自本地关系、幂等、owner 变更失效 | 3.4–3.5、4.3 |
| 原生默认映射 | Read/Write/Admin/Owner、unit/凭据差异、原生状态不变 | 1.4、5.1、5.5 |
| allow-only evaluator | 不建可见性、不绕过账号/unit/credential、错误不伪装 deny | 5.2、5.4–5.6 |
| 受限条件 | AND/OR/all-path、完整非空路径、来源和大小限制 | 5.3、5.6 |
| 真实入口 | 读、clone、分支、PR、设置与生命周期真实观察 | 1.3、8.1–8.9 |
| 决策证据 | 独立原子事务、关联去重、200ms、64KiB、分页与留存 | 6.1–6.6 |
| 管理 API 权限 | 原生 authority 与方法 token scope、认证优先、跨 scope 隔离 | 4.1、4.5、7.1–7.5 |
| 并发管理 | revision 竞争、绑定引用锁、审计失败回滚 | 4.4、4.6、10.2 |
| 脱敏 | 日志/audit/decision/API 无 secret、私密路径或原始错误 | 6.4、6.7、7.4 |
| migration/回滚 | 显式升级不 regrant、重复恢复、关闭及成套备份回退 | 3.2–3.5、9.4–9.5、10.2、10.5 |
| Web/协议兼容 | LOGIN_ONLY/MFA、SSH/PAT/Git HTTP/synthetic 与治理 guard | 9.1–9.3 |

## 生产入口盘点（任务 1.3）

以下是当前代码的调用边界盘点，用于确定 observer 的安全挂点；HTTP handler 中的 actor 以已经认证的 `ctx.Doer` 为准，Git/SSH 则只能使用其真实 transport credential resolution，不能从 URL 或请求体重建主体。业务路径仍独立执行现有 permission、branch protection、WeCom guard 和事务，observer 不参与其返回值。

| 操作族 | 当前主要生产入口 | actor / resource 与结果边界 |
| --- | --- | --- |
| Web repo metadata/code | `routers/web/repo/view_home.go`、`routers/web/repo/view.go`、`routers/web/repo/branch.go` | 在 repository context 已完成后使用 `ctx.Doer` 与 `ctx.Repo.Repository`；拒绝/成功仍由现有 route permission/render 路径决定。 |
| API metadata/code | `routers/api/v1/repo/repo.go`、`routers/api/v1/repo/file.go`（`GetContents*`） | 使用 repo API middleware 赋值的 `ctx.Doer`、`ctx.Repo.Repository`；native token scope 与 code unit 检查不变。 |
| Git HTTP clone/fetch/push | `routers/web/repo/githttp.go:serviceRPC`（upload/receive-pack） | HTTP credential 解析后才能获得 doer 与 repo；传输最终结果只有 Git RPC/transport 结束时才确定，handler 认证不等于 pack 成功。 |
| SSH clone/fetch/push | `cmd/serv.go:runServ`，`cmd/hook.go:runHookPreReceive`，`routers/private/hook_pre_receive.go:HookPreReceive` | SSH key/token 在 serv 层解析；pre-receive 使用可信 hook option、repo/ref/commit；拒绝/成功需按 hook stage 记，不推断最终客户端传输结果。 |
| Branch/file editor | Web `routers/web/repo/branch.go`、`routers/web/repo/editor.go`；API `routers/api/v1/repo/branch.go`、`file.go`；Git push `services/repository/branch.go`、`cmd/hook.go` | route 中 repo/doer 已赋值；ref 操作依现有 protected-branch 和 receive hook 检查，file edit 需从其提交 service 传递 trusted path/ref。Tag 不映射为 branch。 |
| PR create/review | Web `routers/web/repo/compare.go`、`pull_review.go`；API `routers/api/v1/repo/pull.go:CreatePullRequest`、`pull_review.go` | 创建的 target repo 与 review 对象 repo 必须使用服务端加载对象；native status/body/permission 结果保留。 |
| PR merge/auto/force | API `routers/api/v1/repo/pull.go:MergePullRequest`；共享 `services/pull/merge.go:Merge`、`IsUserAllowedToMerge` | service 有 PR、doer 和 base repo，可观察共享 merge path；force/auto 标注各自可信 source，branch protection/required checks 仍按原逻辑执行。 |
| Protection/CODEOWNERS/webhook/CI/secret | API `routers/api/v1/repo/branch.go`、`action.go`、`hook.go`、`git_hook.go`；Web `routers/web/repo/setting/` | 在既有 manage guard 与资源加载之后用 repo/doer；secret value、webhook URL/token 不进入 context、snapshot 或日志。 |
| Migration | `services/migrations/`、`services/repository/repository.go:CreateRepository` | 仅本地 target repo 已分配 ID 后记录 `repo.migrate`；其前失败没有 repo 资源，不能制造 decision。 |
| Transfer/archive/delete | `services/repository/transfer.go`；`models/repo/archiver.go:SetArchiveRepoState`、API `repo.go:updateRepoArchivedState` / Web `setting.go:handleSettingsPostArchive`、`handleSettingsPostUnarchive`；`repository.go:DeleteRepository` / `delete.go:DeleteRepositoryDirectly` | transfer/delete 在变更前 snapshot owner/repo；`services/repository/archiver/archiver.go` 是只读归档下载，不是归档状态修改。数据库事务、仓储清理和异步副作用不能由 observer 改写。 |
| Feature grant | 尚无该产品操作入口 | 仅目录与显式诊断，不添加伪造 route/service hook。 |

这是初步盘点，仍需补齐全部 action 的精确拒绝/成功/事务挂点及测试对照。当前仅接入下文列出的第一批读取入口，不把盘点当作其余调用接入验收。

## 首轮基础切片证据（历史记录）

以下保留首轮 RED/GREEN 与当时的范围，后续进度以下节为准。

- 配置：先补足类型/解析接口，再实跑断言 RED：`disabled_enforce`、`enabled_enforce`、`missing_audit` 返回 nil；实现配置安全门槛后 `TestEnterpriseAuthzConfiguration` GREEN，日志 `tmp/authz-settings-{red,green}.log`。
- 条件：接口建立后 `TestConditions` 实跑 RED（matched/unresolved 与未匹配不同）；实现 AND/all-path/完整上下文与未知值拒绝后 `TestActionCatalog`、`TestConditions` GREEN，日志 `tmp/authz-policy-{red,green}.log`。
- 配置矩阵与 disabled table preflight：本轮 `GOCACHE=$PWD/tmp/go-build go test -count=1 ./modules/setting ./modules/enterpriseauthz ./models/enterpriseauthz ./services/enterpriseauthz ./modelmigration/v28` 全部通过（2.9s、2.4s、3.8s、2.1s、2.5s）；其中 `TestEnterpriseAuthzConfiguration` 覆盖缺省、严格 bool、ENFORCE、audit 和 WeCom 开关，`TestDisabledAuthzRequiresNoPolicyTables` 在表不存在时确认 disabled readiness 不查询角色表。可据此完成 2.2，但不证明生产入口 disabled 热路径零查询。
- evaluator 单 action 用例：先运行 `TestEvaluateCombinesNativeAndRoleActionsWithoutBypassingUnits`，观察到正确红灯（角色尚未应用）；修复后通过。`TestSubjectsCannotEscapeNativeBoundaries` 的 restricted actor 断言先观察到预期失败，再修正 `roleEligible` 后通过。服务尚未接入生产 observer，不能据此完成 5.2/5.4 或 8.x。
- migration/lifecycle：上述定向命令通过 `TestEnterpriseAuthzFoundationMigration`、`TestPolicyUniquenessAndCleanup`、`TestSubjectCleanupPreservesHistory` 及 `TestDisabledPolicyLifecycleCleanup`。当前测试库迁移可重跑、四表/内置 seed/index 存在，绑定与 observation 唯一约束生效；删除 user/team/org/repo 清除 live policy rows 并保留 decision 历史。resolver 对 repo binding 查询严格匹配现 repo owner ID，team/org membership 每次从当前关系读取；PostgreSQL 迁移并发/唯一性和旧 native 权限全量快照仍待 3.5/10.2，未由 SQLite 证据替代。
- 独立事务基础：`TestIndependentTransactionRejectsBusinessTransaction` RED（helper 不存在）后通过；独立写事务遇到现存 business tx 返回 `ErrIndependentTransactionInUse`，未调用 callback。现阶段尚未接入 decision+audit persistence，不能据此完成 6.1。

以上是针对性单测，不代表模型、管理 API、生产 hooks、PostgreSQL 或提案整体验收。

## 继续实施：管理服务、evaluator 与独立观察证据

### 已实现范围与权限矩阵

| 入口/能力 | 当前权限与行为 | 持久化/入口范围 |
| --- | --- | --- |
| system 角色/绑定服务 | 原生 site admin；企微开启时额外要求 active bound management authority | 无 shadow 角色自举；管理 HTTP API 尚未接入 |
| org 角色/绑定服务 | 真实 owner team 或可信系统管理员 | 本地组织与角色可见性校验；无新 UI |
| repo 角色/绑定服务 | 原生可见性；非企微为原生 Admin；企微为既有 creator/真实 owner/超管 guard | 复用下层 native helper，保留现有 guard 包装与审计 |
| evaluator | 真实入口已解析的 credential-aware Permission 与 read/write ceiling | 当前 actor 状态、owner/archive、membership、角色和权限在同一独立一致读事务读取；不按裸 user ID 回读原生权限 |
| Observe adapter | 原生 actor/repo 已安全解析，且资源可见、未持有业务事务 | 不返回授权布尔值；disabled 快速退出，decision+audit 独立原子提交 |

仅使用版本化 DB migration `modelmigration/v28/v361.go` 与八个显式内置角色，不引入 OpenFGA、Keycloak、平台默认授权或管理 UI。管理角色不修改原生 `IsAdmin`、membership、access 或凭据；HTTP token scope 与 Swagger 管理合同仍属于任务 7。

角色服务支持三个 scope 的 CRUD、可见角色独立复制、空权限/省略权限区分、版本前提、内置不可变、同 scope 名称唯一与有引用删除冲突。绑定支持三类本地主体、作用域/当前 owner 校验、Platform Admin 仅系统绑定和幂等写入；管理审计使用 ID、revision、action/effect、condition 指纹的 before/after 白名单，同事务 required persistence。

并发锁覆盖 native scope、绑定主体与引用角色；角色更新/删除、绑定增删和原生主体清理使用相同锁边界。忽略嵌套管理错误不能使外层业务事务提交。修复审查发现的转移清理死结：管理列表/删除按已授权 repo scope 限界，旧 org 角色不可见不再阻止解绑；评估仍排除旧 `scope_owner_id`，新 owner 必须显式重新绑定。

evaluator 已覆盖八角色、原生 Read/Write/Admin/Owner、code/PR 独立 unit 权限、三主体叠加与 ID 去重、匿名/synthetic/native-only、禁用/受限账号、不可见资源、凭据只读和归档写限制。条件采用 branch/source AND 与 all-path，缺失/空/超限上下文为 unresolved；快照稳定排序，保留参与角色 revision 与权限命中指纹，不保存原始 branch/path/credential 内容。候选始终 `candidate_only=true`、`safety_guards_evaluated=false`。

观察器已支持受信进程内 operation/observation ID、同 observation 重试去重、并发 request context 初始化去重、原生 outcome/stage、安全 impersonator/credential 引用、200ms 评估/证据预算与 64KiB 快照上限。失败输出静态计数原因及每原因每分钟一次的安全告警；证据写失败不改变原生响应。共享 audit retention 按同一 cutoff 分批清理 audit/decision，0 永久保留。跨 SSH/internal process 的 ID 传播、决策查询 API 和完整留存查询权限尚未完成。

### 第一批已接入的真实读取入口

| 生产调用 | 观察 action | 实际验证 |
| --- | --- | --- |
| API `repo.Get` / `GetByID` | `repo.view_metadata` | 真实 HTTP disabled/shadow JSON 与状态一致，PAT read-only ceiling 与安全凭据引用 |
| API `GetRawFile` / `GetRawFileOrLFS` / `GetContents*` | `repo.read_code` | contents/contents-ext 真实 HTTP 记录；私仓匿名与 code-hidden 拒绝不增加证据 |
| Web `Home` | metadata 与 code 两个子 observation | 真实已登录读取；每次各一条，source=web，保留原生结果 |

尚未覆盖全部 Web/API 读取分支，任务 8.2 不标完成；Git HTTP/SSH、写操作、merge/auto/force、设置与生命周期观察仍未接入。对象删除的 live policy 清理已实现，不等于删除操作观察已实现。

### 测试先行与审查记录

- 转移解绑 RED：repo role / former org role 的旧绑定列表均返回 0；GREEN：当前 owner 可列出/解除失效绑定，旧角色引用阻止删除直到解绑，新绑定存新 owner ID，跨 scope 删除仍为 404。日志 `tmp/authz-transfer-binding-{red,green}.log`。
- 当前状态快照 RED：沿用早期对象时 transfer/inactive/prohibit/restricted/archived 五种变化均错误 allow；GREEN：在同一只读事务刷新，分别拒绝过期绑定/账号/归档写，快照使用当前 owner。日志 `tmp/authz-snapshot-state-{red,green}.log`。
- 证据 owner/synthetic RED：snapshot owner=4 而 decision owner=2，附带 synthetic ExtDoerData 的正 ID 用户错误 eligible；GREEN：decision/audit owner 与快照同源，synthetic 不命中角色。日志 `tmp/authz-snapshot-evidence-{red,green}.log`。
- 悬空策略引用 RED：匹配绑定引用已不存在的角色时错误返回缺少 action 而没有存储错误；GREEN：返回 `error/policy_read_failed`，不伪装成空角色。日志 `tmp/authz-dangling-role-{red,green}.log`。
- 其他本轮 RED/GREEN 包括 request context 并发初始 operation 创建、白名单日志故障、可信 impersonator、重试 observation 关联、畸形持久化权限与主体清理锁；实现后相关定向测试通过。八角色/三主体/混合 code-PR/条件矩阵扩展用于验收既有行为，不修改原生 resolver 以迎合测试。
- 独立只读审查发现的转移绑定清理问题已修复；复核未发现本切片其他重大正确性/安全/并发问题。审查不替代以下实跑验证，也不代表未接入 API/hooks 的验收。

### 实跑验证与环境边界

- 本轮 PostgreSQL 使用 localhost 上新建的唯一测试数据库与仓库内临时配置，storage=local；结束删除仅该自建数据库/临时配置并恢复预存配置，cleanup exit=0。不复用/重置已有治理测试库，不改变 MinIO 或其他服务。迁移 `TestEnterpriseAuthzFoundationMigration` 已在 PostgreSQL 通过；管理版本竞争、更新/删除/绑定竞争、管理 audit 故障整次回滚、主体删除行锁、独立观察证据及真实读取测试已通过。
- `TestEnterpriseAuthzPolicySnapshotIncludesNativeStateAndPermissions` 在 PostgreSQL 明确先建立读快照，再提交角色权限、owner 与 actor 状态更新；原读事务仍见完整旧状态，后续 evaluator 使用完整当前状态。没有用 sleep 模拟并发。
- 首次全量 backend 的原生 CLI 删除测试因尝试写真实 `~/.ssh/authorized_keys.tmp` 被 sandbox 拒绝。核对 `HOME`/SSH 路径解析后，改用仓库内 `tmp/authz-test-home/.ssh`，保留原 GOPATH/GOMODCACHE；针对该 CLI 测试及 `make test-backend` 全量重跑通过。未修改测试断言或原生 SSH 逻辑，也未申请写真实 HOME。
- 首次 Swagger generator 的编译产生 macOS `ld: warning: -bind_at_load`，被既有严格 warning 检查拒绝；使用 `CGO_ENABLED=0` 重跑 `make generate-swagger swagger-validate lint-swagger` 通过，没有禁用 lint 或放宽规则。本切片还没有新增管理路由，生成检查不能代替任务 7.5 的新 API 合同验收。
- Go 单测/真实集成在当前 macOS 开发宿主执行；Linux 使用 `make lint-go` 的 Linux profile 及 `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -buildvcs=false` 交叉构建验证。不宣称 Linux 原生运行、Windows 服务端或未测试的 MySQL/MSSQL 兼容。

| 最终命令/场景 | 实际结果 | 证据 |
| --- | --- | --- |
| `go test -count=1 ./services/enterpriseauthz` | 通过，3.375s | `tmp/authz-dangling-role-green.log` |
| 13 个受影响包 `go test -p=4 -count=1` | 全部通过，不使用测试缓存 | `tmp/authz-final-unit.log` |
| PostgreSQL `go test -count=1 -run '^TestEnterpriseAuthz(Shadow\|Observation\|Policy)' ./tests/integration` | 通过，8.631s；自建数据库 cleanup exit=0 | `tmp/authz-final-pg.log` |
| SQLite 同组 integration | 通过，4.960s；PG 专属行锁/MVCC 用例明确 skip | `tmp/authz-final-sqlite.log` |
| 独立 HOME 的 `make test-backend GOTEST_FLAGS=-p=4` | 全量通过，保留合法测试缓存 | `tmp/authz-final-backend.log` |
| `go test -race -count=1 -run '^TestObservationConcurrentRequestCreatesOneOperation$' ./services/enterpriseauthz` | 通过 | `tmp/authz-final-race.log` |
| `make fmt` / `make lint-go` | 通过；Linux lint 0 issues | `tmp/authz-final-fmt.log`、`tmp/authz-final-lint.log` |
| `CGO_ENABLED=0 make generate-swagger swagger-validate lint-swagger` | 通过；生成内容无无关 diff | `tmp/authz-final-swagger.log` |
| Linux/amd64 静态交叉构建 | exit=0 | `tmp/authz-final-linux-build.log` |
| 改动 Markdown lint / `git diff --check` | 通过 | 本轮终端输出 |
| `openspec validate add-enterprise-authz-foundation-shadow --strict` | valid；apply 状态 ready，25/56 完成 | 本轮终端输出、`tmp/authz-progress-final.json` |

本轮完成任务 4.1–4.6、5.1–5.2、5.4–5.6、6.1、6.3–6.4、8.1；其余 checkbox 保持未完成。两份预存用户文档校验值保持基线一致。不把全量 backend 通过作为提案全部行为完成的依据。

### 仍必须完成

任务 7 的 API/DTO/token scopes/诊断/决策查询、任务 8 剩余读取与所有协议/写入口、跨进程 observation 传播、完整故障/隐私出口矩阵、LOGIN_ONLY/MFA 与凭据 disabled/shadow 兼容回归、运维 runbook/成套备份回退演练，以及任务 10 的完整验收仍未完成。不能据此提交、推送、归档或宣称提案实施完成。

## 2026-10-01：API/查询验收与用户批准的迁移前置失败审计

本节更新前述历史状态，不把旧的“任务 7 未接入”或 25/56 当作当前进度。当前已完成 34/57：补记经本轮独立实跑确认的 3.3、3.5、6.5、7.1–7.5，并完成用户批准新增的 8.10。任务 8.2 的读取全覆盖、跨进程传播和协议/写入 hooks 等仍未全部完成。

### 已实现与边界

- API-only system/org/repo 角色、绑定、决策查询以及 repo effective-permissions/evaluate 已接入真实路由、token read/write scopes、原生管理 authority 与 enabled gate，Swagger 覆盖 33 个 operation。普通 reader 仅自查，查询他人需管理权限；public-only token 不能读取决策历史。disabled 不先于原生 authority，诊断不冒充真实操作。修复真实 RED 发现的非法持久化 binding subject/scope 返回问题：安全 500，不输出损坏内容；合法旧 owner 失效绑定仍可列出并解绑。
- 决策查询按当前资源/owner/原生 authority 限界，支持过滤、分页最大 100、total count、历史解释及删除资源仅系统管理员可查；复用 audit 留存清理。模型/迁移测试验证完整角色 seed、索引/唯一性、重复执行、部分 seed 失败原子回滚与恢复，以及 15 张原生权限/凭据/企微状态表逐列快照不变。生命周期验证成员撤除、team-repo 解除、转移和四类对象删除，live 策略失效但留存期历史不变。
- Web/API 资源级 metadata/code 读取扩展已实跑，包括 feed、分支/提交/比较、文件及 PR 代码读取；集合入口逐资源覆盖仍需核对，8.2 不因已通过的读取子集而勾选。
- 按用户批准，API/Web/task 在目标仓库 DB 创建提交之前的迁移失败记录 `enterprise:authz:migration:failure`。归属真实本地用户；仅明确 system 来源且无用户 actor 时使用 system。owner ID 只在原生 owner 检查通过后保存。固定阶段/原因/native outcome、受信 operation ID、安全 impersonator ID；无 repo decision、candidate/mismatch/snapshot、URL、仓库名、凭据、HTTP body 或原始错误。每操作最多一条，独立操作不合并，disabled 快速退出；独立事务和 200ms 预算，故障/取消/超时只增加有界安全告警与计数，不改变原生结果。
- 独立审查发现并经真实故障测试修复：`CreateRepositoryDirectly` 可以先提交 DB，再因 Git 初始化及清理失败返回错误并留下真实仓库。创建服务现在仅为受信 migration context 注册最外层事务 after-commit 标记；外层回滚不标记，提交后不再误记前置失败，不额外查询仓库、不改原生清理。已有目标后的迁移 repo 观测、异步传播及 retry 仍待 8.8，未由此次审计替代。
- 本次审计无新增 schema、登录/callback、管理权限、API 或凭据变更；复用已有审计查询、导出和留存，不需要新增 DB/OpenFGA/Keycloak migration。未修改两份预存用户 implementation-plan/proposal-roadmap 文档。

### 测试先行与审查

- 原生 API/Web 七类前置失败在 disabled/shadow 的真实 HTTP 对比先 RED（缺少事件），接线后 GREEN：来源策略/格式、站点/镜像禁用、名称冲突、配额和 owner 拒绝。响应状态/完整 JSON 或去动态字段 HTML、repo 与 decision 数量不变。API quota 422、Web quota 403 是既有分派差异，未为统一测试修改原生逻辑。
- 无可信来源的无用户请求先 RED，修复后不能默认为 system。已有目标但创建 helper 返回错误的 task/API 残留目标测试先 RED，提交标记后 GREEN；任务 RepoID 更新失败也不误记前置失败。普通 context 的最外层提交/回滚标记以审计可见行为验证。
- fault trigger 含 secret/token/OAuth code/callback URL/手机号/邮箱/私密路径；日志、事件及导出不含原文。审计表故障不改原生 HTTP 响应；取消、超时、业务事务冲突及 disabled 无新增证据均覆盖。留存测试调用生产 cleanup，0 永久保留，非零期限清理。PG 独立事务持审计表锁验证 200ms 预算，无 sleep。
- 只读独立评审的创建提交边界问题已修复并复核，无剩余 Critical/Important/Minor；评审不替代测试，也不证明尚未接入的 hooks。

### 本轮实跑证据

PostgreSQL 使用唯一自建测试库、排他锁和 local storage；结束只清理自建数据库/临时配置并恢复预存测试配置，cleanup exit=0。未复用/重置既有治理测试库或修改其他运行服务。

| 验证 | 实际结果 | 证据 |
| --- | --- | --- |
| 迁移六类真实 integration 与 binding 损坏路由，PostgreSQL | 通过，5.029s | `tmp/authz-migration-all-pg.log` |
| 同组 SQLite | 通过，3.303s；PG 锁预算用例明确 skip | `tmp/authz-migration-all-sqlite.log` |
| 全部 `^TestEnterpriseAuthz` integration，PostgreSQL | 通过，27.967s | `tmp/authz-approved-all-integration-pg.log` |
| 全部 `^TestEnterpriseAuthz` integration，SQLite | 通过，16.166s；PG 专属 MVCC/行锁/预算明确 skip | `tmp/authz-approved-all-integration-sqlite.log` |
| 13 个受影响 Go 包 `-count=1 -p=4` | 全部通过；task 无单测文件，其真实路径由 integration 覆盖 | `tmp/authz-approved-all-unit.log` |
| PostgreSQL `TestEnterpriseAuthzFoundationMigration` | 通过，2.462s | `tmp/authz-approved-migration-schema-pg.log` |
| `CGO_ENABLED=0 make generate-swagger swagger-validate lint-swagger` | 通过 | `tmp/authz-approved-swagger.log` |
| `make fmt` / Linux profile `make lint-go` | 通过，0 issues | `tmp/authz-approved-final-lint.log` |
| Linux/amd64 `CGO_ENABLED=0 go build -buildvcs=false` | exit=0，ELF 静态二进制 | `tmp/authz-approved-linux-build.log` |
| 独立 HOME `make test-backend GOTEST_FLAGS=-p=4` | 失败：原有 `services/migrations:TestMigrateWhiteBlocklist` 公网 DNS 用例 | `tmp/authz-migration-backend.log` |
| 独立重跑 `TestMigrateWhiteBlocklist` | 同一原生 DNS 断言仍失败 | `tmp/authz-migration-native-domain-check.log` |

全量后端失败已核对：当前宿主 `gitlab.com`/`github.com` 分别解析为 `198.18.0.151`/`198.18.0.98`，触发原生本地/私有地址网络策略；测试期望公网域名可用而实际环境是 fake DNS。未修改原有测试、hosts/proxy、白名单或放宽安全策略。不能声称本轮全量 backend 通过。新增审计用例不依赖公网抓取。

测试运行宿主为 macOS，Linux 仅完成 profile lint 与交叉构建；不宣称 Linux 原生运行、Windows 服务端或未测试数据库的兼容性。Linux-only 和 callback 关闭范围保持不变。

### 收尾复验

仅同步文档后，再次运行 `go test -count=1 -run '^TestMigrationFailure' ./services/enterpriseauthz` 通过（3.388s），迁移六类 integration 在 PostgreSQL 通过（3.279s，cleanup exit=0）、SQLite 通过（2.395s）。证据分别为 `tmp/authz-migration-resumed-unit.log`、`tmp/authz-migration-resumed-pg.log`、`tmp/authz-migration-resumed-sqlite.log`。本 change 六份 Markdown lint、`git diff --check` 与 strict OpenSpec validation 通过；apply 状态 ready、34/57 完成，记录 `tmp/authz-approved-progress-final.json`。两份用户文档 SHA-256 与基线一致。

### 剩余验收

仍须完成任务 1 的全覆盖核对、6.2/6.6/6.7 的跨入口传播及完整故障/隐私矩阵、8.2–8.9 的剩余读取/全部协议与写入 hooks、9 的登录/凭据/治理兼容及 runbook/备份回退演练、10 的成套最终验收。全量回归的 DNS 环境问题尚未消除。未提交、推送或归档，不能宣称整个 proposal 已完成。

## 2026-10-01 PR 创建与评审生产接线

本节记录任务 8.5 的完整 Web/API 切片，不替代 merge/auto/force、Git HTTP/SSH、file editor、集合读取或其余管理/生命周期 hooks 的验收。

### 真实边界

- 创建在 base/target repo 记录当前原生执行人；不使用 head/fork 替代资源，不从客户端 actor/source 取值，不执行额外 Git diff 补齐条件。原生权限、事务、返回和副作用分支均不消费 candidate。
- Web/API review 创建/提交、代码评论/回复、会话解决/取消、review 删除、驳回/撤销，以及 Code/Review/DismissReview 评论的共用文本编辑/删除均已接入；deprecated 文本 API 复用同一观察。每请求/action 一条，不因多评论或内部 SubmitReview 重复计数。纯 GET、普通 discussion、review requests/assignment、viewed-files、reaction/附件管理不虚构评审提交。
- 原生 archive/admin/CanEnablePulls 拒绝点通过固定路由 metadata 观察 denied/authorization，保留实际顺序和隐私状态。guard-only lookup 使用 SQL 内 current repo/IsPull/type/index 限界的 Exists，不先加载跨仓库 review/comment 正文；SQLite 保留字 index 按仓库惯例引用。
- 未解析 Web urlencoded 表单必须支持真实 HTTP read deadline；最多 64 KiB，ID 提取、目标验证、evaluate、持久化共享 200ms。unsupported/超限/慢流仅报告安全缺口，不无界读 body。完整解析成功才清 deadline，失败保留短 deadline 避免后续 drain。路由 recorder 测试预解析表单，流能力由独立真实 HTTP server 验证，未假装 recorder 支持 TCP deadline。
- API bind malformed JSON、类型错误、缺必填字段的原生 422 在可信 actor/repo 后追加 failed/operation，不重读 body；非 PR、跨仓库及无 marker 请求不造评审记录。Issue 类 token 的文本 API 使用仅 review 的内部 action ceiling，不因此解释为 code/secret 等原生 grants。
- self-review 的 Web 200 redirect、API 422 和权限拒绝均为 denied；普通验证/存储/转换/渲染失败为 failed。head token/code 及他人 pending review 的明确权限拒绝只通过私有 typed outcome 区分：API 隐私 404 原样保留，Web POST head code 拒绝原生会被既有 JSONErrorAuto 映射成 500，也保持不变；共用 GET 不产生 mutation。不存在分支等普通 404 仍 failed，不按状态整体猜授权结果。
- 原生发生部分写入后失败不承诺回滚：第二评论存储失败保留第一评论；resolve 渲染失败保留 ResolveDoerID，终态 failed。evaluator/decision/audit 失败不回滚正常创建/评审副作用或改变拒绝响应；证据事务失败不能出现半套关联。

### 测试先行与复核

- 首轮真实 mutation RED 缺少 decision；native guard、非 PR 目标、渲染失败、跨仓库正文额外读取、Issue PAT 超出动作解释、无界表单读取等 RED 均按实际路径修复并保留回归。最新 API binding RED 为 422 零证据，privacy RED 为 head credential 的 failed 而非 denied；各自两库定向 GREEN。
- SQLite fixture 的 DELETE 不重置自增序列。切片测试仅复位四个原生 fixture 表序列，仍完整比对业务 JSON/HTML 中的 ID/链接，不通过删掉 ID 字段放宽断言。资源读取 activity 时间范围的动态时分秒按日期归一化，保留日期/正文/业务结构断言。
- 真实 HTTP 测试不启用 FullDuplex：先写 native 404 与完整正文，再观察正常/超限/慢流；同时验证正常 ID、异常 error 和客户端相同 status/body。unsupported 测试有 deadline 且 body 未被读取。SQL spy 验证额外目标查询均限定当前 repo，无跨仓库正文读取。
- 六个权限隐私分支验证 candidate allow/native denied mismatch，GET 无 mutation、缺失分支仍 failed，PR/review/comment 原生数量不变。Reviewer 角色不能绕过 self-review、非管理员 dismiss、非作者删除和 blocked user；readonly PAT/不可见资源不为观测额外取对象。
- 三表故障覆盖 Web/API 的成功创建/评审与实际拒绝，disabled 移走企业表仍正常。安全 snapshot/audit 不包含测试 secret/token/OAuth code/邮箱/私密路径。只读评审发现的 binding 和 typed deny 遗漏均已修复复核，当前无剩余 Critical/Important；评审没有代替实际测试。

### 定向实跑证据

| 验证 | 实际结果 | 证据 |
| --- | --- | --- |
| API binding malformed/required/type 与越界目标，PostgreSQL | 通过，2.469s；cleanup exit=0 | `tmp/authz-pull-binding-final-pg.log` |
| binding 与 activity 动态时分秒回归，SQLite | 通过，2.772s | `tmp/authz-pull-binding-activity-final-sqlite.log` |
| head credential/code、pending review 隐私拒绝，PostgreSQL | 通过，3.081s；cleanup exit=0 | `tmp/authz-pull-privacy-final-pg.log` |
| 同组 SQLite | 通过，4.105s | `tmp/authz-pull-privacy-final-sqlite.log` |
| 单预算 guard target 与 validation failed 单测 | 通过，3.605s | `tmp/authz-pull-rejection-unit.log` |
| 真实 HTTP body deadline/大小上限/先写原生拒绝 | 通过，4.542s | `tmp/authz-pull-body-final-native-http.log` |

### 最终批次实跑证据

最终命令串行运行数据库 integration，再运行受影响包、lint 和 build，不延长生产 200ms 预算以换取测试通过。早期与并行编译/lint 同时跑的 PG guard 请求超过预算时出现证据缺口，原生 404 保持不变；单独及最终整组重跑均通过，生产超时语义未放宽。

| 验证 | 实际结果 | 证据 |
| --- | --- | --- |
| 全部 `^TestEnterpriseAuthz` 与既有 PR create/review 相关 integration，PostgreSQL | 通过，87.053s；cleanup exit=0 | `tmp/authz-pull-verified-integration-pg.log` |
| 同组 SQLite | 通过，74.051s；PG 专属行锁/MVCC/预算用例按既有条件 skip | `tmp/authz-pull-verified-integration-sqlite.log` |
| 14 个受影响 Go 包 `-count=1 -p=4` | 全部通过 | `tmp/authz-pull-verified-unit.log` |
| `make fmt` / Linux profile `make lint-go` | 通过，0 issues | `tmp/authz-pull-verified-fmt.log`、`tmp/authz-pull-verified-lint.log` |
| `CGO_ENABLED=0 make generate-swagger swagger-validate lint-swagger` | 通过 | `tmp/authz-pull-verified-swagger.log` |
| Linux/amd64 `CGO_ENABLED=0 go build -buildvcs=false` | exit=0，ELF 静态二进制 | `tmp/authz-pull-verified-linux-build.log`、`tmp/authz-pull-verified-status.log` |
| 独立 HOME `make test-backend GOTEST_FLAGS=-p=4` | 失败：仅原有 `services/migrations:TestMigrateWhiteBlocklist` fake DNS 用例 | `tmp/authz-pull-verified-backend.log` |
| 本 change Markdown / strict OpenSpec / diff whitespace | 全部通过；apply ready，35/57 | `tmp/authz-pull-verified-markdown.log`、`tmp/authz-pull-verified-openspec.log`、`tmp/authz-pull-verified-progress.json` |

以上完成任务 8.5，当前 35/57；其余 22 项未由本切片自动勾选。测试宿主为 macOS，Linux 仅完成 profile lint/交叉 build，不宣称 Linux native runtime 或未测试 DB 兼容。callback 关闭、Linux-only、不改两份用户文档的约束保持不变。全量 backend 复验仍仅失败于原有 DNS 用例：gitlab.com/github.com 当前分别解析到 198.18.0.151/198.18.0.98（`tmp/authz-pull-verified-dns.log`），触发原生私有地址防护。未改测试、hosts/proxy、白名单或放宽网络策略，不宣称全量 backend 通过。未提交、推送、归档。

### 剩余工作

任务 1 的完整入口/失败验收基线、6 的跨进程传播/完整隐私和故障矩阵、8.2 的集合读取核对、8.3/8.4 的 Git HTTP/SSH/file editor/receive hooks、8.6 的 merge/auto/force、8.7/8.8 的设置及目标已存在的迁移/生命周期、8.9 的跨入口故障总矩阵、9 的 LOGIN_ONLY/凭据/治理回归与 runbook/备份回退演练、10 的最终全套验收仍待完成。提案没有整体完成。

收尾仅更新验证文档后再次通过 Markdown lint、strict OpenSpec、`git diff --check`；两份预存用户文档 SHA-256 与基线一致。任务 8.5 的代码不再变更，最终批次证据仍对应当前实现。

## 2026-10-01 合并与集合读取续作

- 合并接入 Web/API/auto/force/manual 真实路径：handler 在 CheckPullMergeable 前捕获，shared Merge/MergedManually 在释放原生锁后填终态；排队只记录 unknown，不当作已合并。auto 使用 ScheduledAutoMerge 的真实 doer 和既有 permission。
- DetachedObservationContext 只复制 operation、精确 actor/repo/action 绑定与安全审计 attribution，不传播取消、deadline、业务 TX 或任意权限上下文。相同 router/service 操作只提交一次，错误 actor 不能结束别人的 observation。
- required-check/admin/force 拒绝、原生白名单 candidate deny/native success、排队/格式/实际 service 失败、可见归档拒绝，以及 evaluator/decision/audit 三种故障已有真实路径测试。API 归档先被 CanEnablePulls 拒绝为原生 404，不改守卫顺序制造 423。
- 资源级读取之外新增 Web/API 实际列表、org/team 结果、星标/订阅、explore metadata/code search、profile README 与 milestones 结果观测。集合用当前执行人 GetDoerRepoPermission，而不是被查看用户的权限；逐实际结果捕获，code search 去重，README 在读取并渲染后才记录 success。
- 组织 metadata 入口的 read:organization-only token 原生可返回 200，内部 ceiling 仅 ViewMetadata，不映射 read_code/clone。team 单资源缺记录先 RED，再复用集合 observer 修复；用户 repository/starred 原生另外要求 Repository scope，未为测试放宽原生路由。
- 权限解析、评估与证据共享 200ms；disabled 不调用 resolver；纯读取不进入原生授权分支或事务。真实 JSON/HTML/分页/count/部分原生副作用对比保持一致。

本轮真实证据（macOS 宿主，隔离 PostgreSQL 与 SQLite；不宣称 Linux native runtime）：

| 命令/范围 | 结果 | 日志 |
| --- | --- | --- |
| merge 第一组前置拒绝 RED | 缺少记录，符合预期失败 | `tmp/authz-merge-precheck-red.log` |
| detached context attribution RED → GREEN | impersonator 缺失后修复，通过 | `tmp/authz-merge-attribution-red.log`、`tmp/authz-merge-attribution-green.log` |
| 完整 merge PostgreSQL | 52.708s，通过，cleanup 0 | `tmp/authz-merge-verified-pg.log` |
| 完整 merge SQLite | 47.860s，通过 | `tmp/authz-merge-verified-sqlite.log` |
| 合并受影响 7 个包 | 通过 | `tmp/authz-merge-unit-final.log` |
| 集合权限解析预算单测 RED → GREEN | API 不存在编译失败后接线通过 | `tmp/authz-collection-budget-red.log`、`tmp/authz-collection-unit.log` |
| 集合/profile PostgreSQL | 11.293s，通过，cleanup 0 | `tmp/authz-collection-profile-green.log` |
| 全局 code search PostgreSQL | 3.793s，通过，cleanup 0 | `tmp/authz-global-code-search.log` |
| 组织 scope 与集合故障 PostgreSQL | 4.477s，通过，cleanup 0 | `tmp/authz-collection-scope-green.log` |
| 全部读取族与 merge PostgreSQL | 73.826s，通过，cleanup 0 | `tmp/authz-reads-merge-pg.log` |

此前 collection 测试错误使用不足原生 scope 的 token，原生 403 正确；测试已按真实路由分派修正，未改 scope 检查。make fmt 已运行，最近 Linux profile lint 报一项新增测试 wastedassign，已改为未初始化声明，仍待最终 lint 复验。合并切片完成任务 8.6；盘点文件已覆盖全部指定生产函数/身份/事务/测试边界，完成 1.3。集合 8.2 仍在整组 SQLite 与独立复核收尾；Git 8.3 已开始，不据此勾选。

## 2026-10-01 读取全矩阵与 clone/fetch 验收

- Git HTTP 仅实际 upload-pack RPC 记录 clone，info-refs/不可见资源/wiki 不虚构 clone。原生命令及 stdin/stdout 复制完成才 success/transport，原生执行失败为 failed；不把 HTTP 开始写 200 等同客户端收齐数据。
- SSH 在 ServCommand 完成真实 user/deploy-key 归属与原生 guard 后记录 unknown/authorization，实际子进程的传输终态未跨进程上报，不能将授权 200 冒充 pack 成功。真实内置 SSH user-key clone/fetch 已在 disabled/shadow 对比；吊销 key 后认证失败且不造决策。
- 覆盖匿名、密码、PAT、Git HTTP deploy token、SSH user/deploy key；安全引用为 ID，不保存 token/key。HTTP/SSH evaluator、decision、audit 故障均不改变原生 RPC/ServCommand 结果，无 decision/audit 半关联。
- 独立复核发现公开 Git HTTP 原生匿名 fallback 允许 user-only PAT 读取，而真实 credential ceiling Read=false。补真实 RED 后修复观测的静默 early-return：仍要求原生已安全解析且可见的 permission，但允许记录 credential deny/native success；evaluator 不读策略，不增加 action 或修改凭据 scope。不可见目标、guard 目标解析的凭据 gate、disabled 与业务 TX 限制保持。独立复核无剩余 Critical/Important/Minor。

| 验证范围 | 真实结果 | 日志 |
| --- | --- | --- |
| public narrow PAT RED | 原生 200，缺少一条记录，预期失败 | `tmp/authz-git-public-ceiling-red.log` |
| narrow ceiling 原生 fallback 单测 | 3.221s，通过；binding 表不可用仍无需角色读取 | `tmp/authz-git-ceiling-unit.log` |
| HTTP/SSH Git 初组及故障 | PostgreSQL 3.463s，通过，cleanup 0 | `tmp/authz-git-ceiling-green.log` |
| 真实 SSH clone/fetch、吊销、SSH 故障 | PostgreSQL 4.404s，通过，cleanup 0 | `tmp/authz-ssh-read-extended.log` |
| 全部读取、merge、HTTP/SSH clone/fetch/fault | PostgreSQL 81.125s，通过，cleanup 0 | `tmp/authz-reading-final-pg.log` |
| 同组 | SQLite 68.915s，通过 | `tmp/authz-reading-final-sqlite.log` |
| make fmt | 退出 0 | `tmp/authz-read-final-fmt.log` |
| make lint-go（Linux profile） | 0 issues，退出 0 | `tmp/authz-read-final-lint.log` |
| 受影响 13 个包 | 全部通过或无测试文件 | `tmp/authz-read-final-unit.log` |

以上完成 8.2/8.3；目前 39/57。此后的分支/file editor 新代码仍在逐片实施，需另行 fmt/lint/全矩阵验收，不能用上述 lint 为后续修改背书。Docker Linux engine 已实际确认可用，但尚未运行此组 Linux native 验收；上述 integration 宿主为 macOS。callback 关闭、Linux-only、不提交/推送/归档保持。

## 2026-10-01 分支跨进程与管理设置续作

本轮以真实 RED→GREEN 补齐设置入口，原生权限/状态码/响应/副作用不变。

- 不同 branch 的 bound Push 只在 exact ref 复用；其它 ref 保留受信 source/ceiling、同 operation 但不同 observation。fork MergeUpstream 的 fast-forward 与 fallback pull.Update 复用实际 Push，不增加虚假 Merge。
- Web/API 分支保护与 required-check、webhook、Actions/CI、secret 接入实际 mutation 和安全前置拒绝。required-check 单独 ManageCI 子记录，普通高级 Wiki/PR 设置不是 CI。runner 跨 scope 和 required scoped workflow 明确拒绝记 denied，普通不存在仍 failed。webhook test/replay 不是管理 action，包含其拒绝路径也不造管理记录。
- disabled 不新增记录；每次真实写入按 action 一次，shared helper 不重复计数；Web 200/303 需要实际成功标记，不能把 validation redirect 当成功。secret/webhook/variable 自由值不进入 authz evidence。
- API webhook-disabled、runner mutation marker、非 CI advanced 设置、runner/required scoped workflow outcome、webhook test/replay 分类均有真实 RED。独立只读复核已闭环前四项，最后 marker 范围亦经独立只读复核闭环，无剩余 Critical/Important。

| 验证 | 实际结果 | 日志 |
| --- | --- | --- |
| exact-ref 去重单测 | RED→GREEN，3.241s | `tmp/authz-different-refs-red.log`、`tmp/authz-different-refs-green.log` |
| fork 同步真实 Web/API 路径 | PostgreSQL RED→GREEN，21.662s，cleanup 0 | `tmp/authz-upstream-red.log`、`tmp/authz-upstream-green.log` |
| Advanced 非 CI 分类 | PostgreSQL RED→GREEN，3.928s，cleanup 0 | `tmp/authz-advanced-not-ci-red.log`、`tmp/authz-advanced-not-ci-green.log` |
| 明确 runner/scoped workflow 拒绝 | PostgreSQL RED→GREEN，4.387s，cleanup 0 | `tmp/authz-settings-outcome-red.log`、`tmp/authz-settings-outcome-green.log` |
| webhook test/replay 分类 | RED 出现 3 条假管理记录，整组 GREEN 不再记录 | `tmp/authz-webhook-execution-red.log`、`tmp/authz-settings-final-pg.log` |
| 全部设置/故障/原生 WorkflowApi 回归 | PostgreSQL 10.788s，通过，cleanup 0 | `tmp/authz-settings-final-pg.log` |
| 同组 | SQLite 12.057s，通过 | `tmp/authz-settings-final-sqlite.log` |
| make fmt | 退出 0 | `tmp/authz-settings-final-fmt.log` |
| make lint-go，Linux profile | 0 issues，退出 0 | `tmp/authz-settings-final-lint.log` |

上述 integration 宿主仍为 macOS，不宣称已执行 Linux native runtime。receive/file 分支代码仍需完整 8.4 验收；新 CLI 还需重建后重跑真实 Git。8.8/8.9/9/10 仍待完成。两份用户文档尚未修改，不提交、推送或归档。

受影响 11 个 Go 包已实际 `go test -count=1 -p=4` 通过或无测试文件，日志 `tmp/authz-settings-final-unit.log`。独立复核包括 hook marker 范围闭环，无剩余 Critical/Important。设置切片完成 8.7，进度 40/57；仍有 17 项，提案未整体完成。

## 2026-10-01 生命周期与迁移交付验收

- archive/transfer/delete 捕获旧 owner/归档状态，释放业务锁/提交或回滚业务事务后独立保存证据。转移开始待接收为 unknown；接收使用本次真实 actor，旧 owner 策略快照与安全 target owner ID 不被新 owner 覆盖。原生 Admin 可删除但 candidate deny 的场景已在原 TestAPIRepositoryDelete 增量回归。
- API/Web 前置可见拒绝与 mirror/确认失败保持原状态码。真实 HTTP 动态表单/JSON 解析要求 read deadline、64 KiB，与评估和持久化共享 200ms；不支持则只报告缺口，不强读正文。通用 PATCH Archived/HasActions 各为独立 action，同 operation 不同 observation。
- 迁移队列在真实目标 ID 建立后记录 unknown，内部任务 payload 保存有界签名 operation ticket。恢复仅原子更新原记录/native audit，不重新评估；retry 使用新 operation；旧任务在执行前捕获 system 快照。uploader 完成不代表 task 已完成；最终任务状态提交失败记录 failed。来源策略拒绝为 denied/migration。
- API 同步迁移保留原 HammerContext/native panic 清理行为。直接迁移只在本地真实目标创建后观察；创建 DB 提交但 Git 初始化失败的外层不伪造前置失败，依照 delta spec 的专门场景保留受信 after-commit 标记。客户端公开 DTO 不接受 queue ticket。
- evaluator/decision/audit 故障保持原生结果，无决策与审计半关联。回滚、删除历史、角色变更历史解释、200ms、64 KiB、取消、日志告警/计数和 secret/token/OAuth code/callback URL/手机号/邮箱/私密路径各出口由核心单测与 API 集成覆盖。

| 验证 | 实际结果 | 日志 |
| --- | --- | --- |
| 生命周期/迁移/历史/原生 Delete/Transfer 全组 | PostgreSQL 33.436s 通过，cleanup 0 | `tmp/authz-lifecycle-migration-verified-pg.log` |
| 同组 | SQLite 28.061s 通过 | `tmp/authz-lifecycle-migration-verified-sqlite.log` |
| 生命周期/迁移与受影响 11 包单测 | 全部通过或无测试文件 | `tmp/authz-latest-unit.log` |
| 核心证据/隐私/留存与分支新增受影响 11 包 | 全部通过或无测试文件 | `tmp/authz-branch-unit.log` |
| 真实入队/API/直接目标/恢复/重试 | 先缺记录或终态错误 RED，再 GREEN | `tmp/authz-migrate-target-red.log`、`tmp/authz-api-migrate-target-red.log`、`tmp/authz-direct-migrate-red.log`、`tmp/authz-migrate-ready-red.log`、`tmp/authz-migrate-retry-red.log`、`tmp/authz-migrate-recovery-green.log` |
| 最终 task 失败及 12 个证据故障组合 | PostgreSQL 10.419s 通过 | `tmp/authz-migrate-fault-full-pg.log` |
| 已有目标来源拒绝 | 原 task failed 分类 RED，修复为 denied 后整组通过 | `tmp/authz-migrate-source-denied-red.log`、`tmp/authz-lifecycle-migration-verified-pg.log` |

本切片完成 6.6、6.7、8.8，不替代 8.4/8.9/9/10 的剩余验收。上述集成宿主是 macOS；Linux native 验收尚在准备，不将交叉编译称为运行通过。

## 2026-10-01 设置部分成功与兼容回归续作

- API repo PATCH HasActions 的实际 unit 持久化接入 ManageCI，不以普通 metadata/Wiki/PR 配置冒充 CI。审阅发现多 action 请求先持久化 CI 再被 mirror archive 拒绝会污染 CI 终态；真实 RED 后让 action-specific 持久化成功保持 success，同操作 archive 单独 denied，保留原生 422 和已发生的 CI 副作用。
- 复用既有 LOGIN_ONLY、token/SSH 账号状态、保护管理员、只读 UI、组织审批/private/quota、受管 team 测试，在 disabled/shadow 下保留全部原断言。既有 Web 管理员目标保护测试的登录人需要真实 bound 管理 authority 才能到达目标 guard；补齐可信第二管理员 fixture，不放宽原生前置 guard，也不改目标保护断言。
- 独立 credential 旧 callback fixture 不代表启用生产 callback；生产仍采用登录刷新 + 定时完整同步，callback 保持关闭。

| 验证 | 实际结果 | 日志 |
| --- | --- | --- |
| API CI+archive 部分成功 | 缺 CI success 的真实 RED → GREEN | `tmp/authz-partial-settings-red.log`、`tmp/authz-compat-settings-green-pg.log` |
| LOGIN_ONLY/凭据/治理双模式及设置全组 | PostgreSQL 13.247s 通过，cleanup 0 | `tmp/authz-compat-settings-green-pg.log` |
| AGit 真实 reader 创建 PR/更新现有 PR | 缺 CreatePullRequest RED → GREEN，8.458s | `tmp/authz-agit-red.log`、`tmp/authz-agit-green.log` |
| API branch rename/update/delete | 缺四条观察 RED → GREEN，7.732s | `tmp/authz-branch-refs-red.log`、`tmp/authz-branch-refs-green.log` |
| Web branch restore、Web/API writer 拒绝 | 分别缺记录 RED → 三组 GREEN，14.604s | `tmp/authz-web-refs-red.log`、`tmp/authz-web-ref-guard-red.log`、`tmp/authz-branch-refs-all-green.log` |

设置与兼容 SQLite 复验、Linux native 运行、完整分支协议/故障矩阵仍在推进；不得将本段视作全部完成。

## 2026-10-01：入口最终复核与 Linux 兼容性

- Linux 实跑环境为 Docker Desktop 的 Linux/amd64 容器（ARM64 宿主上的模拟执行，不宣称原生 ARM64）；非 root uid 1000、Git 2.39.5、Go 1.27.1 构建的静态 ELF。LOGIN_ONLY integration/smoke、账号状态 SSH/PAT/Git HTTP 和企微治理 disabled/shadow 两模式均通过，`tmp/authz-linux-native-compat.log` 为真实输出。首次 root 启动被原生安全守卫拒绝；随后容器 overlay 无空间，改用仓库内独立 TMPDIR 后通过，不修改守卫或清理用户 Docker 数据。
- 真实 HTTP/SSH receive 已覆盖创建/更新、多 branch ref、tag 排除、删除与默认分支删除拒绝；同 operation 各 ref 的 observation ID 独立。Synthetic Actions scopes/cross-repo、deploy key 读写和 deploy token 吊销双模式在 PostgreSQL/SQLite 通过。原测试用 `t.Name()` 生成分支，嵌套后超出原生长度，改为有界 SHA256 名称，未改原生验证。
- AGit 新建 PR 仅记录 CreatePullRequest；更新既有 PR 不虚构创建/普通分支 push。AGit 前置拒绝真 RED（expected 1 / actual 0）后补只观察的 denied/pre_receive；private topic/ref 不进入快照。
- API mirror Delete/Update/Rename 早拒绝真 RED（expected 3 / actual 0）后补固定 action marker 观察，原生 403 不变。fork base 不可读真 RED 后补 fork 目标观察，不记录不可见 base；无推送 up-to-date 为 unknown。
- 独立审阅发现 ff_only 将真实 hook ErrPushRejected 替换为原生参数错误，原观察误标 failed。保护分支 ff_only 回归先 RED 后只保留观测拒绝标记，原生 HTTP 400 不变；普通分叉错误仍 failed。
- 分支/editor/实际 receive/AGit 的 evaluator/decision/audit 三类故障双模式验证 PostgreSQL 通过（24.484s）；SQLite 分支、Web/API CODEOWNERS、synthetic、receive 和 fork 入口组合通过（81.531s）。测试不使用行数作为 observation 自增 ID；SQLite fixture 不重置 decision sequence，改按实际最大 ID 筛选。
- 全量 PostgreSQL 首跑 242.065s 仅 `TestEnterpriseAuthzShadowPullPrivacyDenials` 失败：其“六条 mutation denied”查询同时包含后来接入的 read_code denied。将查询明确限定 Create/Review 两 mutation action，原有每请求数量、响应相等、无副作用及隐私断言保持；不是删掉真实读取观察。
- 最终独立审阅发现真实 hook/queued migration 的 SHA256 observation ID 被 API DTO 的随机 26 字符 ID 校验拒绝。`TestDecisionDTOProtocolObservationID` 真 RED `policy_storage_failed` 后，ObservationID 精确增加 64 字符小写十六进制格式，OperationID 仍严格 26 字符 base32；unit GREEN，receive list/detail 已增加真实回归。不接受任意正文或敏感字符串。

## 2026-10-01：完整 Linux/PostgreSQL 升级、关闭/恢复及旧版回退演练

隔离 Linux/amd64 容器使用非 root uid 1000，专属且事前不存在的 `gitea_authz_rollback_<pid>_<time>` PostgreSQL 库、独立 work/storage/config。旧二进制从 HEAD `419abc7edccf19508727be363b1e8f60706903b6` 的只读 archive 在仓库 tmp 构建，新二进制来自当前工作树；未改任何 Git 状态或用户 Docker 数据。

实际执行旧版 migrate（schema version 361）、CLI 创建原生管理员、旧 Web API 创建并初始化 Git 仓库后，停进程并 `pg_dump -Fc` 全库、备份完整配置/存储与旧版二进制。新版本正式 migrate 至 version 362，八内置角色/68 权限、无自动绑定，真实 Web API 读取产生决策，并经原生 authority 创建自定义 role。native access/collaboration/team/org/SSH/token/企微身份和 authority 摘要未被升级改写。

随后真实停/启 Linux CLI Web 进程进行 shadow enabled→disabled→enabled：关闭时同原生 repo GET 成功、新增决策为零、authz 管理 API 404，role ID/revision 不变；恢复后真实读取有新决策、旧 role/revision 可查询。旧二进制对新 schema 的 migrate 真实拒绝，不修改 version 欺骗保护。

备份事故现场、停止全部本次进程，删除并重建**仅本次专属库**，向空库用 `pg_restore --single-transaction` 成套恢复旧全库/配置/Git/LFS/附件存储和旧版二进制。全部表数据摘要、列/索引/约束/sequence、配置及所有非运行日志文件摘要一致，schema version 恢复 361、新 authz 表不存在；旧版 CLI user list 和原生 Web repo GET 再次通过。专属库 finally 清理成功。

实跑输出 `tmp/authz-linux-rollback-drill.log` 与受限备份目录 `tmp/authz-rollback-backup/evidence.json`；只报告非敏感摘要，不导出密码/config 内凭据或 dump。此为真实完整成套恢复演练，不是仅授权表备份、改 version、模拟开关或旧版读取新库；不代表生产恢复审批及真实企微 callback gate 已通过。

最终检查阶段 `make fmt`、Linux profile `make lint-go`、`generate-swagger swagger-validate lint-swagger`、Linux 旧/新二进制与测试 ELF 构建均真实通过。独立审閱指出的 DTO 协议 ID、mirror 早拒绝、ff_only 真实 hook 拒绝已修复；对应 PostgreSQL 复核组 24.917s 通过（`tmp/authz-review-fixes-pg.log`）。

## 2026-10-01：最终后端测试与外部 DNS 限制

`make test-backend GOTEST_FLAGS=-p=4` 已完整运行。唯一失败为 `services/migrations:TestMigrateWhiteBlocklist`：当前网络 DNS 将 github.com/gitlab.com 解析为 `198.18.0.0/15` benchmark 地址，原生迁移安全检查拒绝。相同未修改的 HEAD archive 中单独运行原测试亦失败（`tmp/authz-final-original-whiteblocklist.log`），Linux 容器显式 DNS 查询同样返回该网段，证明不是本 proposal 回归。未改 hosts/DNS 系统配置、原生网络安全策略或测试断言，不宣称全仓后端测试全绿。

`tmp/authz-final-full-backend.log` 保存完整结果，`tmp/authz-final-targeted-unit.log` 的 16 个受影响包全部通过或明确无测试；涵盖 core/model/module/DTO/common/branch/files/AGit/private/Web/API/setting/audit/pull/task。此测试为 macOS 开发验证；Linux 实际运行与 PostgreSQL 成套升级/恢复另有独立证据，不将交叉编译或 SQLite 单测冒充 Linux/PostgreSQL 实跑。

`make fmt`、Linux profile `make lint-go`、Swagger 生成/验证/lint、15 个改动 Markdown lint 均通过；无 go.mod/go.sum、JS/CSS 或 HTML template 修改，只有生成 Swagger JSON，因此不运行无关 tidy/前端 lint。`git diff --check` 无错误。

企业授权 implementation-plan/roadmap 仅追加实际状态；原始内容 SHA256 分别保持 `84a9f45ef63ec4b2474556678bee1dfae7acdf83deb3e1e24b9387bd386c333f` 与 `6191672d6dbe9f605ae9819988a0f34c98516501743ae6fd56a46aaec6918a75`（追加前缀核验）。保留已有未来阶段原文，不把 enforce/feature/merge gate 宣称已交付。

## 2026-10-01：最终 Linux/PostgreSQL 全量真实入口矩阵

当前代码构建的 Linux/amd64 ELF 在非 root Linux 容器中，运行完整 `^TestEnterpriseAuthz|^TestRepoMergeUpstream$` 选择器，真实 PostgreSQL 独立测试库全部 PASS（`tmp/authz-final-linux-pg.log`）；包括 management/diagnostic/history、版本竞争与引用锁、一致快照、回滚、普通/保护/多-ref/tag HTTP/SSH、AGit HTTP/SSH、editor/CODEOWNERS、Web/API/auto/force/manual merge、设置、同步/异步/创建前迁移、转移/归档/删除及每类 evaluator/decision/audit 故障与 LOGIN_ONLY/凭据/治理兼容。

测试库事前核验不存在，finally 删除成功；原生测试入口要求 DB 名含 test，首次未满足命名安全守卫时立即拒绝，改专属名称后完整通过，没有削弱守卫。测试 TMPDIR/work/config/storage 均为仓库内独立副本，不改用户服务或共享库；Linux 是 ARM64 宿主上实际运行的模拟 amd64，不宣称原生 ARM64/Windows 验收。

最终源码清单逐条核对 19 action、8 内置角色、3 scope/3 subject、allow-only、18 个真实操作 action 的 service/hook 和受权查询；唯一无产品入口的 feature grant 明确 Observed=false/仅诊断。独立审阅 Critical 未发现、Important 三类（mirror/ff_only/协议 ID）均修复并复核关闭；未对预存企微变更或后续 enforce 做越界验收。

## 2026-10-01：末轮分支失败边界与历史留存核对

- `TestEnterpriseAuthzAPIMirrorBranchGuards` 扩展为 Create/Delete/Update/Rename 四请求，真 RED expected 4 / actual 5，确认 Create 的已存在 defer 与新增未知 branch marker 重复。仅去掉 Create 的重复 marker，原 403 不变，defer 保存一条 denied/operation；其余三者仍在原生拒绝边界保存 denied/authorization。
- `TestEnterpriseAuthzAPIEmptyBranchFailures` 四请求真 RED expected 4 / actual 1；Delete/Update/Rename 原空仓库 404 后补只观察的 failed/operation，Create 保留已有 defer。四请求响应正文与原状态不变，disabled 零记录。
- 独立审阅补充 Delete service 前 Count/Sync 失败缺口。`TestEnterpriseAuthzAPIDeleteBranchPreparationFailures` 用只针对 branch SELECT 的有界 ORM hook，两个失败阶段真 RED expected 1 / actual 0；仅在原 APIErrorInternal 后补 failed/operation，500 与 disabled/shadow body 完全一致，不进入 service、不重复。三组 PostgreSQL GREEN 4.201s（`tmp/authz-branch-preparation-green.log`）；审阅确认 Critical/Important 均已关闭。
- 留存边界按已批准 delta spec 的“原有 repo 操作”与独立“共同留存”两要求核对：disabled 的零企业读取约束属于请求观察器；独立 audit cron 仍共同清理到期旧 decision/audit，不加载角色、不评估、不写新决策。design/runbook 明确这一区分，未改变清理行为。现有永久保留/1000 条分批清理测试显式固定 Enabled=false，防止全局设置污染。独立审阅确认无代码或规范冲突；没有用户要求独立 cron 全系统零 SQL 的原文证据。

末轮重新构建及全量验证结果在以下最终验收段记录，不以此前编译或审阅结论冒充最后代码的测试。

## 2026-10-01：最终验收与交付状态

最终 Go 修改完成后，重新执行全部 gates、受影响包与两数据库真实入口矩阵，实际退出码全部为 0：

| 验证 | 实际结果与证据 |
| --- | --- |
| 格式与 Go lint | `make fmt`、Linux profile `make lint-go` 通过，0 issues；`tmp/authz-final-fmt.log`、`tmp/authz-final-lint.log` |
| Swagger | `make generate-swagger swagger-validate lint-swagger` 通过；`tmp/authz-final-swagger.log` |
| Linux 构建 | 当前服务端与 integration ELF、旧版恢复二进制均构建成功；`tmp/authz-final-build-gates.log` |
| 受影响包 | 16 包完整测试：15 包通过，task 明确无测试；`tmp/authz-final-targeted-unit.log` |
| Linux/PostgreSQL 全量 | 最终 ELF 运行完整 `^TestEnterpriseAuthz\|^TestRepoMergeUpstream$`，PASS，独占测试库清理 0；`tmp/authz-final-linux-pg.log` |
| SQLite 全量补充 | 最终代码运行相同完整选择器通过；`tmp/authz-final-all-sqlite.log` |
| PostgreSQL 正式迁移 | 最终代码 `TestEnterpriseAuthzFoundationMigration` 通过，包含旧数据保持、部分 seed 回滚/重试、完整八角色/68 权限及索引约束；独占测试库清理 0，`tmp/authz-final-migration-pg.log` |
| 完整旧版回退 | 真实 Linux/PostgreSQL 成套全库、配置、二进制和 Git/LFS/附件备份及恢复通过；上文 drill 证据，不是只恢复授权表 |
| 文档与规范 | 15 个变动 Markdown lint、OpenSpec strict validation、`git diff --check` 通过；用户原文两文档前缀 SHA256 保持 |

逐条核对 delta spec 与 tasks：19 个 action、八不可变内置角色、三主体/三作用域、allow-only 条件、凭据感知候选授权、原生管理 authority、角色版本/引用锁、一致读、原子管理审计、独立 shadow 证据、分页与留存、隐私/200ms/大小限制、18 个实际操作入口及逐类故障、迁移前置安全审计、LOGIN_ONLY/凭据/企微治理兼容均有实现及真实验证。末轮镜像/空仓库/Count/Sync、协议 ID 和 ff_only 补丁由独立审阅关闭；生产新增 Go 无 TODO/mock/placeholder 或 enforce 实现，75 个新 Go 文件当年 header 检查通过，无 go.mod/go.sum、JS/CSS/HTML template 变动。

**实施任务 57/57 完成。** 保持 shadow-only、Linux-only 和 callback 关闭；feature grant 仅目录/诊断，未来 enforce/merge gate/UI/offboarding 不在本提案。未提交、推送、创建 PR 或归档；保留预存用户修改。

唯一全仓测试限制仍是已记录的 `services/migrations:TestMigrateWhiteBlocklist` 外部 DNS 问题，相同旧版 HEAD 亦失败；未修改网络安全校验或测试，不宣称全仓后端全绿。未宣称 Windows、其他数据库、原生 ARM64、生产容量/SLA 或真实 callback gate 已验收；这些不是本 change 的缺失实现要求。
