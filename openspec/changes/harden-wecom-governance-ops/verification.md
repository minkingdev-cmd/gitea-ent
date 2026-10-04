# 实施与验收记录

## 状态与边界

OpenSpec apply 当前为 **47/49**，剩余 2 项保留未勾选；不归档。

2026-09-30 最新范围决定：服务端永久仅部署 Linux，Windows 服务端及其原生 SSPI 测试不属于支持或验收范围，不再等待 Windows runner，也不阻塞后续 shadow 实施。下文 Windows 缺口描述保留为历史证据，不代表当前验收要求，范围调整不代表补跑通过。用户同时确认采用登录管理员权限刷新 + 定时完整同步、callback 保持关闭；真实 callback 协议证据仅作为独立启用 gate。本次仅同步文档，不新增运行验证或勾选前置任务。

2026-09-30 用户明确当前系统仅需 PostgreSQL；本次同步 proposal/design/tasks/runbook 的数据库范围，MySQL/MSSQL 不再是适配或验收要求。保留 Gitea 通用数据库分支与 SQLite 快速测试，不将范围调整描述为其他数据库已通过。

已落地显式组织/quota、generated 来源迁移、统一原子发布与 DB lease/fencing、默认关闭的加密 callback、持久 receipt/worker、mapping GET/410 契约、证据脱敏和上线恢复 runbook。

本记录是实施证据，不代表生产上线批准、真实应用 callback 联调或全部操作系统验收。未提交、推送或归档；保留用户预存路线图链接和空行变更，仅在既有实施说明中更新过时治理契约，未修改路线图文件。

## 实际复现与修复

以下用例先在原实现观察到失败，再在修复后通过；日志保存在仓库忽略的 `tmp/` 中：

- authority 失败前候选目录已经改变 protected identity；unsupported authority 被当作成功继续发布。
- 超管标签缺失、provider 响应缺失/null `errcode`，被错误当成成功空来源。
- 其他应用 team-admin 被 planner 使用、共享 provenance 的原生成员被删除。
- nested transaction 错误被调用方忽略后，outer commit 仍成功。
- 另一应用的 callback receipt 被领取并标记失败。
- 同秒登录 run ID 冲突；刷新失败后缓存管理员仍在事务外晋升；public promotion 绕过已有 writer lease。
- legacy malformed body 在 guard 后得到 422 而不是 410；读取混入 legacy/其他作用域。
- quota 业务拒绝在 Web 创建/fork/template 入口返回 500 而不是 403。
- callback 的原生 access log 模板泄露 query/header/form；现在只在日志副本中清除敏感请求信息，不改变实际 verifier 请求。

后期故障矩阵增加 6 个 SQLite 写入触发器、8 个取数/取消/fencing/目标场景及正常发布对照；逐表比较 21 表授权快照、旧成功 run 和 published revision。严格 audit 已并行实现，没有所有触发器的修复前 RED 证据，不能将测试编写过程的失败当作生产回归复现。

PostgreSQL 使用 deferred constraint trigger 在最终 commit 才抛错，验证候选空来源的全部写入及 success 证据回滚、独立 failed run 留存、21 表状态和旧 revision 不变。

## 验证命令与结果

所有 Go 命令设置 `GOCACHE=$PWD/tmp/go-build`，lint 设置 `GOLANGCI_LINT_CACHE=$PWD/tmp/golangci-lint`，避免写入宿主不可写缓存。

| 验证 | 实际结果 |
| --- | --- |
| `make help`；相关开发/测试及企业授权文档 | 已检查 |
| `go test -count=1 ./models/...` | 全部 model packages 通过，含 native auth/user/org/repo、DB context、enterprise models |
| `go test -count=1 ./services/enterprisewecom ./modelmigration/v28 ./services/org ./services/repository ./modules/setting ./services/audit ./services/cron ./routers/common ./routers/web ./modules/web/routing ./services/context` | 全部通过；格式化后再复跑核心 6 包通过 |
| `go test -count=1 ./services/auth ./services/auth/source/oauth2 ./services/externalaccount ./routers/web/auth` | 分两次命令执行，全部通过 |
| scoped `go test -race -count=3` | receipt 并发、worker、候选故障、quota 最后额度、登录/authority/promotion 通过 |
| SQLite 企业集成、native key/token scope 回归 | 通过，6.635 秒；含合法 WeCom OAuth MFA、无会话 callback、四状态真实 SSH/PAT/Git HTTP 与吊销 |
| PostgreSQL 企业集成 | 通过，10.096 秒；含 lease/fencing/recovery、receipt 并发去重/领取、quota 争用、最终 commit 故障、MFA 和 SSH 兼容 |
| migration v360 SQLite 与 PostgreSQL | 均通过；重复执行、唯一与歧义来源、native 管理员/成员保留、历史脱敏、索引扩展 |
| `make fmt` / `make lint-go` | 通过；macOS linker 的已知 `-bind_at_load` warning 不被当作测试成功证据 |
| `GOOS=windows TAGS=gogit golangci-lint run --build-tags windows,gogit` | 0 issues，仅静态检查，不代表 Windows SSPI 实跑 |
| `CGO_ENABLED=0 make generate-swagger`、`make swagger-validate`、`make lint-swagger` | 均通过 |
| 改动 Markdown 的 `pnpm exec markdownlint`、`git diff --check`、`openspec validate harden-wecom-governance-ops --strict` | 均通过 |

SQLite 集成命令：

```sh
go test -count=1 -tags 'sqlite sqlite_unlock_notify' \
  -run '^(TestEnterpriseWeCom.*|TestAPIEnterpriseWeCom.*|TestAPI(AdminCreateAndDeleteSSHKey|CreateAndDeleteToken|CreateTokenScopeEscalation|DeniesPermissionBasedOnTokenScope|TokenSelfService))$' \
  ./tests/integration/
```

PostgreSQL 验证使用本次专属隔离测试库，localhost trust、显式 `postgres` 测试用户和仓库 `tmp/` work path，不修改服务配置或其他数据库。默认 PostgreSQL 模板依赖共享 MinIO；为避免触及既有 bucket，本次临时复制模板只将 storage 切换为 local。临时模板和生成配置已删除，专属库经迁移测试清理后查询确认不存在。

PostgreSQL 全部企业集成筛选为 `^(TestEnterpriseWeCom.*|TestAPIEnterpriseWeCom.*)$`；migration 单测另以真实 PostgreSQL 环境运行。普通 `unittest.MainTest` 仍使用 SQLite，不能把其环境变量变更误报为跨 DB 单测。

首次 PostgreSQL 广泛回归暴露既有测试 OAuth source 名称超过 native `external_login_user.provider` 的 25 字符限制；仅将 fixture 改为短名称后完整流程通过，不修改 native schema 或认证语义。

## 待验收任务

- **1.2**：缺少当前部署应用类型的脱敏真实管理员事件 fixture/官方边界证据。官方历史加密 golden vector 和自构造事件不证明自建应用能投递该事件；callback 必须保持关闭。本轮官方页访问被浏览器安全策略阻止，未绕过；不以未访问到文档推断官方不支持。
- **9.1**：本机 macOS；Windows SSPI 仅静态检查，未原生执行。本轮已补齐初始化前拒绝和显式 Negotiate 请求测试，其他禁止 Web 入口、合法 WeCom MFA 续接及 callback 无会话已真实路由验证；仍保留 Windows runner 验收缺口。

当前代码构建的 CLI help 已核对；生产部署版本与 runbook 停机重启步骤仍须在部署隔离环境取得审批后实测。正常运行不新增本地密码后门、不伪造 authority、不额外撤销原生凭据；不能仅通过关闭 `LOGIN_ONLY` 绕过后台管理 guard。

## PostgreSQL 后续验收（2026-09-30）

以下是本次续作重新运行的证据；此前 MySQL/MSSQL 环境缺失记录被用户确认的 PostgreSQL-only 范围取代，并非补跑通过。

| 验证与日志 | 实际结果 |
| --- | --- |
| PostgreSQL 全部企业集成，`tmp/wecom-integration-pg-followup.log` | 通过，10.070 秒 |
| PostgreSQL v360 旧结构迁移，`tmp/migration-pg-followup.log` | 通过，2.492 秒；含保守回填、索引升级、历史脱敏、原生管理员/成员保留与重复执行；据此完成 3.5 |
| 完整企业集成 + 显式开启的续租/恢复，`tmp/wecom-pg-followup-final.log` | 通过，46.165 秒；lease 续租测试明确 PASS（30.18 秒），恢复测试明确 PASS（1.50 秒），不是 SKIP；据此完成 9.4 |
| 15 个受影响 service/settings/router/migration 包，`tmp/affected-unit-pg-followup.log` | 通过；`services/externalaccount` 无测试文件，其余均实际执行 |
| `go test -count=1 ./models/...`，`tmp/models-pg-followup.log` | 全部通过（无测试文件的包未计为实际执行） |
| `make fmt` / `make lint-go`，`tmp/fmt-pg-followup.log` / `tmp/lint-pg-followup.log` | 通过；Linux lint 为 0 issues |
| 改动 Markdown lint、`git diff --check`、OpenSpec strict validate | 通过；专属 PostgreSQL 库经 migration harness 清理后只读查询确认不存在，临时模板/生成配置已移除 |

真实续租测试在 provider 候选抓取期间等待 DB lease 到期时间增长，确认 owner/generation 不变、竞争登录仍 `writer_busy`，随后成功发布 revision 并清 lease。通过 `GITEA_TEST_GOVERNANCE_LEASE_RENEWAL=1` 显式开启，不改变生产 30 秒续租策略，不在普通测试中引入固定 sleep。

恢复测试仅允许 loopback PostgreSQL、`local_debug_gitea_governance_test_` 前缀的专属库和默认 public schema，需显式指定 `GITEA_TEST_RECOVERY_BIN`；实际调用当前代码构建的 CLI 和 `pg_dump` / `pg_restore`：

1. 发布测试 provider 候选并备份完整 DB；备份和恢复配置权限为 0600，随机密码仅保留内存，不输出到测试日志。
2. 用原生 CLI 创建 `--admin --random-password --must-change-password` 临时账号；不传 `--access-token`，比对 token/SSH/identity/authority 全表摘要不变。
3. 临时关闭企业治理后本地密码登录、强制改密和 `/-/admin` 成功；重新启用 `ENABLED` 后同一临时 admin 被拒绝（403），可信绑定管理员仍可访问。
4. 恢复 `LOGIN_ONLY=true`，密码入口返回 403，临时 admin 仍不能访问后台；统一 pipeline 可完整发布，callback 仍关闭。
5. 用原生 CLI 删除临时账号并确认不存在；执行完整 `pg_restore --clean --if-exists --single-transaction`，比对所有 public 表数据、列、索引、约束及 sequence 摘要与备份前一致，当前版本 CLI 仍可读取，可信管理员后台仍可达。

该演练中的 authority 来自测试 provider，管理员已有 session 的访问用于验证后台 guard；企微 OAuth/MFA 的真实路由流程（mock provider）另由完整企业集成验证。配置切换为进程内 settings，不是生产多实例停机重启；没有进行生产成套配置/二进制/仓库/对象存储恢复或多进程强杀。上述生产操作仍是 runbook 上线 gate，不将本地 DB 演练扩张为生产恢复批准。

本轮独立只读审查未发现恢复路径的重要安全或回归问题；按反馈补齐原生 CLI 账号回收及 schema/sequence 比对，明确测试跳过与真实 provider/生产运行的证据边界。五份 delta specs 的对照如下；1.2/9.1 缺口继续保留：

| Delta spec | 实现/验收依据 |
| --- | --- |
| `identity/wecom-governance-ops` | verifier/receipt/worker、统一 publisher、失败矩阵及 PostgreSQL deferred commit 触发器；本轮真实续租、原生 CLI/完整 DB 恢复；真实 callback fixture 和 Windows SSPI 未完成 |
| `identity/wecom-admin-ui-super-admin` | 完整 automation 原子发布、unsupported source 拒绝、active bound guard 与只读页面回归；本轮临时 admin 403/可信绑定 admin 200 |
| `identity/wecom-directory-authz-mapping` | generated scope/read 字段、legacy 410/认证优先级及 Swagger 检查；全部企业 API 集成重新通过 |
| `organization/wecom-team-governance` | 显式组织 ID、类型/冲突/覆盖校验，generated 服务测试与 PostgreSQL 发布回归 |
| `repository/single-org-repo-governance` | quota settings/default/zero/native/error 测试、共同创建事务、PostgreSQL 最后额度并发与实际 API/Web 创建回归 |

据此完成 9.6 的实现/spec/diff/恢复证据核对；并不表示 1.2/9.1 已验收或 proposal 可归档。

## 最后两项续作（2026-09-30）

修复 `SSPI.Verify` 仅依赖 middleware 禁用的防御缺口：`LOGIN_ONLY` 时在原生初始化前返回无用户、不协商、不创建账号或会话。非严格模式不改变原生 SSPI 流程。

- 初始单测 RED 为 `no active login sources of type SSPI found`（`tmp/sspi-login-only-red.log`），证明严格模式仍进入 SSPI 子系统。
- 强化测试设置初始化实例为 nil 和初始化错误 canary；临时将 guard 移至初始化后，测试明确 RED：`Expected nil, but got: &auth.sspiAuthMock{}`（`tmp/sspi-login-only-init-order-red.log`）。恢复正确顺序后直接测试及完整 auth 包均通过；没有复制或重置 `sync.Once`。
- Integration 配置 active SSPI source，并在非严格模式重建 router 后恢复严格模式，使 Windows 环境可注册 SSPI 后再执行拒绝测试。断言显式 Negotiate POST 403、GET 仅转企微 OAuth、无协商 header、Cookie 续用后仍未登录且用户数不变。Smoke 同样发送 Negotiate POST 并用 CookieJar 延续检查。
- macOS 上 middleware 仍因 `setting.IsWindows=false` 不注册 SSPI；直接 Verify 单测证明跨平台前置拒绝，不冒充 Windows DLL/协商执行。Windows 上需原生运行下列测试，不能仅设置 `GOOS=windows`。

```sh
go test -count=1 -run '^TestEnterpriseWeComLoginOnlyRejectsSSPIBeforeNegotiation$' ./services/auth/
go test -count=1 -tags 'sqlite sqlite_unlock_notify' \
  -run '^(TestEnterpriseWeComLoginOnlyIntegration|TestEnterpriseWeComLoginOnlySmoke|TestEnterpriseWeComCallbackProviderRoute)$' \
  ./tests/integration/
```

Windows runner 必须先按仓库测试文档准备原生 Go/SQLite 构建依赖、资源和独立 PostgreSQL 测试配置，不连接生产数据库；本次尚无该执行环境。独立只读审查确认本轮测试强化无重要新问题，同时要求保留 1.2/9.1 未完成。

| 本轮验证与日志 | 实际结果 |
| --- | --- |
| PostgreSQL 全部企业集成，`tmp/wecom-last-two-pg.log` | 通过，9.222 秒；含新增 SSPI HTTP 回归、企微 MFA、callback 无会话及 native SSH/PAT/Git 兼容 |
| auth/web/common/Web-auth 四包，`tmp/auth-last-two.log` | 全部通过，包含修复及初始化顺序强化后的直接 Verify 测试 |
| PostgreSQL v360 迁移，`tmp/migration-last-two-pg.log` | 通过，2.430 秒；专属测试库经 harness 清理后查询为 0，临时配置已移除 |
| `make fmt`，`tmp/fmt-last-two.log` | 通过 |
| 串行 `make lint-go` / Windows `gogit` 静态 lint，`tmp/lint-last-two.log` / `tmp/lint-last-two-windows.log` | 均为 0 issues；Windows 检查没有执行原生 SSPI |
| Markdown lint、OpenSpec strict validate、`git diff --check` | 全部通过 |

首次并发 lint 与 Go 编译时，lint 将仓库 `tmp/test-temp/go-build*` 的瞬态 CGO 文件当作源码而失败；未修改 linter、忽略规则或测试要求，等待编译结束后串行重跑。官方协议与真实 fixture 的输入要求已补充到 runbook；当前两个任务都保留未勾选，未启用 callback、未扩展 suite 授权生命周期。
