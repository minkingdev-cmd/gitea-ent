# 企业授权管理 UI 验证记录

日期：2026-10-03；Linux 完整验收与回退完成于2026-10-04。变更：`add-enterprise-authz-management-ui`。

任务进度：36/36；本提案要求已完成，尚未归档或提交。

## 结论与环境边界

生产实现已接入内置站点管理，具备三作用域角色/条件、主体绑定、有效权限/诊断与真实决策历史。组织/仓库/用户/team/角色以名称选择，ID 仅隐藏提交；历史保留已删除对象候选。浏览器日期与记录时间自动按本地时区渲染，标准时间点提交与保存。全部新增入口仅当前可信系统超管可达，保持 shadow-only。

2026-10-04 用户告知 Docker Desktop 已启动后，确认 `desktop-linux` 可用，使用缓存 Linux/amd64 镜像完成运行时整体验收（6.4）及匹配 foundation 的 UI 回退演练（7.2）。仅创建/清理专用容器和预先不存在的测试数据库，没有启动、修改或停止其他项目容器。

此前本机 Go/PostgreSQL/SQLite/Chromium、交叉编译与 lint 不冒充 Linux 运行验证；现在额外完成以下真实 Linux 容器运行证据。不要求或宣称 Windows 服务端支持；未测试 Firefox、MySQL/MSSQL 等其他组合。

## 权限、按钮与 helper 矩阵

共同准入：合法当前 Web session → 每请求重新加载有效账号及系统 authority → authz enabled → URL scope/对象 → facade 再校验系统与目标 scope authority → 原业务 service。企微开启再要求当前 CorpID/AgentID 下 active、已绑定 management authority；企微关闭使用有效原生 IsAdmin。

| 入口/操作 | 方法与后端路径 | 附加校验 | 证据 |
| --- | --- | --- | --- |
| 企业授权菜单、名称作用域工作区 | GET 根入口、`/scope` | 同一系统 authority、enabled、合法目标；尊重 AppSubURL | Authority、AllEntrypointsAndWeComAuthority |
| 作用域/用户/team/org/role/历史对象名称搜索与分页 | GET `/selectors/{kind}` | 有界 keyword/page/limit、参数化搜索、角色来源/主体关系 | ReadonlyCopyAndSelectors、BindingValidationAndStaleOwner、NameFirstInputs、HistoryNamedSelectors |
| 角色列表、新建、详情、复制 | GET `/scopes/.../roles[/{id}]`、`/roles/new?copy_from=...` | 来源可见性、内置/祖先只读、跨 scope ID | RoleLifecycle、ReadonlyCopyAndSelectors |
| 添加/移除权限、来源选项 | 本地条件构建器，保存时 POST 角色 | 后端 catalog；allow-only；完整规范化条件；完全重复拒绝 | RoleLifecycle、BodyBoundAndConditionRoundTrip、Vitest |
| 保存、清空或保持权限不变 | POST `/roles/new` 或 `/roles/{id}` | session CSRF、urlencoded、大小/字段白名单、revision、同事务 audit | SessionAndCSRF、MultipartBodyBound、RoleValidationAndAuditRollback |
| 删除角色、确认/取消 | POST `/roles/{id}/delete` | 明确确认、原 revision、内置不可变、引用中拒绝 | ReadonlyCopyAndSelectors、RoleLifecycle、浏览器 CRUD |
| 绑定列表、创建绑定 | GET/POST `/bindings` | user/team/org、角色范围、Platform Admin 仅系统、幂等及同事务 audit | BindingLifecycle、BindingValidationAndStaleOwner |
| 解除绑定、确认/取消 | POST `/bindings/{id}/delete` | 当前范围、明确对象确认、业务/审计事务 | BindingRelationChangeAndAuditRollback、BindingConcurrentCreateAndRoleDelete、浏览器取消/确认 |
| 有效权限查询 | GET `/effective-permissions` | repo 上下文、本地目标用户；caller 和原生 permission 固定 | DiagnosticCandidateAndConditions、ManagementUIReusesScopedPolicyAndForcesDiagnosticCaller |
| action 诊断 | POST `/evaluate` | CSRF、固定 diagnostic、完整有界 paths、无真实操作决策 | DiagnosticCandidateAndConditions |
| 历史筛选/分页/详情 | GET `/decisions[/{id}]` | 每页最多100、scope、白名单快照、历史 revision、已删除 repo | DecisionHistoryPrivacyAndScope、PresentationDecisionDTOWhitelist |
| 原 token API | 原 `/api/v1/.../enterprise/authz` | 原 reqToken/scope/目标 authority 不变 | APIAllManagementScopes、APIScopesAndDiagnostics、完整兼容回归 |

超管之外的 org/repo owner、creator/admin、企业 Owner/Platform Admin 不获得 UI。普通 IsAdmin 在企微开启但 unbound/inactive/message-only/其他应用 authority 时拒绝；旧 session 在账号禁用、限制、authority 撤销或存储错误后不能继续维护。facade 撤销测试覆盖读写/诊断、搜索及精确回显；selector 每请求同样校验。禁用路径通过 SQL 捕获证明不查询角色、绑定及目标仓库。

所有 UI 根测试均在 `tests/integration/enterprise_authz_ui*_test.go`；表格中省略统一前缀 `TestEnterpriseAuthzUI`。共享 DTO/facade 测试位于 `services/enterpriseauthz/`。

## Action-to-view 清单

19个 action 全部来自现有 `Catalog()`，不是前端授权常量。角色条件下拉、后端目录说明和诊断 action 选项使用同一目录；缺失 locale key 的 HTML 回归覆盖角色/诊断页面。

| 目录 action | 页面及边界 |
| --- | --- |
| `repo.view_metadata`, `repo.read_code`, `repo.clone` | 角色表单、有效权限、候选诊断；目录提供 unit/risk/Observed |
| `repo.create_branch`, `repo.push_branch`, `repo.push_protected_branch` | 同上；条件构建器与 push_branch 全链路；不计算完整分支保护 |
| `repo.create_pull_request`, `repo.review_pull_request`, `repo.merge_pull_request` | 同上；不声称完整 merge gate 或执行合并 |
| `repo.manage_branch_protection`, `repo.manage_codeowners` | 同上；不新增修改原生安全规则的按钮 |
| `repo.manage_webhook`, `repo.manage_ci`, `repo.manage_secret` | 同上；不显示 webhook secret、凭据或执行配置变更 |
| `repo.manage_feature_grant` | 明示仅目录/诊断、Observed=false；没有功能授权/enforce 开关 |
| `repo.migrate`, `repo.transfer`, `repo.archive`, `repo.delete` | 同上；没有真实迁移/转移/归档/删除操作按钮 |

## 实际验证

测试数据库采用本仓库隔离 helper：互斥执行、专用且预先不存在的数据库、临时测试配置、finally 清理，并恢复原配置字节。不是连接生产数据库，也不通过手工 SQL 给生产 seed/修复授权。

| 检查 | 命令/范围 | 实际结果 |
| --- | --- | --- |
| Go 格式 | `make fmt` | PASS |
| Linux Go lint | `CI='' make lint-go`，仓库内 GOBIN/GOCACHE/GOLANGCI_LINT_CACHE | PASS，0 issues；未运行 Windows lint |
| 模板 | `UV_CACHE_DIR=$PWD/tmp/uv-cache make lint-templates` | PASS，591文件，0错误 |
| JS/TS | `make lint-js ESLINT_FILES='web_src/js/features/admin/enterprise-authz.ts web_src/js/features/admin/enterprise-authz.test.ts web_src/js/index.ts tests/e2e/enterprise-authz.authz.ts playwright.enterprise-authz.config.ts'` | PASS，ESLint及 vue-tsc |
| CSS | `make lint-css` | PASS |
| Markdown / OpenSpec / diff | `pnpm exec markdownlint`、`openspec validate add-enterprise-authz-management-ui --strict`、`git diff --check` | PASS；逐条核对规范、权限矩阵和真实入口；明确未完成的 Linux 验收 |
| 前端产物 | `pnpm exec vite build` | PASS，3.07s（详见 `tmp/authz-time-build.log`） |
| Go unit | `go test -count=1 ./modules/enterpriseauthz ./services/enterpriseauthz ./routers/api/v1/enterpriseauthz` | PASS，包含原 API 安全 DTO 合同 |
| 本机 PostgreSQL UI | `python3 tmp/authz-run-pg.py '^TestEnterpriseAuthzUI'` | PASS，6.287s；浏览器 opt-in 此轮跳过；隔离库清理 exit 0 |
| 本机 PostgreSQL 完整兼容回归 | 完整兼容选择器（见下） | PASS，182.414s，含原 token API/authority/scope、LOGIN_ONLY/MFA、SSH/PAT/Git HTTP、Actions/deploy；隔离库清理 exit 0 |
| 本机 SQLite UI | `python3 tmp/authz-run-sqlite.py '^TestEnterpriseAuthzUI'` | PASS，3.445s（详见 `tmp/authz-time-sqlite.log`）；浏览器 opt-in 此轮跳过 |
| 前端浏览器 unit | `PLAYWRIGHT_BROWSERS=chromium pnpm exec vitest run web_src/js/features/admin/enterprise-authz.test.ts` | PASS，4 tests，363ms；完整前端 Chromium/Node 测试53文件、162 tests，1.79s |
| 真实 HTTP/session + PostgreSQL + Chromium | `AUTHZ_UI_BROWSER_TEST=true python3 tmp/authz-run-pg.py '^TestEnterpriseAuthzUIBrowser$'` | PASS，Go 6.518s；浏览器3 tests，完整维护链路2.6s，上海448ms、纽约579ms，隔离库清理 exit 0 |

完整兼容回归的实际命令：

```bash
python3 tmp/authz-run-pg.py '^TestEnterpriseAuthz|^TestEnterpriseWeComLoginOnly|^TestRepoMergeUpstream$'
```

Linux 交叉编译命令 `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -buildvcs=false -o tmp/authz-linux/gitea .` 与 `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -c -o tmp/authz-linux/integration.test ./tests/integration` 均 exit 0；`file` 确认 ELF x86-64，匹配资源已准备。这证明 Linux 构建，不证明 Linux 运行时或回退。

浏览器 opt-in 用真实路由、真实数据库、真实登录 session 和表单 CSRF，不使用 mock API。链路包含无业务 ID 输入的作用域名称搜索、角色条件创建/回显及键盘输入/新增条目焦点、主体/角色搜索、绑定、诊断、真实 repo 请求产生 shadow 记录、历史 actor/repo 名称选择与本地日期筛选、历史详情、独立复制/删除、解绑取消/确认、revision 更新和最终删除。暗色使用原生自动主题及 computed CSS 确定条件，不是伪造主题 class。

Vitest 默认还请求 Firefox，但本机没有对应可执行文件，默认双浏览器命令未通过；使用已安装 Chromium 的项目支持参数重新执行通过，没有安装浏览器或削弱测试。E2E 专属 profile 使用 `playwright.enterprise-authz.config.ts`，普通未启用 authz 的 E2E 不加入此链路，也不靠永久 skip 伪装验收。

上海/纽约独立 browser context 证明同一冬季和夏季 epoch 呈现不同的正确本地时间；刷新提交仍是原 epoch。纽约不存在的夏令时跳变输入被拒绝，未编辑的重复时段保留原 instant。真实 repo 请求产生记录后验证浏览器 `relative-time` 的实际 shadow DOM（不是隐藏服务器 fallback 文本）按本地时区展示，筛选后记录保持。后端拒绝无时区日期字符串、超限/负值/重复参数和反向范围，兼容旧 Unix 链接。终端不增加新 CLI 或固定 UTC 规则。

## 关键 RED → GREEN 与审查

- 名称优先真实 HTML 测试初始发现可见业务 ID 输入，统一 picker 后通过；改写文字、清除和类型切换清掉旧 ID，错误草稿/回显仍受权。
- 本地时间测试初始回显空值或 UTC naive 日期失败；改为隐藏标准时间点和浏览器本地转换后通过，不把服务器时区当用户时区。
- 历史有名搜索在 PostgreSQL 对未转义的 `user` 子查询错误或空结果，真实浏览器及 keyword integration 先失败；按仓库惯例转义表名后通过，不吞异常或退回手填 ID。
- 无路由时真实 session 请求返回404；实施后全链路可达且权限失败仍拒绝。
- 同一 action 不同条件可完整保存；调换条件顺序后的规范化完全重复权限返回422，既有 API 合同不改。
- 含 CR/LF 的合法 pattern 原实现回显拆成 OR，condition hash 真实测试失败；改为可逆单行 JSON string 转义后原 hash 保持，普通空格/反斜杠不损失。
- 原 multipart 文件可在全局解析后绕过 UI 的 body limit，真实有效 token 请求错误返回303；UI 限定 urlencoded 后拒绝422，不改其他页面的上传行为。
- UI facade 移除系统准入的验证性变更会让旧对象在原生 IsAdmin 撤销后放行，测试失败；恢复后全部方法安全拒绝。
- selector 清空搜索后遗留 aria-busy，前端测试失败；清理旧加载状态后通过。
- 缺少 previous/search_user 文案时实际页面泄露 locale key，HTML 测试失败；补唯一 en-US 源后通过。
- 只读复核发现的条件 round-trip 与 multipart 大小问题均已修复并重跑；没有通过禁用 linter、降低断言或吞错误解决。

本轮只读独立审查发现 Actions/deploy 等虚拟 actor 不在真实用户表，输入显示名称没有结果；补固定后端虚拟用户工厂名称/FullName 匹配（仍 AND 原范围、共用有界计数分页）。真实 observation 搜索先 RED，修复后 PostgreSQL/SQLite GREEN，审查复核未发现边界退化。

本次没有宣称全仓库后端 suite 全绿。上轮全后端验收中的 `TestMigrateWhiteBlocklist` 外部 DNS 失败在未改 HEAD 上可复现，未通过修改授权代码、屏蔽断言或吞错误绕过。

## 无迁移、配置或默认授权变化

实施前 SHA256 基线包含6565个预存文件。当前相对基线的改动仅限 UI 路由/导航/入口、唯一 locale 源、本 change artifacts/测试、共享安全 DTO 包装及现有来源目录的只读导出。基础模型、migration、schema version、配置结构、八个角色 seed、原 API 路由/认证/structs、go.mod/go.sum、Swagger 与企微登录/同步/callback 文件均未修改。

没有新 action、relation、默认角色、隐式回填、OpenFGA/Keycloak、外部授权系统或 callback。DTO 仅抽取已有合同供 Web/API 共同使用；因此本 UI 无需 tidy 或 Swagger 生成。未将工作树中原已存在的 foundation 修改误记为新增 UI migration。

## 截图及回退演练

真实浏览器截图保存在 `docs/enterprise-authz/screenshots/`：

- `authz-management-role-light.png`：角色与条件维护。
- `authz-management-diagnostic-light.png`：候选诊断及条件解释。
- `authz-management-history-dark.png`：原生暗色下真实 shadow 证据。
- `authz-management-filters-light.png`：真实名称筛选、本地日期控件和自动检测的浏览器时区。

上述截图已在本轮完整名称/时区 E2E 重新生成并实际检查，不复用旧手填 ID 界面截图。

Linux 专用运行、浏览器及回退 harness 位于本仓库 `tmp/`，实际运行证据见下方完成记录；不是仅准备脚本即视为通过。截图已更新为最终 Linux 服务端与真实 PostgreSQL 的浏览器验收输出。

没有提交、推送、创建 PR、改写 Git 历史或归档变更；没有修改旧 foundation 的完成及验收记录。

## 2026-10-04 继续验收检查（当时状态）

在用户告知已启动之前再次只读检查：当时 Docker context 为 `desktop-linux`，`docker info` 无法连接，`/Users/minwang/.docker/run/docker.sock` 仍不存在。未启动 Docker Desktop，已向用户请求明确确认（启动可能恢复其他项目容器）。6.4、7.2 继续保持未完成，进度34/36。

本仓库临时 Linux 回退 harness 补充仅已创建容器清理标志、专用 PAT 的原 API 校验、匹配资源整套替换、配置摘要不变断言、二进制摘要记录及工作区资源恢复；未运行这些 Docker 步骤，不将脚本准备或语法通过视为回退成功。

该检查阶段实际通过 Python AST 语法检查、OpenSpec strict validation、`git diff --check` 和6565文件基线核对（11项已允许修改，无新增越界变更）。旧 foundation 验收记录、schema/seed/config 和其他项目运行状态未修改。

## 2026-10-04 Linux 最终完成记录

| 检查 | 实际命令与证据 | 结果 |
| --- | --- | --- |
| Linux/PostgreSQL UI | `python3 tmp/authz-linux-run.py pg '^TestEnterpriseAuthzUI'`；`tmp/authz-ui-linux-pg-runtime.log` | PASS，17个 UI 根测试，含真实 session、权限/CSRF、条件 round-trip、版本竞争、审计回滚、名称与历史；专用数据库清理 exit 0 |
| Linux/SQLite UI | `python3 tmp/authz-linux-run.py sqlite '^TestEnterpriseAuthzUI'`；`tmp/authz-ui-linux-sqlite-runtime.log` | PASS，快速补充，不替代 PostgreSQL |
| Linux/PostgreSQL 完整兼容 | `python3 tmp/authz-linux-run.py pg '^TestEnterpriseAuthz\|^TestEnterpriseWeComLoginOnly\|^TestRepoMergeUpstream$'`；`tmp/authz-ui-linux-compat-runtime.log` | PASS，原 token API/scope/authority、合法登录与拒绝/MFA、SSH/PAT/Git HTTP、Actions/deploy、真实 Git/merge 流程；数据库清理 exit 0 |
| Linux 真实 HTTP + PostgreSQL + Chromium | `python3 tmp/authz-ui-e2e-linux.py`；`tmp/authz-ui-e2e-browser.log` | 3 tests PASS：完整维护3.1s，上海639ms，纽约740ms；Linux 服务端固定 UTC，浏览器分别自动转换本地时区 |
| 匹配 foundation 仅 UI 回退 | 同一 harness；`tmp/authz-ui-e2e-linux.log`、`tmp/authz-ui-e2e-linux-result.json` | PASS；schema version 362 与列定义摘要不变；角色/权限、非空绑定、非空决策及全部既有审计行保留；配置 SHA256 不变；原 API 读到维护后角色，新增 UI 返回404 |

回退使用匹配 foundation 二进制和完整 options/templates/public 资源，未使用更早的不兼容 schema 二进制；没有降 schema、删除策略/历史、回填绑定、修改 authz/enforce/callback 开关或改写生产配置。新启动事件可增加，但所有回退前审计行按原 ID 边界逐行摘要保留，不把正常新增启动事件误判为历史变化。仅初始化独立新测试库时执行既有 foundation migration/seed，不是新增 UI migration。

运行中修正临时 harness 的数据库初始化、API 建仓所需 `write:user` 测试 PAT scope 和 CLI 规范化 INI 后的开关解析；没有放宽产品鉴权、改 UI 权限或降低断言。最终所有步骤重新真实通过，早先失败未冒充成功。

本次专用服务容器和 PostgreSQL 数据库全部清理，临时工作区恢复当前资源。验收前后原有3个其他项目容器的 ID/name 保持一致。源码基线仍为原6565文件中11项已允许改动，无新增越界改动；旧 foundation 完成记录不改写。未提交、推送、创建 PR、修改 Git 历史或归档。
