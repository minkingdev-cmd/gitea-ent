# 高风险执行入口与验收矩阵

## 基线（2026-10-04）

当前 HEAD 为 `c5c6b64159`；用户已明确允许在 master 原地实施。原有未跟踪文件为本 change 的 planning artifacts。foundation/UI 完成记录保留，不回写历史；两项 authorization main specs 尚不存在，未来同步顺序为 foundation → UI → enforce。

foundation 的 verification 记载 Linux/amd64 Docker 非 root + SQLite/PostgreSQL、真实 HTTP/SSH/ref 与失败矩阵；UI 的 2026-10-04 完成记录记载17个 UI 根测试、真实 Chromium 和同 schema 的资源整套回退。这些是前置历史证据，不作为本次实现通过证明。Docker 现有三个 lightrag 容器不属于本项目，不停止/清理/复用。

本次当前 baseline 实跑：`GOCACHE="$PWD/tmp/go-cache" go test ./modules/enterpriseauthz ./modules/setting ./models/enterpriseauthz ./services/enterpriseauthz`，四包通过，输出 `tmp/authz-enforce-baseline.log`。macOS 单测不替代 Linux 服务端验收。

## 执行入口

| 入口/共享业务边界 | actor / 凭据 / 来源 | 意图及原生检查 | 首个副作用、锁与终态 | 本次 actions / 验证族 |
| --- | --- | --- | --- | --- |
| Web/API PR merge → services/pull/merge.go；auto 真正执行；MergedManually | 当前 doer / 原请求 ceiling；auto 保存 doer 后当前读取 | base repo/ref/head/base、原 code/PR/force/checks/review 资格 | merge lock；Git ref/PR merged 状态前；终态不能以排队替代 | merge + 实际 CODEOWNERS；enterprise_authz_merge_enforce_test |
| HTTP/SSH receive → private HookPreReceive/branch → Git 写 refs → post | 私有协议加载 actor；受签名 ceiling/source，不用 git author | 全部 old/new branch refs，保护/签名/file/scope；quarantine diff | pre-receive 全部准入后 refs 写；post 仅终态 | protected push + CODEOWNERS；enterprise_authz_receive_enforce_test |
| Web/API/editor、ChangeRepoFiles、patch/cherry-pick/revert | 当前 doer、真实 Web/API ceiling；file_editor/api | old/new branch、真实 diff、递归删除/rename 两端 | temporary repo 实际 push 前；内部 hook early return 不能代替 guard | protected push + CODEOWNERS；enterprise_authz_files_enforce_test |
| branch create/delete/rename、PR head update、fork sync | 原 doer/ceiling及实际目标仓库 | protected 目标/路径；保留 native source/base/branch/write guard | shared branch/service push/ref mutation 前 | protected push + CODEOWNERS；branch/update/fork 真实测试 |
| Web/API branch protection CRUD/priority | doer、repository ceiling、web/api | code/admin、archive、合法 patterns；required checks 变化 | rule/unit 写前；双 action 同 operation | protection；检查变化加 CI；enterprise_authz_settings_enforce_test |
| repo webhook CRUD | doer/repository ceiling | 原 admin/webhook disabled/URL/对象 scope | webhook 存储/队列/通知前 | webhook；settings/hook 测试 |
| repo secret 写入/删除 | doer、Actions repository ceiling | Web 原 Admin / API 原 Owner、Actions unit、repo scope；不读值 | secret model mutation 前 | secret；settings/secret 测试 |
| repo CI、Actions token perms/variables/runner/workflow toggle | doer、对应原生凭据范围 | 单独 repo scope/runner/workflow/native guard | unit/config/variable/runner/workflow 存储前 | CI；settings/actions 测试；run/dispatch/cancel不冒充管理 |
| API Edit CI+archive；Web danger-zone | 当前 doer / repository ceiling | 收集完整高风险意图；原 admin/danger-zone/mirror | 第一次 unit/repo 更新前统一准入 | CI + archive；lifecycle/settings 复合请求测试 |
| collaborator Web/API → AddOrUpdateCollaborator/DeleteCollaboration | HTTP 当前doer；被授予对象不是actor | 原 admin/team/org配置/企微治理 | access/collaboration事务及通知前 | manage_access；新增真实接口与service测试 |
| repo/team与org/team Web/API → repo_team helpers | 当前doer；org token须保留原organization范围，仅给manage_access ceiling | team-repo所属org、当前repo可见性、原org owner/config/治理 | 全目标准入；一次原业务事务，不能批量部分更新 | manage_access；团队关联/bulk用例 |
| org team UpdateTeam/DeleteTeam | 当前doer与原organization ceiling | 变更前后全部关联repo、units/permission/includes-all；仅名称不接授权action | team/unit/关联/access重算前统一准入 | manage_access；org入口防旁路、多repo拒绝 |
| transfer start/accept/reject/cancel → transfer.go | 实际当前执行人，不用原申请人替代接收者 | 旧owner、目标owner/team、接收资格/配额/治理/状态 | repo global lock及原Tx前；保留pending≠转移完成 | transfer；enterprise_authz_lifecycle_enforce_test |
| Web/API archive/unarchive | 当前doer及动作scope | 原danger-zone/mirror；复合请求先完整检查 | SetArchiveRepoState/Actions schedules前 | archive；lifecycle/edit测试 |
| Web/API delete → DeleteRepository → Directly | 当前doer；固定系统清理另标记 | 原确认、danger-zone、治理、存在性 | 通知/DB/磁盘清理前；历史保留 | delete；lifecycle/delete测试 |
| catalog/decision API + 既有管理UI | API原scope与management authority；UI当前系统超管/session/CSRF | 新mode/auth筛选、旧catalog解码；角色不授予UI | 仅读取；返回旧shadow与新准入区分，不伪成功 | api/ui测试、Swagger、locale仅en-US |

## 无 actor / 间接调用者

| 调用点 | 用途和受信边界 | 需要的适配 |
| --- | --- | --- |
| services/repository/create.go → AddOrUpdateCollaborator | 新仓库初始化creator admin，常在创建事务内 | 固定新建仓库初始化标记；仅该repo，不能用于既有repo委派 |
| services/repository/governance.go → AddOrUpdateCollaborator | 已批准申请发布creator访问 | 原治理批准者及明确操作意图；原授权不被伪造role替代 |
| services/org/team.go:NewTeam/UpdateTeam → AddAllRepositoriesToTeam | includes-all组织团队创建/调整，内部Tx | 人工入口先对全部目标准入，嵌套仅匹配的准入handle |
| services/org/team.go:DeleteTeam → RemoveAllRepositoriesFromTeam | 移除team授权并清关联 | 人工入口统一准入后嵌套handle；不将actor=nil当系统 |
| services/enterprisewecom/team_governance.go → UpdateTeam | 自动生成团队非授权字段维护；现有调用authChanged=false,includeAllChanged=false | 保留现有受治理同步；授权变更若发现须固定私有维护适配 |
| services/user/block.go → DeleteCollaboration | 原生阻止用户时撤销关系 | 按原生caller权限/明确维护意图区分，不从collaborator/victim推actor |
| services/repository/repository.go → DeleteRepositoryDirectly | 用户可控删除 | 原当前doer先准入，不能使用系统维护标记 |
| services/repository/create.go → DeleteRepositoryDirectly | 新仓库创建失败后的补偿清理 | 固定创建事务与新repo目标，不允许扩展到既有repo |
| services/doctor/repository.go、services/repository/check.go → DeleteRepositoryDirectly | doctor/仓库检查维护 | 固定维护调用者、operation kind、目标和审计 |
| services/user/user.go、services/org/org.go → DeleteOwnerRepositoriesDirectly | 用户/组织删除的既有清理 | 固定原生批量删除边界，保留其原生管理员/治理检查与系统审计 |
| services/repository/delete.go → DeleteRepositoryDirectly | 批量清理内部链 | 验证上层固定来源与全部目标；未知caller安全拒绝 |
| services/repository/init.go/template.go → 初始 branch | 固定 Create/Generate 调用点的私有 typed 新仓库标记 | 实际 creator/owner/default branch、当前 native Admin、零 refs/零 branch、强数据库 system audit；首 ref 使用 expected-zero CAS，不借 Git author |
| services/mirror/mirror_pull.go → pull mirror 同步 | 仅 SyncPullMirror 锁内构造私有 typed maintenance intent | 当前 mirror ID/repo/owner/IsMirror 精确匹配，独立 system audit 首 fetch/prune/LFS/wiki 写前提交；未知 direct caller、伪 system、native owner/mirror 改变拒绝 |
| migration / task / uploader /初始化团队 | 既有迁移、新repo初始化 | 不把repo.migrate纳入enforce；嵌套维护不得扩权到用户任意repo请求 |

普通目录/团队成员维护不是新增manage_access产品入口；成员变更在后续执行政策快照中生效。原生业务调用者须逐项验证，以上表格不能代替真实运行证据。

## 模式 × action × 凭据 × 故障

- disabled：不增加企业查询/决策；原有身份/scope/响应/副作用保持。
- shadow：完整旁观、200ms，deny/error/证据故障不改原生结果；manage_access新增旁观。
- enforce：11-action固定集，实际写前完整准入；低风险/migrate仍shadow、feature grant无产品入口。
- Owner、可信超管：默认action正例，同时验证原生规则/凭据限制；撤销authority后的旧session负例。
- Admin：secret/delete/transfer/archive/protected push/manage_access的企业缺权为可达负例；显式匹配角色且原生允许为正例。
- code writer merge、Admin protection/webhook/CI/CODEOWNERS：原生映射贡献allow，缺少角色不是deny；负例覆盖原生guard/范围/错误，而不虚构“移除角色就撤销原生action”。
- reader+Owner企业角色：可见性/native操作阈值不足时拒绝，不提升nativeAdmin；受限PAT/SSH/deploy/Actions不因人类角色扩权。
- 故障：明确deny永不fail-open；policy/前置证据基础设施故障默认503/receive拒绝，显式false只原生fallback；不完整路径/伪造或旧ticket/取消/超限不降级。
- 数据完整性：缺action无DB/Git/磁盘/通知副作用；前置decision+audit一组原子；后置失败保留unknown并告警，不伪造回滚或诱发重试。
- 所有入口均需真实allow/native deny/适用企业deny/业务失败/故障/并发证据；单位预算、完整目标集、复合action和模式显示均独立验证。

## 最终补强与证据定位（2026-10-05）

- 所有受控 Git 写边界复查当前原生规则：receive 同快照完整 pre-receive；files 保留实际签名、force、protected/unprotected file 与新分支共同起点合同。Settings 四类写入仍 AND 当前原生 Admin，API secret 仍 AND Owner；原生身份/权限/规则读取失败为不可降级503。
- 文件 force push 使用 admitted-old lease；普通 push 另保留 non-FF 限制，不通过 lease 获得 force 资格。LFS 失败仅删除本次实际新增 meta ID，不按 OID 删除已授权 metadata/object。真实 race、同 OID 与撤原生规则均有 RED→GREEN。
- 迁移 v362 的部分模型 Sync 同时保留既有普通及唯一索引；迁移前后真实决策 INSERT 的 observation_id 去重可用，重复升级不会破坏约束。
- 固定 mirror pull 是既有系统维护边界，不增加 enforce action 或用户管理入口；repo.migrate 仍仅 shadow，维护 context 不充当通用 system 权限。
- 具体真实测试：enterprise_authz_{receive,files,file_native,branch,merge,settings,access,lifecycle,authentication}_enforce_test.go、enterprise_authz_mirror_maintenance_test.go、enterprise_authz_execution_snapshot_test.go、既有 enterprise_authz_api/ui_*；最终命令/退出码与平台见 verification.md。
