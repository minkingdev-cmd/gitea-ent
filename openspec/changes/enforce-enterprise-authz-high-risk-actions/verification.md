# 实施验证记录

日期：2026-10-04 至 2026-10-05。工作区：`/Users/minwang/Projects/gitea-ent` 当前 master，用户授权原地实施；未创建分支/worktree、commit/push/PR、部署、同步主 specs 或归档。foundation/UI 历史记录未回写，后续主 specs 同步顺序仍为 foundation → UI → enforce，须另获授权。

## 当前交付状态

50/50 tasks 已完成。11 个高风险 action、全部已盘点真实写入边界、机器/固定维护合同、三模式配置、历史 API/UI 和回退恢复均已实施。最新源码的统一 Linux 全入口与全 backend 回归、独立复核、格式/lint/Swagger均已实际通过；严格 OpenSpec 校验通过。

配置不再拒绝全部 ENFORCE：disabled 为 false/false，shadow 为 true/false，enforce 为 true/true；false/true 报 enforce_requires_enabled，非法布尔、审计/seed/schema 缺失拒绝启动。配置开放不是生产启用。

## 需求到实现/实证映射

| 要求/任务 | 当前合同与真实验证 |
| --- | --- |
| 1.x 基线与调用者 | entrypoint-matrix.md 逐项列 actor/credential/current native/首写/终态。不会把前置历史测试当本次通过证据，也不虚构原生并集模型不能产生的企业 deny。 |
| 2.x catalog/config/migration | catalog v2 共20 actions，固定11项支持 enforce；manage_access 仅原生 Owner 默认贡献；只增加 owner/platform-admin 内置权限，revision=1，旧复制角色/绑定/历史 ID 内容保留。migration362、DB363，v361不改；新安装仅证明空库时事务初始化，现存缺 seed不自愈。Linux迁移、旧binary gate与配置测试见下表。 |
| 3.x admission/evidence | 多 action 同一独立政策快照；当前 actor/repo/owner/member/permission/credential，exact private intent、Start/Finish、1s/paths1024/repos1000、取消及未知目标拒绝。原生身份/权限/规则故障不可降级；仅可恢复授权基础设施显式 false 可 fallback，明确 deny 优先。decision+关联audit独立原子先写；终态故障留unknown、不改真实成功或虚构回滚；私有去重/固定安全指标。 |
| 4.x merge/auto/manual | 共享merge及SetMerged首写前准入；普通/force/manual保留原 checks/review/SHA/native；实际最终CODEOWNERS compound。auto只存doer不存allow，真实队列切换及当前成员/原生/role撤销重查；head更新不是merge许可，merge后的head清理独立准入。merge-report.md：LinuxARM64两库7enforce+19原native根及10unit通过。 |
| 5.x Git/files/branch | 全ref外部HTTP/SSH pre-receive统一准入，quarantine actual diff三个CODEOWNERS路径/rename/delete/binary，author不是actor；同快照完整原生 pre-receive。file/editor/patch/cherry/revert共享实际push，新当前native保护/签名/文件/force复查；准入后才LFS写。force exact-old lease，普通仍拒non-FF；失败仅清本次新meta ID，保同OID旧object。branch create/delete/rename/restore、PRhead/fork sync/初始化首ref均实际写前；CAS不伪装进程锁为跨Git原子。专项最新HTTP/SSH含原生签名拒绝两库PASS（receive-signed-{sqlite,pg}-final.log）；其余原生/文件/branch专项报告通过，最新全套统一双DB已PASS，详见下表。 |
| 6.x settings/CI/secrets/webhook | shared CRUD+Web/API首写准入；required checks有效变化compound CI/no-op不加；复合Edit CI+archive缺一全部不写；settings当前native Admin AND，APIsecret当前Owner AND；runner注册仅当前有效精确repo token，actor0/system/NativeOnly，不借创建者角色。Linux两库23父+7native子与机器服务通过，最新再跑通过，settings-report.md。 |
| 7.x manage_access/系统维护 | collaborator/team-repo/bulk与orgteam授权字段变更对完整当前repo集合先准入，原Tx一次写；空集合变化也不复用旧许可，组织scope不泛化。固定私有typed维护需精确caller/target/原生边界+系统审计，nil/system/header/未知caller不豁免；不委派企业API/UIauthority。8HTTP+10repo/3org单位Linux通过，manage-access-report.md。 |
| 8.x lifecycle | transfer各状态按当前实际actor/旧owner/target、pending不等于完成；archive/delete首效前，保原治理/配额/危险区、真实失败与历史留存；bulk完整集合当前资格，固定清理不借owner身份。Linux两库12单位及blocked requiredaudit通过，lifecycle-report.md。 |
| 固定Git维护 | Create/Generate初始branch仅真实creator/current owner/defaultbranch/零refs+零branch、当前native、首写前强systemaudit；镜像pull仅SyncPullMirror锁内精确current mirror/repo/owner/IsMirror私有context，fetch/prune/LFS/wiki前系统审计。mirror-report.md：Linux7case+原mirror/SSRF3root两库通过；migrate仍shadow，非新增用户动作。 |
| 9.x API/UI | 追加字段/filters/catalog、旧v1/v2白名单解码、最大每页100、旧scope/authority/CSRF不变；诊断始终候选，不把allow当业务success。Linux实际15API+20UI server根两库通过，1browser opt-in默认skip；Darwin Chromium独立4/4，真实暗/亮主题/键盘/XSS截图，不冒称Linux浏览器。history-ui-report.md；Swagger最终生成/验证见下表。 |
| 10.1/10.2 认证兼容 | 禁止Web本地/注册/OpenID/Passkey/其它OAuth/反代/SSPI，合法企微/MFA续接，callback持续false；三mode SSH/PAT/API/GitHTTP scope/吊销/状态，Actions缓存token当前task状态与deployNativeOnly。LinuxSQLite及真实LinuxPG17.9通过，auth-compat-report.md。 |
| 10.4/10.5 运维/恢复 | app.example.ini与authz-enforce-runbook新增，保旧时间线；同新版完整独立备份/恢复及真实restart三模式、pending当前policy与auto重新检查，细节见下节。 |

各报告位于仓库 `tmp/authz-enforce-briefs/`，仅辅助证据，本文保存关键实证摘要。全部scope纳入tasks/当前delta specs，不创建平行计划。

## 关键 RED → GREEN 与最终命令

所有日志位于仓库 tmp，均为真实执行。macOS单元开发验证不替代 Linux 服务端验收。

| 验证 | 实际命令/结果/日志 |
| --- | --- |
| 初始catalog/readiness/history/schema RED | 原19actions/缺新列/decoder拒v2/Owner无manage_access，旧代码真实失败；authz-enforce-{catalog,history,migration,model,readiness}-red.log。 |
| empty-install/中断恢复 | modelmigration真实SQL故障在version INSERT前；旧留下半表RED→当前全部回滚、重跑恢复GREEN；authz-enforce-seed-{red,recovery-red,green}.log、seed-report.md。 |
| v362 unique约束最终修正 | 新迁移前后全部index保留与真实InsertDecisionIfAbsent重复幂等测试，旧partial Sync删除observation_id唯一索引真实RED，authz-migration-unique-red.log；IgnoreDropIndices+IgnoreConstrains修正后GREEN，authz-migration-unique-green.log。最新LinuxARM64 SQLite/真实LinuxPG17.9三migration roots PASS：authz-migration-native/{sqlite,pg}.log；PG测试reset自动dropDB。 |
| 当前配置/core四包 | GOCACHE=$PWD/tmp/go-cache CGO_ENABLED=0 go test -count=1 ./modules/setting ./modules/enterpriseauthz ./models/enterpriseauthz ./services/enterpriseauthz，exit0；authz-enforce-config-core-final-green.log。Linuxsetting/config环境probe exit0，authz-backend-final-linux/native-environment-green.log；最新Linuxsettings/currentnative/identity/fallback/machines单位exit0，authz-settings-linux-current-snapshot-unit.log。 |
| 原生读取故障不得fallback | protected rule read、四类settings currentAdmin被撤且显式role候选allow、nativeidentityDB故障旧rawerr false降级有效RED→typed403/503 GREEN；authz-native-rule-core-{red,green}.log、authz-settings-native-core-{red,green}.log、authz-core-native-read-red.log。 |
| Git解析阶段与NativeGuard故障最终补强 | 独立跨域复核发现原生读取 plain policy_read_failed 和 nativeGuard到期后raw错误可false降级；六个真实identity/authority/permission/缺目标case+两个nativeGuard普通/1s预算case均有效RED，authz-git-native-boundary-red.log。第一次错误命名green仍FAIL（外层readErr覆写typed原因），修readErr保留不可恢复优先级后，host全core13.663s、LinuxARM64全core6.471s exit0，authz-git-native-boundary-all-green.log、authz-backend-final-linux/environment-rerun-final.log；role基础设施原生已通过时仍可fallback。两个P1已独立追证关闭，final-cross-domain-review.md。 |
| receive/files定向修复 | execution-review.md 保留初审3P1及后续修复实证；外部pre原生已通过后当前write/CanPush撤销与nativeDB故障真实RED→GREEN；files四原生规则撤销、实际Push三规则ref被改RED→403/ref不变GREEN，authz-files-native-fix/。两个真实签名/新branch继承protectedfile正向兼容也先RED再GREEN，不放宽负例。 |
| LFS同OID/force CAS/普通不扩force | 旧CODE403删除已合法meta、internal-hook race覆写C→B、lease使普通rewind真实RED；精确新metaID、admittedoldlease+non-FF修正。最新Linux SQLite+真实LinuxPG三根exit0：authz-files-review-final-{sqlite,pg}.log；定向独立复核同样通过。 |
| PG一致快照/ticket/post | authz-root-final-linux/snapshot-ticket-pg.log exit0：真实PG独立writer在repeatable-read内撤grant，当组一致allow、下一请求deny；ticket伪造/owned不授许可。post实际ref退回old不能虚记success有效RED→GREEN，authz-post-terminal-actual-{red,green}.log。 |
| 格式/Go lint | make fmt exit0，authz-final-fmt.log；make lint-go exit0/Linux 0issues，authz-final-lint-go.log。最后生产/测试变更后均已重跑，退出0。 |
| JS/templates/JSON | make lint-js ESLINT_FILES=tests/e2e/enterprise-authz.authz.ts exit0；UV_CACHE_DIR仓库tmp make lint-templates exit0/591files0errors；eslint --config eslint.json.config.ts --max-warnings=0 对locale和Swagger2/OpenAPI3 exit0，authz-final-{lint-js,lint-templates,json-lint}.log。无CSS修改不额外要求CSSlint。 |
| Swagger | CGO_ENABLED=0 make generate-swagger、make swagger-validate 均exit0，authz-final-{generate-swagger,swagger-validate}.log。此前scratch execution.red.go被全源扫描失败，保留证据改.go.txt/overlay路径，不削弱generator；误用JS配置JSONignored warnings不算验证，已用真实JSONconfig重跑。 |
| Linux全backend环境 | Go1.27.1 LinuxARM64官方checksum校验SDK、独占非rootUID1000/HOME/TMPDIR/modulecache只读；native-environment-green.log：setting、cmd、migrations probe exit0。最后canonical及签名分类修正后 make test-backend GOTEST_FLAGS="-count=1 -timeout 40m -p 4" 实际exit0；authz-backend-final-linux/all-backend-final.log，242包ok、121包无测试、0失败；仅modelmigration与integration按Makefile独立验证，不以probe代替全量。 |
| 最新全入口统合 | authz-root-native-linux/run.sh build exit0，当前LinuxARM64纯Go Gitea/integration/core binary；core unit、专项HTTP/SSH签名、全 ^TestEnterpriseAuthz SQLite及真实LinuxPG17.9 均exit0/PASS；完整日志 authz-root-native-linux/{core-final,receive-signed-sqlite-final,receive-signed-pg-final,all-sqlite,all-pg}.log。每次同workspace串行、Linux tmpfs真实UID、最后PG数据库DROP/owncontainer及network清理；包含实际并发snapshot、old-ref race、LFS同OID、最新native撤销/force/签名/文件、全部Settings/access/lifecycle/merge/branch、API/UI服务器及原shadow/认证/migration兼容。browser opt-in按原合同skip，真实Chromium另见下节。 |

## 完整恢复演练（10.5）

`sh tmp/authz-rollout-linux/run.sh > tmp/authz-rollout-linux-final.log 2>&1` 实际exit0、ROLLOUT_BACKUP_RESTORE_PASS；匹配新版Linuxamd64 Gitea、UID1000、真实LinuxPG17.9，正式CLI迁移空库，非手改seed/schema/version。

- source实际停止后pg_dump -Fc +完整data/Git/LFS/resources/assets/config/matchedbinary tar，私有权限0600、SHA256通过。source之后真实API撤grant造成数据库摘要不同，证明不是自比较。
- 独立空DB single-transaction恢复，136public tables完整data/row摘要、全部sequence与DDL cmp0；资源恢复到独立空workspace，2149文件SHA256 cmp0。
- 真实restored server启动，旧historyIDs/roleRevision、PAT与Git README200断言；实际restart enforce→shadow→disabled→enforce：决策7→8/8→8/8→13，schema363/seed/history保留。
- pendingtransfer保持原owner/recipient；恢复enforce当前撤grant403，公开bindingAPI204显式恢复后accept202/owner变化；callback持续false。auto真实排队后跨模式/撤grant/实际后台deny见merge-report的Linux双DB实证，非复用申请时许可。
- 旧DB362迁移器/catalog/readiness真实编译，拒DB363与新20-action exactseed；真实进程退出1，version/seed不变。不能降schema/删seed欺骗旧binary。本次不是完整旧server/旧resources备份恢复，更不是生产RPO/RTO验收；安全回退为同新版切模式或匹配整套备份恢复。
- own source/restoreDB/container/network清理完成，备份留仓库tmp不上传。未清/停/修改任何其它项目runtime。

## 测试环境修复与真实限制

- 宿主首次全backend失败：cmd尝试宿主SSH写遭sandbox拒绝、配置gate尚未开放、gitlab.com FakeIP=198.18.0.148被原SSRFnative拒绝。Linux隔离HOME复跑cmd；官方TLS DoH的真实公开IP仅用于隔离测试container的add-host，network none，不改宿主hosts或生产SSRF/测试断言。
- 新HTTP/SSH签名负例捕获原native错误分类问题：Git pipeline返回errors.Join后，直接类型断言未识别errUnverifiedCommit，错误500且不给稳定未验证提示。真实双协议RED与原TestVerifyCommits新增识别断言RED保留，修errors.AsType解包，不删除签名断言/不放宽规则，最终重建验证。
- 首次Linux统合还捕获新签名测试SQL使用RuleName而实际存储列为branch_name，测试设置失败不是签名行为通过；修测试使用真实列后重建完整验证，保留all-sqlite-bind-env-failed.log。
- 第一次native全backend容器只有numeric UID而无passwd entry，OpenSSH签名原测试报 No user exists for uid1000；记录旧all-backend.log，修ownimage添加真实非root用户，不改签名代码/断言，旧已失败运行停止，最新版完整重跑exit0。
- 全backend隔离源码copy无Git元数据使原gitcmd测试报not a repository：仅为该fixture copy初始化空Git目录，不改当前repo Git状态；bind-mount UID映射使千文件fixture Git报dubious ownership，改为独占Linux tmpfs下的repo内TMPDIR/TEST_WORK_PATH并保持UID1000，不使用safe.directory=*或修改原测试。第一次tmpfs缺exec使Go测试binary permission denied，修自己mount加exec；已重新运行gitcmd/core两包exit0，全backend最新再次完整执行exit0。初次全integration重复创建/删除fixture还出现Git cwd已不存在，最新同样用Linux真实tmpfs完整重跑exit0，不虚称该旧运行成功。
- 团队授权UnitsMap最终统合发现v2 JSON map非确定顺序使相同intent偶发403；真实AccessTeamHTTPAndRollback失败及确定排序表示期望的单位RED保留，修为按unit Type排序数组且维持重复Type最后值语义，单位额外验证异序/真实mode变更/重复最后值。不会通过放宽intent匹配解决。
- 同一 root验证workspace并发跑迁移时harness重新copy已执行binary，统合进程exit135且无最终PASS；该旧运行不算通过。所有最终root单位→SQLite→PG串行运行，同workspace不再并发覆盖资源/binary，保留all-sqlite-canonical-and-overwrite-failed.log。
- make fmt扫描正在删除的测试运行目录曾失败，保留authz-final-fmt-during-tests-failed.log；停止旧运行、隔离动态tmpfs后重新make fmt exit0。
- LinuxAMD64仿真与并发编译曾触发shadow200ms/旧5s测试超时，未扩大预算/删除行数断言；改nativeLinuxARM64重跑并保留失败证据。真实HTTP/SSH端到端根可能12–17s，不冒称均达到2s/4s目标。
- PG早期部分切片为Linux被测Gitea+DarwinPG17.9，报告明确区分；最终统合、并发与恢复使用真实LinuxPG17.9。Linux测试容器/SDK/cache/备份均repo内，不写宿主modulecache/SSH、其他项目或生产。
- Chromium4/4是在Darwin浏览器访问开发测试server的独立UI证据，LinuxAPI/UI服务器另实跑；真实企微外部联调、生产部署/多实例滚动发布、断电持久性与其他数据库不在本次验收范围。
- 不承诺Git/对象存储跨介质物理事务：已准入LFS对象写后Git失败可留未引用内容对象，DBmeta只清本次新增ID，不破坏旧合法对象；证据不虚构ref成功或回滚。
- 未修改go.mod/go.sum，不运行make tidy；无CSS修改；没有自主提交/推送/发布/归档。OpenSpec结构校验不能代替代码验收。

## 最终独立复核与逐 requirement 确认

- execution-review.md保留初审3P1事实与 receive/files实际修复、RED及Linux复验；final-cross-domain-review.md另独立审查core/Git/merge/auto/access/lifecycle/固定维护，两个补强P1经真实RED→最终LinuxGREEN关闭，canonical未削弱intent并含duplicate动态断言。无未关闭已确认finding，不能把限定复核说成全仓安全审计。
- 两份delta specs的每个Requirement已对照上表、entrypoint-matrix及实际写边界/测试复查：模式/目录/原生并集/查询审计/协议兼容/写前准入/延迟merge/不可旁路Git/复合设置/授权委派/生命周期/错误/预算与当前政策/受限runner，以及历史UI/认证shadow兼容。50-task内容无漏接/placeholder/不可达mock；固定维护盘点已同步本change设计，不同步主spec。
- 最新前端lint/模板/JSON/Swagger、makefmt/Linuxgolint、Linuxbuild、363个backend包选择集及Linux双DB全部EnterpriseAuthz选择集通过。migration最新三root两库通过；其他首次初始化/旧binary/原nativeMerge等专项见独立报告，不把历史旧日志误称最新整套。
- 真实Chromium4/4日志 history-ui-browser-final.log / history-ui-browser-keyboard.log，截图在 tests/e2e-output/enterprise-authz.authz.ts--d634f-rate-from-business-outcomes-chromium/：enterprise-authz-enforce-deny-light.png、enterprise-authz-enforce-deny-dark.png、enterprise-authz-enforce-fallback-dark.png。目视核查含业务unknown与actualallow分离、暗色对比、键盘与XSS无执行，不冒称Linux浏览器。
- 最终gitdiff --check exit0、gitstatus/stat已保存，当前branch仍master；go.mod/go.sum/v361/前置verification/原repo_merge_upstream_test.go无改动。其余修改均对应本change真实入口/文档/测试/生成物，无临时debug.go进入待交付文件；自有Docker/PG全部清理，三个他项目lightrag容器未操作。
- 最终 `openspec validate enforce-enterprise-authz-high-risk-actions --strict` exit0（valid）；`openspec status --change enforce-enterprise-authz-high-risk-actions --json` 规划 artifacts 全部 done；`openspec instructions apply --change enforce-enterprise-authz-high-risk-actions --json` 实施50/50、remaining0、state=all_done。原始输出保存于仓库 tmp/authz-final-openspec-validate.log、tmp/authz-enforce-status-final.json、tmp/authz-enforce-apply-final.json；Markdown lint与git diff --check exit0。用户未授权commit/push/PR/部署/主spec同步/归档，本次不执行；也不声称生产已开启enforce。
