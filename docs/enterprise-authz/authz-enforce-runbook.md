# 企业仓库高风险授权 enforce 运维手册

## 发布与原生边界

服务端仅部署 Linux。本文是高风险 enforce 的追加交付手册；[原 shadow 手册](authz-shadow-runbook.md)与既有企微治理时间线保留，不把旧版本“不支持 enforce”的声明改成已发布事实。首次启用前确认运行的是已完整接线、支持该开关的新版本，不只替换配置。

固定 enforce 集合为 `repo.merge_pull_request`、`repo.push_protected_branch`、`repo.manage_branch_protection`、`repo.manage_codeowners`、`repo.manage_webhook`、`repo.manage_ci`、`repo.manage_secret`、`repo.manage_access`、`repo.transfer`、`repo.archive`、`repo.delete`。普通读写/branch/tag、PR 创建/评审、`repo.migrate` 不因 Risk 自动进入集合；feature grant 仍仅目录/诊断。secret 不可读，workflow dispatch/run/cancel 不是 CI 管理变更。

实际许可是**当前原生 action 能力与匹配企业角色 allow 的并集**，再与原生认证、凭据 ceiling、scope/unit/资源可见性及动作安全守卫相交。企业角色不是 native permission 替代品：不能升本地管理员、组织 owner/team 管理资格、读 token 写权限、force merge、mirror/danger-zone 资格，不能突破 checks/review/签名/文件/企微治理。原生 Admin 自有 webhook/CI/protection 能力仍保留；Admin 不是 secret/protected push/access/transfer/archive/delete 的统一默认许可。

各入口保留自己的原生差异，例如 API Admin 归档与 Web danger-zone 不相同。不要为让角色生效而放宽路由原生访问条件；按钮可达也不是后端已准入。管理 API/UI 的 authority 继续独立校验，企业 Platform Admin 不赋予管理角色/绑定的访问权限。

## 配置、迁移与统一切换

停所有实例和 worker、确认在途写入结束，备份整库及匹配二进制/assets/配置/Git/LFS/附件存储。在隔离环境验证新版 migration 和 readiness 后，以服务用户运行正式 `gitea ... migrate`；不手改 `version`、补 seed、重跑旧 migration 或只恢复授权表。

当前目录为 catalog v2，additive migration 只给内置 Owner/Platform Admin 补 `manage_access`，不自动加绑定、不改旧自定义复制角色，也不重算旧历史。老 catalog v1 记录仍按当时白名单解释。

| 模式 | ENABLED | ENFORCE | 业务结果 |
| --- | --- | --- | --- |
| disabled | false | false | 原生行为；请求不评估企业策略、不新增决策 |
| shadow | true | false | 仅候选观察，失败不阻断原生行为 |
| enforce | true | true | 固定高风险 action 在首副作用前准入 |

`ENABLED=false,ENFORCE=true` 和非法布尔值拒绝启动。shadow/enforce 都要求数据库审计和完整 schema/seed readiness；不会自动开启审计或修复策略。初次上线用 shadow 比对差异，为真实可达而缺许可的主体显式授权，再批准统一切换；不能把请求字段或诊断 allow 当作执行许可。

```ini
[audit]
RECORD_OUTPUT = database

[enterprise.authz]
ENABLED = true
ENFORCE = true
FAIL_CLOSED_ON_ERROR = true

[enterprise.wecom]
ADMIN_CALLBACK_ENABLED = false
```

所有实例、worker、内部 hook 所用配置与匹配二进制必须一致并重启，禁止长期混跑 shadow/enforce 形成旁路。企微 `LOGIN_ONLY`、合法 OAuth/MFA、身份/authority 同步配置不随模式变化；SSH/PAT/API/Git HTTP/Actions/deploy 认证不转去调用企微 OAuth。callback 持续关闭，不开本地密码后门。

## 执行证据，不把准入当成功

实际副作用前重新加载 actor/owner/当前 native permission/凭据范围与一致政策，全部 actions 一次准入；CI+archive、protection+required checks 的任一拒绝都发生在业务首写之前。跨进程、auto 队列、pending transfer 的实际执行重新建立边界，不保留长期 allow。检查边界之后的政策撤销不追溯取消已准入操作，但下一次执行必须读取当前政策。

| 字段 | 解释 |
| --- | --- |
| `candidate_decision` / `candidate_only` | evaluator 的部分判断；诊断永远仅候选，不保证安全守卫全部通过 |
| `decision_mode` | shadow / enforce；旧记录保留 shadow 解释 |
| `authorization_decision` | `not_enforced` / `allow` / `deny` / `error` / `fallback`，与候选分开 |
| `authorization_reason` | 本次实际准入的安全固定原因 |
| `execution_started` | 首副作用前 Start 证据已确认，不表示事务已提交或 Git 已传输 |
| `native_outcome` / `native_stage` | 真正业务 success/denied/failed/unknown 及所处阶段 |

allow + started + unknown 不能显示“业务成功”；pending transfer/auto 排队不是最终完成。业务终态证据更新失败不能撤销已提交业务或改写真实 HTTP/Git 结果，应保留 unknown 并告警。fallback 是故障窗口下执行原生路径，不是企业角色授予 allow；UI/导出要显式区别。operation/ref/对象意图不同不得复用 admission；诊断、旧 shadow ticket、observer 都不是许可证。

历史查询/API/UI 沿用当前 native authority、scope、每页最多100和后端目录；老/删除 repo 的历史不重新算角色。记录只保存安全 ID、固定 action/source/stage/reason、角色 revision/条件摘要与路径哈希，不泄露 token、secret、OAuth code、body、私密路径原文或原始错误。禁止把完整 DB dump 上传工单。

## 机器身份

- repo runner registration：actor0，当前有效且精确绑定该 repo 的 registration token，只能机器 NativeOnly `manage_ci`；不借发行者/owner，人类 roles 不参与。org/global token 保留原生非 repo 注册规则。
- Actions：actor -2，只接受已原生认证的确切 task 身份，重新检查当前任务 running/cancelling、未撤销 token 与当前 workflow/repo 权限。fork/read-only/scope/cross-repo 限制保留，不借 owner 的 Admin action。
- Deploy：actor -3，确切 deploy-key 身份、当前 repo/mode/key 存在性；仅原生 code/wiki 能力，read-only 不写，无人类 role。

actor0 或负 ID 本身不是通用系统豁免；未知负 ID、positive human+机器 Ext、nil actor、`system` 字符串/header、伪造/错 repo ticket 均不能准入。维护只有明确受信 caller 的私有绑定适配；历史 UI 使用机器名称，凭据 reference 裁掉，不展示 token。

## 故障、预算与可观测性

准入固定总预算1s（含准备、快照与前置证据），shadow 200ms；受控条件所需完整路径最多1024，bulk team/access 全部现有 repo 最多1000。超限拆分操作，不截断后冒充完整，不把普通无受控 action 大 diff 纳入新拒绝。预算不是整个请求/业务执行 SLA。

| 情况 | Web/API/Git 行为 |
| --- | --- |
| missing_action、条件不匹配或未能解析为明确 allow | 安全403 / Git拒绝；即使 fail-closed=false 也拒绝 |
| 原生认证/scope/不可见资源/安全守卫拒绝 | 保留原401/403/404等隐私语义与 native Git 拒绝 |
| 当前 native actor/repo/permission 读取失败 | 安全503 / Git拒绝；无法确认原生资格，即使 fail-closed=false 也不降级 |
| 不可信 actor/credential/target/ticket、超限/不完整差异、客户端取消 | 安全拒绝；不可 fail-open |
| 授权基础设施读失败、1s超时、前置 decision/audit 写失败 | 默认503 / Git拒绝；没有首副作用 |
| 显式 `FAIL_CLOSED_ON_ERROR=false` 且只有可降级基础设施故障 | 恢复未叠加角色的原生路径；可保存时记 fallback |
| 执行后终态证据更新失败 | 保留真实业务结果，unknown + 缺口告警 |

Git 只输出固定安全拒绝原因，不回显 SQL、路径/内容或原始子进程错误。明确 deny 与另一 action 的 DB 错误同时发生不能将全组 fail-open；原生资格读取和守卫自身错误不属于可降级集合，角色/策略表或前置证据的故障才可按配置退回已确认的原生路径。证据全存储故障时只能记录安全日志/指标，不能宣称“已完整审计”。

监测实际实现的指标：

- `enterprise_authz_execution_decision_total{action,decision}`：allow/deny/error/fallback 准入计数。
- `enterprise_authz_execution_failed_total{reason}`：拒绝/安全证据缺口；重点关注 `policy_read_failed`、`evidence_persist_failed`、`execution_timeout`、`execution_canceled`、`invalid_execution_context`、`context_limit_exceeded` 与 bulk limit。
- `enterprise_authz_execution_duration_seconds`：准备、评估、证据准入延迟；监控接近1s比例、DB连接池/写延迟/磁盘增长。
- `enterprise_authz_observation_failed_total{reason}`：shadow观察缺口；与真实拒绝计数分开。

日志按安全原因限流，不能以低日志行数判定无缺口。保留 audit retention 的历史共同清理语义；disabled 不删策略/历史，也不停止既定留存清理。

## 降级窗口与恢复演练

1. 保存各实例版本/配置、policy revisions、operation/decision ID 边界、待执行 transfer/auto 队列与安全指标。为降级登记负责人、原因、开始/截止时间和恢复条件；不要默默把 fail-closed 设 false。
2. 优先同版 `ENFORCE=false` 转 shadow；必要时 `ENABLED=false,ENFORCE=false` 恢复原生路径。停写、统一切换/重启全部实例与 worker；不重放已提交 mutation，不用模式切换取消原生业务事务。
3. 验证原生认证/读写、token scope/revocation、read-only、callbackfalse；shadow新增候选而disabled不新增。schema/version/seed、自定义 role/binding、旧历史与 native权限/凭据应保留。
4. 恢复前在隔离 Linux环境重做当前政策准入。已批准 pending transfer 的接收者仍需当前 action/native资格；排队 auto 也需执行时重新检查，不复用模式切换前的许可。确认旧缺口与新终态没有误标成功，再统一恢复 enforce/fail-closedtrue。
5. DB/存储恢复先停写、保全现场新增历史并确认RPO/RTO。使用完整 PostgreSQL `pg_dump -Fc`，同时备份匹配配置/二进制/assets和同时间点Git/LFS/附件；校验摘要、限制权限。用独立 test DB 执行 `pg_restore --clean --if-exists --single-transaction`，核对所有表数据/DDL/索引/约束/sequence/version及资源摘要，实际运行匹配二进制验证。
6. 同版三模式回退不需也不允许降 schema/seed。旧二进制若不识别新schema/exactseed，必须拒绝启动；不能改 version/drop新表/删除manage_access来骗过。真正退旧版需经验证的完整旧备份DB+资源+配置，保全备份之后的新增历史并取得恢复审批。只有旧 gate 探针而无旧完整server/resources，不能宣称已完成旧版本生产恢复。

隔离演练不接生产库、不安装本地登录后门，也不代替生产审批或外部企微联调。当前 change 的实际命令、环境、失败及恢复证据写入其 verification；未执行的恢复层不得标成已完成。
