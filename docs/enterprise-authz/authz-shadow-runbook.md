# 企业仓库授权 shadow 运维手册

## 1. 发布边界

服务端永久仅面向 Linux；Windows 客户端仍可访问。此版本只观察、不阻断，原生账号状态、仓库/unit 可见性、SSH/PAT/Actions/deploy-key 限权、分支保护和企微治理继续决定实际结果。企业角色不能授予管理 API 访问权，也不会修改 membership、access、IsAdmin 或撤销凭据。

Callback 保持 `ADMIN_CALLBACK_ENABLED=false`。企微身份通过合法登录刷新和定时完整同步更新；不因启用 shadow 打开 callback，也不以旧 callback mock 测试代替真实协议启用 gate。Feature grant、merge gate、enforce、管理 UI 都不是本次交付。

## 2. 配置与预检

先停全部实例及 worker，备份配置/二进制、完整数据库及匹配时间点的 Git/LFS/附件等存储。确认同版 Linux 二进制的 `--help`，用服务运行用户执行批准的迁移：

```sh
/path/to/gitea --work-path /path/to/work --config /path/to/app.ini migrate
```

Migration 361 创建四张企业授权表、八个内置角色及 68 条显式 allow 权限，不回填绑定。它使用正常 schema-version 流程；版本表值是迁移编号加一，不手工改 version、drop 表或只恢复授权表。

```ini
[audit]
RECORD_OUTPUT = database
RETENTION_DAYS = 30

[enterprise.authz]
ENABLED = true
ENFORCE = false
FAIL_CLOSED_ON_ERROR = true

[enterprise.wecom]
ADMIN_CALLBACK_ENABLED = false
```

任意 `ENFORCE=true` 或非法布尔值都拒绝启动；shadow 开启但未配置数据库审计也拒绝。`FAIL_CLOSED_ON_ERROR` 仅预留给未来 enforce，两值在此版本都不能阻断原生请求。启动预检不会替运维开启审计或修复角色。数据库/磁盘运行时故障则产生证据缺口，不改变原生结果。

## 3. 管理与诊断

- 内置 Guest、Reporter、Developer、Reviewer、Maintainer、Security Maintainer、Owner、Platform Admin 不可编辑/删除；复制形成独立快照。
- 自定义角色支持 system/org/repo scope，主体仅 user/team/org。repo 是绑定作用域，不是主体。system 角色可用于下级作用域，org 角色仅本组织及其仓库，repo 角色仅本仓库。权限只允许 `allow`，未知 action、条件/effect 拒绝。
- system 管理需要真实原生管理员；企微启用时还需当前应用 active bound management authority。org 需真实组织 owner；repo 需符合原生 creator/owner/可信超管规则。Platform Admin 只可系统级绑定，不能自举为本地管理员。read/write token scope 仍按方法校验。
- API 前缀为 `/api/v1/enterprise/authz`、`/api/v1/orgs/{org}/enterprise/authz`、`/api/v1/repos/{owner}/{repo}/enterprise/authz`。共同提供 roles、bindings、decisions；action catalog 在 system `/actions`。repo 另有 GET `/effective-permissions` 和 POST `/evaluate`。完整字段/错误以生成 Swagger 为准。
- 更新/删除自定义角色须提交 `expected_revision`；版本冲突、内置变更、引用中删除返回 409。绑定 PUT 幂等，写入与管理审计同事务；403/404 不代表企业 role 能覆盖原生 authority。
- effective-permissions 是自查；查询其他主体需管理权限。evaluate 固定 `request_source=diagnostic`，不是实际操作、不会执行 Git 或修改仓库，也不能伪造 Web/SSH 来源。

## 4. 真实记录与解释

真实入口覆盖 metadata/code、HTTP/SSH clone、分支/file editor/receive、PR 创建/评审/merge（含 auto/force）、保护规则、CODEOWNERS、webhook/CI/secret、已有迁移目标、转移/归档/删除。`repo.manage_feature_grant` 仅目录/诊断，没有生产成功记录。

Candidate allow/deny/error 只是 action 判断，`candidate_only=true`、`safety_guards_evaluated=false`；不是完整 merge gate。native outcome 为 success/denied/failed/unknown，并区分 authorization/pre_receive/transport/operation/migration 阶段。SSH 授权通过、pre-receive 通过、异步排队或无实际推送的 no-op 不能冒充传输成功。只有候选 allow/deny 与明确 native success/denied 才能确定 mismatch。

受信 operation ID 关联一次操作；每 action/ref 有独立 observation ID，同 observation 重试去重，不合并不同请求。受管理的 service/hook 使用签名 ticket 保留 actor/source/凭据 ceiling；缺失/非法 ticket 报告缺口，仍按原生逻辑运行。

查询支持 actor/repo/action/decision/time 过滤及分页，每页最多 100，响应带 `X-Total-Count`。历史解释使用当时的受限快照，角色删除或 repo 转移不重新计算历史；已删除 repo 历史仅系统管理员可查询。目标创建前迁移失败只有用户/系统安全审计，不产生假 repo 决策或 mismatch。

## 5. 容量、隐私与缺口

每 observation 的评估和证据持久化共享 200ms 预算，snapshot 最大 64 KiB；集合按实际返回资源记录，大仓库/搜索/频繁 push 可显著增加写量。上线先测数据库连接池、写延迟、磁盘增长，按实际每秒观察量和记录大小预算容量，不把 200ms 当作请求整体延迟上限或 SLA。

`enterprise_authz_observation_failed_total{reason=...}` 计数缺口；`enterprise_authz_observation_failed` 警告按安全 reason 每分钟限流。重点检查 `policy_read_failed`、`evidence_persist_failed`、`observation_timeout`、`observation_canceled`、`snapshot_limit_exceeded`、`business_transaction_active`、`invalid_observation_context`。计数增长而无记录不代表原生拒绝，更不能宣布“所有操作都已审计”。

证据只保存本地安全 ID、固定 action/source/stage/reason、角色版本/权限摘要和条件指纹；不记录 token/secret/OAuth code、callback/source URL、请求正文、手机号/邮箱、私密路径原文或原始错误。仅使用受权 API/既有审计导出，不把 DB dump 或故障原始输出上传工单。

沿用 audit retention cron 分批清理 audit 与 decision；`RETENTION_DAYS=0` 保留全部。按部署配置确认清理 cron 注册和实际运行，不将未跑 cron 误认为自动清理；索引和留存测试不能替代生产容量监控。

独立 audit 留存任务与请求观察器分离：关闭 shadow 后仍按既定期限共同清理旧 decision 和 audit，不加载角色、不评估、不写新决策。原生请求内零企业查询的约束不禁止该历史清理；永久保留（期限 0）始终不删除。

## 6. 配置关闭与同版恢复

1. 保存当前配置、版本、policy revision 和安全缺口计数。批准后将 `ENABLED=false`，保持 `ENFORCE=false`；企微登录/cron/callback 配置不随之变更。
2. 停全部实例/worker，确认退出，再同版重启。未重启实例和在途请求不保证已停止观察。
3. 验证原生读写/认证仍正常，新增决策停止，authz API 在原生权限检查后返回 404。关闭不删除已有 policy/history；原生对象删除仍会同事务清理 live 策略引用。
4. 修复数据库/容量/配置后，同版重新启用并重启；验证新增真实决策与安全审计成对出现，旧 role revision、原生权限和凭据状态不变。不要用诊断成功替代真实入口验证。

## 7. 完整备份恢复与二进制回退

Additive migration 不代表旧版本能读新 schema；旧版会拒绝较新 version。**禁止手改 version 或删除新表以骗过版本保护。**

在隔离 Linux 环境演练，禁止指向生产/共享测试库：

1. 完全停写，记录备份时间/RPO；备份整个 PostgreSQL（custom-format `pg_dump`）、配置、匹配二进制和 Git/LFS/附件等完整存储，限制备份权限并校验摘要。
2. 用新版本迁移/启动，核对八角色/68 权限、无自动绑定、原生权限/凭据不变。执行真实 shadow 操作、policy 更新，再关闭/恢复观察，记录新旧计数。
3. 模拟需回退时先备份事故现场并停全部进程；评估备份之后丢失的仓库/DB/存储写入，取得恢复审批。不允许在线恢复部分表。
4. 向已确认隔离的空/专属数据库使用 `pg_restore --clean --if-exists --single-transaction` 恢复**整库**，成套恢复同时间点配置、二进制及存储。核对全部表数据、列/索引/约束、sequence、version、存储和配置摘要。
5. 用匹配备份版本启动，验证原生仓库读写/登录/凭据及管理 guard；需要重新升级时只走正式 migration。保持 callback 关闭，不留临时本地密码后门。

若目标旧二进制/备份或完整存储不可得，则不能声称已完成降级；保持停写并上报明确缺口。隔离演练结果不代替生产恢复审批或真实企微联调。

本 change 的实跑证据位于 `openspec/changes/add-enterprise-authz-foundation-shadow/verification.md`；其中区分 PostgreSQL/SQLite、macOS 开发验证与 Linux 运行验证，不宣称未测数据库或 Windows 服务端兼容。
