# 企业合并门禁运维

## 实施状态

本 change 仍在实施验收。普通 Merge、force、auto schedule/worker、manual marker/后台识别、受信 hook admission、终态对账及 PR merge box 已接线；定向单测和 Chromium 组件回归不等于全入口/Linux 上线证明。最新本轮 Linux SQLite/PostgreSQL 故障、并发、重启和协议矩阵尚未完成，Docker daemon 当前不可用。未完成验收前保持默认关闭，不宣称生产防护已全面验收。任务和真实证据分别见 `openspec/changes/add-enterprise-merge-gate/tasks.md` 与 `verification.md`。

## 配置和依赖

```ini
[enterprise.authz]
ENABLED = true
ENFORCE = true

[audit]
RECORD_OUTPUT = database

[enterprise.merge_gate]
ENABLED = false
ENFORCE = false
```

门禁默认关闭；`true,false` 为候选观察，`true,true` 为强制准入。强制模式另要求 action authz 强制开启；即使 action authz 设置 `FAIL_CLOSED_ON_ERROR=false`，门禁仍固定故障关闭。enabled 要求完整审计 schema、两表及索引、内置 Owner/Platform Admin 两个新 action seed。缺失配置或 schema 必须修复正常迁移，不修改 version 表，不手工造 seed。

新 additive migration 为 364，执行完成后的 DB version 为 365；action catalog 为 3。原 version 1/2 决策仍按各自历史目录解释。仅内置 Owner/Platform Admin 默认新增 `repo.manage_sensitive_paths` 和 `repo.bypass_merge_gate`；原生 Admin、Maintainer、Security Maintainer 或旧自定义角色不自动获得这两项能力。

## PR 预览与历史 API

- GET `/api/v1/repos/{owner}/{repo}/enterprise/merge-gate/{index}`：当前 code/PR reader 与 repository read scope；可选 `style` 为 merge/rebase/rebase-merge/squash/fast-forward-only/manually-merged；manual 另传 `commit_id`，必须有受信 receive 历史证明，缺失显示 error，仍是只读 preview。返回当前 head/base、mode、preview_only、安全 reason/descriptor，不返回原始 context、上级策略 ID、快照或自由文本 bypass 理由。不写 merge/feature 准入证据，Cargo index 也仅做只读资格检查。
- GET 同前缀 `/{index}/evaluations` 与 `/{index}/evaluations/{id}`：另要求当前仓库策略管理 authority，拒绝 public-only 凭据。分页及 `X-Total-Count` 与规则 API 一致；ID 同时限定当前仓库/PR，未知快照版本返回 503。历史不可复用为执行许可。
- readonly 凭据的候选合并仍受 write ceiling 限制；reader 获得解释不等于获得 merge/bypass 权限。shadow 标记 `not_enforced`，enforce 预览标记 `not_admitted`。

## 三作用域规则 API

前缀（以部署 ROOT_URL 为基准）：

- `/api/v1/admin/enterprise/authz/protected-path-rules`：当前可信系统管理 authority，admin read/write token scope。
- `/api/v1/orgs/{org}/enterprise/authz/protected-path-rules`：当前组织管理 authority，organization read/write scope。
- `/api/v1/repos/{owner}/{repo}/enterprise/authz/protected-path-rules`：当前仓库管理 authority、原生 code visibility，repository read/write scope；写入另要求 `repo.manage_sensitive_paths`。

GET 列表支持 `page`（默认 1）和 `limit`（默认 20、最大 100），返回 `X-Total-Count`；GET `/{id}` 返回当前作用域规则。POST 创建使用 revision 0；PATCH `/{id}` 使用当前 revision；DELETE `/{id}?expected_revision=N` 保留墓碑，成功 204。跨作用域 ID 不可读写；错误分别为 401/403/404、版本冲突 409、无效输入 422、基础设施故障 503。shadow 下管理权限同样严格；原始规则管理读写均拒绝 public-only 凭据。

```json
{
  "config": {
    "path_pattern": "k8s/**",
    "branch_pattern": "release/*",
    "required_role_id": 123,
    "check_contexts": ["security/gitleaks"],
    "enabled": true
  },
  "expected_revision": 0
}
```

路径仅为用户自行选择的示例，**不会自动创建或默认套用**。角色必须使用真实可见的稳定 ID。path/branch glob 各最多 256 字节；配置最多 16 KiB；最多 64 个 case-sensitive exact context，每个最多 128 字节。拒绝重复、未知、null、非法 UTF-8/控制字符、secret/命令/URL 字段及越界输入。相同规范化配置且 revision 正确的重试不增加版本或重复变更审计；旧 revision 不因内容相同而成功。

global → 当前 owner org → repo 规则累加，个人仓库跳过 org，不存在下级覆盖。仓库转移后旧 owner 的 repo 规则变为 unresolved，新 authority 必须明确 PATCH 修复 owner/角色，不自动撤销敏感治理。角色改名不改变引用 ID；活动启用规则引用的角色不能删除，必须先处理规则引用。repo/org 删除使其规则成为停用墓碑，evaluation 和审计历史保留。

## 最终合并合同与未验收入口

- required feature/path context 使用 exact 大小写匹配；原生 required check 保留 glob。只认 base repo + 当前 head 最新 status；原生 success/skipped 通过，企业 feature/path 仅 success 通过，skipped 阻断。required 有效 contexts 为空必须报告未就绪；enabled 不隐式变为 required，disabled 不撤销其他来源的要求。
- force 保留 `force_merge`，最终 enforce 客户端须额外提交 `bypass_reason` 和 `bypass_categories`。理由去首尾空白后 1–1024 字节、有效 UTF-8、无控制字符；需 merge action、独立 bypass action、原生 bypass 和有效凭据。
- 仅七类可显式豁免：`required_approvals`、`rejected_review`、`official_review_request`、`codeowners_review`、`required_check`、`sensitive_path_approval`、`sensitive_path_check`。其他 mandatory guards、签名、protected files、outdated branch 和任何 error 不可豁免；未选择项仍阻断。没有阻断时记录 requested/not-used，不虚构 bypass。auto 的排队及执行均不得携带 bypass。
- 完整 diff、可信 base CODEOWNERS、当前 head 的有效独立 reviewer 及当前角色身份是敏感规则的验收前提，不能拿预览或排队结果当作执行票据。
- status writer 是信任边界：有合法写权限的主体可能写入同名成功结果，context 名称不是供应商签名证明。使用最小权限 bot、独立受控流水线和凭据轮换；本功能不执行 scanner/AI，不下发云 token，不制造 status，也不自动创建 provider integration。
- manual recognition 是事后治理：Git ref 已写入，拒绝标记不能声称阻止或回滚此前直接 push。直接 push 仍遵守现有 receive/保护分支规则；不得用 Owner 代替未知 pusher。

## 终态、崩溃与对账

- 准入 evaluation 和强制 audit 原子提交后才开始 Git/marker；拒绝独立提交，不随业务回滚丢失。错误或 evidence 失败返回 503，不能继承 action fail-open。
- `SetMerged` 在业务事务中额外写 `enterprise:merge-gate:marker` 收据，绑定 evaluation/operation/PR、snapshot hash 和实际 result SHA。仅有 Git 包含提交或 PR 已 merged 不足以证明某次 operation 成功。
- 普通执行与对账均要求同一 operation 的 marker 收据。终态 audit 失败返回 `merge_gate_terminal_unknown`（503），原记录可能保留 `started`；Git/PR 可能已改变，503 不等于未执行，不要盲目重试。
- `reconcile_enterprise_merge_gate` 启动时和每五分钟扫描超过十分钟的 `started/unknown`，分页且每条持 PR lock，依据可信目标分支、PR merged SHA 和匹配 marker 修正证据。没有完整因果证明则保持 `unknown`；不重 push、不改 PR、不猜成 failed/succeeded，不覆盖封存快照。运行中的前十分钟不是 crash 证明。
- 丢失 marker、原始 manual receive provenance、已删除资源或审核证据的记录只能保留待调查状态。由受权人员通过 history API 和现有受限审计核实，不手工改 evaluation/DB version，也不删历史。
- Linux SQLite/PostgreSQL 已实跑终态故障、取消/超时与独立进程重启对账，验证 started/unknown 只修证据、不重 push。请求取消后 Git/PR 可能已写成功但终态仍 unknown/503，应按 history/marker 对账，不能把503当成未执行。测试使用隔离 fixture 跨过保护窗口并调用真实 reconcile，不由 cron 注册推导实际墙钟调度或生产重启已验收。

## 自动合并和事后识别

schedule 的 waiting/not_admitted 不是长期 merge 许可。queue ID 与原 actor/资源/凭据归因同事务保存；worker 复核当前 token/SSH key/账号、权限和策略，原 ceiling 与当前 ceiling 取交集。public-only 和组织资源限制不能因排队后 token 扩权而扩大；PAT generation 变更、凭据吊销或历史归因缺失需重新排队，不保存 bearer。内部签名密钥轮换可能使旧 generation 不再有效，应受权重新排队，不手工补 attribution。

status/review/conversation 和 role/rule/feature 变更可重新触发。策略/讨论变更只在提交后唤醒；现有 unique queue 去重。同 queue、同完整 fingerprint 的明确 deny 保持暂停，不重复生成准入尝试；事实变化后才重新评估。enforce 启动时分批复核所有仍排队的 PR（不限于最近 24 小时），补偿离线期间丢失的唤醒。replace/cancel 保留旧证据但使旧关联失效；自动路径不能继承 bypass，分支清理也不能凭裸 actor 重建无限凭据。

manual receive 捕获真实 old/new refs、PR head 与 pusher/凭据归因；目标分支后续推进不抹掉已有证明。active marker 仍遵守独立有限 bypass，后台从原 receive pusher 重新校验，不用最新 branch pusher 或 Owner 代替。未知 provenance 保留 `git_already_present=true` 的 error/not_started，ActorID=0 只表示无法确认的历史主体，不能准入、启动或 bypass。没有原始非零历史 diff 则不标记 PR merged，已写 Git 不被伪装为遭阻止。

## shadow → enforce 与回退

完成全入口、凭据、并发、故障、恢复和 Linux SQLite/PostgreSQL 验收后，先统一所有实例/worker 的 shadow 配置，核对候选原因、旧 force/queue 行为及原有 authz/feature enforce；通过后再经运维授权切换 enforce。merge box 现提供安全 typed reasons、普通/bypass 区分、必填理由/显式类别、shadow/unknown 提示和手动证明输入；浏览器按钮不是权限或准入票据。

Web 沿用当前原生 `http.NewCrossOriginProtection` 的 Origin/Fetch Metadata 边界，不新增登录旁路或自造 CSRF token。API 沿用原 credential scopes，rules/history 原始管理数据继续要求当前 scope authority，shadow 也不放宽。隔离 Linux 服务上的真实 Chromium session 跨来源 POST 已验证403且 PR/ref不变；按钮隐藏和客户端表单校验不能替代服务端校验。

紧急回退只切换模式并统一实例配置；`ENFORCE=false` 撤销新增强阻断但保留候选，`ENABLED=false` 停止门禁查询/证据，均不关闭原有 action/feature/receive 守卫。回退会放宽治理保障，应记录审批与风险。保留两表、action seed 和审计历史，不删表、不倒改 DB version。旧 binary 的降级仅使用匹配的完整 DB+Git/storage/queue/配置备份，不改企微 LOGIN_ONLY 或 callback。生产部署/重启不属于本次授权。
