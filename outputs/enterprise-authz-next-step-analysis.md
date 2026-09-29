# 企业授权系统现状分析与下一步建议

分析日期：2026-09-29
分析范围：`feature/enterprise-authz` 当前分支、未提交工作区、`docs/enterprise-authz/`、OpenSpec 变更 `wecom-only-web-login`

## 结论摘要

**当前不应直接进入企业授权 overlay（角色、repo action、feature grant）开发，也不应归档 `wecom-only-web-login`。**

当前实现已经形成企业微信 Web 登录的主要骨架，但仍处于“功能代码基本成形、尚未达到可上线完成定义”的状态。OpenSpec 显示 38/38 任务完成且 strict validation 通过，只能证明任务清单被勾选且文档结构有效，不能替代代码审查、运行时集成和生产验收。

建议先创建一个短周期的 **Phase 1 收敛/加固批次**，优先解决密钥泄漏风险、启停语义、登录锁死风险、同步未接线和同步一致性。完成后再归档当前 OpenSpec 变更，随后进入 Phase 2，而不是跳到 Phase 3。

## 1. 当前状态

### 1.1 Git 与变更状态

- 当前分支：`feature/enterprise-authz`
- 相对远端同名分支：ahead 2
- 已修改 tracked 文件：16 个
- 未跟踪文件：32 个
- 涉及 Go 文件：30 个
- 工作区包含较大规模未提交实现，不适合在未完成安全和集成审查前直接归档或发起合并。
- 分支中的 `chore(dev): configure go module proxy` 与企业鉴权功能不是同一业务关注点，后续准备 PR 时应确认是否需要拆分；不要重写历史，可通过新分支或正常后续提交处理。

### 1.2 已实现的主干能力

当前代码已覆盖以下骨架：

1. `[enterprise.wecom]` 配置与 secret URI 读取。
2. 企业微信 OAuth provider 和授权 URL 构造。
3. OAuth callback 后的 `userid` 解析与企业边界检查。
4. `wecom_identity`、department、tag、membership 模型及 migration。
5. 首次登录创建 Gitea 用户与身份绑定。
6. login-only 模式下隐藏或拒绝密码、注册、OpenID、Passkey、非 WeCom OAuth2 Web 登录入口。
7. 登录、拒绝、身份绑定、同步审计事件。
8. PAT、Git HTTP Basic token、SSH key 查找路径的兼容性测试。
9. 部门、成员、标签、membership 的幂等 upsert 服务。

当前主登录链路可概括为：

```text
[enterprise.wecom]
        |
        v
Generic OAuth2 source -> WeCom provider -> WeCom API
        |                                  |
        +------------ callback ------------+
                         |
                         v
            services/enterprisewecom/login
                         |
          +--------------+---------------+
          v                              v
   wecom_identity                 Gitea local user
                                          |
                                          v
                         external_login_user + Web session
```

目录同步目前是孤立能力：

```text
SyncDirectory() -> upsert snapshots
      ^
      |
  无 cron、无 API、无启动调用点
```

### 1.3 已执行验证

| 验证 | 结果 |
| --- | --- |
| `make help` | 已执行，确认 `fmt`、`lint-go`、`test-backend`、`test-integration` 等目标 |
| `openspec validate wecom-only-web-login --strict` | 通过 |
| `gofmt -d`（所有改动 Go 文件） | 无差异 |
| `go vet`（相关包） | 通过 |
| 新增配置、模型、provider、登录、同步、Web guard、PAT/Git HTTP/SSH 聚焦测试 | 通过 |
| migration 聚焦测试 | 通过 |
| 相关包完整 `go test` | 未完整完成；当前设备禁止 `httptest` 监听本地端口，导致已有 HTTP 测试 panic，属于执行环境限制，不能据此判定代码失败，也不能声称完整测试已通过 |

## 2. 需求与实现差距

## 2.1 P0：归档或合并前必须解决

### P0-1：HTTP 错误可能把 CorpSecret、access token 或授权 code 泄漏到日志和页面

证据：

- `services/enterprisewecom/client.go:78-88` 把 `corpsecret` 放入请求 URL。
- `services/enterprisewecom/client.go:104-114` 把 `access_token` 和 `code` 放入请求 URL。
- `services/enterprisewecom/client.go:137-145` 直接返回 `http.Client.Do` 的原始错误；Go transport 错误通常包含完整 URL。
- `routers/web/auth/oauth.go:148-160` 将 callback error description 写日志，并可能放入通用错误提示。

现有测试只验证审计数据库 metadata 不含敏感值，没有验证应用日志、Flash 消息和 HTTP transport error 的脱敏。

**建议：**

- 在 WeCom client 边界统一包装并脱敏 transport 错误，不向上层返回含 query string 的错误。
- callback 对 WeCom 错误只记录固定 reason code，详细内部错误也必须经过脱敏。
- 增加日志捕获测试，覆盖 `corpsecret`、`access_token`、`code` 不出现在日志、页面和审计中。

### P0-2：`ENABLED=false` 没有真正禁用 WeCom 登录源

证据：

- `EnterpriseWeCom.Enabled` 只参与 `EnterpriseWeComLoginOnly()`。
- `routers/web/auth/oauth.go` 对任何 provider 类型为 `wecom` 的 source 都执行企业微信专用登录处理，没有检查 `EnterpriseWeCom.Enabled`。
- `services/auth/source/oauth2/providers_wecom.go` 也没有把 `ENABLED=false` 作为 provider 不可用条件。

因此，只要数据库里存在活跃 WeCom OAuth source 且仍配置了必要字段，`ENABLED=false` 仍可能允许该登录路径，与“disabled-by-default preserves existing behavior”不一致。

**建议：** 明确定义并实现启停语义：当 `ENABLED=false` 时，WeCom source 不展示、不能发起、callback 也应拒绝；增加 disabled-mode 正反测试。

### P0-3：login-only 可在没有可用 WeCom source 时锁死全部 Web 管理员

配置校验只检查 CorpID、AgentID 和 secret，不确认数据库中是否存在且仅存在预期的活跃 WeCom auth source。若启用 `LOGIN_ONLY=true` 但 source 未创建或失效，系统会关闭其他 Web 登录入口，却没有可跳转的企业微信入口。

**建议：**

- 增加运行时 preflight/health check，至少检测活跃 WeCom source 数量与 provider 初始化是否成功。
- 明确两阶段上线流程：先创建并验证 source，再开启 login-only。
- 提供离线恢复 runbook，并在部署文档中写明验证和回滚步骤。
- 增加“0 个 source”“1 个 source”“多个 source”“source 初始化失败”测试。

### P0-4：目录同步没有接入系统执行路径

全仓搜索显示 `SyncDirectory` 只有定义和测试调用；`SYNC_INTERVAL` 只被读取和测试，没有 cron、worker、启动任务或管理 API 使用它。

这意味着任务 5.1/5.2 和规范中的“启用时系统 SHALL synchronize”尚未真正完成。

**建议：** 使用仓库现有 `services/cron.RegisterTask` 模式接入周期同步，并补充受 site admin 权限保护的手动触发/状态查询入口；若决定把自动同步留给下一变更，应立即缩小当前 proposal/spec 范围并把相关任务恢复为未完成，而不是维持 38/38。

## 2.2 P1：进入真实部署前解决

### P1-1：同步只有 upsert，没有完整快照对账

当前同步不会：

- 删除已经不再存在或不可见的 department、tag、membership；
- 把离职、禁用或移出应用可见范围的 identity 标记为 `left` / `inactive` / `out_of_scope`；
- 在仅开启 tag 同步时为 tag member 创建 identity snapshot；
- 在中途失败时回滚已写入的部分数据。

结果是离职成员可能继续保持 `active`，陈旧 membership 可能继续参与未来授权映射。这与登录拒绝和未来授权安全边界直接相关。

**建议：** 使用带 sync generation/batch ID 的全量快照对账，在事务中完成 upsert、缺失项失效和陈旧关系清理；只有完整批次成功后才切换当前快照。

### P1-2：WeCom client 的超时、取消和 token 使用方式不适合生产

- 默认使用无总超时的 `http.DefaultClient`。
- 目录接口使用 `context.Background()`，丢失调用方取消和服务关闭信号。
- 每次列部门、成员或标签都会重新获取 access token，大型组织会放大请求量和限流风险。

**建议：** 让目录接口显式接收 `context.Context`；配置有限 HTTP timeout；缓存 access token，并在过期前安全刷新；对 WeCom 限流和瞬时失败使用有上限的退避重试。

### P1-3：首次创建 Gitea 用户与身份绑定不是同一事务

`AuthenticateOAuthLogin` 先创建用户，再单独绑定 identity。并发首次登录或唯一键冲突时，可能留下没有 WeCom binding 的孤立用户。

**建议：** 使用仓库约定的 `db.WithTx` / `db.WithTx2` 把用户创建、identity binding 和必要的 external login linkage 收敛到一致性边界；增加并发和失败回滚测试。

### P1-4：兼容性测试强度低于需求陈述

- SSH 测试只验证 key 插入和查询，没有运行真实 SSH auth path。
- Git HTTP 测试验证 Basic token 解析，但没有覆盖 clone/fetch route 与 repo 权限。
- 缺少完整 Web integration/e2e：真实 state session、mock WeCom API、callback、session 建立、再次登录和禁用身份。
- 缺少多数据库 migration 验证。

**建议：** 保留现有快速单测，再增加最少数量的 integration tests：

1. mock WeCom 服务完成真实 OAuth state/callback；
2. login-only 下非 WeCom Web 路径 403；
3. SSH/PAT/Git HTTP 完整认证入口不受影响；
4. migration 至少进入现有数据库 CI 矩阵。

### P1-5：部署文档与状态记录不一致

- `custom/conf/app.example.ini` 有配置项，但没有完整的 auth source 创建顺序、可信回调域、上线验证、紧急恢复和 secret 轮换 runbook。
- OpenSpec 任务为 38/38，实施计划的 Phase 0/Phase 1 仍全部未勾选。
- Phase 0 的企业微信真实应用验证尚无证据。

**建议：** 把“代码完成”“集成验证完成”“生产就绪”分开记录；在真实 WeCom 测试租户验证前，不要把 Phase 0 标记完成。

## 3. 建议执行顺序

### Step 1：重新打开当前变更的完成定义

先不要归档 `wecom-only-web-login`。把下列项目补回任务清单：

1. 敏感 URL/error 脱敏与日志测试。
2. `ENABLED=false` 强制禁用语义。
3. 零可用 WeCom source 的启动/运行时保护和上线 runbook。
4. 同步调度接线，或明确从当前 scope 移出。
5. 快照对账、离职/不可见状态和事务一致性。
6. 真实 OAuth callback integration test。

### Step 2：先做安全与可恢复性加固

优先修 P0-1、P0-2、P0-3。这些问题直接影响 secret 安全和管理员可登录性，风险高于继续增加业务能力。

完成标准：

- 日志、页面、审计均不泄漏 CorpSecret、access token、authorization code；
- `ENABLED=false` 时所有 WeCom Web 登录入口不可用；
- login-only 不会在缺少有效 source 时静默锁死，且有经过验证的离线恢复步骤。

### Step 3：完成目录同步闭环

按 Phase 2 的最小闭环实现：

```text
cron/manual trigger
      -> fetch with timeout + cached token
      -> build complete visible snapshot
      -> transactional reconcile
      -> mark missing identities out_of_scope/left per policy
      -> commit snapshot
      -> audit + observable status
```

此阶段暂不把部门/标签映射到 repo role，但必须把身份状态数据做对，否则后续授权会建立在陈旧数据上。

### Step 4：补齐验证矩阵

建议验证顺序：

1. `make fmt`
2. 精确单元测试
3. `make lint-go`
4. migration test
5. Web auth integration test
6. SSH/PAT/Git HTTP path integration tests
7. 支持数据库的 CI migration/integration matrix
8. 使用企业微信测试应用执行人工 smoke test，记录 CorpID/AgentID/回调域和可见范围验证结果，但不记录 secret

当前设备无法监听 `httptest` 本地端口，因此完整 HTTP 测试应在允许 loopback listener 的开发环境或 CI 中执行。

### Step 5：整理变更边界并归档 OpenSpec

全部 P0/P1 验证通过后：

- 排除 `.agents/` 等本地工具文件，不混入产品 PR；
- 确认 OpenSpec artifacts 是否按团队约定纳入版本控制；
- 更新 Phase 0/1 状态与验证证据；
- 将产品代码、测试、文档组织成可审查的常规提交；
- 再执行 OpenSpec archive。

### Step 6：再启动后续企业授权变更

当前登录和身份同步稳定后，下一项正式需求应是 **Phase 2：企业微信授权映射基础**，之后才是 **Phase 3：角色和 repo action overlay**。

推荐拆成两个 OpenSpec change，避免一次跨越过多安全边界：

1. `wecom-directory-reconciliation-and-mapping`
   - 完整同步、身份状态、映射模型、手动同步 API、审计。
2. `enterprise-repo-role-overlay`
   - role definition、permission、subject binding、shadow-mode evaluator、少量高风险入口试点。

不要一开始就同时接入 merge、branch protection、webhook、secret 和 Git receive hook。先让 evaluator 以 shadow mode 运行并比较原生 Gitea 决策，再逐个入口 enforce。

## 4. 推荐的近期里程碑

| 里程碑 | 目标 | 退出条件 |
| --- | --- | --- |
| M1：Phase 1 安全收敛 | 登录链路安全且不会锁死 | P0 全部关闭，完整 Web integration 通过 |
| M2：目录快照可信 | 同步可调度、可取消、可对账 | 离职/不可见状态测试、事务回滚测试、同步状态可观测 |
| M3：映射 shadow mode | 企业微信主体映射到 Gitea 主体，不直接阻断 | 映射幂等、审计完整、shadow decision 可比较 |
| M4：repo action 小范围 enforce | 先保护 webhook/secret/branch protection 等高风险写操作 | 403 负例、管理员正例、回滚开关和审计通过 |
| M5：统一 merge gate | 接入 required checks、CODEOWNERS、敏感路径和 AI review | Web/API/auto merge 同一 evaluator，策略快照可解释 |

## 5. 最终判断

当前工作不是“从零开始”，也不是“已经完成可归档”，而是处于：

> **Phase 1 主路径已经实现，但生产安全、运行接线和一致性闭环尚未完成。**

最有价值的下一步不是扩展更多授权表和权限动作，而是用一个短迭代把现有企业微信登录变更变成可信的身份基础层。只有身份来源、状态同步和回滚路径可靠，后续 repo action 与 feature grant 才有安全的主体数据可依赖。
