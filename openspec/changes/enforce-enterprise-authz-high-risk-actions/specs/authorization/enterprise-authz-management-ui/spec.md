## MODIFIED Requirements

### Requirement: Decision history is bounded explainable and privacy safe

系统 MUST 提供受权的 actor/repo/action/candidate/time 筛选、每页最多 100 的分页和详情；呈现 operation/observation ID、候选/原生结果、stage、reason、missing actions、mismatch 和当时安全快照。unknown MUST NOT 冒充原生 success 或计算确定 mismatch；历史 MUST 不用当前角色覆盖。已删除仓库证据 MUST 可在系统范围由超管查询，MUST 不要求读取已删除 repo。页面 MUST 仅展示白名单安全字段，不包含 token/secret/原始错误、HTTP body、代码/diff 或私密路径原文。新历史 MUST 明确区分 shadow/enforce mode、实际企业授权结果和 fallback，不将企业拒绝冒充原生拒绝，不把未执行当作已运行结果；旧 shadow/catalog 快照 MUST 可读。筛选 MUST 增加 mode 与实际企业授权结果，并保留名称选择/失效选择清理及既有范围校验。

#### Scenario: Administrator compares a candidate allowance with native denial

- **WHEN** 超管打开真实观察的候选 allow、原生 denied 记录
- **THEN** 页面清楚区分结果、stage 与 mismatch 并使用当时角色 revision/条件摘要解释，不显示“操作成功”

#### Scenario: History remains queryable after repository deletion

- **WHEN** 超管在系统历史查询已删除 repo ID 的保留期记录
- **THEN** 展示安全历史及已删除标识，不依赖不存在的 repo 页面或重算当前策略

#### Scenario: Sensitive or malformed evidence is not rendered verbatim

- **WHEN** 输入或记录含 HTML/script、secret/token、私密 paths 或不合合同的 snapshot
- **THEN** 文本被转义且仅白名单安全内容进入页面；坏证据返回安全失败，不渲染原始 JSON 或内部错误

#### Scenario: Mode filters do not confuse enforcement with observation

- **WHEN** 超管筛选 enforce deny/fallback 或查看升级前 shadow 记录
- **THEN** 列表/详情使用当时 mode 与实际授权结果；fallback 明示按原生继续，shadow 明示仅观察，deny 明示未执行，不把诊断候选或 unknown 渲染为成功

### Requirement: Authentication and shadow compatibility remain unchanged

新增 UI MUST NOT 开放本地密码、注册、OpenID、Passkey、其他 OAuth、反代或 SSPI 登录旁路；合法企微及 MFA 续接 MUST 保持原有行为。SSH key、PAT/API token、Git HTTP token 和受限 Actions/deploy actor 的认证、scope、吊销机制 MUST 不变；disabled/shadow 的原生行为 MUST 不变，enforce 下只有 enterprise-repo-actions 规定的高风险 action 授权可以收紧，UI MUST NOT 自行授权或阻断这些操作。服务端 MUST 仅部署/验收 Linux；callback MUST 保持关闭，身份更新仍为合法登录刷新与定时完整同步；UI MUST 不提供 enforce 开关/执行许可、feature grant、完整 merge gate 或企微手工 mapping 维护。

#### Scenario: UI is not an alternative sign-in path

- **WHEN** LOGIN_ONLY 环境中的未登录用户从新增 URL 或表单尝试本地/其他 Web 登录
- **THEN** 原有登录拒绝继续生效，UI 不创建新 session 或本地超管后门

#### Scenario: Credentials and native requests keep their previous behavior

- **WHEN** 原 SSH/PAT/Git HTTP/Actions/deploy actor 认证或在 disabled/shadow 执行 repo 操作
- **THEN** UI 不改变认证、scope、吊销、权限、原生响应或 shadow 行为，不新增企微 OAuth 校验

#### Scenario: Enforcement does not expand management UI authority

- **WHEN** 用户持 Owner/Platform Admin/manage_access 企业角色，但没有当前系统超管 authority
- **THEN** 不获得任何新增或既有 UI 入口/详情/筛选/搜索/写入权限；诊断仍是候选结果，没有修改 enforce 配置的按钮
