## 1. 准入、权限与现有合同盘点

- [x] 1.1 读取本 change 全部 artifacts、AGENTS 与开发文档，核对 foundation 模型/migration/service/已验证状态；记录预存用户修改，不修改或归档旧提案，不另建平行计划。
- [x] 1.2 盘点系统超管、Web session/CSRF、导航、角色/条件、主体/范围、diagnostic/history DTO 的实际调用与依赖；形成路由/搜索/按钮/facade 权限矩阵及 action-to-view 测试清单。
- [x] 1.3 确认 DB/seed/config/action/默认角色均无需新增，保持原 API scope；必要的共享安全转换只能保持旧合同，不引入 OpenFGA/Keycloak、隐式回填或生产 callback。

## 2. 超管准入与统一页面入口

- [x] 2.1 先建立真实 Web session 权限失败测试：普通用户、org owner、repo creator/owner/admin、企业 Owner/Platform Admin、企微普通 IsAdmin/inactive/unbound/message-only/其他应用 authority 对所有入口均拒绝；合法系统超管正例及企微关闭的原生管理员边界。
- [x] 2.2 实现 `/-/admin/enterprise/authz` 路由组、系统超管 middleware 与重新校验的 UI facade；页面/helper/selector/mutation/diagnostic/detail 均先认证/超管、enabled 后才加载目标/策略，不接受 PAT/Basic/synthetic actor 替代 Web session。
- [x] 2.3 接入既有 admin 导航和布局、scope 切换/明确目标、角色/绑定/诊断/历史 Tab；非超管或 disabled 隐藏新增入口，不向 org/repo 设置开放 owner-only 页面。
- [x] 2.4 增加有界分页 scope/user/team/org/role selector，当前 session 受权后搜索，限制查询长度/页大小并参数化；不接受 repo 主体、跨组织 team 或篡改 scope/caller。
- [x] 2.5 验证 authority 撤销、账号禁用/受限、存储失败、旧 session/表单、disabled 零企业策略读取；直接 URL/helper/POST 与菜单权限一致，权限失败不能泄漏搜索数据或产生审计假成功。

## 3. 角色与条件完整维护

- [x] 3.1 先建立三作用域角色列表/详情、创建/复制/编辑/删除真实流程测试，覆盖祖先来源、内置只读、复制独立和同范围名称冲突；实现复用原 service 的页面与提交。
- [x] 3.2 实现来自后端 catalog 的 action 选择与 unit/risk/Observed 帮助；feature grant 明示仅目录/诊断，不新增开关或 enforce 按钮。
- [x] 3.3 实现 branch/path/source 条件结构化表单与准确 round-trip，保持 AND/OR/all-path/unresolved 语义；验证未修改、无条件、空权限集、非法/未知/重复/超限字段，不丢条件或部分保存。
- [x] 3.4 编辑/删除携带原 expected_revision，补两个编辑者版本竞争与引用中删除回归；409 显示明确操作提示、保留页面内草稿，不自动覆盖新版本。
- [x] 3.5 接入真实持久化后的成功反馈、确认/取消、PRG 或同源 helper 提交；审计写失败/业务存储失败返回安全500且整次回滚，无半套权限、重复成功审计或假成功。

## 4. 主体绑定与失效解释

- [x] 4.1 先覆盖 user/team/org 合法绑定、解除与重复写入幂等，再实现三作用域列表/主体/角色选择与确认；显式显示来源 scope 和作用对象。
- [x] 4.2 验证角色跨 scope、Platform Admin 仅系统绑定、主体删除/组织关系/team-repo 变化、篡改 ID/hidden scope 后后端仍拒绝，搜索筛选不能替代服务校验。
- [x] 4.3 以当前只读 view model 标记旧 owner 转移后的不生效绑定，提供显式解除/重新绑定流程；无自动修复，不写 membership/access/IsAdmin/企微映射。
- [x] 4.4 覆盖并发绑定/角色删除、绑定审计失败回滚、重复点击/错误恢复；真实前后策略与原生权限摘要保持合同。

## 5. 有效权限、诊断与历史

- [x] 5.1 为选定仓库/本地用户实现有效权限页与 POST action/branch/paths 诊断，caller 固定当前超管、source 固定 diagnostic、CSRF 必需；system/org 提示选 repo，不伪造非 repo 评估。
- [x] 5.2 覆盖候选 allow/native guard 未评估、missing actions、AND/all-path/unresolved、选他人、无效账号、越界/超限输入；诊断不执行 Git、不保存真实 repo 操作决策、不声称具体 PAT/key 限权结果。
- [x] 5.3 实现 decision actor/repo/action/candidate/time 筛选、最大100分页、详情链接与错误/空状态；基于原受权查询，不全库浏览器过滤。
- [x] 5.4 实现 operation/observation、candidate/native/stage/reason/mismatch、当时 revision/条件摘要的安全展示；包括协议64hex observation、unknown 无确定 mismatch、历史角色变更与 system 查询已删除 repo。
- [x] 5.5 抽取确有必要的最小安全 DTO/显示转换以避免 Web 跨 router 依赖，保持原 API 输出；坏 snapshot/未知存储值安全失败，不输出 raw JSON、原始错误、token/secret/代码/diff/私密 paths。

## 6. 前端、安全与兼容验收

- [x] 6.1 后端 view model 提供 catalog/状态/原因/选项的显示语义与本地化；补 locale 源，仅编辑 `locale_en-US.json`，不在 JS 硬编码授权业务或手改其他语言文件。
- [x] 6.2 完善原生主题、暗色、语义 label/keyboard/focus、非仅颜色状态、loading/empty/error、保留页内编辑及安全确认；无新组件库/SPA、令牌输入或敏感浏览器持久存储。
- [x] 6.3 覆盖缺 session、PAT/header 伪装、缺/错 CSRF、GET mutation、跨 scope ID、取消/异常、HTML/script 注入、私密字段和日志/响应脱敏；所有异步 endpoint 都执行同一超管准入。
- [x] 6.4 在 Linux/PostgreSQL 运行真实 Web 管理/诊断/历史和管理审计回滚/版本竞争；SQLite 作快速补充。浏览器 E2E 走角色条件 CRUD、绑定/解除、诊断及历史完整链路，semantic locator/确定条件，无 sleep 掩盖竞争，并留截图。
- [x] 6.5 回归原 token API 的 scope 与 org/repo authority 正负例、企微 LOGIN_ONLY 禁止登录路径及合法 MFA 续接、SSH/PAT/Git HTTP/Actions/deploy actor；确认 UI 没改变原生行为、callback 或 shadow-only。

## 7. 文档、验证与交付

- [x] 7.1 更新企业授权 UI 运维说明、导航/超管定义、三作用域维护流程、并发/失效/缺口处理、UI 与原 API 权限区别；保留基础提案原 API-only 验收记录，说明独立新增 UI。
- [x] 7.2 记录当前无 DB migration/seed/config 修改的证据，演练匹配 foundation 版本的 UI 回退；不删除已维护策略/历史、不回填绑定、不降 schema 或修改服务器开关。
- [x] 7.3 Go/模板修改运行 `make fmt`，按改动运行 Linux `make lint-go`、`lint-templates`、`lint-js`、`lint-css` 与前端构建；有 Go module/API 合同变化才分别 tidy/Swagger 生成验证，并真实记录结果。
- [x] 7.4 运行最快受影响 unit/integration/前端测试与浏览器回归、Markdown lint、`git diff --check`、OpenSpec strict validation；逐条对照 specs/权限矩阵/全部按钮helper，无 placeholder/mock/生产不可达，明确环境限制，不声明未测 Windows/其他DB。
- [x] 7.5 仅真实验证后同步 tasks 与 verification，交付截图和完整限制；不提交、推送、创建 PR、修改历史或归档，除非用户另行要求。

## 8. 名称优先交互修正

- [x] 8.1 按用户确认同步规范与设计，不新增平行计划；盘点全部业务 ID/Unix 输入及回显、错误、已删除对象路径。
- [x] 8.2 统一受权名称选择器和隐藏 ID，支持当前名称/来源回显、清除/更换、键盘/分页、类型变化及输入改写立即失效，覆盖无效/撤销/跨 scope 校验。
- [x] 8.3 历史 actor/repo 使用受权历史对象候选，保留已删除对象查询；显示当前名称而不伪造历史名称；浏览器本地时区日期控件与标准时间点严格转换（含跨时区及夏令时），兼容旧链接及分页。
- [x] 8.4 先 RED 再实现，复测无业务 ID 输入的真实角色/绑定/诊断/历史全链路、错误回显、过期选择、日期和权限负例；更新文档、截图及验证记录。
