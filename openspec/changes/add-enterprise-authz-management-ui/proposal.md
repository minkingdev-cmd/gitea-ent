## Why

`add-enterprise-authz-foundation-shadow` 已提供角色、绑定、候选权限诊断和决策查询，但 API-only 不适合日常维护。用户于 2026-10-03 明确要求 Gitea 内置 UI，并限定仅系统超级管理员访问；需要完整可维护页面，同时保持 shadow 与原生授权边界。

## What Changes

- 在既有站点管理框架增加“企业授权”入口，集中管理 system/org/repo 三种作用域，不在组织或仓库设置中向 owner/admin 开放维护入口。
- 所有新增页面、表单、详情、搜索候选及异步接口仅允许当前可信系统超级管理员。企微启用时要求原生管理员且当前应用 active、已绑定管理 authority，普通本地管理员不得回退放行。企微关闭时沿用原生有效站点管理员；组织/仓库 owner、企业 Owner/Platform Admin 均不能靠角色取得 UI 权限。
- 提供角色列表、创建/复制/编辑/删除、显式 action 及 branch/path/source 条件表单；内置角色只读可复制，完整处理版本冲突、引用中删除和校验错误。
- 提供 user/team/org 绑定与解除、当前生效/旧 owner 失效状态、合法作用域/主体选择，不修改企微自动生成映射或原生成员关系。
- 提供选定仓库/用户的有效权限及 action 诊断；提供真实 shadow 决策的筛选、分页、详情与安全历史解释，明确区分候选结果和原生结果。
- 使用现有 Web 登录 session 和 CSRF 防护，不要求用户输入 PAT、不在浏览器保存令牌、不将原 token API 放宽为 session API。已有管理/诊断 API 权限与行为不变，UI 拥有更严格的独立准入。
- authz disabled 时隐藏新增入口，直接访问在认证/超管校验后返回 404；不提供运行时启用 authz/enforce 或更改服务器配置的按钮。
- 保持 Linux-only、shadow-only、callback 关闭及合法登录刷新/定时完整同步；SSH key、PAT/API token、Git HTTP token 的创建、认证、scope、吊销和原生请求结果不变。

## Capabilities

### New Capabilities

- `authorization/enterprise-authz-management-ui`：仅系统超管可达的内置作用域维护、角色/条件与绑定表单、权限诊断、shadow 历史查询及 Web 安全闭环。

### Modified Capabilities

无。新增独立 UI 合同，既有企业授权 API 与企微管理只读/自动化规范不修改；不重写已完成 foundation 提案的 API-only 交付记录。

## Impact

- 依赖工作树中已完成的 `add-enterprise-authz-foundation-shadow`，实施前验证模型、migration、service、目录和受权查询可用；不要求先归档或自动勾选前置提案。
- 增加 Web admin handler、模板与必要的小型前端模块，扩展 admin 路由/导航和表单；复用 `services/enterpriseauthz`，不复制 evaluator/CRUD 或增加外部授权系统。
- 增加集成/E2E 权限、CSRF、表单/并发、错误和浏览器安全测试；沿用 Gitea 视觉、暗色主题和 locale 流程，仅编辑 `locale_en-US.json`。
- 默认不需要 DB migration、新 action、内置角色 seed、配置开关或 OpenFGA/Keycloak。若实际实现发现必要的新持久化合同，先修订本提案与显式 migration 任务，不做启动回填。
- 文档说明仅超管 UI 与现有 API authority 的区别、候选授权限制及可视化维护流程。没有新登录入口、enforce、feature grant、merge gate、授权 UI 权限委派或生产 callback 启用。
