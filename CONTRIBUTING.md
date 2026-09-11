# 贡献指南（CONTRIBUTING）

感谢参与本项目。本文约定开发环境、质量门禁与提交规范，保证每次合入都不降低现有的安全与可靠性水位。

## 1. 环境要求

| 依赖    | 版本           | 说明                                |
| ------- | -------------- | ----------------------------------- |
| Node.js | ≥18（建议 22） | 与 `Dockerfile` 基础镜像口径一致    |
| MongoDB | 6.x            | 本地需先启动（`net start MongoDB`） |
| npm     | 随 Node        | 后端在根目录、前端在 `web-admin/`   |

## 2. 本地启动

```bash
# 1. 安装依赖（前后端各一次）
npm install
npm --prefix web-admin install

# 2. 准备环境配置
cp .env.example .env          # 按需修改；密钥本地可留 .env，生产一律 *_FILE 注入

# 3. 启动（三选一）
./start.bat                   # Windows 一键：清端口 + 起前后端 + 打开登录页
./dev-backend.cmd             # 仅后端（3000）
./dev-vite.cmd                # 仅前端 dev server（3001，代理 /api 到 3000）
```

容器方式见 `README.md` 的 Docker Compose 章节；生产密钥与部署清单见
`deployment/secret-rotation.md`、`deployment/rollback-drill.md`。

## 3. 合并前必过的门禁（本地全部可跑）

```bash
npm test                      # 后端 jest（含覆盖率棘轮阈值，低于基线即红）
npm run test:coverage         # 覆盖率门禁口径
npm --prefix web-admin test   # 前端 vitest（含覆盖率阈值）
npm run lint:all              # 前后端 ESLint（recommended 全量 error）
npm run format:check          # prettier 全仓格式门禁
npm run test:e2e              # HTTP 冒烟（完整启动序列走查）
```

规则：

- **不许带红合并**。偶发失败不允许「重跑一次就好」——先定位根因（历史教训见
  `src/tests/setup.js` 的隔离注释）；确属环境抖动需在 PR 说明里给出证据。
- **覆盖率棘轮只升不降**：`jest.config.js` / `vite.config.js` 的
  `coverageThreshold` 基线贴着实测值，补测试后应顺手上调基线。
- **分层纪律**：`src/tests/architecture/layeringRatchet.test.js` 锁定
  「controller 直连 models 只减不增、新 controller 零容忍」。新功能的数据访问
  一律经 `src/services/`；确需下沉存量直连时，改完同步调低棘轮基线。
- **格式**：提交前跑 `npm run format`（不要手工对齐，交给 prettier）。

## 4. 代码约定（要点）

- **常量单一事实来源**：审计分类/动作枚举只改 `src/constants/audit.js`；
  路由前缀映射在 `src/utils/auditMeta.js`，两侧由启动断言防漂移。
- **密钥与敏感值**：不进 `environment`、不进日志、不进测试夹具。
  注入走 `src/config/secrets.js` 的 `*_FILE` 机制；新增密钥变量须登记进
  `FILE_BACKED_SECRETS` 与 `docker-compose.yml` 的 secrets 段。
- **日志**：结构化字段进 winston meta（`logger.warn('消息', { userId })`），
  不把用户标识拼进消息字符串。
- **错误处理**：控制器用 `asyncHandler` + `ApiError`；错误码新增须同时补
  前端 i18n 映射（`web-admin/src/utils/errorCodeI18n.js` 有对账测试）。
- **前端**：组件文案走 i18n（禁止中文裸键）；色值走 `--xf-*` 变量；
  会话身份状态只经 `@/store` 的 auth 域，令牌永不进 JS 可读存储。
- **审计**：新增写路由必须在 `AUDIT_LOG_ACTIONS` 白名单登记动作，
  否则审计页筛选会 400（白名单旁有历史教训注释，改前读一下）。

## 5. 提交与评审

- 一个变更只解决一件事；修复类提交在注释/描述里带问题编号（仓库惯例：
  `优化清单编号` 或 `P*/R*/T*` 溯源），方便审计回溯。
- PR 描述包含：**动机 → 方案要点 → 自测清单**（跑过的门禁命令与结果、
  手工验证路径）。涉及界面变化的附截图或录屏。
- 纯重构必须「行为不变 + 全量测试绿」，不与功能变更混在一个提交。

## 6. 测试要求

- 新功能/缺陷修复**必须附带测试**；安全相关路径（认证、权限、审计）
  要求错误分支与边界用例，不只走快乐路径。
- 源码级静态断言（读文件查字符串）只用于「无法用运行时断言的不变量」，
  且要容忍格式化换行；界面断言优先补 `data-testid`。
- E2E 增量见 `e2e/README.md`（Playwright 旅程）。

## 7. 文档同步

行为变更必须同步文档，否则视为未完成：

- 用户可见行为 → `README.md` 与 `CHANGELOG.md`（Keep a Changelog 格式）
- 架构/选型决策 → 新增 ADR（规范见 `docs/adr/README.md`，编号只增不复用）
- 运维动作 → 对应 Runbook（`deployment/` 下）

## 8. 安全问题请勿公开提交

发现漏洞请**私密**报告维护者（勿开公开 issue/PR）：附复现步骤、影响面与
建议修复方向；请勿在报告中携带真实生产凭据。修复与披露节奏遵循
90 天协调披露惯例。依赖漏洞以 `npm run security:audit` 与 CI
`security-audit` job 为门禁，例外登记制度见
`deliverables/security-scan-record-*.md`。

## 9. 目录速览

```
src/            后端（config/ controllers/ services/ middleware/ models/ utils/）
web-admin/      前端（Vue3 + Pinia + Element Plus）
scripts/        运维脚本（备份/恢复/密钥生成与迁移/压测/漏扫辅助）
e2e/            Playwright 浏览器旅程
migrations/     数据库迁移（migrate-mongo）
deployment/     部署配置样例与演练手册
docs/           ADR、架构图、依赖观察清单
deliverables/   评估报告与留档记录
```
