# web-admin — 消防安全管理系统前端

Vue 3 + Vite + Element Plus + Pinia + vue-i18n 的管理端单页应用。

## 快速上手

> 本仓库**不是** npm workspace：根目录只装后端依赖，前端依赖装在 `web-admin/`
> 自己的 `node_modules`（两份独立 lockfile）。只在根目录 `npm install` 后直接
> `npm run dev` 会因缺少 vite 而失败——前端依赖必须在前端目录单独安装。

```bash
# 0. 环境要求：Node >= 22.12.0（根目录与 web-admin 的 engines 同口径）
#    后端需先配置 .env（cp .env.example .env），见根 README「快速开始」

# 1. 安装前端依赖（必须在 web-admin 目录下执行；npm ci 严格按 lockfile 安装）
cd web-admin
npm ci                 # 本地开发也可用 npm install

# 2. 本地开发（默认端口见 vite.config.js；/api 等代理到后端 3000 端口）
npm run dev            # 默认监听 127.0.0.1:3001，需先启动后端

# 3. 生产构建（构建后可跑 bundle 预算闸）
npm run build
npm run build:budget

# 4. 本地预览构建产物
npm run preview
```

## 常用命令

| 命令 | 作用 |
| --- | --- |
| `npm run dev` | Vite 开发服务器（热更新） |
| `npm run build` | 生产构建 |
| `npm run build:budget` | 构建产物体积预算检查 |
| `npm run test` | 跑全部 vitest 测试（一次性） |
| `npm run test:watch` | vitest watch 模式 |
| `npm run test:coverage` | 带覆盖率的测试 |
| `npm run lint` / `lint:fix` | ESLint 检查 / 自动修复 |

单文件调试：`npx vitest run src/tests/views/userView.test.js`（路径可带 `-t "用例名"`）。
提交前请只跑与改动面相关的测试文件，全量测试由集成阶段统一执行。

## 依赖版本策略

- `vue-i18n` 是唯一**精确锁定**的运行时依赖（`11.4.16`，不带 `^`）。原因：
  它是全站文案渲染的单点依赖，且本仓用自定义 messageCompiler 替换了默认 JIT
  编译器（`src/i18n/index.js`），对 vue-i18n 内部的编译/回退行为敏感；该依赖又是
  从已 EOL 的 v9/v10 大版本跳跃升级而来（9.14.5 → 11.4.16，见 CHANGELOG 2026-10-30），
  minor 区间内再漂移的风险收益比最差。精确锁定强制升级走「显式改版本号 → 复核
  行为 → 重算锁文件锚」的流程，而不是被 `^` 区间静默带上。
- 其余依赖用 `^` 区间 + lockfile 锁定实际解析版本。两份 lockfile（根目录与
  `web-admin/`）的 semantic 哈希由 CI `dependency-policy` 闸比对
  `deployment/lockfile-anchor.json`：任何 lockfile 变更（含手动编辑）都会在锚
  校验时现形，改完依赖必须跑
  `node scripts/check-lockfile-integrity.js --update` 并人工复核 diff。

## 目录结构速览

```
src/
├── api → 已并入 utils/api.js      # axios 实例、拦截器、api.* 端点封装
├── assets/styles/                 # global / view-refine / apple-* / dark 等分层样式
├── components/                    # 跨视图复用组件（卡片、对话框、表单部件）
├── composables/                   # useLatestRequest / usePermission / useListLoadState 等
├── constants/                     # 枚举与权限码常量
├── data/                          # 静态字典（如 IP 归属地译名）
├── directives/                    # 自定义指令
├── i18n/                          # vue-i18n 实例、locales 词表、按页懒加载词表
├── layout/                        # 主布局（侧边栏、顶栏、全局弹层）
├── router/                        # 路由表与全局守卫（会话恢复、权限、深链回跳）
├── schemas/                       # zod 形状校验（登录/权限等关键响应）
├── store/                         # Pinia：auth（会话/权限）、app（主题/语言）
├── utils/                         # api、errorReporter、withSyncLock、copyText 等纯工具
├── views/                         # 路由页面（每个业务域一个 View）
└── tests/                         # vitest 测试（helpers/componentHarness 为挂载基座）
```

## 测试约定

- 测试框架是 **vitest + jsdom**（与后端 jest 体系相互独立，勿混用断言库）。
- 组件测试统一用 `src/tests/helpers/componentHarness.js` 挂载真实 SFC：
  自带 i18n / memory-router / 独立 pinia，并提供 `click`（对齐浏览器禁用语义）、
  `flush`、`waitFor`（轮询终态，不写死 tick）。
- **禁止固定 sleep**：等待异步结果一律用 `waitFor` / `flush` 轮询到稳定终态。
- 新增测试放在 `src/tests/` 对应子目录（views / components / utils / store / router…）。
- 行为变更必须配测试；测试期望值在用例内独立给出，不 import 被测实现本身，
  避免实现写错时断言恒真。
- `api` 等带模块级单例的模块，用例内用 `vi.resetModules()` + 动态 import 隔离。

## 约定与注意

- 错误提示统一由 `src/utils/api.js` 响应拦截器按状态码/错误码提示；组件 catch 里
  再弹泛化文案会双提示，除非 `!isHandledApiError(e)`。
- 写入口（提交/删除/导出等）用 `withSyncLock`（`src/utils/withSyncLock.js`）做
  同 tick 双击防重；`:disabled="submitting"` 要等重渲染，拦不住同 tick 连点。
- 列表请求用 `useLatestRequest` 竞态门票，过期响应不得回填。
- 主题存 localStorage（`themeMode`），语言存 localStorage（`locale`，兼容旧
  sessionStorage 值）；改语言只走 `appStore.setLanguage`。
- Prettier printWidth=100、单引号、无分号（以各目录 `.prettierrc` 为准），ESLint
  随 `npm run lint` 执行。
