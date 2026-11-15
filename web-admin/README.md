# web-admin — 消防安全管理系统前端

Vue 3 + Vite + Element Plus + Pinia + vue-i18n 的管理端单页应用。

## 快速上手

```bash
# 依赖安装（在仓库根目录执行，workspace 共享一份 lockfile）
npm install

# 本地开发（默认端口见 vite.config.js；后端代理同文件底部 server.proxy）
npm run dev            # 在 web-admin 目录下执行

# 生产构建（构建后可跑 bundle 预算闸）
npm run build
npm run build:budget

# 本地预览构建产物
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
