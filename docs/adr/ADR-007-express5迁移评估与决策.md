# ADR-007：Express 4→5 迁移评估与决策

- **状态**：已评估，迁移获批（低风险，择窗口执行）
- **日期**：2026-09-05
- **涉及**：`package.json`（express ^4.22.2）、`src/app.js`、`src/routes/*`、全部中间件接线；遗留清单 D 档

## 背景

Express 4.x 已停止维护（EOL），不再接收安全补丁；Express 5.x 为当前主线。本仓库为消防安全管理系统，后端无独立架构团队维护窗口，迁移必须以「一次半日窗口 + 全量回归兜底」的规模完成，不接受长周期改造。

## 逐项破坏面扫描结果（基于源码 grep 实证）

| Express 5 破坏点                                                   | 本仓库现状                                                                                                             | 结论                                                                             |
| ------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------- |
| path-to-regexp v8：拒绝正则路由、`:param?` 可选段、匿名 `*` 通配   | 路由层 `:param?` **0 处**、正则路由 **0 处**、`'*'` 通配 **0 处**；404 兜底用 `app.use((req,res)=>…)`（v5 不受影响）   | ✅ 无影响                                                                        |
| `req.param()` 移除                                                 | 0 处                                                                                                                   | ✅                                                                               |
| `res.send(status)` / `res.json(status, obj)` 数字重载移除          | 0 处（全仓统一 `res.status(x).json(...)`，由 ApiResponse 封装）                                                        | ✅                                                                               |
| `app.del` / `app.configure` / `express.createServer` 移除          | 0 处                                                                                                                   | ✅                                                                               |
| 默认 query parser 行为变化（v5 倾向 simple，嵌套查询对象解析收窄） | `app.set('query parser')` 未配置；列表接口入参全部为扁平标量（page/limit/cursor/状态枚举），express-validator 显式校验 | ✅ 建议迁移时显式 `app.set('query parser', 'extended')` 固定现状，消除隐性行为差 |
| Promise 自动转发（handler reject → error middleware）              | v5 新能力，对本仓为**净收益**：未捕获的 async reject 不再挂起请求                                                      | ✅                                                                               |
| `trust proxy` 等 `app.set` 语义                                    | 继续存在，G6/TRUST_PROXY_HOPS 逻辑不变                                                                                 | ✅                                                                               |

### 中间件兼容性

| 依赖                     | 版本     | v5 兼容                    |
| ------------------------ | -------- | -------------------------- |
| cors                     | 2.8.5    | ✅                         |
| helmet                   | 7.1.0    | ✅                         |
| morgan                   | 1.10.0   | ✅                         |
| express-rate-limit       | 7.1.5    | ✅（官方声明支持 5）       |
| express-validator        | 7.0.1    | ✅                         |
| socket.io（attach 挂接） | 现用版本 | ✅（不感知路由解析）       |
| swagger-ui-express       | 现用版本 | ✅（serve/setup 模式不变） |

## 决策

**迁移获批，安排一个半日窗口执行**，步骤固化如下：

1. `npm install express@^5`（唯一版本变更，不动中间件）；
2. `src/app.js` 显式追加 `app.set('query parser', 'extended')`（固定现状，防止隐性行为差）；
3. 全量回归：`npm test`（111 套件）+ `npm run test:e2e`（完整启动序列）+ `npm run test:prod-drill`（生产门禁）——e2e/prod-drill 已接入 CI（I-L6），迁移提交必须三绿；
4. 冒烟人工项：/api-docs Basic Auth、/metrics、CSP 上报、WebSocket 连接；
5. 回滚预案：单提交变更，`git revert` 即回 4.22.2。

## 后果

- 4.x EOL 的安全补丁缺口消除；获得 v5 的 Promise 自动转发，减少一处异步错误类盲区。
- path-to-regexp 收益为「路由声明错误在启动期即暴露」，本仓路由全部为静态段+具名参数，无转换负担。
- 本 ADR 记录的扫描快照对应 commit `229b3b8` 后的工作区；若后续新增通配/正则路由需重扫（迁移执行时复核一次即可，约 10 分钟）。
