# 消防安全管理系统 · 全项目 OWASP Top 10 安全审计报告

**审计日期**：2026-09-02
**审计范围**：后端 `src/`（210 个 JS 文件 / 53,450 行）、前端 `web-admin/src/`（82 文件 / 22,946 行）、
`Dockerfile`、`docker-compose.yml`、`deployment/`、`.env` 配置
**审计方法**：静态代码审查 + 模式扫描 + 关键路径人工验证（未做动态渗透测试）
**审计依据**：OWASP Top 10 (2021) — A01 越权 / A02 加密失效 / A03 注入 / A05 安全配置错误 /
A06 易受攻击组件 / A07 认证失败 / A08 完整性 / A09 日志监控失效 / A10 SSRF

---

## TL;DR

**总体结论：这个项目的安全水位明显高于同类业务系统的平均水平，未发现 Critical 或 High 级漏洞。**

认证链路、注入防护、密钥管理、错误处理四处做得相当扎实，且代码注释里能看到明确的威胁建模痕迹
（不是"碰巧写对了"，而是"知道为什么这么写"）。

主要风险集中在 **A06 依赖组件**：三个核心依赖落后一个大版本，且**本次未能完成 CVE 在线验证**
（`npm audit` 被网络策略阻断，详见"审计限制"章节）。这是本次审计唯一遗留的实质盲区。

| 分级 | 数量 | 概览 |
|---|---|---|
| 🔴 Critical | 0 | — |
| 🟠 High | 0 | — |
| 🟡 Medium | 1 | 依赖版本滞后且 CVE 状态未验证（A06） |
| 🔵 Low | 3 | CSRF 无来源放行（A01）、就绪探针信息泄露（A05）、密码最小长度（A07） |

---

## 一、审计限制（请务必先读）

本次有 **一项实质性盲区**，影响结论完整性：

**`npm audit` 未能执行。** 三种途径均失败：

| 途径 | 结果 |
|---|---|
| `registry.npmjs.org` audit 端点 | HTTP 400 Bad Request（网络策略拦截） |
| `registry.npmmirror.com` | `[NOT_IMPLEMENTED] /-/npm/v1/security/*` |
| Google OSV API (`api.osv.dev`) | 连接超时 |

因此：**所有已安装依赖的 CVE 状态 = 未验证**。下文 A06 的判定基于版本号与公开知识比对，
属于**推断**而非确认。请在可正常访问 `registry.npmjs.org` 的环境补跑一次：

```bash
npm audit --json > audit.json     # 后端
cd web-admin && npm audit --json > audit.json
```

另外，本次为**纯静态审查**，未做动态渗透测试、未做模糊测试、未验证业务逻辑漏洞
（如越权的具体组合路径）。以下"已验证防护"的成立前提是部署配置正确（详见第五节）。

---

## 二、问题清单

### 🟡 M-1　依赖版本滞后，且 CVE 状态未验证
**OWASP**: A06 易受攻击和过时的组件　**位置**: `package.json`

| 包 | 当前版本 | 最新稳定版 | 差距 |
|---|---|---|---|
| `mongoose` | 8.24.1 | 9.9.4 | 落后 1 个主版本 |
| `ua-parser-js` | 1.0.41 | 2.0.10 | 落后 1 个主版本 |
| `express` | 4.22.2 | 5.2.1 | 落后 1 个主版本（4.x 已 EOL） |

**风险分析**
- `express@4.x` 已进入维护末期，新发现的漏洞可能不再有 4.x 补丁，这是三者中最需要排期的。
- `ua-parser-js` 历史上出现过原型污染类 CVE（影响 1.x 早期版本），当前 1.0.41 大概率已覆盖修复，
  但**本次无法在线确认**，属于待验证项。
- `mongoose` 8.24.1 是 8.x 线内的较新补丁，风险相对低。

**已核对为最新的关键安全包**（无版本滞后）：`jsonwebtoken@9.0.3`、`ipaddr.js@2.5.0`、
`exceljs@4.4.0`、`swagger-ui-express@5.0.1`、`svg-captcha@1.4.0`、`helmet@7.2.0`。

**建议**
- P0：在可联网环境补跑 `npm audit`，确认无已知 CVE 后再排升级。
- P1：制定 `express` 4→5 迁移计划（Express 5 有破坏性变更，需回归测试）。
- P2：`ua-parser-js` 2.x 迁移（API 有变化，但改动面小）。

---

### 🔵 L-1　CSRF 防御在"无来源请求"场景下放行
**OWASP**: A01 失效的访问控制　**位置**: `src/middleware/originCheck.js:38-42`

```js
// 现状：无 Origin 也无 Referer 时直接放行
if (!origin && !referer) {
  return next();
}
```

**风险分析**
放行无来源请求是为了兼容 curl / 服务器间调用，是常见的工程取舍。真正的防护由另外两道承担：
1. 令牌 Cookie 为 `SameSite=strict`（`src/utils/cookie.js`），跨站请求根本不会携带
2. 认证优先走 `Authorization: Bearer`（`src/middleware/auth.js`），非 Cookie 路径不受 CSRF 影响
3. 前端额外实现了一次性 CSRF Token 机制

因此**实际可利用性低**，判定为 Low。但在纵深防御视角下，若未来放宽 `SameSite` 或
新增纯 Cookie 认证的写接口，这条放行会成为突破口。

**建议**（选一）
- 方案 A（推荐，改动小）：无来源时，若请求携带认证 Cookie 则拒绝，仅放行 Bearer 路径：
  ```js
  if (!origin && !referer) {
    // 无来源 + 走 Cookie 认证 = 可疑，要求显式 CSRF Token
    if (req.headers.cookie && !req.headers['x-csrf-token']) {
      return ApiResponse.forbidden(res, '缺少 CSRF 令牌');
    }
    return next();
  }
  ```
- 方案 B：对写操作强制要求 `X-Requested-With` 自定义头（浏览器跨站表单无法伪造自定义头）。

---

### 🔵 L-2　就绪探针可能泄露数据库内部错误信息
**OWASP**: A05 安全配置错误　**位置**: `src/app.js:252-267`

```js
// apps.js:262-267
.catch((err) => {
  res.status(503).json({
    status: 'unready',
    checks: { mongo: err.message },   // ← 原始错误消息直接外泄
    timestamp: new Date().toISOString(),
  });
});
```

`err.message` 可能包含 MongoDB 连接串主机、端口、副本集名、认证失败细节等内部拓扑信息。
`/readyz` 通常无鉴权且会被公网负载均衡器探测，等于给攻击者一张内网结构提示图。

对比之下，`/health`（:245）做得很好 —— 只返回 `{status:'ok'}`，没有任何内部信息。`/readyz` 应对齐这个口径。

**建议**
```js
// 生产环境只回显布尔状态，详细信息写日志不外泄
const detail = config.nodeEnv === 'production' ? 'unavailable' : err.message;
logger.error('就绪探针失败', { error: err.message });   // 详情进日志
res.status(503).json({
  status: 'unready',
  checks: { mongo: detail },
  timestamp: new Date().toISOString(),
});
```

---

### 🔵 L-3　密码最小长度 8 位
**OWASP**: A07 识别与认证失败　**位置**: `src/models/User.js:52`

```js
minlength: [8, '密码至少 8 个字符'],
```

8 位已满足 NIST SP 800-63B 的最低要求，但低于当前推荐的 12 位。
考虑到项目已有 bcrypt 12 轮哈希、登录失败锁定、分层限流三重兜底，**暴力破解可行性很低**。

**建议**：新建用户时提升到 12 位（存量用户不受影响），并在注册接口提示密码强度。

---

## 三、已验证的防护（安全确认清单）

以下项经代码审阅确认**实现正确且生效**，列出以便回归测试时守住基线，也避免后续重构误拆。

### A01 访问控制
- **RBAC 三层校验**：`middleware/rbac.js` 支持权限码精确匹配、模块通配符（`user:*`）、
  超级管理员 `*:*`，以及 `AND`/`OR` 组合逻辑
- **数据范围隔离**：`getDataScope()` 按角色 level 划分 `all/department/self/none` 四档，
  `applyDataScopeToQuery()` 有**显式 deny 判定**（未匹配任何档位时返回 false 而非空过滤），
  避免了"忘记过滤就放行全部"的经典越权
- **水平越权防护**：`isRecordInScope()` 支持单条记录的范围校验，含数组字段路径处理
- **ObjectId 校验**：`applyObjectIdParams()` 逐子 Router 注册
  （注释记录了 Express 4 参数回调不向子 Router 传播这一真实坑，修正得当）
- **WebSocket 鉴权**：认证超时强制断连（防连接池耗尽）+ 房间名白名单

### A02 加密与密钥管理
- **密码哈希**：bcryptjs，**12 轮**（`src/config/index.js:64`）—— 对纯 JS 实现而言已是较高成本
- **对称加密**：AES-256-**GCM** 认证加密（`utils/encryption.js`），防密文篡改与填充预言机
- **JWT**：`algorithms: ['HS256']` 锁定算法，杜绝 `alg:none` / 算法混淆攻击
- **密钥强度**：`.env` 中 `JWT_SECRET` / `JWT_REFRESH_SECRET` / `AES_SECRET_KEY` / `HMAC_SECRET`
  **均为 64 字符强随机值**；且 `config/validate.js` 在启动期强制校验密钥强度，弱密钥直接拒绝启动
- **密钥不入代码库**：`.env` 未被 git 跟踪，`Dockerfile` 用显式 `COPY src/` 而非 `COPY . .`
  （注释明确说明是为了避免 `.env` 被打进镜像），`deployment/` 内无硬编码密钥
- **会话吊销**：`tokenVersion` 强制存在且必须匹配（防绕过）、`passwordChangedAt` 秒级比较、
  令牌黑名单、设备级 `sid` 会话校验、用户 IP 允许范围校验

### A03 注入
- **MongoDB 操作符清洗**：`deepSanitizeKeys()` 递归剔除 `$` 前缀与含 `.` 的键，
  深度上限 10 防栈溢出，同时剔除 `__proto__`/`constructor`/`prototype`（原型污染防护）
- **HTTP 参数污染**：`hpp` 中间件（白名单仅放行 `search`/`sort`）
- **查询标量收敛**：`queryScalarGuard` 防 `?search[$regex]=` 被 qs 解析为对象后进入 Mongo
- **扫描确认**：全仓**无** `$where`、无 JS `eval`、无 `new Function`、无用户输入直传 `new RegExp`
  （`sharedCache.js` 中的 `eval` 是 Redis Lua 脚本执行，非 JS 求值，安全）
- **SQL 注入**：使用 Mongoose ODM，不涉及字符串拼接 SQL

### A05 安全配置
- **错误信息脱敏**：`errorHandler.js` 生产环境不返回字段级校验详情，
  `CastError`/`DuplicateKeyError` 均转为通用文案，异常分支有防二次抛错处理
- **CORS**：白名单模式 + `credentials: true` 配置正确，未使用通配符
- **安全头**：helmet 7.2.0
- **信息最小化**：`/health` 仅返回 `{status:'ok'}`
- **指标端点鉴权**：`/metrics` 有 `metricsAuth`，`/api/metrics` 需 `security:audit` 权限
- **trust proxy 处理**：区分开发/生产默认值，非法 `TRUST_PROXY_HOPS` 有告警
  （IP  spoofing 会击穿限流与黑名单，此处处理正确）

### A07 认证与 XSS
- **前端 XSS**：全仓**零** `v-html`、零 `innerHTML`/`outerHTML`/`document.write`，
  Vue 模板默认转义，XSS 面基本闭合
- **令牌存储**：令牌走 httpOnly + `SameSite=strict` + 生产 `secure` 的 Cookie，
  Web Storage 仅存非敏感的界面状态（`currentUser`/`permissions`/主题偏好），
  设计文档在 `web-admin/src/store/storage.js` 注释中有清晰说明
- **限流**：分层设计 —— IP 级、全局 30 次、导出 30 次、登录 10 次（`skipSuccessfulRequests`）
- **敏感操作二次验证**：`requireReAuthentication()` 支持密码或 MFA 验证码
- **前端路由守卫**：以 `authStore.isAuthenticated` + `/auth/me` 探测真实会话为准，
  非纯本地判断（避免本地状态被篡改后绕过）

### A09 日志与监控
- **查询串脱敏**：morgan 自定义 `safe-url` token 调用 `redactUrlQuery`，
  避免 token/密码出现在 URL 中被明文长期落盘（`app.js:202`）—— **这个细节很多项目会漏**
- **审计日志**：`auditLog()` 全局中间件，覆盖写操作与敏感读路径
- **Sentry** 集成，含请求追踪与错误上报

---

## 四、审计中发现的其他观察（非漏洞）

| 项 | 位置 | 说明 |
|---|---|---|
| 日志体积 57MB 且持续增长 | `logs/` | 8/23–9/2 共 10 天，约 5.7MB/天。有 `winston-daily-rotate-file` 且配了 `maxSize:10m` / `maxFiles:90d`，**留存策略正常**，但需确认磁盘配额与运维清理流程 |
| 请求日志未覆盖安全拒绝事件 | `src/middleware/rateLimit.js` | 限流/CSRF 拦截未写审计日志，攻击尝试取证困难（此前已识别，在修） |
| 初始管理员密码落盘 | `src/services/initData.js:745` | 写入 `.admin-initial-password` 并 chmod 600，Windows 下 mode 无效会告警。已有缓解，但建议启动后提示删除该文件 |
| 大文件可维护性 | `initData.js` 1039 行、`authService.js` 978 行、`RegisterView.vue` 1424 行 | 非安全问题，但增加回归风险 |

---

## 五、部署配置核查结果

| 检查项 | 结果 |
|---|---|
| `.env` 是否被 git 跟踪 | ✅ 否（`git ls-files` 确认未入库，`.gitignore` 覆盖 `.env`/`.env.*`/`!.env.example`） |
| 部署配置是否硬编码密钥 | ✅ 无（`docker-compose.yml` / `deployment/` / `Dockerfile` 均为空命中） |
| `.env` 是否被打进镜像 | ✅ 否（Dockerfile 用显式 `COPY src/`、`COPY package*.json`，非 `COPY . .`） |
| 密钥强度 | ✅ 4 把核心密钥均 64 字符强随机值 |
| MongoDB 连接串是否内联凭据 | ✅ 未内联（`MONGODB_URI` 长度 40，无 `user:pass@` 结构） |
| 源码硬编码密钥 | ✅ 无（`src/` 下扫描为空命中） |

**关键前提**：以上"已验证防护"的成立依赖部署时配置正确，特别是：
1. 生产环境 `NODE_ENV=production`（否则 Cookie 不带 `secure`、错误可能回显详情）
2. `TRUST_PROXY_HOPS` 按真实代理跳数配置（否则 IP 限流/黑名单/审计 IP 全失真）
3. `CORS_ORIGIN` 显式配置为真实域名（否则回退本地开发白名单）
4. 生产环境密钥与开发环境**完全不同**（当前 `.env` 是开发密钥，切勿复用）

---

## 六、加固行动清单

| 优先级 | 项 | 预计工作量 | 关联 |
|---|---|---|---|
| P0 | 可联网环境补跑 `npm audit`，确认依赖 CVE 状态 | 10 分钟 | M-1 |
| P1 | `/readyz` 生产环境脱敏错误信息 | 15 分钟 | L-2 |
| P1 | 评估 `express` 4→5 迁移可行性 | 需评估 | M-1 |
| P2 | CSRF 无来源请求改为要求 Token（方案 A） | 30 分钟 | L-1 |
| P2 | `ua-parser-js` 升级至 2.x | 小 | M-1 |
| P3 | 新建用户密码最小长度提升至 12 位 | 5 分钟 | L-3 |
| P3 | 确认生产日志磁盘配额与清理流程 | 运维 | 观察项 |

---

## 七、复测建议

修复完成后建议复测以下路径：
1. 补跑 `npm audit` 并确认 0 high/critical
2. 生产配置下访问 `/readyz`（Mongo 异常时），确认不泄露内部信息
3. 模拟无 Origin 的 Cookie 认证写请求（如 `curl -X POST` 带 Cookie 无 CSRF Token），确认被拦截
4. 回归：正常浏览器登录与写操作不受 L-1 修复影响

---

*本报告基于 2026-09-02 的代码快照。静态审查无法替代动态渗透测试，
建议在生产发布前补充一次针对业务逻辑漏洞（尤其是越权组合路径）的动态测试。*
