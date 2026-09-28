/**
 * 存活/就绪探针路径的**唯一清单**。
 *
 * 两个消费方必须同尺，且必须是同一份数据而不是两份抄本：
 *   - `middleware/protocolCompliance.js`（命中 `isProbeRequest` 时整条闸门直接 next()，
 *     方法/Content-Type/Content-Length/头卫生/Host 五项校验全部跳过）
 *   - `middleware/rateLimit.js` 里全站挂载的资源型限流器 `skip`（不计配额）
 *
 * 漏掉后者的失败形态是固定的部署事故：容器 HEALTHCHECK 与 `scripts/deploy.js` 门禁都以
 * `127.0.0.1` 高频探测 `/readyz`、`/health`，全站限流一旦把它们计入配额，门禁会对
 * **完全健康的新版本恒红并自动回滚**（protocolCompliance.js 的 P3-35 注释记过同一条链：
 * Host 白名单漏放行探针时得到的是同一个结局）。
 *
 * 反向代价要如实说明：豁免按路径生效、不区分来源，因此这两个端点不受洪水保护。
 * 二者都是无鉴权的常量级 GET/HEAD（`/readyz` 含一次 Mongo ping），与"闸门跑了、限流没跑"
 * 的哈希链写入放大相比不是同一量级的风险面。
 *
 * 【豁免面必须精确到「探针路径 + 探针方法」，不是路径前缀】
 * 两个消费方原先都用 `helpers.matchesAnyPathPrefix`（`f === p || f.startsWith(p + '/')`）
 * 判定，于是 `/health` 一名豁免了整个 `/health/...` 子树；又因为判定里不看方法，
 * 任意方法（含带体的 POST）一起免检。实测（supertest 打真实 createApp()）：
 *   POST /health/zznope   → 404，响应里**没有** RateLimit-* 头（两个限流器都 skip 掉了）
 *   POST /health/zznope   → Content-Type: text/plain 照样放行（协议合规闸整体没碰它）
 *   POST /api/zznope      → 415 CONTENT_TYPE_UNSUPPORTED，且带全套 RateLimit-* 头（对照）
 *   40 × POST /health/zzflood（每发 ~200KB JSON）→ 全部 404，一条 429 都没有
 * 后果正是 `app.js` 里"限流必须早于 body 解析"那段论证要挡的东西：未认证者可以用
 * `/health/<任意后缀>` 让服务端**不计配额地**反复解析 1MB 级 JSON，同时绕开
 * Content-Length/Content-Type/头部数量/方法白名单四道闸。前缀语义在这里没有价值——
 * 真实的探针只有 `curl GET /health`、`curl GET /readyz`（compose/ci/deploy.js 三处实测，
 * 见 deployment/rollback-drill.md 与 .github/workflows/ci.yml），没有一个消费子树或换方法。
 *
 * 方法维度也收口（不只收子树）：`POST /health` 与 `POST /health/x` 的代价同源，
 * 只改前缀等于把同一个放大面留在最短的那条 URL 上。于是非探针方法打到探针路径时
 * 回归普通表面语义：先撞协议合规闸（405）并写审计，其后吃 429——配额由限流器管，
 * 不再是"零配额 + 零闸门"。探针本身（GET/HEAD）的豁免一字未动。
 *
 * 大小写与斜杠仍要与路由同尺：`GET /HEALTH` 真实命中 `/health` 的处理，尾部斜杠
 * 在 strict routing 关闭时同样命中，故判定前先小写、去一个尾斜杠。
 */
const PROBE_PATHS = ['/health', '/readyz'];

/** 探针方法：存活/就绪检查只会是 GET（HEAD 同语义、无响应体，给 LB 留口子） */
const PROBE_METHODS = ['GET', 'HEAD'];

/** 与路由同尺的归一：小写 + 去掉一个尾斜杠（根路径 '/' 保持原样） */
const normalizeProbePath = (fullPath) => {
  const raw = String(fullPath || '').toLowerCase();
  return raw.length > 1 && raw.endsWith('/') ? raw.slice(0, -1) : raw;
};

/**
 * 判定"这是一次探针"，两个消费方必须用它而不是自己抄一遍规则：
 * 只认精确探针路径 + 只认探针方法。
 */
const isProbeRequest = (method, fullPath) =>
  PROBE_METHODS.includes(String(method || '').toUpperCase()) &&
  PROBE_PATHS.includes(normalizeProbePath(fullPath));

module.exports = { PROBE_PATHS, PROBE_METHODS, isProbeRequest, normalizeProbePath };
