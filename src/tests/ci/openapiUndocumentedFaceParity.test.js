'use strict';

/**
 * 未文档面（豁免面）的**状态码**与**理由**闸（第 24 轮）
 *
 * 与同目录 openapiStatusParity.test.js 的分工（一份取数、不设第二把尺子）：
 *   · 那份管**业务面双向一致**：文档声明的成功码 == 实现静态可见的成功码，且
 *     「实现有、文档无」的端点必须登记在它的台账里（成员集合由它维护）。
 *   · 本份只管**未文档面的两个更细的洞**——它那份判据在这两点上是空的：
 *
 *     ① 台账理由只要求「非空白」。于是「POST /csp-report，恒回 204」这句话里**没有任何
 *        一个字被机器读过**：把实现从 204 改成 200，理由还是成立的文字，台账照样绿。
 *        这正是 Lead 点名的反向漂移面：wellKnownRoutes.js:99,153 两个 204 端点
 *        「有实现无文档」，而它们的**码**此前没有任何判据盯着。
 *     ② 理由不指向证据：写「恒回 204」却不要求任何文件里真的出现过这个端点路径。
 *
 * 取数复用 helpers/statusParityContract（与业务面闸同一份前缀/处理器解析）。
 * 本闸**不**自己维护成员台账：成员集合由那份台账定义，这里只补「每条成员的码」
 * 与「每条成员的理由 + 证据」。两份成员台账会立刻互相漂移。
 */

const fs = require('fs');
const path = require('path');

const {
  buildRouteOps,
  normalizePath,
  implOf,
  undocumentedEndpoints,
} = require('./helpers/statusParityContract');

const ROOT = path.resolve(__dirname, '../../..');
const SPEC = JSON.parse(fs.readFileSync(path.join(ROOT, 'src/docs/openapi.json'), 'utf8'));
const ROUTE_OPS = buildRouteOps();

/**
 * 未文档面的**码**与**依据**。
 *
 * codes 是「这个端点成功时会发哪些码」的**可核对声明**——不是描述，是判据输入：
 * 由 D1 与实现静态可见的成功码逐条比对。只收 2xx/3xx（失败码不在本闸范围）。
 * evidence 必须是一个真实文件，且文件里要出现该端点的路径字面（D2 核对）。
 */
const UNDOCUMENTED_FACE = [
  {
    key: 'GET /readyz',
    codes: [200],
    evidence: 'src/app.js',
    why: '就绪探针：成功路径走 res.json 的默认 200，不 ready 时显式 503（失败码不属本闸范围）。',
  },
  {
    key: 'GET /metrics',
    codes: null,
    evidence: 'src/app.js',
    why: 'Prometheus 抓取端点：处理器是外部模块标识符 metricsEndpoint，静态解析不到码，故 codes 只能为 null；由 D1 的规模锚点兜住「不许普遍解析不到」。',
  },
  {
    key: 'GET /api/metrics',
    codes: [200],
    evidence: 'src/app.js',
    why: '面板 JSON 快照：ApiResponse.success 缺省状态码 200（在认证 + security:audit 之后）。',
  },
  {
    key: 'GET /api-docs.json',
    codes: [200],
    evidence: 'src/app.js',
    why: '文档自身的 JSON：res.json(swagger.openapiSpec) 的默认 200；仅 ENABLE_API_DOCS 时注册。',
  },
  {
    key: 'GET /.well-known/security.txt',
    codes: [200],
    evidence: 'src/routes/wellKnownRoutes.js',
    why: 'RFC 9116 发现文件：res.send(buildSecurityTxt(req)) 的默认 200，路径由协议固定。',
  },
  {
    key: 'GET /security.txt',
    codes: [200],
    evidence: 'src/routes/wellKnownRoutes.js',
    why: '同上，根路径兼容位置，与上一条同一处理器 serveSecurityTxt，故码必须相同。',
  },
  {
    key: 'POST /csp-report',
    codes: [204],
    evidence: 'src/routes/wellKnownRoutes.js',
    why: '浏览器 CSP 违规单向上报：res.status(204).end()。上报是单向通知、浏览器不消费响应体，改成 200 会在客户端控制台制造二次噪音。',
  },
  {
    key: 'POST /client-errors',
    codes: [204],
    evidence: 'src/routes/wellKnownRoutes.js',
    why: '前端异常/Web Vitals 单向上报：同样 res.status(204).end()；会话失效后仍要能上报，故无认证。',
  },
];

const opOf = (key) => ROUTE_OPS.find((o) => `${o.method} ${normalizePath(o.path)}` === key) || null;

describe('未文档面的状态码与理由', () => {
  test('D0 成员集合与业务面闸的未文档集合一致（不设第二份成员台账）', () => {
    const actual = undocumentedEndpoints(SPEC, ROUTE_OPS);
    expect(actual).toEqual(UNDOCUMENTED_FACE.map((e) => e.key).sort());
  });

  test('D1 每条声明的成功码 == 实现静态可见的成功码（204 改 200 必须红）', () => {
    const violations = [];
    let verified = 0;
    for (const entry of UNDOCUMENTED_FACE) {
      const op = opOf(entry.key);
      const impl = op ? implOf(op) : null;
      if (!impl || impl.codes.length === 0) {
        violations.push(`${entry.key}：实现里取不到成功码，无法核对`);
        continue;
      }
      if (entry.codes === null) continue; // 显式放弃核对，由下面的规模锚点兜底
      verified += 1;
      const actual = impl.codes
        .filter((c) => c >= 200 && c < 400)
        .slice()
        .sort();
      if (JSON.stringify(actual) !== JSON.stringify(entry.codes.slice().sort())) {
        violations.push(
          `${entry.key}：声明 ${entry.codes.join('/')}，实现实际 ${actual.join('/')}`
        );
      }
    }
    expect(violations).toEqual([]);
    // 规模锚点：8 条里只允许 1 条（/metrics）放弃核对——全部放弃也必须是红的。
    expect(verified).toBeGreaterThanOrEqual(7);
  });

  test('D2 每条的理由够长，且证据文件里真的写着该端点的路径', () => {
    const violations = [];
    for (const entry of UNDOCUMENTED_FACE) {
      if (entry.why.length < 40) violations.push(`${entry.key}：理由太短`);
      const file = path.join(ROOT, entry.evidence);
      if (!fs.existsSync(file)) {
        violations.push(`${entry.key}：证据文件不存在 ${entry.evidence}`);
        continue;
      }
      const endpointPath = entry.key.split(' ')[1];
      if (!fs.readFileSync(file, 'utf8').includes(endpointPath)) {
        violations.push(`${entry.key}：${entry.evidence} 里找不到路径字面 ${endpointPath}`);
      }
    }
    expect(violations).toEqual([]);
  });

  test('D3 判据非空转：未文档面规模与已核对条数都成规模', () => {
    expect(UNDOCUMENTED_FACE.length).toBeGreaterThanOrEqual(8);
    expect(ROUTE_OPS.length).toBeGreaterThan(120);
  });
});
