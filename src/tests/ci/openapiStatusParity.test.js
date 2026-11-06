'use strict';

/**
 * 文档成功码 ↔ 实现实际返回的**双向**对账闸（第 23 轮，lead 指定）
 *
 * 缺陷形状（第 22 轮只读普查实测 4 处，见 work/audit-round22-doc-2xx-census.md）：
 * 文档写 201、实现回 200 —— POST /api/permissions/batch、POST /api/security/report、
 * POST /api/security/forensic/pool-ban/confirm、POST /api/security/ip-list。
 * 第三方照文档写 `if (res.status === 201)` 的客户端永远进不了成功分支，而全部回归用例绿。
 *
 * 为什么能逃过现行门禁（两把闸都在"外面"）：
 *   ① `scripts/check-openapi-drift.js` 对账的是「生成器 ↔ 产物」——改文档的人把 generate.js
 *      与 openapi.json 一起改成 201，两边自洽，闸放行（本地实测 isDeepStrictEqual === true）；
 *   ② 既有回归用例反过来把**实现**的 200 钉死（permissionBatchCreateSemantics.test.js:120、
 *      securityDeep.test.js:156、forensicRoutesContract.test.js:204 都断言 200 且全部通过）。
 *   两侧各有守卫、谁也不看对方，于是漂移成一个"两边都有人守"的空档。
 *
 * 本闸四条腿：
 *   #1 前提自证：路由表解析非空、每个端点都定位到处理函数（定位不到 = 判据作用域漏了，必须红）。
 *   #2 正向：文档声明的 2xx/3xx 集合 == 实现静态可见的成功码集合。
 *   #3 反向：实现里有、文档里没有的端点必须登记在台账里（"漏文档"不许无声发生）。
 *   #4 两条变异自证：把某端点文档改回 201 ⇒ #2 红而 drift 闸仍绿；台账漏登记 ⇒ #3 红。
 *
 * 判据边界（如实声明）：成功码只取**静态可见**的（ApiResponse.success 第 4 字面量参 /
 * created / noContent / res.status(<2xx|3xx>) / 动态 ternary 里的字面量）。抽不出来的
 * 一律进台账由人复核，#2 不会把它当默认 200 —— 那是本仓反复踩过的假绿形状。
 */

const fs = require('fs');
const path = require('path');
const { isDeepStrictEqual } = require('util');

const {
  buildRouteOps,
  normalizePath,
  implOf,
  successCodesOf,
  statusViolations,
  undocumentedEndpoints,
  coverageViolations,
} = require('./helpers/statusParityContract');

const ROOT = path.resolve(__dirname, '../../..');
const SPEC_FILE = path.join(ROOT, 'src/docs/openapi.json');
const readSpec = () => JSON.parse(fs.readFileSync(SPEC_FILE, 'utf8'));
const SPEC = readSpec();
const ROUTE_OPS = buildRouteOps();

/**
 * 反向漂移台账：实现里有、OpenAPI 里没有的端点。
 *
 * 登进这里不等于"合法"，只是"已被人看过并写下理由"。新增端点若落进这个集合而不登记，
 * #3 立刻红 —— 在此之前"漏文档"没有任何信号（drift 闸只比生成器与产物，两边一起漏就都漏）。
 */
const UNDOCUMENTED = [
  // ---- 运维/发现端点：不是业务 API，OpenAPI 面只覆盖业务接口 ----
  // 注意 GET /health 不在这张表里：它**在**文档中（openapi.json 的 /health.get 200），
  // 台账只收"实现有、文档无"，把已文档化的端点写进来会让 #3 变成永远红的噪声。
  { key: 'GET /readyz', why: '就绪探针（app.js:448），200/503 按 Mongo+Redis+拓扑判定' },
  { key: 'GET /metrics', why: 'Prometheus 拉取端点（app.js:509），METRICS_ENABLED=false 时不存在' },
  { key: 'GET /api/metrics', why: '面板 JSON 快照（app.js:515），认证 + security:audit' },
  { key: 'GET /api-docs.json', why: '文档自身的 JSON（app.js:553），仅 ENABLE_API_DOCS 时存在' },
  // ---- 匿名发现/上报端点：路径由 RFC 9116、CSP report-uri、浏览器行为固定 ----
  { key: 'GET /.well-known/security.txt', why: 'RFC 9116 发现文件（wellKnownRoutes.js）' },
  { key: 'GET /security.txt', why: '同上，根路径兼容位置' },
  { key: 'POST /csp-report', why: '浏览器 CSP 违规上报（wellKnownRoutes.js:96），恒回 204' },
  {
    key: 'POST /client-errors',
    why: '前端异常/Web Vitals 上报（wellKnownRoutes.js:151），恒回 204',
  },
  // 注：GET /api/version 曾在这里（"待补文档"）。lead 已把它补进 generate.js（产物 104 paths / 125 ops），
  // 于是它从"实现有、文档无"里消失 —— 台账必须同步删，否则 #3 变成永远红的噪声。
];

describe('文档成功码与实现返回的双向对账', () => {
  test('#1 前提自证：路由表解析非空、无重复键、每个端点都定位得到处理函数', () => {
    // 作用域自证：解析器整体失效时下面所有判据都会"通过"（空集合 == 无违规）
    expect(ROUTE_OPS.length).toBeGreaterThan(120);
    const keys = ROUTE_OPS.map((o) => `${o.method} ${normalizePath(o.path)}`);
    expect(new Set(keys).size).toBe(keys.length);
    // 定位不到处理函数 = 判据看不见这个端点，绝不能当作"它没有成功码"
    const blind = ROUTE_OPS.filter((o) => implOf(o) === null).map(
      (o) => `${o.method} ${normalizePath(o.path)}`
    );
    expect(blind).toEqual([]);
    // 静态抽取必须真的抽到东西：全表都抽成空集合时 #2 会变成"文档也该是空"的假红/假绿
    const empty = ROUTE_OPS.filter((o) => implOf(o).codes.length === 0).map(
      (o) => `${o.method} ${normalizePath(o.path)}`
    );
    expect(empty).toEqual([]);
  });

  test('#2 文档声明的 2xx/3xx 必须等于实现静态可见的成功码（不只对账生成器↔产物）', () => {
    const violations = statusViolations(SPEC, ROUTE_OPS);
    expect(violations).toEqual([]);
  });

  test('#3 反向：实现里有、文档里没有的端点必须登记（漏文档不许无声发生）', () => {
    const actual = undocumentedEndpoints(SPEC, ROUTE_OPS);
    // 双向：多一个未登记 ⇒ 红（新端点漏文档）；登记了但源里已经没有 ⇒ 也红（台账腐化）
    expect(actual).toEqual(UNDOCUMENTED.map((x) => x.key).sort());
    for (const entry of UNDOCUMENTED) {
      expect({ key: entry.key, why: entry.why }).toEqual({
        key: entry.key,
        why: expect.stringMatching(/\S/),
      });
    }
  });

  test('#4a 变异自证：把 ip-list POST 文档改回 201 ⇒ #2 红，而 openapi-drift 闸仍绿', () => {
    // 真实漂移不会只改产物：改文档的人跑 docs:generate，生成器与产物**一起**变。
    // 这里就按那个形状变异（两边同改），证明 drift 闸对这种漂移是瞎的。
    const generator = JSON.parse(JSON.stringify(require('../../docs/generate')));
    const artifact = readSpec();
    // 前提：当前生成器与产物本来就一致（否则下面的"仍绿"是别的缺陷造成的）
    expect(isDeepStrictEqual(generator, artifact)).toBe(true);

    const swap = (spec) => {
      const post = spec.paths['/api/security/ip-list'].post;
      post.responses['201'] = post.responses['200'];
      delete post.responses['200'];
      return spec;
    };
    const mutatedGenerator = swap(JSON.parse(JSON.stringify(generator)));
    const mutatedArtifact = swap(JSON.parse(JSON.stringify(artifact)));

    // ① drift 闸的判据本体：生成器 vs 产物 —— 变异后依然一致 ⇒ 放行（这就是漏报机理）
    expect(isDeepStrictEqual(mutatedGenerator, mutatedArtifact)).toBe(true);
    // ② 本闸：必须红，且指名道姓就这一个端点
    expect(statusViolations(mutatedArtifact, ROUTE_OPS)).toEqual([
      {
        key: 'POST /api/security/ip-list',
        declared: [201],
        impl: [200],
        why: '文档 201 vs 实现 200',
      },
    ]);
    // ③ 变异没把别的端点一起打红（否则"红"可能来自无关破坏）
    const untouched = statusViolations(artifact, ROUTE_OPS);
    expect(untouched).toEqual([]);
  });

  test('#4b 变异自证：台账漏登记一个端点 ⇒ #3 红（且只多出那一条）', () => {
    const actual = undocumentedEndpoints(SPEC, ROUTE_OPS);
    const dropped = UNDOCUMENTED.map((x) => x.key)
      .sort()
      .slice(1);
    // 模拟"新人删掉一行台账"：实际集合与台账不再相等
    expect(actual).not.toEqual(dropped);
    expect(actual.length - dropped.length).toBe(1);
    // 反向：源里删掉端点后台账残留也必须能被发现（用台账加一条不存在的端点模拟）
    const phantom = [...new Set([...actual, 'POST /api/does-not-exist'])].sort();
    expect(phantom).not.toEqual(actual);
  });

  test('#5 判据有牙（合成样例）：200 / 201 / 204 / 304 / 动态三元 各走一遍', () => {
    // 抽得出 = 判得动；这条防的是"抽取器退化成只会返回 200"而 #2 变成永远绿
    const codes = (body) => successCodesOf(body).codes;
    expect(codes("return ApiResponse.success(res, x, '成功', 201);")).toEqual([201]);
    expect(codes("return ApiResponse.success(res, x, '成功');")).toEqual([200]);
    expect(codes('return ApiResponse.created(res, x);')).toEqual([201]);
    expect(codes('res.status(204).end();')).toEqual([204]);
    expect(codes('return res.status(304).send(buffer);')).toEqual([304]);
    // 失败码不是成功码：改密成功但会话吊销失败时先置 503 再写审计（authController/profile.js:70）
    expect(codes("res.status(503); return ApiResponse.codeError(res, 'X');")).toEqual([]);
    // 动态状态码：把 ternary 里的字面量都算候选，且原文进台账
    const dyn = successCodesOf('res.status(ready ? 200 : 503).json({});');
    expect(dyn.codes).toEqual([200]);
    expect(dyn.dynamicStatus).toEqual(['ready ? 200 : 503']);
  });
  test('#6 采集口自证：手抄镜像漏项是"双向失明"，必须由判据自己抓（不是靠总数>120）', () => {
    // lead 在 docs/openapiSync 上踩到的形状：MOUNTS 手抄漏了 versionRoutes ⇒ 那个端点既不进
    // "漏文档"也不进"幽灵文档"，两条对账同时看不见它，闸却全绿。
    // 本闸的 routeOps 是解析来的，但解析器仍可能整体漏掉一个文件 / 一条分支 ——
    // 那时 #1 的"总数 > 120"照样成立（130 个照样大于 120），只有逐文件的采集口自证看得见。
    expect(coverageViolations(ROUTE_OPS)).toEqual([]);

    // 变异自证：从采集结果里删掉 versionRoutes 的全部端点 ⇒ 本判据红、而 #1 与 #2 仍绿
    const withoutVersion = ROUTE_OPS.filter((o) => !o.source.endsWith('versionRoutes.js'));
    expect(withoutVersion.length).toBeGreaterThan(120); // #1 的总数门槛抓不到
    // #2 只是少看一个端点，不会报错 —— 与"全表"跑出来的结果逐项相同（不写死 [] 是刻意的：
    // 本文件其它变异用例会把 SPEC 改坏，这里若写死 [] 就会跟着红，红的来源就不再是采集口）。
    expect(statusViolations(SPEC, withoutVersion)).toEqual(statusViolations(SPEC, ROUTE_OPS));
    expect(coverageViolations(withoutVersion)).toEqual([
      { kind: 'route-file-silent', detail: 'versionRoutes.js' },
    ]);

    // 反向：app.js 的内联端点整段解析失败时也必须红（否则 /health、/readyz、/metrics 全消失而无人发现）
    const withoutApp = ROUTE_OPS.filter((o) => o.source !== 'src/app.js');
    expect(coverageViolations(withoutApp)).toEqual([
      { kind: 'app-inline-silent', detail: 'src/app.js' },
    ]);
  });
});
