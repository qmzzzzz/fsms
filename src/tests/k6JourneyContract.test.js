'use strict';

/**
 * b（2026-09-19）：scripts/perf/k6-core-journeys.js 的可证伪契约
 *
 * k6 脚本不在 jest 里执行（仓库里没有 k6 运行时），所以这里做两件能真正证伪的事：
 *  1) 语法：拷成 .mjs 交给 `node --check` 解析——改坏 ESM 语法必红；
 *  2) 结构：把「这次修掉的三条」钉在代码上（缺凭据即停、显式 Bearer、
 *     登录失败不再往下打），并自带负向自证，避免退化成恒绿的文本断言。
 *
 * 踩过的坑（已写进 code 视图）：注释里会解释「原来错在哪」，
 * 文本断言若在原文上做，会命中注释而被错误的文本满足——首轮 M2 变异就是这么活的。
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

const SCRIPT = path.join(__dirname, '../../scripts/perf/k6-core-journeys.js');
const src = fs.readFileSync(SCRIPT, 'utf8').replace(/\r\n/g, '\n');
const code = src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');

describe('k6 核心旅程脚本契约', () => {
  test('仍是可解析的 ESM（无 k6 运行时，语法是唯一能自动执行的门禁）', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'probe-k6-'));
    const copy = path.join(dir, 'journey.mjs');
    try {
      fs.copyFileSync(SCRIPT, copy);
      expect(() =>
        execFileSync(process.execPath, ['--check', copy], { encoding: 'utf8', stdio: 'pipe' })
      ).not.toThrow();
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
    // 前提自证：视图里确实有可执行代码，否则下面的结构断言全是空对空
    expect(code).toContain('export default function');
  });

  test('缺 K6_USER/K6_PASS 时 setup() 直接抛错，不跑满全程测 401', () => {
    expect(code).toMatch(/export function setup\(\)\s*\{[\s\S]*?throw new Error/);
    expect(code).toMatch(/if\s*\(\s*!USERNAME\s*\|\|\s*!PASSWORD\s*\)/);
    // 负向自证：判据确实会失败（空 setup 体不满足上面的正则）
    expect('export function setup() {\n}'.replace(/^\s*\/\/.*$/gm, '')).not.toMatch(
      /export function setup\(\)\s*\{[\s\S]*?throw new Error/
    );
  });

  test('凭据以显式 Bearer 下发，不再依赖自动 cookie jar', () => {
    expect(code).toMatch(/Authorization:\s*`Bearer \$\{authToken\}`/);
    expect(code).toMatch(/http\.get\([\s\S]{0,200}Authorization/);
    // 死代码 jarCookies 是「以为要手工管 cookie」的痕迹，留着会误导下一个改脚本的人
    expect(code).not.toMatch(/jarCookies/);
    // 负向自证：视图里没有 cookie API，说明判据不是靠巧合通过
    expect(code).not.toMatch(/cookieJar|\.jar\b/);
    // 前提自证：注释确实被剥离过（原文比代码视图长），否则 code 视图等于原文、
    // 首轮那种「断言命中注释」的假绿会原样复发
    expect(src.length).toBeGreaterThan(code.length);
  });

  test('F-64b：登录失败真的结束本次迭代（原实现的 return 只跳出了 group 回调）', () => {
    const body = code.slice(code.indexOf('export default function'));
    const guard = body.search(/\n {2}if \(!login\(\)\)/);
    const firstGroup = body.indexOf('group(');
    expect(guard).toBeGreaterThan(-1);
    expect(firstGroup).toBeGreaterThan(-1);
    // 守卫必须在任何 group( 之前，否则那个 return 只跳出回调
    expect(guard).toBeLessThan(firstGroup);
    // 负向自证：把守卫放进 group 回调里（F-64b 原样）必须被本条抓到
    expect(
      /\n {2}if \(!login\(\)\)/.exec(
        "  group('x', () => {\n    if (!login()) {\n      return;\n    }"
      )
    ).toBe(null);
  });

  test('offset 深页单独计量且不设凭空阈值（否则首页 P95 基线被退化页污染）', () => {
    expect(code).toMatch(/new Trend\('deep_page_latency_ms'/);
    const thresholdBlock = code.slice(
      code.indexOf('thresholds: {'),
      code.indexOf('}', code.indexOf('list_latency_ms:'))
    );
    expect(thresholdBlock).toContain('list_latency_ms');
    // 只断言「没有阈值条目」，不能断言「不含这个词」——注释里就解释过为什么不设
    expect(thresholdBlock).not.toMatch(/^\s*deep_page_latency_ms:\s*\[/m);
    // 深页请求必须显式带上深页指标，否则会落回 listLatency
    expect(code).toMatch(/offset 深页',\s*deepPageLatency\)/);
    // 留档摘要里也要有它，否则首轮实测无处回填
    expect(code).toContain('deep_page_latency_ms: data.metrics.deep_page_latency_ms?.values');
  });
});
