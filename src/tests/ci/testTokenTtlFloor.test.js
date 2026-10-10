/**
 * 【这台闸守什么】
 *
 * 测试夹具签发的 JWT 寿命。缺陷形态不是"某人写错一个数字"，而是**时间维度上的假红**：
 * 全量 jest 拥挤时实测有套 suite 被排到 80 分钟，而 beforeAll 里普遍签的是 1h 令牌——
 * 令牌在用之前就过期，请求方拿到的是随机 401，红的是"会话有效期"这条无关断言。
 * 这类红无法靠读代码发现，只能靠一把量得出寿命的尺子在全测试树上扫。
 *
 * 【判据】
 * 扫 src/tests 下每个套件里 expiresIn 的字面量写法，按 jsonwebtoken（ms 语义）折成秒，
 * 要求不低于 FLOOR_SECONDS；短于地板的必须逐条登记在 DELIBERATE_SHORT_TTL 里，
 * 清单是**封闭集合**（双向）：出现未登记短 TTL 即红；登记了而源码里已经没有同样红。
 * 这是 KNOWN_UNENFORCED / commentViewSingleSource 的封闭清单姿势——豁免必须是可核对的
 * 清单，不是可以无限堆积的筐。
 *
 * 【为什么地板取 6 小时而不是 2 小时】
 * 实测最坏排队 80 分钟。1h 只给 1.33 倍余量（这就是原来会假红的原因），2h 给 1.5 倍，
 * 6h 给 4.5 倍；同时仍远短于 refresh 的 7 天，不会把"access 本该过期"的语义抹掉——
 * 那条由 DELIBERATE_SHORT_TTL 里那几个零值/负值站点专门钉住。
 *
 * 【已知边界（有意不收，写清楚免得下个读者以为收了）】
 *  - 只扫**字面量**。配置推导值（读 config.jwt.refreshExpire 那种）不扫：那是被测的生产
 *    配置本身，由 durationToMsParity / authCookies 那几套按 exp-iat 现场反推钉住。
 *    采集器把它们单列，并用一条覆盖前提钉住"确实见到了、且没有当成违规"。
 *  - 本文件自排除（SELF）：末条用例的正样本里就有 1h，不排除就会变成自己的靶。
 *  - 不看 web-admin：前端不签 JWT。
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '../../..');
const SELF = 'src/tests/ci/testTokenTtlFloor.test.js';

const FLOOR_SECONDS = 6 * 3600;

const DELIBERATE_SHORT_TTL = {
  '0s': '钉「过期即 401 AUTH_TOKEN_EXPIRED」：必须真的过期，长 TTL 会让这条用例恒走有效分支',
  '-1s': '钉「已过期的 access/refresh 不得再通过校验」：负值即已过期，是语义用例不是夹具',
  '-10s': '登出入口专用：access 已过期仍须能登掉自己的会话（吊销入口不得随 access 一起失效）',
};

const UNIT_SECONDS = { ms: 0.001, s: 1, m: 60, h: 3600, d: 86400 };

/** jsonwebtoken 的 expiresIn 字面量折成秒；不认识的字面量回 null（不许猜） */
function ttlToSeconds(raw) {
  const m = /^(-?\d+(?:\.\d+)?)\s*(ms|s|m|h|d)?$/.exec(String(raw).trim());
  if (!m) return null;
  return Number(m[1]) * UNIT_SECONDS[m[2] || 's'];
}

function listTestFiles(dir, acc = []) {
  if (!fs.existsSync(dir)) return acc;
  for (const name of fs.readdirSync(dir)) {
    const full = path.join(dir, name);
    if (fs.statSync(full).isDirectory()) listTestFiles(full, acc);
    else if (name.endsWith('.test.js')) acc.push(full);
  }
  return acc;
}

const LITERAL_RE = /expiresIn\s*:\s*(['"`])([^'"`]*)\1/;
const HAS_EXPIRES_IN = /expiresIn/;

function collect() {
  const literal = [];
  const nonLiteral = [];
  for (const abs of listTestFiles(path.join(ROOT, 'src/tests'))) {
    const rel = path.relative(ROOT, abs).split(path.sep).join('/');
    if (rel === SELF) continue;
    const lines = fs.readFileSync(abs, 'utf8').split(/\r?\n/);
    lines.forEach((text, i) => {
      if (!HAS_EXPIRES_IN.test(text)) return;
      const m = text.match(LITERAL_RE);
      if (m) literal.push({ rel, line: i + 1, value: m[2] });
      else nonLiteral.push(`${rel}:${i + 1}`);
    });
  }
  return { literal, nonLiteral };
}

describe('测试夹具令牌 TTL 地板', () => {
  const { literal, nonLiteral } = collect();

  test('前提：扫描确实覆盖了测试树（否则下面的对账是空集假绿）', () => {
    expect(literal.length).toBeGreaterThan(150);
    expect(new Set(literal.map((s) => s.value)).size).toBeGreaterThanOrEqual(3);
    // 配置推导值必须被见到且被排除在判据外：这条钉住"采集器没把它们误判成违规"，
    // 也钉住"将来有人删光配置推导写法时覆盖前提先红"，而不是静默缩小射程。
    expect(nonLiteral.length).toBeGreaterThan(0);
  });

  test('字面量寿命不得低于地板，除非逐条登记理由（封闭清单双向）', () => {
    const tooShort = [
      ...new Set(literal.filter((s) => ttlToSeconds(s.value) < FLOOR_SECONDS).map((s) => s.value)),
    ].sort();
    expect(tooShort).toEqual(Object.keys(DELIBERATE_SHORT_TTL).sort());
    // 每条理由必须是"能拿去问人的具体句子"，不接受空串或占位
    for (const v of tooShort) {
      expect((DELIBERATE_SHORT_TTL[v] || '').length).toBeGreaterThan(10);
    }
  });

  test('低于地板的每一处都落在登记值上（不是只对账了取值集合）', () => {
    const stray = literal.filter(
      (s) => ttlToSeconds(s.value) < FLOOR_SECONDS && !(s.value in DELIBERATE_SHORT_TTL)
    );
    expect(stray.map((s) => `${s.rel}:${s.line} ${s.value}`)).toEqual([]);
  });

  test('采集到的字面量一律可解析（解析不出 = 闸门对它沉默，正是要拦的）', () => {
    const unparsed = [
      ...new Set(literal.map((s) => s.value).filter((v) => ttlToSeconds(v) === null)),
    ];
    expect(unparsed).toEqual([]);
  });

  test('探测器自证：ttlToSeconds 的正样本与负样本各自钉死（改坏解析器必须红）', () => {
    expect(ttlToSeconds('1h')).toBe(3600);
    expect(ttlToSeconds('30m')).toBe(1800);
    expect(ttlToSeconds('90s')).toBe(90);
    expect(ttlToSeconds('7d')).toBe(604800);
    expect(ttlToSeconds('-10s')).toBe(-10);
    expect(ttlToSeconds('24h')).toBe(86400);
    expect(ttlToSeconds('1.5h')).toBe(5400);
    expect(ttlToSeconds('500ms')).toBe(0.5);
    // 负样本：jsonwebtoken 不接受的写法必须回 null，不许猜成一个数
    expect(ttlToSeconds('abc')).toBeNull();
    expect(ttlToSeconds('')).toBeNull();
    expect(ttlToSeconds('1 hour')).toBeNull();
    expect(ttlToSeconds(undefined)).toBeNull();
  });
});
