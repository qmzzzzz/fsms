const { markResponseAbortedByError } = require('../../middleware/errorHandler');
const { stripControlChars } = require('../../utils/helpers');
const { canonicalPayload, computeHash } = require('../../utils/auditChainPayload');

jest.mock('../../services/auditBuffer', () => ({ push: jest.fn() }));
const auditBuffer = require('../../services/auditBuffer');

/**
 * 更正事件（`markResponseAbortedByError`）的字节形态（批次 71）。
 *
 * 【为什么单独钉这一条】流式导出在表头已发出后失败时，全局审计那条记录已经写出，
 * append-only 的正解是追加一条更正事件——它经 `auditBuffer.push` 进**批量路径**，
 * 也就是「先算哈希、后铸造」那一侧。本仓在批次 34 立过一条不变量：
 * **任何喂给哈希/落盘的定长截断，必须在截断之后做孤立代理项归一**。
 * 这条写入点当时不在覆盖面里，用的仍是裸 `String(text).slice(0, 512)`；
 * `auditBuffer` 自身不做任何清洗（其源码内无 stripControlChars/sanitize），
 * 于是半个代理对会一路进哈希载荷，而落盘编码时它被替换成 U+FFFD
 * ⇒ 内存值 ≠ 落库值 ⇒ 这条记录**永久 hash_mismatch**，与真实篡改同形，
 * 而且它是「系统自己承认出错」的那条事件，核验器红起来最难排查。
 *
 * 【三条用例的分工】① 钉修复本身（落库形态＝清洗后的形态）；② 把机理钉成前提，
 * 不依赖被测码，证明「裸 slice」确实让内存哈希与落盘重算分叉——免得后来人把这条读成洁癖；
 * ③ 登记表：这个函数体内不许再出现未经清洗的定长截断，新增一格必须当场回答同一问题。
 */

const ASTRAL = '\u{1D400}'; // 2 个 UTF-16 单元：高代理 D835 + 低代理 DC00

/** 返回第一个孤立代理项的下标，没有则 null（与既有代理项用例同款判据） */
function firstLoneSurrogate(s) {
  for (let i = 0; i < s.length; i += 1) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      if (!(s.charCodeAt(i + 1) >= 0xdc00 && s.charCodeAt(i + 1) <= 0xdfff)) return i;
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      if (!(s.charCodeAt(i - 1) >= 0xd800 && s.charCodeAt(i - 1) <= 0xdbff)) return i;
    }
  }
  return null;
}

/** 落盘侧的 UTF-8 编码回环：未配对的代理项被替换成 U+FFFD（与驱动/BSON 同形） */
const wireRoundTrip = (value) => Buffer.from(value, 'utf8').toString('utf8');

/** 512 边界正好落在代理对中间的一份失败原因文本 */
const splitAtBoundary = () => 'a'.repeat(511) + ASTRAL + ' 导出中断';

const baseReq = () => ({
  method: 'GET',
  originalUrl: '/api/reports/audit-logs/export?format=xlsx',
  path: '/api/reports/audit-logs/export',
  ip: '10.1.2.3',
  id: 'req-1',
  user: { userId: 'u1', username: 'auditor' },
});

const writtenRes = () => ({ locals: { auditRecordWritten: true }, statusCode: 200 });

/**
 * 扫「未经清洗的定长截断」：任何 `.slice(0, N)` 若其左侧 80 个字符内没有
 * `stripControlChars(`，就当成裸截断。（清洗的正解写法是 stripControlChars(x, N)，
 * 截断在清洗函数内部完成，函数体里不会出现裸 `.slice(0, N)`。）
 */
function findUnguardedTruncations(text) {
  const re = /\.slice\(\s*0\s*,\s*\d+\s*\)/g;
  const out = [];
  let m;
  while ((m = re.exec(text)) !== null) {
    const before = text.slice(Math.max(0, m.index - 80), m.index);
    if (!/stripControlChars\(/.test(before)) out.push(m[0]);
  }
  return out;
}

describe('更正审计事件的 reason 截断必须与哈希链同一把尺', () => {
  beforeEach(() => auditBuffer.push.mockClear());

  it('落在 512 边界的代理对不得留下孤立代理项，且必须是清洗后的形态', () => {
    const text = splitAtBoundary();
    markResponseAbortedByError(baseReq(), writtenRes(), text);

    expect(auditBuffer.push).toHaveBeenCalledTimes(1);
    const doc = auditBuffer.push.mock.calls[0][0];
    expect(doc.body.reason).toBe(stripControlChars(text, 512));
    expect(firstLoneSurrogate(doc.body.reason)).toBeNull();
  });

  it('前提自证：裸 slice(0,512) 的同一份文本确实让内存哈希与落盘重算分叉', () => {
    const raw = String(splitAtBoundary()).slice(0, 512);
    expect(firstLoneSurrogate(raw)).toBe(511); // 边界确实劈开了代理对
    expect(firstLoneSurrogate(wireRoundTrip(raw))).toBeNull(); // 落盘后形态已变（U+FFFD）

    const fork = (value) => {
      const doc = { body: { reason: value, reqId: 'req-1' } };
      const stored = { body: { reason: wireRoundTrip(value), reqId: 'req-1' } };
      return {
        inMemory: computeHash('0'.repeat(64), canonicalPayload(doc, 4)),
        afterWire: computeHash('0'.repeat(64), canonicalPayload(stored, 4)),
      };
    };

    const bad = fork(raw);
    expect(bad.inMemory).not.toBe(bad.afterWire); // 这条缺陷的真实后果：永久 hash_mismatch
    const good = fork(stripControlChars(splitAtBoundary(), 512));
    expect(good.inMemory).toBe(good.afterWire); // 清洗写法在同一判据下闭合
  });

  it('登记表：该函数体内不得再有未经清洗的定长截断（判据自身要有牙）', () => {
    const fs = require('fs');
    const src = fs.readFileSync(require.resolve('../../middleware/errorHandler.js'), 'utf8');
    const code = src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
    const body = code.slice(code.indexOf('function markResponseAbortedByError'));

    // 前提自证：切片非空（函数名改了这里就是空串，判据会假绿）
    expect(body.length).toBeGreaterThan(500);
    expect(findUnguardedTruncations(body)).toEqual([]);

    // 判据反向自证：把缺陷写法塞回去必须被扫到，且清洗写法必须扫不出
    expect(findUnguardedTruncations('body: { reason: String(text).slice(0, 512) }')).toEqual([
      '.slice(0, 512)',
    ]);
    expect(findUnguardedTruncations('body: { reason: stripControlChars(text, 512) }')).toEqual([]);
  });
});
