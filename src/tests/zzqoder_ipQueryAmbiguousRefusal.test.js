'use strict';

/**
 * （2026-09-19）：IP 命中查询接口不得对歧义 IP 给出 verdict
 *
 * 这条是**自我一致性收尾**，缺陷由此前的 IP 收紧改动引入：
 * 让 `models/IPBlacklist.findMatchingEntries` 对 `0177.0.0.1`、`2130706433`
 * 这类歧义文本返回空名单（请求期该客户端既不命中黑也不命中白——这是对的）。
 * 但 `GET /api/security/ip-list/query` 的响应体里还印着
 * `normalizedIP: normalizeIP(rawIP)` ⇒ 同一份响应同时说了两件相反的事：
 *   "这个地址归一化后是 127.0.0.1" + "verdict = allowed"
 * 而 127.0.0.1 可能正躺在黑名单里。管理员读到的是一条**看似已核对过的错结论**，
 * 且 HTTP 200 无任何提示——比 之前"按 127.0.0.1 判定为 blocked"更误导，
 * 因为那时至少两个字段说的是同一个地址。
 *
 * 处置：歧义文本在**入站处明确拒答**（复用已注册的 IP_FORMAT_INVALID，不新增错误码），
 * 并把宽松解析出的规范地址回给调用方，让其用规范写法重查。
 * 规范形态（含 `::ffff:` 映射写法）的行为必须一字不变——那是本判据的正对照。
 */

const mongoose = require('mongoose');

const makeRes = () => {
  const res = { statusCode: 200, body: null, locals: {} };
  res.status = (c) => {
    res.statusCode = c;
    return res;
  };
  res.json = (b) => {
    res.body = b;
    return res;
  };
  res.setHeader = () => res;
  return res;
};

describe('zzqoder IP 命中查询的歧义文本拒答', () => {
  let IPBlacklist;
  let queryIPMatch;
  const next = (err) => {
    throw err; // asyncHandler 不该吞下任何东西：有错就是未覆盖分支
  };

  const call = async (ip) => {
    const res = makeRes();
    await queryIPMatch({ query: ip === undefined ? {} : { ip }, get: () => '' }, res, next);
    return res;
  };

  beforeAll(async () => {
    IPBlacklist = require('../models/IPBlacklist');
    ({ queryIPMatch } = require('../controllers/ipListController'));
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
  });

  beforeEach(async () => {
    await IPBlacklist.deleteMany({});
    IPBlacklist.invalidateSnapshot();
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) await mongoose.connection.close();
  });

  describe('歧义形态：明确拒答，不给 verdict', () => {
    // 127.0.0.1 确实在黑名单里——这正是"错结论有杀伤力"的前提
    beforeEach(async () => {
      await IPBlacklist.blockIP('127.0.0.1', { type: 'black', durationMs: 0, reason: 'f84' });
    });

    // 每行的第二个值是**实测**的宽松解析结果（`node -e` 直接调 normalizeIP 取得），
    // 不是推断：最后一行尤其说明问题——映射前缀被吞掉，文本看着像在问 127.0.0.1，
    // 实际被解析成 177.0.0.1，接口若照样给 verdict 就是在答另一个问题。
    test.each([
      ['八进制', '0177.0.0.1', '127.0.0.1'],
      ['十六进制', '0x7f.0.0.1', '127.0.0.1'],
      ['单数字（=127.0.0.1）', '2130706433', '127.0.0.1'],
      ['八进制无点形态', '017700000001', '127.0.0.1'],
      ['短写', '127.1', '127.0.0.1'],
      ['尾段前导零', '127.0.0.01', '127.0.0.1'],
      ['IPv6 映射里嵌八进制（解析结果彻底错位）', '::ffff:0177.0.0.1', '177.0.0.1'],
    ])('%s ⇒ 400 IP_FORMAT_INVALID（而不是 200 + allowed）', async (_name, ip, expected) => {
      const res = await call(ip);
      expect(res.statusCode).toBe(400);
      expect(res.body.errors.errorCode).toBe('IP_FORMAT_INVALID');
      // 危害本体：修复前这里产出的是 success:true + verdict:'allowed'
      expect(res.body.success).not.toBe(true);
      expect(res.body.data?.verdict).toBeUndefined();
      // 拒答必须给出可用的信息：宽松解析出的规范地址写进响应，调用方不用猜
      expect(res.body.errors.normalizedIP).toBe(expected);
      expect(res.body.message).toContain(expected);
    });
  });

  describe('正对照：规范形态的行为一字不变', () => {
    test('规范地址命中黑名单 ⇒ verdict=blocked', async () => {
      await IPBlacklist.blockIP('127.0.0.1', { type: 'black', durationMs: 0, reason: 'f84' });
      const res = await call('127.0.0.1');
      expect(res.statusCode).toBe(200);
      expect(res.body.data.verdict).toBe('blocked');
      expect(res.body.data.primaryBlack.ip).toBe('127.0.0.1');
    });

    test('IPv6 映射写法仍与规范 v4 等价（严格化不许误伤真实客户端）', async () => {
      await IPBlacklist.blockIP('127.0.0.1', { type: 'black', durationMs: 0, reason: 'f84' });
      const res = await call('::ffff:127.0.0.1');
      expect(res.statusCode).toBe(200);
      expect(res.body.data.verdict).toBe('blocked');
    });

    test('白名单优先规则照常生效', async () => {
      await IPBlacklist.blockIP('10.9.9.9', { type: 'black', durationMs: 0, reason: 'f84' });
      await IPBlacklist.blockIP('10.9.9.9', { type: 'white', durationMs: 0, reason: 'f84' });
      const res = await call('10.9.9.9');
      expect(res.body.data.verdict).toBe('whitelisted');
    });

    test('CIDR 网段命中照常返回最宽条目', async () => {
      await IPBlacklist.blockIP('192.168.0.0/16', { type: 'black', durationMs: 0, reason: 'f84' });
      const res = await call('192.168.5.7');
      expect(res.body.data.verdict).toBe('blocked');
      expect(res.body.data.primaryBlack.ip).toBe('192.168.0.0/16');
    });
  });

  describe('既有 400 契约不变形', () => {
    test.each([
      ['未传', undefined],
      ['空串', ''],
      ['纯空白', '   '],
      ['CIDR 当查询目标', '10.0.0.0/8'],
      ['完全不是 IP', 'not-an-ip'],
      ['非字符串（extended parser 造出的数组）', ['127.0.0.1', '10.0.0.1']],
      ['非字符串（操作符对象）', { $ne: 'x' }],
    ])('%s ⇒ 400 IP_SINGLE_REQUIRED', async (_name, ip) => {
      const res = await call(ip);
      expect(res.statusCode).toBe(400);
      expect(res.body.errors.errorCode).toBe('IP_SINGLE_REQUIRED');
    });
  });
});
