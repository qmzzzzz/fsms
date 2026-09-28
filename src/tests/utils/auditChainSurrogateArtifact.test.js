/**
 * 审计哈希链上的「孤立代理项伪影」（本会话独立实测，非采信任何报告）
 *
 * 缺陷链：
 *   ① `stripControlChars(value, maxLength)` 用 `.length` / `.slice` 按 **UTF-16 码元**截断，
 *      边界落在代理对中间就把一对劈成两半，留下一个**在 UTF-8 里根本不存在**的高代理项；
 *   ② 存储层（BSON 字符串就是 UTF-8）把那个孤立码元改写成 U+FFFD 落盘；
 *   ③ 哈希却在**序列化之前**、用内存文档算（`auditLogHooks.js` 的 pre('save')），
 *      而校验器 `auditChainVerify.js` 是拿**读回来**的文档重算。
 *   ⇒ 「写库前哈希 ≠ 读回重算哈希」：一条没人碰过的记录永久判为 hash_mismatch。
 *
 * 为什么这条值得单独钉：未认证者一条请求（`user-agent: 'A' + '😀'.repeat(400)`）即可投毒，
 * 且产物与**真实篡改同形**；`scripts/verify-audit-chain.js` 的退出码就是部署门禁。
 * 更坏的诱导后果是逼运维去跑重签脚本——台账已两次把那种脚本定性为灭迹风险。
 *
 * 第二条触发面与截断无关：请求体里一个 JSON 转义 `"\ud800"`，`JSON.parse` 自己就产出
 * 孤立代理项，`stripControlCharsDeep`（body/params/query 的统一清洗）照样放行。
 *
 * 判据方向：修法只可能改变"当前已经算不回来"的那批串；BMP 文本与未被劈开的代理对
 * 必须逐字节不变，否则就是改哈希口径（「奇数边界劈开的半个代理项…」那条用例守这条）。
 * 用例按位置引用在此文件不可靠：整份测试跑 `--randomize`，顺序随 seed 变（见下 beforeAll 的造数注释）。
 */

const mongoose = require('mongoose');

const { stripControlChars, stripControlCharsDeep } = require('../../utils/helpers');
const { verifyAuditChain } = require('../../services/auditChainVerify');

/** 逐码元扫描：返回第一处孤立代理项的位置，没有则 null */
const firstLoneSurrogate = (s) => {
  for (let i = 0; i < s.length; i += 1) {
    const code = s.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = s.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return i;
      i += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return i;
    }
  }
  return null;
};

describe('审计链：定长截断不得产出落盘会被改写的码元', () => {
  let AuditLog;
  /**
   * 造数放 beforeAll，不放兄弟用例：后两条用例都要读库，而 `--randomize` 下
   * 「链校验」行可能排在「真库往返」行之前 —— 届时集合还是空的，
   * verifyAuditChain 扫到 0 条，那行就退化成对空窗口签字（seed=777001 实测红）。
   * beforeAll 与用例顺序无关，且让两条用例断言的是**同一条**记录，结论可归属。
   */
  let hostile;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    AuditLog = require('../../models/AuditLog');
    const userAgent = stripControlChars(`A${'😀'.repeat(400)}`, 512);
    const body = stripControlCharsDeep(JSON.parse('{"remark":"备注\\ud800尾部"}'));
    const created = await AuditLog.create({
      action: 'malformed_request_blocked',
      category: 'security',
      username: 'anonymous',
      method: 'TRACE',
      path: '/csp-report',
      ip: '127.0.0.1',
      statusCode: 400,
      userAgent,
      reason: userAgent,
      body,
    });
    // 存的是**清洗后的输入值**本身，不是 doc 上的字段：中间件若改写了值，
    // 往返用例必须能看出来，而不是拿被改写后的值跟自己比。
    hostile = { created, userAgent, body };
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) await mongoose.connection.close();
  });

  test('奇数边界劈开的半个代理项被归一成 U+FFFD，偶数边界与 BMP 文本逐字节不变', () => {
    const emoji = '😀'.repeat(400);
    for (const max of [10, 11, 12, 511, 512, 513]) {
      const out = stripControlChars(emoji, max);
      expect(out.length).toBe(max);
      expect(firstLoneSurrogate(out)).toBeNull();
      if (max % 2 === 0) {
        // 偶数边界本来就切在对外 ⇒ 修法不得动它一个码元
        expect(out).toBe(emoji.slice(0, max));
      } else {
        // 奇数边界 ⇒ 只允许把被劈开的那一半换成 U+FFFD，长度不变、前面的完整字符一个不丢
        expect(out).toBe(`${emoji.slice(0, max - 1)}\uFFFD`);
      }
    }
    for (const clean of ['abc123', '消防设备巡检'.repeat(80), 'A😀B']) {
      expect(stripControlChars(clean, 1024)).toBe(clean);
    }
  });

  test('输入侧的孤立代理项（body 里的 \\ud800 转义）也被归一，成对的不受影响', () => {
    const body = stripControlCharsDeep(
      JSON.parse('{"remark":"备注\\ud800尾部","low":"低半\\udc00开头","ok":"😀完整对"}')
    );
    expect(firstLoneSurrogate(body.remark)).toBeNull();
    expect(body.remark).toBe('备注\uFFFD尾部');
    // 反方向的孤儿（落单的低代理项）同样要归一：JSON.parse('"\\udc00"') 一样能造出来
    expect(firstLoneSurrogate(body.low)).toBeNull();
    expect(body.low).toBe('低半\uFFFD开头');
    expect(body.ok).toBe('😀完整对');
  });

  test('真库往返：清洗后的内存值必须与读回值逐字符相同（哈希对得上的充要条件）', async () => {
    const readBack = await AuditLog.findById(hostile.created._id).lean();
    expect(readBack.userAgent).toBe(hostile.userAgent);
    expect(firstLoneSurrogate(readBack.userAgent)).toBeNull();
    expect(readBack.body.remark).toBe(hostile.body.remark);
  });

  test('官方链校验器对上述记录不得报 hash_mismatch（缺陷原貌：intact=false 且逐条累加）', async () => {
    // 带 filter 只验自己造的那条：全窗扫描的结论取决于"此刻库里还留着谁的造数"，
    // 而本缺陷的判据是**记录级哈希重算**（校验器第 1 层，与顺序无关）。
    // total 精确等于 1 而不是 >0：扫到 0 条时"没有 hash_mismatch"是空窗口给的假绿。
    const report = await verifyAuditChain(AuditLog, { filter: { _id: hostile.created._id } });
    expect(report.total).toBe(1);
    expect(report.byType.hash_mismatch).toBe(0);
    expect(report.intact).toBe(true);
  });
});
