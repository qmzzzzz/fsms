/**
 * 「没验成」不得被当成「验过了」
 *
 * `report.intact` 的字面含义只是"扫过的这批没断"，它不蕴含"扫全了"、
 * "hmac 层真参与了校验"、"集合里有东西可扫"。修复前 auditController 只看
 * `intact`（外加 hmacChecked），于是三种"不完整"都被回答成「审计链完整」并把核验审计记成 low：
 *   ① HMAC_SECRET 未配置时 hmac 层**整段跳过**（无密钥 SHA-256 可被整条链重算）；
 *   ② 窗口撞上 maxRecords 而库里还有更多（局部结论）；
 *   ③ 集合为 0 条（绕过模型钩子直连 deleteMany({}) 即可造出，等于为灭迹签发合格证）。
 * 运维脚本一直三类都管，在线侧才是 UI 与运维实际读的那一个，错得更贵。
 * 现两侧共用 services/auditChainVerify.js 里的 computeChainVerdict 唯一判据。
 *
 * 只替换三个边界：verifyAuditChain（控制器内惰性 require，改模块属性即生效）、
 * AuditLog.create（核验审计真实落库，截住才读得到 riskLevel）与
 * AuditLog.estimatedDocumentCount（集合条数即"扫全了没"的分母）。
 * res 桩必须带 locals：控制器会写 res.locals.skipGlobalAudit。
 */

const verifyModule = require('../services/auditChainVerify');
const AuditLog = require('../models/AuditLog');
const { verifyAuditChainIntegrity } = require('../controllers/auditController');

/**
 * 必须连库：控制器在核验前后还会走别的模型调用，mongoose 未连接时不会立刻报错，
 * 而是把命令压进 bufferCommands 队列直到超时（实测每例卡 ~20s → 整套直接超时失败）。
 * 这类"没连库"的表现是超时而不是断言失败，容易被误判成产品问题。
 */
beforeAll(async () => {
  const mongoose = require('mongoose');
  if (mongoose.connection.readyState === 0) {
    await mongoose.connect(process.env.MONGODB_URI);
  }
});

afterAll(async () => {
  const mongoose = require('mongoose');
  if (mongoose.connection.readyState !== 0) {
    await mongoose.connection.close();
  }
});

const realVerify = verifyModule.verifyAuditChain;
const realCreate = AuditLog.create;
const realEstimatedDocumentCount = AuditLog.estimatedDocumentCount;

// 扫描口径必须一并模拟：判据把"没回传 scanned"当作局部校验（fail-closed ⇒ 永不判 0），
// 缺这个字段的桩会让所有"应当宣称完整"的用例红成"口径未知"，读起来像产品缺陷。
// filter 取 {}（服务层对无 filter 的扫描就是回显空对象），与被测的在线路径一致。
//
// legacy 同理，且是同一族 fail-closed 的第二格：判据用它判断"扫到的这批里有没有
// 一条真的带 hash"。缺它 ⇒ 按"整窗无哈希"处理 ⇒ 一律否决（宁 INCOMPLETE，不假 PASS）。
// 生产报告（verifyAuditChain）无条件写出 legacy，所以桩必须像生产报告那样带上它；
// 缺字段的形态只可能来自测试桩，与上面 hmacChecked 那条注释同一个道理。
// 这里的桩描述"全量、无断裂、可背书"的现场 ⇒ legacy 必须是 0（一条 legacy 都没有）。
const BASE = {
  total: 10,
  breaks: 0,
  byType: {},
  samples: [],
  intact: true,
  legacy: 0,
  scanned: { maxRecords: 20000, fromLatest: true, filter: {} },
};

/** 空链即可：核验服务只用到 find().sort().limit().lean() 这一条链式接口 */
function emptyChainModel() {
  return {
    find: () => {
      const query = {
        sort: () => query,
        limit: () => query,
        lean: () => [],
      };
      return query;
    },
  };
}

/**
 * @param {object} report 伪造的核验报告
 * @param {object} [opts]
 * @param {number} opts.collectionTotal 库里实际条数（判据拿它判断"扫全了没"和"有没有东西可扫"）；
 *   默认与 report.total 相等，即"窗口==全量"这一最常见情形
 * @param {object} opts.query 请求 query，limit 用于把 maxRecords 压到窗口内以造出截断
 * @returns {Promise<{body:?object, audit:?object, nextErr:?Error}>}
 *   nextErr 一并返回：控制器被 asyncHandler 包住，内部抛错会走 next 而非 reject，
 *   不把它取出来就会看到"res 从没被写过"的无因失败（本次改动踩过）。
 */
async function runWith(report, opts = {}) {
  const { collectionTotal = report.total, query = {} } = opts;
  const recorded = [];
  verifyModule.verifyAuditChain = async () => report;
  // 必须是 async：控制器对 create() 结果挂了 .catch(onAuditWriteFailure(...))；
  // 且必须截住 create——核验审计是真实落库的，不截住就会写进本文件的隔离库
  AuditLog.create = async (entry) => {
    recorded.push(entry);
    return entry;
  };
  AuditLog.estimatedDocumentCount = async () => collectionTotal;

  const req = {
    query,
    user: { userId: '000000000000000000000001', username: 'auditor', sessionId: null },
    ip: '203.0.113.1',
    method: 'GET',
    originalUrl: '/api/security/audit-logs/verify',
    get: () => 'probe-agent',
  };
  const res = {
    locals: {},
    _body: null,
    status(code) {
      res._code = code;
      return res;
    },
    json(body) {
      res._body = body;
      return res;
    },
  };
  let nextErr = null;

  try {
    await verifyAuditChainIntegrity(req, res, (e) => {
      nextErr = e;
    });
  } finally {
    verifyModule.verifyAuditChain = realVerify;
    AuditLog.create = realCreate;
    AuditLog.estimatedDocumentCount = realEstimatedDocumentCount;
  }
  return { body: res._body, audit: recorded[0], nextErr };
}

afterEach(() => {
  verifyModule.verifyAuditChain = realVerify;
  AuditLog.create = realCreate;
  AuditLog.estimatedDocumentCount = realEstimatedDocumentCount;
});

describe('审计链核验：hmac 层未校验时不得宣称完整', () => {
  test('核心：HMAC 未配置时话术必须自承「不构成完整性证明」', async () => {
    const { body, audit, nextErr } = await runWith({ ...BASE, hmacChecked: false });
    expect(nextErr).toBeNull();
    expect(body).not.toBeNull();
    expect(body.message).not.toBe('审计链完整');
    // 话术来源是判据的 reasons（与脚本 INCOMPLETE 同一句），不是控制器自己拼的字符串
    expect(body.message).toContain('HMAC');
    expect(body.message).toContain('hmac 层未参与校验');
    expect(body.message).toContain('不构成完整性证明');
    // data.intact 的机器可读语义保持不变（openapi 契约与多条既有用例在消费它）；
    // 但机器可读的"未校验"信号必须同时可见，否则消费方只看 intact 就会被误导
    expect(body.data.intact).toBe(true);
    expect(body.data.hmacChecked).toBe(false);
    // 核验审计同步降级：这条记录是"核验持续有效"的留存凭据，没验成不能记成 low
    expect(audit.riskLevel).toBe('high');
  });

  test('反向保护：已校验且无断裂 → 仍回答「审计链完整」', async () => {
    const { body } = await runWith({ ...BASE, hmacChecked: true });
    expect(body.message).toBe('审计链完整');
  });

  /**
   * 控制器用的是 `hmacChecked !== false`（缺字段时按已校验处理）。本用例旧版把它
   * 当成"向后兼容"优点断言下来——评审指出这等于给 fail-open 背书：将来收口成
   * `=== true` 会在这里变红，反而诱导出"回退修复"。
   *
   * 这里不再替默认分支说话，而是钉住它成立的前提：报告唯一的生产来源
   * （auditChainVerify）必然显式写出布尔 hmacChecked，"字段缺失"只可能来自测试桩。
   * 两个断言防的是同一件事，但只有这个版本会在真正加固时帮忙而非碍事。
   *
   * 顺带实测记录：把 process.env.HMAC_SECRET 删掉**不会**让真实报告变 false——
   * 密钥取自 src/config 单例（加载期定型，且 tests/setup.js 在加载前就注入了测试密钥），
   * 所以 false 分支只能在控制器边界用桩覆盖（即上面两条用例）。
   */
  test('生产来源必须显式写出布尔 hmacChecked（缺字段形态只可能来自桩）', async () => {
    const { verifyAuditChain } = require('../services/auditChainVerify');
    const { isHmacConfigured } = require('../utils/auditChain');
    const config = require('../config');

    const report = await verifyAuditChain(emptyChainModel(), { maxRecords: 10 });

    expect(Object.prototype.hasOwnProperty.call(report, 'hmacChecked')).toBe(true);
    expect(typeof report.hmacChecked).toBe('boolean');
    // 报告字段与实际配置同源：不得是硬编码常量，也不得读另一份密钥
    expect(report.hmacChecked).toBe(isHmacConfigured());
    expect(isHmacConfigured()).toBe(Boolean(config.hmacSecret));
  });
});

/**
 * 判据合并：在线接口此前只看 `intact && hmacChecked`，运维脚本还看截断与空集合，
 * 同一个事实在两处给出不同结论（脚本退 2，接口答"完整"）。
 * 现在两侧共用 computeChainVerdict，这里钉住新增的两类"不完整"在 HTTP 面同样不放过。
 */
describe('审计链核验：与运维脚本同一判据', () => {
  test('窗口撞上上限且库里还有更多 → 只是局部结论，不得宣称完整', async () => {
    // limit=10 把 maxRecords 压到 report.total，造出"扫了 10 条、库里 50 条"
    const { body, audit, nextErr } = await runWith(
      { ...BASE, total: 10, hmacChecked: true },
      { collectionTotal: 50, query: { limit: '10' } }
    );
    expect(nextErr).toBeNull();
    expect(body.message).not.toBe('审计链完整');
    expect(body.message).toContain('不构成完整性证明');
    expect(body.message).toContain('仅覆盖 10/50');
    expect(body.data.intact).toBe(true);
    // 核验审计同时降级为 high：留存里不得出现"没扫全却记成 low"的绿记录
    expect(audit.riskLevel).toBe('high');
  });

  test('空集合 → 「无断裂」不等于「链完好」（灭迹现场不得签发合格证明）', async () => {
    // 直连 deleteMany({}) 绕过模型钩子即可清空集合，此后 intact 恒真
    const { body, audit, nextErr } = await runWith(
      { ...BASE, total: 0, intact: true, hmacChecked: true },
      { collectionTotal: 0 }
    );
    expect(nextErr).toBeNull();
    expect(body.message).not.toBe('审计链完整');
    expect(body.message).toContain('审计集合为空');
    expect(audit.riskLevel).toBe('high');
  });

  test('真发现断裂时话术取「存在断裂」而非弱化的「未发现断裂」', async () => {
    // 两个条件同时成立（有断裂 + 没扫全）：更严重、可行动的那条必须赢，
    // 否则一条"未发现断裂但不构成证明"的消息会把安全事件读起来像例行提醒
    const { body, audit } = await runWith(
      {
        ...BASE,
        total: 10,
        breaks: 3,
        intact: false,
        byType: { chain_break: 3 },
        hmacChecked: true,
      },
      { collectionTotal: 50, query: { limit: '10' } }
    );
    expect(body.message).toBe('审计链存在断裂');
    expect(audit.riskLevel).toBe('high');
  });

  test('豁免口子只属于运维脚本：HTTP 面没有 allowEmpty/allowNoHmac 的等价输入', async () => {
    // 判据的第四个入参来源固定为本请求算出的 maxRecords 与真实集合条数，
    // 调用方任何 query 参数都无法把 incomplete 洗成 complete：
    // limit 只能变小（更容易判成截断），from 只改窗口起点
    const { body: small } = await runWith(
      { ...BASE, total: 1, hmacChecked: true },
      { collectionTotal: 50, query: { limit: '1', from: 'earliest' } }
    );
    const { body: big } = await runWith(
      { ...BASE, total: 50, hmacChecked: true },
      { collectionTotal: 50, query: { limit: '50', from: 'latest' } }
    );
    expect(small.message).toContain('不构成完整性证明');
    expect(big.message).toBe('审计链完整');
  });
});

/**
 * 告警明细的键必须来自报告，不能来自控制器里手抄的一份清单。
 *
 * 修复前 logger.error 逐项硬编码 hash_mismatch/hmac_missing/hmac_mismatch/chain_break 四类，
 * 而服务层的 byType 有五类（后加的 hash_stripped 正是"抹哈希洗白"那一类）。
 * 后果不是少打一个字段那么轻：收到"发现 N 处断裂"的人按明细去定位，
 * 四类全是 0 便以为报告出错，唯独看不出这 N 处属于哪一类——最危险的那类恰好隐身。
 */
describe('审计链断裂告警：明细与服务层类型清单同源', () => {
  test('byType 里每一个键都要出现在告警里（含后新增的类型）', async () => {
    const logger = require('../utils/logger');
    // 类型清单以真实报告为准，测试里不重抄一遍——否则新增类型时这里同样不会红
    const { verifyAuditChain } = require('../services/auditChainVerify');
    const types = Object.keys(
      (await verifyAuditChain(emptyChainModel(), { maxRecords: 1 })).byType
    );
    expect(types.length).toBeGreaterThanOrEqual(4);

    const byType = Object.fromEntries(types.map((t) => [t, t === 'hash_stripped' ? 2 : 0]));
    const spy = jest.spyOn(logger, 'error').mockImplementation(() => {});
    try {
      const { body, audit } = await runWith(
        { ...BASE, total: 10, breaks: 2, intact: false, byType, hmacChecked: true },
        { collectionTotal: 10 }
      );
      expect(body.message).toBe('审计链存在断裂');
      expect(audit.riskLevel).toBe('high');
      const line = spy.mock.calls.map((args) => String(args[0])).join('\n');
      for (const t of types) expect(line).toContain(`${t}=`);
      expect(line).toContain('发现 2 处断裂');
      expect(line).toContain('hash_stripped=2');
    } finally {
      spy.mockRestore();
    }
  });

  test('无断裂时不打断裂告警（否则日志里凭空多出安全事件）', async () => {
    const logger = require('../utils/logger');
    const spy = jest.spyOn(logger, 'error').mockImplementation(() => {});
    try {
      const { body } = await runWith({ ...BASE, hmacChecked: true }, { collectionTotal: 10 });
      expect(body.message).toBe('审计链完整');
      expect(spy).not.toHaveBeenCalled();
    } finally {
      spy.mockRestore();
    }
  });
});

/**
 * F-154：判据必须机器可读
 *
 * 上面那批用例本身就暴露了形态：话术（body.message）说"不构成完整性证明"，
 * 而 `body.data.intact` 仍是 true，Swagger 教的恰恰是 intact/breaks/byType。
 * 只读 data 的消费方（CI 门禁、前端绿点）拿到的仍是合格证。
 * 现在 payload 里并列给出判据字段，message 保持原样——两条都要能单独成立。
 */
describe('F-154：核验结论必须能在 data 里读到，不依赖中文话术', () => {
  test('一条都没验过：intact 仍为 true（旧语义不悄改），但判据字段必须自承不能背书', async () => {
    const { body } = await runWith({ ...BASE, total: 0, intact: true }, { collectionTotal: 500 });
    expect(body.data.intact).toBe(true);
    expect(body.data.canAttestIntact).toBe(false);
    expect(body.data.verdictCode).toBe(2);
    // 没有分母，消费方无从知道"扫了多少 / 库里有多少"⇒ 必须回传
    expect(body.data.collectionTotal).toBe(500);
    expect(body.data.verdictReasons.join(' ')).toContain('一条都没验过');
  });

  test('正对照：全量、hmac 真跑过 ⇒ 判据字段给出可背书（不是恒 false 的死闸）', async () => {
    const { body } = await runWith({ ...BASE, hmacChecked: true }, { collectionTotal: 10 });
    expect(body.data.canAttestIntact).toBe(true);
    expect(body.data.verdictCode).toBe(0);
    expect(body.data.verdictReasons).toEqual([]);
  });

  test('真断裂时 verdictCode=1（不得与"没验成"的 2 混成一格）', async () => {
    const { body } = await runWith(
      { ...BASE, hmacChecked: true, intact: false, breaks: 2, byType: { hash_mismatch: 2 } },
      { collectionTotal: 10 }
    );
    expect(body.data.canAttestIntact).toBe(false);
    expect(body.data.verdictCode).toBe(1);
  });
});
