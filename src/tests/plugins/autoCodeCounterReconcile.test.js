/**
 * 自动编号计数器的自愈与可归因性（plugins/autoIncrement.js）
 *
 * 编号唯一性**完全**建立在 counters 集合的一个 `$inc` 上：计数器文档一旦消失
 * （从备份恢复时漏掉 counters、运维清库、把 counters 排除在迁移之外），
 * seq 就从 1 重新开始，生成的编号会与存量文档撞上 `unique` 索引。
 * 后果不是"某条数据脏了"而是**该实体的创建永久失败**：
 *   E11000 → errorHandler 映射成 400「资源已存在」，
 *   而提交请求里根本没有"已存在的资源"——真正坏掉的计数器在错误信息里毫不露面。
 *
 * 本文件钉五格：
 *   ① 唯一索引确实生效（否则下面的"会撞"这一格是假的）；
 *   ② 计数器丢失后新建必须续上存量最大编号，而不是抛 E11000；
 *   ③ 常规连续新建不得因此跳号（自愈不能变成新的坏账）；
 *   ④ 对齐发生时要留下点名根因的日志；计数器丢失的瞬间并发创建时，至少有一条必须
 *      能恢复成功（其余撞唯一键属可重试的常规冲突，不在本条目的治疗范围内）；
 *   ⑤ 对齐的成本只落在"计数器刚被重建"那一格——常规取号路径一次存量查询都不能有。
 *
 * ② 的实现坑：编号是**补零定宽**字符串，按字符串取最大会在跨宽度时取错
 * （`'ZZP-9999' > 'ZZP-10000'` 逐字符比较为真）。用例「跨宽度」专门盯这一格，
 * 用字符串排序的实现会在那里变红。
 *
 * 探针用独立 schema + 独立 collection，只删自己那一把 counters 键，
 * 不碰 FireAlarm/FireDevice 的真实计数器（jest 多 worker 共用同一个内存库）。
 */
const mongoose = require('mongoose');
const logger = require('../../utils/logger');
const autoIncrement = require('../../plugins/autoIncrement');

const PAD = 4;
const PREFIX = 'ZZP';
const COUNTER_ID = `probe_${PREFIX}`;
const codeOf = (seq) => `${PREFIX}-${String(seq).padStart(PAD, '0')}`;

const probeSchema = new mongoose.Schema(
  {
    code: { type: String, required: true, unique: true },
    note: String,
  },
  { collection: 'autocode_probe', versionKey: false }
);
probeSchema.plugin(autoIncrement, {
  field: 'code',
  counterPrefix: 'probe',
  seqPadding: PAD,
  generatePrefix: () => PREFIX,
});

describe('autoIncrement 计数器丢失后的自愈', () => {
  let Probe;
  let counters;

  /** 直接写库种存量：绕过插件与校验，造出"编号已存在但计数器不在"的状态 */
  const seedCodes = async (codes) => {
    await Probe.collection.insertMany(codes.map((code) => ({ code })));
  };
  const maxExistingSeq = async () => {
    const rows = await Probe.find({}).select('code').lean();
    const seqs = rows
      .map((r) => r.code)
      .filter((c) => c.startsWith(`${PREFIX}-`))
      .map((c) => Number(c.slice(PREFIX.length + 1)));
    return seqs.length ? Math.max(...seqs) : 0;
  };

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    Probe = mongoose.model('AutoCodeProbe', probeSchema);
    counters = mongoose.connection.db.collection('counters');
    // unique 索引必须真的在：没有它，"撞号"这一格根本不成立，用例会假绿
    await Probe.syncIndexes();
  });

  afterAll(async () => {
    await Probe.deleteMany({}).catch(() => {});
    await counters.deleteMany({ _id: COUNTER_ID }).catch(() => {});
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  beforeEach(async () => {
    await Probe.deleteMany({});
    await counters.deleteMany({ _id: COUNTER_ID });
  });

  test('前提：code 上的 unique 索引真的在拦截重复（否则"撞号"一格是假的）', async () => {
    await Probe.create({ code: codeOf(1), note: 'first' });
    let err;
    await Probe.create({ code: codeOf(1), note: 'second' }).catch((e) => {
      err = e;
    });
    expect(err).toBeDefined();
    expect(err.code).toBe(11000);
  });

  test('计数器被抹掉后新建：必须续上存量最大编号，而不是抛 E11000', async () => {
    const created = await Promise.all([
      Probe.create({ note: 'a' }),
      Probe.create({ note: 'b' }),
      Probe.create({ note: 'c' }),
    ]);
    // 并发取号顺序不确定，比集合不比位置（位置比对会让本用例在并发下随机红）
    expect(created.map((d) => d.code).sort()).toEqual([codeOf(1), codeOf(2), codeOf(3)]);

    await counters.deleteMany({ _id: COUNTER_ID });

    const recovered = await Probe.create({ note: 'after-reset' });
    expect(recovered.code).toBe(codeOf(4));
    expect(await Probe.countDocuments({})).toBe(4);
  });

  test('反向对照：计数器不丢时连续新建不得跳号（自愈不得变成新的坏账）', async () => {
    const codes = [];
    for (let i = 0; i < 5; i++) codes.push((await Probe.create({ note: `n${i}` })).code);
    expect(codes).toEqual([1, 2, 3, 4, 5].map(codeOf));
  });

  test('跨宽度：存量最大编号超过补零宽度时，对齐必须按数值而不是字符串', async () => {
    // 'ZZP-9999' 逐字符比较大于 'ZZP-10000'，按字符串排序取最大会算出 10000 → 撞号
    await seedCodes([codeOf(2), 'ZZP-10000']);
    // 前提：存量里确实同时存在 4 位与 5 位宽度的编号（否则本用例退化成普通对齐）
    expect(await maxExistingSeq()).toBe(10000);
    await counters.deleteMany({ _id: COUNTER_ID });
    const recovered = await Probe.create({ note: 'after-wide-reset' });
    expect(Number(recovered.code.slice(PREFIX.length + 1))).toBe(10001);
    expect(await Probe.countDocuments({ code: recovered.code })).toBe(1);
  });

  test('其它前缀/其它形态的编号不得参与对齐（只认本计数器生成的形态）', async () => {
    await seedCodes(['E2E-SMOKE-9999', 'ZZP-0003', `${PREFIX}X-0500`]);
    await counters.deleteMany({ _id: COUNTER_ID });
    const recovered = await Probe.create({ note: 'shape-filter' });
    expect(recovered.code).toBe(codeOf(4));
    expect(await Probe.countDocuments({ code: recovered.code })).toBe(1);
    expect(await Probe.countDocuments({})).toBe(4);
  });

  test('对齐发生时要留下点名根因的 warn（运维要看得见是计数器坏了）', async () => {
    const spy = jest.spyOn(logger, 'warn').mockImplementation(() => {});
    try {
      await Probe.create({ note: 'x1' });
      await Probe.create({ note: 'x2' });
      spy.mockClear();
      await counters.deleteMany({ _id: COUNTER_ID });
      await Probe.create({ note: 'x3' });
      const logged = spy.mock.calls.map((c) => String(c[0])).join('\n');
      expect(logged).toContain(COUNTER_ID);
      expect(logged).toContain(codeOf(2));
    } finally {
      spy.mockRestore();
    }
  });

  test('对齐只在计数器刚被重建时发生：常规取号路径不得多问一次存量', async () => {
    const spy = jest.spyOn(Probe, 'aggregate');
    try {
      // beforeEach 已删掉本探针的计数器 ⇒ 第一次创建就是"计数器诞生"，会对齐一次
      await Probe.create({ note: 'birth' });
      expect(spy).toHaveBeenCalledTimes(1);
      spy.mockClear();
      for (let i = 0; i < 4; i++) await Probe.create({ note: `p${i}` });
      expect(spy).not.toHaveBeenCalled();
      await counters.deleteMany({ _id: COUNTER_ID });
      await Probe.create({ note: 'triggers-align' });
      expect(spy).toHaveBeenCalledTimes(1);
    } finally {
      spy.mockRestore();
    }
  });

  test('并发：计数器丢失的瞬间多条创建在飞时，至少要有一条恢复成功', async () => {
    // 存量 0001..0003（顺序创建，确保 persisted max = 3），然后抹掉计数器
    for (let i = 0; i < 3; i++) await Probe.create({ note: `base${i}` });
    await counters.deleteMany({ _id: COUNTER_ID });
    const settled = await Promise.allSettled([
      Probe.create({ note: 'c1' }),
      Probe.create({ note: 'c2' }),
      Probe.create({ note: 'c3' }),
    ]);
    const codes = settled
      .filter((r) => r.status === 'fulfilled')
      .map((r) => Number(r.value.code.slice(PREFIX.length + 1)));
    // 修复前三条全部从 1 起重排 → 全部撞唯一键 → 成功数为 0，本用例红
    expect(codes.length).toBeGreaterThanOrEqual(1);
    expect(Math.min(...codes)).toBeGreaterThan(3);
    expect(new Set(codes).size).toBe(codes.length);
    expect(await Probe.countDocuments({})).toBe(3 + codes.length);
    // 失败方（若有）必须是显式的唯一键冲突，不得静默写入重号
    for (const r of settled.filter((x) => x.status === 'rejected')) {
      expect(r.reason.code).toBe(11000);
    }
  });
});
