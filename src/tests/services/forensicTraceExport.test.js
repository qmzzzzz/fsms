/** T5 溯源查询与签名导出：查询必须拒绝全表扫描；导出必须「没密钥就不签」且篡改能被判红。 */
const trace = require('../../services/forensicTrace');
const exp = require('../../services/forensicExport');

beforeEach(() => {
  trace.resetTraceState();
  jest.restoreAllMocks();
});

const modelOf = (records) => {
  const m = {
    find: jest.fn(() => ({
      select: jest.fn(() => ({
        sort: jest.fn(() => ({ limit: jest.fn(() => ({ lean: jest.fn(async () => records) })) })),
      })),
    })),
    aggregate: jest.fn(async () => []),
  };
  return m;
};

describe('查询条件：拒绝把全表当溯源用', () => {
  test('一个维度都不给 ⇒ 条件为 null（也就不会去查库）', () => {
    expect(trace.conditionOf({})).toBeNull();
  });

  test('地址解析不出 ⇒ 条件也为 null（宁可空结果，不要误抓全表）', () => {
    expect(trace.conditionOf({ ip: '999.999.999.999' })).toBeNull();
  });

  test('IP 走 ipQueryVariants 同源变体：::ffff: 映射形态一并命中', () => {
    const c = trace.conditionOf({ ip: '1.2.3.4' });
    expect(c.ip.$in).toContain('1.2.3.4');
    expect(c.ip.$in).toContain('::ffff:1.2.3.4');
  });

  test('时间区间倒序 ⇒ 条件为 null（否则 Mongo 老实返回 0 条，被读成"这段时间很干净"）', () => {
    const since = new Date('2026-11-02T00:00:00Z');
    const until = new Date('2026-11-01T00:00:00Z');
    expect(since > until).toBe(true); // 前提自证：这一对确实是倒序，改了日期常量本条也不会空转
    expect(trace.conditionOf({ ip: '1.2.3.4', since, until })).toBeNull();
    // 正序同一天边界照旧放行（不能把合法区间一起拒掉）
    expect(trace.conditionOf({ ip: '1.2.3.4', since: until, until: since })).not.toBeNull();
    // 零长区间（起止同一时刻 = 精确查一个瞬间）是合法查询，不许被"必须严格正序"顺手拒掉；
    // 少了这一条，判据从 `>` 写成 `>=` 也不会有任何用例变红。
    expect(trace.conditionOf({ ip: '1.2.3.4', since: until, until: until })).not.toBeNull();
  });

  test('倒序时间线 ⇒ ok:false 且不查库（判据不可用要报出来，不是给一份空结果）', async () => {
    const model = modelOf([{ ip: '1.2.3.4' }]);
    const r = await trace.traceTimeline({
      model,
      ip: '1.2.3.4',
      since: new Date('2026-11-02T00:00:00Z'),
      until: new Date('2026-11-01T00:00:00Z'),
    });
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('no_criteria');
    expect(model.find).not.toHaveBeenCalled();
  });

  test('时间窗必须有边界（否则七天默认值就形同虚设）', () => {
    const c = trace.conditionOf({ ip: '1.2.3.4', since: new Date('2026-11-01T00:00:00Z') });
    expect(c.createdAt.$gte).toBeInstanceOf(Date);
  });

  test('limit 封顶，防止一次拉爆（溯源页默认不是导出）', () => {
    expect(trace.clampLimit(999999)).toBe(trace.MAX_LIMIT);
    expect(trace.clampLimit(0)).toBe(trace.DEFAULT_LIMIT);
    expect(trace.clampLimit('abc')).toBe(trace.DEFAULT_LIMIT);
  });
});

describe('同一指纹的网段分布：判据不可用时不得退化成全表聚合', () => {
  test('倒序时间窗 + 有指纹 ⇒ ok:false 且不聚合（$match:null 会匹配整个集合）', async () => {
    const model = modelOf([]);
    const r = await trace.actorPools({
      model,
      fingerprint: 'fp-1',
      since: new Date('2026-11-02T00:00:00Z'),
      until: new Date('2026-11-01T00:00:00Z'),
    });
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('no_criteria');
    expect(model.aggregate).not.toHaveBeenCalled();
  });

  test('对照：没有指纹 ⇒ 走 no_fingerprint（与"判据不可用"分开报，不合成一个笼统失败）', async () => {
    const model = modelOf([]);
    const r = await trace.actorPools({ model });
    expect(r.reason).toBe('no_fingerprint');
    expect(model.aggregate).not.toHaveBeenCalled();
  });
});

describe('时间线：只出摘要字段（体只在被标记过时才有）', () => {
  test('无判据 ⇒ ok:false 且不查库', async () => {
    const model = modelOf([]);
    const r = await trace.traceTimeline({ model });
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('no_criteria');
    expect(model.find).not.toHaveBeenCalled();
  });

  test('有判据 ⇒ 正序返回并计 queries', async () => {
    const model = modelOf([{ ip: '1.2.3.4', trigger: { reason: 'brute_force' } }]);
    const r = await trace.traceTimeline({ model, ip: '1.2.3.4' });
    expect(r.ok).toBe(true);
    expect(r.count).toBe(1);
    expect(trace.getTraceStats().queries).toBe(1);
  });

  test('limit 截断时取最近 N 条：查询按时间倒序取数，返回再翻回正序', async () => {
    // 库返回的已经是「最近 N 条」的倒序结果
    const newestFirst = [
      { createdAt: new Date('2026-10-02T00:00:00Z'), ip: '2.2.2.2' },
      { createdAt: new Date('2026-10-01T00:00:00Z'), ip: '1.1.1.1' },
    ];
    const sort = jest.fn(() => ({
      limit: jest.fn(() => ({ lean: jest.fn(async () => newestFirst) })),
    }));
    const model = { find: jest.fn(() => ({ select: jest.fn(() => ({ sort })) })) };
    const r = await trace.traceTimeline({ model, ip: '1.2.3.4', limit: 2 });
    // 页面/导出文案承诺的是「最近 {count} 条」：取数方向反了就会变成「最早 N 条」
    expect(sort).toHaveBeenCalledWith({ createdAt: -1 });
    expect(r.records.map((x) => x.ip)).toEqual(['1.1.1.1', '2.2.2.2']);
  });
});

describe('traceActor：把「他的 ip 池」直接答出来', () => {
  test('汇总触发原因与网段分布，并带上 pools', async () => {
    const model = modelOf([
      { ip: '1.2.3.4', ipSegment: '1.2.3', trigger: { reason: 'brute_force' } },
      { ip: '1.2.3.5', ipSegment: '1.2.3', trigger: { reason: 'brute_force' } },
    ]);
    model.aggregate = jest.fn(async () => [
      {
        _id: '1.2.3',
        hits: 2,
        ips: ['1.2.3.4', '1.2.3.5'],
        firstSeen: new Date(),
        lastSeen: new Date(),
      },
    ]);
    const r = await trace.traceActor({ model, fingerprint: 'f'.repeat(32) });
    expect(r.ok).toBe(true);
    expect(r.triggers).toEqual({ brute_force: 2 });
    // 子文档直接当对象键会被 ToPropertyKey 折成 '[object Object]' ⇒ 分布恒一条。
    // 这条钉住"键必须是 reason"，而不是"恰好拿到了一条字符串"。
    expect(Object.keys(r.triggers)).not.toContain('[object Object]');
    expect(r.segments).toEqual({ '1.2.3': 2 });
    expect(r.pools[0].distinctIps).toBe(2);
  });

  test('无指纹就不查 pools（不给不存在的维度发聚合）', async () => {
    const model = modelOf([]);
    const r = await trace.traceActor({ model, ip: '1.2.3.4' });
    expect(r.pools).toEqual([]);
    expect(model.aggregate).not.toHaveBeenCalled();
  });
});

describe('签名导出：可离线复核', () => {
  const SECRET = 'x'.repeat(32);
  const records = [{ ip: '1.2.3.4', action: 'login_failed' }];

  test('没密钥 ⇒ 拒绝导出，绝不产出看起来签过的包', () => {
    const r = exp.buildExport({ records, secret: '' });
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('no_secret');
  });

  test('正常导出后原文校验通过（否则下面的判红只是恒红）', () => {
    const { pkg } = exp.buildExport({ records, secret: SECRET });
    expect(exp.verifyExport({ pkg, secret: SECRET }).ok).toBe(true);
  });

  test('改一条记录 ⇒ records_modified（签名覆盖记录内容）', () => {
    const { pkg } = exp.buildExport({ records, secret: SECRET });
    const tampered = { ...pkg, records: [{ ip: '9.9.9.9', action: 'login_failed' }] };
    expect(exp.verifyExport({ pkg: tampered, secret: SECRET }).reason).toBe('records_modified');
  });

  test('只改清单锚点不改记录 ⇒ signature_mismatch（锚点也参与签名）', () => {
    const { pkg } = exp.buildExport({
      records,
      secret: SECRET,
      manifestRef: { chainHash: 'a'.repeat(64) },
    });
    const swapped = { ...pkg, manifestRef: { chainHash: 'b'.repeat(64) } };
    expect(exp.verifyExport({ pkg: swapped, secret: SECRET }).reason).toBe('signature_mismatch');
  });

  test('换密钥 ⇒ key_mismatch（不能拿别的密钥冒充）', () => {
    const { pkg } = exp.buildExport({ records, secret: SECRET });
    expect(exp.verifyExport({ pkg, secret: 'y'.repeat(32) }).reason).toBe('key_mismatch');
  });

  test('记录数超上限 ⇒ 拒绝（一次导出不该把内存拉爆）', () => {
    const many = Array.from({ length: exp.MAX_RECORDS + 1 }, (_, i) => ({ i }));
    expect(exp.buildExport({ records: many, secret: SECRET }).reason).toBe('too_many_records');
  });

  test('摘要稳定：键序不同不影响签名（同一批数据两次导出可比对）', () => {
    const a = exp.buildExport({ records: [{ x: 1, y: 2 }], secret: SECRET });
    const b = exp.buildExport({ records: [{ y: 2, x: 1 }], secret: SECRET });
    expect(a.pkg.digest).toBe(b.pkg.digest);
  });
});
