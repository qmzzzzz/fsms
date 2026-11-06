/** T5 溯源查询与签名导出：查询必须拒绝全表扫描；导出必须「没密钥就不签」且篡改能被判红。
 * 另钉三件读侧契约：行摘要把 response.status/trigger.reason 提升为顶层 status/reason、
 * SUMMARY_FIELDS 不得再有模型不存在的幽灵投影路径、按 IP/网段溯源时「他的 ip 池」由
 * 库内指纹派生（derivedPools）而非恒空。 */
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

describe('时间线行摘要：子文档字段提升到行顶层（界面「触发说明/状态码」两列的数据源）', () => {
  test('response.status / trigger.reason → 顶层 status / reason，response 残壳拆除', async () => {
    const model = modelOf([
      {
        ip: '1.2.3.4',
        trigger: { reason: 'brute_force', markedAt: new Date('2026-11-01T00:00:00Z') },
        response: { status: 401 },
      },
    ]);
    const r = await trace.traceTimeline({ model, ip: '1.2.3.4' });
    expect(r.ok).toBe(true);
    const row = r.records[0];
    expect(row.status).toBe(401);
    expect(row.reason).toBe('brute_force');
    // 摘要投影只带 response.status；提升完必须拆壳，别把空 response 对象漏给导出
    expect(row.response).toBeUndefined();
    expect(row.trigger).toEqual({ reason: 'brute_force', markedAt: expect.any(Date) });
  });

  test('缺响应/缺原因的旧行：如实落 null，不造 0 或空串冒充', async () => {
    const model = modelOf([{ ip: '1.2.3.4' }]);
    const r = await trace.traceTimeline({ model, ip: '1.2.3.4' });
    expect(r.records[0].status).toBeNull();
    expect(r.records[0].reason).toBeNull();
  });
});

describe('摘要投影：只许写模型真实存在的路径（幽灵投影回归闸）', () => {
  // 背景：SUMMARY_FIELDS 曾投影顶层 status/reason/markedAt——模型里没有这三个字段
  // （状态码在 response.status、触发原因在 trigger.reason 子文档），读侧两列永远渲染
  // '-'；而下面的 modelOf 桩忽略 .select()，查库类测试全部绿灯，漏到运维对着全 '-' 的
  // 列发问才暴露。此闸逐条对 schema 验存在：再有幽灵路径，CI 直接红。
  // trigger/device 是裸嵌套对象，mongoose 只登记叶子路径（schema.path('trigger') 为
  // undefined），所以前缀命中子路径也算存在——但 status/reason/markedAt 这类幽灵
  // 前缀下没有任何子路径，依旧拦得住。
  const ForensicCapture = require('../../models/ForensicCapture');
  const registeredPaths = Object.keys(ForensicCapture.schema.paths);
  const pathExists = (field) =>
    Boolean(ForensicCapture.schema.path(field)) ||
    registeredPaths.some((p) => p.startsWith(field + '.'));
  test.each(trace.SUMMARY_FIELDS)('投影路径 %s 在 ForensicCapture schema 上存在', (field) => {
    expect(pathExists(field)).toBe(true);
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

  test('按 IP 溯源：库内观测到的指纹自动派生池——「换 IP 不换机器」在最常用入口直接可见', async () => {
    const model = modelOf([{ ip: '1.2.3.4', fingerprint: 'aa11', ipSegment: '1.2.3' }]);
    model.aggregate = jest.fn(async () => [
      {
        _id: { fingerprint: 'aa11', segment: '1.2.3' },
        hits: 3,
        ips: ['1.2.3.4', '1.2.3.9'],
        firstSeen: new Date(),
        lastSeen: new Date(),
      },
    ]);
    const r = await trace.traceActor({ model, ip: '1.2.3.4' });
    expect(r.ok).toBe(true);
    expect(r.pools[0]).toMatchObject({ fingerprint: 'aa11', segment: '1.2.3', hits: 3 });
    // 窗口必须与 timeline 已解析的窗口对齐：缺省 since 时 $match 也要带下界，
    // 不能退化成只挂 $lte 的无上界聚合（全史扫描）。
    const match = model.aggregate.mock.calls[0][0][0].$match;
    expect(match.createdAt.$gte).toBeInstanceOf(Date);
    expect(match.createdAt.$lte).toBeInstanceOf(Date);
  });

  test('按 IP 溯源：库内无指纹 ⇒ 池为空，但聚合照发（指纹由聚合自己发现，没有可预检的维度）', async () => {
    const model = modelOf([]);
    const r = await trace.traceActor({ model, ip: '1.2.3.4' });
    expect(r.pools).toEqual([]);
    expect(model.aggregate).toHaveBeenCalledTimes(1);
  });
});

describe('derivedPools：从库内指纹归桶出 top N 指纹的网段池', () => {
  const groupOf = (fingerprint, segment, hits, ips) => ({
    _id: { fingerprint, segment },
    hits,
    ips,
    firstSeen: new Date('2026-11-01T00:00:00Z'),
    lastSeen: new Date('2026-11-02T00:00:00Z'),
  });

  test('同指纹多段：指纹总命中归桶，桶内按段命中倒序', async () => {
    const model = modelOf([]);
    model.aggregate = jest.fn(async () => [
      groupOf('fp-a', '1.2.3', 2, ['1.2.3.4', '1.2.3.9']),
      groupOf('fp-a', '10.0.0', 5, ['10.0.0.1']),
    ]);
    const r = await trace.derivedPools({
      model,
      ip: '1.2.3.4',
      since: new Date('2026-11-01T00:00:00Z'),
      until: new Date('2026-11-02T00:00:00Z'),
    });
    expect(r.ok).toBe(true);
    expect(r.pools.map((p) => p.segment)).toEqual(['10.0.0', '1.2.3']);
    expect(r.pools[0]).toMatchObject({ fingerprint: 'fp-a', hits: 5, distinctIps: 1 });
  });

  test('指纹封顶：只答 top N（按总命中），多出的指纹不进池', async () => {
    const model = modelOf([]);
    const groups = [];
    for (let i = 0; i < trace.MAX_DERIVED_FINGERPRINTS + 1; i += 1) {
      groups.push(
        groupOf(`fp-${i}`, `10.0.${i}`, trace.MAX_DERIVED_FINGERPRINTS + 1 - i, [`10.0.${i}.1`])
      );
    }
    model.aggregate = jest.fn(async () => groups);
    const r = await trace.derivedPools({ model, ip: '1.2.3.4' });
    const fps = [...new Set(r.pools.map((p) => p.fingerprint))];
    expect(fps).toHaveLength(trace.MAX_DERIVED_FINGERPRINTS);
    expect(fps).not.toContain('fp-5'); // 总命中最低的落选
  });

  test('无指纹的行归不了池：跳过，不造 unknown 桶冒充证据', async () => {
    const model = modelOf([]);
    model.aggregate = jest.fn(async () => [groupOf(null, '1.2.3', 9, ['1.2.3.4'])]);
    const r = await trace.derivedPools({ model, ip: '1.2.3.4' });
    expect(r.pools).toEqual([]);
  });

  test('判据不可用（时间倒序）⇒ ok:false 且不聚合（同 actorPools 口径）', async () => {
    const model = modelOf([]);
    const r = await trace.derivedPools({
      model,
      ip: '1.2.3.4',
      since: new Date('2026-11-02T00:00:00Z'),
      until: new Date('2026-11-01T00:00:00Z'),
    });
    expect(r.ok).toBe(false);
    expect(model.aggregate).not.toHaveBeenCalled();
  });

  test('actorPools 缺省 since ⇒ $match 带下界（API 不传 since 也不许无界聚合）', async () => {
    const model = modelOf([]);
    await trace.actorPools({
      model,
      fingerprint: 'fp-1',
      until: new Date('2026-11-02T00:00:00Z'),
    });
    const match = model.aggregate.mock.calls[0][0][0].$match;
    expect(match.createdAt.$gte).toBeInstanceOf(Date);
    expect(match.createdAt.$lte).toBeInstanceOf(Date);
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
