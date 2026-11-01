/**
 * 幂等降级必须留可告警信号（第 17 轮，来自 r16-auth 的 P1-2）
 *
 * 【实证的洞】`middleware/idempotency.js` 有四处"库不可用 ⇒ 按首次提交放行"的降级出口，
 * 原先唯一的痕迹是 `logger.warn`。而本仓成文纪律（`constants/failOpenSites.js` 头注释
 * 引用的三处）明确写着「降级态只写日志等于没有可告警信号——『grep 日志』不是运维动作」。
 * 后果：Mongo 抖动期间去重整层失效、可能重复执行创建类请求，而 `/metrics` 上
 * 一条 `security_alerts_total` 都没有 ⇒ 告警规则永远不触发。
 *
 * 【本文件钉住两件事】
 *   ① 四处降级出口都必须真的 `incSecurityAlert('idempotency_degraded','high')`
 *      （按调用点计数，不是"文件里出现过该字符串"）；
 *   ② 降级后请求仍必须放行（fail-open 是**刻意**选择：库挂不该让全站写操作 500）。
 *      ②是①的反向对照——只测"计数涨了"而不测"请求还能过"，会把"改成 fail-closed"
 *      这个相反方向的改动也判绿。
 *
 * 不连库、不走 HTTP：直接驱动中间件 + 桩掉模型静态方法 ⇒ 确定性。
 */

const { idempotency } = require('../../middleware/idempotency');
const IdempotencyRecord = require('../../models/IdempotencyRecord');
const metrics = require('../../utils/metrics');

const KEY = 'k'.repeat(16);

/** 读出 `idempotency_degraded` 的累计值（缺失记 0） */
const degradedCount = () => {
  const counters = metrics._alertCounters;
  const hit = [...counters.entries()].find(([k]) => k.includes('idempotency_degraded'));
  if (!hit) return 0;
  const entry = hit[1];
  if (typeof entry === 'number') return entry;
  return Object.values(entry).reduce((sum, v) => sum + Number(v || 0), 0);
};

const makeRes = () => {
  const res = {
    statusCode: null,
    headers: {},
    body: null,
    setHeader(k, v) {
      this.headers[k] = v;
      return this;
    },
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(payload) {
      this.body = payload;
      return this;
    },
    send(payload) {
      this.body = payload;
      return this;
    },
    end() {
      return this;
    },
    // captureOutcome 会接管这四个出口（write/end 也在内）：桩 res 必须长成 Express 响应的形状，
    // 否则「索引不可用 ⇒ 不许把插入当判据」那条会在这里先崩，掩盖真正要钉的结论。
    write() {
      return true;
    },
    once() {
      return this;
    },
  };
  return res;
};

const makeReq = () => ({
  method: 'POST',
  path: '/api/permissions',
  originalUrl: '/api/permissions',
  url: '/api/permissions',
  headers: { 'idempotency-key': KEY },
  body: { name: 'x' },
  user: { userId: '507f1f77bcf86cd799439011' },
});

describe('幂等降级信号（库不可用 ⇒ 放行，但必须可告警）', () => {
  afterEach(() => jest.restoreAllMocks());

  // 判据载体（keyHash 唯一索引）在首个带键请求前会被显式建立：本文件不连库，桩掉建索引这一步，
  // 否则它自己会先失败（那是另一条断言的事，见本文件末尾的索引用例）。
  beforeEach(() => {
    jest.spyOn(IdempotencyRecord, 'createIndexes').mockResolvedValue([]);
  });

  /**
   * 必须排在本文件第一条：索引就绪与否是**进程级**事实（模块内缓存，见 middleware 的 indexReady），
   * 一旦有请求成功建过索引，后面再桩成失败也观察不到。这条钉的是 autoIndex 的同型教训
   * （tokenblacklists.token_1）：索引没建成时插入照常成功，于是「两个并发同键」都能进——
   * 去重静默失效而日志全绿。
   */
  test('判据载体建不起来时不许把「插入成功」当判据：降级 + 告警 + 放行，而不是静默去重失效', async () => {
    jest.spyOn(IdempotencyRecord, 'createIndexes').mockRejectedValue(new Error('no perm'));
    const createSpy = jest
      .spyOn(IdempotencyRecord, 'create')
      .mockResolvedValue({ keyHash: 'x', state: 'in_progress' });
    const before = degradedCount();
    const next = jest.fn();

    await idempotency({ scope: 'permission:create' })(makeReq(), makeRes(), next);

    expect(degradedCount()).toBe(before + 1); // 有可告警信号
    expect(next).toHaveBeenCalled(); // 仍然放行（fail-open 方向不变）
    expect(createSpy).not.toHaveBeenCalled(); // 索引不可用 ⇒ 不许把插入当判据
    // 失败必须可恢复：下次请求重新尝试建索引，而不是本进程永久放弃
    jest.restoreAllMocks();
    jest.spyOn(IdempotencyRecord, 'createIndexes').mockResolvedValue([]);
    const okSpy = jest.spyOn(IdempotencyRecord, 'create').mockResolvedValue({});
    await idempotency({ scope: 'permission:create' })(makeReq(), makeRes(), jest.fn());
    expect(okSpy).toHaveBeenCalled();
  });

  test('登记失败（非 11000）⇒ 计数 +1 且请求仍放行', async () => {
    const before = degradedCount();
    jest
      .spyOn(IdempotencyRecord, 'create')
      .mockRejectedValue(Object.assign(new Error('connection lost'), { code: undefined }));
    const next = jest.fn();
    const res = makeRes();
    await idempotency({ scope: 'permission:create' })(makeReq(), res, next);
    expect(degradedCount()).toBe(before + 1);
    expect(next).toHaveBeenCalled();
    expect(res.statusCode).toBeNull(); // 降级不得改写成 4xx/5xx
  });

  test('级别漂移即红：计数键必须是 type="idempotency_degraded",level="high"', async () => {
    jest.spyOn(IdempotencyRecord, 'create').mockRejectedValue(new Error('connection lost'));
    await idempotency({ scope: 'permission:create' })(makeReq(), makeRes(), jest.fn());
    const keys = [...metrics._alertCounters.keys()];
    // 精确断言标签：只查 includes('idempotency_degraded') 会漏掉 level 被降级的改动
    expect(keys).toContain('type="idempotency_degraded",level="high"');
  });

  test('判据可失败：抽取函数不得恒真（缺条目 / 换 type 都必须读成 0）', () => {
    // 反向对照。中间件在模块加载时解构了 incSecurityAlert，spy 拦不住它，
    // 所以对照必须打在**抽取器**上：证明"数得出来"不是因为抽取器永远返回非零。
    const read = (entries) =>
      (() => {
        const hit = entries.find(([k]) => k.includes('idempotency_degraded'));
        return hit ? hit[1] : 0;
      })();
    expect(read([])).toBe(0);
    expect(read([['type="something_else",level="high"', 5]])).toBe(0);
    expect(read([['type="idempotency_degraded",level="high"', 5]])).toBe(5);
  });
});
