/**
 * query 注入防线的**行为**门禁：物化必须真的生效，且挂载顺序不可被悄悄改掉
 *
 * 为什么要单独一份、且必须跑在真实 express 实例上：
 *
 * 1. 既有那组 sanitizeMongo 单测（middleware/securitySanitizeAndBlacklistDegrade.test.js）
 *    用的是**手搓的 req 桩对象**，而桩上的 `query` 是普通自有属性。
 *    真实 Express 5 里 `req.query` 是**原型上的 getter**（express/lib/request.js 的
 *    `defineGetter(req, 'query', ...)`），每次访问重新解析 URL。
 *    ⇒ 那组单测**结构上不可能**发现"对 req.query 原地清洗是空操作"这件事。
 *    本仓已经吃过一次这个亏：P1-33 记的是"清洗结果在下一次访问时被丢弃"，
 *    而实测比那更彻底——同一 handler 同一 tick 内回读就已经是全新对象。
 *
 * 2. "物化生效"是一件**没有任何报错就会静默失效**的事：defineProperty 抛错会被
 *    catch，框架改实现则连 catch 都进不去。注释写着"本中间件有效"不构成证据，
 *    只有"回读身份相等"才是。所以这里断言的是运行时事实，不是源码形态。
 *
 * 3. 挂载点与顺序同样是注释级约定。此前 query 侧的真实防线是 queryScalarGuard
 *    单个中间件，"若移除它 query 注入防线归零"这句话只写在注释里。
 *    本文件把它变成可执行不变量：src/app.js 必须挂 materializeQuery，
 *    且必须早于 queryScalarGuard / queryLengthLimit / auditLog。
 *
 * 判定不依赖任何实现细节猜测：handler 里读 `Object.getOwnPropertyDescriptor(req, 'query')`
 * —— 真实 getter 场景下它是 undefined（属性在原型上），物化之后必须是 data descriptor。
 * 再读一次 `req.query` 验证清洗结果真的落在**同一个对象**上。
 */

const fs = require('fs');
const path = require('path');
const express = require('express');
const request = require('supertest');

const { materializeQuery } = require('../../middleware/security');
const { queryScalarGuard, queryLengthLimit } = require('../../middleware/queryLimit');

// __dirname = src/tests/app ⇒ 上溯两级是 src/，再上一级才是仓库根
const ROOT = path.resolve(__dirname, '../../..');
const APP_JS = path.join(ROOT, 'src', 'app.js');

/**
 * 最小可观测探针：在真实 express + 真实 supertest 上挂一段只读的 handler，
 * 把"物化是否生效""清洗是否落在同一对象上"如实报回来。
 *
 * 刻意不引入 createApp()：那份 app 挂着限流、黑名单、审计缓冲与 Mongo，
 * 会把"框架行为"与"本仓业务装配"两件事混在一起，失败时看不出是哪一层坏了。
 */
const buildProbeApp = (middlewares) => {
  const app = express();
  app.set('query parser', 'extended'); // 与 src/app.js 同一条设置
  middlewares.forEach((mw) => app.use('/api/', mw));
  app.get('/api/probe', (req, res) => {
    const descriptor = Object.getOwnPropertyDescriptor(req, 'query');
    const first = req.query;
    const second = req.query;
    const search = (first || {}).search;
    res.json({
      isOwnDataProperty: !!descriptor && 'value' in descriptor,
      isWritable: !!descriptor && descriptor.writable === true,
      stableAcrossReads: first === second,
      keys: Object.keys(first || {}),
      // `?search[$regex]=^a` 的顶层键是 `search`，`$regex` 藏在**下一层**——
      // 只查顶层键会让"操作符是否被剔除"永远读到 []，两侧都绿，等于没测。
      searchType: typeof search,
      searchKeys: search && typeof search === 'object' ? Object.keys(search) : [],
    });
  });
  return app;
};

describe('req.query 物化（真实 Express 5 getter 场景）', () => {
  test('前提自证：未物化时 req.query 确实不是自有属性，且原地清洗无效', async () => {
    // 这条是**反向对照**：它证明本文件测的是真实框架行为，而不是一个恰好通过的桩。
    // 若哪天 Express 改回 getter 内部缓存，本条会红——那时下面几条的前提需要重写，
    // 而不是悄悄让它们变成恒真。
    const app = buildProbeApp([]);
    const res = await request(app).get('/api/probe?search[$regex]=^a&page=2');

    expect(res.status).toBe(200);
    // 未物化 ⇒ 描述符不存在（属性在原型上）
    expect(res.body.isOwnDataProperty).toBe(false);
    // 未物化 ⇒ 每次访问都是新对象（这正是"原地清洗无效"的根因）
    expect(res.body.stableAcrossReads).toBe(false);
    // 未物化 ⇒ 操作符键原样透传（qs 解析结果未被任何东西清洗）
    expect(res.body.searchType).toBe('object');
    expect(res.body.searchKeys).toEqual(['$regex']);
  });

  test('物化后 req.query 是自有可写数据属性，且跨多次读取稳定', async () => {
    const app = buildProbeApp([materializeQuery()]);
    const res = await request(app).get('/api/probe?search=abc&page=2');

    expect(res.status).toBe(200);
    expect(res.body.isOwnDataProperty).toBe(true);
    expect(res.body.isWritable).toBe(true);
    // 物化的直接收益：下游再读多少次都是同一份快照，不会中途变脸
    expect(res.body.stableAcrossReads).toBe(true);
  });

  test('物化时清洗真的落在同一个对象上（$ 前缀键被剔除，非仅新建空壳）', async () => {
    const app = buildProbeApp([materializeQuery()]);
    const res = await request(app).get('/api/probe?search[$regex]=^a&page=2');

    expect(res.status).toBe(200);
    // 操作符被剥掉，`search` 变成空对象而不是键被整个吃掉——
    // 随后由 queryScalarGuard 按"非标量"拒掉（下一条钉这条链）
    expect(res.body.searchKeys).toEqual([]);
    expect(res.body.keys).toContain('search');
    expect(res.body.keys).toContain('page');
  });

  test('物化 + queryScalarGuard：操作符对象仍被 400 拒绝（两道防线各自独立成立）', async () => {
    const app = buildProbeApp([materializeQuery(), queryScalarGuard()]);
    const res = await request(app).get('/api/probe?search[$regex]=^a');

    expect(res.status).toBe(400);
    expect(res.body.errors.errorCode).toBe('QUERY_PARAM_MUST_BE_SCALAR');
  });

  test('queryScalarGuard 单独存在时同样拒绝（不依赖上游是否清洗过）', async () => {
    // 刻意不挂 materializeQuery：钉住"标量收敛是独立防线"这条不变式。
    // 有人日后把 materializeQuery 摘掉时，这一条仍然应当是绿的——
    // 而上面那条会红，那才是真正该红的地方。
    const app = buildProbeApp([queryScalarGuard()]);
    const res = await request(app).get('/api/probe?status=a&status=b');

    expect(res.status).toBe(400);
    expect(res.body.errors.errorCode).toBe('QUERY_PARAM_MUST_BE_SCALAR');
  });

  test('queryLengthLimit 单独存在时对超长值仍然 400（另一道独立防线）', async () => {
    const app = buildProbeApp([queryLengthLimit(20)]);
    const res = await request(app).get(`/api/probe?search=${'x'.repeat(50)}`);

    expect(res.status).toBe(400);
    expect(res.body.message).toContain('查询参数超长');
  });

  test('正常标量 query 完全不受影响（物化不得改变合法请求的形态）', async () => {
    const app = buildProbeApp([materializeQuery(), queryScalarGuard(), queryLengthLimit(200)]);
    const res = await request(app).get('/api/probe?search=fire&page=2&sort=-createdAt');

    expect(res.status).toBe(200);
    expect(res.body.keys.sort()).toEqual(['page', 'search', 'sort']);
    expect(res.body.searchType).toBe('string');
  });
});

describe('src/app.js 的 query 防线挂载（源码形态不变量）', () => {
  // 这里只钉**挂载与顺序**——上面那组钉**行为**。两者分开是因为它们会在不同的时候红：
  // 行为红 = 框架/实现变了；形态红 = 有人把中间件摘了或调序了。
  let src;
  let stripped;

  /**
   * 剥掉块注释与行注释，避免注释里出现的中间件名把顺序判据喂成假阳性
   * （与 scripts/compliance-check.js 的 codeViews 同一条纪律：
   * 「注释满足源码形态检查」是本仓专门设过防的一类假绿）。
   */
  const stripComments = (text) =>
    text.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');

  beforeAll(() => {
    src = fs.readFileSync(APP_JS, 'utf8');
    stripped = stripComments(src);
  });

  const mountIndex = (needle) => {
    const i = stripped.indexOf(needle);
    expect(i).toBeGreaterThan(-1);
    return i;
  };

  test('app.js 必须挂载 materializeQuery', () => {
    expect(stripped).toMatch(/app\.use\(\s*'\/api\/'\s*,\s*materializeQuery\(\)\s*\)/);
  });

  test('materializeQuery 必须早于 queryScalarGuard 与 queryLengthLimit', () => {
    const materialize = mountIndex('materializeQuery()');
    const scalar = mountIndex('queryScalarGuard()');
    const length = mountIndex('queryLengthLimit(200)');
    expect(materialize).toBeLessThan(scalar);
    expect(materialize).toBeLessThan(length);
  });

  test('materializeQuery 必须早于 auditLog（审计落盘的 query 快照应是清洗后的）', () => {
    expect(mountIndex('materializeQuery()')).toBeLessThan(mountIndex('auditLog()'));
  });

  test('sanitizeMongo 不得再遍历 req.query（写了也是空操作，留着只制造假防线）', () => {
    // 读 security.js（sanitizeMongo 的定义处），不是 app.js（那里只有调用点）
    const security = fs.readFileSync(path.join(ROOT, 'src', 'middleware', 'security.js'), 'utf8');
    const body = stripComments(security).slice(
      stripComments(security).indexOf('const sanitizeMongo ='),
      stripComments(security).indexOf('const materializeQuery')
    );
    expect(body).toContain('req.body');
    expect(body).toContain('req.params');
    expect(body).not.toContain('req.query');
  });
});
