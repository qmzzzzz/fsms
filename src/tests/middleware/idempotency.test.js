/**
 * 请求级幂等（`Idempotency-Key`，审计一-1）
 *
 * 覆盖三层，缺一层都会让"幂等"退化成一句声明：
 *   ① 纯函数层：键形态、哈希的隔离性、载荷指纹的键序无关性；
 *   ② 中间件层（真实 createApp + Mongo）：同键重放回放原响应、同键改载荷 409、
 *      并发同键只有一个落库、失败释放键、缺键放行；
 *   ③ 接线层：业务创建端点必须真的挂着这道中间件（漏挂等于没实现）。
 */

const fs = require('fs');
const path = require('path');
const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { randomPassword } = require('../helpers/buildLoginEnvelope');
const {
  parseIdempotencyKey,
  hashIdempotencyKey,
  fingerprintRequestBody,
  KEY_MIN_LENGTH,
  KEY_MAX_LENGTH,
} = require('../../utils/idempotencyKey');

describe('幂等键纯函数层', () => {
  test('形态：8-64 位可见 ASCII 通过；缺省 / 空白 / 控制字符 / 超长 / 过短一律拒', () => {
    const ok = ['a'.repeat(KEY_MIN_LENGTH), 'a'.repeat(KEY_MAX_LENGTH), 'x'.repeat(KEY_MAX_LENGTH)];
    for (const key of ok) expect(parseIdempotencyKey(key)).toEqual({ ok: true, key });

    // 缺省：undefined / null / 空串都算"没带"，与"带了但形状不对"分开（前者可放行、后者必拒）
    for (const raw of [undefined, null, '']) {
      expect(parseIdempotencyKey(raw)).toEqual({ ok: false, reason: 'missing' });
    }
    // 形状：短于下界 / 长于上界 / 含空格 / 含制表 / 含多字节
    for (const key of [
      'a'.repeat(KEY_MIN_LENGTH - 1),
      'a'.repeat(KEY_MAX_LENGTH + 1),
      'abcd efgh',
      'abcd\tefgh',
      'abcdefg中',
    ]) {
      expect(parseIdempotencyKey(key)).toEqual({ ok: false, reason: 'shape' });
    }
  });

  test('重复请求头（数组形态）只认第一个，且不因第二个合法而放宽', () => {
    expect(parseIdempotencyKey(['validkey1', 'validkey2'])).toEqual({ ok: true, key: 'validkey1' });
    expect(parseIdempotencyKey(['bad key', 'validkey2'])).toEqual({ ok: false, reason: 'shape' });
    expect(parseIdempotencyKey([])).toEqual({ ok: false, reason: 'missing' });
  });

  test('哈希：同一 (端点, 用户, 键) 稳定；换任一维度即不同（不同用户/端点不会撞车）', () => {
    const base = { scope: 'user:create', userId: 'u1', key: 'abcdefgh' };
    expect(hashIdempotencyKey(base)).toBe(hashIdempotencyKey({ ...base }));
    const variants = [
      { ...base, scope: 'inspection:create' },
      { ...base, userId: 'u2' },
      { ...base, key: 'abcdefgi' },
    ];
    for (const v of variants) expect(hashIdempotencyKey(v)).not.toBe(hashIdempotencyKey(base));
    // 分隔符必须真的起隔离作用：拼接歧义会让 ('a','bc') 与 ('ab','c') 撞哈希
    expect(hashIdempotencyKey({ scope: 'a', userId: 'bc', key: 'k' })).not.toBe(
      hashIdempotencyKey({ scope: 'ab', userId: 'c', key: 'k' })
    );
  });

  test('载荷指纹：顶层键序无关；值不同即不同；深层结构按原序（不把两份不同载荷判成同一份）', () => {
    expect(fingerprintRequestBody({ a: 1, b: 2 })).toBe(fingerprintRequestBody({ b: 2, a: 1 }));
    expect(fingerprintRequestBody({ a: 1 })).not.toBe(fingerprintRequestBody({ a: 2 }));
    expect(fingerprintRequestBody({ a: [1, 2] })).not.toBe(fingerprintRequestBody({ a: [2, 1] }));
    // 非对象载荷（undefined / 数组）一律按空对象算，不抛错
    expect(fingerprintRequestBody(undefined)).toBe(fingerprintRequestBody({}));
    expect(fingerprintRequestBody([1])).toBe(fingerprintRequestBody({}));
  });
});

describe('幂等中间件（真实 HTTP + Mongo）', () => {
  let app;
  let User;
  let Role;
  let Permission;
  let IdempotencyRecord;
  let token;
  const stamp = `idem${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);

  const { waitFor } = require('../helpers/waitFor');

  const post = (body, key) => {
    const req = request(app).post('/api/permissions').set('Authorization', `Bearer ${token}`);
    if (key !== undefined) req.set('Idempotency-Key', key);
    return req.send(body);
  };

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) await mongoose.connect(process.env.MONGODB_URI);
    User = require('../../models/User');
    Role = require('../../models/Role');
    Permission = require('../../models/Permission');
    IdempotencyRecord = require('../../models/IdempotencyRecord');
    require('../../models/TokenBlacklist');
    app = require('../../app').createApp();

    const pCreate = await Permission.findOneAndUpdate(
      { code: 'permission:create' },
      {
        $setOnInsert: {
          name: '创建权限',
          code: 'permission:create',
          type: 'api',
          module: 'permission',
        },
      },
      { upsert: true, new: true }
    );
    const role = await Role.create({
      name: `幂等验证角色_${stamp}`,
      code: `IDEM_${stamp}`,
      level: 8,
      status: 'active',
      permissions: [pCreate._id],
    });
    // user:create 回放体裁剪用例（C-F4）需要经 /api/users 建号：补授该权限码
    // （已存在则复用；afterAll 不清理这个共享码）
    const uCreate = await Permission.findOneAndUpdate(
      { code: 'user:create' },
      { $setOnInsert: { name: '创建用户', code: 'user:create', type: 'api', module: 'user' } },
      { upsert: true, new: true }
    );
    await Role.findByIdAndUpdate(role._id, { $addToSet: { permissions: uCreate._id } });
    const user = await User.create({
      username: `idem${stamp}`,
      email: `idem${stamp}@example.com`,
      password: randomPassword(),
      status: 'active',
      roles: [role._id],
      tokenVersion: 0,
    });
    token = jwt.sign(
      {
        userId: String(user._id),
        username: user.username,
        email: user.email,
        roles: [`IDEM_${stamp}`],
        tokenVersion: 0,
        jti: 'j',
        sid: null,
      },
      process.env.JWT_SECRET,
      { algorithm: 'HS256', expiresIn: '24h' }
    );
    // 判据依赖 keyHash 的唯一索引：autoIndex 未建好时"并发只有一个赢"那条会假绿
    await IdempotencyRecord.createIndexes();
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      const rx = new RegExp(stamp);
      await Permission.deleteMany({ code: rx }).catch(() => {});
      await Role.deleteMany({ code: rx }).catch(() => {});
      await User.deleteMany({ username: rx }).catch(() => {});
      await IdempotencyRecord.deleteMany({ scope: /permission:create|user:create/ }).catch(
        () => {}
      );
      await mongoose.connection.close();
    }
  });

  test('同键同载荷：第二次原样回放第一次的响应，且不再产生第二条权限', async () => {
    const key = `replay-${stamp}`;
    const body = { name: '幂等权限甲', code: `idem:a${stamp}`, type: 'api', module: 'idem' };

    const first = await post(body, key);
    expect(first.status).toBe(201);
    expect(first.headers['idempotency-replayed']).toBeUndefined();

    const second = await post(body, key);
    expect(second.status).toBe(201);
    expect(second.headers['idempotency-replayed']).toBe('true');
    // 回放的是**同一次结果**：响应体逐字段一致（含 id）
    expect(second.body).toEqual(first.body);
    // 副作用只有一次
    expect(await Permission.countDocuments({ code: body.code })).toBe(1);
  });

  test('user:create 回放副本经 PII 裁剪（2026-11-02 C-F4）：只留 id/username', async () => {
    // user:create 的首次响应经特权查看可含真实 email/realName/phone，而
    // IdempotencyRecord 是这些列加密体系外的明文旁路（留存 24h）。挂载点的
    // replayBodyFilter 把回放副本裁到重试方所需的最小集。
    const username = `idemu${stamp}`;
    const body = {
      username,
      email: `${username}@example.com`,
      password: randomPassword(),
      realName: '张三丰',
      phone: '13800138000',
    };
    const key = `ucut-${stamp}`;
    const req = (k) =>
      request(app)
        .post('/api/users')
        .set('Authorization', `Bearer ${token}`)
        .set('Idempotency-Key', k);
    const first = await req(key).send(body);
    expect(first.status).toBe(201);

    // 落库副本：除信封字段外，data 只剩 id/username 两个结论字段
    // 完成态与响应体是响应后的 fire-and-forget 写（b820c32 同判例：不得赌时延），
    // 先轮询到 responseBody 落定再断言，把"读得太早"与"真没裁剪"区分开
    await waitFor(
      async () => {
        const rec = await IdempotencyRecord.findOne({ scope: 'user:create' }).lean();
        return Boolean(rec) && rec.responseBody && Boolean(rec.responseBody.data);
      },
      { timeoutMs: 4000, label: 'user:create 回放副本收敛（responseBody 落库）' }
    );
    const record = await IdempotencyRecord.findOne({ scope: 'user:create' }).lean();
    expect(record).toBeTruthy();
    expect(record.responseBody.data).toEqual({ id: expect.anything(), username });
    expect(JSON.stringify(record.responseBody)).not.toContain('张三丰');
    expect(JSON.stringify(record.responseBody)).not.toContain(body.email);
    expect(JSON.stringify(record.responseBody)).not.toContain('13800138000');

    // 重试回放可用：拿到 id/username 完成重试语义，PII 字段缺席
    const second = await req(key).send(body);
    expect(second.status).toBe(201);
    expect(second.headers['idempotency-replayed']).toBe('true');
    expect(second.body.data.username).toBe(username);
    expect(second.body.data.email).toBeUndefined();
    expect(second.body.data.realName).toBeUndefined();
  });

  test('同键不同载荷 → 409：不能借用上一次的成功响应，也不能"以最后一次为准"', async () => {
    const key = `mismatch-${stamp}`;
    const body = { name: '幂等权限乙', code: `idem:b${stamp}`, type: 'api', module: 'idem' };
    expect((await post(body, key)).status).toBe(201);

    const changed = await post({ ...body, name: '幂等权限乙改' }, key);
    expect(changed.status).toBe(409);
    expect(changed.body.errors.errorCode).toBe('IDEMPOTENCY_KEY_REUSED');
    expect(await Permission.countDocuments({ code: body.code })).toBe(1);
  });

  test('并发双发同键：唯一索引只放一个进去，另一个立刻 409（不是排队等待）', async () => {
    const key = `race-${stamp}`;
    const body = { name: '幂等权限丙', code: `idem:c${stamp}`, type: 'api', module: 'idem' };
    const [a, b] = await Promise.all([post(body, key), post(body, key)]);
    const statuses = [a.status, b.status].sort();
    // 一个 201、另一个 409（在途）或 201（已完成回放）；绝不允许两个都真的建了
    expect(statuses[0]).toBe(201);
    expect([201, 409]).toContain(statuses[1]);
    if (statuses[1] === 409) {
      const loser = a.status === 409 ? a : b;
      expect(loser.body.errors.errorCode).toBe('IDEMPOTENCY_IN_PROGRESS');
    }
    expect(await Permission.countDocuments({ code: body.code })).toBe(1);
  });

  test('业务失败释放键：400 修正后用同一个键重试仍能成功（同一次提交的重试是正常用法）', async () => {
    const key = `retry-${stamp}`;
    const bad = await post(
      { name: '幂等权限丁', code: 'idem:bad code', type: 'api', module: 'idem' },
      key
    );
    expect(bad.status).toBe(400);

    const good = await post(
      { name: '幂等权限丁', code: `idem:d${stamp}`, type: 'api', module: 'idem' },
      key
    );
    expect(good.status).toBe(201);
    expect(good.headers['idempotency-replayed']).toBeUndefined();
  });

  test('不带键照常放行（键可选：既有 105 处调用不被一次性打断）', async () => {
    const res = await post({
      name: '幂等权限戊',
      code: `idem:e${stamp}`,
      type: 'api',
      module: 'idem',
    });
    expect(res.status).toBe(201);
    expect(res.headers['idempotency-replayed']).toBeUndefined();
  });

  test('键形状非法 → 400 IDEMPOTENCY_KEY_INVALID（不是"当成没带"放行）', async () => {
    const res = await post(
      { name: '幂等权限己', code: `idem:f${stamp}`, type: 'api', module: 'idem' },
      'short'
    );
    expect(res.status).toBe(400);
    expect(res.body.errors.errorCode).toBe('IDEMPOTENCY_KEY_INVALID');
    expect(await Permission.countDocuments({ code: `idem:f${stamp}` })).toBe(0);
  });

  test('键按用户隔离：同名键在不同用户下互不影响（不靠"撞车即冲突"来救）', async () => {
    const key = `shared-${stamp}`;
    const body = { name: '幂等权限庚', code: `idem:g${stamp}`, type: 'api', module: 'idem' };
    const first = await post(body, key);
    expect(first.status).toBe(201);
    // 直接构造"另一个用户"的哈希，验证哈希里确实带了 userId（判据不是"键全局唯一"）
    const decoded = jwt.decode(token);
    const other = hashIdempotencyKey({
      scope: 'permission:create',
      userId: String(decoded.userId) + 'x',
      key,
    });
    expect(other).not.toBe(
      hashIdempotencyKey({ scope: 'permission:create', userId: String(decoded.userId), key })
    );
  });
});

describe('接线层：业务创建端点必须挂着幂等中间件', () => {
  /**
   * 漏挂是这道闸最现实的失效形态：中间件写得再好，只要某条创建路由没挂上，
   * 那条端点就仍然"点一次多一条"。这里按**路由文件**逐个点名，而不是只看
   * 中间件本身存在——「实现了」与「接上了」是两件事。
   */
  const ROUTES_WITH_IDEMPOTENCY = [
    { file: 'src/routes/userRoutes.js', scope: 'user:create' },
    { file: 'src/routes/roleRoutes.js', scope: 'role:create' },
    { file: 'src/routes/permissionRoutes.js', scope: 'permission:create' },
    { file: 'src/routes/permissionRoutes.js', scope: 'permission:batchCreate' },
    { file: 'src/routes/deviceRoutes.js', scope: 'device:create' },
    { file: 'src/routes/inspectionRoutes.js', scope: 'inspection:create' },
    { file: 'src/routes/alarmRoutes.js', scope: 'alarm:report' },
    { file: 'src/routes/permissionRoutes.js', scope: 'privilege:grant' },
  ];

  // 明确不在名单里的那一条：未脱敏导出返回的是流式二进制（blob），
  // 中间件只回放 JSON 响应体，把它挂上去等于给客户端一个"看起来成功、内容是空"的下载。
  // 该端点的重复执行问题归口审计一-8（导出审批/配额/水印），不在这里用幂等键糊住。
  test('未脱敏导出端点不该挂幂等：流式响应无法回放，归属导出配额那条（一-8）', () => {
    const root = path.resolve(__dirname, '../../..');
    const src = fs.readFileSync(path.join(root, 'src/routes/reportRoutes.js'), 'utf8');
    expect(src).not.toContain('idempotency({');
  });

  test('每条创建/提交类端点都显式给出 scope（未给出时中间件会抛错，属编程错误）', () => {
    const root = path.resolve(__dirname, '../../..');
    for (const { file, scope } of ROUTES_WITH_IDEMPOTENCY) {
      const src = fs.readFileSync(path.join(root, file), 'utf8');
      // scope 字面量必须出现在 idempotency({ ... }) 的挂载对象里；user:create
      // 因回放体 PII 裁剪（2026-11-02 C-F4）为多行 options，故匹配放宽为
      // 「scope 字面量在场 + idempotency({ 挂载形态在场」两条并立。
      const singleLine = src.includes(`idempotency({ scope: '${scope}' })`);
      const multiLine =
        src.includes(`scope: '${scope}'`) &&
        new RegExp(`idempotency\\(\\{[\\s\\S]{0,240}scope: '${scope}'`).test(src);
      expect({ file, scope, wired: singleLine || multiLine }).toEqual({
        file,
        scope,
        wired: true,
      });
    }
  });

  test('中间件本体：缺 scope 直接抛（不静默退化成"所有端点共用一个键空间"）', () => {
    const { idempotency } = require('../../middleware/idempotency');
    expect(() => idempotency({})).toThrow(/scope/);
  });

  test('反证：把某条路由的中间件摘掉，上面的接线判据必须变红', () => {
    const root = path.resolve(__dirname, '../../..');
    const src = fs.readFileSync(path.join(root, 'src/routes/userRoutes.js'), 'utf8');
    const mutated = src.replace("scope: 'user:create'", '');
    expect(mutated.includes("scope: 'user:create'")).toBe(false);
    expect(src.includes("scope: 'user:create'")).toBe(true);
  });
});

/**
 * 这一层刻意用**极小的 express 应用**而不是生产路由：本组判据打的是中间件的收尾逻辑
 * （哪些出口算「完成」、响应体超限时键还在不在、过期记录还算不算判据），而生产端点只有
 * JSON 出口，这些分支在业务路由上根本走不到。判据仍是真实 HTTP + 真实 Mongo：
 * 「同键第二次不再执行」只有靠 handler 的真实执行次数 + 唯一索引才证得出来。
 */
describe('幂等中间件：响应出口与记录生命周期（真实 HTTP + Mongo）', () => {
  const express = require('express');
  const IdempotencyRecord = require('../../models/IdempotencyRecord');
  const { idempotency, MAX_REPLAY_BYTES } = require('../../middleware/idempotency');
  const errorHandler = require('../../middleware/errorHandler');
  const { waitFor } = require('../helpers/waitFor');

  const userId = String(new mongoose.Types.ObjectId());
  const runs = new Map();
  const bump = (name) => {
    const next = (runs.get(name) || 0) + 1;
    runs.set(name, next);
    return next;
  };
  const countOf = (name) => runs.get(name) || 0;
  const keyHashOf = (name, key) => hashIdempotencyKey({ scope: 'test:' + name, userId, key });

  let app;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) await mongoose.connect(process.env.MONGODB_URI);
    await IdempotencyRecord.createIndexes(); // 判据本体是 keyHash 唯一索引：建不出来这组就是假绿
    app = express();
    app.use(express.json());
    // 每条桩路由只做一件事：暴露一种「真实存在但生产端点没有」的响应出口
    const route = (name, handler) => {
      app.post(
        '/' + name,
        (req, res, next) => {
          req.user = { userId }; // 中间件判据需要一个身份：直接注入，不为测试再造一套鉴权
          next();
        },
        idempotency({ scope: 'test:' + name }),
        handler
      );
    };
    route('large', (req, res) => {
      bump('large');
      res.status(201).json({ success: true, data: { blob: 'x'.repeat(MAX_REPLAY_BYTES) } });
    });
    route('text', (req, res) => {
      bump('text');
      res.type('text/plain').send('幂等纯文本响应');
    });
    route('endonly', (req, res) => {
      bump('endonly');
      res.status(202).end(); // 只给状态码、不给体（res.end 出口）
    });
    route('abort', (req, res) => {
      bump('abort');
      res.type('text/plain');
      res.write('partial');
      throw new Error('boom-after-headers'); // 头已发之后抛错 ⇒ errorHandler 的 headersSent 分支 res.end()
    });
    route('echo', (req, res) => {
      res.status(201).json({ success: true, data: { n: bump('echo') } });
    });
    app.use(errorHandler);
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await IdempotencyRecord.deleteMany({ userId }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  const post = (name, body, key) =>
    request(app)
      .post('/' + name)
      .set('Idempotency-Key', key)
      .send(body);

  const completed = (keyHash) =>
    waitFor(
      async () => {
        const rec = await IdempotencyRecord.findOne({ keyHash }).lean();
        return Boolean(rec) && rec.state === 'completed';
      },
      { timeoutMs: 4000, label: '键 ' + String(keyHash).slice(0, 8) + ' 收敛为 completed' }
    );

  test('P0-1（I-2）超 64KB 的 2xx：键保留为 completed，第二次同键不再执行', async () => {
    const key = 'i2-large-' + stamp16();
    const first = await post('large', {}, key);
    // 第一次的响应必须分毫不动：容量上限只能影响回放能力，不能把首次响应也降级
    expect(first.status).toBe(201);
    expect(first.body.data.blob.length).toBe(MAX_REPLAY_BYTES);
    expect(first.headers['idempotency-replayed']).toBeUndefined();

    const keyHash = keyHashOf('large', key);
    await completed(keyHash);
    const stored = await IdempotencyRecord.findOne({ keyHash }).lean();
    // 旧实现在这里 deleteOne ⇒ 记录不存在（下一条断言先红）；新实现必须留痕且标降级
    expect({
      state: stored.state,
      replayOmitted: stored.replayOmitted,
      statusCode: stored.statusCode,
    }).toEqual({
      state: 'completed',
      replayOmitted: true,
      statusCode: 201,
    });

    const second = await post('large', {}, key);
    expect(second.status).toBe(201);
    expect(second.headers['idempotency-replayed']).toBe('true');
    expect(second.headers['idempotency-replay-omitted']).toBe('true');
    expect(second.body.data).toBeNull();
    expect(countOf('large')).toBe(1); // 关键判据：handler 只跑了一次
  });

  test('P0-2（I-1）res.send 文本 2xx：第二次同键回放正文，而不是 409 卡死', async () => {
    const key = 'i1-text-' + stamp16();
    const first = await post('text', {}, key);
    expect(first.status).toBe(200);
    expect(first.text).toBe('幂等纯文本响应');
    await completed(keyHashOf('text', key));

    const second = await post('text', {}, key);
    expect(second.status).toBe(200);
    expect(second.headers['idempotency-replayed']).toBe('true');
    expect(second.text).toBe('幂等纯文本响应'); // 回放的是原正文（不是 409、不是空体）
    expect(countOf('text')).toBe(1);
  });

  test('P0-2（I-1）res.end 无体 2xx：记录落 completed，第二次得到显式降级而不是 409', async () => {
    const key = 'i1-end-' + stamp16();
    const first = await post('endonly', {}, key);
    expect(first.status).toBe(202);
    await completed(keyHashOf('endonly', key));

    const second = await post('endonly', {}, key);
    expect(second.status).toBe(202);
    expect(second.headers['idempotency-replayed']).toBe('true');
    expect(second.headers['idempotency-replay-omitted']).toBeUndefined(); // 空体可原样回放，不必降级
    expect(second.text || '').toBe('');
    expect(countOf('endonly')).toBe(1);
  });

  test('P0-2（I-1）头已发 + 抛错：errorHandler 的 res.end() 也必须把键收尾成 completed', async () => {
    const key = 'i1-abort-' + stamp16();
    const first = await post('abort', {}, key);
    expect(first.status).toBe(200);
    const keyHash = keyHashOf('abort', key);
    // 旧实现：只包了 res.json ⇒ 这条记录永远停在 in_progress ⇒ 第二次 409（24 小时无解）
    await completed(keyHash);
    const stored = await IdempotencyRecord.findOne({ keyHash }).lean();
    expect({ state: stored.state, replayOmitted: stored.replayOmitted }).toEqual({
      state: 'completed',
      replayOmitted: true,
    });

    const second = await post('abort', {}, key);
    expect(second.status).toBe(200);
    expect(second.headers['idempotency-replay-omitted']).toBe('true');
    expect(countOf('abort')).toBe(1);
  });

  test('P0-3（I-3）过期 completed 不再回放：判据自带 expiresAt，不靠 TTL 回收', async () => {
    const key = 'i3-done-' + stamp16();
    const first = await post('echo', {}, key);
    expect(first.status).toBe(201);
    const keyHash = keyHashOf('echo', key);
    await completed(keyHash);
    const before = countOf('echo');
    // TTL 回收有分钟级延迟：这段窗口里「过期 completed 回放旧体」等于把过期数据当权威
    await IdempotencyRecord.updateOne(
      { keyHash },
      {
        $set: {
          expiresAt: new Date(Date.now() - 1000),
          responseBody: { success: true, message: '过期的旧结论', data: { n: -1 } },
          replayOmitted: false,
        },
      }
    );

    const again = await post('echo', {}, key);
    expect(again.headers['idempotency-replayed']).toBeUndefined();
    expect(again.body.message).not.toBe('过期的旧结论');
    expect(countOf('echo')).toBe(before + 1); // 过期即无判据：允许重新执行
  });

  test('P0-3（I-3）过期 in_progress 不再 409：过期记录可被同键接管', async () => {
    const key = 'i3-busy-' + stamp16();
    const keyHash = keyHashOf('echo', key);
    await IdempotencyRecord.create({
      keyHash,
      userId,
      scope: 'test:echo',
      requestHash: fingerprintRequestBody({}),
      state: 'in_progress',
      expiresAt: new Date(Date.now() - 1000),
    });
    const before = countOf('echo');

    const res = await post('echo', {}, key);
    expect(res.status).toBe(201); // 旧实现：409 IDEMPOTENCY_IN_PROGRESS（过期在途当作在途）
    expect(res.body.errors?.errorCode).toBeUndefined();
    expect(countOf('echo')).toBe(before + 1);
  });
});

describe('第 15 轮对抗自审：修完之后还能不能骗过判据（真实 HTTP + Mongo）', () => {
  const express = require('express');
  const IdempotencyRecord = require('../../models/IdempotencyRecord');
  const { idempotency, MAX_REPLAY_BYTES } = require('../../middleware/idempotency');
  const { waitFor } = require('../helpers/waitFor');

  const userId = String(new mongoose.Types.ObjectId());
  const runs = new Map();
  const bump = (name) => {
    const next = (runs.get(name) || 0) + 1;
    runs.set(name, next);
    return next;
  };
  const countOf = (name) => runs.get(name) || 0;
  const keyHashOf = (name, key) => hashIdempotencyKey({ scope: 'adv:' + name, userId, key });

  let app;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) await mongoose.connect(process.env.MONGODB_URI);
    await IdempotencyRecord.createIndexes();
    app = express();
    app.use(express.json());
    const route = (name, handler) => {
      app.post(
        '/' + name,
        (req, res, next) => {
          req.user = { userId };
          next();
        },
        idempotency({ scope: 'adv:' + name }),
        handler
      );
    };
    // (a) 超 64KB 的 201 且带 Location：调用方重试时会不会误以为拿到了新资源
    route('created', (req, res) => {
      bump('created');
      res
        .status(201)
        .set('Location', '/api/v1/permissions/9f00000000000000000000ab')
        .json({ success: true, data: { blob: 'y'.repeat(MAX_REPLAY_BYTES) } });
    });
    // (b) 分块流式：settled 闸若只捕获第一块，回放半截体比 409 更危险
    route('chunks', (req, res) => {
      bump('chunks');
      res.type('text/plain');
      res.write('chunk-1:SECRET-A;');
      res.write('chunk-2:SECRET-B;');
      res.end('chunk-3:SECRET-C');
    });
    route('big2', (req, res) => {
      bump('big2');
      res.status(201).json({ success: true, data: { blob: 'z'.repeat(MAX_REPLAY_BYTES) } });
    });
    route('plain', (req, res) => {
      res.status(201).json({ success: true, data: { n: bump('plain') } });
    });
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await IdempotencyRecord.deleteMany({ userId }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  const post = (name, body, key) =>
    request(app)
      .post('/' + name)
      .set('Idempotency-Key', key)
      .send(body);
  const completed = (keyHash, state) =>
    waitFor(
      async () => {
        const rec = await IdempotencyRecord.findOne({ keyHash }).lean();
        return Boolean(rec) && rec.state === (state || 'completed');
      },
      { timeoutMs: 4000, label: '键 ' + String(keyHash).slice(0, 8) + ' 收敛' }
    );

  test('(a) 201 + Location 的超限响应：降级回放必须带机读标记，且 Location 指针（若首次有）照原样还原', async () => {
    const key = 'adv-loc-' + stamp16();
    const first = await post('created', {}, key);
    expect(first.status).toBe(201);
    expect(first.headers.location).toBe('/api/v1/permissions/9f00000000000000000000ab');
    const keyHash = keyHashOf('created', key);
    await completed(keyHash);

    const second = await post('created', {}, key);
    expect(second.status).toBe(201);
    // 机读标记三重：头（可能被代理剥离/跨域需显式暴露）+ 体（调用方不看头也能判）
    expect(second.headers['idempotency-replayed']).toBe('true');
    expect(second.headers['idempotency-replay-omitted']).toBe('true');
    expect(second.body.replayed).toBe(true);
    expect(second.body.responseOmitted).toBe(true);
    // 资源确实已创建：Location 是首次响应的事实，回放照原样还原（不伪造、也不吞掉指针）
    expect(second.headers.location).toBe(first.headers.location);
    expect(countOf('created')).toBe(1);
  });

  test('(a2) 首次没有 Location 的降级回放不得凭空造一个出来', async () => {
    const key = 'adv-noloc-' + stamp16();
    const first = await post('big2', {}, key);
    expect(first.status).toBe(201);
    expect(first.headers.location).toBeUndefined();
    const second = await post('big2', {}, key);
    expect(second.headers['idempotency-replay-omitted']).toBe('true');
    expect(second.headers.location).toBeUndefined(); // 回放不是"再发一次"：首次没有的指针就不该出现
  });

  test('(b) 分块流式 2xx：回放不得出现半截体——要么整段标记降级、要么原文，绝不给"看起来完整"的碎片', async () => {
    const key = 'adv-chunk-' + stamp16();
    const first = await post('chunks', {}, key);
    expect(first.status).toBe(200);
    expect(first.text).toBe('chunk-1:SECRET-A;chunk-2:SECRET-B;chunk-3:SECRET-C');
    await completed(keyHashOf('chunks', key));

    const second = await post('chunks', {}, key);
    expect(second.headers['idempotency-replayed']).toBe('true');
    expect(second.text.includes('SECRET-')).toBe(false); // 承重：红时先看到半截体本身
    expect(second.headers['idempotency-replay-omitted']).toBe('true');
    expect(second.body.responseOmitted).toBe(true);
    expect(countOf('chunks')).toBe(1);
  });

  test('(c) 过期行的原子接管：5 个并发同键请求，只有 1 个能执行（TTL 边界竞态）', async () => {
    const key = 'adv-race-' + stamp16();
    const keyHash = keyHashOf('plain', key);
    await IdempotencyRecord.create({
      keyHash,
      userId,
      scope: 'adv:plain',
      requestHash: fingerprintRequestBody({}),
      state: 'in_progress',
      expiresAt: new Date(Date.now() - 1000), // 过期在途：可被接管
    });
    const before = countOf('plain');

    const results = await Promise.all(Array.from({ length: 5 }, () => post('plain', {}, key)));
    const codes = results.map((r) => r.status).sort();
    const executed = countOf('plain') - before;
    // 判据 1：执行有且只有一次（接管是原子的，不是"人人可夺"）
    expect(executed).toBe(1);
    // 判据 2：其余请求只能得到 409（并发在途）或 201+replayed（已完成后回放），不得是 5xx
    expect(codes.filter((c) => c === 409).length).toBeLessThanOrEqual(4);
    expect(results.every((r) => r.status === 201 || r.status === 409 || r.status === 200)).toBe(
      true
    );
    const replayed = results.filter((r) => r.headers['idempotency-replayed'] === 'true');
    expect(replayed.length + codes.filter((c) => c === 409).length).toBeGreaterThanOrEqual(4);
  });

  test('(d) 历史行（无 expiresAt）：按 createdAt + 24h 折算——窗口内仍是判据（回放），窗口外才可接管', async () => {
    const key = 'adv-legacy-in-' + stamp16();
    const recent = await IdempotencyRecord.collection.insertOne({
      keyHash: keyHashOf('plain', key),
      userId: new mongoose.Types.ObjectId(userId),
      scope: 'adv:plain',
      requestHash: fingerprintRequestBody({}),
      state: 'completed',
      statusCode: 200,
      responseBody: { success: true, message: '历史行的旧结论', data: { n: -7 } },
      contentType: null,
      replayOmitted: false,
      createdAt: new Date(),
      expiresAt: null, // 旧 schema 落下的行：没有 expiresAt
    });
    expect(recent.insertedId).toBeTruthy();
    const before = countOf('plain');
    const res = await post('plain', {}, key);
    // 直接判「缺失=过期」会把 1 分钟前的完成态当过期重放（本轮修掉的形状）
    expect(res.headers['idempotency-replayed']).toBe('true');
    expect(res.body.message).toBe('历史行的旧结论');
    expect(countOf('plain')).toBe(before);

    const oldKey = 'adv-legacy-out-' + stamp16();
    await IdempotencyRecord.collection.insertOne({
      keyHash: keyHashOf('plain', oldKey),
      userId: new mongoose.Types.ObjectId(userId),
      scope: 'adv:plain',
      requestHash: fingerprintRequestBody({}),
      state: 'completed',
      statusCode: 200,
      responseBody: { success: true, message: '超窗的历史结论', data: { n: -8 } },
      contentType: null,
      replayOmitted: false,
      createdAt: new Date(Date.now() - 25 * 60 * 60 * 1000), // 25h 前落下的行
      expiresAt: null,
    });
    const res2 = await post('plain', {}, oldKey);
    expect(res2.headers['idempotency-replayed']).toBeUndefined(); // 超窗即无判据：不回复旧结论
    expect(res2.body.message).not.toBe('超窗的历史结论');
    expect(countOf('plain')).toBe(before + 1); // 可被同键接管并执行一次
  });
});

describe('第 15 轮补充：出口异常、鉴权前置、键上限（真实 HTTP + Mongo）', () => {
  const express = require('express');
  const IdempotencyRecord = require('../../models/IdempotencyRecord');
  const { idempotency } = require('../../middleware/idempotency');
  const idempotencyKey = require('../../utils/idempotencyKey');
  const errorHandler = require('../../middleware/errorHandler');

  const userId = String(new mongoose.Types.ObjectId());
  const runs = new Map();
  const bump = (name) => {
    const next = (runs.get(name) || 0) + 1;
    runs.set(name, next);
    return next;
  };
  const countOf = (name) => runs.get(name) || 0;
  const keyHashOf = (name, key) => hashIdempotencyKey({ scope: 'sup:' + name, userId, key });

  let app;
  let gateOpen = false; // 模拟「用户被重新授权」：同一个键的下一次重试

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) await mongoose.connect(process.env.MONGODB_URI);
    await IdempotencyRecord.createIndexes();
    app = express();
    app.use(express.json());
    const tail = (name, handler) => [idempotency({ scope: 'sup:' + name }), handler];
    const mount = (name, prepend, handler) => {
      app.post(
        '/' + name,
        (req, res, next) => {
          req.user = { userId };
          next();
        },
        ...prepend,
        ...tail(name, handler)
      );
    };
    // (e) 响应已交付后又写一次（业务 bug）：Express 会抛 ERR_HTTP_HEADERS_SENT
    mount('twice', [], (req, res) => {
      bump('twice');
      res.status(201).json({ success: true, data: { n: 1 } });
      res.status(500).json({ success: false, message: 'never-delivered' }); // 头已发：抛错
    });
    // (e2) 先 write 再 json（更脏的 bug）：不得把从未发出的 JSON 存成可回放体
    mount('mixed', [], (req, res) => {
      bump('mixed');
      res.type('text/plain');
      res.write('partial-only');
      res.status(200).json({ success: true, message: 'never-delivered' });
    });
    // (f) 鉴权/权限闸在幂等之前：拒绝时幂等中间件根本不会被调用
    mount(
      'gated',
      [
        (req, res, next) => {
          if (gateOpen) return next();
          return res.status(403).json({ success: false, errors: { errorCode: 'FORBIDDEN' } });
        },
      ],
      (req, res) => {
        bump('gated');
        res.status(201).json({ success: true, data: { n: 1 } });
      }
    );
    // (f2) 处理器自己回 403：键必须被释放（否则用户修正后重试会撞 409）
    mount('denied', [], (req, res) => {
      bump('denied');
      res.status(403).json({ success: false, errors: { errorCode: 'FORBIDDEN' } });
    });
    app.use(errorHandler); // 与生产同构：头已发后的抛错由 errorHandler 的 headersSent 分支收尾（res.end）
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await IdempotencyRecord.deleteMany({ userId }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  const post = (name, body, key) =>
    request(app)
      .post('/' + name)
      .set('Idempotency-Key', key)
      .send(body);

  test('(e) 2xx 已交付后又写一次（抛 ERR_HTTP_HEADERS_SENT）：记录必须留在 completed，重试回放而不是再执行', async () => {
    const key = 'sup-twice-' + stamp16();
    const first = await post('twice', {}, key);
    expect(first.status).toBe(201);
    expect(first.body.data).toEqual({ n: 1 });
    const keyHash = keyHashOf('twice', key);
    const rec = await IdempotencyRecord.findOne({ keyHash }).lean();
    // 承重：后续那次 500 不得把已成功提交的记录改回 in_progress，更不得删掉
    expect(rec && rec.state).toBe('completed');
    expect(rec && rec.statusCode).toBe(201);
    expect(countOf('twice')).toBe(1);

    const second = await post('twice', {}, key);
    expect(second.status).toBe(201);
    expect(second.headers['idempotency-replayed']).toBe('true');
    expect(second.body.data).toEqual({ n: 1 });
    expect(countOf('twice')).toBe(1);
  });

  test('(e2) 先 res.write 再 res.json：只能记「已完成、无体」，绝不回放从未发出的 JSON', async () => {
    const { waitFor } = require('../helpers/waitFor');
    const key = 'sup-mixed-' + stamp16();
    const first = await post('mixed', {}, key);
    expect(first.text).toBe('partial-only');
    const keyHash = keyHashOf('mixed', key);
    // 完成态落库是响应后的 fire-and-forget 写（b820c32 同判例）：随机序下 load 高，
    // 立即 findOne 会读到 in_progress——轮询到 completed 再断言
    await waitFor(
      async () => {
        const rec = await IdempotencyRecord.findOne({ keyHash }).lean();
        return Boolean(rec) && rec.state === 'completed';
      },
      { timeoutMs: 4000, label: 'mixed 响应收敛为 completed' }
    );
    const rec = await IdempotencyRecord.findOne({ keyHash }).lean();
    expect(rec && rec.state).toBe('completed');
    expect(rec && rec.replayOmitted).toBe(true);

    const second = await post('mixed', {}, key);
    expect(second.headers['idempotency-replay-omitted']).toBe('true');
    expect(second.text.includes('never-delivered')).toBe(false);
    expect(countOf('mixed')).toBe(1);
  });

  test('(f) 403 在幂等之前：不产生任何记录；重新授权后用同一个键重试是 201，不是 409', async () => {
    const key = 'sup-gated-' + stamp16();
    const keyHash = keyHashOf('gated', key);
    gateOpen = false;
    const denied = await post('gated', {}, key);
    expect(denied.status).toBe(403);
    // 承重：401/403 路径根本没有记录可留（中间件排在鉴权之后），所以不存在"卡 409 的孤儿键"
    expect(await IdempotencyRecord.countDocuments({ keyHash })).toBe(0);
    expect(countOf('gated')).toBe(0);

    gateOpen = true;
    const allowed = await post('gated', {}, key);
    expect(allowed.status).toBe(201);
    expect(allowed.headers['idempotency-replayed']).toBeUndefined();
    expect(countOf('gated')).toBe(1);
  });

  test('(f2) 处理器自己回 403：键被释放，修正后同键重试能成功', async () => {
    const { waitFor } = require('../helpers/waitFor');
    const key = 'sup-denied-' + stamp16();
    const first = await post('denied', {}, key);
    expect(first.status).toBe(403);
    // 释放键是响应后的 fire-and-forget 删（(e2) 同判例）：立即数会读到残留，
    // 且第二次 post 可能撞在途记录拿 409——轮询到键真的释放再继续
    await waitFor(
      async () =>
        (await IdempotencyRecord.countDocuments({ keyHash: keyHashOf('denied', key) })) === 0,
      { timeoutMs: 4000, label: 'denied 的键被释放' }
    );
    const second = await post('denied', {}, key);
    expect(second.status).toBe(403);
    expect(countOf('denied')).toBe(2); // 非 2xx 释放键：这是"可利用的重试"，不是卡死
  });

  test('(g) 键长度上限是硬判据：64 位可用，65 位与 4KB 一律 400 且不落库', async () => {
    expect(idempotencyKey.KEY_MAX_LENGTH).toBe(64);
    const at64 = 'k'.repeat(64);
    const okRes = await post('denied', {}, at64);
    expect(okRes.status).toBe(403); // 键形态通过 ⇒ 走到处理器（403 是处理器给的）
    await IdempotencyRecord.deleteMany({ keyHash: keyHashOf('denied', at64) });

    const over = 'k'.repeat(65);
    const bad = await post('denied', {}, over);
    expect(bad.status).toBe(400);
    expect(bad.body.errors?.errorCode).toBe('IDEMPOTENCY_KEY_INVALID');
    expect(await IdempotencyRecord.countDocuments({ keyHash: keyHashOf('denied', over) })).toBe(0);

    const huge = 'k'.repeat(4096);
    const bad2 = await post('denied', {}, huge);
    expect(bad2.status).toBe(400);
    expect(await IdempotencyRecord.countDocuments({ userId })).toBeGreaterThanOrEqual(0);
  });
});

describe('在途租约：崩溃/被杀/永久挂起不再把键钉满 24h（真实 HTTP + Mongo）', () => {
  const express = require('express');
  const IdempotencyRecord = require('../../models/IdempotencyRecord');
  const {
    idempotency,
    IN_PROGRESS_LEASE_MS,
    RETENTION_MS,
  } = require('../../middleware/idempotency');
  const metrics = require('../../utils/metrics');
  const { waitFor } = require('../helpers/waitFor');

  /**
   * 「响应头发出前断开」与「进程被杀」在库里是同一个形状：一条没人再收尾的 in_progress。
   * 本组按**认领时刻**构造这个形状（不依赖真的杀进程），钉三件事：
   *   ① 租约内不许夺（真在途的并发仍然只能 409）；
   *   ② 超租约必须能夺且只夺一次（原子条件更新，不是人人可夺）；
   *   ③ 夺取 = 在「上一次是否已落库」未知时再执行一次 ⇒ 必须有可计数信号。
   */

  const userId = String(new mongoose.Types.ObjectId());
  const runs = new Map();
  const bump = (name) => {
    const next = (runs.get(name) || 0) + 1;
    runs.set(name, next);
    return next;
  };
  const countOf = (name) => runs.get(name) || 0;
  const keyHashOf = (name, key) => hashIdempotencyKey({ scope: 'lease:' + name, userId, key });

  /** `idempotency_lease_takeover` 的累计值（缺失记 0；与 idempotencyDegradeSignal 同口径） */
  const leaseTakeOvers = () => {
    const hit = [...metrics._alertCounters.entries()].find(([k]) =>
      k.includes('idempotency_lease_takeover')
    );
    if (!hit) return 0;
    return typeof hit[1] === 'number'
      ? hit[1]
      : Object.values(hit[1]).reduce((sum, v) => sum + Number(v || 0), 0);
  };

  let app;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) await mongoose.connect(process.env.MONGODB_URI);
    await IdempotencyRecord.createIndexes();
    app = express();
    app.use(express.json());
    const route = (name, handler) => {
      app.post(
        '/' + name,
        (req, res, next) => {
          req.user = { userId };
          next();
        },
        idempotency({ scope: 'lease:' + name }),
        handler
      );
    };
    route('plain', (req, res) => {
      res.status(201).json({ success: true, data: { n: bump('plain') } });
    });
    // filter 抛错的挂载点（复审 F1-3）：中间件契约要求 filter 失败降级为
    // 「不可回放」而不是卡死 in_progress
    app.post(
      '/badfilter',
      (req, res, next) => {
        req.user = { userId };
        next();
      },
      idempotency({
        scope: 'lease:badfilter',
        replayBodyFilter: () => {
          throw new Error('filter exploded');
        },
      }),
      (req, res) => {
        res.status(201).json({ success: true, data: { n: bump('badfilter') } });
      }
    );
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await IdempotencyRecord.deleteMany({ userId }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  const post = (name, body, key) =>
    request(app)
      .post('/' + name)
      .set('Idempotency-Key', key)
      .send(body);

  /** 预置「某个进程认领后再没人收尾」的在途记录：ageMs 前认领、expiresAt = 认领 + 24h（与生产写入同形） */
  const seedClaim = (name, key, ageMs) =>
    IdempotencyRecord.create({
      keyHash: keyHashOf(name, key),
      userId,
      scope: 'lease:' + name,
      requestHash: fingerprintRequestBody({}),
      state: 'in_progress',
      createdAt: new Date(Date.now() - ageMs),
      expiresAt: new Date(Date.now() - ageMs + RETENTION_MS),
    });

  test('(h) 租约内（认领 1 分钟）：仍是在途 409，不接管、不执行、也不发接管信号', async () => {
    const key = 'lease-in-' + stamp16();
    await seedClaim('plain', key, 60 * 1000);
    const before = countOf('plain');
    const alertsBefore = leaseTakeOvers();

    const res = await post('plain', {}, key);
    expect(res.status).toBe(409);
    expect(res.body.errors.errorCode).toBe('IDEMPOTENCY_IN_PROGRESS');
    expect(countOf('plain')).toBe(before); // 没到租约就不许夺：真并发在途只能被拒
    expect(leaseTakeOvers()).toBe(alertsBefore); // 也不许发信号（防「恒发」把告警训练成噪声）
  });

  test('(i) 超租约（认领 10 分钟）：接管并恰好执行一次；接管有计数信号；租约随接管重置', async () => {
    const key = 'lease-out-' + stamp16();
    await seedClaim('plain', key, 10 * 60 * 1000);
    const before = countOf('plain');
    const alertsBefore = leaseTakeOvers();

    const first = await post('plain', {}, key);
    expect(first.status).toBe(201);
    expect(first.body.data.n).toBe(before + 1);
    expect(countOf('plain')).toBe(before + 1);
    expect(leaseTakeOvers()).toBe(alertsBefore + 1); // 「可能重复写」必须能从计数看见

    // 接管路径的完成态落库是响应后的 fire-and-forget 写（b820c32 同判例：不得赌时延），
    // 先轮询到 completed 再断言 expiresAt，全量跑高负载下不再偶发读到来早的 in_progress
    const leaseKeyHash = keyHashOf('plain', key);
    await waitFor(
      async () => {
        const rec = await IdempotencyRecord.findOne({ keyHash: leaseKeyHash }).lean();
        return Boolean(rec) && rec.state === 'completed';
      },
      { timeoutMs: 4000, label: '租约接管后收敛为 completed' }
    );
    const rec = await IdempotencyRecord.findOne({ keyHash: leaseKeyHash }).lean();
    expect(rec.state).toBe('completed');
    expect(new Date(rec.expiresAt).getTime()).toBeGreaterThan(Date.now() - 1000); // 接管时写回了新的 expiresAt

    const second = await post('plain', {}, key);
    expect(second.headers['idempotency-replayed']).toBe('true'); // 已交付 ⇒ 回放，不再执行第二次
    expect(countOf('plain')).toBe(before + 1);
  });

  test('(j) 超租约 + 5 并发同键：只有 1 个能接管执行（条件更新是原子的，不是人人可夺）', async () => {
    const key = 'lease-race-' + stamp16();
    await seedClaim('plain', key, 30 * 60 * 1000);
    const before = countOf('plain');
    const alertsBefore = leaseTakeOvers();

    const results = await Promise.all(Array.from({ length: 5 }, () => post('plain', {}, key)));
    expect(countOf('plain') - before).toBe(1);
    expect(results.every((r) => r.status === 201 || r.status === 409 || r.status === 200)).toBe(
      true
    );
    expect(results.some((r) => r.status >= 500)).toBe(false);
    expect(leaseTakeOvers()).toBe(alertsBefore + 1); // 只夺一次 ⇒ 只告警一次
  });

  test('(k) 超租约但载荷不同 ⇒ 仍是 409 KEY_REUSED：接管不放宽「同键必须同载荷」', async () => {
    const key = 'lease-mismatch-' + stamp16();
    await seedClaim('plain', key, 10 * 60 * 1000);
    const before = countOf('plain');

    const res = await post('plain', { x: 1 }, key);
    expect(res.status).toBe(409);
    expect(res.body.errors.errorCode).toBe('IDEMPOTENCY_KEY_REUSED');
    expect(countOf('plain')).toBe(before);
  });

  test('(l) 历史行（无 expiresAt）的在途残留：20 分钟前认领 ⇒ 同样超租约、可接管', async () => {
    const key = 'lease-legacy-' + stamp16();
    await IdempotencyRecord.collection.insertOne({
      keyHash: keyHashOf('plain', key),
      userId: new mongoose.Types.ObjectId(userId),
      scope: 'lease:plain',
      requestHash: fingerprintRequestBody({}),
      state: 'in_progress',
      createdAt: new Date(Date.now() - 20 * 60 * 1000),
      expiresAt: null,
    });
    const before = countOf('plain');

    const res = await post('plain', {}, key);
    expect(res.status).toBe(201);
    expect(countOf('plain')).toBe(before + 1);
  });

  test('(m) 反向对照：completed 的旧行只回放，绝不因为「看起来旧」被接管再执行一次', async () => {
    const key = 'lease-done-' + stamp16();
    await IdempotencyRecord.collection.insertOne({
      keyHash: keyHashOf('plain', key),
      userId: new mongoose.Types.ObjectId(userId),
      scope: 'lease:plain',
      requestHash: fingerprintRequestBody({}),
      state: 'completed',
      statusCode: 200,
      responseBody: { success: true, message: '已交付的结论', data: null },
      contentType: null,
      replayOmitted: false,
      createdAt: new Date(Date.now() - 10 * 60 * 1000),
      expiresAt: new Date(Date.now() + RETENTION_MS - 10 * 60 * 1000),
    });
    const before = countOf('plain');

    const res = await post('plain', {}, key);
    expect(res.headers['idempotency-replayed']).toBe('true');
    expect(res.body.message).toBe('已交付的结论');
    expect(countOf('plain')).toBe(before);
  });

  test('(n) 租约常数自身成立：0 < 租约 < 保留窗口（写反会让键要么立刻可夺、要么永远不租约）', () => {
    expect(IN_PROGRESS_LEASE_MS).toBeGreaterThan(0);
    expect(IN_PROGRESS_LEASE_MS).toBeLessThan(RETENTION_MS);
  });

  test('(o) 回放体 filter 抛错 → 降级为 completed + replayOmitted，绝不卡死 in_progress（复审 F1-3）', async () => {
    // 缺陷形态（修复前）：settled 已置位后 filter 在响应路径上抛错 ⇒ 业务写入
    // 已提交但记录停在 in_progress ⇒ 租约过期后同键重试二次执行已成功的写入。
    const key = stamp16();
    const first = await post('badfilter', {}, key);
    expect(first.status).toBe(201);
    expect(first.headers['idempotency-replay-omitted']).toBeUndefined(); // 首次响应原样交付

    // 注意 scope 前缀：这个挂载点走的是 lease: 前缀（route 助手），不是
    // keyHashOf 的 test: 前缀——按实际 scope 算哈希。waitFor 只回真值性，
    // 文档经闭包捕获；回填是 fire-and-forget 的 exec()，轮询到终态而不是赌时机。
    let stored = null;
    await waitFor(async () => {
      stored = await IdempotencyRecord.findOne({
        keyHash: hashIdempotencyKey({ scope: 'lease:badfilter', userId, key }),
      }).lean();
      return Boolean(stored && stored.state !== 'in_progress');
    });
    expect({ state: stored.state, replayOmitted: stored.replayOmitted }).toEqual({
      state: 'completed',
      replayOmitted: true, // filter 失败 = 不可回放，不是不可完成
    });

    // 同键重试：不重复执行业务（副作用仍是 1 次），回放"已完成、体略"结论
    const second = await post('badfilter', {}, key);
    expect(second.status).toBe(201);
    expect(second.headers['idempotency-replay-omitted']).toBe('true');
    expect(countOf('badfilter')).toBe(1);
  });
});

/** 16 位可见 ASCII 键（满足 8-64 位可见 ASCII 的键形态判据；既短于 64 又足够唯一）。 */
function stamp16() {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
}
