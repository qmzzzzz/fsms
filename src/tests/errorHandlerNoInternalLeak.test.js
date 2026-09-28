/**
 * errorHandler 的对外契约：每一条分支都不许把内部细节写给客户端
 *
 * 为什么单独钉这一份：`src/middleware/errorHandler.js` 是信息泄露的最后一道闸，
 * 但此前只有 10 个套件**间接**经过它（且多数把 errorHandler 整个 mock 掉），
 * 没有任何一处按"每条分支 × 生产/开发"系统断言过响应体。
 * 最典型的回退形态就是"调试时顺手把 err.message / err.stack 回显出去"——
 * 那一次改动会让 500 响应带上文件路径、依赖版本甚至凭据片段，
 * 而单元测试（只断言状态码）不会红。
 *
 * 本用例的写法：给每种错误形状灌入**唯一哨兵串**（message/stack/path/errmsg/errors 里各一处），
 * 再断言哨兵从不出现在响应体里。这比"断言等于某个通用文案"更能挡住意外改动：
 * 换文案仍可能通过，回显内部信息必然失败。
 *
 * 同时钉住两个方向性契约（防止"为了过闸一律吞掉"的过度收紧）：
 *  - ApiError 分支**必须**原样回显 err.message（那是我们自己写的对外文案）；
 *  - 开发模式下 ValidationError 必须带上字段明细（生产才收敛）。
 */

const path = require('path');

const MOD_PATH = path.join(__dirname, '..', 'middleware', 'errorHandler.js');

const S = {
  message: 'SENTINEL_INNER_MESSAGE',
  stack: 'Error: SENTINEL_STACK\n    at /home/deploy/app/src/internal/secret.js:7:12',
  path: 'SENTINEL_SCHEMA_PATH',
  errmsg:
    'E11000 duplicate key error collection: app.users index: email_1 dup key: SENTINEL_DUP_DETAIL',
  nested: 'SENTINEL_VALIDATION_RULE',
  query: 'token=SENTINEL_IN_QUERY',
};

function makeRes({ headersSent = false, writableEnded = false } = {}) {
  const res = {
    headersSent,
    writableEnded,
    statusCode: 200,
    locals: {},
    body: null,
    status(code) {
      res.statusCode = code;
      return res;
    },
    json(payload) {
      res.body = payload;
      return res;
    },
    end() {
      res.ended = true;
      return res;
    },
  };
  return res;
}

const makeReq = () => ({
  method: 'POST',
  originalUrl: `/api/devices/export?${S.query}`,
  path: '/api/devices/export',
  ip: '203.0.113.9',
  user: { userId: '507f1f77bcf86cd799439011', username: 'zzq' },
});

function run(handler, err, opts) {
  const req = makeReq();
  const res = makeRes(opts);
  handler(err, req, res, () => {});
  return res;
}

/** 响应体整体序列化后不得出现任何哨兵 */
function expectNoSentinel(res) {
  const wire = JSON.stringify(res.body ?? null);
  for (const [name, token] of Object.entries(S)) {
    expect({ name, wire }).not.toMatchObject({ name, wire: expect.stringContaining(token) });
  }
}

describe('zzqoder errorHandler 生产模式下逐分支不得回显内部细节', () => {
  const prevEnv = process.env.NODE_ENV;
  let handler;

  beforeAll(() => {
    process.env.NODE_ENV = 'production';
    handler = require(MOD_PATH);
  });

  afterAll(() => {
    if (prevEnv === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = prevEnv;
  });

  // ---- 逐分支：状态码 + 哨兵不外泄 ----
  const CASES = [
    [
      'CastError（Mongoose 坏 ObjectId）',
      { name: 'CastError', path: S.path, message: S.message },
      400,
    ],
    [
      'DuplicateKey（11000，带 keyPattern）',
      { code: 11000, keyPattern: { email: 1 }, errmsg: S.errmsg, message: S.message },
      400,
    ],
    [
      'DuplicateKey（11000，缺 keyPattern/keyValue）',
      { code: 11000, errmsg: S.errmsg, message: S.message },
      400,
    ],
    [
      'ValidationError（带 errors 明细）',
      {
        name: 'ValidationError',
        message: S.message,
        errors: { email: { path: S.path, message: S.nested } },
      },
      400,
    ],
    ['JsonWebTokenError', { name: 'JsonWebTokenError', message: S.message }, 401],
    ['TokenExpiredError', { name: 'TokenExpiredError', message: S.message }, 401],
    [
      'entity.parse.failed（JSON 解析失败）',
      { type: 'entity.parse.failed', message: S.message },
      400,
    ],
    ['entity.too.large（请求体超限）', { type: 'entity.too.large', message: S.message }, 413],
    [
      '未知错误（普通 Error + stack）',
      { name: 'TypeError', message: S.message, stack: S.stack },
      500,
    ],
    ['未知错误且 message 为空', { name: 'Error', message: '', stack: S.stack }, 500],
  ];

  test.each(CASES)('%s → %i 且响应体不含任何内部哨兵', (_label, errShape, status) => {
    const res = run(handler, errShape);
    expect(res.statusCode).toBe(status);
    expect(res.body.success).toBe(false);
    expect(typeof res.body.message).toBe('string');
    expectNoSentinel(res);
  });

  test('取数有效：上面确实跑了多条分支（防 test.each 空数组恒绿）', () => {
    expect(CASES.length).toBeGreaterThanOrEqual(9);
  });

  test('码化分支必须带 errorCode（前端据此做 i18n，不得退化成裸文案）', () => {
    expect(
      run(handler, { name: 'ValidationError', message: S.message, errors: {} }).body.errors
    ).toMatchObject({
      errorCode: 'VALIDATION_FAILED',
    });
    expect(
      run(handler, { type: 'entity.parse.failed', message: S.message }).body.errors
    ).toMatchObject({
      errorCode: 'JSON_PARSE_FAILED',
    });
    expect(
      run(handler, { type: 'entity.too.large', message: S.message }).body.errors
    ).toMatchObject({
      errorCode: 'PAYLOAD_EXCEEDS_LIMIT',
    });
    expect(run(handler, new Error(S.message)).body.errors).toMatchObject({
      errorCode: 'INTERNAL_ERROR',
    });
  });

  test('生产模式下 ValidationError 不得回传字段名（schema 信息）', () => {
    const res = run(handler, {
      name: 'ValidationError',
      message: S.message,
      errors: { email: { path: S.path, message: S.nested } },
    });
    expect(res.body.errors.fieldErrors).toBeUndefined();
  });

  // ---- 反向控制：闸不该把"我们自己想说的话"也吞掉 ----
  test('ApiError 分支按契约回显自身 message（防"一律通用文案"式过度收紧）', () => {
    const err = Object.assign(new Error('额度不足，请 10 分钟后再试'), {
      isApiError: true,
      statusCode: 429,
      errors: { retryAfter: 600 },
    });
    const res = run(handler, err);
    expect(res.statusCode).toBe(429);
    expect(res.body.message).toBe('额度不足，请 10 分钟后再试');
    expect(res.body.errors).toEqual({ retryAfter: 600 });
  });

  test('ApiError 缺 statusCode 时落 400，不得落到 500 分支', () => {
    const err = Object.assign(new Error('参数不合法'), { isApiError: true });
    const res = run(handler, err);
    expect(res.statusCode).toBe(400);
    expect(res.body.message).toBe('参数不合法');
  });

  // ---- headersSent 早退分支：错误处理器不得在响应已发出后再写 ----
  test('响应头已发出时：不再 status/json，结束响应并把原因挂到 res.locals', () => {
    const res = run(handler, Object.assign(new Error(S.message), { stack: S.stack }), {
      headersSent: true,
    });
    expect(res.body).toBeNull();
    expect(res.statusCode).toBe(200);
    expect(res.ended).toBe(true);
    expect(res.locals.responseAbortedByError).toBe(S.message);
  });

  test('响应已自然结束时不得重复 end（二次 end 会抛 ERR_STREAM_ALREADY_FINISHED）', () => {
    const res = run(handler, new Error(S.message), { headersSent: true, writableEnded: true });
    expect(res.ended).toBeUndefined();
    expect(res.locals.responseAbortedByError).toBe(S.message);
  });

  test('headersSent 且 err 无 message 时原因回落为"未知错误"，不得抛 TypeError', () => {
    const res = run(handler, {}, { headersSent: true });
    expect(res.locals.responseAbortedByError).toBe('未知错误');
    expect(res.ended).toBe(true);
  });
});

describe('zzqoder errorHandler 开发模式仅放宽日志与字段明细，不回显 stack', () => {
  const prevEnv = process.env.NODE_ENV;
  let handler;

  beforeAll(() => {
    process.env.NODE_ENV = 'development';
    // errorHandler 在调用期读 NODE_ENV（不是模块加载期），故无需重置模块缓存
    handler = require(MOD_PATH);
  });

  afterAll(() => {
    if (prevEnv === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = prevEnv;
  });

  test('开发模式下 ValidationError 必须带字段明细（否则前端表单定位不到错误）', () => {
    const res = run(handler, {
      name: 'ValidationError',
      message: S.message,
      errors: { email: { path: 'email', message: S.nested } },
    });
    expect(res.body.errors.fieldErrors).toEqual([{ field: 'email', message: S.nested }]);
  });

  test('开发模式下未知错误仍然只回通用文案：stack 只能进日志，不能进响应', () => {
    const res = run(handler, Object.assign(new Error(S.message), { stack: S.stack }));
    expect(res.statusCode).toBe(500);
    expectNoSentinel(res);
  });

  test('非 development 的字面量（prod/production/staging）一律走严格口径', () => {
    const saved = process.env.NODE_ENV;
    try {
      for (const v of ['prod', 'production', 'staging', '', 'Development']) {
        process.env.NODE_ENV = v;
        const res = run(handler, Object.assign(new Error(S.message), { stack: S.stack }));
        expect({ v, body: res.body.message }).not.toMatchObject({
          v,
          body: expect.stringContaining('SENTINEL'),
        });
        expect(res.body.errors).toMatchObject({ errorCode: 'INTERNAL_ERROR' });
      }
    } finally {
      process.env.NODE_ENV = saved;
    }
  });
});
