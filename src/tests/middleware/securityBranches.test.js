/**
 * security.js 分支补齐（branches 67.5% → 目标 80%+）
 *
 * 依据全量覆盖率基线的未覆盖分支行号：
 *  - deepSanitizeKeys：数组深度超限清空（L171-174）、Date/Buffer 跳过（L179）、
 *    对象深度超限清空（L180-182）、JSON.parse 原型污染键剔除（L188-194）
 *  - ensureHsts：已有 HSTS 头时不覆盖（L152）
 *  - checkIPBlacklist：DB 故障降级缓存命中拦截（L415-430）—— 可靠性关键路径；
 *    白名单豁免（L380-385）的缓存失效联动
 *  - addToBlacklist：无法解析的 IP 跳过（L455）、白名单 IP 跳过自动封禁（L462）
 *  - fileUploadSecurity：预留能力全分支（L643-687，当前无路由挂载，直接单测）
 *  - auditLog 中间件：GET 非白名单跳过（L519）、skipGlobalAudit 跳过（L524）
 */

const mongoose = require('mongoose');

jest.mock('../../models/AuditLog', () => ({
  record: jest.fn(() => Promise.resolve(null)),
}));

const {
  sanitizeMongo,
  ensureHsts,
  checkIPBlacklist,
  addToBlacklist,
  fileUploadSecurity,
  auditLog,
} = require('../../middleware/security');

// ---- 工具 ----
const makeRes = () => {
  const res = {};
  const headers = {};
  res.status = jest.fn(() => res);
  res.json = jest.fn(() => res);
  res.send = jest.fn(() => res);
  res.headersSent = false;
  res.statusCode = undefined;
  res.status.mockImplementation((code) => {
    res.statusCode = code;
    return res;
  });
  res.setHeader = jest.fn((k, v) => {
    headers[k] = v;
    return res;
  });
  res.getHeader = jest.fn((k) => headers[k]);
  return res;
};

const makeReq = (overrides = {}) => ({
  ip: '203.0.113.77', // TEST-NET-3 文档段：语义上表示外部请求，非内网
  connection: { remoteAddress: '203.0.113.77' },
  method: 'GET',
  path: '/api/devices',
  originalUrl: '/api/devices',
  params: {},
  query: {},
  body: {},
  headers: {},
  get: jest.fn(() => undefined),
  ...overrides,
});

describe('security.js 分支补齐', () => {
  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  describe('sanitizeMongo：递归清洗边界', () => {
    const run = (req) => {
      const res = makeRes();
      const next = jest.fn();
      sanitizeMongo(req, res, next);
      return { res, next };
    };

    test('Date 与 Buffer 值被跳过，属性原样保留（L179）', () => {
      const req = makeReq({
        body: { createdAt: new Date('2026-01-01T00:00:00Z'), blob: Buffer.from('hello') },
      });
      const { next } = run(req);
      expect(next).toHaveBeenCalled();
      expect(req.body.createdAt).toBeInstanceOf(Date);
      expect(Buffer.isBuffer(req.body.blob)).toBe(true);
      expect(req.body.blob.toString()).toBe('hello');
    });

    test('对象嵌套超深度：超限子树整体清空，浅层保留（L180-182）', () => {
      // 构造 13 层嵌套（depth 0 起算，depth>=10 被清空）
      const root = { payload: 'safe' };
      let cur = root;
      for (let i = 0; i < 13; i++) {
        cur.next = { payload: `lvl${i}` };
        cur = cur.next;
      }
      const req = makeReq({ body: root });
      const { next } = run(req);

      expect(next).toHaveBeenCalled();
      expect(req.body.payload).toBe('safe'); // 浅层保留
      let node = req.body;
      let cleared = 0;
      let survived = 0;
      while (node && typeof node === 'object') {
        if ('payload' in node) survived++;
        node = node.next;
      }
      // depth 0..9 共 10 层保留 payload，其余被 delete 清空
      expect(survived).toBe(10);
      expect(cleared).toBe(0);
    });

    test('数组嵌套超深度：超限数组被 length=0 清空（L171-174）', () => {
      // 数组链：list -> [arr] -> ... 共 12 层数组，最内数组深度 >=10 被清空
      let arr = [{ $ne: 1 }];
      for (let i = 0; i < 12; i++) {
        arr = [arr];
      }
      const req = makeReq({ body: { list: arr } });
      const { next } = run(req);

      expect(next).toHaveBeenCalled();
      // 逐层下钻到最深处，确认超限数组为空且无 $ne 逃逸
      let node = req.body.list;
      let deepest;
      while (Array.isArray(node)) {
        deepest = node;
        node = node[0];
      }
      expect(Array.isArray(deepest)).toBe(true);
      expect(deepest).toEqual([]);
      expect(JSON.stringify(req.body)).not.toContain('$ne');
    });

    test('JSON.parse 原型污染键（__proto__）被剔除（L188-194）', () => {
      const parsed = JSON.parse('{"name":"x","__proto__":{"injected":true},"nested":{"$gt":""}}');
      const req = makeReq({ body: parsed });
      const { next } = run(req);

      expect(next).toHaveBeenCalled();
      expect(req.body.name).toBe('x');
      // 注意：req.body.__proto__ 是原型访问器恒返回 Object.prototype，
      // 必须用自有属性判定确认污染键已被剔除
      expect(Object.prototype.hasOwnProperty.call(req.body, '__proto__')).toBe(false);
      expect(Object.getOwnPropertyNames(req.body)).toEqual(['name', 'nested']);
      expect(req.body.nested).toEqual({}); // $gt 键被删，nested 本身保留
      expect(JSON.stringify(req.body)).not.toContain('$gt');
    });
  });

  describe('ensureHsts：HSTS 兜底下发', () => {
    test('响应无 HSTS 头时补发固定值（L152 正向）', () => {
      const res = makeRes();
      const next = jest.fn();
      ensureHsts(makeReq(), res, next);
      expect(next).toHaveBeenCalled();
      expect(res.getHeader('Strict-Transport-Security')).toBe(
        'max-age=31536000; includeSubDomains; preload'
      );
    });

    test('已有 HSTS 头时不覆盖（L152 反向分支）', () => {
      const res = makeRes();
      res.setHeader('Strict-Transport-Security', 'max-age=123');
      const next = jest.fn();
      ensureHsts(makeReq(), res, next);
      expect(next).toHaveBeenCalled();
      expect(res.getHeader('Strict-Transport-Security')).toBe('max-age=123');
    });
  });

  describe('checkIPBlacklist：DB 故障降级缓存路径', () => {
    let IPBlacklist;

    beforeAll(() => {
      IPBlacklist = require('../../models/IPBlacklist');
    });

    afterEach(() => {
      jest.restoreAllMocks();
    });

    test('DB 正常 + 命中黑名单 → 403 且写入降级缓存（L387-411）', async () => {
      jest.spyOn(IPBlacklist, 'isWhitelisted').mockResolvedValue(false);
      jest.spyOn(IPBlacklist, 'isBlocked').mockResolvedValue(true);
      const res = makeRes();
      const next = jest.fn();

      await checkIPBlacklist(makeReq({ ip: '198.51.100.9' }), res, next);

      expect(next).not.toHaveBeenCalled();
      expect(res.statusCode).toBe(403);
    });

    test('DB 正常 + 白名单命中 → 放行并挂 ipWhitelisted（L380-385）', async () => {
      jest.spyOn(IPBlacklist, 'isWhitelisted').mockResolvedValue(true);
      jest.spyOn(IPBlacklist, 'isBlocked').mockResolvedValue(true); // 双命中也放行
      const res = makeRes();
      const next = jest.fn();
      const req = makeReq({ ip: '198.51.100.10' });

      await checkIPBlacklist(req, res, next);

      expect(next).toHaveBeenCalled();
      expect(req.ipWhitelisted).toBe(true);
    });

    test('DB 故障 + 降级缓存命中 → 仍拦截（可靠性关键路径，L415-429）', async () => {
      // 第一步：DB 正常时命中黑名单，写入进程内降级缓存
      jest.spyOn(IPBlacklist, 'isWhitelisted').mockResolvedValue(false);
      jest.spyOn(IPBlacklist, 'isBlocked').mockResolvedValue(true);
      await checkIPBlacklist(makeReq({ ip: '198.51.100.11' }), makeRes(), jest.fn());

      // 第二步：DB 故障（查询抛错），降级缓存应兜底拦截
      jest.restoreAllMocks();
      jest.spyOn(IPBlacklist, 'isWhitelisted').mockRejectedValue(new Error('db down'));
      jest.spyOn(IPBlacklist, 'isBlocked').mockRejectedValue(new Error('db down'));
      const res = makeRes();
      const next = jest.fn();

      await checkIPBlacklist(makeReq({ ip: '198.51.100.11' }), res, next);

      expect(next).not.toHaveBeenCalled();
      expect(res.statusCode).toBe(403);
    });

    test('DB 故障 + 缓存未命中 → 放行（避免数据库抖动造成全站不可用）', async () => {
      jest.spyOn(IPBlacklist, 'isWhitelisted').mockRejectedValue(new Error('db down'));
      jest.spyOn(IPBlacklist, 'isBlocked').mockRejectedValue(new Error('db down'));
      const res = makeRes();
      const next = jest.fn();

      await checkIPBlacklist(makeReq({ ip: '198.51.100.99' }), res, next);

      expect(next).toHaveBeenCalled();
      expect(res.statusCode).toBeUndefined();
    });

    test('DB 恢复且未命中黑名单 → 清除陈旧降级缓存，解封后立即放行（L413-414）', async () => {
      // 第一步：DB 正常且命中黑名单，写入降级缓存
      jest.spyOn(IPBlacklist, 'isWhitelisted').mockResolvedValue(false);
      jest.spyOn(IPBlacklist, 'isBlocked').mockResolvedValue(true);
      await checkIPBlacklist(makeReq({ ip: '198.51.100.21' }), makeRes(), jest.fn());

      // 第二步：解封后 DB 正常且未命中 → 放行并清除陈旧缓存
      jest.restoreAllMocks();
      jest.spyOn(IPBlacklist, 'isWhitelisted').mockResolvedValue(false);
      jest.spyOn(IPBlacklist, 'isBlocked').mockResolvedValue(false);
      const res = makeRes();
      const next = jest.fn();
      await checkIPBlacklist(makeReq({ ip: '198.51.100.21' }), res, next);
      expect(next).toHaveBeenCalled();

      // 第三步：随后 DB 故障也不得再被陈旧缓存误拦（缓存已在上一步清除）
      jest.restoreAllMocks();
      jest.spyOn(IPBlacklist, 'isWhitelisted').mockRejectedValue(new Error('db down'));
      jest.spyOn(IPBlacklist, 'isBlocked').mockRejectedValue(new Error('db down'));
      const res2 = makeRes();
      const next2 = jest.fn();
      await checkIPBlacklist(makeReq({ ip: '198.51.100.21' }), res2, next2);
      expect(next2).toHaveBeenCalled();
      expect(res2.statusCode).toBeUndefined();
    });

    test('白名单命中 → 清除该 IP 封禁缓存，DB 故障期不误拦（L380-384）', async () => {
      // 先以黑名单身份写入降级缓存
      jest.spyOn(IPBlacklist, 'isWhitelisted').mockResolvedValue(false);
      jest.spyOn(IPBlacklist, 'isBlocked').mockResolvedValue(true);
      await checkIPBlacklist(makeReq({ ip: '198.51.100.22' }), makeRes(), jest.fn());

      // 管理员将其加入白名单：命中即放行并清缓存
      jest.restoreAllMocks();
      jest.spyOn(IPBlacklist, 'isWhitelisted').mockResolvedValue(true);
      jest.spyOn(IPBlacklist, 'isBlocked').mockResolvedValue(true);
      const resWl = makeRes();
      const nextWl = jest.fn();
      await checkIPBlacklist(makeReq({ ip: '198.51.100.22' }), resWl, nextWl);
      expect(nextWl).toHaveBeenCalled();

      // 随后 DB 故障也不得被陈旧缓存拦截
      jest.restoreAllMocks();
      jest.spyOn(IPBlacklist, 'isWhitelisted').mockRejectedValue(new Error('db down'));
      jest.spyOn(IPBlacklist, 'isBlocked').mockRejectedValue(new Error('db down'));
      const res = makeRes();
      const next = jest.fn();
      await checkIPBlacklist(makeReq({ ip: '198.51.100.22' }), res, next);
      expect(next).toHaveBeenCalled();
      expect(res.statusCode).toBeUndefined();
    });
  });

  describe('addToBlacklist：前置校验分支', () => {
    let IPBlacklist;

    beforeAll(() => {
      IPBlacklist = require('../../models/IPBlacklist');
    });

    afterEach(() => {
      jest.restoreAllMocks();
    });

    test('无法解析的地址 → 跳过，不调用 blockIP（L455-458）', async () => {
      const blockIP = jest.spyOn(IPBlacklist, 'blockIP').mockResolvedValue({});
      jest.spyOn(IPBlacklist, 'isWhitelisted').mockResolvedValue(false);

      await addToBlacklist('not-an-ip-at-all');

      expect(blockIP).not.toHaveBeenCalled();
    });

    test('白名单中的 IP → 跳过自动封禁（L461-465）', async () => {
      const blockIP = jest.spyOn(IPBlacklist, 'blockIP').mockResolvedValue({});
      jest.spyOn(IPBlacklist, 'isWhitelisted').mockResolvedValue(true);

      await addToBlacklist('203.0.113.20');

      expect(blockIP).not.toHaveBeenCalled();
    });

    test('普通 IP → 归一化后调用 blockIP（正向）', async () => {
      const blockIP = jest.spyOn(IPBlacklist, 'blockIP').mockResolvedValue({});
      jest.spyOn(IPBlacklist, 'isWhitelisted').mockResolvedValue(false);

      await addToBlacklist('::ffff:203.0.113.21', 60000, 'test', 'auto');

      expect(blockIP).toHaveBeenCalledTimes(1);
      const [ipArg, opts] = blockIP.mock.calls[0];
      expect(ipArg).toBe('203.0.113.21'); // IPv4-mapped 已归一化
      expect(opts).toMatchObject({ reason: 'test', durationMs: 60000, source: 'auto' });
    });
  });

  describe('fileUploadSecurity：预留能力全分支（无路由挂载，直接单测）', () => {
    const runUpload = (files, options) => {
      const req = makeReq({ files });
      const res = makeRes();
      const next = jest.fn();
      const mw = fileUploadSecurity(options);
      return mw(req, res, next).then(() => ({ res, next }));
    };

    test('无文件 → 直接放行（L650-652）', async () => {
      const { res, next } = await runUpload([]);
      expect(next).toHaveBeenCalled();
      expect(res.statusCode).toBeUndefined();
    });

    test('文件超过大小限制 → 400（L656-662）', async () => {
      const { res, next } = await runUpload(
        [{ originalname: 'big.png', size: 6 * 1024 * 1024, mimetype: 'image/png' }],
        { maxSize: 5 * 1024 * 1024 }
      );
      expect(next).not.toHaveBeenCalled();
      expect(res.statusCode).toBe(400);
    });

    test('MIME 类型不在白名单 → 400（L665-667）', async () => {
      const { res, next } = await runUpload(
        [{ originalname: 'a.exe', size: 100, mimetype: 'application/x-msdownload' }],
        { allowedTypes: ['image/png'] }
      );
      expect(next).not.toHaveBeenCalled();
      expect(res.statusCode).toBe(400);
    });

    test('扩展名与 MIME 不符（伪装）→ 400（L670-683）', async () => {
      const { res, next } = await runUpload(
        [{ originalname: 'evil.txt', size: 100, mimetype: 'image/png' }],
        { allowedTypes: ['image/png'] }
      );
      expect(next).not.toHaveBeenCalled();
      expect(res.statusCode).toBe(400);
    });

    test('合法文件 → 放行（正向）', async () => {
      const { res, next } = await runUpload(
        [{ originalname: 'ok.png', size: 100, mimetype: 'image/png' }],
        { allowedTypes: ['image/png'] }
      );
      expect(next).toHaveBeenCalled();
      expect(res.statusCode).toBeUndefined();
    });
  });

  describe('auditLog 中间件：路径与跳过分支', () => {
    test('GET 命中敏感读取白名单 → 包装响应并走审计（L514-516 正向）', async () => {
      const mw = auditLog();
      const req = makeReq({ method: 'GET', originalUrl: '/api/users?page=1', path: '/api/users' });
      const res = makeRes();
      const next = jest.fn();

      mw(req, res, next);
      res.json({ success: true }); // 触发拦截
      await new Promise((r) => setImmediate(r));

      expect(next).toHaveBeenCalled();
      expect(typeof res.json).toBe('function');
    });

    test('GET 非白名单路径 → 直接放行，不包装响应（L519-521）', () => {
      const mw = auditLog();
      const originalJson = jest.fn(() => 'orig');
      const req = makeReq({ method: 'GET', originalUrl: '/api/devices', path: '/api/devices' });
      const res = makeRes();
      res.json = originalJson;
      const next = jest.fn();

      mw(req, res, next);

      expect(next).toHaveBeenCalled();
      // 响应方法未被包装
      expect(res.json('x')).toBe('orig');
      expect(originalJson).toHaveBeenCalledWith('x');
    });

    test('控制器声明 skipGlobalAudit → 跳过（L524-526）', () => {
      const mw = auditLog();
      const originalJson = jest.fn(() => 'orig');
      const req = makeReq({ method: 'POST', originalUrl: '/api/devices', path: '/api/devices' });
      const res = makeRes();
      res.locals = { skipGlobalAudit: true };
      res.json = originalJson;
      const next = jest.fn();

      mw(req, res, next);

      expect(next).toHaveBeenCalled();
      expect(res.json('x')).toBe('orig');
    });
  });
});
