/**
 * 日志合规化核心逻辑测试：哈希链连续性、append-only 防篡改、canonicalPayload 稳定性
 *
 * 覆盖等保/ISO 审计日志合规改造的关键不变式：
 * - canonicalPayload 字段顺序固定、确定性
 * - computeHash 为确定性 SHA-256
 * - chainBatch 批内顺序串链
 * - AuditLog.create 经 pre('save') 自动产出 hash 且 prevHash 指向上一条
 * - append-only 钩子拒绝 update/delete，{bypassAppendOnly:true} 可放行
 */

const mongoose = require('mongoose');

const {
  canonicalPayload,
  computeHash,
  chainBatch,
  getLatestHash,
  computeHmac,
  isHmacConfigured,
  getChainTail,
  advanceChainTail,
  rollbackChainTail,
  resyncChainTail,
  CURRENT_PAYLOAD_VERSION,
} = require('../../utils/auditChain');

describe('审计日志合规化', () => {
  let AuditLog;

  beforeAll(async () => {
    AuditLog = require('../../models/AuditLog');
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
  });

  afterEach(async () => {
    // append-only 钩子会拒绝 deleteMany，测试清理通过 bypassAppendOnly 绕过
    await AuditLog.deleteMany({ username: /^chain_|^append_/ }, { bypassAppendOnly: true });
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  // ---------- 纯函数层：canonicalPayload / computeHash / chainBatch ----------
  describe('canonicalPayload — 规范化与确定性', () => {
    test('相同字段值产出相同字符串（字段顺序固定）', () => {
      const a = {
        timestamp: '2026-08-22T00:00:00.000Z',
        action: 'login',
        category: 'auth',
        userId: 'u1',
        username: 'alice',
        ip: '::1',
        path: '/api/auth/login',
        statusCode: 200,
        body: {},
      };
      const b = {
        path: '/api/auth/login',
        statusCode: 200,
        body: {},
        timestamp: '2026-08-22T00:00:00.000Z',
        action: 'login',
        category: 'auth',
        userId: 'u1',
        username: 'alice',
        ip: '::1',
      };
      expect(canonicalPayload(a)).toBe(canonicalPayload(b));
    });

    test('body 缺省补 {}（与 schema default 一致）', () => {
      const withBody = {
        timestamp: '2026-08-22T00:00:00.000Z',
        action: 'a',
        category: 'auth',
        userId: null,
        username: 'x',
        ip: '::1',
        path: '/p',
        statusCode: 200,
        body: {},
      };
      const noBody = {
        timestamp: '2026-08-22T00:00:00.000Z',
        action: 'a',
        category: 'auth',
        userId: null,
        username: 'x',
        ip: '::1',
        path: '/p',
        statusCode: 200,
      };
      expect(canonicalPayload(noBody)).toBe(canonicalPayload(withBody));
    });

    test('不同字段值产出不同字符串', () => {
      const a = {
        timestamp: '2026-08-22T00:00:00.000Z',
        action: 'login',
        category: 'auth',
        userId: null,
        username: 'x',
        ip: '::1',
        path: '/p',
        statusCode: 200,
        body: {},
      };
      const b = { ...a, statusCode: 401 };
      expect(canonicalPayload(a)).not.toBe(canonicalPayload(b));
    });
  });

  describe('computeHash — 确定性 SHA-256', () => {
    test('相同输入产出 64 位 hex 且稳定', () => {
      const h1 = computeHash(null, '{"a":1}');
      const h2 = computeHash(null, '{"a":1}');
      expect(h1).toBe(h2);
      expect(h1).toMatch(/^[0-9a-f]{64}$/);
    });

    test('prevHash 变化则 hash 变化（链式依赖）', () => {
      const p = '{"a":1}';
      expect(computeHash(null, p)).not.toBe(computeHash('abc', p));
    });

    test('undefined prevHash 等同 null', () => {
      expect(computeHash(undefined, '{"a":1}')).toBe(computeHash(null, '{"a":1}'));
    });
  });

  describe('chainBatch — 批内顺序串链', () => {
    test('每条 prevHash 指向上一条 hash，返回链尾', () => {
      const docs = [
        {
          timestamp: new Date(),
          action: 'a1',
          category: 'auth',
          userId: null,
          username: 'chain_x',
          ip: '::1',
          path: '/p1',
          statusCode: 200,
          body: {},
        },
        {
          timestamp: new Date(),
          action: 'a2',
          category: 'auth',
          userId: null,
          username: 'chain_x',
          ip: '::1',
          path: '/p2',
          statusCode: 200,
          body: {},
        },
        {
          timestamp: new Date(),
          action: 'a3',
          category: 'auth',
          userId: null,
          username: 'chain_x',
          ip: '::1',
          path: '/p3',
          statusCode: 200,
          body: {},
        },
      ];
      const tail = chainBatch(docs, null);

      expect(docs[0].prevHash).toBeNull();
      expect(docs[1].prevHash).toBe(docs[0].hash);
      expect(docs[2].prevHash).toBe(docs[1].hash);
      expect(tail).toBe(docs[2].hash);
      // 每条 hash 都已填充
      expect(docs.every((d) => d.hash && d.hash.length === 64)).toBe(true);
    });

    test('批次接续已有链尾（startPrevHash 非 null）', () => {
      const docs = [
        {
          timestamp: new Date(),
          action: 'b1',
          category: 'auth',
          userId: null,
          username: 'chain_y',
          ip: '::1',
          path: '/p',
          statusCode: 200,
          body: {},
        },
      ];
      const tail = chainBatch(docs, 'prevhashvalue');
      expect(docs[0].prevHash).toBe('prevhashvalue');
      expect(tail).toBe(docs[0].hash);
    });
  });

  // ---------- 断链根因回归：串链时的 payload 必须与落库后的文档一致 ----------
  describe('chainBatch 与 schema 默认值对齐（AUX-02 断链根因）', () => {
    test('串链前补齐所有带 default 的 payload 字段', () => {
      // auditBuffer 走 insertMany：chainBatch 在入库前算 hash，
      // 而 Mongoose 在入库时才填 riskLevel='low' / riskFactors=[] / params,query,body={}。
      // 若不预先补齐，算 hash 用的是 undefined、落库后是默认值 →
      // 校验时重算必然 hash_mismatch（实测 4182/4776 条记录受此影响）
      const doc = {
        action: 'chain_defaults',
        category: 'system',
        username: 'chain_defaults',
        ip: '::1',
        path: '/p',
        statusCode: 200,
        success: true,
      };
      chainBatch([doc], null);

      expect(doc.riskLevel).toBe('low');
      expect(doc.riskFactors).toEqual([]);
      expect(doc.params).toEqual({});
      expect(doc.query).toEqual({});
      expect(doc.body).toEqual({});
      expect(doc.timestamp).toBeInstanceOf(Date);
    });

    test('默认值表覆盖 schema 中所有「参与 payload 且有 default」的字段', () => {
      // 防漂移守卫：schema 新增带 default 的 payload 字段却忘记登记到
      // PAYLOAD_SCHEMA_DEFAULTS 时，同类断链会再次出现
      const { PAYLOAD_SCHEMA_DEFAULTS, PAYLOAD_FIELDS_V3 } = require('../../utils/auditChain');
      const paths = AuditLog.schema.paths;

      const missing = PAYLOAD_FIELDS_V3.filter((field) => {
        const path = paths[field];
        if (!path) return false;
        const hasDefault = path.options && path.options.default !== undefined;
        // 数组字段（riskFactors）在 mongoose 中默认即 []，需单独识别
        const isArrayWithImplicitDefault = path.instance === 'Array';
        return (
          (hasDefault || isArrayWithImplicitDefault) &&
          !Object.prototype.hasOwnProperty.call(PAYLOAD_SCHEMA_DEFAULTS, field)
        );
      });

      expect(missing).toEqual([]);
    });

    test('v2 历史口径仅用于校验存量、不影响 v3 新写入', () => {
      // 校验端对 v2 记录额外尝试「riskLevel/riskFactors 缺席」的历史口径，
      // 把已知的默认值漂移与真实篡改区分开；v3 记录不得享受这份宽容
      const {
        canonicalPayloadV2LegacyBatch,
        CURRENT_PAYLOAD_VERSION,
      } = require('../../utils/auditChain');
      expect(CURRENT_PAYLOAD_VERSION).toBe(3);

      const doc = {
        timestamp: new Date('2026-08-25T00:00:00.000Z'),
        action: 'a',
        category: 'system',
        username: 'x',
        ip: '::1',
        path: '/p',
        statusCode: 200,
        params: {},
        query: {},
        body: {},
        riskLevel: 'low',
        riskFactors: [],
      };
      // 历史口径把这两个字段视为缺席 → 与当前口径产出不同的 payload
      expect(canonicalPayloadV2LegacyBatch(doc)).not.toBe(canonicalPayload(doc, 3));
      // 且不篡改入参
      expect(doc.riskLevel).toBe('low');
    });

    test('批量落库后重算 hash 与库内一致（端到端）', async () => {
      // 直接用 insertMany 复现 auditBuffer 的落库方式
      const docs = [
        {
          action: 'chain_e2e_1',
          category: 'system',
          username: 'chain_e2e',
          ip: '::1',
          path: '/e1',
          statusCode: 200,
          success: true,
        },
        {
          action: 'chain_e2e_2',
          category: 'system',
          username: 'chain_e2e',
          ip: '::1',
          path: '/e2',
          statusCode: 200,
          success: true,
        },
        {
          action: 'chain_e2e_3',
          category: 'system',
          username: 'chain_e2e',
          ip: '::1',
          path: '/e3',
          statusCode: 200,
          success: true,
        },
      ];
      chainBatch(docs, null);
      await AuditLog.insertMany(docs, { ordered: false });

      const stored = await AuditLog.find({ username: 'chain_e2e' }).sort({ _id: 1 }).lean();
      expect(stored).toHaveLength(3);

      for (const doc of stored) {
        expect(doc.hashVersion).toBe(3);
        const recomputed = computeHash(doc.prevHash, canonicalPayload(doc, doc.hashVersion || 1));
        expect(recomputed).toBe(doc.hash);
      }
      // 批内链接性
      expect(stored[1].prevHash).toBe(stored[0].hash);
      expect(stored[2].prevHash).toBe(stored[1].hash);
    });
  });

  // ---------- 归一化与版本分支（P3-49：把棘轮基线抬到真实覆盖）----------
  describe('normalizeValue 与 payload 版本分支', () => {
    /** 构造最小可用的 v1 文档（v1 字段集较窄） */
    const v1Doc = (over = {}) => ({
      timestamp: '2026-08-22T00:00:00.000Z',
      action: 'a',
      category: 'auth',
      userId: null,
      username: 'x',
      ip: '::1',
      path: '/p',
      statusCode: 200,
      body: {},
      ...over,
    });

    test('version < 2 走 v1 口径，与 v2/v3 产出不同', () => {
      const doc = v1Doc();
      expect(canonicalPayload(doc, 1)).not.toBe(canonicalPayload(doc, 2));
      // v1 只含 9 个字段，v2 含全字段白名单
      expect(canonicalPayload(doc, 1).length).toBeLessThan(canonicalPayload(doc, 2).length);
    });

    test('v1：Date 型 timestamp 与等值 ISO 字符串产出一致', () => {
      const iso = '2026-08-22T00:00:00.000Z';
      expect(canonicalPayload(v1Doc({ timestamp: new Date(iso) }), 1)).toBe(
        canonicalPayload(v1Doc({ timestamp: iso }), 1)
      );
    });

    test('v1：timestamp 为空串/null/undefined 均归一为 null', () => {
      const base = canonicalPayload(v1Doc({ timestamp: null }), 1);
      expect(canonicalPayload(v1Doc({ timestamp: '' }), 1)).toBe(base);
      expect(canonicalPayload(v1Doc({ timestamp: undefined }), 1)).toBe(base);
    });

    test('v1：body 缺省补 {}', () => {
      const doc = v1Doc();
      delete doc.body;
      expect(canonicalPayload(doc, 1)).toBe(canonicalPayload(v1Doc({ body: {} }), 1));
    });

    test('ObjectId 归一为 hex（同一 id 的两种形态等价）', () => {
      const oid = new mongoose.Types.ObjectId();
      const asObj = canonicalPayload({ ...v1Doc(), userId: oid }, CURRENT_PAYLOAD_VERSION);
      const asStr = canonicalPayload(
        { ...v1Doc(), userId: oid.toHexString() },
        CURRENT_PAYLOAD_VERSION
      );
      expect(asObj).toBe(asStr);
    });

    test('非有限数（NaN/Infinity）归一为 null，避免 JSON 序列化差异', () => {
      const nan = canonicalPayload({ ...v1Doc(), duration: NaN }, CURRENT_PAYLOAD_VERSION);
      const nul = canonicalPayload({ ...v1Doc(), duration: null }, CURRENT_PAYLOAD_VERSION);
      expect(nan).toBe(nul);
      expect(canonicalPayload({ ...v1Doc(), duration: Infinity }, CURRENT_PAYLOAD_VERSION)).toBe(
        nul
      );
    });

    test('布尔与数值保留原类型（不被 String() 吞掉）', () => {
      const t = canonicalPayload({ ...v1Doc(), success: true }, CURRENT_PAYLOAD_VERSION);
      const s = canonicalPayload({ ...v1Doc(), success: 'true' }, CURRENT_PAYLOAD_VERSION);
      expect(t).not.toBe(s);
    });

    test('嵌套对象键序漂移不影响产出（stableStringify 递归排序）', () => {
      const a = { ...v1Doc(), body: { z: 1, a: { y: 2, b: [3, { d: 4, c: 5 }] } } };
      const b = { ...v1Doc(), body: { a: { b: [3, { c: 5, d: 4 }], y: 2 }, z: 1 } };
      expect(canonicalPayload(a, CURRENT_PAYLOAD_VERSION)).toBe(
        canonicalPayload(b, CURRENT_PAYLOAD_VERSION)
      );
    });

    test('数组顺序参与 hash（数组是有序结构，不能排序）', () => {
      const a = { ...v1Doc(), riskFactors: ['x', 'y'] };
      const b = { ...v1Doc(), riskFactors: ['y', 'x'] };
      expect(canonicalPayload(a, CURRENT_PAYLOAD_VERSION)).not.toBe(
        canonicalPayload(b, CURRENT_PAYLOAD_VERSION)
      );
    });
  });

  // ---------- HMAC 与链尾指针 ----------
  describe('computeHmac / 链尾指针管理', () => {
    test('配置了 HMAC_SECRET 时产出 64 位 hex 且确定性', () => {
      expect(isHmacConfigured()).toBe(true);
      const h = computeHmac('a'.repeat(64));
      expect(h).toMatch(/^[0-9a-f]{64}$/);
      expect(computeHmac('a'.repeat(64))).toBe(h);
    });

    test('不同 hash 产出不同 hmac', () => {
      expect(computeHmac('a'.repeat(64))).not.toBe(computeHmac('b'.repeat(64)));
    });

    test('getChainTail 首次从 DB 读、之后以内存为准', async () => {
      await resyncChainTail();
      const first = await getChainTail(AuditLog);
      const dbTail = await getLatestHash(AuditLog);
      expect(first).toBe(dbTail);

      // 推进链尾后，即使 DB 未变，getChainTail 也应返回内存值
      // （DB 落库存在异步延迟，以 DB 为准会重复读旧尾造成分叉）
      await advanceChainTail('f'.repeat(64));
      expect(await getChainTail(AuditLog)).toBe('f'.repeat(64));
    });

    test('rollbackChainTail 在链尾未被他人接续时回滚成功', async () => {
      await advanceChainTail('a'.repeat(64));
      expect(await rollbackChainTail('a'.repeat(64), 'b'.repeat(64))).toBe(true);
      expect(await getChainTail(AuditLog)).toBe('b'.repeat(64));
    });

    test('rollbackChainTail 在链尾已被接续时拒绝回滚（不可挽回的分叉）', async () => {
      await advanceChainTail('c'.repeat(64));
      // 期望的当前值与实际不符 → 说明已有后续记录接上，回滚会造成二次分叉
      expect(await rollbackChainTail('a'.repeat(64), 'b'.repeat(64))).toBe(false);
    });

    test('resyncChainTail 后重新从 DB 同步（部分落库成功的自愈入口）', async () => {
      await advanceChainTail('e'.repeat(64));
      await resyncChainTail();
      const tail = await getChainTail(AuditLog);
      expect(tail).toBe(await getLatestHash(AuditLog));
      expect(tail).not.toBe('e'.repeat(64));
    });

    afterAll(async () => {
      // 归还干净状态，避免影响同 worker 内后续测试文件
      await resyncChainTail();
    });
  });

  // ---------- 模型层：pre('save') 自动哈希链 ----------
  describe('AuditLog — pre(save) 自动哈希链', () => {
    test('create 后 hash/prevHash 已填充', async () => {
      const doc = await AuditLog.create({
        action: 'chain_test',
        category: 'system',
        username: 'chain_save',
        ip: '::1',
        path: '/api/test',
        statusCode: 200,
        success: true,
      });
      expect(doc.hash).toBeTruthy();
      expect(doc.hash).toMatch(/^[0-9a-f]{64}$/);
      // 首条 prevHash 可为 null 或指向既有链尾
      expect(doc.prevHash === null || typeof doc.prevHash === 'string').toBe(true);
    });

    test('连续写入：后一条 prevHash 指向前一条 hash', async () => {
      // 先取当前链尾，再写两条
      const first = await AuditLog.create({
        action: 'chain_seq1',
        category: 'system',
        username: 'chain_seq',
        ip: '::1',
        path: '/api/seq1',
        statusCode: 200,
        success: true,
      });
      const second = await AuditLog.create({
        action: 'chain_seq2',
        category: 'system',
        username: 'chain_seq',
        ip: '::1',
        path: '/api/seq2',
        statusCode: 200,
        success: true,
      });
      // 第二条的 prevHash 应等于第一条的 hash（getLatestHash 按 _id 降序取链尾）
      expect(second.prevHash).toBe(first.hash);
    });

    test('getLatestHash 返回最新一条 hash', async () => {
      // 并发安全断言：jest 多 worker 共享同一个内存 MongoDB，其它套件可能在
      // create 与查询之间并发写入新记录，导致「刚创建的记录」不再是链尾（竞态误报）。
      // 因此改为带重试地验证函数契约：返回值恒等于按 _id 降序最新记录的 hash。
      let matched = false;
      for (let i = 0; i < 3 && !matched; i += 1) {
        await AuditLog.create({
          action: 'chain_latest',
          category: 'system',
          username: 'chain_latest',
          ip: '::1',
          path: '/api/latest',
          statusCode: 200,
          success: true,
        });
        const latest = await AuditLog.findOne({}, { hash: 1 }).sort({ _id: -1 }).lean();
        const got = await getLatestHash(AuditLog);
        matched = !!latest && got === latest.hash;
      }
      expect(matched).toBe(true);
    });
  });

  // ---------- 防篡改：append-only 钩子 ----------
  describe('append-only 防篡改钩子', () => {
    test('updateOne 被拒绝', async () => {
      const doc = await AuditLog.create({
        action: 'append_upd',
        category: 'system',
        username: 'append_upd',
        ip: '::1',
        path: '/api/upd',
        statusCode: 200,
        success: true,
      });
      await expect(
        AuditLog.updateOne({ _id: doc._id }, { $set: { success: false } })
      ).rejects.toThrow(/append-only|禁止/);
    });

    test('deleteMany 被拒绝', async () => {
      await AuditLog.create({
        action: 'append_del',
        category: 'system',
        username: 'append_del',
        ip: '::1',
        path: '/api/del',
        statusCode: 200,
        success: true,
      });
      await expect(AuditLog.deleteMany({ username: 'append_del' })).rejects.toThrow(
        /append-only|禁止/
      );
    });

    test('findOneAndUpdate 被拒绝', async () => {
      const doc = await AuditLog.create({
        action: 'append_fau',
        category: 'system',
        username: 'append_fau',
        ip: '::1',
        path: '/api/fau',
        statusCode: 200,
        success: true,
      });
      await expect(
        AuditLog.findOneAndUpdate({ _id: doc._id }, { action: 'tampered' })
      ).rejects.toThrow(/append-only|禁止/);
    });

    test('{bypassAppendOnly:true} 可放行清理', async () => {
      await AuditLog.create({
        action: 'append_bypass',
        category: 'system',
        username: 'append_bypass',
        ip: '::1',
        path: '/api/bypass',
        statusCode: 200,
        success: true,
      });
      // 不抛错即视为放行
      await AuditLog.deleteMany({ username: 'append_bypass' }, { bypassAppendOnly: true });
      const cnt = await AuditLog.countDocuments({ username: 'append_bypass' });
      expect(cnt).toBe(0);
    });
  });

  // ---------- 密钥保护：hmac 不得随响应外泄 ----------
  describe('RESPONSE_EXCLUDE — 阻断 HMAC 离线爆破通道', () => {
    test('投影常量排除 hmac 与敏感入参字段', () => {
      const projection = AuditLog.RESPONSE_EXCLUDE;
      expect(typeof projection).toBe('string');
      const missing = ['-hmac', '-body', '-params', '-query'].filter(
        (f) => !projection.split(/\s+/).includes(f)
      );
      expect(missing).toEqual([]);
    });

    test('经该投影查询的文档不含 hmac，但仍保留 hash/prevHash', async () => {
      // 同时暴露 (hash, hmac) 即构成明文—标签对，可离线穷举 HMAC_SECRET；
      // 因此 hmac 必须缺席，而 hash/prevHash 单独暴露不泄露密钥（SHA-256 无密钥参与）
      const created = await AuditLog.create({
        action: 'chain_noleak',
        category: 'system',
        username: 'chain_noleak',
        ip: '::1',
        path: '/api/noleak',
        statusCode: 200,
        success: true,
      });
      // 前置确认：库内确实写入了 hmac，否则本用例会因「本来就没有」而假绿
      const raw = await AuditLog.findById(created._id).lean();
      expect(typeof raw.hmac).toBe('string');
      expect(raw.hmac.length).toBeGreaterThan(0);

      const exposed = await AuditLog.findById(created._id).select(AuditLog.RESPONSE_EXCLUDE).lean();
      expect(exposed.hmac).toBeUndefined();
      expect(exposed.hash).toBe(raw.hash);
      expect(exposed.prevHash).toBe(raw.prevHash);
    });
  });
});
