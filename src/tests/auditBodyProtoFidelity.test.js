/**
 * 审计副本必须与真实请求体同形：`__proto__` 这类 own 键不得在脱敏环节消失
 *
 * `{"__proto__": ...}` 是攻击探针的常见形态（express.json 与 JSON.parse 都会造出
 * 真正的 own 键）。此前为控制字符注入做了 stripControlCharsDeep 保键加固，
 * 但**下一环** sanitizeAuditBody 用的是 `cleaned[key] = value` —— 赋 `__proto__`
 * 走的是 Object.prototype 的 setter，键被整个丢弃：审计副本里连"这个键存在过"
 * 都没留下，而这条链路存在的理由恰恰是"事后能还原请求形状"。
 *
 * 本文件钉三件事：
 *   ① 脱敏后 `__proto__` 仍是 own 键、值原样保留，且敏感键照样打码；
 *   ② 全局原型没被污染（这才是"绕开 setter"的真正目的，不能只保住键）；
 *   ③ 两条"同口径"路径（writeStatics 的 strip∘sanitize 与 security 中间件的
 *      sanitize∘strip）必须产出同一份文档——顺序不该改变取证结果。
 * 第 ④ 组实测数据库往返，把"落库后还能不能读回来"这一层的事实也记下来。
 */
const { sanitizeAuditBody } = require('../models/auditLogSanitizer');
const { stripControlCharsDeep } = require('../utils/helpers');

describe('审计副本同形：__proto__ 等 own 键不得被脱敏环节吞掉', () => {
  const PROBE = 'zzqoder_proto_probe_value';

  const rawBody = () =>
    // 必须走 JSON.parse：对象字面量里的 __proto__ 是设置原型，不是 own 键；
    // express.json / body-parser 产出的正是 JSON.parse 这种 own 键形态。
    JSON.parse(`{"__proto__":"${PROBE}","password":"P@ss1#zzqoder","normal":"kept"}`);

  describe('① 脱敏结果仍含该 own 键', () => {
    test('__proto__ 键与值都保留，敏感键照样打码', () => {
      const out = sanitizeAuditBody(rawBody());

      expect(Object.prototype.hasOwnProperty.call(out, '__proto__')).toBe(true);
      expect(Object.keys(out)).toContain('__proto__');
      expect(out.__proto__).toBe(PROBE);
      expect(out.password).toBe('***');
      expect(out.normal).toBe('kept');
    });

    test('嵌套层同样保留（递归路径上每一层都走同一个赋值点）', () => {
      const nested = JSON.parse(`{"a":{"b":{"__proto__":"${PROBE}"}}}`);
      const out = sanitizeAuditBody(nested);
      expect(Object.keys(out.a.b)).toEqual(['__proto__']);
    });
  });

  describe('② 全局原型不得被污染', () => {
    test('脱敏过程自身不改变 Object.prototype / Array.prototype', () => {
      const before = Object.getOwnPropertyNames(Object.prototype).join(',');
      sanitizeAuditBody(rawBody());
      sanitizeAuditBody(JSON.parse(`{"constructor":{"prototype":{"x":1}},"a":1}`));
      expect(Object.getOwnPropertyNames(Object.prototype).join(',')).toBe(before);
      expect({}[PROBE]).toBeUndefined();
      expect([][PROBE]).toBeUndefined();
    });
  });

  describe('③ 两条同口径路径必须产出同一文档', () => {
    test('strip∘sanitize 与 sanitize∘strip 结果逐键一致', () => {
      const raw = JSON.parse(
        `{"__proto__":"${PROBE}","token":"T-SECRET","weird":"a\\u0001b","n":{"code":"C"}}`
      );
      const a = stripControlCharsDeep(sanitizeAuditBody(raw));
      const b = sanitizeAuditBody(stripControlCharsDeep(raw));

      expect(Object.keys(a).sort()).toEqual(Object.keys(b).sort());
      expect(JSON.stringify(a)).toBe(JSON.stringify(b));
      // 反过空守卫：这条链路上确实有键存在，否则上面的相等是空集相等
      expect(Object.keys(a).length).toBe(4);
    });
  });

  describe('④ 落库往返（把事实记下来，而不是假设）', () => {
    const mongoose = require('mongoose');
    let AuditLog;

    beforeAll(async () => {
      if (mongoose.connection.readyState === 0) {
        await mongoose.connect(process.env.MONGODB_URI);
      }
      AuditLog = require('../models/AuditLog');
    });

    afterAll(async () => {
      if (mongoose.connection.readyState !== 0) {
        await mongoose.connection.close();
      }
    });

    test('链一致性：带 __proto__ 的请求体脱敏落库后，重算哈希必须仍对得上', async () => {
      const { verifyAuditChain } = require('../services/auditChainVerify');
      const action = `zzqoder_proto_${Date.now().toString(36)}`.replace(/[^a-z0-9_]/g, '');
      await AuditLog.create({
        action,
        category: 'security',
        username: 'zzqoder_auditor',
        method: 'POST',
        path: '/api/zzqoder-proto',
        ip: '203.0.113.1',
        success: true,
        body: sanitizeAuditBody(rawBody()),
      });
      // 直连集合读：绕开 mongoose 的 schema cast，只看存储层实际存了什么
      const raw = await AuditLog.collection.findOne({ action });
      const storedKeys = Object.keys(raw.body || {});

      // 签名在 pre('save') 里取 this.toObject()，落库取的是 cast 后的文档：
      // 若脱敏结果保留了某个键而 cast 把它丢掉，重算出的规范 JSON 就与入库哈希不一致，
      // 核验会报**假断裂**（把"防篡改"变成"防自己"）。这条断言就是那道闸。
      const report = await verifyAuditChain(AuditLog, { filter: { action }, maxRecords: 10 });
      await AuditLog.collection.deleteMany({ action });

      // 先判链：签名取的是 pre('save') 里的 this.toObject()，落库取的是 cast 后的文档。
      // 两者形状不一致就会在核验时重算出不同规范 JSON → **假断裂**。这条是那道闸。
      expect(report.breaks).toBe(0);
      // 再记下本次改动实测到的存储层事实：mongoose 的 Mixed cast 仍会丢掉 __proto__ 键，
      // 所以"脱敏同形"目前只到函数边界为止，没到取证库为止。
      // 若哪天写入层做了键转义（或 cast 不再丢键），这条会转红——那是好消息，
      // 届时把它改成 toContain，别删。
      expect(storedKeys).not.toContain('__proto__');
    });
  });
});
