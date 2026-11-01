'use strict';

/**
 * 画像字段的写入面判据：三个口令派生字段必须在登录时算好、随既有蜜罐审计行的 body 落库。
 *
 * 为什么这一半必须单独有闸：ADR-013 P2 的「零新写入面」指的是零新集合，不是零字段。
 * 派生字段只要漏接一处，画像那边就永远看到 credentialStemHits = 0——而「词干命中为零」
 * 在本仓是有语义的（共享出口的排除判据要用它），所以漏接不是缺字段，是判据反向失效：
 * 真撞库的来源会被当成「办公室输错口令」放过。所以这里既钉「两个入口都带了」，
 * 也钉「没带时不伪造一个值」。
 *
 * 两半分工：静态半钉接线（login.js 的两次调用必须传 credentialShape），行为半钉落库
 * （两个 watch 模块收到 credentialShape 后 body 里必须真的有那三个键）。缺任一半都留下
 * 「函数签名改了但调用点没改」这种最常见的漏接形态。
 */
const fs = require('fs');
const path = require('path');
const mongoose = require('mongoose');

const ROOT = path.resolve(__dirname, '../../..');
const readSrc = (rel) => fs.readFileSync(path.join(ROOT, rel), 'utf8');

/** 剥掉行注释与块注释，保留行号：本闸要能区分「真的传了」与「注释里写着传了」 */
const stripComments = (src) => {
  const out = [];
  let inBlock = false;
  for (const line of src.split(/\r?\n/)) {
    if (inBlock) {
      out.push('');
      if (line.includes('*/')) inBlock = false;
      continue;
    }
    const t = line.trimStart();
    if (t.startsWith('//') || t.startsWith('/*') || t.startsWith('*')) {
      if (t.startsWith('/*') && !t.includes('*/')) inBlock = true;
      out.push('');
      continue;
    }
    out.push(line);
  }
  return out.join('\n');
};

describe('画像派生字段的写入面：两个蜜罐入口都带、且落进既有 body', () => {
  test('静态：login.js 的两处蜜罐/哨兵调用都传了 credentialShape（注释不算）', () => {
    const code = stripComments(readSrc('src/services/authService/login.js'));
    const passes = code
      .split(/\r?\n/)
      .filter((line) => /credentialShape:/.test(line));
    expect(passes).toHaveLength(2); // 两个入口各一次：少一处 = 那类行永远缺派生字段
    for (const line of passes) {
      expect(line).toMatch(/credentialShape:\s*credentialShapeOf\(password\)/); // 传的是派生函数的结果，不是随手一个对象
    }
  });

  test('静态：两条 watch 入口把 credentialShape 放进既有 body，写入面不新增', () => {
    const canary = stripComments(readSrc('src/services/canaryWatch.js'));
    const honeypot = stripComments(readSrc('src/services/honeypotWatch.js'));
    expect(canary).toMatch(/body: credentialShape \? \{ canary, credentialShape \} : \{ canary \}/);
    expect(honeypot).toMatch(/body: credentialShape \? \{ honeypot, credentialShape \} : \{ honeypot \}/);
    // 写入面不新增：两个文件里 create 的**条数**是本轮改动前后不变的常量，加一处就红。
    // canaryWatch 只有幽灵名一处；honeypotWatch 三处（诱饵登录 / HTTP 陷阱探测 / WS 探测），
    // 后者是既有面，本轮一个字都没动。
    expect(canary.match(/AuditLog\.create\(/g)).toHaveLength(1);
    expect(honeypot.match(/AuditLog\.create\(/g)).toHaveLength(3);
  });

  describe('行为半：落库的 body 里真的有三个派生键，且没传时不伪造', () => {
    const stamp = ('spp' + Date.now()).replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);
    let AuditLog;
    let canaryWatch;
    let honeypotWatch;
    let securityAlert;

    const ctxOf = (ip) => ({
      ip,
      userAgent: 'test-agent',
      fingerprint: 'fp-shape',
      method: 'POST',
      path: '/api/auth/login',
      req: { headers: { 'user-agent': 'test-agent' }, ip, connection: {} },
    });

    beforeAll(async () => {
      if (mongoose.connection.readyState === 0) {
        await mongoose.connect(process.env.MONGODB_URI);
      }
      require('../../models/User');
      require('../../models/TokenBlacklist');
      AuditLog = require('../../models/AuditLog');
      canaryWatch = require('../../services/canaryWatch');
      honeypotWatch = require('../../services/honeypotWatch');
      securityAlert = require('../../services/securityAlert');
    });

    afterAll(async () => {
      const coll = mongoose.connection.collection('auditlogs');
      await coll.deleteMany({ username: new RegExp(stamp) }).catch(() => {});
      await coll.deleteMany({ ip: /^198[.]51[.]100[.](21|22|31)$/ }).catch(() => {}); // 哨兵名是固定名单名，按来源 IP 清
    });

    beforeEach(() => {
      jest.spyOn(securityAlert, 'dispatchNotification').mockImplementation(() => {});
    });

    afterEach(() => {
      jest.restoreAllMocks();
    });

    test('哨兵入口：带 credentialShape ⇒ body 三键齐；不带 ⇒ body 里没有这个键', async () => {
      const { credentialShapeOf } = require('../../constants/credentialShape');
      await canaryWatch.recordGhostAttempt({
        username: 'root',
        ...ctxOf('198.51.100.21'),
        credentialShape: credentialShapeOf('Password123'),
      });
      await canaryWatch.recordGhostAttempt({
        username: 'guest',
        ...ctxOf('198.51.100.22'),
      });
      const withShape = await AuditLog.findOne({
        action: 'canary_username_attempt',
        ip: '198.51.100.21',
      }).lean();
      expect(Object.keys(withShape.body).sort()).toEqual(['canary', 'credentialShape']);
      expect(withShape.body.credentialShape).toMatchObject({
        credentialStemHits: 1,
        lengthBucket: '8-11',
        charsetClass: 'lud',
      });
      const bare = await AuditLog.findOne({
        action: 'canary_username_attempt',
        ip: '198.51.100.22',
      }).lean();
      expect(Object.keys(bare.body)).toEqual(['canary']); // 没传就是没传：不许补一份空画像
    });

    test('蜜罐入口：body 三键齐，且诱饵口令结构性命中词干表、body 无明文无哈希', async () => {
      const { credentialShapeOf } = require('../../constants/credentialShape');
      const lureName = stamp + 'trap';
      await honeypotWatch.recordHoneypotLogin({
        username: lureName,
        ...ctxOf('198.51.100.31'),
        credentialShape: credentialShapeOf('Password123'),
      });
      const doc = await AuditLog.findOne({
        action: 'honeypot_login',
        username: lureName,
      }).lean();
      expect(Object.keys(doc.body).sort()).toEqual(['credentialShape', 'honeypot']);
      expect(doc.body.credentialShape.credentialStemHits).toBe(1);
      const serialized = JSON.stringify(doc.body);
      expect(serialized).not.toContain('Password123');
      expect(serialized).not.toMatch(/[0-9a-f]{16,}/i);
    });
  });
});