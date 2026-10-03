/**
 * Top-8 前半：审计 username 过滤由「子串 + 大小写不敏感正则」改为「前缀 + collation 范围查询」
 *
 * 缺陷（实测确认）：原实现是 `{ $regex: escapeRegExp(u), $options: 'i' }`。
 *   1. **不锚定** ⇒ 子串匹配，`adm` 会误命中 `damin`（语义误报）；
 *   2. **大小写不敏感的正则无法使用索引**——MongoDB 的 `$regex` 实现不感知 collation，
 *      也无法利用大小写不敏感索引 ⇒ 任何索引都用不上。
 *   本机实测（6939 条真实数据）：子串 / 前缀锚定 / 带 `i` / 不带 `i` 四种形态
 *   **连等值查询都是 COLLSCAN**（集合上根本没有 username 索引）。
 *
 * 修复：`{ $gte: prefix, $lt: nextPrefix(prefix) }` ＋ `{username:1,timestamp:-1}` collation 索引。
 * 本机实测（2000 条 + 该索引）keysExamined：子串+i = 2000、前缀+i = 2000、
 * **前缀 + collation 范围 = 1144**。即"只把正则改成前缀、保留 `i`"收益**为零**，
 * collation 才是让前缀真正生效的开关。
 *
 * 【2026-09-30 修正：上界算法本身曾是错的，collation 把它放大成"查不到"】
 * 原上界 = 「末字符码点 +1」（'zzz' → 'zz{'）。它在二进制比较下成立，但本查询
 * **必须**挂 collation，而 ICU 排序不是码点序——标点权重排在字母之前，于是
 * `'pfx{' < 'pfxz'`，区间 `[$gte 'pfxz', $lt 'pfx{')` 成为**空集**：
 * 以 z 结尾的用户名前缀**恒返回 0 条**（'Z'→'['、'9'→':' 同理）。
 * 实测：同一数据下 collation 命中 0 条、二进制命中 2 条。
 * 现改为追加最高码位哨兵 U+FFFF（ICU 给未分配码位的隐式权重高于一切已分配字符），
 * 已逐类实测与锚定正则 `^prefix` + `i` 一致（末字符 z / Z / 9 / _ / a / A / 中），
 * 且仍是单侧有界区间 ⇒ 索引不退化（keysExamined 与旧上界相同）。
 * 该缺陷原先只在 cursorTiebreakPagination 的夹具里以 ~1/10 概率显形（其用户名
 * 由 `tb${Date.now()}` 逐位映射而来，末位为 'z' 约 1/10），现在由 ④ 的确定性用例钉住。
 *
 * 可证伪性（每条都实测过会红）：
 *  - `usernamePrefixCondition` 退回 `$regex` ⇒ ①③ 红；
 *  - 索引的 `collation` 去掉 ⇒ ② 红；
 *  - service 里 `withCollation` 去掉 ⇒ ⑤（真跑 DB）红；
 *  - `auditExportService` 里 `withCollation` 去掉 ⇒ ⑥ 红（列表能搜到、导出搜不到）；
 *  - 上界退回「末字符码点 +1」⇒ ①（形状）与 ④ 的 z 前缀用例红。
 */

'use strict';

const fs = require('fs');
const path = require('path');
const mongoose = require('mongoose');
const AuditLog = require('../../models/AuditLog');
const User = require('../../models/User');
const {
  buildAuditQuery,
  usernamePrefixCondition,
  nextUsernamePrefixUpperBound,
} = require('../../utils/auditQuery');

const ROOT = path.join(__dirname, '../../..');
const TAG = `auc${Date.now().toString(36)}`;
const COLLATION = { locale: 'en', strength: 2 };

// 前缀都是 `${TAG}a`；四条覆盖：大小写变体 ×2、更长前缀、以及"子串会误命中、前缀不会"的反例
const NAMES = {
  upper: `${TAG}Admin`,
  lower: `${TAG}admin`,
  longer: `${TAG}administrator`,
  // 含子串 `${TAG}a` 但**不在开头** ⇒ 子串匹配会命中它，前缀匹配不会
  infix: `zz${TAG}a`,
  // 末字符为 z 的一组：钉住「上界用『末字符码点 +1』会在 ICU 下变成空区间」这条缺陷。
  // 旧实现下 `^${TAG}z` 恒返回 0 条——上界 `${TAG}{` 里的 '{' 是标点，ICU 下标点权重
  // 排在字母之前，于是 [$gte `${TAG}z`, $lt `${TAG}{`) 是空集。
  zDigit: `${TAG}z1`,
  zLower: `${TAG}zebra`,
  zRepeat: `${TAG}zz`,
};

const mkDoc = (username) => ({
  action: 'user_login',
  category: 'auth',
  username,
  ip: '10.9.9.9',
  method: 'POST',
  path: '/api/auth/login',
  success: true,
  riskLevel: 'low',
});

describe('Top-8 前半：username 前缀 + collation 范围查询', () => {
  describe('① 前缀上界（纯函数）', () => {
    test('上界 = 前缀 + 最高码位哨兵 U+FFFF（collation 下严格大于任何前缀扩展）', () => {
      expect(nextUsernamePrefixUpperBound('adm')).toBe('adm\uFFFF');
      expect(nextUsernamePrefixUpperBound('a')).toBe('a\uFFFF');
      // 末字符是 z **不**做特殊处理：旧实现把它「码点 +1」成 '{'，
      // 而 ICU 下标点排在字母之前 ⇒ 'pfx{' < 'pfxz' ⇒ 区间空集、恒返回 0 条。
      // 这条契约由下面 ④ 的真跑 DB 用例兜住，不再只断言字符串形状。
      expect(nextUsernamePrefixUpperBound('zzz')).toBe('zzz\uFFFF');
    });

    test('正则元字符原样保留（范围比较天然免疫正则注入，不再需要转义）', () => {
      expect(nextUsernamePrefixUpperBound('alice(.*')).toBe('alice(.*\uFFFF');
      expect(usernamePrefixCondition('alice(.*')).toEqual({
        $gte: 'alice(.*',
        $lt: 'alice(.*\uFFFF',
      });
    });

    test('哨兵与输入内容无关：已是最大码位的输入也照样追加（不丢后缀）', () => {
      expect(nextUsernamePrefixUpperBound('a\u{10FFFF}')).toBe('a\u{10FFFF}\uFFFF');
      expect(nextUsernamePrefixUpperBound('\u{10FFFF}')).toBe('\u{10FFFF}\uFFFF');
    });

    test('空串无上界（退化为单边 $gte，不产生 $lt: ""）', () => {
      expect(nextUsernamePrefixUpperBound('')).toBeNull();
      expect(usernamePrefixCondition('')).toEqual({ $gte: '' });
    });
  });

  describe('② 索引：存在、命名、且必须带 collation', () => {
    const entry = AuditLog.schema
      .indexes()
      .find(([keys]) => keys.username === 1 && keys.timestamp === -1);

    test('schema 声明了 {username:1,timestamp:-1}', () => {
      expect(entry).toBeDefined();
    });

    test('该索引带 collation（去掉它前缀范围就用不上索引）', () => {
      expect(entry[1].collation).toEqual(COLLATION);
      expect(entry[1].name).toBe('username_ci_timestamp');
    });

    test('防漂移：与 User.USERNAME_COLLATION（username_ci 唯一索引）同口径', () => {
      // 用户名在业务上是大小写不敏感的标识（User 侧判重已按此口径）。
      // 两处常量若漂移，审计搜索与用户判重就会对"Admin 是不是 admin"给出不同答案。
      expect(AuditLog.AUDIT_USERNAME_COLLATION).toEqual(COLLATION);
      expect(AuditLog.AUDIT_USERNAME_COLLATION).toEqual(User.USERNAME_COLLATION);
    });
  });

  describe('③ buildAuditQuery 回报 collation 标记', () => {
    test('带 username ⇒ usernamePrefix 为 true（下游据此挂 collation）', () => {
      const built = buildAuditQuery({ query: { username: `${TAG}a`, action: 'auth_login' } });
      expect(built.usernamePrefix).toBe(true);
      expect(built.query.username).toEqual({ $gte: `${TAG}a`, $lt: `${TAG}a\uFFFF` });
      // 不得退回正则
      expect(built.query.username.$regex).toBeUndefined();
      expect(built.query.username.$options).toBeUndefined();
    });

    test('不带 username ⇒ 标记为 false（带了会屏蔽其它不带 collation 的索引）', () => {
      const built = buildAuditQuery({ query: { action: 'auth_login' } });
      expect(built.usernamePrefix).toBe(false);
      expect(built.query.username).toBeUndefined();
    });
  });

  describe('④ 真跑 DB：collation 是正确性开关，不只是性能开关', () => {
    beforeAll(async () => {
      if (mongoose.connection.readyState === 0) {
        await mongoose.connect(process.env.MONGODB_URI);
      }
      await AuditLog.insertMany(Object.values(NAMES).map(mkDoc));
      await AuditLog.ensureIndexes();
    });

    afterAll(async () => {
      await AuditLog.deleteMany(
        { username: { $in: Object.values(NAMES) } },
        {
          bypassAppendOnly: true,
        }
      );
      if (mongoose.connection.readyState !== 0) await mongoose.connection.close();
    });

    const found = (docs) => docs.map((d) => d.username).sort();

    test('带 collation：大小写变体全部命中，且不再误命中子串（damin）', async () => {
      const cond = usernamePrefixCondition(`${TAG}a`);
      const docs = await AuditLog.find({ username: cond }).collation(COLLATION).select('username');
      expect(found(docs)).toEqual([NAMES.upper, NAMES.lower, NAMES.longer].sort());
      // 反例在数据里：子串匹配会命中它，前缀匹配不会
      expect(found(docs)).not.toContain(NAMES.infix);
    });

    test('不带 collation：漏掉首字母大写的 ADMIN 形态（默认二进制比较下它 < 前缀）', async () => {
      const cond = usernamePrefixCondition(`${TAG}a`);
      const docs = await AuditLog.find({ username: cond }).select('username');
      expect(found(docs)).toEqual([NAMES.lower, NAMES.longer].sort());
      expect(found(docs)).not.toContain(NAMES.upper);
    });

    test('子串语义确实已被取消（旧实现会命中 infix）', async () => {
      const docs = await AuditLog.find({
        username: { $regex: `${TAG}a`, $options: 'i' },
      }).select('username');
      // 旧形态仍能命中 infix——这正是被替换掉的行为，保留它作为"确实变了"的证据
      expect(found(docs)).toContain(NAMES.infix);
    });

    // 2026-09-30：这条是本文件此前**没有**钉住的那一格。
    // 原上界「末字符码点 +1」在二进制比较下成立，但本查询必须挂 collation，
    // 而 ICU 排序不是码点序 ⇒ 末字符为 z 时上界 '{' 反而**小于**前缀，区间空集。
    // 缺陷由 cursorTiebreakPagination 暴露（其夹具用户名末位为 'z' 的概率约 1/10，
    // 表现为 ~1/10 的偶发红），这里把它变成**确定性**回归。
    test('末字符为 z 的前缀不得是空区间（旧上界在 ICU 下小于前缀本身）', async () => {
      const prefix = `${TAG}z`;
      const cond = usernamePrefixCondition(prefix);
      // 旧实现此处给出 `$lt: `${TAG}{`` ⇒ ICU 下区间为空 ⇒ 下面恒为 []
      expect(cond.$lt).toBe(`${prefix}\uFFFF`);
      const docs = await AuditLog.find({ username: cond }).collation(COLLATION).select('username');
      expect(found(docs)).toEqual([NAMES.zDigit, NAMES.zLower, NAMES.zRepeat].sort());
    });
  });

  describe('⑤ 写法门禁：列表与导出两条路径都必须按需挂 collation', () => {
    const read = (rel) =>
      fs
        .readFileSync(path.join(ROOT, rel), 'utf8')
        .split('\n')
        .filter((l) => !/^\s*(\/\/|\*|\/\*)/.test(l))
        .join('\n');

    test('auditQueryService：4 处查询点（汇总 aggregate + 两个取页 find + countDocuments）', () => {
      const src = read('src/services/auditQueryService.js');
      expect(src.match(/withCollation\(/g) || []).toHaveLength(4);
      // 2026-10-01 列表链预算（utils/queryBudget.js）：countDocuments 携带 maxTimeMS 选项，
      // collation 仍由 withCollation 在其上追加——两道闸各管一维。
      // prettier 会把这一串折行，断言用容折行正则而不是字面子串
      expect(src).toMatch(
        /withCollation\(\s*AuditLog\.countDocuments\(query,\s*listCountOptions\(\)\),\s*collation\s*\)/
      );
      expect(src).toContain('summarizeByRiskLevel(query, collation)');
      // 裸 countDocuments 不许复辟
      expect(src).not.toContain('await AuditLog.countDocuments(query);');
    });

    test('auditExportService：2 处查询点（countDocuments + 流式 find）', () => {
      const src = read('src/services/auditExportService.js');
      expect(src.match(/withCollation\(/g) || []).toHaveLength(2);
      expect(src).not.toContain('await AuditLog.countDocuments(query);');
    });

    test('两个 service 共用同一份 withCollation（不许各写一份后漂移）', () => {
      const defs = ['src/utils/auditQuery.js', 'src/services/auditQueryService.js'].map(
        (f) => (read(f).match(/const withCollation\s*=/g) || []).length
      );
      expect(defs[0]).toBe(1);
      expect(defs[1]).toBe(0); // service 只能 import，不能自己再定义
    });

    test('collation 由 query 决定：仅 usernamePrefix 为真时才挂', () => {
      const src = read('src/services/auditQueryService.js');
      expect(src).toContain('built.usernamePrefix ? AuditLog.AUDIT_USERNAME_COLLATION : null');
      const ctrl = read('src/controllers/auditController.js');
      expect(ctrl).toContain('built.usernamePrefix ? AuditLog.AUDIT_USERNAME_COLLATION : null');
    });
  });
});
