/**
 * /api/security/audit-logs 的游标错误语义
 *
 * 要钉住的性质：一个「结构合法、但排序键值与本接口排序键类型不兼容」的游标，
 * 必须和其余三个游标列表接口一样返回 **400**（客户端据此回第一页重查），
 * 不能被服务内部的 catch-all 降级成 500 `AUDIT_QUERY_FAILED`。
 *
 * 为什么这类游标会真实出现：游标是不透明串，客户端无法预知它的 v 属于哪个接口。
 * 把设备列表（v 是 deviceCode 字符串）或告警列表的游标贴进审计接口，
 * 就会得到一个 decodeCursor 放行、castCursorValue('date') 拒绝的载荷。
 *
 * 500 的代价不是"文案不好看"，而是两件事：
 *  1. `logger.error('审计日志查询失败')` 被一个纯客户端输入触发 ⇒ 告警噪声；
 *  2. 前端无法区分「游标作废，回首页」与「服务端故障，重试」⇒ 前者被当成后者会死循环重试。
 */

const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

const encode = (payload) => Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');

describe('审计日志游标的 400/500 分界', () => {
  let app;
  let token;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    const User = require('../../models/User');
    const Role = require('../../models/Role');
    const Permission = require('../../models/Permission');
    const AuditLog = require('../../models/AuditLog');

    // 幂等播种：code 有 unique 索引，并行套件也会播同一条
    const auditPerm = await Permission.findOneAndUpdate(
      { code: 'security:audit' },
      {
        $setOnInsert: { name: '审计日志', code: 'security:audit', type: 'api', module: 'security' },
      },
      { upsert: true, new: true }
    );
    const role = await Role.findOneAndUpdate(
      { code: 'SUPER_ADMIN_CURSOR_SEMANTICS' },
      {
        $setOnInsert: {
          name: '超级管理员_游标语义测试',
          code: 'SUPER_ADMIN_CURSOR_SEMANTICS',
          level: 10,
          isBuiltIn: true,
          permissions: [auditPerm._id],
        },
      },
      { upsert: true, new: true }
    );
    const admin = await User.findOneAndUpdate(
      { username: 'cursor_sem_admin' },
      {
        $setOnInsert: {
          username: 'cursor_sem_admin',
          email: 'cursor_sem_admin@example.com',
          password: 'Test@1234567',
          roles: [role._id],
        },
      },
      { upsert: true, new: true }
    );
    token = jwt.sign(
      {
        userId: String(admin._id),
        username: admin.username,
        tokenVersion: admin.tokenVersion ?? 0,
      },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    await AuditLog.insertMany([
      {
        action: 'login_success',
        category: 'auth',
        username: 'cursor_sem_admin',
        userId: admin._id,
        ip: '127.0.0.1',
        success: true,
        riskLevel: 'low',
        method: 'POST',
        path: '/api/auth/login',
        timestamp: new Date('2026-06-01T10:00:00Z'),
      },
      {
        action: 'login_failed',
        category: 'auth',
        username: 'cursor_sem_admin',
        userId: admin._id,
        ip: '127.0.0.1',
        success: false,
        riskLevel: 'medium',
        method: 'POST',
        path: '/api/auth/login',
        timestamp: new Date('2026-06-02T10:00:00Z'),
      },
    ]);

    const { createApp } = require('../../app');
    app = createApp();
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  const query = (cursor) =>
    request(app)
      .get('/api/security/audit-logs')
      .query({ cursor })
      .set('Authorization', `Bearer ${token}`);

  test('前置事实：decodeCursor 会放行这种载荷（缺陷不在解码层，而在错误分层）', () => {
    const { decodeCursor } = require('../../utils/cursorPagination');
    const payload = { v: 'ZZZ', id: '0'.repeat(24) };
    expect(decodeCursor(encode(payload))).toEqual(payload);
  });

  test('v 不是日期：必须 400 且文案指向游标，不得是 500/AUDIT_QUERY_FAILED', async () => {
    const res = await query(encode({ v: 'ZZZ', id: '0'.repeat(24) }));
    expect(res.status).toBe(400);
    expect(res.body.success).toBe(false);
    expect(res.body.message).toContain('游标');
  });

  test('v 是数组：同样 400（标量收口之外的第二形态）', async () => {
    const res = await query(encode({ v: [1, 2], id: '0'.repeat(24) }));
    expect(res.status).toBe(400);
    expect(res.body.message).toContain('游标');
  });

  test('合法游标仍然可用：修复不能把这条路径一起 400 掉', async () => {
    const page = await request(app)
      .get('/api/security/audit-logs')
      .query({ limit: 1 })
      .set('Authorization', `Bearer ${token}`);
    expect(page.status).toBe(200);
    const docs = page.body.data.data;
    expect(docs).toHaveLength(1);

    const { encodeCursor } = require('../../utils/cursorPagination');
    const cursor = encodeCursor({ v: docs[0].timestamp, id: String(docs[0]._id) });
    const next = await query(cursor);
    expect(next.status).toBe(200);
    expect(next.body.data.meta.total).toBeNull();
    // 这里的判据不能假设库里只有我那两条夹具：全量并发时同一集合被其它套件追加，
    // 精确「剩 0 条」乃至「hasNext=false」都不成立（实测首版就红在剩 0 条）。
    // 确定性成立的是位置关系——续翻页必须严格排在锚点之后
    // （时间不晚于锚点、且不重复锚点自己）。
    const anchorAt = new Date(docs[0].timestamp).getTime();
    for (const row of next.body.data.data) {
      expect(new Date(row.timestamp).getTime()).toBeLessThanOrEqual(anchorAt);
      expect(String(row._id)).not.toBe(String(docs[0]._id));
    }
  });
});
