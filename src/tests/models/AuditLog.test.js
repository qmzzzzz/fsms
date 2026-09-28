/**
 * AuditLog 模型测试：脱敏递归性、风险评估准确性、method 取值全集与越枚举降级
 */

const mongoose = require('mongoose');

describe('AuditLog 模型静态方法', () => {
  let AuditLog;

  beforeAll(async () => {
    AuditLog = require('../../models/AuditLog');
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
  });

  afterEach(async () => {
    // append-only 钩子会拒绝 deleteMany，测试清理需通过 bypassAppendOnly 绕过
    await AuditLog.deleteMany(
      { username: /^sanitize_|^risk_|^method_/ },
      { bypassAppendOnly: true }
    );
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  const makeReq = (overrides = {}) => ({
    ip: '::1',
    method: 'PUT',
    originalUrl: '/api/auth/password',
    params: {},
    query: {},
    body: {},
    get: (h) => (h === 'user-agent' ? 'jest' : undefined),
    ...overrides,
  });

  describe('recordSensitiveAction — body 递归脱敏', () => {
    test('嵌套对象与数组中的敏感字段一并脱敏', async () => {
      const req = makeReq({
        body: {
          currentPassword: 'a',
          profile: { token: 'secret-token', nested: { password: 'p' } },
          list: [{ refreshToken: 'rt' }, { safe: 'keep' }],
        },
      });
      const doc = await AuditLog.recordSensitiveAction(
        null,
        'sanitize_user',
        'change_password',
        'auth',
        req,
        { statusCode: 200 },
        5
      );

      expect(doc.body.currentPassword).toBe('***');
      // 关键回归点：此前仅遍历第一层，嵌套层级明文落库
      expect(doc.body.profile.token).toBe('***');
      expect(doc.body.profile.nested.password).toBe('***');
      expect(doc.body.list[0].refreshToken).toBe('***');
      expect(doc.body.list[1].safe).toBe('keep');
    });

    test('非敏感字段与原始类型保持不变', async () => {
      const req = makeReq({ body: { realName: '张三', age: 30, active: true, tags: ['a', 'b'] } });
      const doc = await AuditLog.recordSensitiveAction(
        null,
        'sanitize_user',
        'user_update',
        'user',
        req,
        { statusCode: 200 },
        5
      );
      expect(doc.body.realName).toBe('张三');
      expect(doc.body.age).toBe(30);
      expect(doc.body.active).toBe(true);
      expect(doc.body.tags).toEqual(['a', 'b']);
    });

    test('超深嵌套被截断而非抛栈溢出', async () => {
      // 叶子口令埋在第 12 层，远超 MAX_SANITIZE_DEPTH(6)
      let deep = { password: 'x' };
      for (let i = 0; i < 12; i++) deep = { level: deep };
      const req = makeReq({ body: deep });
      const doc = await AuditLog.recordSensitiveAction(
        null,
        'sanitize_user',
        'user_update',
        'user',
        req,
        { statusCode: 200 },
        5
      );
      expect(doc).toBeTruthy();
      // 「截断」的判据必须是能看出截断发生了，且明文没漏：
      // 只断 doc truthy 时，把深度超限分支改成原样返回（明文入库）也照样绿。
      // 实测：第 6 层起被替换为 '[深度超限]'，password 叶子不会出现在结果里。
      const serialized = JSON.stringify(doc.body);
      expect(serialized).toContain('[深度超限]');
      expect(serialized).not.toContain('password');
      // 前 6 层必须原样保留（截断不等于整段丢弃）
      expect(doc.body.level.level.level.level.level).toBeDefined();
    });
  });

  describe('recordSensitiveAction — 风险评估', () => {
    test('无代理的普通成功操作为 low（修复 proxy_detected 永假命中）', async () => {
      const doc = await AuditLog.recordSensitiveAction(
        null,
        'risk_user',
        'user_update',
        'user',
        makeReq(),
        { statusCode: 200 },
        5
      );
      expect(doc.riskFactors).toEqual([]);
      expect(doc.riskLevel).toBe('low');
    });

    test('单级代理（X-Forwarded-For 仅一个地址）不计入风险', async () => {
      const req = makeReq({
        get: (h) =>
          h === 'x-forwarded-for' ? '203.0.113.9' : h === 'user-agent' ? 'jest' : undefined,
      });
      const doc = await AuditLog.recordSensitiveAction(
        null,
        'risk_user',
        'user_update',
        'user',
        req,
        { statusCode: 200 },
        5
      );
      expect(doc.riskFactors).toEqual([]);
      expect(doc.riskLevel).toBe('low');
    });

    test('多级代理链被标记 multi_hop_proxy', async () => {
      const req = makeReq({
        get: (h) =>
          h === 'x-forwarded-for'
            ? '203.0.113.9, 198.51.100.7'
            : h === 'user-agent'
              ? 'jest'
              : undefined,
      });
      const doc = await AuditLog.recordSensitiveAction(
        null,
        'risk_user',
        'user_update',
        'user',
        req,
        { statusCode: 200 },
        5
      );
      expect(doc.riskFactors).toContain('multi_hop_proxy');
      expect(doc.riskLevel).toBe('medium');
    });

    test('删除操作计入 delete_operation', async () => {
      const doc = await AuditLog.recordSensitiveAction(
        null,
        'risk_user',
        'user_delete',
        'user',
        makeReq(),
        { statusCode: 200 },
        5
      );
      expect(doc.riskFactors).toContain('delete_operation');
      expect(doc.riskLevel).toBe('medium');
    });

    test('失败的批量删除累积为 high', async () => {
      const doc = await AuditLog.recordSensitiveAction(
        null,
        'risk_user',
        'user_batch_delete',
        'user',
        makeReq(),
        { statusCode: 500 },
        5
      );
      expect(doc.riskFactors).toEqual(
        expect.arrayContaining(['delete_operation', 'batch_operation', 'error_response'])
      );
      expect(doc.riskLevel).toBe('high');
    });

    test('path 使用完整 originalUrl 而非被剥离的 req.path', async () => {
      const req = makeReq({ originalUrl: '/api/auth/password?x=1', path: '/password' });
      const doc = await AuditLog.recordSensitiveAction(
        null,
        'risk_user',
        'change_password',
        'auth',
        req,
        { statusCode: 200 },
        5
      );
      expect(doc.path).toBe('/api/auth/password');
    });
  });

  describe('索引声明', () => {
    test('不存在被复合索引前缀覆盖的冗余单字段索引', () => {
      const signatures = AuditLog.schema.indexes().map(([key]) => Object.keys(key).join('|'));
      // 这些单字段索引应已被 {字段, timestamp:-1} 复合索引取代
      for (const redundant of [
        'action',
        'category',
        'userId',
        'statusCode',
        'success',
        'ip',
        'riskLevel',
      ]) {
        expect(signatures).not.toContain(redundant);
      }
    });

    test('关键查询维度均有 timestamp 降序复合索引', () => {
      const signatures = AuditLog.schema.indexes().map(([key]) =>
        Object.entries(key)
          .map(([k, v]) => `${k}:${v}`)
          .join('|')
      );
      for (const expected of [
        'userId:1|timestamp:-1',
        'category:1|timestamp:-1',
        'action:1|timestamp:-1',
        'riskLevel:1|timestamp:-1',
        'success:1|timestamp:-1',
        'ip:1|timestamp:-1',
        'category:1|action:1|timestamp:-1',
      ]) {
        expect(signatures).toContain(expected);
      }
    });

    test('TTL 索引保留可配留存期（与 constants/retention 单一声明一致）', () => {
      const ttl = AuditLog.schema
        .indexes()
        .find(([, opts]) => opts && opts.expireAfterSeconds !== undefined);
      expect(ttl).toBeTruthy();
      // P3-46：不再在测试里复刻解析逻辑（原为 `parseInt(...) || 180`，
      // 与模型侧的钳制口径不同，配置为 1 时测试期望 1 天而模型实为 90 天）。
      // 改为直接比对单一声明，口径只有一处
      const { RETENTION_SECONDS, MIN_RETENTION_DAYS } = require('../../constants/retention');
      expect(ttl[1].expireAfterSeconds).toBe(RETENTION_SECONDS);
      // 无论环境变量如何取值，TTL 都不得低于合规下限
      expect(ttl[1].expireAfterSeconds).toBeGreaterThanOrEqual(MIN_RETENTION_DAYS * 24 * 60 * 60);
      expect(ttl[0]).toEqual({ timestamp: -1 });
    });
  });

  /**
   * method 维：取值全集 + 「越枚举怎么办」
   *
   * 这一维原先只在模型里写死 5 个动词，而**写入方交出来的方法名不受这 5 个约束**：
   * Express 把 HEAD 路由到 GET 处理器，全局审计中间件与 authenticate 又都排在路由之前，
   * 所以"带 token 的 HEAD"是常态流量（监控 curl -I、探测脚本、浏览器预取）。
   * 方法名落在枚举外时失败的是**整条文档**（Mongoose 对 enum 外取值报 ValidationError），
   * 而两条落库路径都不说"是 method 越枚举"：
   *   - 直写 AuditLog.record()：错误进 catch，只留一行 error 日志 + audit_write_failed 指标，
   *     ip_range_denied（riskLevel=high）这类事件在留存里凭空消失；
   *   - 缓冲路径 auditBuffer 的 insertMany({ordered:false})：该文档被当"毒文档"重试数轮后丢弃，
   *     与真正的外部畸形文档同形，事后无法区分。
   * 修复的判据因此是两条而不是第一条：**枚举要覆盖真实流量**（HEAD/OPTIONS 进枚举，
   * 保住"这次探测是 HEAD"这一维），**越枚举要降级而非丢行**（setter 抹成未设置，整条保住）。
   * 取舍写明：宁可少一维，不可丢一行——少一维仍可由 path/ip/action 定位同一次请求，
   * 丢一行是不可逆的取证缺口。
   */
  describe('method 枚举：宁可少一维，不可丢一行', () => {
    const { AUDIT_HTTP_METHODS, AUDIT_RISK_LEVELS } = require('../../constants/audit');

    const entry = (method, username) => ({
      action: 'ip_range_denied',
      category: 'security',
      username,
      method,
      path: '/api/auth/me',
      ip: '::ffff:127.0.0.1',
      success: false,
      riskLevel: 'high',
    });

    const readOwnRow = async (username) => AuditLog.findOne({ username }).lean();

    test('HEAD / OPTIONS 必须在枚举内，且逐字入库（不是被抹空后落库）', async () => {
      for (const method of ['HEAD', 'OPTIONS']) {
        const doc = await AuditLog.record(entry(method, `method_${method.toLowerCase()}`));
        // record() 落库失败时吞错返回 null——这正是缺陷"静默"的形态
        expect(doc).not.toBeNull();
        expect(doc.method).toBe(method);
        const row = await readOwnRow(`method_${method.toLowerCase()}`);
        expect(row?.method).toBe(method);
      }
    });

    test('反向对照：GET 照常落库（证明上一条不是因为"什么都不校验"而白过）', async () => {
      const doc = await AuditLog.record(entry('GET', 'method_get_control'));
      expect(doc).not.toBeNull();
      expect(doc.method).toBe('GET');
      expect((await readOwnRow('method_get_control'))?.method).toBe('GET');
    });

    test('越枚举的动词（TRACE/CONNECT/自定义/空串）必须降级为「不记 method」，整条记录保住', async () => {
      // Node 的 HTTP 解析器不限制方法名，TRACE/CONNECT 与任意自定义动词都会走到审计层。
      for (const method of ['TRACE', 'CONNECT', 'ZZ-PROBE', '']) {
        const username = `method_odd_${method.replace(/[^A-Za-z]/g, 'x') || 'empty'}`;
        const doc = await AuditLog.record(entry(method, username));
        expect({ method, doc: doc !== null }).toEqual({ method, doc: true });
        expect(doc.method).toBeUndefined();
        // 落库形态：字段整个不存在，而不是空串（空串在查询侧会与"未记录"混同）
        const row = await readOwnRow(username);
        expect(row).toBeTruthy();
        expect('method' in row).toBe(false);
      }
    });

    test('缓冲路径 insertMany 同样受保护：混入越枚举文档时三条全部入库且无错', async () => {
      // 这条才是本缺陷的真实落库形态（全局审计中间件走 auditBuffer，不是 record()）。
      // 未修复时 insertMany 会抛聚合错误、HEAD 那条最终被丢弃。
      const docs = await AuditLog.insertMany([
        entry('HEAD', 'method_buf_head'),
        entry('TRACE', 'method_buf_trace'),
        entry('POST', 'method_buf_post'),
      ]);
      expect(docs).toHaveLength(3);
      const rows = await AuditLog.find({ username: /^method_buf_/ }).lean();
      const byUser = Object.fromEntries(rows.map((r) => [r.username, r.method]));
      expect(Object.keys(byUser).sort()).toEqual(
        ['method_buf_head', 'method_buf_post', 'method_buf_trace'].sort()
      );
      expect(byUser.method_buf_head).toBe('HEAD');
      expect(byUser.method_buf_post).toBe('POST');
      expect(byUser.method_buf_trace).toBeUndefined();
    });

    test('单一事实来源：schema 的 enum 就是 constants/audit.js 那份，且两处写入点不再私抄', () => {
      const fs = require('fs');
      const path = require('path');
      // 与 AUDIT_CATEGORIES 同一口径（模型头注释自陈：漂移会造成静默丢弃）
      expect(AuditLog.schema.path('method').enumValues).toEqual(AUDIT_HTTP_METHODS);
      expect(AUDIT_HTTP_METHODS).toEqual(expect.arrayContaining(['HEAD', 'OPTIONS']));

      const PRIVATE_LIST = "'GET', 'POST', 'PUT', 'DELETE', 'PATCH'";
      const root = path.join(__dirname, '..', '..', '..');
      for (const rel of ['src/middleware/security.js', 'src/middleware/protocolCompliance.js']) {
        const text = fs.readFileSync(path.join(root, rel), 'utf8');
        expect({ file: rel, privateList: text.includes(PRIVATE_LIST) }).toEqual({
          file: rel,
          privateList: false,
        });
      }
      // 判据自证：私抄回来必须被上一条抓到（否则那是个恒真的文本闸）
      expect(`x: [${PRIVATE_LIST}].includes(req.method)`.includes(PRIVATE_LIST)).toBe(true);

      // riskLevel 同一口径（2026-09-25 补齐）：模型此前私抄 `['low','medium','high','critical']`，
      // 于是本文件头注释宣称的「单一事实来源」对这一维其实不成立。漂移后果与 method 那次同形：
      // 给常量加一档后，查询/导出侧白名单放行、落库却被 ValidationError 拒，
      // 缓冲路径把整行当毒文档重试数轮后丢弃，既不报错也不告警。
      expect(AuditLog.schema.path('riskLevel').enumValues).toEqual(AUDIT_RISK_LEVELS);
      const RISK_PRIVATE_LIST = "'low', 'medium', 'high', 'critical'";
      const modelSrc = fs.readFileSync(path.join(root, 'src/models/AuditLog.js'), 'utf8');
      expect(modelSrc.includes(RISK_PRIVATE_LIST)).toBe(false);
      // 同上：文本闸必须能抓到私抄，否则这条是个恒绿的摆设
      expect(`enum: [${RISK_PRIVATE_LIST}]`.includes(RISK_PRIVATE_LIST)).toBe(true);
    });
  });
});
