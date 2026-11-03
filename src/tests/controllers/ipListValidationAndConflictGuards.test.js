/**
 * ──────────────────────────────────────────────────────────────────────────
 * 本文件的定位（2026-09-20 补注，由变异审计批量补齐）
 *
 * 被测对象：ipListController 的校验 / 冲突 / 拒绝侧
 * 守护的不变式：全网段非超管必须 403 + critical 审计；黑白名单冲突必须 400；IP 格式与时长越界必须拒绝
 * 可证伪性：本轮未做变异实测
 *
 * 命名沿革：2026-09-20 由 `ipListBranches.test.js` 更名。旧名里的
 *   Coverage / Gap / Hardening / Branch 说的是「当初为什么写它」（补覆盖率基线），
 *   **不是它的价值判据**；它能否挡住回归，由变异实测回答，不由文件名回答。
 *   旧名保留在本行，便于既往审计报告的 `grep 旧文件名` 仍能定位到本文件。
 * 依据：`deliverables/AGENT工作总账与待办-2026-09-21.md`（§2.9 测试资产 / §6 方法；原编号 §6-AW/AX/AY/AZ/BA 已随原台账删除，无法逐条映射）
 * ──────────────────────────────────────────────────────────────────────────
 */

/**
 * ipListController 分支补齐
 *
 * 【行号说明】本文件早期版本按覆盖率基线标注 `L<行号>`，后续行号漂移已失效；
 * 现改为语义描述。
 *
 * 覆盖范围（securityDeep 已覆盖 CRUD 正向与全网段超管成功路径，这里补齐
 * 校验/冲突/拒绝侧）：
 *  - getIPList：路由校验链消费（?type= 非法值）
 *  - queryIPMatch：缺 IP / CIDR 网段不是合法查询单址
 *  - addIPEntry：IP 必填、type 枚举、格式非法、时长越界、
 *    全网段非超管 403 + critical 审计、加黑被白名单覆盖冲突 400
 *  - removeIPEntry：记录不存在 404、全网段非超管 403（删除侧对称约束）
 *
 * 集成风格：supertest + createApp + JWT 直签（对齐 securityDeep.test.js）。
 */

const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { randomPassword } = require('../helpers/buildLoginEnvelope');
const { waitFor } = require('../helpers/waitFor');

describe('ipListController 分支补齐', () => {
  let app;
  let IPBlacklist;
  let superToken; // 内置超管：造全网段条目与白名单前置
  let secToken; // 安全员（security:config，非超管）：校验/冲突/403 分支主角
  let secUserId;
  let secUserName;
  const stamp = `ipl${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);
  const PASSWORD = randomPassword();
  const createdIds = [];

  const signToken = (userId, username) =>
    jwt.sign({ userId, username, tokenVersion: 0 }, process.env.JWT_SECRET, { expiresIn: '24h' });

  /**
   * 取本操作员名下的越权审计记录。
   *
   * 两点必须说清，否则这条判据是假的：
   *  - AuditLog.record 是 fire-and-forget（控制器不 await），响应回来时落库可能还在路上，
   *    所以用 waitFor 轮询到该行真实出现；等不到就由 waitFor 抛超时错误——
   *    不做"等不到就跳过"，也不返回 null 让断言在别处含糊转红。
   *  - username 带 stamp，本套件之外没有同名人，因此查到的就是这次 403 留下的痕迹。
   *    再加 method 收窄：POST/DELETE 两条用例共用同一操作员，否则后者会读到前者。
   *    分片删除用例又各留一条 DELETE 审计（body.ip 不同），故调用方还必须按
   *    body.ip 再收窄一次——只按 method 轮询会被同套件里更早的拒绝记录冒充。
   */
  const findEscalationAudit = async (method, extraFilter = {}) => {
    const AuditLog = require('../../models/AuditLog');
    let doc = null;
    await waitFor(
      async () => {
        doc = await AuditLog.findOne({
          username: secUserName,
          action: 'privilege_escalation',
          method,
          ...extraFilter,
        })
          .sort({ _id: -1 })
          .lean();
        return !!doc;
      },
      { label: `越权审计落库（method=${method}, username=${secUserName}）` }
    );
    return doc;
  };

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    const User = require('../../models/User');
    const Role = require('../../models/Role');
    const Permission = require('../../models/Permission');
    IPBlacklist = require('../../models/IPBlacklist');

    const wildcardPerm = await Permission.findOneAndUpdate(
      { code: '*:*' },
      { $setOnInsert: { name: '全部权限', code: '*:*', type: 'api', module: 'system' } },
      { upsert: true, new: true }
    );
    let builtInSuper = await Role.findOne({ code: 'SUPER_ADMIN' });
    if (!builtInSuper) {
      builtInSuper = await Role.create({
        name: '超级管理员',
        code: 'SUPER_ADMIN',
        level: 10,
        permissions: [wildcardPerm._id],
      });
    }
    const superUser = await User.create({
      username: `iplsuper${stamp}`,
      email: `iplsuper${stamp}@example.com`,
      password: PASSWORD,
      roles: [builtInSuper._id],
    });
    superToken = signToken(String(superUser._id), superUser.username);

    // 安全员：持 security:config 可进 IP 名单接口，但非内置超管
    const configPerm = await Permission.findOneAndUpdate(
      { code: 'security:config' },
      {
        $setOnInsert: {
          name: '安全配置',
          code: 'security:config',
          type: 'api',
          module: 'security',
        },
      },
      { upsert: true, new: true }
    );
    const secRole = await Role.create({
      name: `安全员_${stamp}`,
      code: `SEC_OP_${stamp}`,
      level: 5,
      permissions: [configPerm._id],
    });
    const secUser = await User.create({
      username: `iplsec${stamp}`,
      email: `iplsec${stamp}@example.com`,
      password: PASSWORD,
      roles: [secRole._id],
    });
    secToken = signToken(String(secUser._id), secUser.username);
    secUserId = String(secUser._id);
    secUserName = secUser.username;

    // 白名单豁免本机回环段：后续用例创建全网段黑名单（0.0.0.0/0）后，
    // checkIPBlacklist 会拦截一切来源 IP（含 supertest 的本机请求），
    // 白名单优先级更高，挂 ipWhitelisted 后 API 才能继续触达控制器分支。
    // 直接经模型层落库（同步名单快照），不依赖 app 实例，且必须先于
    // 任何全网段黑名单条目存在。
    // durationMs=0（永久）不可省：救援路径判据要求覆盖操作者的白名单**永不过期**，
    // 缺省 1 小时的临时白不算救援路径（否则一小时后二次自锁）——本用例的 /0 前置会因此被拒。
    const loopbackWhite = await IPBlacklist.blockIP('127.0.0.0/8', {
      type: 'white',
      reason: '分支补齐-回环豁免前置',
      source: 'manual',
      durationMs: 0,
    });
    if (loopbackWhite?._id) createdIds.push(loopbackWhite._id);

    const { createApp } = require('../../app');
    app = createApp();
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      const User = require('../../models/User');
      const Role = require('../../models/Role');
      await User.deleteMany({ username: new RegExp(`^ipl(super|sec)${stamp}$`) }).catch(() => {});
      await Role.deleteMany({ code: new RegExp(`^SEC_OP_${stamp}$`) }).catch(() => {});
      // 清理本文件创建的名单条目（含超管造的全网段/白名单前置与回环豁免）
      await IPBlacklist.deleteMany({
        $or: [
          { ip: { $in: ['10.0.0.0/8', '0.0.0.0/0', '127.0.0.0/8'] } },
          { source: 'manual', reason: /分支补齐/ },
        ],
      }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  const superGet = (url) => request(app).get(url).set('Authorization', `Bearer ${superToken}`);
  const secPost = (url, body) =>
    request(app).post(url).set('Authorization', `Bearer ${secToken}`).send(body);
  const secDel = (url) => request(app).delete(url).set('Authorization', `Bearer ${secToken}`);

  test('GET ?type=非法值 → 路由校验链 400（校验结果必须被消费）', async () => {
    const res = await superGet('/api/security/ip-list?type=bogus').set(
      'Authorization',
      `Bearer ${superToken}`
    );
    expect(res.status).toBe(400);
    // 「校验结果必须被消费」的判据是明细透传（路由 400 与「校验被忽略后控制器兜底 400」同码）
    expect(res.body.errors.errorCode).toBe('VALIDATION_FAILED');
    expect(res.body.errors.fieldErrors[0].path).toBe('type');
  });

  test('GET /query 缺 IP 或传 CIDR 网段 → 400 仅接受单地址', async () => {
    const empty = await superGet('/api/security/ip-list/query?ip=');
    expect(empty.status).toBe(400);
    // 缺值必须点名 IP_SINGLE_REQUIRED：与「格式非法」是同状态码下的不同契约
    expect(empty.body.errors.errorCode).toBe('IP_SINGLE_REQUIRED');

    const cidr = await superGet('/api/security/ip-list/query?ip=10.0.0.0/8');
    expect(cidr.status).toBe(400);
    // 网段不是单址：同一错误码，证明 CIDR 被「单地址」这条规则挡下
    expect(cidr.body.errors.errorCode).toBe('IP_SINGLE_REQUIRED');
  });

  test('POST 空 IP → 400（必填校验）', async () => {
    const res = await secPost('/api/security/ip-list', { ip: '', type: 'black' });
    expect(res.status).toBe(400);
    expect(res.body.errors.errorCode).toBe('VALIDATION_FAILED');
    expect(res.body.errors.fieldErrors[0].path).toBe('ip');
  });

  test('POST type 非法 → 400（路由校验器先行拦截，控制器枚举双保险）', async () => {
    const res = await secPost('/api/security/ip-list', { ip: '203.0.113.50', type: 'grey' });
    expect(res.status).toBe(400);
    expect(res.body.errors.errorCode).toBe('VALIDATION_FAILED');
    expect(res.body.errors.fieldErrors[0].path).toBe('type');
  });

  test('POST 非法 IP 文本 → 400 IP_FORMAT_INVALID，拒绝入库死记录', async () => {
    const res = await secPost('/api/security/ip-list', { ip: '999.999.999.999', type: 'black' });
    expect(res.status).toBe(400);
    // 标题点名的错误码必须断言：否则把 IP_FORMAT_INVALID 换成别的 400 码不会红
    expect(res.body.errors.errorCode).toBe('IP_FORMAT_INVALID');
    // 「拒绝入库死记录」是行为声明，必须查库证伪（400 只说明响应，不说明没落库）
    const IPBlacklist = require('../../models/IPBlacklist');
    expect(await IPBlacklist.countDocuments({ ip: '999.999.999.999' })).toBe(0);
  });

  test('POST durationHours 越界 → 400（0 至 8760 小时）', async () => {
    const res = await secPost('/api/security/ip-list', {
      ip: '203.0.113.51',
      type: 'black',
      durationHours: -5,
    });
    expect(res.status).toBe(400);
    expect(res.body.errors.errorCode).toBe('VALIDATION_FAILED');
    expect(res.body.errors.fieldErrors[0].path).toBe('durationHours');
  });

  test('POST 全网段 0.0.0.0/0 by 非超管 → 403 + critical 越权审计', async () => {
    const res = await secPost('/api/security/ip-list', { ip: '0.0.0.0/0', type: 'black' });
    expect(res.status).toBe(403);
    // 错误码而非文案子串：别的 403 闸门（权限/范围）也能说出"仅超级管理员"，
    // 只断文案就会让"换了一道闸"的回归静默过关。
    expect(res.body.errors.errorCode).toBe('FULL_RANGE_FORBIDDEN');
    // 标题里的"critical 越权审计"是本用例的主要判据：这条记录是安全概览
    // criticalAlerts 与风险评分的高危来源之一，删掉写入或降级都不会影响 403。
    // 按 body.ip 精确认领：本文件另有「分片铺满」（128.0.0.0/1）的 POST 403 审核，只按
    // method 轮询在随机顺序下可能先命中它而误判本用例；与调用方注释同一口径。
    const audit = await findEscalationAudit('POST', { 'body.ip': '0.0.0.0/0' });
    expect(audit).not.toBeNull();
    expect({
      userId: String(audit.userId),
      category: audit.category,
      riskLevel: audit.riskLevel,
      riskFactors: audit.riskFactors,
      success: audit.success,
      path: audit.path,
      body: audit.body,
    }).toEqual({
      userId: secUserId,
      category: 'security',
      riskLevel: 'critical',
      riskFactors: ['full_range_cidr_attempt'],
      success: false,
      path: '/api/security/ip-list',
      body: { ip: '0.0.0.0/0', type: 'black' },
    });
    // B6（2026-11-03）：critical 未遂留痕必须带客户端地址——与同文件其余五处同形态。
    // 事后连"这次未遂从哪个地址来"都答不了的话，未遂审计只剩半条证据。
    expect(audit.ip).toBeTruthy();
    expect(audit.clientInfo).toBeTruthy();
    expect(audit.clientInfo.socketPeer).toBeTruthy();
  });

  test('POST 分片铺满地址族（两条 /1）→ 与 /0 同等收口，非超管 403', async () => {
    // 单条 0.0.0.0/1 只是半张网，可以正常加入；但第二条 /1 补齐后并集等价于
    // 0.0.0.0/0。只按单条 bits===0 判定的守卫会在这里静默放行。
    const first = await request(app)
      .post('/api/security/ip-list')
      .set('Authorization', `Bearer ${superToken}`)
      .send({
        ip: '0.0.0.0/1',
        type: 'white',
        reason: '分支补齐-分片前置',
        typedConfirm: '0.0.0.0/1',
      });
    expect(first.status).toBe(200);

    try {
      const res = await secPost('/api/security/ip-list', { ip: '128.0.0.0/1', type: 'white' });
      expect(res.status).toBe(403);
      expect(res.body.errors.errorCode).toBe('FULL_RANGE_FORBIDDEN');

      // 越权审计按 body.ip 精确认领：同一操作员上一条 POST 审计（/0 用例）还在库里，
      // 只按 method 轮询会立刻命中旧行，把「本次拒绝是否留痕」断成假绿。
      const AuditLog = require('../../models/AuditLog');
      let audit = null;
      await waitFor(
        async () => {
          audit = await AuditLog.findOne({
            username: secUserName,
            action: 'privilege_escalation',
            method: 'POST',
            'body.ip': '128.0.0.0/1',
          }).lean();
          return !!audit;
        },
        { label: '分片铺满地址族的越权审计落库' }
      );
      expect(audit.riskFactors).toEqual(['full_range_cidr_attempt']);
      expect(audit.riskLevel).toBe('critical');
    } finally {
      const id = first.body?.data?._id;
      if (id) {
        await request(app)
          .delete(`/api/security/ip-list/${id}`)
          .set('Authorization', `Bearer ${superToken}`);
      }
    }
  });

  test('B11 同一权限位的 ip-list 入口必须与 pool-ban 共享护栏：不许把自己封在外面', async () => {
    // 取证页的 pool-ban 有四道判据（并集/自伤/活跃流量/打字确认），而 ip-list 只有并集一条。
    // 同一个 security:config 权限位上的两个入口，判据必须一致——否则"封段会切断消防上报"
    // 这条结论在另一条路径上等于不存在（第 18 轮 controllers lane 实测 /16 直接 200）。
    // 判据针对**网段**：把调用者自己所在的 /24 加黑 = 把自己（和同事）封在门外。
    // 用回环网段是因为 supertest 里的客户端地址就是回环——这条用例要的是"网段罩住调用者"，
    // 用 203.0.113.0/24 那种"别人的网段"测不出自伤闸（实测：那样会 200）。
    const res = await secPost('/api/security/ip-list', {
      ip: '127.0.0.0/24',
      type: 'black',
      reason: '把自己封了',
      typedConfirm: '127.0.0.0/24',
    });
    expect(res.status).toBe(400);
    expect(res.body.errors.reason).toBe('operator_inside');
  });

  test('B11 并集铺满的**真实网段**不许绕过自伤判据（只有 /0 本身才是例外）', async () => {
    // 旧实现把 coveredFamilies.length > 0 当成"属于全网段口径"，于是**自身并非 /0** 的真实
    // 网段被整类排除在段护栏外：0.0.0.0/1 罩住一半 IPv4、含着调用者自己，却一路 200。
    // 判据应该是"这一条本身是不是 /0"，不是"并集是否铺满"——后者是并集判据的输入，不是豁免理由。
    const ids = [];
    try {
      const first = await request(app)
        .post('/api/security/ip-list')
        .set('Authorization', `Bearer ${superToken}`)
        .send({
          ip: '128.0.0.0/1',
          type: 'black',
          reason: '并集前置',
          typedConfirm: '128.0.0.0/1',
        });
      expect(first.status).toBe(200);
      ids.push(first.body?.data?._id);

      const res = await request(app)
        .post('/api/security/ip-list')
        .set('Authorization', `Bearer ${superToken}`)
        .send({ ip: '0.0.0.0/1', type: 'black', reason: '并集绕过', typedConfirm: '0.0.0.0/1' });
      expect(res.status).toBe(400);
      // 0.0.0.0/1 覆盖 127.0.0.1（supertest 的来源地址）⇒ 自伤判据必须命中
      expect(res.body.errors.reason).toBe('operator_inside');
    } finally {
      for (const id of ids.filter(Boolean)) {
        await request(app)
          .delete(`/api/security/ip-list/${id}`)
          .set('Authorization', `Bearer ${superToken}`);
      }
    }
  });

  test('B11 大段必须显式确认（≥256 个地址不许一句话封掉）', async () => {
    const res = await secPost('/api/security/ip-list', {
      ip: '198.51.100.0/24',
      type: 'black',
      reason: '大段',
    });
    expect(res.status).toBe(400);
    expect(res.body.errors.reason).toBe('typed_confirmation_required');
  });

  // ==================== B5 白名单段级护栏对称收口（2026-11-03） ====================
  describe('B5 白名单段级护栏对称收口', () => {
    /** 清理本组用例落库的条目（按 _id），防串场 */
    const cleanup = async (id) => {
      if (!id) return;
      await request(app)
        .delete(`/api/security/ip-list/${id}`)
        .set('Authorization', `Bearer ${superToken}`)
        .send();
    };

    test('大段白名单（/1）无确认 ⇒ 400 typed_confirmation_required（原来整段豁免）', async () => {
      // 用 IPv6 /1：不与既有 v4 白名单前置（127.0.0.0/8 回环豁免）发生并集/覆盖关系，
      // 保证 400 来自段级确认判据而不是 guardFullRangeCIDR 的并集收口
      const res = await secPost('/api/security/ip-list', {
        ip: '::/1',
        type: 'white',
        reason: '分支补齐-白名单段确认',
      });
      expect(res.status).toBe(400);
      expect(res.body.errors.reason).toBe('typed_confirmation_required');
      expect(res.body.errors.expected).toBe('::/1'); // 与全网段分支同口径：回带归一化确认串
    });

    test('带确认 ⇒ 200 落库，且审计行 body 带 riskFactors=[large_segment_whitelist]', async () => {
      const AuditLog = require('../../models/AuditLog');
      const res = await secPost('/api/security/ip-list', {
        ip: '::/1',
        type: 'white',
        reason: '分支补齐-白名单段确认',
        typedConfirm: '::/1',
      });
      expect(res.status).toBe(200);
      const id = res.body?.data?._id;
      try {
        // recordDurably 在响应前 await：行必然已落库，无需 waitFor
        const audit = await AuditLog.findOne({
          action: 'ip_whitelist_added',
          'body.ip': '::/1',
        })
          .sort({ _id: -1 })
          .lean();
        expect(audit).not.toBeNull();
        expect(audit.body.riskFactors).toEqual(['large_segment_whitelist']);
      } finally {
        await cleanup(id);
      }
    });

    test('/0 回归不受影响：白名单 /0 仍由 guardFullRangeCIDR 收口（非超管 403，而非段级 400）', async () => {
      const res = await secPost('/api/security/ip-list', {
        ip: '0.0.0.0/0',
        type: 'white',
        reason: '分支补齐-白名单段确认',
      });
      // 若 /0 误入新开的白名单确认分支，这里会变成 400 typed_confirmation_required
      expect(res.status).toBe(403);
      expect(res.body.errors.errorCode).toBe('FULL_RANGE_FORBIDDEN');
    });

    test('兼容性：内网网段（192.168.0.0/16）加白带确认可通过，小段（/24 级以下）不带确认也通过', async () => {
      // 大段内网加白：≥256 主机 ⇒ 需确认，带上即通过（黑名单侧同规模同判据，无方向偏袒）
      const big = await secPost('/api/security/ip-list', {
        ip: '192.168.0.0/16',
        type: 'white',
        reason: '分支补齐-白名单段确认',
        typedConfirm: '192.168.0.0/16',
      });
      expect(big.status).toBe(200);
      // 小段白名单（<256 主机）不受确认门槛影响：加白只放行的既有语义不变
      const small = await secPost('/api/security/ip-list', {
        ip: '192.168.77.0/25',
        type: 'white',
        reason: '分支补齐-白名单段确认',
      });
      expect(small.status).toBe(200);
      await cleanup(big.body?.data?._id);
      await cleanup(small.body?.data?._id);
    });
  });

  test('POST 加黑被白名单覆盖 → 400 冲突，信任标记不可被封禁覆盖', async () => {
    // 前置：超管加白 10.0.0.0/8
    const white = await request(app)
      .post('/api/security/ip-list')
      .set('Authorization', `Bearer ${superToken}`)
      .send({
        ip: '10.0.0.0/8',
        type: 'white',
        reason: '分支补齐-白名单前置',
        typedConfirm: '10.0.0.0/8',
      });
    // 实测 200（新增名单条目固定 200）；这是后续断言的前置，值必须确定
    expect(white.status).toBe(200);
    if (white.body?.data?._id) createdIds.push(white.body.data._id);

    const res = await secPost('/api/security/ip-list', { ip: '10.1.1.1', type: 'black' });
    expect(res.status).toBe(400);
    expect(res.body.message).toContain('已被白名单条目');
  });

  test('DELETE 不存在的记录 → 404', async () => {
    const res = await secDel('/api/security/ip-list/000000000000000000000000');
    expect(res.status).toBe(404);
    expect(res.body.errors.errorCode).toBe('IP_LIST_ENTRY_NOT_FOUND');
  });

  test('DELETE 全网段条目 by 非超管 → 403（删除侧对称约束）', async () => {
    // 前置：超管创建全网段黑名单条目
    const full = await request(app)
      .post('/api/security/ip-list')
      .set('Authorization', `Bearer ${superToken}`)
      // 超管也要逐字确认（guardFullRangeCIDR）：这条断言是新增前置，不是放宽
      .send({
        ip: '0.0.0.0/0',
        type: 'black',
        reason: '分支补齐-全网段前置',
        typedConfirm: '0.0.0.0/0',
      });
    // 实测 200（同上前置）
    expect(full.status).toBe(200);
    const fullId = full.body?.data?._id || full.body?.data?.id;
    if (fullId) createdIds.push(fullId);

    try {
      const res = await secDel(`/api/security/ip-list/${fullId}`);
      expect(res.status).toBe(403);
      expect(res.body.errors.errorCode).toBe('FULL_RANGE_FORBIDDEN');
      // 删除侧的对称约束同样要留高危痕迹：这条记录与添加侧共用 riskFactors 前缀，
      // 只在后缀上区分（removal），写错一个词 SIEM 侧就把"拆防线"当成"加防线未遂"。
      const audit = await findEscalationAudit('DELETE', { 'body.ip': '0.0.0.0/0' });
      expect(audit).not.toBeNull();
      expect({
        riskLevel: audit.riskLevel,
        riskFactors: audit.riskFactors,
        success: audit.success,
        path: audit.path,
      }).toEqual({
        riskLevel: 'critical',
        riskFactors: ['full_range_cidr_removal_attempt'],
        success: false,
        path: `/api/security/ip-list/${fullId}`,
      });
    } finally {
      // 前置的全网段黑名单必须收回：留到后续用例会把「加黑被白名单覆盖 → 400」
      // 的并集判据提前顶成 403（随机顺序实测）。超管删除不受全网段守卫限制。
      if (fullId) {
        await request(app)
          .delete(`/api/security/ip-list/${fullId}`)
          .set('Authorization', `Bearer ${superToken}`);
      }
    }
  });

  /**
   * 分片删除守卫：两条 /1 各自都只是半张网，单条 bits===0 判据会放行逐个删除，
   * 于是非超管能把超管配置的全覆盖状态拆掉。删除侧必须和添加侧一样看并集，
   * 但只拦「删掉后覆盖率下降」的那一步——冗余条目不影响覆盖，不应误伤。
   */
  const addPairAsSuper = async (pair) => {
    const ids = [];
    for (const ip of pair) {
      const res = await request(app)
        .post('/api/security/ip-list')
        .set('Authorization', `Bearer ${superToken}`)
        // 铺满的那一条（第二条）会被要求逐字确认；不铺满时后端不看这个字段，故统一带上
        .send({ ip, type: 'white', reason: '分支补齐-分片删除前置', typedConfirm: ip });
      expect(res.status).toBe(200);
      ids.push(res.body?.data?._id);
    }
    return ids;
  };

  const expectRemovalGuarded = async (pair, targetIp) => {
    const ids = await addPairAsSuper(pair);
    try {
      const targetId = ids[0];
      expect(targetId).toBeTruthy();

      const res = await secDel(`/api/security/ip-list/${targetId}`);
      expect(res.status).toBe(403);
      expect(res.body.errors.errorCode).toBe('FULL_RANGE_FORBIDDEN');
      // 「拒绝」必须是"仍在"，而不是"删了但回 403"
      expect(await IPBlacklist.countDocuments({ _id: targetId })).toBe(1);

      // 同一操作员在 /0 用例里也留过 DELETE 审计，按 body.ip 精确认领本次拒绝
      const AuditLog = require('../../models/AuditLog');
      let audit = null;
      await waitFor(
        async () => {
          audit = await AuditLog.findOne({
            username: secUserName,
            action: 'privilege_escalation',
            method: 'DELETE',
            'body.ip': targetIp,
          }).lean();
          return !!audit;
        },
        { label: `分片删除的越权审计落库（${targetIp}）` }
      );
      expect(audit.riskFactors).toEqual(['full_range_cidr_removal_attempt']);
      expect(audit.riskLevel).toBe('critical');
    } finally {
      for (const id of ids) {
        if (!id) continue;
        await request(app)
          .delete(`/api/security/ip-list/${id}`)
          .set('Authorization', `Bearer ${superToken}`);
      }
    }
  };

  test('DELETE 分片铺满 IPv4（两条 /1）by 非超管 → 403（删除侧同样看并集）', async () => {
    await expectRemovalGuarded(['0.0.0.0/1', '128.0.0.0/1'], '0.0.0.0/1');
  });

  test('DELETE 分片铺满 IPv6（两条 /1）by 非超管 → 403', async () => {
    await expectRemovalGuarded(['::/1', '8000::/1'], '::/1');
  });

  test('DELETE 全覆盖名单中的冗余条目 → 不受守卫误伤', async () => {
    // /0 已铺满，再挂一条 /1 只是冗余。删除 /1 不会降低覆盖率 ⇒ 非超管应放行。
    const ids = [];
    try {
      // 两条都要确认串：/0 之后这条 /1 是冗余的，但判据是「并集铺满」——
      // 冗余与否由 DB 里的存量决定，前端与控制器都不该自己算（那会成为第二份事实）
      for (const [ip, reason] of [
        ['0.0.0.0/0', '分支补齐-全覆盖前置'],
        ['0.0.0.0/1', '分支补齐-冗余前置'],
      ]) {
        const res = await request(app)
          .post('/api/security/ip-list')
          .set('Authorization', `Bearer ${superToken}`)
          .send({ ip, type: 'white', reason, typedConfirm: ip });
        expect(res.status).toBe(200);
        ids.push(res.body?.data?._id);
      }

      const res = await secDel(`/api/security/ip-list/${ids[1]}`);
      expect(res.status).toBe(200);
      expect(await IPBlacklist.countDocuments({ _id: ids[1] })).toBe(0);
      // 全覆盖条目本身仍在
      expect(await IPBlacklist.countDocuments({ _id: ids[0] })).toBe(1);
    } finally {
      for (const id of ids) {
        if (!id) continue;
        await request(app)
          .delete(`/api/security/ip-list/${id}`)
          .set('Authorization', `Bearer ${superToken}`);
      }
    }
  });

  test('POST 携带未知字段 → 400 且点名该字段，且不落库（拼错时长字段名不得静默变永久封禁）', async () => {
    // 实测过的坏结果：客户端把时长写成 duration / expiresIn / hours，express 不报错、
    // controller 取不到 durationHours ⇒ 归一化成 0 ⇒ 永久封禁，界面与审计里都看不出差别。
    // 判据取三条：状态码 400、fieldErrors 点名拼错的键、库里确实没有这条记录。
    const typoIP = '203.0.113.77';
    const res = await secPost('/api/security/ip-list', {
      ip: typoIP,
      type: 'black',
      duration: 24,
    });

    expect(res.status).toBe(400);
    expect(res.body.errors?.errorCode).toBe('VALIDATION_FAILED');
    expect(res.body.errors.fieldErrors.map((e) => e.path)).toContain('duration');
    expect(await IPBlacklist.countDocuments({ ip: typoIP })).toBe(0);
  });

  test('POST 审计持久化失败 ⇒ 500，且这次名单变更必须有全局审计留痕（不得状态已变、审计为零）', async () => {
    // 夹具只构造 recordDurably 的两个重抛条件：AuditLog.create 失败 + WAL 未启用。
    // 条目已落库（不可回滚）⇒ 兜底只能是全局审计按路由补记这次 500 —— 恰好 1 条。
    const AuditLog = require('../../models/AuditLog');
    const auditBuffer = require('../../services/auditBuffer');
    const spyCreate = jest.spyOn(AuditLog, 'create').mockRejectedValue(new Error('audit down'));
    const spyWal = jest.spyOn(auditBuffer, 'isWalEnabled').mockReturnValue(false);
    const spyPush = jest.spyOn(auditBuffer, 'push');
    const ip = '203.0.113.79';
    try {
      const res = await secPost('/api/security/ip-list', {
        ip,
        type: 'black',
        reason: '分支补齐-审计重抛夹具',
      });
      expect(res.status).toBe(500);
      expect(res.body.errors.errorCode).toBe('INTERNAL_ERROR');

      await new Promise((r) => setImmediate(r));
      await new Promise((r) => setImmediate(r));

      const entry = await IPBlacklist.findOne({ ip, type: 'black' });
      const stateChanged = !!entry;
      const pushed = spyPush.mock.calls
        .map(([doc]) => doc)
        .filter((doc) => doc && doc.path === '/api/security/ip-list');
      expect(stateChanged || pushed.length > 0).toBe(true);
      expect(pushed).toHaveLength(1);
      expect(pushed[0]).toMatchObject({
        action: 'security_ip-list',
        category: 'security',
        statusCode: 500,
        success: false,
      });
    } finally {
      spyCreate.mockRestore();
      spyWal.mockRestore();
      spyPush.mockRestore();
    }
  });

  test('DELETE 审计持久化失败 ⇒ 500，且这次解除封禁必须有全局审计留痕（不得状态已变、审计为零）', async () => {
    // 先正常建一条条目（该步审计照常成功），再用夹具删除它：条目已删（不可回滚）⇒
    // 唯一可接受的兜底是全局审计补记这次 500，恰好 1 条。
    const created = await secPost('/api/security/ip-list', {
      ip: '203.0.113.80',
      type: 'black',
      reason: '分支补齐-删除夹具前置',
    });
    expect(created.status).toBe(200);
    const id = created.body.data._id;
    createdIds.push(id);

    const AuditLog = require('../../models/AuditLog');
    const auditBuffer = require('../../services/auditBuffer');
    const spyCreate = jest.spyOn(AuditLog, 'create').mockRejectedValue(new Error('audit down'));
    const spyWal = jest.spyOn(auditBuffer, 'isWalEnabled').mockReturnValue(false);
    const spyPush = jest.spyOn(auditBuffer, 'push');
    try {
      const path = `/api/security/ip-list/${id}`;
      const res = await secDel(path);
      expect(res.status).toBe(500);
      expect(res.body.errors.errorCode).toBe('INTERNAL_ERROR');

      await new Promise((r) => setImmediate(r));
      await new Promise((r) => setImmediate(r));

      const still = await IPBlacklist.findById(id).lean();
      const stateChanged = !still;
      const pushed = spyPush.mock.calls
        .map(([doc]) => doc)
        .filter((doc) => doc && doc.path === path);
      expect(stateChanged || pushed.length > 0).toBe(true);
      expect(pushed).toHaveLength(1);
      expect(pushed[0]).toMatchObject({
        action: 'security_ip-list',
        category: 'security',
        statusCode: 500,
        success: false,
      });
    } finally {
      spyCreate.mockRestore();
      spyWal.mockRestore();
      spyPush.mockRestore();
    }
  });
});
