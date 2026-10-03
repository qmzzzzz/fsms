/**
 * POST /api/security/report 的「目标事实核验 + 账号维度限流」
 * （2026-10-01 拍板：校 ID + 存在性 + 限流；保留「无权限码也可举报」的原始设计意图）
 *
 * 修复前的形状：任何登录用户都能提交任意 `targetId`，服务端原样写进一条
 * `riskLevel:'high'` 的审计行，而路由注释自称「本人资源…无越权面」。两条后果：
 *   ① 结构化字段可以指向**别人的**记录或不存在的对象；
 *   ② 该端点没有任何独立配额，单账号可批量刷高危行（安全概览的「高风险操作数」
 *      与告警取数都读这批行）。
 *
 * 判据（每条都可证伪，且都回读数据库而不是只看状态码）：
 *   A 存在性：合法但不存在的 ObjectId ⇒ 404，且不落审计行；
 *   B 数据范围：self/department 档指向范围外记录 ⇒ 403，且不落审计行；
 *     同一条记录对 all 档、对属主臂（含设备的 createdBy、报警的 handler 数组臂）
 *     必须放行——只判"拒绝"不判"放行"的闸门会把业务判死而 CI 仍绿；
 *   C system 型：不带 targetId 放行；带 targetId 拒绝。这一条是**绕口封堵**判据：
 *     若 system 可以随便填 ID，把 targetType 改成 system 就绕过 A/B 两道闸；
 *   D 限流：同一账号配额内全放行、超限第一次 429（阈值在本文件钉死为 20，并同时校验
 *     服务端声明的 RateLimit-Limit——跟着导出常量写用例的话，把 20 调成 2000 也照样全绿）；
 *     **换账号立刻放行**（证明键是 userId 而不是 IP）；
 *     **轮换 X-Forwarded-For 不得恢复配额**（证明键里没有 IP 成分——
 *     `userId:ip` 组合键在生产 TRUST_PROXY_HOPS=1 下等于"每换一个假 IP 多一份配额"，
 *     同一缺陷的实测见 credentialLimiterPerUserBucket.test.js）。
 *   E 投影完备性（静态闸）：A/B 两道判据要成立，services 层的 findScopeFieldsByIds
 *     投影必须覆盖 DATA_SCOPE_FIELDS 里该资源的每一条属主臂与部门臂。少一列是**假 deny**
 *     （用户只是"报不了"，日志却写着越权），比漏判更难发现，所以按声明逐臂对账，
 *     而不是靠 fixture 恰好碰到那一臂。变异实证：删掉 alarm 的 `handler` 一列，
 *     B 的数组臂用例与 E 同时变红。
 *
 * 已知取舍（不是缺陷，写下来免得被当成漏洞重新发现）：
 *   无任何角色的账户 dataScope 为 `none`（rbac.js 的 fail-closed 分支），
 *   于是连"举报自己的记录"也会被 403。这与该账户看不到任何数据是一致的。
 */

const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

const DEVICE_TYPE_VALUES = Object.values(require('../../utils/constants').DEVICE_TYPE);
const DEPT_A = 'ZZRTS-A';
const DEPT_C = 'ZZRTS-C';
const PASSWORD = 'Aa1!b2@c3#d4';

// trust proxy 在 createApp() 内读 env ⇒ 必须在 require('../../app') 之前设好，
// 否则 D 组的 XFF 轮换全是假的（req.ip 恒为 socket 地址，任何键形都测不出差别）
const ORIG_TRUST_PROXY_HOPS = process.env.TRUST_PROXY_HOPS;
process.env.TRUST_PROXY_HOPS = '1';

describe('POST /api/security/report：目标事实核验与账号维度限流', () => {
  let app;
  let User;
  let AuditLog;
  let FireDevice;
  let FireAlarm;
  let tokens;
  let ids;

  const stamp = `rts${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);
  /** 每次换一个地址（203.0.113.0/24 是 TEST-NET-3，不会与真实对端冲突） */
  const xff = (i) => `203.0.113.${i}`;

  const post = (token, body, fromIp) => {
    const req = request(app).post('/api/security/report').set('Authorization', `Bearer ${token}`);
    if (fromIp) req.set('X-Forwarded-For', fromIp);
    return req.send(body);
  };

  /** 按 reason 精确取本用例自己写的那一行（按 userId 计数会变成用例顺序的函数） */
  const rowsByReason = (reason) => AuditLog.find({ action: 'suspicious_report', reason }).lean();

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    const Role = require('../../models/Role');
    const Permission = require('../../models/Permission');
    AuditLog = require('../../models/AuditLog');
    FireDevice = require('../../models/FireDevice');
    FireAlarm = require('../../models/FireAlarm');
    require('../../models/TokenBlacklist');

    const anyPerm = await Permission.create({
      name: '举报用权限',
      code: `${stamp}:read`,
      type: 'api',
      module: 'security',
    });
    const mkRole = (code, level) =>
      Role.create({ name: `${stamp} ${code}`, code, level, permissions: [anyPerm._id] });
    const selfRole = await mkRole(`${stamp}_SELF`, 4); // self 档
    const deptRole = await mkRole(`${stamp}_DEPT`, 7); // department 档
    const allRole = await mkRole(`${stamp}_ALL`, 10); // all 档

    const mkUser = (username, roles, department) =>
      User.create({
        username: `${username}${stamp}`,
        email: `${username}${stamp}@example.com`,
        password: PASSWORD,
        department,
        roles,
      });
    const selfUser = await mkUser('zzrts_self', [selfRole._id], DEPT_A);
    const deptUser = await mkUser('zzrts_dept', [deptRole._id], DEPT_A);
    const allUser = await mkUser('zzrts_all', [allRole._id], DEPT_C);
    const otherUser = await mkUser('zzrts_other', [selfRole._id], DEPT_C);
    // 限流用例专用账户（level 10：让每一条都走到"业务放行"，计数才只反映配额）。
    // burst/fresh/roter 各自独占一个账号且各用例只用自己的账号——--randomize 打乱
    // 文件内用例顺序后，配额消耗不会跨用例串线（3 seed 实测的套内顺序耦合）。
    const burstUser = await mkUser('zzrts_burst', [allRole._id], DEPT_A);
    const freshUser = await mkUser('zzrts_fresh', [allRole._id], DEPT_A);
    const roterUser = await mkUser('zzrts_roter', [allRole._id], DEPT_A);
    const otherBurstUser = await mkUser('zzrts_burst2', [allRole._id], DEPT_A);

    const sign = (u) =>
      jwt.sign(
        { userId: String(u._id), username: u.username, tokenVersion: 0 },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
      );
    tokens = {
      self: sign(selfUser),
      dept: sign(deptUser),
      all: sign(allUser),
      other: sign(otherUser),
      burst: sign(burstUser),
      fresh: sign(freshUser),
      roter: sign(roterUser),
      burst2: sign(otherBurstUser),
    };
    ids = {
      selfUser: String(selfUser._id),
      otherUser: String(otherUser._id),
      strangerId: new mongoose.Types.ObjectId().toHexString(), // 合法格式、不存在
    };

    // 范围内/范围外的两份设备：devMine 由 self 档本人建档且楼栋 = 本人部门；
    // devTheirs 由他人建档、楼栋在另一个部门 ⇒ 两道判据同时不命中
    const mkDevice = (code, building, extra) =>
      FireDevice.create({
        deviceCode: `${code}${stamp}`,
        deviceName: `${code} 名称`,
        deviceType: DEVICE_TYPE_VALUES[0],
        installDate: new Date('2026-01-01'),
        location: { building },
        ...extra,
      });
    const devMine = await mkDevice('RTS-DEV-MINE', DEPT_A, { createdBy: selfUser._id });
    const devTheirs = await mkDevice('RTS-DEV-THEIRS', DEPT_C, { createdBy: otherUser._id });

    // 报警的属主是数组臂 ['reporter.userId','handler']：
    // alarmHandled 只命中 handler 这一臂——它专门盯"范围判定有没有真的按数组取并集"
    const mkAlarm = (extra) =>
      FireAlarm.create({
        alarmType: 'smoke',
        description: '范围核验夹具',
        location: { building: DEPT_A },
        ...extra,
      });
    const alarmMine = await mkAlarm({ reporter: { userId: selfUser._id } });
    const alarmTheirs = await mkAlarm({
      reporter: { userId: otherUser._id },
      location: { building: DEPT_C },
    });
    const alarmHandled = await mkAlarm({
      reporter: { userId: otherUser._id },
      handler: selfUser._id,
      location: { building: DEPT_C },
    });

    ids.devMine = String(devMine._id);
    ids.devTheirs = String(devTheirs._id);
    ids.alarmMine = String(alarmMine._id);
    ids.alarmTheirs = String(alarmTheirs._id);
    ids.alarmHandled = String(alarmHandled._id);

    const { createApp } = require('../../app');
    app = createApp();
  });

  afterAll(async () => {
    if (ORIG_TRUST_PROXY_HOPS === undefined) delete process.env.TRUST_PROXY_HOPS;
    else process.env.TRUST_PROXY_HOPS = ORIG_TRUST_PROXY_HOPS;
    if (mongoose.connection.readyState !== 0) {
      await AuditLog.deleteMany({ action: 'suspicious_report', username: /zzrts/ }).catch(() => {});
      await FireAlarm.deleteMany({ description: '范围核验夹具' }).catch(() => {});
      await FireDevice.deleteMany({ deviceCode: /RTS-DEV/ }).catch(() => {});
      await User.deleteMany({ username: /zzrts/ }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  // ==================== A. 存在性 ====================
  describe('A 记录型 target 必须真实存在', () => {
    test('合法格式但不存在的设备 ID ⇒ 404，且不落审计行', async () => {
      const reason = `不存在设备_${stamp}`;
      const res = await post(tokens.self, {
        targetType: 'device',
        targetId: ids.strangerId,
        reason,
      });
      expect(res.status).toBe(404);
      expect(res.body.errors.errorCode).toBe('DEVICE_NOT_FOUND');
      expect(await rowsByReason(reason)).toHaveLength(0);
    });

    test('不存在的用户 ID ⇒ 404 USER_NOT_FOUND（该码注册表里是 401，本处必须是 404）', async () => {
      const res = await post(tokens.self, {
        targetType: 'user',
        targetId: ids.strangerId,
        reason: `不存在用户_${stamp}`,
      });
      expect(res.status).toBe(404);
      expect(res.body.errors.errorCode).toBe('USER_NOT_FOUND');
    });
  });

  // ==================== B. 数据范围 ====================
  describe('B 记录型 target 必须落在举报人的数据范围内', () => {
    test('self 档指向他人建档、他部门楼栋的设备 ⇒ 403 且不落审计行', async () => {
      const reason = `越权设备_${stamp}`;
      const res = await post(tokens.self, {
        targetType: 'device',
        targetId: ids.devTheirs,
        reason,
      });
      expect(res.status).toBe(403);
      expect(res.body.errors.errorCode).toBe('DEVICE_VIEW_FORBIDDEN');
      expect(await rowsByReason(reason)).toHaveLength(0);
    });

    test('正向对照：同一条设备对 all 档放行（闸门不是无条件拒绝）', async () => {
      const reason = `范围内设备_${stamp}`;
      const res = await post(tokens.all, {
        targetType: 'device',
        targetId: ids.devTheirs,
        reason,
      });
      expect(res.status).toBe(200);
      const rows = await rowsByReason(reason);
      expect(rows).toHaveLength(1);
      expect(rows[0].targetId).toBe(ids.devTheirs);
      expect(rows[0].riskLevel).toBe('high');
    });

    test('本人建档的设备对 self 档放行', async () => {
      const res = await post(tokens.self, {
        targetType: 'device',
        targetId: ids.devMine,
        reason: `本人设备_${stamp}`,
      });
      expect(res.status).toBe(200);
    });

    test('department 档按楼栋放行（同部门、非本人建档）', async () => {
      const res = await post(tokens.dept, {
        targetType: 'device',
        targetId: ids.devMine,
        reason: `同部门设备_${stamp}`,
      });
      expect(res.status).toBe(200);
    });

    test('报警属主的数组臂：仅命中 handler 也算在范围内（判定必须取并集而不是单字段）', async () => {
      const res = await post(tokens.self, {
        targetType: 'alarm',
        targetId: ids.alarmHandled,
        reason: `我处理中的报警_${stamp}`,
      });
      expect(res.status).toBe(200);
    });

    test('正向对照：本人上报的报警放行', async () => {
      const res = await post(tokens.self, {
        targetType: 'alarm',
        targetId: ids.alarmMine,
        reason: `我上报的报警_${stamp}`,
      });
      expect(res.status).toBe(200);
    });

    test('他人上报且非我处理的报警 ⇒ 403', async () => {
      const res = await post(tokens.self, {
        targetType: 'alarm',
        targetId: ids.alarmTheirs,
        reason: `越权报警_${stamp}`,
      });
      expect(res.status).toBe(403);
      expect(res.body.errors.errorCode).toBe('ALARM_VIEW_FORBIDDEN');
    });

    test('举报自己的用户记录放行（self 短路臂）', async () => {
      const res = await post(tokens.self, {
        targetType: 'user',
        targetId: ids.selfUser,
        reason: `本人记录_${stamp}`,
      });
      expect(res.status).toBe(200);
    });

    test('举报同事的用户记录对 self 档 ⇒ 403（结构化字段不能指向看不见的人）', async () => {
      const reason = `越权用户_${stamp}`;
      const res = await post(tokens.self, {
        targetType: 'user',
        targetId: ids.otherUser,
        reason,
      });
      expect(res.status).toBe(403);
      expect(res.body.errors.errorCode).toBe('USER_SCOPE_FORBIDDEN');
      expect(await rowsByReason(reason)).toHaveLength(0);
    });
  });

  // ==================== C. system 型与绕口 ====================
  describe('C system 型：不带 targetId 放行，带 targetId 拒绝（否则改类型就绕过 A/B）', () => {
    test('系统级举报（无 targetId）⇒ 200', async () => {
      const res = await post(tokens.self, {
        targetType: 'system',
        reason: `系统级举报_${stamp}`,
      });
      expect(res.status).toBe(200);
    });

    test('同一个真实 ID，换成 system 型必须被拒 —— 绕口封堵判据', async () => {
      // 参照项是 A 组那条 404：真实 ID 在 device 型下走到范围闸（这里给的是
      // 无角色账户看不到的他人设备，返回 403），而 system 型必须在**路由层**就拒绝，
      // 绝不能因为"类型换成 system 就不核验了"而放行。
      const asRecord = await post(tokens.self, {
        targetType: 'device',
        targetId: ids.devTheirs,
        reason: `绕口对照-记录型_${stamp}`,
      });
      expect(asRecord.status).toBe(403);

      const res = await post(tokens.self, {
        targetType: 'system',
        targetId: ids.devTheirs,
        reason: `绕口对照-system_${stamp}`,
      });
      expect(res.status).toBe(400);
      expect(res.body.errors.errorCode).toBe('VALIDATION_FAILED');
      expect(res.body.errors.fieldErrors.map((e) => e.path)).toContain('targetId');
    });

    test('记录型缺 targetId ⇒ 400 点名 targetId（不得退化成"没有对象的系统级举报"）', async () => {
      const res = await post(tokens.self, {
        targetType: 'device',
        reason: `缺目标 ID_${stamp}`,
      });
      expect(res.status).toBe(400);
      expect(res.body.errors.fieldErrors.map((e) => e.path)).toContain('targetId');
      // 文案也是判据：删掉链首的 .exists({values:'falsy'}) 后，字段缺失会由后面的
      // .isString() 拒（undefined 不是字符串），状态码和 path 全都一样 ⇒ 只看这两项
      // 是"绿但不设防"。变异实证：去掉 exists 本条仍绿，加上 msg 断言才真正钉住
      // 「缺字段」这一分支的提示（空串同理，由 falsy 归入缺字段而不是"格式无效"）。
      const missing = res.body.errors.fieldErrors.find((e) => e.path === 'targetId');
      expect(missing.msg).toBe('请提供被举报对象的 ID');

      const empty = await post(tokens.self, {
        targetType: 'device',
        targetId: '',
        reason: `空目标 ID_${stamp}`,
      });
      expect(empty.status).toBe(400);
      const emptyErr = empty.body.errors.fieldErrors.find((e) => e.path === 'targetId');
      expect(emptyErr.msg).toBe('请提供被举报对象的 ID');
    });

    test('记录型的非 ObjectId 字符串 ⇒ 400（原 100 字符上限判据由格式判据取代）', async () => {
      const res = await post(tokens.self, {
        targetType: 'device',
        targetId: 'dev-not-an-id',
        reason: `非 ID 字符串_${stamp}`,
      });
      expect(res.status).toBe(400);
      expect(res.body.errors.fieldErrors.map((e) => e.path)).toContain('targetId');
    });
  });

  // ==================== D. 账号维度限流 ====================
  describe('D 账号维度限流：配额按 userId，不受来源 IP 影响', () => {
    // 配额在本用例里钉死：rateLimit.js 刻意**不导出**这个数（导出后再按值驱动，
    // 有人把 20 调成 2000 用例照样全绿 ⇒ 绿但不设防）。改配额必须撞红这里。
    const MAX = 20;
    const legal = (i) => ({
      targetType: 'system',
      reason: `配额_${stamp}_${i}`,
    });

    test('配额内全放行、超限第一次 429，且 429 的文案指向本桶', async () => {
      expect(MAX).toBeGreaterThan(5); // 判据防呆：MAX 被误调成 0/1 时本组用例无意义
      const first = await post(tokens.burst, legal(1));
      expect(first.status).toBe(200);
      // 服务端**声明**的配额（draft-6 的 RateLimit-Limit，由 express-rate-limit 按
      // options.max 写出）与用例钉死的数同值：把"数字写在哪儿"和"闸确实在这个数上"接上。
      expect(first.headers['ratelimit-limit']).toBe(String(MAX));
      for (let i = 2; i <= MAX; i += 1) {
        // 每一次都必须是 200：若中途出现 400/403/404，说明后面测的根本不是配额
        const res = await post(tokens.burst, legal(i));
        expect(res.status).toBe(200);
      }
      const over = await post(tokens.burst, legal(MAX + 1));
      expect(over.status).toBe(429);
      expect(over.body.message).toBe('举报提交过于频繁，请稍后再试');
      expect(await rowsByReason(legal(MAX + 1).reason)).toHaveLength(0);
    }, 60000);

    test('换账号立刻恢复（证明键是 userId 而不是 IP）', async () => {
      // 用自己独占的账号（fresh）：--randomize 会打乱文件内用例顺序，本用例可能
      // 排在「轮换 XFF」之后——独占账号的配额不被别的用例消耗，顺序无关。
      const res = await post(tokens.fresh, legal(1));
      expect(res.status).toBe(200);
    });

    test('轮换 X-Forwarded-For 不得恢复配额（证明键里没有 IP 成分）', async () => {
      // 独占账号从第 1 次填满（不再隐式依赖"上一条已让 burst2 用掉 1 次"的顺序
      // 前提），填满后逐切换 IP 打到 429——配额键里没有 IP 成分才成立。
      for (let i = 1; i <= MAX; i += 1) {
        expect((await post(tokens.roter, legal(i), xff(i))).status).toBe(200);
      }
      const rotated = [];
      for (let i = MAX + 1; i <= MAX + 10; i += 1) {
        const res = await post(tokens.roter, legal(i), xff(i));
        rotated.push(res.status);
      }
      expect(rotated).toHaveLength(10); // 防呆：空数组的 .every() 恒为 true
      expect(rotated.every((s) => s === 429)).toBe(true);
    }, 60000);

    test('前提自证：本应用确实信任 XFF（req.ip 由请求方决定），上一条才不是空转', async () => {
      // trust proxy = 1 时 proxy-addr 把 req.ip 取自 X-Forwarded-For ⇒ 攻击者可任意
      // 移动它。上一条在这个前提下仍然全程 429，才等于"IP 不在配额键里"。
      // 若这里的 trust proxy 变成 false/undefined（配置漂移），上一条就退化成
      // "同一个 req.ip 打了 10 次"，配额桶按 userId 组键的事实再没人盯。
      expect(app.get('trust proxy')).toBe(1);
    });
  });

  // ==================== E. 投影完备性（静态闸） ====================
  // 举报核验的数据访问在 services 层（分层棘轮不允许控制器直连 model），三个 getter 返回
  // **投影后的 lean 文档**。投影少一列 ⇒ 命中那一臂的记录被判成越权：这是"假 deny"，
  // 用户只表现为"报不了"，而日志写着越权——比漏判更难被发现，且 B 组用例只在"恰好有
  // 一条走那一臂"时才可能变红。所以这里按**声明**逐臂对账，而不是靠 fixture 碰运气。
  describe('E 三个 findScopeFieldsByIds 的 select 覆盖 DATA_SCOPE_FIELDS 的每一条臂', () => {
    const fs = require('fs');
    const path = require('path');
    const { DATA_SCOPE_FIELDS } = require('../../constants/dataScopeFields');

    const GETTERS = [
      ['user', '../../services/userService'],
      ['device', '../../services/DeviceService'],
      ['alarm', '../../services/AlarmService'],
    ];

    /** 取某个 service 源码里 findScopeFieldsByIds 的 select 投影字段列表 */
    const projectionOf = (relPath) => {
      const src = fs.readFileSync(path.resolve(__dirname, `${relPath}.js`), 'utf8');
      const start = src.indexOf('findScopeFieldsByIds');
      expect(start).toBeGreaterThan(-1); // 方法被改名/删除 ⇒ 本闸必须红，而不是静默跳过
      const body = src.slice(start, start + 1200);
      const matched = body.match(/\.select\(\s*'([^']+)'/);
      expect(matched).not.toBeNull(); // getter 不再用投影 ⇒ 先说明理由再改这条判据
      return matched[1].trim().split(/\s+/);
    };

    test.each(GETTERS)('%s 的每条属主臂与部门臂都在投影里', (kindName, relPath) => {
      const fields = DATA_SCOPE_FIELDS[kindName];
      const owners = [].concat(fields.ownerField);
      expect(owners.length).toBeGreaterThan(0);
      const projection = projectionOf(relPath);
      for (const arm of [...owners, fields.departmentField]) {
        expect(projection).toContain(arm);
      }
    });

    test('反向自证：判据确实会拒绝一个不存在的臂（否则上一条可能恒绿）', () => {
      // 若 projectionOf 因为正则失配而返回空数组，`toContain` 会全部报错；但更要防的是
      // "返回了整段 select 却从不区分字段"的形态——用一个必然不在投影里的臂证明
      // toContain 在做逐项比较，而不是恒真。
      expect(projectionOf('../../services/AlarmService')).not.toContain('zzNotARealField');
      expect(projectionOf('../../services/AlarmService').length).toBeGreaterThanOrEqual(3);
    });
  });
});
