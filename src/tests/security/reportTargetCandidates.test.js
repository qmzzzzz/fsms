/**
 * GET /api/security/report-targets —— 举报对象候选（2026-10-21）
 *
 * 修复的缺陷是**可用性**而不是越权：举报对话框原先要求用户粘贴 24 位 ObjectId，
 * 而一线人员拿不到该值（它只出现在接口响应里，界面上从不显示）⇒ 记录型举报
 * 事实上不可用。修法是把输入框换成"可搜索的对象选择器"，候选由本端点提供。
 *
 * 这个端点同时是**新的读取面**，所以判据都钉在"它没有比提交核验多给出一寸"上：
 *
 *   A 免权限码可达：没有任何权限码的账户也能拿到 200（举报对全员开放，
 *     挂权限码等于让一线报不了警）。空范围返回空数组，而不是 403。
 *   B 候选集 = 举报人数据范围：与提交时的 `resolveReportTargetViolation` 同判据。
 *     self 档看不到他人建档/他部门楼栋的设备；all 档看得到；报警的数组属主臂
 *     （handler）与用户的「本人 _id 短路」都必须成立。
 *   C **同值性（本套件最重要的一条）**：候选里出现的每一个 id，拿去 POST /report
 *     必须 200；范围外记录必须 403/404。只判"范围外不出现"会让"假 deny"
 *     （能提交却选不到）漏过——那正是 `buildDataScopeFilter` 与 `isRecordInScope`
 *     在 self/department 边界上分叉的形态。
 *   D 最小投影：响应里不得出现 phone/email（用户）、description/reporter（报警）。
 *     候选列表不是用户管理页，PII 的明文通道只有 POST /security/view-sensitive。
 *   E 参数边界：type 只允许 user/device/alarm（system 不指向具体对象）；
 *     keyword 必须字符串且 ≤100；未认证 401。
 *   F 上限与独立配额：单次最多 20 条；搜索 25 次后仍能提交举报——证明候选查询
 *     消耗的是账号级通用桶（authenticate 内的 userLimiter），而不是举报提交的
 *     20 次写配额。共用时用户还没提交就把配额吃光，429 文案还指向"提交过于频繁"。
 *
 * 已知取舍（不是缺陷）：无角色的账户 dataScope 为 `none`，候选恒为空——
 * 与"该账户看不到任何数据"一致，此时前端引导改用「系统问题 + 文字描述」。
 */

const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

const DEVICE_TYPE_VALUES = Object.values(require('../../utils/constants').DEVICE_TYPE);
const DEPT_A = 'ZZRTC-A';
const DEPT_C = 'ZZRTC-C';
const PASSWORD = 'Aa1!b2@c3#d4';

describe('GET /api/security/report-targets：候选集与提交核验同值', () => {
  let app;
  let User;
  let FireDevice;
  let FireAlarm;
  let tokens;
  let ids;

  const stamp = `rtc${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);

  const get = (token, params) => {
    const req = request(app).get('/api/security/report-targets');
    if (token) req.set('Authorization', `Bearer ${token}`);
    return req.query(params);
  };
  const post = (token, body) =>
    request(app).post('/api/security/report').set('Authorization', `Bearer ${token}`).send(body);
  const candidateIds = (res) => (res.body.data.items || []).map((i) => i.id);

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    const Role = require('../../models/Role');
    const AuditLog = require('../../models/AuditLog');
    FireDevice = require('../../models/FireDevice');
    FireAlarm = require('../../models/FireAlarm');
    require('../../models/TokenBlacklist');

    const mkRole = (code, level) =>
      Role.create({ name: `${stamp} ${code}`, code, level, permissions: [] });
    const selfRole = await mkRole(`${stamp}_SELF`, 4); // self 档
    const allRole = await mkRole(`${stamp}_ALL`, 10); // all 档

    const mkUser = (username, roles, department) =>
      User.create({
        username: `${username}${stamp}`,
        email: `${username}${stamp}@example.com`,
        password: PASSWORD,
        department,
        roles,
      });
    const selfUser = await mkUser('zzrtc_self', [selfRole._id], DEPT_A);
    const allUser = await mkUser('zzrtc_all', [allRole._id], DEPT_C);
    const otherUser = await mkUser('zzrtc_other', [selfRole._id], DEPT_C);
    // 无任何角色 ⇒ dataScope none（rbac 的 fail-closed 分支）：证明端点不挂权限码
    const noRoleUser = await mkUser('zzrtc_norole', [], DEPT_A);

    const sign = (u) =>
      jwt.sign(
        { userId: String(u._id), username: u.username, tokenVersion: 0 },
        process.env.JWT_SECRET,
        { expiresIn: '24h' }
      );
    tokens = {
      self: sign(selfUser),
      all: sign(allUser),
      other: sign(otherUser),
      noRole: sign(noRoleUser),
    };
    ids = {
      selfUser: String(selfUser._id),
      otherUser: String(otherUser._id),
      strangerId: new mongoose.Types.ObjectId().toHexString(),
    };

    const mkDevice = (code, building, extra) =>
      FireDevice.create({
        deviceCode: `${code}${stamp}`.toUpperCase(),
        deviceName: `${code} 名称`,
        deviceType: DEVICE_TYPE_VALUES[0],
        installDate: new Date('2026-01-01'),
        location: { building, floor: '2F', room: '201' },
        ...extra,
      });
    const devMine = await mkDevice('RTC-DEV-MINE', DEPT_A, { createdBy: selfUser._id });
    const devTheirs = await mkDevice('RTC-DEV-THEIRS', DEPT_C, { createdBy: otherUser._id });

    const mkAlarm = (extra) =>
      FireAlarm.create({
        alarmType: 'smoke',
        description: '候选夹具',
        location: { building: DEPT_A },
        ...extra,
      });
    const alarmMine = await mkAlarm({ reporter: { userId: selfUser._id } });
    const alarmTheirs = await mkAlarm({
      reporter: { userId: otherUser._id },
      location: { building: DEPT_C },
    });
    // 只命中 handler 数组臂：钉住"范围判定真的按属主数组取并集"
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
    void AuditLog;
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      const AuditLog = require('../../models/AuditLog');
      await AuditLog.deleteMany({ action: 'suspicious_report', username: /zzrtc/ }).catch(() => {});
      await FireAlarm.deleteMany({ description: '候选夹具' }).catch(() => {});
      await FireDevice.deleteMany({ deviceCode: /RTC-DEV/ }).catch(() => {});
      await User.deleteMany({ username: /zzrtc/ }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  // ==================== A. 免权限码可达 ====================
  describe('A 免权限码（举报对全员开放）', () => {
    test('没有任何角色的账户也能拿到 200（空候选，而不是 403）', async () => {
      const res = await get(tokens.noRole, { type: 'device' });
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(candidateIds(res)).toEqual([]);
    });

    test('未认证 ⇒ 401（端点不是匿名可读）', async () => {
      const res = await get(null, { type: 'device' });
      expect(res.status).toBe(401);
    });
  });

  // ==================== B. 候选集 = 数据范围 ====================
  describe('B 候选集与举报人数据范围一致', () => {
    test('self 档：只列出本人建档/本部门的设备，不出现他人设备', async () => {
      const res = await get(tokens.self, { type: 'device' });
      expect(res.status).toBe(200);
      const list = candidateIds(res);
      expect(list).toContain(ids.devMine);
      expect(list).not.toContain(ids.devTheirs);
    });

    test('all 档：同一条他人设备必须出现（闸门不是无条件收窄）', async () => {
      const res = await get(tokens.all, { type: 'device' });
      const list = candidateIds(res);
      expect(list).toContain(ids.devTheirs);
    });

    test('报警的属主是数组臂：handler=本人 的记录必须出现', async () => {
      const res = await get(tokens.self, { type: 'alarm' });
      const list = candidateIds(res);
      expect(list).toContain(ids.alarmMine);
      expect(list).toContain(ids.alarmHandled);
      expect(list).not.toContain(ids.alarmTheirs);
    });

    test('用户的「本人 _id 短路」：self 档候选里必须包含自己', async () => {
      // buildDataScopeFilter 在 user 类型（属主臂 createdBy）会把自己筛掉——
      // 这正是本端点不能用它、而要用 buildRecordScopeFilter 的原因
      const res = await get(tokens.self, { type: 'user' });
      const list = candidateIds(res);
      expect(list).toContain(ids.selfUser);
      expect(list).not.toContain(ids.otherUser);
    });
  });

  // ==================== C. 同值性（核心） ====================
  describe('C 候选与提交核验同值：选得到的都能提交', () => {
    test('self 档候选里的每个 id，提交举报必须 200', async () => {
      for (const type of ['user', 'device', 'alarm']) {
        const res = await get(tokens.self, { type });
        const list = candidateIds(res);
        expect(list.length).toBeGreaterThan(0);
        for (const id of list) {
          const posted = await post(tokens.self, {
            targetType: type,
            targetId: id,
            reason: `同值性_${type}_${stamp}`,
          });
          expect({ type, id, status: posted.status }).toEqual({ type, id, status: 200 });
        }
      }
    });

    test('范围外记录（他人设备）提交仍被 403 —— 候选收窄没有放宽提交侧', async () => {
      const res = await post(tokens.self, {
        targetType: 'device',
        targetId: ids.devTheirs,
        reason: `范围外_${stamp}`,
      });
      expect(res.status).toBe(403);
    });
  });

  // ==================== D. 最小投影 ====================
  describe('D 候选不带 PII 与业务正文', () => {
    test('用户候选只有 id/kind/code/name/detail，不含 phone/email', async () => {
      const res = await get(tokens.all, { type: 'user' });
      expect(res.status).toBe(200);
      expect(res.body.data.items.length).toBeGreaterThan(0);
      for (const item of res.body.data.items) {
        expect(Object.keys(item).sort()).toEqual(['code', 'detail', 'id', 'kind', 'name']);
      }
      const raw = JSON.stringify(res.body);
      expect(raw).not.toMatch(/phone|email/i);
    });

    test('报警候选不含 description 与 reporter', async () => {
      const res = await get(tokens.self, { type: 'alarm' });
      const raw = JSON.stringify(res.body);
      expect(raw).not.toContain('候选夹具');
      expect(raw).not.toMatch(/reporter/);
      for (const item of res.body.data.items) {
        expect(item).not.toHaveProperty('description');
      }
    });
  });

  // ==================== E. 参数边界 ====================
  describe('E 参数边界', () => {
    test('type=system ⇒ 400（system 不指向具体对象，没有候选）', async () => {
      const res = await get(tokens.self, { type: 'system' });
      expect(res.status).toBe(400);
      expect(res.body.errors.errorCode).toBe('VALIDATION_FAILED');
    });

    test('type 缺失或未知 ⇒ 400', async () => {
      expect((await get(tokens.self, {})).status).toBe(400);
      expect((await get(tokens.self, { type: 'inspection' })).status).toBe(400);
    });

    test('原型链成员不得冒充合法 type（constructor/toString/valueOf/__proto__/hasOwnProperty ⇒ 400）', async () => {
      // 缺陷形态（2026-11-02，r21-c）：`REPORT_TARGET_CANDIDATE_KINDS` 是**普通对象字面量**，
      // 裸下标 `KINDS[req.query.type]` 会顺着原型链取到 Object.prototype 的成员——
      // `constructor`/`toString`/`valueOf`/`hasOwnProperty` 全是函数、`__proto__` 是对象，
      // 全部 truthy ⇒ :322 的 `!kind` 兜底**不放行** ⇒ :331 `kind.fields.ownerField`
      // 撞 undefined ⇒ TypeError ⇒ 500。
      //
      // 这不是「类型校验不严」，而是 **fail-closed 兜底被原型链击穿**：兜底还在、还在跑，
      // 但它比对的不是「这张表有没有这个键」，而是「顺着原型链能不能取到东西」。
      // 所以修复不能靠在路由层再列一份 type 白名单（那会变成第二份清单 = 两把尺子），
      // 而是把兜底本身改成自有的键判定（Object.hasOwn）。
      const prototypeKeys = ['constructor', 'toString', 'valueOf', '__proto__', 'hasOwnProperty'];
      const observed = [];
      for (const type of prototypeKeys) {
        const res = await get(tokens.self, { type });
        observed.push(`${type}=${res.status}`);
        // 逐条断言 400，不用「整组一个 toEqual」掩盖是哪一条漏了
        expect({ type, status: res.status }).toEqual({ type, status: 400 });
        expect(res.body.errors.errorCode).toBe('VALIDATION_FAILED');
        expect(res.body.errors.fieldErrors).toEqual([{ field: 'type', message: '无效的目标类型' }]);
      }
      expect(observed).toEqual(prototypeKeys.map((t) => `${t}=400`));
    });

    test('同型普查对照：POST /report 的 targetType 由路由 isIn 拦，原型链成员同样 400', async () => {
      // 本文件第二张表 REPORT_TARGET_KINDS[targetType]（sensitive.js:211）是**同一个裸下标形状**，
      // 只是它的前置校验在路由 :89 `body('targetType').isIn(REPORT_TARGET_TYPES)`。
      // 这条用例把「那道 isIn 确实挡得住原型链成员」变成可复核的事实：validator.isIn 走数组
      // indexOf（不是对象下标），所以 constructor/__proto__ 都不在集合里 ⇒ 400。
      // 若哪天有人把 isIn 从链上摘掉，这里会立刻从 400 变 500。
      for (const targetType of ['constructor', '__proto__', 'hasOwnProperty']) {
        const res = await post(tokens.self, { targetType, reason: `原型链_${targetType}` });
        expect({ targetType, status: res.status }).toEqual({ targetType, status: 400 });
      }
    });

    test('反向对照：白名单内的三类仍 200、inspection 仍 400（上一条不是恒 400 造的绿）', async () => {
      for (const type of ['user', 'device', 'alarm']) {
        const res = await get(tokens.all, { type });
        expect({ type, status: res.status }).toEqual({ type, status: 200 });
        expect(Array.isArray(res.body.data.items)).toBe(true);
      }
      expect((await get(tokens.all, { type: 'inspection' })).status).toBe(400);
    });

    test('keyword 超过全局入参上限（200）⇒ 400（app.js 的 queryLengthLimit）', async () => {
      const res = await get(tokens.self, { type: 'device', keyword: 'x'.repeat(201) });
      expect(res.status).toBe(400);
    });

    test('keyword 按编号前缀命中，未命中返回空数组而不是全量', async () => {
      const hit = await get(tokens.all, { type: 'device', keyword: 'RTC-DEV-MINE' });
      expect(candidateIds(hit)).toContain(ids.devMine);
      expect(candidateIds(hit)).not.toContain(ids.devTheirs);
      const miss = await get(tokens.all, { type: 'device', keyword: 'zzz-no-such' });
      expect(candidateIds(miss)).toEqual([]);
    });
  });

  // ==================== F. 上限与独立限流 ====================
  describe('F 上限与独立配额', () => {
    test('单次最多 20 条', async () => {
      const bulk = [];
      for (let i = 0; i < 25; i += 1) {
        bulk.push({
          deviceCode: `RTC-BULK-${String(i).padStart(2, '0')}${stamp}`.toUpperCase(),
          deviceName: `批量设备 ${i}`,
          deviceType: DEVICE_TYPE_VALUES[0],
          installDate: new Date('2026-01-01'),
          location: { building: DEPT_C },
          createdBy: new mongoose.Types.ObjectId(ids.otherUser),
        });
      }
      await FireDevice.insertMany(bulk);
      const res = await get(tokens.all, { type: 'device', keyword: 'RTC-BULK' });
      expect(res.status).toBe(200);
      expect(res.body.data.items).toHaveLength(20);
      await FireDevice.deleteMany({ deviceCode: /RTC-BULK/ });
    });

    test('配额与举报提交桶独立：搜满一批后仍能提交举报（搜索不吃提交配额）', async () => {
      // 用一个专属账号，避免与其它用例的计数串线
      const Role = require('../../models/Role');
      const allRole = await Role.findOne({ code: `${stamp}_ALL` });
      const solo = await User.create({
        username: `zzrtc_solo${stamp}`,
        email: `zzrtc_solo${stamp}@example.com`,
        password: PASSWORD,
        department: DEPT_A,
        roles: [allRole._id],
      });
      const soloToken = jwt.sign(
        { userId: String(solo._id), username: solo.username, tokenVersion: 0 },
        process.env.JWT_SECRET,
        { expiresIn: '24h' }
      );

      // 搜索 25 次（超过举报提交桶的 20 次配额），随后提交仍必须 200。
      // 共用桶时这里会是 429——而 429 文案写着"举报提交过于频繁"，
      // 用户根本看不出是搜索把配额吃光的。
      for (let i = 0; i < 25; i += 1) {
        const r = await get(soloToken, { type: 'device' });
        expect(r.status).toBe(200);
      }
      const posted = await post(soloToken, {
        targetType: 'device',
        targetId: ids.devMine,
        reason: `独立桶_${stamp}`,
      });
      expect(posted.status).toBe(200);
    });
  });
});
