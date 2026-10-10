/**
 * 审计utils 加固回归（新增文件，不改既有测试；前缀 zzqA_ 避免与并行 agent 冲突）
 * 覆盖两处可证伪缺陷：
 *  F-A1 helpers.isBreachedPassword 空白绕过（"Admin@123456 " 曾通过弱口令黑名单）
 *  F-A2 utils/dateFormat 展示未带 BUSINESS_TIMEZONE（UTC 容器里导出行日期落后 8 小时）
 */

const { isBreachedPassword } = require('../../utils/helpers');
const { formatDateTime, formatDate } = require('../../utils/dateFormat');

describe('F-A1 弱口令黑名单不因空白变体被绕过', () => {
  test('命中集合口令的加空格/内嵌空格变体仍判为泄露口令', () => {
    expect(isBreachedPassword('admin@123')).toBe(true); // 前提：基线命中
    expect(isBreachedPassword('admin@123 ')).toBe(true);
    expect(isBreachedPassword(' admin@123')).toBe(true);
    expect(isBreachedPassword('\tAdmin@123456 \n')).toBe(true);
  });

  test('强随机口令不得被误伤（去空白不引入假阳性）', () => {
    expect(isBreachedPassword('Vn6$Rw83pKx5')).toBe(false);
    expect(isBreachedPassword('Fire@2026Safe!')).toBe(false);
  });
});

describe('F-A2 报表时间按业务时区渲染', () => {
  // 期望值不用字面串、也不改 process.env.TZ，理由都是实测出来的（第三轮审计 O-TZ）：
  //  1) jest realm 内进程中途改 TZ 不生效——TZ=UTC 之后 toLocaleDateString 仍按宿主区
  //     （本机 resolvedOptions().timeZone=Asia/Shanghai）渲染，"强制 UTC"的断言会恒绿；
  //  2) 字面分隔符由 Intl 的调用形态决定，不由数据决定：同一瞬间
  //     toLocaleDateString('zh-CN') 出 '2026/8/21'（short 样式 y/M/d），
  //     toLocaleString('zh-CN', { hour12:false }) 出 '2026-08-21 00:00:00'（yMd 骨架 y-M-d）。
  //     钉字面串等于把断言绑在运行时的模式表上——换 Node/ICU 就假红。
  // 所以期望一律用**与被测实现同一套 API**（同 locale、同选项、显式 timeZone）现场构造，
  // 只钉"展示用的时区是不是 BUSINESS_TIMEZONE"；再用两个 TZ_BUSINESS 取值做差分：
  // 实现一旦丢掉 timeZone，两臂都退化成宿主时区 ⇒ 差分恒等 ⇒ 必红，且与宿主区是哪个无关。
  const INSTANT = '2026-08-20T16:00:00Z'; // 东八区 8-21 00:00 / UTC 8-20 16:00：跨业务日界
  const ZONE_A = 'Asia/Shanghai';
  const ZONE_B = 'UTC';

  const wantDate = (tz) => new Date(INSTANT).toLocaleDateString('zh-CN', { timeZone: tz });
  const wantDateTime = (tz) =>
    new Date(INSTANT).toLocaleString('zh-CN', { hour12: false, timeZone: tz });

  /** 在指定 TZ_BUSINESS 下重载 utils/dateFormat（BUSINESS_TIMEZONE 是模块加载期常量） */
  const loadDateFormat = (businessZone) => {
    const saved = process.env.TZ_BUSINESS;
    process.env.TZ_BUSINESS = businessZone;
    try {
      let mod;
      jest.isolateModules(() => {
        mod = require('../../utils/dateFormat');
      });
      return mod;
    } finally {
      if (saved === undefined) delete process.env.TZ_BUSINESS;
      else process.env.TZ_BUSINESS = saved;
    }
  };

  test('前提自证：所选瞬间在两个业务区取值下渲染结果不同（差分臂的地基）', () => {
    // 这一条若转红，说明下面的差分断言失去了判据（例如有人把 INSTANT 挪到两区同日）。
    expect(wantDate(ZONE_A)).not.toBe(wantDate(ZONE_B));
    expect(wantDateTime(ZONE_A)).not.toBe(wantDateTime(ZONE_B));
  });

  test('展示时区取自 BUSINESS_TIMEZONE：丢 timeZone 或硬编码东八区都转红', () => {
    const a = loadDateFormat(ZONE_A);
    const b = loadDateFormat(ZONE_B);
    expect(a.formatDate(INSTANT)).toBe(wantDate(ZONE_A));
    expect(a.formatDateTime(INSTANT)).toBe(wantDateTime(ZONE_A));
    expect(b.formatDate(INSTANT)).toBe(wantDate(ZONE_B));
    expect(b.formatDateTime(INSTANT)).toBe(wantDateTime(ZONE_B));
    // 换业务区 ⇒ 展示跟着换（硬编码 'Asia/Shanghai' 而无视常量在这一臂转红）
    expect(a.formatDate(INSTANT)).not.toBe(b.formatDate(INSTANT));
    expect(a.formatDateTime(INSTANT)).not.toBe(b.formatDateTime(INSTANT));
  });

  test('空值仍统一返回占位符', () => {
    expect(formatDate(null)).toBe('-');
    expect(formatDateTime(undefined)).toBe('-');
  });
});

describe('F-A3 审计 action/path 派生不被攻击者可控超长段撑爆（索引键/审计抑制）', () => {
  const { deriveAction, auditPath } = require('../../utils/auditMeta');

  test('超长非动态段不得拼进 action，且总长有界', () => {
    const junk = 'a'.repeat(5000);
    const action = deriveAction('GET', `/api/devices/${junk}`, 'device');
    expect(action.length).toBeLessThanOrEqual(96);
    expect(action).not.toContain(junk.slice(0, 100));
    // 垃圾段被丢弃后回落到方法映射，仍是一个合法短 action
    expect(action).toBe('device_view');
  });

  test('合法子动作段不受影响（截断/过滤不得误伤真实路由）', () => {
    const OID = '507f1f77bcf86cd799439011';
    expect(deriveAction('PUT', `/api/users/${OID}/roles`, 'user')).toBe('user_roles');
    expect(deriveAction('POST', '/api/security/ip-list', 'security')).toBe('security_ip-list');
    expect(deriveAction('PUT', `/api/alarms/${OID}/false-alarm`, 'alarm')).toBe(
      'alarm_false-alarm'
    );
  });

  test('auditPath 有界（≤512），超长 URL 不整段落库', () => {
    const p = auditPath({ originalUrl: '/api/devices/' + 'b'.repeat(2000) });
    expect(p.length).toBeLessThanOrEqual(512);
  });
});

describe('F-A4 stripControlCharsDeep 对 __proto__ 键不触发原型 setter', () => {
  const { stripControlCharsDeep } = require('../../utils/helpers');

  test('__proto__ 被存为自身可枚举键，而非挂成原型', () => {
    const parsed = JSON.parse('{"__proto__":{"polluted":1},"safe":2}');
    const out = stripControlCharsDeep(parsed);
    // 关键：out 的原型不能被污染
    expect({}.polluted).toBeUndefined();
    // 且 '__proto__' 作为自身可枚举属性被忠实保留（审计副本 = 请求体）
    expect(Object.prototype.hasOwnProperty.call(out, '__proto__')).toBe(true);
    expect(Object.keys(out)).toContain('__proto__');
    expect(out.safe).toBe(2);
  });
});

describe('F-A5 self 数据范围进 aggregate 前须把字符串 userId 转 ObjectId（否则看板静默全 0）', () => {
  const mongoose = require('mongoose');
  const { scopeFilterFor } = require('../../services/reportExportService');

  test('纯函数：hex 字符串被转成 ObjectId；部门名/deny 哨兵不误伤', () => {
    const oid = new mongoose.Types.ObjectId();
    const self = scopeFilterFor('device', { type: 'self', userId: oid.toString() });
    // 设备 ownerField 为数组 → $or，两臂的字符串值都应被 cast
    expect(self.$or[0].createdBy instanceof mongoose.Types.ObjectId).toBe(true);
    expect(String(self.$or[0].createdBy)).toBe(oid.toString());
    // 部门名不是 ObjectId，保持字符串
    expect(scopeFilterFor('device', { type: 'department', department: 'A栋' })).toEqual({
      'location.building': 'A栋',
    });
    // deny 档：#12 后"范围不可用"即 403 DATA_SCOPE_DENIED，不再回 { _id: null } 空集
    // ——空集让调用方分不清「这个楼栋没有设备」与「这个账号没有可见范围」。
    // 形状注记：抛的是 ApiError，statusCode/code 与 errorCodes.js 单一来源一致。
    let denied;
    try {
      scopeFilterFor('device', { type: 'department', department: '' });
    } catch (err) {
      denied = err;
    }
    expect(denied).toBeDefined();
    expect(denied.message).toMatch(/没有可用的数据范围/);
    expect(denied.statusCode).toBe(403);
    expect(denied.code).toBe('DATA_SCOPE_DENIED');
    // 已是 ObjectId 实例：不变。
    // 形状注记：alarm 的属主口径现在是**数组**（reporter.userId + handler，
    // 与报警列表接口对齐），所以条件长成 `$or:[{reporter.userId},{handler}]` 而不是
    // 顶层单键——两臂的值都必须是同一个 ObjectId 实例（未被重新 cast 过）。
    const alarmSelf = scopeFilterFor('alarm', { type: 'self', userId: oid });
    expect(alarmSelf.$or[0]['reporter.userId']).toBe(oid);
    expect(alarmSelf.$or[1].handler).toBe(oid);
    // 12 位十六进制的部门/楼栋名不得被误当 ObjectId（isValidObjectId 会认 12 字符，
    // 但真正的 ObjectId 恒为 24 hex）——否则会被 cast 成一个不存在的 ObjectId → 聚合静默 0 行。
    expect(scopeFilterFor('device', { type: 'department', department: 'deadbeef0011' })).toEqual({
      'location.building': 'deadbeef0011',
    });
  });

  test('端到端：字符串 userId 的 self 范围，聚合 $match 必须命中（修复前恒为 0）', async () => {
    if (mongoose.connection.readyState === 0) await mongoose.connect(process.env.MONGODB_URI);
    const FireDevice = require('../../models/FireDevice');
    const creator = new mongoose.Types.ObjectId();
    await FireDevice.deleteMany({ createdBy: creator });
    await FireDevice.create({
      deviceName: 'x',
      deviceType: 'smoke_detector',
      installDate: new Date(),
      location: { building: 'A栋' },
      createdBy: creator,
    });
    // dataScope.userId 来自 JWT，是字符串——正是触发 bug 的形态
    const filter = scopeFilterFor('device', { type: 'self', userId: creator.toString() });
    const agg = await FireDevice.aggregate([{ $match: filter }]);
    expect(agg.length).toBe(1);
    await FireDevice.deleteMany({ createdBy: creator });
  });
});

describe('F-A6 getDataScope 停用角色不授予数据范围 + roles 数组含 null 洞不崩（#8）', () => {
  const User = require('../../models/User');
  const { getDataScope } = require('../../middleware/rbac');
  let spy;
  afterEach(() => spy && spy.mockRestore());
  const stub = (populatedUser) => {
    spy = jest
      .spyOn(User, 'findById')
      .mockReturnValue({ populate: (arg) => applyPopulate(populatedUser, arg) });
  };

  /**
   * F-208：假 populate 必须**消费它收到的实参**。原实现是
   * `populate: () => Promise.resolve(populatedUser)`——把 `rbac.js:173-181` 传进来的
   * `{ path, select, match:{status:'active'} }` 整个丢掉，于是那条 `match` 从来没被执行过：
   * 用例名叫"停用角色不授予数据范围"，实际断言与它毫无关系（**删掉 match 三条照样全绿**）。
   * 这里按 mongoose 的语义实现最小可信版本：只保留满足 `match` 的角色。
   * 关键点是**筛选条件来自被测方**——判据不再是测试自己写死的期望，
   * 而是"rbac 到底传了什么"，所以 rbac 那行被删时本文件必须翻红（见最后一条用例）。
   * null 洞不参与 match（`!r` 直接放行）：它们要留给 rbac 的 `filter(Boolean)` 去消化，
   * 那才是这两条防御用例真正的靶子。
   */
  const applyPopulate = (user, arg) => {
    const match = arg && arg.match;
    const roles = (user.roles || []).filter(
      (r) => !r || !match || Object.keys(match).every((k) => r[k] === match[k])
    );
    return Promise.resolve({ ...user, roles });
  };

  // 注：实测 mongoose 8.24.1 的 populate+match **不会**产生 null 洞（见 populateMatchShape.test.js）。
  // 下面两条用例注入字面 null，验证 filter(Boolean) 这层**防御性冗余**在将来版本改为留 null 时仍成立。
  test('active L4 + roles 数组含 null 洞（防御）→ 取 L4 得 self，且不因 null.level 抛错', async () => {
    stub({ department: 'D', roles: [{ level: 4, status: 'active' }, null] });
    expect(await getDataScope('uid')).toEqual({ type: 'self', userId: 'uid' });
  });

  test('roles 全为 null 洞（防御）→ none（deny），fail-closed', async () => {
    stub({ department: 'D', roles: [null, null] });
    expect(await getDataScope('uid')).toEqual({ type: 'none' });
  });

  test('有效 active L9 → all（正常范围不被误伤）', async () => {
    stub({ department: 'D', roles: [{ level: 9, status: 'active' }] });
    expect(await getDataScope('uid')).toEqual({ type: 'all' });
  });

  test('F-208 牙齿：停用（status:inactive）的 L9 角色必须换不来 all —— 删掉 rbac 的 match 这条就红', async () => {
    stub({ department: 'D', roles: [{ level: 9, status: 'inactive' }] });
    // 停用 SUPER_ADMIN 后仍返回 {type:'all'} 是当初的缺陷本体：10+ 处列表/统计/报表照常全量放行
    expect(await getDataScope('uid')).toEqual({ type: 'none' });
    // 反向对照（防空泛）：把 status 改回 active，同一夹具必须得到 all
    stub({ department: 'D', roles: [{ level: 9, status: 'active' }] });
    expect(await getDataScope('uid')).toEqual({ type: 'all' });
  });
});

describe('F-A7 Inspection.description/priority 不再被 strict 模式静默丢弃（P3-14 兑现）', () => {
  const Inspection = require('../../models/Inspection');

  test('路由/服务放行的 description/priority 真正进入文档', () => {
    const doc = new Inspection({
      title: '月度巡检',
      inspectionType: 'monthly',
      description: '  含泵房与配电室  ',
      priority: 'high',
    });
    // 修复前：schema 未声明 → strict 模式丢弃 → 这两个字段为 undefined
    expect(doc.priority).toBe('high');
    // trim 生效
    expect(doc.description).toBe('含泵房与配电室');
    // 仍可校验长度上限（路由 max 500/20 与 schema 对齐）
    const tooLong = new Inspection({
      title: 't',
      inspectionType: 'daily',
      priority: 'x'.repeat(21),
    });
    expect(tooLong.validateSync().errors.priority).toBeDefined();
  });
});

describe('F-A8 getDataScope 的 jsdoc 阈值必须与 LEVEL_* 常量同源（文档漂移门禁，F-209）', () => {
  /**
   * 为什么值得为注释立一道闸（不是洁癖）：
   * LEVEL_SELF 从 5 下调到 4 那次（种子角色 FIREFIGHTER=4 落入 none 档的缺陷修复）只改了代码，
   * 函数头 jsdoc 至今写着 "level >= 5"。数据范围阈值是安全语义：一个新人照注释配角色，
   * 会得出与运行时完全不同的授权面，而且**没有任何测试会红**。
   *
   * 闸门的自证结构（防"闸门本身假绿"）：
   * 两侧各自独立解析，解析不到 = null 判红。所以「把注释改写得不含数字」这种
   * 最省事的绕法会直接撞红，而不是让两个 undefined 相等而蒙混过关。
   */
  const fs = require('fs');
  const path = require('path');
  const SRC = fs
    .readFileSync(path.join(__dirname, '../../middleware/rbac.js'), 'utf8')
    .split(/\r?\n/);

  // 代码侧：`const LEVEL_XXX = <int>;`
  const codeLevel = (name) => {
    const line = SRC.find((l) => new RegExp(`^\\s*const ${name} = \\d+;`).test(l));
    return line ? Number(line.match(/=\s*(\d+)/)[1]) : null;
  };
  // 文档侧：jsdoc 里 `- <scope>: …（角色 level >= <int>）`
  const docLevel = (scope) => {
    const line = SRC.find((l) => new RegExp(`^\\s*\\*\\s*- ${scope}:.*level >= \\d+`).test(l));
    return line ? Number(line.match(/level >=\s*(\d+)/)[1]) : null;
  };

  const PAIRS = [
    ['LEVEL_ALL', 'all'],
    ['LEVEL_DEPARTMENT', 'department'],
    ['LEVEL_SELF', 'self'],
  ];

  test.each(PAIRS)('%s ↔ jsdoc "%s"：两侧都能解析到阈值（闸门不空转）', (name, scope) => {
    expect({ name, code: codeLevel(name) }).toEqual({ name, code: expect.any(Number) });
    expect({ name, doc: docLevel(scope) }).toEqual({ name, doc: expect.any(Number) });
  });

  test.each(PAIRS)('%s ↔ jsdoc "%s"：代码与文档阈值相等（改任一侧就红）', (name, scope) => {
    expect(docLevel(scope)).toBe(codeLevel(name));
  });

  test('反向对照：解析器对不存在的名字返回 null（证明上面两条的"解析不到判红"是真的会判红）', () => {
    expect(codeLevel('LEVEL_NOT_A_REAL_CONST')).toBeNull();
    expect(docLevel('nonexistent-scope')).toBeNull();
  });
});

// 收尾必须关连接：mongodb-memory-server 是所有套件共用的同一个 mongod，
// 不关的套件会让 jest worker 在 FORCE_EXIT_DELAY(500ms) 后被强杀
// （"A worker process has failed to exit gracefully"），强杀会吞掉该套件的输出。
// readyState 守卫是为了不关别人建立的连接；本条挂在根作用域，故在本套件所有
// describe 自己的 afterAll 之后才跑。这里就地 require('mongoose')：本仓有 3 个套件
// 只在 describe 体内 require，从根作用域引用那个名字会 ReferenceError。
afterAll(async () => {
  const mongoose = require('mongoose');
  if (mongoose.connection.readyState !== 0) await mongoose.connection.close();
});
