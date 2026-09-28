/**
 * 路由校验面与模型约束面的字段级对账（防止"接口回 2xx、数据被静默剥离"）
 *
 * 本仓的路由用 express-validator 声明字段，模型用 Mongoose schema 声明同一批字段，
 * 两边各写各的、没有任何机制保证一致。已经实测过一次真实断裂：
 *   alarmRoutes 校验 `location.detail` ≤200 并且原样转发给 FireAlarm.create，
 *   但 FireAlarm.location 下没有 detail 子路径 ⇒ strict 模式把它**静默剥离**：
 *   接口回 201、"靠东侧消防箱内"这类信息永久丢失，且没有任何日志。
 * 同一类断裂还有反方向：schema 的 maxlength 比路由上限更小时，路由放行的值会由
 * DB 抛出**点不出字段名**的 400（errorHandler 在非 development 下抹掉 fieldErrors）。
 *
 * 因此本文件对每条写入链做三格对账，全部从**路由源码**里解析字段，不手写清单：
 *   ① 路由校验过的字段，模型必须有同名 schema path；
 *   ② 模型若声明了 maxlength，不得小于路由上限；
 *   ②b 同一字段在多条写入链上的上限必须同宽，且必须等于模型 maxlength（见下）；
 *   ③ 合法值必须真的落库（回读原始文档，绕开 getter/lean 的任何美化）。
 * 解析驱动意味着"新增一条校验规则"会自动进入对账：漏配 schema 立刻变红，
 * 而不是等某个接口悄悄丢字段。
 *
 * ②b 补的是 ② 的反方向，而且它对应一类真实数据（本仓实测）：`model` 在 create 链
 * 与模型上都是 100，唯独 update 链写死 50。② 只判"schema 严于路由"，于是这条断裂
 * 一路绿着——而它的后果不是报错，是**死数据**：用 API 建出来的 51~100 字符型号合法
 * 入库，前端编辑页整表提交时永远 400，那条记录从此改不动，也没有任何日志说明为什么。
 */

const fs = require('fs');
const path = require('path');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const request = require('supertest');
const { randomPassword } = require('../helpers/buildLoginEnvelope');

const ROOT = path.join(__dirname, '..', '..');
const stamp = `pc${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);
const PASSWORD = randomPassword();

/**
 * 从路由源码里切出 `const <name> = [ ... ];` 整段，再按 `body('x')` 分块，
 * 每块取字段名与该块内的 `isLength({ max: N })`。
 * 只认 body()：query()/param() 校验的是查询串和路径参数，本来就不入库。
 */
function parseValidationChain(routeFile, constName) {
  const src = fs.readFileSync(path.join(ROOT, 'routes', routeFile), 'utf8').replace(/\r\n/g, '\n');
  const start = src.indexOf(`const ${constName} = [`);
  if (start === -1) throw new Error(`路由源码里找不到常量 ${constName}（改名了吗？）`);
  const end = src.indexOf('\n];', start);
  if (end === -1) throw new Error(`常量 ${constName} 的数组结尾没找到`);
  const body = src.slice(start, end);
  const opens = [...body.matchAll(/body\('([^']+)'\)/g)];
  return opens.map((m, i) => {
    const chunk = body.slice(m.index, opens[i + 1] ? opens[i + 1].index : body.length);
    const max = chunk.match(/isLength\(\{[^}]*\bmax:\s*(\d+)/);
    return { field: m[1], max: max ? Number(max[1]) : null };
  });
}

/**
 * 模型侧声明的字符串上限。Mongoose 允许 `[100, '型号最多 100 个字符']` 的元组形态，
 * 直接拿去当数字用会得到一个数组（首轮实跑即因此造出 `model: ''` 的设备，
 * 把"合法宽度"测成了空串）——归一必须在这里做一次，而不是每个用例各抄一遍。
 */
const schemaMaxLength = (model, field) => {
  const declared = model.schema.path(field)?.options?.maxlength;
  return Array.isArray(declared) ? declared[0] : declared;
};

describe('写入链字段与模型 schema 的对账', () => {
  /**
   * `*` 结尾的元素级规则（images.*）不参与 schema path 对账——Mongoose 的数组
   * 元素约束不是 schema path；它由本文件的第 ③ 格（真的落库）与
   * locationCoordinatesBoundary.test.js 的长度用例共同覆盖。
   *
   * 顶层 building/floor/room 是"控制字段"：模型里没有这三个 path，控制器把它们
   * 并入 location（deviceController.js 的 `...location` 合并）。这个豁免不是空口
   * 说的——下面的"顶层楼栋并入 location"用例真的提交并回读，豁免失效时它会先变红。
   */
  const MERGED_TOP_LEVEL = new Set(['building', 'floor', 'room']);

  const CHAINS = [
    { routeFile: 'alarmRoutes.js', constName: 'reportAlarmValidation', modelName: 'FireAlarm' },
    { routeFile: 'deviceRoutes.js', constName: 'createDeviceValidation', modelName: 'FireDevice' },
    { routeFile: 'deviceRoutes.js', constName: 'updateDeviceValidation', modelName: 'FireDevice' },
  ];

  let User;
  let Role;
  let Permission;
  let FireAlarm;
  let FireDevice;
  let app;
  let token;

  const auth = () => ({ Authorization: `Bearer ${token}` });
  const tokenFor = (userId, username) =>
    jwt.sign({ userId: String(userId), username, tokenVersion: 0 }, process.env.JWT_SECRET, {
      expiresIn: '1h',
    });

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    Role = require('../../models/Role');
    Permission = require('../../models/Permission');
    FireAlarm = require('../../models/FireAlarm');
    FireDevice = require('../../models/FireDevice');

    const wildcard = await Permission.findOneAndUpdate(
      { code: '*:*' },
      { $setOnInsert: { name: '全部权限', code: '*:*', type: 'api', module: 'system' } },
      { upsert: true, new: true }
    );
    let superRole = await Role.findOne({ code: 'SUPER_ADMIN' });
    if (!superRole) {
      superRole = await Role.create({
        name: '超级管理员',
        code: 'SUPER_ADMIN',
        level: 10,
        permissions: [wildcard._id],
      });
    }
    const operator = await User.create({
      username: `${stamp}op`,
      email: `${stamp}op@example.com`,
      password: PASSWORD,
      roles: [superRole._id],
    });
    token = tokenFor(operator._id, operator.username);
    app = require('../../app').createApp();
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  // ==================== 解析器本身必须先自证 ====================
  test('解析器前提：每条链都能解析出字段，且 location.detail 在列（防解析退化成套空）', () => {
    for (const c of CHAINS) {
      const fields = parseValidationChain(c.routeFile, c.constName).map((f) => f.field);
      expect(fields.length).toBeGreaterThan(3);
      // detail 是本批的真实断裂点；解析不到它就说明正则或常量名失效了
      expect(fields).toContain('location.detail');
    }
  });

  // ==================== ① + ② 字段级对账 ====================
  describe.each(CHAINS)('$constName → $modelName', ({ routeFile, constName, modelName }) => {
    test('路由校验的每个字段：模型必须有对应 schema path，且 maxlength 不得严于路由', () => {
      const model = { FireAlarm, FireDevice }[modelName];
      const parsed = parseValidationChain(routeFile, constName);
      const failures = [];
      for (const { field, max } of parsed) {
        if (field.includes('*') || MERGED_TOP_LEVEL.has(field)) continue;
        // pathType 而不是 path()：`location` 这类"容器字段"（路由只判 .isObject()）在
        // Mongoose 里是 nested 而非 schema path，用 path() 查会把它误判成缺失。
        const kind = model.schema.pathType(field);
        if (kind !== 'real' && kind !== 'nested') {
          failures.push(
            `${field}: 路由校验了它，但 ${modelName}.schema 没有这个 path（会被静默剥离）`
          );
          continue;
        }
        if (kind !== 'real') continue; // 容器无长度约束，逐格由子字段各自的规则对账
        const schemaPath = model.schema.path(field);
        const schemaMax = Array.isArray(schemaPath.options?.maxlength)
          ? schemaPath.options.maxlength[0]
          : schemaPath.options?.maxlength;
        if (max !== null) {
          // 两个方向都要闭合：只判 "schema 严于路由" 的话，schema 一旦**没声明**
          // maxlength 就整条判据不成立（删掉模型的 maxlength 用例仍绿，DB 侧无上限）。
          if (typeof schemaMax !== 'number') {
            failures.push(`${field}: 路由上限 ${max}，但 schema 未声明 maxlength（DB 侧无上限）`);
          } else if (schemaMax < max) {
            failures.push(
              `${field}: 路由上限 ${max}，schema maxlength ${schemaMax}（DB 会抛出点不出名字的 400）`
            );
          }
        }
      }
      expect({ chain: constName, failures }).toEqual({ chain: constName, failures: [] });
    });
  });

  // ==================== ②b 跨写入链的同宽对账 ====================
  /** `(model, field)` → 各条链上的上限；只收带 `isLength({max})` 的字段 */
  const capsByModelField = () => {
    const table = {};
    for (const c of CHAINS) {
      for (const { field, max } of parseValidationChain(c.routeFile, c.constName)) {
        if (max === null || field.includes('*')) continue;
        const key = `${c.modelName}.${field}`;
        table[key] = table[key] || { key, modelName: c.modelName, field, caps: {} };
        table[key].caps[c.constName] = max;
      }
    }
    return table;
  };

  /** 顶层 building/floor/room 的真实落点（控制器把它们并入 location） */
  const schemaPathOf = (field) => (MERGED_TOP_LEVEL.has(field) ? `location.${field}` : field);

  describe('②b 同一字段的多个写入口必须同宽，且都等于模型 maxlength', () => {
    test('前提自证：对账表非空且真的含跨链同名字段（否则"无冲突"是解析失效的假绿）', () => {
      const rows = Object.values(capsByModelField());
      expect(rows.length).toBeGreaterThanOrEqual(8);
      const shared = rows.filter((r) => Object.keys(r.caps).length > 1).map((r) => r.key);
      expect(shared).toEqual(
        expect.arrayContaining(['FireDevice.model', 'FireDevice.deviceName', 'FireDevice.remark'])
      );
    });

    test('链间不一致 或 与 schema 不等宽，都算断裂', () => {
      const failures = [];
      for (const row of Object.values(capsByModelField())) {
        const caps = [...new Set(Object.values(row.caps))];
        if (caps.length > 1) {
          failures.push(
            `${row.key}: 各链上限不一致 ${JSON.stringify(row.caps)}（窄的那条会让宽的那条建出来的数据改不动）`
          );
        }
        const model = { FireAlarm, FireDevice }[row.modelName];
        const schemaMax = schemaMaxLength(model, schemaPathOf(row.field));
        if (typeof schemaMax !== 'number') {
          failures.push(`${row.key}: 路由上限 ${caps.join('/')}，schema 却没声明 maxlength`);
        } else if (caps.some((c) => c !== schemaMax)) {
          failures.push(`${row.key}: 路由上限 ${caps.join('/')} ≠ schema maxlength ${schemaMax}`);
        }
      }
      expect(failures).toEqual([]);
    });

    /**
     * 上面那条只遍历"有上限的字段"，所以**把某条链上的 isLength 整条删掉**会让该字段
     * 从对账表里消失 ⇒ 三条判据一起空转。这一条按"链上出现过 body('x') 就必须有上限"
     * 反向补齐：schema 声明了 maxlength 的字段，每条接受它的链都必须自己界住长度
     * （删掉之后超限值会落到 Mongoose ValidationError，而 errorHandler 在生产环境
     * 刻意不回传字段级明细 ⇒ 又是一句点不出名字的"数据验证失败"）。
     */
    test('每条链上出现过的字符串字段：模型有 maxlength 就必须在这条链上有上限', () => {
      const failures = [];
      for (const c of CHAINS) {
        const model = { FireAlarm, FireDevice }[c.modelName];
        for (const { field, max } of parseValidationChain(c.routeFile, c.constName)) {
          if (field.includes('*') || max !== null) continue;
          const schemaMax = schemaMaxLength(model, schemaPathOf(field));
          if (typeof schemaMax === 'number') {
            failures.push(`${c.constName}.${field}: schema maxlength ${schemaMax}，链上却没有上限`);
          }
        }
      }
      expect(failures).toEqual([]);
    });
  });

  // ==================== ③ 合法值必须真的落库 ====================
  const alarmLeaves = () =>
    parseValidationChain('alarmRoutes.js', 'reportAlarmValidation')
      .map((f) => f.field)
      .filter((f) => f.startsWith('location.') && !f.includes('coordinates'))
      .map((f) => f.slice('location.'.length));

  test('报警上报：location 下被校验的每一格都必须原样落库', async () => {
    const leaves = alarmLeaves();
    expect(leaves).toContain('detail');
    const location = Object.fromEntries(leaves.map((k) => [k, `${k}-${stamp}`]));
    const description = `${stamp}desc`;
    const res = await request(app)
      .post('/api/alarms/report')
      .set(auth())
      .send({ alarmType: 'smoke', description, location });
    expect(res.status).toBeLessThan(400);
    const raw = await FireAlarm.collection.findOne({ description });
    expect(raw).not.toBeNull();
    // 整对象比对：只断言 detail 会放过"其它格子被剥了"，而本用例的口径是"没一格被剥"
    expect(raw.location).toMatchObject(location);
  });

  test('设备创建：location 下被校验的每一格都必须原样落库', async () => {
    const leaves = parseValidationChain('deviceRoutes.js', 'createDeviceValidation')
      .map((f) => f.field)
      .filter((f) => f.startsWith('location.') && !f.includes('coordinates'))
      .map((f) => f.slice('location.'.length));
    const deviceCode = `${stamp}dv1`;
    const location = Object.fromEntries(leaves.map((k) => [k, `${k}-${stamp}`]));
    const res = await request(app)
      .post('/api/devices')
      .set(auth())
      .send({
        deviceCode,
        deviceName: `${stamp}设备`,
        deviceType: 'extinguisher',
        installDate: '2025-01-01',
        location,
      });
    expect(res.status).toBeLessThan(400);
    const raw = await FireDevice.collection.findOne({ deviceCode: deviceCode.toUpperCase() });
    expect(raw).not.toBeNull();
    expect(raw.location).toMatchObject(location);
  });

  test('豁免的前提：设备顶层 building/floor/room 由控制器并入 location（不是丢字段）', async () => {
    const deviceCode = `${stamp}dv2`;
    const res = await request(app)
      .post('/api/devices')
      .set(auth())
      .send({
        deviceCode,
        deviceName: `${stamp}设备2`,
        deviceType: 'extinguisher',
        installDate: '2025-01-01',
        building: `${stamp}栋`,
        floor: `${stamp}层`,
        room: `${stamp}室`,
      });
    expect(res.status).toBeLessThan(400);
    const raw = await FireDevice.collection.findOne({ deviceCode: deviceCode.toUpperCase() });
    expect(raw.location).toMatchObject({
      building: `${stamp}栋`,
      floor: `${stamp}层`,
      room: `${stamp}室`,
    });
  });

  test('设备更新：detail 走 PUT 同样必须落库（更新链与创建链是两套字段名单）', async () => {
    const deviceCode = `${stamp}dv3`;
    const created = await FireDevice.create({
      deviceCode,
      deviceName: `${stamp}设备3`,
      deviceType: 'extinguisher',
      installDate: new Date('2025-01-01'),
    });
    const res = await request(app)
      .put(`/api/devices/${created._id}`)
      .set(auth())
      .send({ location: { detail: `${stamp}靠东侧消防箱内` } });
    expect(res.status).toBeLessThan(400);
    const raw = await FireDevice.collection.findOne({ _id: created._id });
    expect(raw.location?.detail).toBe(`${stamp}靠东侧消防箱内`);
  });

  /**
   * ③ 的另一半：合法值不只是"长值能写进去"，还包括**空值写得出去**。
   * 更新链对 location 按子字段合并 ⇒ 缺键＝保持原值，于是"清空"唯一的表达方式是空串
   * （undefined 在 JSON.stringify 那一步就蒸发成缺键）。整条链必须在空串上闭合：
   * 路由得放行它（这几格只有 isString + isLength，空串合法），服务得真的写回空串。
   * 任一环把空串当"没提"处理，本用例立刻转红，而不是等用户在编辑页发现"删不掉"。
   */
  test('设备更新的清空指令：location 每一格都能被空串清掉，未提及的键不受影响', async () => {
    const leaves = parseValidationChain('deviceRoutes.js', 'updateDeviceValidation')
      .map((f) => f.field)
      .filter((f) => f.startsWith('location.') && !f.includes('coordinates'))
      .map((f) => f.slice('location.'.length));
    expect(leaves).toContain('detail');

    const deviceCode = `${stamp}dv7`;
    const filled = Object.fromEntries(leaves.map((k) => [k, `${k}-${stamp}`]));
    const created = await FireDevice.create({
      deviceCode,
      deviceName: `${stamp}设备7`,
      deviceType: 'extinguisher',
      installDate: new Date('2025-01-01'),
      location: { ...filled, coordinates: { lat: 31.1, lng: 121.1 } },
    });
    for (const k of leaves) expect(created.location[k]).toBe(filled[k]); // 起点自证

    const res = await request(app)
      .put(`/api/devices/${created._id}`)
      .set(auth())
      .send({ location: Object.fromEntries(leaves.map((k) => [k, ''])) });
    expect(res.status).toBeLessThan(400);

    const raw = await FireDevice.collection.findOne({ _id: created._id });
    const notCleared = leaves.filter((k) => raw.location[k] !== '');
    expect({ notCleared, stored: leaves.map((k) => raw.location[k]) }).toEqual({
      notCleared: [],
      stored: leaves.map(() => ''),
    });
    // 清空不是"顺手重置"：载荷里没提的 coordinates 必须一格不少
    expect(raw.location.coordinates).toMatchObject({ lat: 31.1, lng: 121.1 });
  });

  /**
   * ②b 的行为面：宽度的**唯一**事实来源是模型，所以"模型允许的长度"必须同时是
   * 创建与更新两条链允许的长度。修复前这条是 400（update 链 50 < 模型 100），
   * 而 400 来自校验层 ⇒ 用户看到的是"这个字段填不了这么长"，库里却明明存着这么长。
   */
  test('设备：模型上限那么宽的型号，创建之后还能原样更新（整表提交不是死数据）', async () => {
    const deviceCode = `${stamp}dv4`;
    const widest = schemaMaxLength(FireDevice, 'model');
    // 前提自证：宽度确实是从模型取到的正整数（元组形态没归一时它会是个数组，
    // 'M'.repeat(数组) 静默得到空串 ⇒ 整条用例其实在测空值）
    expect(Number.isInteger(widest)).toBe(true);
    expect(widest).toBeGreaterThanOrEqual(20);
    const wideModel = 'M'.repeat(widest);
    const created = await request(app)
      .post('/api/devices')
      .set(auth())
      .send({
        deviceCode,
        deviceName: `${stamp}设备4`,
        deviceType: 'extinguisher',
        installDate: '2025-01-01',
        model: wideModel,
      });
    expect(created.status).toBeLessThan(400);
    const raw = await FireDevice.collection.findOne({ deviceCode: deviceCode.toUpperCase() });
    expect(raw.model).toHaveLength(widest);

    // 编辑页 submitForm 是整表提交：把刚存进去的值原样带回去必须仍然合法
    const updated = await request(app)
      .put(`/api/devices/${raw._id}`)
      .set(auth())
      .send({
        deviceName: `${stamp}设备4改`,
        deviceType: 'extinguisher',
        installDate: '2025-01-01',
        model: wideModel,
      });
    expect(updated.status).toBeLessThan(400);
    expect((await FireDevice.collection.findOne({ _id: raw._id })).model).toBe(wideModel);
  });

  test('反向保护：收口不等于取消——超过模型上限一个字符仍被拒绝，且不留下半个字节', async () => {
    // 用例自带数据：不依赖上一条先跑（文件内用例顺序耦合会让随机种子下偶发红）
    const widest = schemaMaxLength(FireDevice, 'model');
    const deviceCode = `${stamp}dv5`;
    const created = await FireDevice.create({
      deviceCode,
      deviceName: `${stamp}设备5`,
      deviceType: 'extinguisher',
      installDate: new Date('2025-01-01'),
      model: 'M'.repeat(widest),
    });
    const over = 'M'.repeat(widest + 1);

    const viaCreate = await request(app)
      .post('/api/devices')
      .set(auth())
      .send({
        deviceCode: `${stamp}dv6`,
        deviceName: `${stamp}设备6`,
        deviceType: 'extinguisher',
        installDate: '2025-01-01',
        model: over,
      });
    expect(viaCreate.status).toBeGreaterThanOrEqual(400);

    const viaUpdate = await request(app)
      .put(`/api/devices/${created._id}`)
      .set(auth())
      .send({ model: over });
    expect(viaUpdate.status).toBeGreaterThanOrEqual(400);
    // 被拒的这次 PUT 不能改动任何已存值
    expect((await FireDevice.collection.findOne({ _id: created._id })).model).toHaveLength(widest);
  });
});
