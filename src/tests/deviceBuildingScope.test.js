/**
 * 设备楼栋的部门维度闸（与巡检共用 rbac.isDepartmentValueAllowed）
 *
 * `location.building` 就是 device 的 departmentField，且在更新白名单里；
 * 而范围闸此前只看"改前这台设备在不在范围内" ⇒ 一次合法 PUT 就能把设备
 * 搬到别的楼栋（搬出后既脱离自己可见范围，又凭空出现在别的部门清单里）。
 * 创建路径同理：路由只判字符串长度。
 */
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const request = require('supertest');

const { randomPassword } = require('./helpers/buildLoginEnvelope');
const { isDepartmentValueAllowed } = require('../middleware/rbac');
const DEVICE_TYPE = Object.values(require('../utils/constants').DEVICE_TYPE)[0];

const DEPT_A = 'ZZDB-A';
const DEPT_B = 'ZZDB-B';
const stamp = `zzdb${Date.now()}`.replace(/[^a-z0-9]/g, '').slice(0, 8);

describe('rbac.isDepartmentValueAllowed 档位真值表', () => {
  test.each([
    ['all 不限', { type: 'all' }, DEPT_B, true],
    ['department 命中', { type: 'department', department: DEPT_A }, DEPT_A, true],
    ['department 不命中', { type: 'department', department: DEPT_A }, DEPT_B, false],
    ['department 但本人未配置部门 ⇒ deny', { type: 'department', department: '' }, DEPT_A, false],
    // 这一行才真正区分"要求已配置部门"与"只做等值比较"：两边都是空值时等值比较会放行
    [
      'department 未配置且值也为空 ⇒ 仍 deny（不得空对空互相匹配）',
      { type: 'department', department: '' },
      '',
      false,
    ],
    ['department 配置了但值为空 ⇒ deny', { type: 'department', department: DEPT_A }, '', false],
    ['self：该维度不参与 ⇒ 放行', { type: 'self', userId: 'u1' }, DEPT_B, true],
    ['none ⇒ deny', { type: 'none' }, DEPT_A, false],
    ['未识别档位 ⇒ deny（新增档位不得静默放行）', { type: 'future' }, DEPT_A, false],
    ['缺 dataScope ⇒ deny', null, DEPT_A, false],
  ])('%s', (_label, scope, value, expected) => {
    expect(isDepartmentValueAllowed(scope, value)).toBe(expected);
  });
});

describe('设备楼栋只能落在操作者自己部门', () => {
  let app;
  let FireDevice;
  let deptToken;
  let operatorId;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) await mongoose.connect(process.env.MONGODB_URI);
    const User = require('../models/User');
    const Role = require('../models/Role');
    const Permission = require('../models/Permission');
    FireDevice = require('../models/FireDevice');
    require('../models/AuditLog');
    require('../models/TokenBlacklist');

    const wildcard = await Permission.findOneAndUpdate(
      { code: '*:*' },
      { $setOnInsert: { name: '全部权限', code: '*:*', type: 'api', module: 'system' } },
      { upsert: true, new: true }
    );
    const mkRole = (code, level) =>
      Role.create({
        name: `${stamp} ${code}`,
        code: `${stamp}_${code}`.toUpperCase().replace(/[^A-Z0-9_]/g, '_'),
        level,
        permissions: [wildcard._id],
      });
    const deptRole = await mkRole('DEPT', 7);
    const operator = await User.create({
      username: `${stamp}_op`,
      email: `${stamp}_op@example.com`,
      password: randomPassword(),
      department: DEPT_A,
      roles: [deptRole._id],
    });
    operatorId = String(operator._id);
    deptToken = jwt.sign(
      { userId: operatorId, username: operator.username, tokenVersion: operator.tokenVersion ?? 0 },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );
    const { createApp } = require('../app');
    app = createApp();
  });

  afterAll(async () => {
    await FireDevice.deleteMany({ deviceCode: new RegExp(`^${stamp.toUpperCase()}`) }).catch(
      () => {}
    );
    if (mongoose.connection.readyState !== 0) await mongoose.connection.close();
  });

  const createDevice = (tag, extra) =>
    request(app)
      .post('/api/devices')
      .set('Authorization', `Bearer ${deptToken}`)
      .send({
        deviceCode: `${stamp.toUpperCase()}-${tag}`,
        deviceName: `${stamp} 设备`,
        deviceType: DEVICE_TYPE,
        installDate: '2026-01-01',
        ...extra,
      });

  test('在其他楼栋登记设备：403 且不落库', async () => {
    const res = await createDevice('BAD', { building: DEPT_B });
    expect(res.status).toBe(403);
    expect(res.body.errors.errorCode).toBe('DEVICE_OPERATE_FORBIDDEN');
    expect(await FireDevice.countDocuments({ deviceCode: `${stamp.toUpperCase()}-BAD` })).toBe(0);
  });

  test('反向对照：本部门楼栋可登记；不填楼栋也可登记', async () => {
    const ok = await createDevice('OWN', { building: DEPT_A });
    expect(ok.status).toBe(201);
    const blank = await createDevice('BLANK', {});
    expect(blank.status).toBe(201);
  });

  test('更新判新值：把他楼栋写进 location 被拒且数据未变', async () => {
    const created = await createDevice('MOV', { building: DEPT_A });
    expect(created.status).toBe(201);
    const id = created.body.data._id || created.body.data.id;

    const res = await request(app)
      .put(`/api/devices/${id}`)
      .set('Authorization', `Bearer ${deptToken}`)
      .send({ location: { building: DEPT_B } });
    expect(res.status).toBe(403);
    const after = await FireDevice.findById(id).lean();
    expect(after.location.building).toBe(DEPT_A);
  });

  test('原样回传同一楼栋不算搬迁（不得误伤整对象回传的客户端）', async () => {
    const created = await createDevice('ECHO', { building: DEPT_A });
    const id = created.body.data._id || created.body.data.id;
    const res = await request(app)
      .put(`/api/devices/${id}`)
      .set('Authorization', `Bearer ${deptToken}`)
      .send({ location: { building: DEPT_A, floor: '3F' } });
    expect(res.status).toBe(200);
    const after = await FireDevice.findById(id).lean();
    expect(after.location.building).toBe(DEPT_A);
    expect(after.location.floor).toBe('3F');
  });
});
