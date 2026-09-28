/**
 * 仪表盘缓存的三条口径（reportDashboardService.js）
 *
 * 命中路径与计算路径唯一的对外差别是 `message` 里那句"（缓存命中）"。
 * 而既有覆盖只比过两次调用的 `body.data` 全等
 * （`src/tests/controllers/reportExport.test.js` 的"首次计算 + 二次命中缓存"），
 * 于是这三件事一层防护都没有：
 *   ① 命中/计算两条分支可区分——把命中分支的文案写成同一句，
 *      线上就再也分不出"这份数字是刚算的还是 30 秒前留下的"，
 *      而仪表盘是审计口径的看板，这个区别正是运维要看的；
 *   ② 缓存键含**范围指纹**——键是 `dash:<userId>:sha1(filters)`。
 *      若哪天有人把指纹省成 `dash:<userId>`，被调走部门的用户会在一个 TTL 窗口里
 *      继续拿到**原部门**的统计数字：范围变更不生效期，且响应体看不出它是缓存来的
 *      （①坏了就连②都无从察觉，两条要分别钉）；
 *   ③ `type:'none'` 在缓存之前就短路返回空看板——它不得占用缓存，
 *      也不得因为别人先算过而报"命中"。
 *
 * 三个用例各用独立用户，互不共享缓存条目（键含 userId），因此不依赖执行顺序。
 */
const mongoose = require('mongoose');
const { getDashboardData } = require('../services/reportDashboardService');
const { randomPassword } = require('./helpers/buildLoginEnvelope');

const CACHE_HIT = '（缓存命中）';
const stamp = `dc${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);
const BUILDING_A = `BLDDC${stamp}A`;
const BUILDING_B = `BLDDC${stamp}B`;

describe('仪表盘缓存的命中可区分 / 范围指纹 / none 不占缓存', () => {
  let User;
  let Role;
  let FireDevice;
  let deptRole;
  let noneRole;
  const created = { users: [], roles: [], docs: [] };

  const mkUser = async (tag, department, role) => {
    const u = await User.create({
      username: `dcu${stamp}_${tag}`,
      email: `dcu${stamp}_${tag}@example.com`,
      password: randomPassword(),
      department,
      roles: [role._id],
    });
    created.users.push(u._id);
    return String(u._id);
  };

  /** 在指定楼栋落一条设备；返回文档 id 以便收尾删除 */
  const seedDevice = async (building) => {
    const d = await FireDevice.create({
      deviceCode: `DDC-${stamp}-${building.slice(-1)}`,
      deviceName: '缓存口径设备',
      deviceType: 'hydrant',
      status: 'normal',
      installDate: new Date(),
      expiryDate: new Date(Date.now() + 30 * 86400000),
      location: { building },
    });
    created.docs.push(d._id);
    return d;
  };

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../models/User');
    Role = require('../models/Role');
    FireDevice = require('../models/FireDevice');
    // department 档（level 7）：范围 = 自己的部门；无权限也够用，本文件直连服务层
    deptRole = await Role.create({
      name: `缓存部门角色_${stamp}`,
      code: `DC_DEPT_${stamp}`,
      level: 7,
      isBuiltIn: false,
      permissions: [],
    });
    noneRole = await Role.create({
      name: `缓存无档角色_${stamp}`,
      code: `DC_NONE_${stamp}`,
      level: 1,
      isBuiltIn: false,
      permissions: [],
    });
    created.roles.push(deptRole._id, noneRole._id);
    await seedDevice(BUILDING_A);
  });

  afterAll(async () => {
    await FireDevice.deleteMany({ _id: { $in: created.docs } }).catch(() => {});
    await User.deleteMany({ _id: { $in: created.users } }).catch(() => {});
    await Role.deleteMany({ _id: { $in: created.roles } }).catch(() => {});
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  test('同一用户同一范围：第二次必须声明缓存命中，且数字与首次全等', async () => {
    const userId = await mkUser('hit', BUILDING_A, deptRole);
    const first = await getDashboardData(userId);
    expect(first.message).not.toContain(CACHE_HIT);
    expect(first.data.devices.total).toBe(1);

    const second = await getDashboardData(userId);
    expect(second.message).toContain(CACHE_HIT);
    expect(second.data).toEqual(first.data);
  });

  test('范围变了必须重算：被调走部门的人不得继续拿到原部门的数字', async () => {
    const userId = await mkUser('moved', BUILDING_A, deptRole);
    const before = await getDashboardData(userId);
    expect(before.message).not.toContain(CACHE_HIT);
    expect(before.data.devices.total).toBe(1);

    await User.updateOne({ _id: userId }, { $set: { department: BUILDING_B } });
    const after = await getDashboardData(userId);
    // 缓存键含范围指纹 ⇒ 这是一次真算，而不是把旧部门的数字发出去
    expect(after.message).not.toContain(CACHE_HIT);
    expect(after.data.devices.total).toBe(0);
    // 反向对照：旧数字确实还在缓存里能被命中，说明上一行不是因为"缓存整体失效"才绿
    await User.updateOne({ _id: userId }, { $set: { department: BUILDING_A } });
    const back = await getDashboardData(userId);
    expect(back.message).toContain(CACHE_HIT);
    expect(back.data.devices.total).toBe(1);
  });

  test('type:none 在缓存之前短路：两次都是未命中文案且恒为空看板', async () => {
    const userId = await mkUser('none', BUILDING_A, noneRole);
    const first = await getDashboardData(userId);
    const second = await getDashboardData(userId);
    for (const res of [first, second]) {
      expect(res.message).not.toContain(CACHE_HIT);
      expect(res.data.devices.total).toBe(0);
      expect(res.data.alarms.total).toBe(0);
      expect(res.data.inspections.total).toBe(0);
    }
  });
});
