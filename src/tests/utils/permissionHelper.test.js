/**
 * 层级校验 helper 测试（报告 O-13：getOperatorMaxLevel / maxRoleLevel 单一事实来源）
 *
 * 重点保护历史语义：空角色数组 → -Infinity（fail-closed：无角色操作者
 * 不得执行任何层级操作）；undefined → 0。改写为 0 是安全回归。
 */

const mongoose = require('mongoose');
const { randomPassword } = require('../helpers/buildLoginEnvelope');

describe('层级校验 helper（O-13）', () => {
  let User;
  let Role;
  let permissionHelper;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    Role = require('../../models/Role');
    permissionHelper = require('../../utils/permissionHelper');
  });

  // 清理挪入 afterAll（此前写在用例断言之后）：断言一失败，LV_A_*/LV_B_* 角色与
  // lvl_user_* 用户就残留库中。用例内只登记，无论成败统一回收。
  const createdRoleIds = [];
  const createdUserIds = [];

  afterAll(async () => {
    try {
      if (mongoose.connection.readyState !== 0) {
        await User.deleteMany({ _id: { $in: createdUserIds } }).catch(() => {});
        await Role.deleteMany({ _id: { $in: createdRoleIds } }).catch(() => {});
      }
    } finally {
      if (mongoose.connection.readyState !== 0) {
        await mongoose.connection.close();
      }
    }
  });

  describe('maxRoleLevel 纯函数语义', () => {
    test('正常角色集合取最高层级', () => {
      expect(permissionHelper.maxRoleLevel([{ level: 4 }, { level: 8 }, { level: 1 }])).toBe(8);
    });

    test('level 缺失按 0 参与计算', () => {
      expect(permissionHelper.maxRoleLevel([{}, { level: 3 }])).toBe(3);
    });

    test('空数组返回 -Infinity（fail-closed：无角色操作者低于一切层级）', () => {
      expect(permissionHelper.maxRoleLevel([])).toBe(-Infinity);
    });

    test('undefined/null 返回 0（与历史内联实现的 `|| [0]` 兜底一致）', () => {
      expect(permissionHelper.maxRoleLevel(undefined)).toBe(0);
      expect(permissionHelper.maxRoleLevel(null)).toBe(0);
    });
  });

  describe('getOperatorMaxLevel', () => {
    test('按用户实时角色计算最高层级', async () => {
      const stamp = Date.now();
      const roleA = await Role.create({ name: '层级A', code: `LV_A_${stamp}`, level: 4 });
      const roleB = await Role.create({ name: '层级B', code: `LV_B_${stamp}`, level: 8 });
      const user = await User.create({
        username: `lvl_user_${stamp}`,
        email: `lvl_${stamp}@example.com`,
        password: randomPassword(),
        roles: [roleA._id, roleB._id],
      });

      createdRoleIds.push(roleA._id, roleB._id);
      createdUserIds.push(user._id);

      const maxLevel = await permissionHelper.getOperatorMaxLevel(String(user._id));
      expect(maxLevel).toBe(8);
    });

    test('用户不存在返回 0（undefined 路径）', async () => {
      const maxLevel = await permissionHelper.getOperatorMaxLevel(
        String(new mongoose.Types.ObjectId())
      );
      expect(maxLevel).toBe(0);
    });
  });
});
