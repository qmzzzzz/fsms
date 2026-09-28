/**
 * 权限码对账：路由要求的码必须"可被授予"，目录里的码必须有去处
 *
 * 为什么这是一条门禁而不是一次性修补：
 * 权限文档表（initData 的 defaultPermissions）是角色编辑页唯一的可勾选来源，
 * 而路由侧的 checkPermission('x') 只要写错一个字符，那个接口就变成
 * "除了 *:* 超级管理员，谁都永远拿不到"——403 看起来像运维配漏了，
 * 实际是目录里压根没有这个可授予项。反方向同样糟：目录里留着一个没有任何
 * 判据使用的码，运维会以为"给了这个权限就能做某事"，给了之后仍然 403。
 *
 * 本文件同时钉两个方向，并把已知的一处一侧不一致**显式列成带理由的例外**：
 * 例外清单是精确集合（成员与条数都断言），所以它不会因为"再加一条就绿了"而悄悄长大。
 *
 * 可证伪性：
 *  - 删掉 initData 里任一 permission:create/update/delete 条目 ⇒ 第 1 条用例红；
 *  - 给某个路由新增一个目录里不存在的码 ⇒ 第 1 条用例红；
 *  - 目录里新增一个无人使用的码而不进例外清单 ⇒ 第 2 条用例红；
 *  - 第 3 条端到端用例证明"补齐之后真的能授权"（不是只让文本对账变绿）。
 */

'use strict';

const fs = require('fs');
const path = require('path');

const mongoose = require('mongoose');
const request = require('supertest');
const jwt = require('jsonwebtoken');

const { defaultPermissions } = require('../../services/initData');
const { randomPassword } = require('../helpers/buildLoginEnvelope');

const ROOT = path.resolve(__dirname, '../..');
const SCAN_DIRS = ['routes', 'controllers', 'middleware'];

/** 从源码里收集被要求的权限码，返回 code → 出现位置 */
function collectRequiredCodes() {
  const required = new Map();
  const files = [];
  for (const dir of SCAN_DIRS) {
    const abs = path.join(ROOT, dir);
    for (const f of fs.readdirSync(abs)) {
      if (!f.endsWith('.js')) continue;
      files.push({ name: `src/${dir}/${f}`, text: fs.readFileSync(path.join(abs, f), 'utf8') });
    }
  }
  for (const { name, text } of files) {
    text.split(/\r?\n/).forEach((line, i) => {
      const codes = [
        ...[
          ...line.matchAll(
            /(?:checkPermission|requirePermission|hasPermission|requireAnyPermission)\(\s*'([^']+)'/g
          ),
        ].map((m) => m[1]),
        ...[
          ...line.matchAll(
            /(?:checkPermission|requirePermission|hasAnyPermission|hasPermission)\(\s*\[([^\]]*)\]/g
          ),
        ].flatMap((m) => [...m[1].matchAll(/'([^']+)'/g)].map((q) => q[1])),
      ];
      for (const code of codes) {
        if (!required.has(code)) required.set(code, []);
        required.get(code).push(`${name}:${i + 1}`);
      }
    });
  }
  return required;
}

const required = collectRequiredCodes();
const catalogCodes = new Set(defaultPermissions.map((p) => p.code));

describe('权限码对账（目录 ↔ 判据）', () => {
  test('前提：扫描确实覆盖了路由与控制器（否则下面的对账是空集假绿）', () => {
    expect(required.size).toBeGreaterThan(25);
    expect(required.has('role:create')).toBe(true);
    expect(required.has('permission:create')).toBe(true);
  });

  test('[A] 被路由/控制器要求的码，必须存在于权限目录里（可授予性）', () => {
    const ungrantable = [...required.keys()]
      .filter((code) => code !== '*:*' && !catalogCodes.has(code))
      .map((code) => `${code} ← ${required.get(code).slice(0, 2).join(', ')}`)
      .sort();
    expect(ungrantable).toEqual([]);
  });

  // 目录里有、但没有任何判据使用的码。逐条给出理由；清单是精确集合。
  const KNOWN_UNENFORCED = {
    '*:*': '超级管理员通配，本身就是"所有判据的兜底"，不会出现在单个路由上',
    'device:scrap':
      '设备报废端点当前要求 device:update（routes/deviceRoutes.js 的 scrap 路由），这个码无人执行；改成要求它是**授权面变更**（FIRE_SUPERVISOR 已持有它），需人工裁定，见 §8 开放项',
    'alarm:stats': '报警统计端点走 alarm:read，此码为前端菜单/报表占位，无判据使用',
    'device:stats': '设备统计端点走 device:read，此码同上',
    'user:assign_role':
      '分配角色的端点要求 user:update（并另有层级校验），此码无人执行；同样属"给了也不生效"的历史遗留',
  };

  test('[B] 目录里无人使用的码必须逐条有理由（不得悄悄扩清单）', () => {
    const apiCodes = defaultPermissions.filter((p) => p.type !== 'menu').map((p) => p.code);
    const unenforced = [...new Set(apiCodes)].filter((c) => !required.has(c)).sort();
    expect(unenforced).toEqual(Object.keys(KNOWN_UNENFORCED).sort());
    // 每条理由必须是"能拿去问人的具体句子"，不接受空串或占位
    for (const code of unenforced) {
      expect((KNOWN_UNENFORCED[code] || '').length).toBeGreaterThan(10);
    }
  });

  test('[C] 新补的三条权限文档字段完整（角色树按这些字段渲染与授权）', () => {
    for (const code of ['permission:create', 'permission:update', 'permission:delete']) {
      const doc = defaultPermissions.find((p) => p.code === code);
      expect(doc).toBeTruthy();
      expect({ name: doc.name, type: doc.type, module: doc.module, method: doc.method }).toEqual({
        name: expect.any(String),
        type: 'api',
        module: 'system',
        method: expect.stringMatching(/^(POST|PUT|DELETE)$/),
      });
      expect(doc.path).toMatch(/^\/api\/permissions/);
    }
    // 目录内不得有重复码（重复会让 upsert 静默覆盖，前端树出现两个同名项）
    const codes = defaultPermissions.map((p) => p.code);
    const dupes = [...new Set(codes.filter((c, i) => codes.indexOf(c) !== i))].sort();
    expect(dupes).toEqual([]);
  });
});

describe('补齐之后：授予 permission:create 的角色真的能创建权限', () => {
  let app;
  let Permission;
  let Role;
  let User;
  const tag = `pcp${Date.now().toString(36)}`;
  const created = { users: [], roles: [], perms: [] };

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    Permission = require('../../models/Permission');
    Role = require('../../models/Role');
    User = require('../../models/User');
    const { createApp } = require('../../app');
    app = createApp();
  });

  afterAll(async () => {
    if (created.users.length) await User.deleteMany({ _id: { $in: created.users } });
    if (created.roles.length) await Role.deleteMany({ _id: { $in: created.roles } });
    if (created.perms.length) await Permission.deleteMany({ _id: { $in: created.perms } });
    if (mongoose.connection.readyState !== 0) await mongoose.connection.close();
  });

  let seq = 0;
  const seedActor = async (codes) => {
    seq += 1;
    const perms = [];
    for (const code of codes) {
      const doc = defaultPermissions.find((p) => p.code === code) || {};
      const perm = await Permission.create({
        code,
        name: doc.name || code,
        type: doc.type || 'api',
        module: doc.module || 'system',
      });
      perms.push(perm);
      created.perms.push(perm._id);
    }
    const role = await Role.create({
      name: `${tag}${seq}-role`,
      code: `${tag.toUpperCase()}${seq}_ROLE`,
      level: 5,
      permissions: perms.map((p) => p._id),
    });
    created.roles.push(role._id);
    const user = await User.create({
      username: `${tag}u${seq}`,
      email: `${tag}u${seq}@example.com`,
      password: randomPassword(),
      roles: [role._id],
    });
    created.users.push(user._id);
    const token = jwt.sign(
      { userId: String(user._id), username: user.username, tokenVersion: 0, type: 'access' },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
    return token;
  };

  // 路由校验器要求的形态：^(\*|[a-z]+):(\*|[a-z_]+)$ —— 带数字的编码会被 400 挡在门外，
  // 与本用例要证明的东西无关，所以这里用纯字母编码
  const NEW_CODE = 'zzparity:customperm';

  test('持有 permission:create 的角色可创建权限（此前该码无法被授予，必然 403）', async () => {
    const token = await seedActor(['permission:create']);
    const res = await request(app)
      .post('/api/permissions')
      .set('Authorization', `Bearer ${token}`)
      .send({ name: '对账用新权限', code: NEW_CODE, type: 'api', module: 'system' });
    const createdId = res.body?.data?._id;
    if (createdId) created.perms.push(createdId);
    expect({ status: res.status, errors: res.body?.errors }).toEqual({
      status: 201,
      errors: undefined,
    });
    expect(createdId).toBeTruthy();
  });

  test('未持有该码的角色仍被拒（补齐目录不等于放开授权）', async () => {
    const token = await seedActor(['permission:read']);
    const res = await request(app)
      .post('/api/permissions')
      .set('Authorization', `Bearer ${token}`)
      .send({ name: '越界权限', code: 'zzparity:nope', type: 'api', module: 'system' });
    expect({ status: res.status, code: res.body?.errors?.errorCode }).toEqual({
      status: 403,
      code: 'PERMISSION_DENIED',
    });
  });
});
