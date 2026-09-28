/**
 * 停用角色不得继续参与授权判定
 *
 * 缺陷形态：`userPermissionService.getPermissions` 与 `permissionHelper`（P3-8 / P1-22）
 * 早已对 populate 的 roles 加 `match:{status:'active'}`，注释写明"管理员停用角色后必须立即失效"。
 * 但同一份语义在别处被重新实现时漏掉了这个 match：
 *   middleware/auth.js                  → req.user.roleCodes（checkRole / userLimiter 的输入）
 *   services/websocketService（3 处）    → 受限房间 membership 与周期复查
 *   services/authService（2 处）         → 登录响应 / 会话刷新的客户端权限快照
 *   controllers/securityController      → 查看他人 PII 时的"目标层级"
 * 上述 5 个文件已修。`middleware/rbac.js` 的 getDataScope 是同型第 6 处，
 * 该文件当时在途改动，留作待办（本用例只覆盖已修的 5 处）。
 *
 * 断言两层：
 *  ① 行为层（真正的证明）：真库 + 真生产方法，验证停用角色不进入判定结果；
 *     并对照服务端既有口径（生效权限才返回），确认这不是新发明的规则。
 *  ② 接线层（机械不变量）：只扫上述 5 个"授权判定"文件，要求其中每一处
 *     roles populate 都显式带 `status: 'active'`。刻意**不**扫展示用途的站点
 *     （ipListController / userService 读角色名是给人看的，过滤反而是错的）——
 *     把不变量声明在"判定"这一类上，才不会逼出假阳性或被后人直接加白名单绕过。
 */

const fs = require('fs');
const path = require('path');
const mongoose = require('mongoose');

describe('停用角色不参与授权判定', () => {
  let Role;
  let User;
  let Permission;
  let WebSocketService;
  let userPermissionService;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    Role = require('../models/Role');
    User = require('../models/User');
    Permission = require('../models/Permission');
    WebSocketService = require('../services/websocketService');
    userPermissionService = require('../services/userPermissionService');
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  let uid;
  let activeRole;
  let inactiveRole;

  beforeAll(async () => {
    const stamp =
      Date.now()
        .toString(36)
        .replace(/[^a-z]/gi, '')
        .slice(0, 6) || 'a1';
    const mod = `zzqoderbrackets${stamp}`;
    const permOfActive = await Permission.create({
      name: '生效角色权限',
      module: mod,
      code: `${mod}:activeread`,
      type: 'api',
    });
    const permOfInactive = await Permission.create({
      name: '停用角色权限',
      module: mod,
      code: `${mod}:inactiveread`,
      type: 'api',
    });
    activeRole = await Role.create({
      name: `生效低阶-${stamp}`,
      code: `ZZQODER_ACTIVE_${stamp.toUpperCase()}`,
      level: 4,
      status: 'active',
      permissions: [permOfActive._id],
    });
    inactiveRole = await Role.create({
      name: `停用高阶-${stamp}`,
      code: `ZZQODER_INACTIVE_${stamp.toUpperCase()}`,
      level: 9,
      status: 'inactive',
      permissions: [permOfInactive._id],
    });
    uid = new mongoose.Types.ObjectId();
    await User.create({
      _id: uid,
      username: `zzqoder_${stamp}`,
      email: `zzqoder_${stamp}@example.com`,
      password: 'Aa1!aaaaaaaaaaaaaaaa',
      status: 'active',
      roles: [activeRole._id, inactiveRole._id],
    });
  });

  /**
   * 直接驱动生产方法本身，不构造 WebSocket 服务器（constructor 会真起 io）。
   * revalidateSocket / _applyRevalidation 只依赖 logger + socket 形参，
   * 所以把这两个真方法挂到一个普通对象上即为真调用路径。
   */
  const makeRevalidator = () => ({
    revalidateSocket: WebSocketService.prototype.revalidateSocket,
    _applyRevalidation: WebSocketService.prototype._applyRevalidation,
  });

  test('行为：WebSocket 授权复查返回的角色码集合不含停用角色', async () => {
    const socket = {
      id: 'zzqoder-sock-1',
      userId: uid,
      tokenVersion: 0,
      roleCodes: ['STALE_FROM_HANDSHAKE'],
      rooms: new Set(),
      emit() {},
      disconnect() {},
    };

    const r = await makeRevalidator().revalidateSocket(socket);

    expect(r.ok).toBe(true);
    expect(r.roleCodes).toContain(activeRole.code);
    expect(r.roleCodes).not.toContain(inactiveRole.code);
    // 回写到 socket 的快照同样必须干净——join-room 读的就是它
    expect(socket.roleCodes).toContain(activeRole.code);
    expect(socket.roleCodes).not.toContain(inactiveRole.code);
  });

  test('对照：服务端权限解析同样只认生效角色（既有约定，非本次改动新规则）', async () => {
    const codes = await userPermissionService.getPermissions(String(uid));
    const list = (codes || []).map((p) => (typeof p === 'string' ? p : p.code));
    expect(list.some((c) => String(c).includes(':activeread'))).toBe(true);
    expect(list.some((c) => String(c).includes(':inactiveread'))).toBe(false);
  });

  test('行为：带 match 的 populate 产出的数组可被 ?.code 安全消费', async () => {
    const populated = await User.findById(uid).populate({
      path: 'roles',
      select: 'code',
      match: { status: 'active' },
    });
    const codes = populated.roles.map((r) => r?.code).filter(Boolean);
    expect(codes).toEqual([activeRole.code]);
    // 防御性：实测 8.24.1 的 match 不会产生 null 洞（见 zzqoder_populateMatchShape.test.js），
    // 此处的 ?.code 是防将来版本改为留 null —— 任何 r.code 形态都不该抛 TypeError。
    for (const r of populated.roles) {
      expect(() => r?.code).not.toThrow();
    }
  });

  test('接线：操作者侧 roles populate 须带 status:active；目标侧保护层须不带（方向相反）', () => {
    // 操作者侧不变量：停用角色**不得**参与授予（auth/websocket/login-snapshot 取 roleCodes/level 时须过滤 active）。
    const OPERATOR_FILES = [
      'middleware/auth.js',
      'services/websocketService.js',
      'services/authService.js',
    ];
    const root = path.join(__dirname, '..');
    const violations = [];
    let inspectedSites = 0;

    for (const rel of OPERATOR_FILES) {
      const src = fs.readFileSync(path.join(root, rel), 'utf8').replace(/\r\n/g, '\n');
      const lines = src.split('\n');
      lines.forEach((line, i) => {
        const isRolesPopulate =
          /\.populate\(\s*['"]roles['"]/.test(line) || /path:\s*['"]roles['"]/.test(line);
        if (!isRolesPopulate) return;
        inspectedSites += 1;
        // 字符串式 .populate('roles', …) 无法携带 match —— 一律视为违规
        if (/\.populate\(\s*['"]roles['"]\s*,/.test(line)) {
          violations.push(`${rel}:${i + 1} 字符串式 populate（无法携带 match）`);
          return;
        }
        // 对象式：在该语句起 6 行内必须出现 active 状态过滤
        const window = lines.slice(i, i + 6).join(' ');
        if (!/status:\s*'active'/.test(window)) {
          violations.push(`${rel}:${i + 1} roles populate 缺少 match:{status:'active'}`);
        }
      });
    }

    // 先确认扫描确实看到了站点，防止"正则没命中所以全绿"的假守卫
    expect(inspectedSites).toBeGreaterThanOrEqual(6);
    expect(violations).toEqual([]);

    // 目标侧不变量**相反**（securityController view-sensitive 计算目标的保护层用于"操作者须严格更高"）：
    // 目标的 roles populate 绝不能按 active 过滤——停用角色随时可恢复，且过滤到空集时
    // maxRoleLevel([]) 返回 -Infinity，会让 `opLevel <= targetLevel` 对所有 system:read 持有者恒 false
    // → 该账号 PII 全体裸奔（真实 fail-open）。故此处反向钉死：不带 match + 空角色显式拒绝。
    const sec = fs
      .readFileSync(path.join(root, 'controllers/securityController.js'), 'utf8')
      .replace(/\r\n/g, '\n');
    const targetPop = sec.match(/\.populate\(\{[^}]*path:\s*'roles'[^}]*\}\)/);
    expect(targetPop).not.toBeNull();
    expect(targetPop[0]).not.toMatch(/status:\s*'active'/);
    expect(sec).toMatch(/targetRoles\.length === 0/);
  });
});
