/**
 * ──────────────────────────────────────────────────────────────────────────
 * 本文件的定位（2026-09-20 补注，由变异审计批量补齐）
 *
 * 被测对象：授权与会话（P2-8/10~15 + 恢复码过滤条件）
 * 守护的不变式：每条 403 后必须回读 DB 证明「报错且未写库」；登录失败响应体逐字节一致（防账号枚举）
 * 可证伪性：本轮未做变异实测
 * 既有评价：既往审计列为**正面记账**（真 HTTP + 真库 + 故障注入，deliverables/七维代码健康度深度审计-2026-09-18.md）
 *
 * 命名沿革：2026-09-20 由 `authzHardening.test.js` 更名。旧名里的
 *   Coverage / Gap / Hardening / Branch 说的是「当初为什么写它」（补覆盖率基线），
 *   **不是它的价值判据**；它能否挡住回归，由变异实测回答，不由文件名回答。
 *   旧名保留在本行，便于既往审计报告的 `grep 旧文件名` 仍能定位到本文件。
 * 依据：`deliverables/AGENT工作总账与待办-2026-09-21.md`（§2.9 测试资产 / §6 方法；原编号 §6-AW/AX/AY/AZ/BA 已随原台账删除，无法逐条映射）
 * ──────────────────────────────────────────────────────────────────────────
 */

/**
 * 批次A 授权/会话类修复回归（P2-8/10/11/12/13/14/15 + 恢复码过滤条件失效）
 */

const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

describe('授权与会话加固回归', () => {
  let app;
  let User;
  let Role;
  let Permission;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    Role = require('../../models/Role');
    Permission = require('../../models/Permission');
    const { createApp } = require('../../app');
    app = createApp();
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  /** 幂等播种权限（多套件并行共享内存库） */
  const seedPerm = (code, module = 'system') =>
    Permission.findOneAndUpdate(
      { code },
      { $setOnInsert: { code, name: code, type: 'api', module } },
      { upsert: true, new: true }
    );

  const seedRole = (code, level, permIds) =>
    Role.findOneAndUpdate(
      { code },
      { $setOnInsert: { code, name: code, level, permissions: permIds } },
      { upsert: true, new: true }
    );

  const signFor = (user) =>
    jwt.sign(
      { userId: String(user._id), username: user.username, tokenVersion: user.tokenVersion ?? 0 },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

  // ================= P2-8 权限子集校验 =================
  describe('P2-8 assignRoles 权限子集校验', () => {
    let opToken;
    let target;
    let deviceRole; // 操作者不持有的权限集
    let sameLevelRole;
    let operatorId; // 给 test 体内新建的目标当属主（beforeAll 里的 operator 不外露）

    beforeAll(async () => {
      const assignPerm = await seedPerm('role:assign');
      const userReadPerm = await seedPerm('user:read');
      const deviceDeletePerm = await seedPerm('device:delete', 'device');

      // 操作者：level 5，持 role:assign + user:read，**不持** device:delete
      const opRole = await seedRole('SUBSET_OP_ROLE', 5, [assignPerm._id, userReadPerm._id]);
      const operator = await User.create({
        username: 'subset_op',
        email: 'subset_op@example.com',
        password: 'Qz7#Lm42vTx9',
        roles: [opRole._id],
      });
      opToken = signFor(operator);
      operatorId = operator._id;

      // 层级低于操作者（层级校验会放行），但含操作者没有的 device:delete
      // —— 这正是 P2-8 的要害：层级不变量成立，权限却被横向放大
      deviceRole = await seedRole('SUBSET_DEVICE_ROLE', 4, [deviceDeletePerm._id]);
      // 权限是操作者子集 —— 合法路径
      sameLevelRole = await seedRole('SUBSET_SAFE_ROLE', 4, [userReadPerm._id]);

      target = await User.create({
        username: 'subset_target',
        email: 'subset_target@example.com',
        password: 'Qz7#Lm42vTx9',
        // 目标必须在操作者的数据范围内（本仓夹具此前一律不带 createdBy/department，
        // 范围闸会先拒，P2-8 与目标侧层级闸根本走不到）
        createdBy: operator._id,
        roles: [],
      });
    });

    test('授予自身不持有的权限被拒（层级合规也不放行）', async () => {
      const res = await request(app)
        .put(`/api/users/${target._id}/roles`)
        .set('Authorization', `Bearer ${opToken}`)
        .send({ roles: [String(deviceRole._id)] });

      expect(res.status).toBe(403);
      expect(res.body.message).toContain('device:delete');
      // 角色未被写入
      const after = await User.findById(target._id).select('roles');
      expect(after.roles.map(String)).not.toContain(String(deviceRole._id));
    });

    test('给自己挂富权限角色同样被拒（isSelf 不再是豁免口）', async () => {
      const self = await User.findOne({ username: 'subset_op' });
      const res = await request(app)
        .put(`/api/users/${self._id}/roles`)
        .set('Authorization', `Bearer ${opToken}`)
        .send({ roles: [String(deviceRole._id)] });

      expect(res.status).toBe(403);
      // 「不再是豁免口」的判据是角色没被写进去：只断 403 无法区分
      // 「被新逻辑拦住」与「被旧逻辑以别的理由拦住」
      const selfAfter = await User.findById(self._id).select('roles').lean();
      expect(selfAfter.roles.map(String)).not.toContain(String(deviceRole._id));
    });

    test('授予自身持有的权限子集仍然放行（合法路径不受影响）', async () => {
      const res = await request(app)
        .put(`/api/users/${target._id}/roles`)
        .set('Authorization', `Bearer ${opToken}`)
        .send({ roles: [String(sameLevelRole._id)] });

      expect(res.status).toBe(200);
      // 「放行」的判据是变更真的落库（200 也可能来自「什么都没做的空操作」）
      const afterOk = await User.findById(target._id).select('roles').lean();
      expect(afterOk.roles.map(String)).toContain(String(sameLevelRole._id));
    });

    test('收权操作不被误拦（目标已持有的权限不算本次授予）', async () => {
      // 目标先由超管挂上 device 角色
      await User.findByIdAndUpdate(target._id, { $set: { roles: [deviceRole._id] } });

      // 操作者把它换成自己权限范围内的角色 → 属于收权，应放行
      const res = await request(app)
        .put(`/api/users/${target._id}/roles`)
        .set('Authorization', `Bearer ${opToken}`)
        .send({ roles: [String(sameLevelRole._id)] });

      expect(res.status).toBe(200);
      // 收权语义的判据是角色集合真的被替换成 sameLevelRole（deviceRole 被摘掉），
      // 而不只是「返回了 200」。若把「目标已持有的权限」误算成本次授予，
      // 这里会 403 —— 反向若实现变成空操作，下面的 toContain/toHaveLength 会红。
      const afterDowngrade = await User.findById(target._id).select('roles').lean();
      expect(afterDowngrade.roles.map(String)).toEqual([String(sameLevelRole._id)]);
    });

    test('目标用户层级高于操作者 → 403 且角色未被写入（assignRoles 的目标侧层级闸）', async () => {
      // 覆盖 assignRoles 的目标用户层级保护：操作者 level 5，目标是 level 8 的用户。
      // 变异验证：把 `if (!isSelf && targetUserMaxLevel >= operatorMaxLevel)` 整个删掉，
      // 本用例必须转红——原先没有任何用例覆盖这条闸门（P2 变异存活）。
      const highRole = await seedRole('SUBSET_HIGH_ROLE', 8, []);
      const highUser = await User.create({
        username: `subset_high_${Date.now().toString(36)}`,
        email: `subset_high_${Date.now().toString(36)}@example.com`,
        password: 'Qz7#Lm42vTx9',
        // 目标必须在操作者的数据范围内（本仓夹具此前一律不带 createdBy/department，
        // 范围闸会先拒，P2-8 与目标侧层级闸根本走不到）
        createdBy: operatorId,
        roles: [highRole._id],
      });

      const res = await request(app)
        .put(`/api/users/${highUser._id}/roles`)
        .set('Authorization', `Bearer ${opToken}`)
        .send({ roles: [String(sameLevelRole._id)] });

      expect(res.status).toBe(403);
      expect(res.body.errors.errorCode).toBe('USER_ROLE_ASSIGN_PEER_OR_HIGHER_FORBIDDEN');
      // 层级闸拦下的请求不得写库（否则等于「报错但已生效」）
      const unchanged = await User.findById(highUser._id).select('roles').lean();
      expect(unchanged.roles.map(String)).toEqual([String(highRole._id)]);

      await User.findByIdAndDelete(highUser._id).catch(() => {});
      await Role.deleteOne({ code: 'SUBSET_HIGH_ROLE' }).catch(() => {});
    });
  });

  // ================= P2-10 / P2-11 防枚举 =================
  describe('P2-10/11 登录响应统一化', () => {
    const PASSWORD = 'Qz7#Lm42vTx9';

    beforeAll(async () => {
      await User.create({
        username: 'enum_normal',
        email: 'enum_normal@example.com',
        password: PASSWORD,
      });
      // 配了 IP 白名单的账户：从其它 IP 探测时原先返回 403/AUTH_IP_RANGE_DENIED
      await User.create({
        username: 'enum_iprestricted',
        email: 'enum_ip@example.com',
        password: PASSWORD,
        allowedIPs: '10.99.99.0/24',
      });
    });

    const login = (username, password = 'WrongPass@123') =>
      request(app).post('/api/auth/login').send({ username, password });

    test('四类失败路径返回完全一致的状态码与错误码', async () => {
      const cases = await Promise.all([
        login('enum_nonexistent_zz'), // 用户不存在
        login('enum_normal'), // 存在但密码错
        login('enum_iprestricted', PASSWORD), // 存在且密码对，但 IP 不在范围
      ]);

      for (const res of cases) {
        expect(res.status).toBe(401);
        expect(res.body.errors?.errorCode).toBe('AUTH_INVALID_CREDENTIALS');
      }
      // 响应体逐字节一致（含 message），不留任何可区分特征
      const bodies = cases.map((r) => JSON.stringify({ ...r.body, timestamp: undefined }));
      expect(new Set(bodies).size).toBe(1);
    });

    test('IP 受限账户不再返回可区分的 403/AUTH_IP_RANGE_DENIED', async () => {
      const res = await login('enum_iprestricted', PASSWORD);
      expect(res.status).not.toBe(403);
      expect(res.body.errors?.errorCode).not.toBe('AUTH_IP_RANGE_DENIED');
    });

    test('「用户不存在」路径同样消耗 bcrypt 时间（抹平时序侧信道）', async () => {
      // 直接验证抹平函数存在且真实执行 bcrypt：
      // 端到端计时在 CI 上不稳定（GC/调度抖动），改为断言实现契约
      const bcrypt = require('bcryptjs');
      const config = require('../../config');
      const spy = jest.spyOn(bcrypt, 'compare');
      await login('enum_nonexistent_yy');
      // 用户不存在也必须至少调用一次 compare
      expect(spy).toHaveBeenCalled();
      // 只断言"调了 compare"没有牙齿：把抹平用的哑哈希写成 cost 4，真实登录仍是
      // cost 12 ⇒ 两条路径的 CPU 开销差约 60 倍，用户名枚举的时序侧信道原样回来了，
      // 而这条用例照样绿。cost 就编码在哈希串的前缀里，直接把它比给 config 看。
      const dummyHashes = spy.mock.calls
        .map(([, hash]) => hash)
        .filter((h) => typeof h === 'string');
      expect(dummyHashes.length).toBeGreaterThan(0);
      const expectedPrefix = `$2a$${config.bcryptRounds}$`;
      expect(dummyHashes.every((h) => h.startsWith(expectedPrefix))).toBe(true);
      spy.mockRestore();
    });
  });

  // ================= P2-15 mfaSecret 静态加密 =================
  describe('P2-15 MFA 种子加密存储', () => {
    const {
      encryptMfaSecret,
      decryptMfaSecret,
      isEncryptedMfaSecret,
      ENC_PREFIX,
    } = require('../../utils/mfaSecret');
    const { generateSecret } = require('../../utils/totp');

    test('加解密往返一致且密文不含明文', () => {
      const secret = generateSecret();
      const enc = encryptMfaSecret(secret);

      expect(enc.startsWith(ENC_PREFIX)).toBe(true);
      expect(enc).not.toContain(secret);
      expect(decryptMfaSecret(enc)).toBe(secret);
    });

    test('存量明文原样透传（迁移期不锁死既有用户）', () => {
      const legacy = generateSecret();
      expect(isEncryptedMfaSecret(legacy)).toBe(false);
      expect(decryptMfaSecret(legacy)).toBe(legacy);
    });

    test('空值不被加密（否则判空逻辑全部失效）', () => {
      expect(encryptMfaSecret('')).toBe('');
      expect(decryptMfaSecret('')).toBe('');
    });

    test('重复加密幂等（不产生双层密文）', () => {
      const enc = encryptMfaSecret(generateSecret());
      expect(encryptMfaSecret(enc)).toBe(enc);
    });

    test('密文被篡改时解密失败并返回空串（GCM 认证生效）', () => {
      const enc = encryptMfaSecret(generateSecret());
      // 必须在「字节」层面翻转，不能替换 base64 字符串的尾部字符：
      // 密文段是 base64，末尾常带 '=' 填充，填充前那个字符的低位 bit 不参与解码，
      // 替换它有约 7% 概率解出完全相同的字节序列——密文其实没变，GCM 自然验证通过，
      // 用例随机失败（实测 300 次 22 次误判）。
      // 格式：enc:v1:gcm:<iv hex>:<tag hex>:<base64 密文>
      const parts = enc.split(':');
      const raw = Buffer.from(parts[parts.length - 1], 'base64');
      raw[0] ^= 0xff;
      parts[parts.length - 1] = raw.toString('base64');
      const tampered = parts.join(':');
      expect(tampered).not.toBe(enc);
      expect(decryptMfaSecret(tampered)).toBe('');
    });

    test('enroll 落库为密文，且校验路径能正常还原', async () => {
      const u = await User.create({
        username: 'mfa_enc_user',
        email: 'mfa_enc@example.com',
        password: 'Qz7#Lm42vTx9',
      });
      const token = signFor(u);

      const res = await request(app)
        .post('/api/auth/mfa/enroll')
        .set('Authorization', `Bearer ${token}`);
      expect(res.status).toBe(200);
      const plainSecret = res.body.data.secret;
      expect(plainSecret).toMatch(/^[A-Z2-7]+$/);

      // 库内必须是密文，不能是刚刚返回的明文
      const stored = await User.findById(u._id).select('+mfaSecret');
      expect(stored.mfaSecret).not.toBe(plainSecret);
      expect(isEncryptedMfaSecret(stored.mfaSecret)).toBe(true);
      // 但能还原回同一个种子（否则认证器里的码永远对不上）
      expect(decryptMfaSecret(stored.mfaSecret)).toBe(plainSecret);
    });

    test('用真实 TOTP 码可通过 enable（端到端验证加密未破坏校验链）', async () => {
      const { hotp, base32Decode } = require('../../utils/totp');
      const u = await User.create({
        username: 'mfa_e2e_user',
        email: 'mfa_e2e@example.com',
        password: 'Qz7#Lm42vTx9',
      });
      const token = signFor(u);

      const enroll = await request(app)
        .post('/api/auth/mfa/enroll')
        .set('Authorization', `Bearer ${token}`);
      const secret = enroll.body.data.secret;

      const counter = Math.floor(Date.now() / 1000 / 30);
      const code = hotp(base32Decode(secret), counter);

      const enable = await request(app)
        .post('/api/auth/mfa/enable')
        .set('Authorization', `Bearer ${token}`)
        .send({ mfaCode: code });

      expect(enable.status).toBe(200);
      expect(enable.body.data.enabled).toBe(true);
      expect(Array.isArray(enable.body.data.recoveryCodes)).toBe(true);
    });
  });

  // ================= 恢复码跨用户 / 重放防护（Critical 回归） =================
  describe('MFA 恢复码跨用户与重放防护', () => {
    const { hotp, base32Decode } = require('../../utils/totp');

    /**
     * 创建用户 → enroll → enable MFA，返回 { user, recoveryCodes }
     * @param {string} username
     * @param {string} password
     */
    const setupMfaUser = async (username, password) => {
      const u = await User.create({ username, email: `${username}@example.com`, password });
      const token = signFor(u);

      const enroll = await request(app)
        .post('/api/auth/mfa/enroll')
        .set('Authorization', `Bearer ${token}`);
      const secret = enroll.body.data.secret;

      const counter = Math.floor(Date.now() / 1000 / 30);
      const code = hotp(base32Decode(secret), counter);

      const enable = await request(app)
        .post('/api/auth/mfa/enable')
        .set('Authorization', `Bearer ${token}`)
        .send({ mfaCode: code });

      return { user: u, recoveryCodes: enable.body.data.recoveryCodes };
    };

    test('用户 A 的恢复码不能用于登录用户 B（恢复码绑定用户）', async () => {
      const PASS_A = 'Qz7#Lm42vTx9';
      const PASS_B = 'Wx9$Km51nRx2';
      const { recoveryCodes: codesA } = await setupMfaUser('rc_cross_a', PASS_A);
      await setupMfaUser('rc_cross_b', PASS_B);

      // 用 B 的密码 + A 的恢复码登录 B → 必须 401/400，不能签发会话
      const res = await request(app)
        .post('/api/auth/login')
        .send({ username: 'rc_cross_b', password: PASS_B, mfaCode: codesA[0] });

      // 实测 401；本用例主张是「不能签发会话」，双可能形式掩盖了拒绝通道的漂移
      expect(res.status).toBe(401);
      expect(res.body.success).toBeFalsy();
      // 绝不能返回 token
      expect(res.body.data?.token).toBeUndefined();
    });

    test('恢复码使用一次后即失效（不可重放）', async () => {
      const PASS = 'Rt3#Hp84qWx5';
      const { recoveryCodes } = await setupMfaUser('rc_replay_user', PASS);
      const recoveryCode = recoveryCodes[0];

      // 第一次使用恢复码登录 → 成功
      const first = await request(app)
        .post('/api/auth/login')
        .send({ username: 'rc_replay_user', password: PASS, mfaCode: recoveryCode });
      expect(first.status).toBe(200);
      expect(first.body.data.token).toBeTruthy();

      // 第二次重放同一恢复码 → 必须失败
      const replay = await request(app)
        .post('/api/auth/login')
        .send({ username: 'rc_replay_user', password: PASS, mfaCode: recoveryCode });
      // 实测 401（恢复码重放被拒）
      expect(replay.status).toBe(401);
      expect(replay.body.success).toBeFalsy();
      expect(replay.body.data?.token).toBeUndefined();
    });
  });
});
