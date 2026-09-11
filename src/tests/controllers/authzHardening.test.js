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
      { expiresIn: '1h' }
    );

  // ================= P2-8 权限子集校验 =================
  describe('P2-8 assignRoles 权限子集校验', () => {
    let opToken;
    let target;
    let deviceRole; // 操作者不持有的权限集
    let sameLevelRole;

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

      // 层级低于操作者（层级校验会放行），但含操作者没有的 device:delete
      // —— 这正是 P2-8 的要害：层级不变量成立，权限却被横向放大
      deviceRole = await seedRole('SUBSET_DEVICE_ROLE', 4, [deviceDeletePerm._id]);
      // 权限是操作者子集 —— 合法路径
      sameLevelRole = await seedRole('SUBSET_SAFE_ROLE', 4, [userReadPerm._id]);

      target = await User.create({
        username: 'subset_target',
        email: 'subset_target@example.com',
        password: 'Qz7#Lm42vTx9',
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
    });

    test('授予自身持有的权限子集仍然放行（合法路径不受影响）', async () => {
      const res = await request(app)
        .put(`/api/users/${target._id}/roles`)
        .set('Authorization', `Bearer ${opToken}`)
        .send({ roles: [String(sameLevelRole._id)] });

      expect(res.status).toBe(200);
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
      const spy = jest.spyOn(bcrypt, 'compare');
      await login('enum_nonexistent_yy');
      // 用户不存在也必须至少调用一次 compare
      expect(spy).toHaveBeenCalled();
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

      expect([400, 401]).toContain(res.status);
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
      expect([400, 401]).toContain(replay.status);
      expect(replay.body.success).toBeFalsy();
      expect(replay.body.data?.token).toBeUndefined();
    });
  });
});
