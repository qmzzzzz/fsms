/**
 * 认证剩余分支覆盖（冲 95% 批次 B2）
 *
 * 覆盖 refresh 全失败矩阵（缺失/坏签名/类型不符/用户删除/版本不符/改密拒绝）、
 * 轮换 + 重放检测全量吊销、恢复码重生成、mfaEnable/mfaEnroll 边界、
 * 登录失败路径（用户不存在/密码错误/IP 白名单拒绝）。
 */

const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { randomPassword } = require('../helpers/buildLoginEnvelope');
const { REFRESH_COOKIE_NAME, ACCESS_COOKIE_NAME } = require('../../utils/cookie');

describe('认证剩余分支（批次 B2）', () => {
  let app;
  let User;
  let Role;
  let Permission;
  let superToken;
  let superUserId;
  let superUsername;
  const stamp = `b2${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);
  const PASSWORD = randomPassword();

  /** 从 set-cookie 串提取 refresh token 值（cookie 名经常量引用；值需 URL 解码） */
  const refreshOf = (res) => {
    const cookies = (res.headers['set-cookie'] || []).map((c) => c.split(';')[0]).join('; ');
    const pair = cookies.split('; ').find((c) => c.startsWith(REFRESH_COOKIE_NAME + '='));
    return pair ? decodeURIComponent(pair.split('=').slice(1).join('=')) : null;
  };

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    Role = require('../../models/Role');
    Permission = require('../../models/Permission');
    require('../../models/TokenBlacklist');

    const wildcardPerm = await Permission.findOneAndUpdate(
      { code: '*:*' },
      { $setOnInsert: { name: '全部权限', code: '*:*', type: 'api', module: 'system' } },
      { upsert: true, new: true }
    );
    const superRole = await Role.create({
      name: '超管_批次B2',
      code: `SUPER_ADMIN_B2_${stamp}`,
      level: 10,
      isBuiltIn: false,
      permissions: [wildcardPerm._id],
    });
    const admin = await User.create({
      username: `b2admin${stamp}`,
      email: `b2admin${stamp}@example.com`,
      password: PASSWORD,
      roles: [superRole._id],
    });
    superUserId = String(admin._id);
    superUsername = admin.username;
    superToken = jwt.sign(
      { userId: superUserId, username: superUsername, tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    const { createApp } = require('../../app');
    app = createApp();
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await User.deleteOne({ username: `b2admin${stamp}` }).catch(() => {});
      await User.deleteMany({ username: new RegExp(`^b2u${stamp}`) }).catch(() => {});
      await Role.deleteOne({ code: `SUPER_ADMIN_B2_${stamp}` }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  const login = (username, password) =>
    request(app).post('/api/auth/login').send({ username, password });

  test('登录失败路径：用户不存在（哑 compare 抹时序）/ 密码错误（计数递增）', async () => {
    const ghost = await login('no_such_user_xyz', 'Whatever!123');
    expect(ghost.status).toBe(401);
    expect(ghost.body.errors?.errorCode).toBe('AUTH_INVALID_CREDENTIALS');

    const wrongPwd = await login(superUsername, 'Wrong!Pass1xy');
    expect(wrongPwd.status).toBe(401);
    expect(wrongPwd.body.errors?.errorCode).toBe('AUTH_INVALID_CREDENTIALS');

    const u = await User.findById(superUserId).select('failedLoginCount');
    expect(u.failedLoginCount).toBeGreaterThan(0);
    await User.findByIdAndUpdate(superUserId, { failedLoginCount: 0 });
  });

  test('登录失败路径：IP 白名单不匹配统一 401（不泄露账号存在性）', async () => {
    await User.create({
      username: `b2u${stamp}ip`,
      email: `b2u${stamp}ip@example.com`,
      password: PASSWORD,
      allowedIPs: '10.99.99.99',
    });
    const res = await login(`b2u${stamp}ip`, PASSWORD);
    expect(res.status).toBe(401);
    expect(res.body.errors?.errorCode).toBe('AUTH_INVALID_CREDENTIALS');
  });

  test('refresh 全失败矩阵：缺失/坏签名/类型不符/tokenVersion 不符/用户删除', async () => {
    const missing = await request(app).post('/api/auth/refresh').send({});
    expect(missing.status).toBe(400);

    const badSig = await request(app)
      .post('/api/auth/refresh')
      .send({
        refreshToken: jwt.sign(
          { userId: superUserId, type: 'refresh', tokenVersion: 0 },
          'wrong-secret'
        ),
      });
    expect(badSig.status).toBe(401);

    const wrongType = await request(app)
      .post('/api/auth/refresh')
      .send({ refreshToken: superToken });
    expect(wrongType.status).toBe(401);

    const wrongVersion = await request(app)
      .post('/api/auth/refresh')
      .send({
        refreshToken: jwt.sign(
          { userId: superUserId, type: 'refresh', tokenVersion: 99 },
          process.env.JWT_REFRESH_SECRET,
          { expiresIn: '1h' }
        ),
      });
    expect(wrongVersion.status).toBe(401);

    const ghostId = new mongoose.Types.ObjectId().toString();
    const ghostUser = await request(app)
      .post('/api/auth/refresh')
      .send({
        refreshToken: jwt.sign(
          { userId: ghostId, type: 'refresh', tokenVersion: 0 },
          process.env.JWT_REFRESH_SECRET,
          { expiresIn: '1h' }
        ),
      });
    expect(ghostUser.status).toBe(401);
  });

  test('refresh 轮换成功 + 旧令牌重放检测触发 401', async () => {
    const loginRes = await login(superUsername, PASSWORD);
    expect(loginRes.status).toBe(200);
    console.error('RAW_SET_COOKIE', JSON.stringify(loginRes.headers['set-cookie']));
    const oldRefresh = refreshOf(loginRes);
    console.error(
      'PARSED_REFRESH',
      JSON.stringify(oldRefresh && oldRefresh.slice(-20)),
      'len',
      oldRefresh && oldRefresh.length
    );

    const rotated = await request(app).post('/api/auth/refresh').send({ refreshToken: oldRefresh });
    console.error('ROTATE', rotated.status, JSON.stringify(rotated.body).slice(0, 200));
    expect(rotated.status).toBe(200);

    // 重放已被轮换消费的旧 refresh → 重放检测分支 → 401
    const replay = await request(app).post('/api/auth/refresh').send({ refreshToken: oldRefresh });
    expect(replay.status).toBe(401);

    // 重放触发了全量吊销（tokenVersion 递增）：按库内新版本重签操作者令牌
    const fresh = await User.findById(superUserId).select('username tokenVersion');
    superToken = jwt.sign(
      { userId: superUserId, username: fresh.username, tokenVersion: fresh.tokenVersion ?? 0 },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    // 重新登录恢复会话供后续用例
    const relogin = await login(superUsername, PASSWORD);
    expect(relogin.status).toBe(200);
  });

  test('refresh：密码修改后旧 refresh 拒绝（passwordChangedAt）', async () => {
    const loginRes = await login(superUsername, PASSWORD);
    const refresh = refreshOf(loginRes);

    // 推进 passwordChangedAt 到未来（+10s 确保秒级比较 changedSec > iat 成立）
    await User.findByIdAndUpdate(superUserId, { passwordChangedAt: new Date(Date.now() + 10000) });

    const res = await request(app).post('/api/auth/refresh').send({ refreshToken: refresh });
    expect(res.status).toBe(401);

    // passwordChangedAt 推进已使旧 iat 令牌全部失效：
    // 把 changedAt 拉回过去（解除对后续签发令牌的 10s 毒化），再重签供后续用例
    await User.findByIdAndUpdate(superUserId, { passwordChangedAt: new Date(Date.now() - 60000) });
    const fresh = await User.findById(superUserId).select('username tokenVersion');
    superToken = jwt.sign(
      { userId: superUserId, username: fresh.username, tokenVersion: fresh.tokenVersion ?? 0 },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
    expect(ACCESS_COOKIE_NAME).toBe('access_token');
  });

  test('MFA enable/enroll 边界：未 enroll enable 400 / 格式错误 400 / 已开启重复 enroll', async () => {
    const noEnroll = await request(app)
      .post('/api/auth/mfa/enable')
      .set('Authorization', `Bearer ${superToken}`)
      .send({ mfaCode: '123456' });
    expect(noEnroll.status).toBe(400);

    const enroll = await request(app)
      .post('/api/auth/mfa/enroll')
      .set('Authorization', `Bearer ${superToken}`);
    expect(enroll.status).toBe(200);
    const badFormat = await request(app)
      .post('/api/auth/mfa/enable')
      .set('Authorization', `Bearer ${superToken}`)
      .send({ mfaCode: 'abcdef' });
    expect(badFormat.status).toBe(400);

    const { hotp, base32Decode } = require('../../utils/totp');
    const secret = enroll.body.data.secret;
    const nextCode = hotp(base32Decode(secret), Math.floor(Date.now() / 1000 / 30) + 1);
    const enabled = await request(app)
      .post('/api/auth/mfa/enable')
      .set('Authorization', `Bearer ${superToken}`)
      .send({ mfaCode: nextCode });
    expect(enabled.status).toBe(200);

    const reEnroll = await request(app)
      .post('/api/auth/mfa/enroll')
      .set('Authorization', `Bearer ${superToken}`);
    expect(reEnroll.status).toBe(400);

    // 清理 MFA 状态
    await User.findByIdAndUpdate(superUserId, {
      mfaEnabled: false,
      mfaSecret: '',
      mfaRecoveryCodes: [],
    });
  });

  test('恢复码重生成：错误口令 400 + 正确口令 200 且旧码作废', async () => {
    const enroll = await request(app)
      .post('/api/auth/mfa/enroll')
      .set('Authorization', `Bearer ${superToken}`);
    const secret = enroll.body.data.secret;
    const { hotp, base32Decode } = require('../../utils/totp');
    const code = hotp(base32Decode(secret), Math.floor(Date.now() / 1000 / 30) + 1);
    const enabled = await request(app)
      .post('/api/auth/mfa/enable')
      .set('Authorization', `Bearer ${superToken}`)
      .send({ mfaCode: code });
    const oldCodes = enabled.body.data.recoveryCodes;

    // 确定性：enable 已消费 enable 时刻窗口的 counter，+2 码未必落在当前 ±1
    // 容差内——直接把 mfaLastCounter 重置为 0，任何当前窗口码都满足重放检查
    await User.findByIdAndUpdate(superUserId, { mfaLastCounter: 0 });

    const badRegen = await request(app)
      .post('/api/auth/mfa/recovery-codes')
      .set('Authorization', `Bearer ${superToken}`)
      .send({ mfaCode: '000000' });
    expect(badRegen.status).toBe(400);

    const ctr = Math.floor(Date.now() / 1000 / 30);
    const nextCode = hotp(base32Decode(secret), ctr + 1);
    const regen = await request(app)
      .post('/api/auth/mfa/recovery-codes')
      .set('Authorization', `Bearer ${superToken}`)
      .send({ mfaCode: nextCode });
    expect(regen.status).toBe(200);
    expect(regen.body.data.recoveryCodes).toHaveLength(10);
    expect(regen.body.data.recoveryCodes).not.toContain(oldCodes[0]);

    // 清理 MFA 状态
    await User.findByIdAndUpdate(superUserId, {
      mfaEnabled: false,
      mfaSecret: '',
      mfaRecoveryCodes: [],
      failedLoginCount: 0,
    });
  });
});
