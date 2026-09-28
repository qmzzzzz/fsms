/**
 * ──────────────────────────────────────────────────────────────────────────
 * 本文件的定位（2026-09-20 补注，由变异审计批量补齐）
 *
 * 被测对象：auth 中间件的秒级边界与 MFA 缓存失效
 * 守护的不变式：改密同秒新签发令牌必须放行、早于改密秒必须拒绝；MFA 开关必须失效 60s 用户缓存
 * 可证伪性：本轮未做变异实测
 *
 * 命名沿革：2026-09-20 由 `authEdge.test.js` 更名。旧名里的
 *   Coverage / Gap / Hardening / Branch 说的是「当初为什么写它」（补覆盖率基线），
 *   **不是它的价值判据**；它能否挡住回归，由变异实测回答，不由文件名回答。
 *   旧名保留在本行，便于既往审计报告的 `grep 旧文件名` 仍能定位到本文件。
 * 依据：`deliverables/AGENT工作总账与待办-2026-09-21.md`（§2.9 测试资产 / §6 方法；原编号 §6-AW/AX/AY/AZ/BA 已随原台账删除，无法逐条映射）
 * ──────────────────────────────────────────────────────────────────────────
 */

/**
 * 认证边界测试（第三批审计 #8/#9）
 * - #8：passwordChangedAt(毫秒) 与 token iat(整秒) 同秒边界 —— 改密后同秒新签发的令牌必须放行，
 *        早于改密秒的令牌必须拒绝
 * - #9：MFA 开关后必须失效 authenticate 的 60s 用户缓存（防保护延迟生效窗口）
 */

const express = require('express');
const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const crypto = require('crypto');

const secret = process.env.JWT_SECRET || 'test-jwt-secret-for-testing-only';

const buildProtectedApp = () => {
  const { authenticate } = require('../../middleware/auth');
  // authenticate 的 loadValidUser 会 populate('roles')，必须先注册 Role 模型，
  // 否则 MissingSchemaError → 500（同 auth.test.js 的处理）
  require('../../models/Role');
  const app = express();
  app.use(express.json());
  app.get('/protected', authenticate, (req, res) => res.json({ success: true }));
  return app;
};

describe('认证边界（第三批审计）', () => {
  let User;
  let app;
  const createdUsers = [];

  // 本项目 jsonwebtoken 版本在 payload 已含 iat 时保留原值（实测验证），
  // 直接放 payload 即可控制 iat；注意不能用 noTimestamp（它会删除 payload.iat）
  const makeToken = (user, iat) =>
    jwt.sign(
      {
        userId: String(user._id),
        username: user.username,
        type: 'access',
        tokenVersion: 0,
        jti: crypto.randomUUID(),
        ...(iat !== undefined ? { iat } : {}),
      },
      secret,
      { expiresIn: '1h' }
    );

  const createUser = async (suffix) => {
    const u = await User.create({
      username: `iat_edge_${suffix}_${Date.now()}`,
      email: `iat_edge_${suffix}_${Date.now()}@test.local`,
      password: 'E!d1' + crypto.randomBytes(8).toString('hex'),
    });
    createdUsers.push(u);
    return u;
  };

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    app = buildProtectedApp();
  });

  afterAll(async () => {
    for (const u of createdUsers) await u.deleteOne();
    // T-1：关闭连接，避免遗留连接拖住 jest worker 优雅退出
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  test('#8 改密后同秒新签发的令牌应放行（秒级比较不误拒）', async () => {
    const user = await createUser('same');
    const changedAt = new Date();
    await User.findByIdAndUpdate(user._id, { passwordChangedAt: changedAt });

    const token = makeToken(user, Math.floor(changedAt.getTime() / 1000));
    const res = await request(app).get('/protected').set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
  });

  test('#8 早于改密秒的令牌应被拒绝（401 密码已修改）', async () => {
    // 独立用户：避免上一测试认证留下的 60s 用户缓存干扰本测试的改密断言
    const user = await createUser('older');
    const changedAt = new Date();
    await User.findByIdAndUpdate(user._id, { passwordChangedAt: changedAt });

    const olderIat = Math.floor(changedAt.getTime() / 1000) - 30; // 改密前 30 秒
    const token = makeToken(user, olderIat);

    const res = await request(app).get('/protected').set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(401);
    expect(res.body.message).toContain('密码已修改');
  });

  test('#9 MFA 开关后用户缓存立即失效（无 60s 延迟窗口）', async () => {
    const { invalidateUserCache } = require('../../middleware/auth');
    const user = await createUser('mfa');

    // 触发缓存填充：一次成功认证
    const token = makeToken(user);
    const warm = await request(app).get('/protected').set('Authorization', `Bearer ${token}`);
    // 首次认证必须真的进了业务处理器：这里同时是「缓存被填充」的前提，
    // 若 200 来自别处（如中间件短路），后续的缓存失效断言就失去意义
    expect(warm.status).toBe(200);
    expect(warm.body).toEqual({ success: true });

    // 模拟 mfaEnable/mfaDisable 路径：更新库 + 失效缓存（与 controller 一致）。
    // 【可观测性边界，实测】authenticate 的 loadValidUser 投影里没有 mfaEnabled
    // （middleware/auth.js:73 的 select 列表），authenticate 全文也不读该字段；
    // 因此「MFA 开关」本身对 /protected 的响应不可观测——本段写库+失效是为对齐
    // 生产路径形态，真正被断言的是紧随其后的 tokenVersion 通道（同一份缓存）。
    // 变异验证：把本段两行整体删除，本用例仍绿（不可证伪，故不声称它被验证）。
    await User.findByIdAndUpdate(user._id, { mfaEnabled: true });
    invalidateUserCache(String(user._id));

    // 再借 tokenVersion 验证同一缓存通道：改库+失效后旧令牌立即 401（无 60s 缓存延迟）
    await User.findByIdAndUpdate(user._id, { tokenVersion: 1 });
    invalidateUserCache(String(user._id));

    const res = await request(app).get('/protected').set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(401);
    // 401 必须来自凭据新鲜度通道（SESSION_EXPIRED = tokenVersion 不匹配），
    // 而不是黑名单/签名类 401：只有点名该错误码才能证明是 tokenVersion 比对拦下的，
    // 而非别的 401 巧合。
    // 变异验证：把 invalidateUserCacheLocal 改成 no-op → 转红；把本用例两处
    // invalidateUserCache 调用一起删除 → 转红（缓存返回旧 tokenVersion=0 而放行）。
    // 【实测边界】只删其中一处不转红：失效标记是幂等的，两处调用中任一都能
    // 触发重读，因此无法用「删一处」来区分二者——不声称更强的主张。
    expect(res.body.errors.errorCode).toBe('SESSION_EXPIRED');
  });
});
