/**
 * 注册流 create 撞唯一索引的归一臂补测（覆盖率缺口：authService/session.js :154）
 *
 * 判重与写入之间存在窗口（双击提交/并发脚本）：先到者 201，后到者撞 username_ci /
 * emailKey_1 唯一索引——原始 MongoError 冒泡成 500 会给出「该用户名刚刚被注册」的
 * 弱时间信号（500 vs 模糊拒绝可分），与防枚举口径矛盾。service 层把它归一成与
 * 上方判重相同的 DUPLICATE 出口。本套件用 create 注入 E11000 钉住这条臂。
 */
'use strict';

const mongoose = require('mongoose');
const { randomPassword } = require('../helpers/buildLoginEnvelope');

describe('registerUser 的 create 撞键归一臂（DUPLICATE）', () => {
  let User;
  let SystemConfig;
  let registerUser;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    SystemConfig = require('../../models/SystemConfig');
    // 注册闸：验证码开关关（套件自己种配置行 + 清缓存，不依赖别的套件的库态）
    await SystemConfig.deleteMany({ key: 'registerCaptchaEnabled' }).catch(() => {});
    await SystemConfig.create({ key: 'registerCaptchaEnabled', value: false });
    SystemConfig.invalidateRegisterCaptchaCache?.();
    registerUser = require('../../services/authService/session').registerUser;
  });

  afterAll(async () => {
    await User.deleteMany({ username: /^zzdup/ }).catch(() => {});
    // 本套件在 beforeAll 种下的全局配置行也要回收，并同步失效进程内缓存
    await SystemConfig.deleteMany({ key: 'registerCaptchaEnabled' }).catch(() => {});
    SystemConfig.invalidateRegisterCaptchaCache?.();
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  test('判重通过但 create 撞 username_ci 唯一索引 ⇒ outcome=DUPLICATE（不冒泡 500）', async () => {
    const createSpy = jest.spyOn(User, 'create').mockRejectedValueOnce(
      Object.assign(new Error('E11000 duplicate key error collection users index username_ci_1'), {
        code: 11000,
        keyPattern: { username_ci: 1 },
      })
    );

    const out = await registerUser(
      {
        username: `zzdup${Date.now()}`,
        email: `zzdup${Date.now()}@example.com`,
        password: randomPassword(),
        realName: '撞键测试',
        privacyConsent: true,
      },
      { ip: '127.0.0.1', userAgent: 'dup-key-test', method: 'POST', path: '/api/auth/register' }
    );

    expect(createSpy).toHaveBeenCalled();
    expect(out.outcome).toBe('DUPLICATE');
    createSpy.mockRestore();
  });

  test('判重通过但 create 撞 emailKey 唯一索引（emailKey_1）⇒ 同样归一 DUPLICATE', async () => {
    // 服务注释声称 username_ci / emailKey_1 两把唯一索引共用同一条归一臂。
    // 上一条只钉了 username_ci 分支；这里补 emailKey 分支——若有人把归一收窄成
    // 只认 username_ci，邮箱撞键会重新以 500 冒泡（防枚举口径被打破）。
    const createSpy = jest.spyOn(User, 'create').mockRejectedValueOnce(
      Object.assign(new Error('E11000 duplicate key error collection users index emailKey_1'), {
        code: 11000,
        keyPattern: { emailKey: 1 },
      })
    );

    const out = await registerUser(
      {
        username: `zzdupem${Date.now()}`,
        email: `zzdupem${Date.now()}@example.com`,
        password: randomPassword(),
        realName: '邮箱撞键测试',
        privacyConsent: true,
      },
      { ip: '127.0.0.1', userAgent: 'dup-key-test', method: 'POST', path: '/api/auth/register' }
    );

    expect(createSpy).toHaveBeenCalled();
    expect(out.outcome).toBe('DUPLICATE');
    createSpy.mockRestore();
  });

  test('非撞键的 create 失败照常抛出（归一臂不吞真实故障）', async () => {
    const createSpy = jest
      .spyOn(User, 'create')
      .mockRejectedValueOnce(new Error('写库故障（注入）'));

    await expect(
      registerUser(
        {
          username: `zzdup${Date.now()}x`,
          email: `zzdup${Date.now()}x@example.com`,
          password: randomPassword(),
          realName: '非撞键',
          privacyConsent: true,
        },
        { ip: '127.0.0.1', userAgent: 'dup-key-test', method: 'POST', path: '/api/auth/register' }
      )
    ).rejects.toThrow('写库故障（注入）');
    createSpy.mockRestore();
  });
});
