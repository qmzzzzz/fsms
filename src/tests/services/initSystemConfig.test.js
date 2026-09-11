/**
 * initSystemConfig 播种语义回归（P1-7）
 *
 * 背景（安全属性倒退）：allowPublicRegistration 原先用 SystemConfig.set 无条件
 * 覆写，每次服务重启都按 ALLOW_PUBLIC_REGISTRATION 环境变量还原。管理员通过
 * PUT /api/security/config/allowPublicRegistration 关闭公开注册后，
 * 一次重启就悄悄重新开放公网注册；反向的「临时开放后关闭」同样无法持久。
 * 紧邻的 loginCaptchaEnabled 早已改用 $setOnInsert 并注释了这一理由。
 *
 * 修复口径：两个开关都只在配置不存在时播种，运行时状态由 API 独占管理。
 */

const mongoose = require('mongoose');

describe('P1-7 initSystemConfig 只播种不覆写', () => {
  let SystemConfig;
  let initSystemConfig;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    ({ SystemConfig } = require('../../models'));
    ({ initSystemConfig } = require('../../services/initData'));
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  const KEYS = ['allowPublicRegistration', 'loginCaptchaEnabled'];

  /** 清掉两个开关，模拟全新部署 */
  const resetConfigs = async () => {
    await SystemConfig.deleteMany({ key: { $in: KEYS } });
    SystemConfig.invalidateRegistrationCache();
    SystemConfig.invalidateLoginCaptchaCache();
  };

  const withEnv = async (value, fn) => {
    const original = process.env.ALLOW_PUBLIC_REGISTRATION;
    if (value === undefined) delete process.env.ALLOW_PUBLIC_REGISTRATION;
    else process.env.ALLOW_PUBLIC_REGISTRATION = value;
    try {
      await fn();
    } finally {
      if (original === undefined) delete process.env.ALLOW_PUBLIC_REGISTRATION;
      else process.env.ALLOW_PUBLIC_REGISTRATION = original;
    }
  };

  test('首次启动按环境变量播种（true）', async () => {
    await resetConfigs();
    await withEnv('true', async () => {
      await initSystemConfig();
      const doc = await SystemConfig.findOne({ key: 'allowPublicRegistration' }).lean();
      expect(doc.value).toBe(true);
      expect(doc.valueType).toBe('boolean');
    });
  });

  test('首次启动按环境变量播种（缺省视为 false）', async () => {
    await resetConfigs();
    await withEnv(undefined, async () => {
      await initSystemConfig();
      const doc = await SystemConfig.findOne({ key: 'allowPublicRegistration' }).lean();
      expect(doc.value).toBe(false);
    });
  });

  // ===== 核心回归：曾经的安全属性倒退 =====
  test('管理员关闭注册后重启不被 env=true 还原', async () => {
    await resetConfigs();
    await withEnv('true', async () => {
      await initSystemConfig();
      expect((await SystemConfig.findOne({ key: 'allowPublicRegistration' }).lean()).value).toBe(
        true
      );

      // 管理员通过 API 关闭（SystemConfig.set 是配置接口的底层）
      await SystemConfig.set('allowPublicRegistration', false, null);
      expect(await SystemConfig.isRegistrationAllowed()).toBe(false);

      // 模拟服务重启
      await initSystemConfig();

      const after = await SystemConfig.findOne({ key: 'allowPublicRegistration' }).lean();
      expect(after.value).toBe(false);
      expect(await SystemConfig.isRegistrationAllowed()).toBe(false);
    });
  });

  test('管理员开启注册后重启不被 env=false 还原（反向同样持久）', async () => {
    await resetConfigs();
    await withEnv('false', async () => {
      await initSystemConfig();
      await SystemConfig.set('allowPublicRegistration', true, null);

      await initSystemConfig();

      expect((await SystemConfig.findOne({ key: 'allowPublicRegistration' }).lean()).value).toBe(
        true
      );
    });
  });

  test('登录验证码开关维持既有的 $setOnInsert 语义（不回归）', async () => {
    await resetConfigs();
    await initSystemConfig();
    await SystemConfig.set('loginCaptchaEnabled', true, null);

    await initSystemConfig();

    expect((await SystemConfig.findOne({ key: 'loginCaptchaEnabled' }).lean()).value).toBe(true);
  });

  test('播种后缓存被显式失效（updateOne 绕过了 set 内置的失效逻辑）', async () => {
    await resetConfigs();
    // 先读一次，让负缓存生效
    await SystemConfig.isRegistrationAllowed();

    await withEnv('true', async () => {
      await initSystemConfig();
      // 若缓存未被失效，此处仍会读到播种前的 false
      expect(await SystemConfig.isRegistrationAllowed()).toBe(true);
    });
  });
});
