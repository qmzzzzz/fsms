/**
 * 系统初始化数据服务 · 系统配置播种（allowPublicRegistration / loginCaptchaEnabled）
 * 2026-10-19 批 3c：自 src/services/initData.js 拆出（纯搬家，语义不变）。
 */

const logger = require('../../utils/logger');

/**
 * 初始化系统配置（注册开关等）
 */
const initSystemConfig = async () => {
  const { SystemConfig } = require('../../models');

  // 注册开关：默认关闭公开注册（生产环境安全）
  // 仅在配置不存在时按环境变量播种（$setOnInsert），此后由
  // PUT /api/security/config/allowPublicRegistration 独占管理。
  //
  // 必须用 $setOnInsert 而非无条件 set：若每次启动都按 env 覆写，
  // 管理员在运行时关闭注册后，一次重启就会按 ALLOW_PUBLIC_REGISTRATION=true
  // 悄悄重新开放公网注册——安全属性静默倒退，且反向的「临时开放后关闭」
  // 同样无法持久。与紧邻的 loginCaptchaEnabled 保持同一口径。
  await SystemConfig.updateOne(
    { key: 'allowPublicRegistration' },
    {
      $setOnInsert: {
        key: 'allowPublicRegistration',
        value: process.env.ALLOW_PUBLIC_REGISTRATION === 'true',
        valueType: 'boolean',
        description: '公开注册开关',
      },
    },
    { upsert: true }
  );

  // 登录验证码开关：默认关闭；仅在配置不存在时播种（$setOnInsert），
  // 管理员通过 API 修改后的状态不会被服务重启覆盖
  await SystemConfig.updateOne(
    { key: 'loginCaptchaEnabled' },
    {
      $setOnInsert: {
        key: 'loginCaptchaEnabled',
        value: false,
        valueType: 'boolean',
        description: '登录图形验证码开关',
      },
    },
    { upsert: true }
  );

  // updateOne 绕过了 SystemConfig.set 内置的缓存失效，此处显式清理：
  // 测试/嵌入场景可能在同进程内先读过开关（写入负缓存），播种后需让其重读
  SystemConfig.invalidateRegistrationCache();
  SystemConfig.invalidateLoginCaptchaCache();

  logger.info('系统配置初始化完成');
};

module.exports = { initSystemConfig };
