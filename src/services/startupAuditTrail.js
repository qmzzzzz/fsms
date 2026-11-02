/**
 * 启动期密钥治理留痕（WB-1 + P2-3）：密钥强度校验通过 + JWT 签发密钥轮换。
 * 从 `src/index.js` 抽出——入口同时撞 max-lines(300) 与 max-lines-per-function(100)，
 * 纪律「只许降不许升」故拆分而非抬基线。选它是因为纯副作用、不参与启动控制流
 * （两条写入失败都只告警），调用点时序与失败语义一字未变。
 * 判据走 `config/validate` 的环境归一：字面量比较会让 `NODE_ENV=prod` 静默少一条留痕。
 */

const logger = require('../utils/logger');

/** 两条留痕都不阻断启动：审计不可用不应反过来让服务起不来；非生产语义直接返回。 */
const recordStartupAuditTrail = async () => {
  // 内联 require 而非模块顶层：保持与抽出前一致的加载时机（原实现即在块内按需 require）
  const { requiresProductionSemantics } = require('../config/validate');
  if (!requiresProductionSemantics()) return;

  try {
    const AuditLog = require('../models/AuditLog');
    await AuditLog.record({
      action: 'security_key_strength_audit',
      category: 'security',
      username: 'system',
      ip: '127.0.0.1',
      success: true,
      riskLevel: 'low',
      reason: '启动配置校验通过：JWT/JWT_REFRESH/AES/HMAC 密钥均满足强度要求',
    });
  } catch (auditErr) {
    logger.warn(`密钥强度审计留痕写入失败：${auditErr.message}`);
  }

  // P2-3：基线态只登记不落审计（首次配置不是轮换），currentKid 变化时写 jwt_key_rotated；失败只告警
  try {
    await require('./jwtKeyRotationAudit').recordJwtKeyRotation();
  } catch (rotationErr) {
    logger.warn(`JWT 密钥轮换审计留痕失败：${rotationErr.message}`);
  }
};

module.exports = { recordStartupAuditTrail };
