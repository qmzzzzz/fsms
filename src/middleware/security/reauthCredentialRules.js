/**
 * 二次验证凭据的字段契约（/security/reauth 与管理员写操作共用）。抽出而非复制：strict 模式下「密文与明文并存」或
 * 长度上限的任一处调整只改一边，就会一边拒绝、一边把坏格式送进口令比对，两处失败形态从此不同。
 */

const { body } = require('express-validator');
const config = require('../../config');

/** 明文轨守卫：LOGIN_ENCRYPT_STRICT=true 后所有明文口令字段直接拒绝 */
const rejectPlaintextInStrict = () => {
  if (config.loginEncryptStrict) {
    throw new Error('服务端已启用口令加密传输，请刷新页面后重试');
  }
  return true;
};

/** 口令密文字段的统一格式约束（ECDH 信封 base64，上限与 loginCipher 一致） */
const encPasswordField = (field) =>
  body(field)
    .optional({ values: 'falsy' })
    .isString()
    .withMessage('口令密文格式无效')
    .isLength({ max: 1024 })
    .withMessage('口令密文长度异常');

/** strict 模式下 enc 与明文字段并存视为协议违规（与 authRoutes 同口径） */
const rejectEncPlaintextCoexistence = (encField, plainField) =>
  body(plainField).custom((value, { req }) => {
    if (config.loginEncryptStrict && req.body[encField] && value !== undefined && value !== '') {
      throw new Error(`已提供口令密文（${encField}），禁止同时携带明文字段（${plainField}）`);
    }
    return true;
  });

const reauthCredentialValidation = [
  encPasswordField('encCurrentPassword'),
  rejectEncPlaintextCoexistence('encCurrentPassword', 'currentPassword'),
  body('currentPassword')
    .if((value, { req }) => !req.body.encCurrentPassword)
    .optional({ values: 'falsy' })
    .isString()
    .withMessage('密码格式无效')
    .isLength({ max: 128 })
    .withMessage('密码长度异常')
    .custom(rejectPlaintextInStrict),
  body('mfaCode')
    .optional({ values: 'falsy' })
    .isString()
    .withMessage('验证码格式无效')
    .matches(/^\d{6}$/)
    .withMessage('验证码应为 6 位数字'),
];

module.exports = {
  rejectPlaintextInStrict,
  encPasswordField,
  rejectEncPlaintextCoexistence,
  reauthCredentialValidation,
};
