/** 凭据字段契约（/security/reauth、管理员写操作与改密两条链共用）。抽出而非复制：任一处调整只改一边，两处的失败形态从此不同 */

const { body } = require('express-validator');
const config = require('../../config');
const { validatePasswordStrength } = require('../../utils/helpers');

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

/** strict 模式下 enc 与明文字段并存视为协议违规 */
const rejectEncPlaintextCoexistence = (encField, plainField) =>
  body(plainField).custom((value, { req }) => {
    if (config.loginEncryptStrict && req.body[encField] && value !== undefined && value !== '') {
      throw new Error(`已提供口令密文（${encField}），禁止同时携带明文字段（${plainField}）`);
    }
    return true;
  });

const passwordStrengthCheck = (value) => {
  // 统一强度策略的校验器壳：文案来自 helpers 单一实现（含长度上限与泄露黑名单）
  const err = validatePasswordStrength(value);
  if (err) throw new Error(err);
  return true;
};

// 明文轨口令统一上限 128 = 登录链（loginValidation）接受的口令上限，view-sensitive 与 /reauth 早已是 128；change-password 曾是 64，历史 65~128 字符口令会「能登录却改不了密码」。
const PLAINTEXT_PASSWORD_MAX_LENGTH = 128;

const reauthCredentialValidation = [
  encPasswordField('encCurrentPassword'),
  rejectEncPlaintextCoexistence('encCurrentPassword', 'currentPassword'),
  body('currentPassword')
    .if((value, { req }) => !req.body.encCurrentPassword)
    .optional({ values: 'falsy' })
    .isString()
    .withMessage('密码格式无效')
    .isLength({ max: PLAINTEXT_PASSWORD_MAX_LENGTH })
    .withMessage('密码长度异常')
    .custom(rejectPlaintextInStrict),
  body('mfaCode')
    .optional({ values: 'falsy' })
    .isString()
    .withMessage('验证码格式无效')
    .matches(/^\d{6}$/)
    .withMessage('验证码应为 6 位数字'),
];

/** 改密两条链（/auth/password、/security/change-password）共用；withConfirmPassword 仅后者需要 */
const buildChangePasswordValidation = ({ withConfirmPassword = false } = {}) => [
  encPasswordField('encCurrentPassword'),
  rejectEncPlaintextCoexistence('encCurrentPassword', 'currentPassword'),
  encPasswordField('encNewPassword'),
  rejectEncPlaintextCoexistence('encNewPassword', 'newPassword'),
  body('currentPassword')
    .if((value, { req }) => !req.body.encCurrentPassword)
    .isString()
    .withMessage('当前密码格式无效')
    .notEmpty()
    .withMessage('请提供当前密码')
    .isLength({ max: PLAINTEXT_PASSWORD_MAX_LENGTH })
    .withMessage('当前密码长度异常')
    .custom(rejectPlaintextInStrict),
  body('newPassword')
    .if((value, { req }) => !req.body.encNewPassword)
    .isString()
    .withMessage('新密码格式无效')
    .custom(passwordStrengthCheck)
    .custom(rejectPlaintextInStrict),
  ...(withConfirmPassword
    ? [
        body('confirmPassword').custom((value, { req }) => {
          if (!req.body.encNewPassword && value !== req.body.newPassword) {
            throw new Error('两次输入的密码不一致'); // 密文轨下明文在信封内，一致性由控制器解密后比对
          }
          return true;
        }),
      ]
    : []),
];

module.exports = {
  rejectPlaintextInStrict,
  encPasswordField,
  rejectEncPlaintextCoexistence,
  passwordStrengthCheck,
  reauthCredentialValidation,
  buildChangePasswordValidation,
};
