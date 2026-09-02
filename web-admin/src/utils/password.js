/**
 * 密码强度校验 - 与后端统一策略对齐
 * 后端实现见 src/utils/helpers.js PASSWORD_RULES：
 * 至少 12 位、不超过 64 字符（且 UTF-8 编码不超过 72 字节），
 * 且包含大写字母、小写字母、数字、特殊字符
 * （L-1，2026-09-02：最小长度 8 → 12，前后端必须同步，否则一端拒绝另一端接受）
 */

/**
 * 密码强度正则（与后端 PASSWORD_RULES 等价，合并为单个表达式）
 *
 * P3-29：特殊字符类由 `[!@#$%^&*(),.?":{}|<>]` 放宽为全部 ASCII 可打印标点
 * （四段区间 !-/ :-@ [-` {-~），此前 `Str0ng-Pass_2026` 这类强口令会被前端
 * 提前拒绝，用户甚至无法提交。前后端必须同步放宽，否则一端拒绝另一端接受。
 */
export const PASSWORD_STRENGTH_REGEX =
  /^(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9])(?=.*[!-/:-@[-`{-~]).{12,64}$/

/** 与后端一致的长度上限：字符数 64、UTF-8 字节数 72（bcrypt 硬边界） */
export const PASSWORD_MAX_LENGTH = 64
export const PASSWORD_MAX_BYTES = 72

/**
 * 计算字符串的 UTF-8 字节长度
 * @param {string} str 待计算字符串
 * @returns {number} 字节数
 */
const utf8ByteLength = (str) => new TextEncoder().encode(str).length

/**
 * 校验密码强度
 * @param {string} password 待校验密码
 * @returns {boolean} 是否满足强度要求
 */
export const isStrongPassword = (password) => {
  if (typeof password !== 'string') return false
  if (password.length > PASSWORD_MAX_LENGTH) return false
  if (utf8ByteLength(password) > PASSWORD_MAX_BYTES) return false
  return PASSWORD_STRENGTH_REGEX.test(password)
}

/**
 * 逐条评估密码规则（供注册页强度指示器复用）
 *
 * 与 isStrongPassword 共用同一组判据：指示器全绿即等价于 isStrongPassword 为真，
 * 不能各自写一套正则——否则会出现「五条全绿但提交被拒」这种自相矛盾的界面。
 *
 * @param {string} password 待评估密码
 * @returns {{length: boolean, upper: boolean, lower: boolean, digit: boolean, symbol: boolean, passed: number, total: number, satisfied: boolean}}
 */
export const evaluatePasswordRules = (password) => {
  const value = typeof password === 'string' ? password : ''
  const checks = {
    // 长度同时受字符数与 UTF-8 字节数约束（后者是 bcrypt 的 72 字节硬边界）
    length:
      value.length >= 12 &&
      value.length <= PASSWORD_MAX_LENGTH &&
      utf8ByteLength(value) <= PASSWORD_MAX_BYTES,
    upper: /[A-Z]/.test(value),
    lower: /[a-z]/.test(value),
    digit: /[0-9]/.test(value),
    symbol: /[!-/:-@[-`{-~]/.test(value),
  }
  const passed = Object.values(checks).filter(Boolean).length
  return {
    ...checks,
    passed,
    total: 5,
    satisfied: passed === 5,
  }
}

/**
 * 生成 el-form 密码强度校验规则
 * @param {string} message i18n 提示文案（如 t('validation.passwordStrength')）
 * @returns {object} async-validator 规则
 */
export const passwordStrengthRule = (message) => ({
  validator: (rule, value, callback) => {
    if (!value) {
      // 空值交由 required 规则处理
      callback()
      return
    }
    if (isStrongPassword(value)) {
      callback()
    } else {
      callback(new Error(message))
    }
  },
  trigger: 'blur',
})
