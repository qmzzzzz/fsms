/**
 * 错误码 i18n 映射对齐测试
 *
 * 背景：web-admin 无 ESLint，key 拼写错误只能靠运行时发现（vue-i18n 会
 * 回显 key 本身 + 控制台警告）。本测试静态锁定：ERROR_CODE_I18N_MAP 的
 * 每个 key 在 zh-CN 与 en-US 两个 locale 都能解析出非 key 文案。
 *
 * 同时锁定后端错误码契约样例：前端映射的码集合应覆盖后端已迁移码
 * （双向对齐的简化近似：断言关键码存在，避免测试与后端注册表强耦合）。
 */
import { describe, test, expect, beforeEach } from 'vitest'
import { ERROR_CODE_I18N_MAP, resolveErrorMessage } from '@/utils/api'
import i18n from '@/i18n'

const LOCALES = ['zh-CN', 'en-US']

describe('ERROR_CODE_I18N_MAP 与 locale 对齐', () => {
  beforeEach(() => {
    // 清空假性缓存：切 locale 时 vue-i18n 消息编译可能被复用
  })

  LOCALES.forEach((locale) => {
    test(`${locale}：每个映射 key 均解析出非 key 文案`, () => {
      i18n.global.locale.value = locale
      for (const [code, i18nKey] of Object.entries(ERROR_CODE_I18N_MAP)) {
        const resolved = i18n.global.t(i18nKey)
        expect(resolved, `${code} → ${i18nKey} 在 ${locale} 未解析`).not.toBe(i18nKey)
        expect(resolved.trim().length, `${code} → ${i18nKey} 文案为空`).toBeGreaterThan(0)
      }
    })
  })

  test('关键认证/安全码已收录', () => {
    const mustHave = [
      'FULL_RANGE_FORBIDDEN',
      'AUTH_INVALID_CREDENTIALS',
      'AUTH_IP_RANGE_DENIED',
      'AUTH_USER_NOT_FOUND',
      'CAPTCHA_INVALID',
      'MFA_CODE_INVALID',
      'MFA_ATTEMPTS_EXCEEDED',
      'MFA_VERIFY_FAILED',
      'IP_REQUIRED',
      'IP_FORMAT_INVALID',
    ]
    mustHave.forEach((code) => {
      expect(ERROR_CODE_I18N_MAP[code], `缺少错误码 ${code}`).toBeDefined()
    })
  })

  test('超管不可变约束码已收录（此前这批消息只有中文原文）', () => {
    const mustHave = [
      'CANNOT_DELETE_SELF',
      'CANNOT_DELETE_SUPER_ADMIN',
      'CANNOT_DISABLE_SUPER_ADMIN',
      'CANNOT_LOCK_SUPER_ADMIN',
      'CANNOT_RESET_MFA_SUPER_ADMIN',
      'CANNOT_GRANT_SUPER_ADMIN_ON_CREATE',
      'SUPER_ADMIN_ROLE_NOT_DETACHABLE',
      'SUPER_ADMIN_ROLE_NOT_GRANTABLE',
      'SUPER_ADMIN_ROLE_PERMISSIONS_LOCKED',
      'SUPER_ADMIN_ROLE_NOT_CLONABLE',
    ]
    mustHave.forEach((code) => {
      expect(ERROR_CODE_I18N_MAP[code], `缺少错误码 ${code}`).toBeDefined()
    })
  })
})

describe('resolveErrorMessage', () => {
  test('已知码返回本地化文案', () => {
    i18n.global.locale.value = 'zh-CN'
    const msg = resolveErrorMessage({
      errors: { errorCode: 'AUTH_INVALID_CREDENTIALS' },
      message: '用户名或密码错误',
    })
    expect(msg).toBe('用户名或密码错误')
  })

  test('英文 locale 返回英文文案（取代中文字符串匹配）', () => {
    i18n.global.locale.value = 'en-US'
    const msg = resolveErrorMessage({
      errors: { errorCode: 'MFA_ATTEMPTS_EXCEEDED' },
      message: '验证尝试次数过多，请 10 分钟后再试',
    })
    expect(msg).toBe('Too many verification attempts. Please try again in 10 minutes')
  })

  test('未码化接口（无 errorCode）返回 null，调用方回退后端 message', () => {
    expect(resolveErrorMessage({ message: '任意未码化消息' })).toBeNull()
    expect(resolveErrorMessage({ errors: null, message: 'x' })).toBeNull()
  })

  test('未知码（后端新增、前端未跟上）返回 null 而非报错', () => {
    expect(resolveErrorMessage({ errors: { errorCode: 'FUTURE_CODE' } })).toBeNull()
  })

  test('params 透传：FULL_RANGE_FORBIDDEN 的 {ip} 占位被填充', () => {
    i18n.global.locale.value = 'zh-CN'
    const msg = resolveErrorMessage({
      errors: { errorCode: 'FULL_RANGE_FORBIDDEN', ip: '0.0.0.0/0' },
    })
    expect(msg).toContain('0.0.0.0/0')
  })
})
