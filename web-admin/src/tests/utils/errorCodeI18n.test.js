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

  // W4（2026-10-31）：动态状态是「码 + 参数」通道的第二个真实用例（第一个是 FULL_RANGE_FORBIDDEN
  // 的 {ip}）。下面两条断言的是**实测字符串**——用真实 i18n 模块跑出来的现值，
  // 不是拼出来的模板，值来自 web-admin/src/i18n/locales/{zh-CN,en-US}.js 的
  // errors.privilegeGrantNotActive（与 apiStatusCodes.test.js 的 expired 用例同源、不同参数）。
  test('params 透传：PRIVILEGE_GRANT_NOT_ACTIVE 的 {currentStatus} 被真正填充（中英各一次）', () => {
    const expected = {
      'zh-CN': '该授权当前不在生效期（当前：revoked）',
      'en-US': 'This grant is not currently within its effective period (current: revoked)',
    }
    for (const locale of LOCALES) {
      i18n.global.locale.value = locale
      const msg = resolveErrorMessage({
        errors: { errorCode: 'PRIVILEGE_GRANT_NOT_ACTIVE', currentStatus: 'revoked' },
      })
      expect(msg, locale).toBe(expected[locale])
      // 占位被真正替换：留着花括号就是把模板喷给用户
      expect(msg, locale).not.toContain('{')
      expect(msg, locale).toContain('revoked')
    }
  })

  /**
   * 负向断言：缺参时**保留字面占位符**，而不是替换成空串。
   *
   * 这不是「随便钉个现状」，而是本仓 web-admin/src/i18n/index.js 的自定义 messageCompiler
   * 的**有意行为**：它的回退链是「values 命中 → ctx.list 位置参数 → 原样返回 match」。
   * 之所以不用 vue-i18n 默认编译器：默认实现走 new Function（JIT），CSP 无
   * "unsafe-eval" 时登录页渲染直接 EvalError（见该文件头注释）。
   *
   * 这条断言的用意：
   *  1. 谁把编译器改回默认实现 ⇒ 缺参行为变化（空串/其它）⇒ 立即红；
   *  2. 谁把词表里的 {currentStatus} 占位删掉（"反正缺参看不出来"）⇒ 期望串里仍带占位 ⇒ 也红。
   * 缺参的真实场景：后端 409 的 errors 未携带 currentStatus（老版本/半升级）——
   * 用户至少看到「当前：{currentStatus}」这种明显异常，而不是「当前：」的空洞。
   */
  test('缺参保留字面占位符（自定义 messageCompiler 的有意行为，非替换成空串）', () => {
    const expected = {
      'zh-CN': '该授权当前不在生效期（当前：{currentStatus}）',
      'en-US': 'This grant is not currently within its effective period (current: {currentStatus})',
    }
    for (const locale of LOCALES) {
      i18n.global.locale.value = locale
      // errors 存在但缺 currentStatus：模拟后端 409 未携带动态状态字段
      const msg = resolveErrorMessage({ errors: { errorCode: 'PRIVILEGE_GRANT_NOT_ACTIVE' } })
      expect(msg, locale).toBe(expected[locale])
      expect(msg, locale).toContain('{currentStatus}')
    }
  })
})
