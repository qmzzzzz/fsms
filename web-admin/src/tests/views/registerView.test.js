/**
 * 注册页强化回归测试
 *
 * 两部分：
 *  1. evaluatePasswordRules 与 isStrongPassword 必须同源同判 ——
 *     强度指示器「五条全绿」若与提交校验不一致，界面就会自相矛盾
 *     （全绿却提交被拒，或标红却能提交成功）。
 *  2. RegisterView 的主题适配静态不变量 —— 组件样式必须走 --xf-* 变量，
 *     写死 #fff / #000 这类色值在 html.dark 下会变成刺眼的白板。
 *     这类问题无法用 jsdom 断言（CSS 变量不参与计算），故以源码约束兜住。
 */
import { describe, test, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import {
  evaluatePasswordRules,
  isStrongPassword,
  PASSWORD_MAX_LENGTH,
  PASSWORD_MAX_BYTES,
} from '@/utils/password'

const readSrc = (rel) => readFileSync(resolve(__dirname, '../..', rel), 'utf8')

describe('evaluatePasswordRules 逐条判据', () => {
  test('空口令五条全不通过', () => {
    const r = evaluatePasswordRules('')
    expect(r.passed).toBe(0)
    expect(r.satisfied).toBe(false)
    expect(r.total).toBe(5)
  })

  test('非字符串入参按空串处理（不抛错）', () => {
    for (const v of [null, undefined, 123, {}, []]) {
      expect(evaluatePasswordRules(v).passed).toBe(0)
    }
  })

  test('逐项识别缺失的规则', () => {
    // 缺大写
    expect(evaluatePasswordRules('abcdefg1!').upper).toBe(false)
    // 缺小写
    expect(evaluatePasswordRules('ABCDEFG1!').lower).toBe(false)
    // 缺数字
    expect(evaluatePasswordRules('Abcdefgh!').digit).toBe(false)
    // 缺特殊字符
    expect(evaluatePasswordRules('Abcdefg1').symbol).toBe(false)
    // 长度不足（7 位）
    expect(evaluatePasswordRules('Abcde1!').length).toBe(false)
  })

  test('合格口令五条全通过', () => {
    const r = evaluatePasswordRules('Str0ng-Pass_2026')
    expect(r).toMatchObject({
      length: true,
      upper: true,
      lower: true,
      digit: true,
      symbol: true,
    })
    expect(r.satisfied).toBe(true)
    expect(r.passed).toBe(5)
  })

  test('P3-29 放宽后的标点（- 与 _）被视为特殊字符', () => {
    expect(evaluatePasswordRules('Str0ng-Pass').symbol).toBe(true)
    expect(evaluatePasswordRules('Str0ng_Pass').symbol).toBe(true)
  })

  test('长度上限：字符数 64 与 UTF-8 字节数 72 双约束', () => {
    // 恰好 64 字符且全 ASCII（64 字节）→ 通过
    const ok = 'Aa1!' + 'x'.repeat(PASSWORD_MAX_LENGTH - 4)
    expect(ok.length).toBe(PASSWORD_MAX_LENGTH)
    expect(evaluatePasswordRules(ok).length).toBe(true)

    // 65 字符 → 超字符上限
    expect(evaluatePasswordRules(ok + 'y').length).toBe(false)

    // 25 个汉字 = 75 字节（>72），字符数只有 29 却已越过 bcrypt 边界
    const cjk = 'Aa1!' + '密'.repeat(25)
    expect(cjk.length).toBeLessThan(PASSWORD_MAX_LENGTH)
    expect(new TextEncoder().encode(cjk).length).toBeGreaterThan(PASSWORD_MAX_BYTES)
    expect(evaluatePasswordRules(cjk).length).toBe(false)
  })

  test('satisfied 与 isStrongPassword 结论完全一致（同源判据）', () => {
    const samples = [
      '',
      'a',
      'abcdefgh',
      'ABCDEFGH',
      '12345678',
      '!!!!!!!!',
      'Abcdefg1',
      'Abcdefg!',
      'abcdefg1!',
      'ABCDEFG1!',
      'Str0ng-Pass_2026',
      'Aa1!Aa1!',
      'Aa1!' + 'x'.repeat(60),
      'Aa1!' + 'x'.repeat(61),
      'Aa1!' + '密'.repeat(25),
    ]
    for (const s of samples) {
      expect(evaluatePasswordRules(s).satisfied).toBe(isStrongPassword(s))
    }
  })
})

describe('RegisterView 主题与可访问性不变量', () => {
  const source = readSrc('views/RegisterView.vue')
  // 语言/主题切换入口已抽取为共享组件，断言指向新实现（AuthPrefs.vue）
  const authPrefsSource = readSrc('components/AuthPrefs.vue')
  // D-2：信息核对拆为 RegisterSummary 组件，暗色覆盖断言随之指向新实现
  const summarySource = readSrc('components/RegisterSummary.vue')

  test('不写死背景色值：样式一律走 --xf-* 变量', () => {
    // 只检查 background 属性上的硬编码色值；--xf-* 里的 rgba() 由 global/dark.css 负责翻转
    const hardcoded = source
      .split('\n')
      .filter((line) => /^\s*background(-color)?\s*:/.test(line))
      .filter((line) => /#[0-9a-fA-F]{3,8}\b/.test(line))
    expect(hardcoded).toEqual([])
  })

  test('提供主题切换入口（登录前主布局不可用）', () => {
    // 主题入口已抽取为共享组件 AuthPrefs：视图必须挂载它，具体切换实现断言指向组件
    expect(source).toContain('<AuthPrefs')
    expect(authPrefsSource).toContain('appStore.setThemeMode')
    for (const cmd of ['command="system"', 'command="light"', 'command="dark"']) {
      expect(authPrefsSource).toContain(cmd)
    }
  })

  test('暗色下必须显式覆盖的位置已覆盖（提示条与光斑）', () => {
    expect(summarySource).toContain('html.dark .summary__row')
    expect(source).toContain('html.dark .register__aurora')
  })

  test('强度条与信息核对已拆为子组件（D-2）', () => {
    expect(source).toContain('<PasswordStrengthMeter')
    expect(source).toContain('<RegisterSummary')
    // 子组件与提交校验共用同一套判据，保证界面指示与后端准入一致
    expect(readSrc('components/PasswordStrengthMeter.vue')).toContain('evaluatePasswordRules')
  })

  test('语言/主题切换是带文字的按钮而非裸图标', () => {
    expect(authPrefsSource).toContain('auth-prefs__text') // 图标+文字，非裸图标
    expect(authPrefsSource).toContain('themeLabel')
    expect(authPrefsSource).toContain('languageLabel')
  })

  test('分步向导：三步 + 分步字段校验 + 提交前整表校验', () => {
    expect(source).toContain('STEP_FIELDS')
    expect(source).toContain('validateField(fields)')
    expect(source).toContain('registerFormRef.value.validate()')
  })

  test('确认密码随密码变更联动重校验', () => {
    expect(source).toContain("validateField('confirmPassword')")
  })

  test('选填字段不设 required（与后端 optional 一致）', () => {
    // realName / department 不应出现在 rules 中的 required 项
    const rulesBlock = source.slice(
      source.indexOf('const rules = {'),
      source.indexOf('// 改密码后重新校验确认框')
    )
    expect(/realName:\s*\[[^\]]*required:\s*true/s.test(rulesBlock)).toBe(false)
    expect(/department:\s*\[[^\]]*required:\s*true/s.test(rulesBlock)).toBe(false)
  })

  test('不引入中文裸键（新代码必须用规范键）', () => {
    expect(/(?:\$t|\bt)\(\s*'[^']*[\u4e00-\u9fa5]/.test(source)).toBe(false)
  })
})

describe('LoginView 语言切换可见性', () => {
  const source = readSrc('views/LoginView.vue')
  const authPrefsSource = readSrc('components/AuthPrefs.vue')

  test('语言入口带当前语言文字（原为不可见的裸图标）', () => {
    // 语言入口位于共享 AuthPrefs 组件，视图仅以 class 传参定位
    expect(source).toContain('<AuthPrefs')
    expect(authPrefsSource).toContain('auth-prefs__text')
    expect(authPrefsSource).toContain('languageLabel')
  })

  test('不写死背景色值（验证码占位块此前是 #f0f2f5）', () => {
    const hardcoded = source
      .split('\n')
      .filter((line) => /^\s*background(-color)?\s*:/.test(line))
      .filter((line) => /#[0-9a-fA-F]{3,8}\b/.test(line))
    expect(hardcoded).toEqual([])
  })
})
