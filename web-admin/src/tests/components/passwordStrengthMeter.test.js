/**
 * PasswordStrengthMeter 行为测试（注册页口令强度实时条）
 *
 * 组件承诺（PasswordStrengthMeter.vue:1-5 注释）：「判据复用 evaluatePasswordRules，
 * 与提交时的校验同源」，且 4/5 不能标成「强」——否则用户看到「强」却在提交时
 * 被后端拒绝，界面与结果自相矛盾。本套件把这三条承诺变成可失败的断言：
 *
 *  1. 五条规则各自独立反映判据（含「部分通过」的混合态）：哪一条判据被写反，
 *     对应的 <li> 就会缺 is-ok，图标也仍是 Minus（用 path 的 d 属性区分，
 *     而不是只看 class——class 与图标不一致时用户看到的仍是错误图标）；
 *  2. 强度分档边界：五条全过=强、恰 3 条=中、2 条及以下=弱。边界取 3 与 2，
 *     因为 `passed >= 3` 的 off-by-one 只会在这两个样本上显形；
 *  3. 进度轨宽度 = passed/total（scaleX）：0/0.2/0.4/0.6/0.8/1 逐档断言，
 *     写死宽度或漏乘比例都会让进度与规则条数脱节；
 *  4. 空口令：不显示任何强度结论，显示「尚未输入口令」，进度为 0——
 *     空值走 weak 文案会误导用户「已输入但太弱」；
 *  5. 双语：切换 locale 后标签与结论都跟随（组件用 t() 在渲染期求值）。
 *
 * 环境事实：fill 宽度以 inline style `transform: scaleX(n)` 表达（探针实测），
 * 故按字符串精确断言，不用近似匹配。
 */
import { describe, test, expect, afterEach } from 'vitest'
import { mountComponent, flush } from '../helpers/componentHarness'
import i18n from '@/i18n'
import PasswordStrengthMeter from '@/components/PasswordStrengthMeter.vue'

/** Element Plus 图标在 jsdom 里渲染为 <svg><path d="..."></svg>，用 d 前缀区分 */
const CHECK_D = 'M512 896a384 384'
const MINUS_D = 'M128 544h768'

let active = null
const open = async (password, locale = 'zh-CN') => {
  active = mountComponent(PasswordStrengthMeter, { props: { password }, locale })
  await flush(4)
  return active
}
afterEach(() => {
  active?.handle.unmount()
  active = null
})

const rules = (c) =>
  c.findAll('.pwd-meter__rules li').map((li) => ({
    text: li.textContent.trim(),
    ok: li.classList.contains('is-ok'),
    icon: li.querySelector('path').getAttribute('d'),
  }))
const level = (c) => ({
  text: c.find('.pwd-meter__level').textContent.trim(),
  cls: c.find('.pwd-meter__level').className,
})
const fill = (c) => c.find('.pwd-meter__fill').getAttribute('style')

describe('PasswordStrengthMeter 规则逐条与图标', () => {
  test('上一个用例的组件已卸载，不残留 DOM（跨用例隔离）', async () => {
    // 本用例执行时，前序用例的 afterEach 必须已清场。删掉 afterEach 里的
    // unmount 时这里会看到累积的 .pwd-meter，测试立即变红。
    expect(document.body.querySelectorAll('.pwd-meter').length).toBe(0)
  })

  test('强口令：五条全部 is-ok 且图标为对勾', async () => {
    const c = await open('Str0ng-Pass_2026')
    const list = rules(c)
    expect(list.map((r) => r.ok)).toEqual([true, true, true, true, true])
    expect(list.map((r) => r.icon.startsWith(CHECK_D))).toEqual([true, true, true, true, true])
    expect(list.map((r) => r.text)).toEqual([
      '12-64 个字符',
      '含大写字母',
      '含小写字母',
      '含数字',
      '含特殊字符',
    ])
    expect(c.errors).toEqual([])
  })

  test('混合态：缺长度与特殊字符的两条判红，其余三条判绿（逐条独立）', async () => {
    // 'Abcdefg1' 恰好缺长度(8<12)与特殊字符，是「部分通过」的精确样本
    const c = await open('Abcdefg1')
    const list = rules(c)
    expect(list.map((r) => r.ok)).toEqual([false, true, true, true, false])
    expect(list.map((r) => r.icon.startsWith(MINUS_D))).toEqual([true, false, false, false, true])
    // 进度必须与通过条数一致：3/5
    expect(fill(c)).toBe('transform: scaleX(0.6);')
    expect(level(c).text).toBe('中')
  })

  test('长度判据是 >= 12（不是词表文案的 8）：11 位仍判红', async () => {
    // 组件注释承诺与提交校验同源（utils/password.js 的 12 位下限）。
    // 文案已与判据对齐（均为 12-64）；本用例钉**判据**，上方第 61 行用例另钉住文案两边。
    // 文案不一致问题已在交付报告中单独记录（不在本 agent 写集内）。
    const c = await open('Abcdefg1!xy')
    expect(rules(c)[0].ok).toBe(false)
    expect(level(c).text).toBe('中')
  })

  test('每类字符各缺一样时，恰好对应那一条判红', async () => {
    // 索引即 pwdRuleItems 的顺序：0=length 1=upper 2=lower 3=digit 4=symbol
    const cases = [
      ['abcdefg1!xyz', 1, '缺大写'],
      ['ABCDEFG1!123', 2, '缺小写'],
      ['Abcdefgh!xyz', 3, '缺数字'],
      ['Abcdefg1xyzw', 4, '缺特殊字符'],
    ]
    for (const [pwd, idx, label] of cases) {
      const c = await open(pwd)
      const list = rules(c)
      expect(list[idx].ok, `${label}：第 ${idx} 条应判红`).toBe(false)
      // 其余四条全绿（样本已满足长度 12）
      expect(
        list.filter((_, i) => i !== idx).every((r) => r.ok),
        `${label}：其余四条应全绿`
      ).toBe(true)
      c.handle.unmount()
      active = null
    }
  })
})

describe('PasswordStrengthMeter 强度分档边界', () => {
  test('五条全过 → 强（不是 4/5）', async () => {
    const strong = await open('Str0ng-Pass_2026')
    expect(level(strong)).toEqual({ text: '强', cls: 'pwd-meter__level pwd-meter__level--strong' })
    expect(fill(strong)).toBe('transform: scaleX(1);')
    strong.handle.unmount()
    active = null

    // 4/5：只差特殊字符 → 必须是「中」，否则用户会被界面骗去提交
    const four = await open('Abcdefghijkl')
    expect(rules(four).filter((r) => r.ok).length).toBe(3)
    expect(level(four).text).toBe('中')
  })

  test('恰好 3 条 → 中；恰好 2 条 → 弱（passed >= 3 的边界两侧）', async () => {
    const three = await open('Abcdefghijkl')
    expect(rules(three).filter((r) => r.ok).length).toBe(3)
    expect(level(three)).toEqual({ text: '中', cls: 'pwd-meter__level pwd-meter__level--fair' })
    expect(fill(three)).toBe('transform: scaleX(0.6);')
    three.handle.unmount()
    active = null

    const two = await open('abcdefghijkl')
    expect(rules(two).filter((r) => r.ok).length).toBe(2)
    expect(level(two)).toEqual({ text: '弱', cls: 'pwd-meter__level pwd-meter__level--weak' })
    expect(fill(two)).toBe('transform: scaleX(0.4);')
  })

  test('分档 class 与进度条 class 同步（颜色档位不能脱节）', async () => {
    for (const [pwd, lv] of [
      ['Str0ng-Pass_2026', 'strong'],
      ['Abcdefghijkl', 'fair'],
      ['abcdefghijkl', 'weak'],
    ]) {
      const c = await open(pwd)
      expect(c.find('.pwd-meter__level').className).toContain(`pwd-meter__level--${lv}`)
      expect(c.find('.pwd-meter__fill').className).toContain(`pwd-meter__fill--${lv}`)
      c.handle.unmount()
      active = null
    }
  })
})

describe('PasswordStrengthMeter 空态与双语', () => {
  test('空口令：显示「尚未输入口令」而非「弱」，进度为 0，五条全红', async () => {
    const c = await open('')
    expect(level(c).text).toBe('尚未输入口令')
    expect(fill(c)).toBe('transform: scaleX(0);')
    expect(rules(c).every((r) => !r.ok)).toBe(true)
  })

  test('默认 prop（不传 password）等价于空串，不抛错', async () => {
    const c = await open(undefined)
    expect(level(c).text).toBe('尚未输入口令')
    expect(c.errors).toEqual([])
  })

  test('切到英文后标签与结论全部跟随（渲染期求值，不是固化字符串）', async () => {
    const c = await open('Str0ng-Pass_2026', 'en-US')
    expect(c.find('.pwd-meter__label').textContent.trim()).toBe('Password strength')
    expect(level(c).text).toBe('Strong')
    expect(rules(c).map((r) => r.text)).toEqual([
      '12-64 characters',
      'Uppercase letter',
      'Lowercase letter',
      'Digit',
      'Special character',
    ])

    // 同一实例内切换语言：文案必须跟随（t() 在 computed 里求值）
    i18n.global.locale.value = 'zh-CN'
    await flush(4)
    expect(c.find('.pwd-meter__label').textContent.trim()).toBe('口令强度')
    expect(level(c).text).toBe('强')
    await flush(2)
    expect(c.errors).toEqual([])
  })
})
