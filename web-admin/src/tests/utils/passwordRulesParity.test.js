/**
 * 口令强度判据前后端对账（A3）
 *
 * `web-admin/src/utils/password.js` 的文件头写着"与后端 PASSWORD_RULES 等价，前后端必须
 * 同步，否则一端拒绝另一端接受"，可它把同一组判据抄了两遍还各自硬编码：合并正则
 * `PASSWORD_STRENGTH_REGEX`（`.{12,64}` + 四类字符 + 特殊字符区间）、
 * `evaluatePasswordRules` 里逐条的 `length/upper/lower/digit/symbol`（又一份 `12`）。
 * 这类重复历史上已经出过两次事故：L-1 把最小长度 8 抬到 12 时要求"前后端必须同步"、
 * P3-29 放宽特殊字符类时要求"必须同步放宽"——而本仓没有任何一条用例能在**只改一端**时
 * 变红，全靠注释提醒。这条对账把提醒换成门禁：用 `createRequire` 直接载入后端
 * `src/utils/helpers.js` 的真实实现（该文件零 require，跨边界引入无副作用），
 * 用一组探针口令跑两端并断言结论一致。不新增依赖。
 *
 * 刻意不管的那一条：泄露口令黑名单（`BREACHED_PASSWORDS`）是**后端单边判据**。
 * 前端不拦是设计——清单打进 SPA 包等于把它发布成一份人人可读的撞库字典，
 * 且注册/改密以后端为准。所以"后端因黑名单拒"的探针单独放行，见下面的理由分类。
 */
import { describe, test, expect } from 'vitest'
import { createRequire } from 'node:module'

const require = createRequire(import.meta.url)
const {
  validatePasswordStrength,
  isBreachedPassword,
  PASSWORD_SPECIAL_REGEX,
  PASSWORD_MAX_BYTES,
  PASSWORD_MAX_LENGTH,
} = require('../../../../src/utils/helpers.js')

import {
  isStrongPassword,
  evaluatePasswordRules,
  PASSWORD_STRENGTH_REGEX,
  PASSWORD_MAX_LENGTH as FRONT_MAX_LENGTH,
  PASSWORD_MAX_BYTES as FRONT_MAX_BYTES,
} from '@/utils/password'

/**
 * 探针：每条都覆盖一次"两端各自的判据表达式"，而不是随手取的口令。
 * 长度边界（11/12）、四类字符各缺一种、P3-29 的 `-`/`_`/`+`/`[`、
 * 字符数上限边界（64/65）、UTF-8 字节边界（70/73，中文字符 3 字节）、
 * 命中黑名单的三种不同路径、以及非字符串输入。
 */
const PROBES = [
  'Aa1!aaaa', // 8 字符：长度不足
  'Aa1!aaaaaaa', // 11 字符：正好差一位
  'Aa1!aaaaaaaa', // 12 字符：达标
  'aa1!aaaaaaaa', // 缺大写
  'AA1!aaaaaaaa', // 缺小写
  'Aa!!aaaaaaaa', // 缺数字
  'Aa1aaaaaaaaa', // 缺特殊字符
  'Str0ng-Pass_2026', // P3-29：- 与 _ 必须算特殊字符（旧清单会误拒）
  'Aa1+aaaaaaaa[', // 同上：+ 与 [
  'Aa1!' + '安'.repeat(22), // 26 字符 / 70 字节：字节数达标
  'Aa1!' + '安'.repeat(23), // 26 字符 / 73 字节：字符数没问题，字节数越界
  `Aa1!${'x'.repeat(60)}`, // 64 字符：字符数上界
  `Aa1!${'x'.repeat(61)}`, // 65 字符：超字符数上界
  'Password@123', // 强度全过 + 直接命中黑名单（后端单边拒绝）
  'admin@123', // 黑名单成员但长度不足：拒绝理由必须归到"长度"而不是"黑名单"
  '  Aa1!aaaaaaaa  ', // 首尾空格：长度按原串算，两端都不做 trim
  null,
  undefined,
  123456789012,
]

const label = (p) => (typeof p === 'string' ? JSON.stringify(p) : String(p))

/**
 * 后端"因黑名单而拒"的判定基准
 *
 * 取一条已知满足全部强度规则、且命中黑名单的口令，让后端自己说出那句话——
 * 这样文案改了基准跟着改，测试里没有中文常量。
 */
const BREACH_REJECTION = validatePasswordStrength('Password@123')

/** 只按强度判据（不含黑名单）看后端的结论 */
const backendRejectsOnStrength = (p) => {
  const verdict = validatePasswordStrength(p)
  return verdict !== null && verdict !== BREACH_REJECTION
}

describe('口令强度：前后端判据对账', () => {
  test('数值上限两端一致（字符数与 bcrypt 的 72 字节硬边界）', () => {
    // 前端把同名常量当"抄一份"的锚点导出；不一致时下面所有探针都失去意义
    expect(FRONT_MAX_LENGTH).toBe(PASSWORD_MAX_LENGTH)
    expect(FRONT_MAX_BYTES).toBe(PASSWORD_MAX_BYTES)
    // 同时钉住绝对值：常量对上了但一起改错（比如把 72 抬到 128）也是事故
    expect(PASSWORD_MAX_LENGTH).toBe(64)
    expect(PASSWORD_MAX_BYTES).toBe(72)
  })

  test('特殊字符区间一致（前端合并正则里嵌的必须是后端那一份）', () => {
    expect(PASSWORD_STRENGTH_REGEX.source).toContain(PASSWORD_SPECIAL_REGEX.source)
  })

  test('基准探针自己先站住：Password@123 强度达标且确实命中黑名单', () => {
    // 上一版本用了 'Admin@123' 做这个基准，而它只有 9 位——被"长度至少 12 位"先拦掉，
    // 于是分类基准拿到的是长度消息，整条对账的豁免口径跟着失效。这条断言就是不让这种
    // "探针前提不成立"再悄悄把门禁变成假绿/假红。
    expect(isBreachedPassword('Password@123')).toBe(true)
    expect(isStrongPassword('Password@123')).toBe(true)
    expect(BREACH_REJECTION).not.toBeNull()
    // 黑名单只在强度规则之后才判定，所以这条消息不可能同时是某条强度规则的消息
    expect(validatePasswordStrength('admin@123')).not.toBe(BREACH_REJECTION)
  })

  test('逐条探针：两端强度结论必须一致（后端只以黑名单为由的拒绝除外）', () => {
    const frontendRejects = new Set(PROBES.filter((p) => !isStrongPassword(p)).map(label))
    const backendRejects = new Set(PROBES.filter(backendRejectsOnStrength).map(label))
    // 断言成集合而不是逐条 if：失败时直接看到"哪一端多拦/少拦了哪条"
    expect(frontendRejects).toEqual(backendRejects)
    // 防空转：探针集必须真的跨过边界（全拒或全收都能让上面那条恒真）
    expect(frontendRejects.size).toBeGreaterThan(3)
    expect(PROBES.length - frontendRejects.size).toBeGreaterThan(3)
  })

  test('黑名单不是死代码：三条命中路径各有其形，且前端全都不拦', () => {
    // 规则顺序是"先全部强度规则、后黑名单"，而清单里 40 条中有 39 条不足 12 位。
    // 所以必须钉住"确实存在强度达标的口令能走到黑名单这一支"，否则哪天有人把清单
    // 里的成员全部改短、G8 就静默失效，而复杂度校验看起来一切正常。
    const cases = {
      'Password@123': '清单成员本身够长（12 位），大小写+数字+符号齐活',
      'Admin@123456789': '末尾数字被归一化收敛：admin@123456789 → admin@123',
      'Password@ 123': '含空格的变体：比对前去掉所有空白',
    }
    for (const [pwd, why] of Object.entries(cases)) {
      expect(isStrongPassword(pwd), why).toBe(true)
      expect(isBreachedPassword(pwd), why).toBe(true)
      expect(validatePasswordStrength(pwd), why).toBe(BREACH_REJECTION)
    }
  })

  test('前端自身两份判据不得互相漂移：指示器全绿 == isStrongPassword 为真', () => {
    for (const probe of PROBES) {
      expect(evaluatePasswordRules(probe).satisfied).toBe(isStrongPassword(probe))
    }
    // 逐条子判据也必须与后端同源（区间漂移时这里先红，而不是等到用户看到"五条全绿却被拒"）
    for (const probe of PROBES.filter((p) => typeof p === 'string')) {
      expect(evaluatePasswordRules(probe).symbol).toBe(PASSWORD_SPECIAL_REGEX.test(probe))
    }
  })
})
