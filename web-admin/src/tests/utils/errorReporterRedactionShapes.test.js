/**
 * 上报负载的凭据脱敏：**字符串内嵌**形态与 URL 键形态（第 16 轮审计 F1/F2）
 *
 * 为什么单独一个文件：errorReporterBufferEdges.test.js 只覆盖「对象键」形态
 * （headers:{Authorization:...} 走 DROPPED_OBJECT_KEYS 整键丢弃），从未覆盖
 * 「凭据写在字符串里」的形态。变异实测：把 redactSensitiveText 整段删掉，
 * 既有 52 条用例全绿——即这两条路径此前**没有任何判据**。
 *
 * 两条被测缺陷（修复前均可复现，见 work/audit-round16-web.md F1/F2）：
 *  F1 Authorization 的值以 "Bearer " 开头时，通用键值规则先吃到 "Bearer" 这个词，
 *     把值切成 "Bearer" + 剩余 JWT ⇒ 专用 Bearer 规则再也匹配不到，JWT 明文存活。
 *  F2 URL 键只做驼峰拆分，于是 token[]=（axios 数组参数）、access.token=、
 *     x-auth-token=、password[x]=、sid= 全部漏码。
 *
 * 判据写成「原文必须不出现」而不是「等于某个串」：脱敏的契约是"凭据不得落地"，
 * 具体替换成 *** 还是别的形式属于实现细节，不该被测试钉死。
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import {
  initErrorHandling,
  getLoggedErrors,
  clearLoggedErrors,
  redactUrl,
  reportDegradation,
} from '@/utils/errorReporter'

const app = { config: {} }

describe('上报负载凭据脱敏：字符串内嵌形态（F1）', () => {
  beforeEach(() => {
    initErrorHandling(app)
    clearLoggedErrors()
    vi.spyOn(console, 'error').mockImplementation(() => {})
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  const JWT = 'eyJhbGciOiJIUzI1NiJ9.SUPERSECRETPAYLOAD.sig'
  const BASIC = 'dXNlcjpwYXNzd29yZA=='

  test.each([
    ['Authorization: Bearer <JWT>', `Authorization: Bearer ${JWT}`, JWT],
    ['authorization=bearer <JWT>（小写方案）', `authorization=bearer ${JWT}`, JWT],
    ['x-auth-token: Bearer <JWT>', `x-auth-token: Bearer ${JWT}`, JWT],
    ['Authorization: Basic <base64>', `Authorization: Basic ${BASIC}`, BASIC],
    ['token: Bearer <JWT>（无 Authorization 前缀）', `token: Bearer ${JWT}`, JWT],
  ])('%s 的凭据不得出现在入库消息里', (_label, message, secret) => {
    reportDegradation(message)
    const entries = getLoggedErrors()
    expect(entries.length).toBeGreaterThan(0)
    const stored = JSON.stringify(entries)
    expect(stored).not.toContain(secret)
  })
})

describe('上报负载凭据脱敏：URL 键形态（F2）', () => {
  test.each([
    ['access.token', '/x?access.token=SECRET_A', 'SECRET_A'],
    ['token[]（axios 数组参数）', '/x?token[]=SECRET_B', 'SECRET_B'],
    ['password[x]（嵌套参数）', '/x?password[x]=SECRET_C', 'SECRET_C'],
    ['x-auth-token', '/x?x-auth-token=SECRET_D', 'SECRET_D'],
    ['sid', '/x?sid=SECRET_E', 'SECRET_E'],
    ['%74oken（百分号编码的键名）', '/x?%74oken=SECRET_F', 'SECRET_F'],
  ])('%s 的值必须被打码', (_label, url, secret) => {
    expect(redactUrl(url)).not.toContain(secret)
  })

  test('非敏感键保持原值（否则打码扩权会毁掉排障信息）', () => {
    expect(redactUrl('/x?postcode=100080&page=2')).toBe('/x?postcode=100080&page=2')
  })
})

describe('去重窗口命中但原条目已裁剪时不得吞掉事件（F4）', () => {
  beforeEach(() => {
    initErrorHandling(app)
    clearLoggedErrors()
    vi.spyOn(console, 'error').mockImplementation(() => {})
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  test('record → clearLoggedErrors → 5s 内再 record 同一条，缓冲必须有 1 条', () => {
    // 旧实现：去重窗口仍开着（recentKeys 未清），但 stored 已被清空 ⇒
    // 找不到可累加的条目就直接 return，这次错误一条都不留。
    // 现场最需要的恰恰是"刚出错"，被吞掉的是最有价值的那一条。
    reportDegradation('dedupe-pruned-probe')
    expect(getLoggedErrors()).toHaveLength(1)
    clearLoggedErrors()
    expect(getLoggedErrors()).toHaveLength(0)
    reportDegradation('dedupe-pruned-probe')
    expect(getLoggedErrors()).toHaveLength(1)
  })
})

/**
 * 「同一凭据换个书写位置」的跨形态判据（第 17 轮 r17-web F1 的补齐）。
 *
 * 缺陷形态：字符串形态的键清单是**手抄的一小份更窄清单**，于是 signature= / otp= /
 * mfaCode= / captchaId= / sessionId= / sid= / jwt= / bearer= / secret_key= 写进 URL 会被打码，
 * 写进 message 则明文外发。修法不是再抄一份更长的手写清单（下一轮照样漂移），而是让字符串
 * 形态**从同一份清单派生**；本组用例把这条结构性约束钉住：清单里任何一个键，两种形态都必须
 * 打码——加键的人不必记得改两处，改一处即自动覆盖。
 */
describe('两种形态共用一份敏感清单（F1 的结构性约束）', () => {
  beforeEach(() => {
    initErrorHandling(app)
    clearLoggedErrors()
    vi.spyOn(console, 'error').mockImplementation(() => {})
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  // 与 SENSITIVE_QUERY_KEYS 逐项对齐的探针：**故意不 import 常量**——一旦用例顺着实现改，
  // 它就只剩「实现等于自己」这句话，再也挡不住下一个人往清单里加键而忘了另一侧。
  const KEYS = [
    'password',
    'passwd',
    'pwd',
    'token',
    'access_token',
    'refresh_token',
    'secret',
    'apikey',
    'api_key',
    'signature',
    'sign',
    'mfa',
    'otp',
    'captcha',
    'authorization',
    'session',
    'id_token',
    'jwt',
    'bearer',
    'sid',
  ]

  test('前提自证：探针清单覆盖全部被测键，且 code 按形态**有意**区别对待', () => {
    expect(KEYS.length).toBeGreaterThanOrEqual(20)
    expect(KEYS).not.toContain('code')
    // URL 形态必须打码 `code`：查询串里的 code 是 OAuth 授权码，与「错误码」同形不同义，
    // 这里按凭据处理（isSensitivePairKey 里的 normalized === 'code' 分支）。
    expect(redactUrl('/x?code=42')).toContain('code=***')
    // 而对象/字符串形态的 `code` 是排障要用的错误码，必须原样保留（见本组最后一条用例）。
    // 这条差异不是疏漏，是两种载体的语义差别，故意钉在这里免得后人"统一口径"时把一侧改坏。
  })

  test('清单里每个键写进 URL 都必须打码', () => {
    const leaked = KEYS.filter((k) => !redactUrl('/x?' + k + '=SECRETVALUE').includes('***'))
    expect(leaked).toEqual([])
  })

  test('清单里每个键写进字符串（message）都必须打码——与 URL 形态逐键对齐', () => {
    // 旧实现下这条会印出一串键名：字符串形态的手写清单比 URL 形态窄。
    reportDegradation('probe ' + KEYS.map((k) => k + '=SECRETVALUE').join(' '))
    const text = JSON.stringify(getLoggedErrors())
    const leaked = KEYS.filter((k) => new RegExp(k + '[=:]+SECRETVALUE', 'i').test(text))
    expect(leaked).toEqual([])
  })

  test('驼峰与下划线两种写法等价（mfaCode / mfa_code / MFA_CODE 同判）', () => {
    reportDegradation('probe mfaCode=SECRETVALUE mfa_code=SECRETVALUE MFA_CODE=SECRETVALUE')
    expect(JSON.stringify(getLoggedErrors())).not.toContain('SECRETVALUE')
  })

  test('安全的错误码不得被连带打码（这条是修复自身的回归护栏）', () => {
    // 本轮把 code 纳入派生清单后，JSON.stringify({code:42}) 被打成 "{code:***"，
    // E16 用例当场变红。排障要用的错误码必须保留。
    reportDegradation('{"code":42,"detail":"boom"}')
    expect(getLoggedErrors()[0].message).toContain('42')
    expect(getLoggedErrors()[0].message).not.toContain('***')
  })
})

/**
 * 值里嵌 URL 的递归脱敏（第 17 轮 r17-web F2）。
 *
 * 缺陷形态：redactPairs 只看 key、不递归 value，于是 OAuth 回调把凭据藏在 next=/redirect_uri=
 * 里时原样外发。这些断言用 not.toContain 而不是等值比较：契约是「凭据不得落地」，
 * 替换成 *** 还是别的形式属实现细节。
 */
describe('值内嵌 URL 的递归脱敏（F2）', () => {
  const SECRET = 'NESTEDSECRETVALUE'

  const cases = [
    '/cb?next=https://x/cb?token=' + SECRET,
    '/cb?next=%2Fcb%3Ftoken%3D' + SECRET,
    '/cb?redirect_uri=https%3A%2F%2Fx%2Fcb%3Faccess_token%3D' + SECRET,
    '/cb?returnUrl=/cb?refresh_token=' + SECRET,
    '/cb?next=https://x/cb#access_token=' + SECRET,
  ]

  test('前提自证：未嵌套形态仍然正常打码（否则下面全绿可能只是整段没动）', () => {
    expect(redactUrl('/cb?token=' + SECRET)).toContain('***')
    // 与上一条同源：明文形态也不得存活（原先把这行落在新用例之后，整段语法就断了）
    expect(redactUrl('/cb?token=' + SECRET)).not.toContain(SECRET)
  })

  test('深度到顶（>3 层）失败关闭：明文形态同样不许漏（分界在 3/4 层，与编码无关）', () => {
    // 直接以 depth=4 调用：这是"值里再套 URL"到第 4 层的真实位置（redactNestedValue
    // 每下沉一层 depth+1）。早先的实现是"只有仍是百分号编码才抹"，于是 4 层纯明文
    // 直接把 token 原文留在上报负载里——本轮 audit-web 的探针实测复现。
    expect(redactUrl('/cb?next=https://x/cb?token=' + SECRET, 4)).not.toContain(SECRET)
    expect(
      redactUrl('/cb?next=' + encodeURIComponent('https://x/cb?token=' + SECRET), 4)
    ).not.toContain(SECRET)
    // 3 层（未到顶）仍按常规打码，不是"一律抹掉"：到顶判定不能被顺手放宽成 >=
    expect(redactUrl('/cb?next=https://x/cb?token=' + SECRET, 3)).not.toContain(SECRET)
  })

  cases.forEach((raw) => {
    test('嵌套凭据不得明文存活：' + raw.slice(0, 34), () => {
      expect(redactUrl(raw)).not.toContain(SECRET)
    })
  })

  test('自相似串不得把递归打爆（值里套值，深度有界）', () => {
    // 构造 500 层 next= 嵌套：无界递归要么栈溢出、要么耗时过长，两者都是拒绝服务面
    let nested = '/x?token=' + SECRET
    for (let i = 0; i < 500; i += 1) nested = '/x?next=' + encodeURIComponent(nested)
    const started = Date.now()
    const out = redactUrl(nested)
    expect(Date.now() - started).toBeLessThan(1000)
    expect(out).not.toContain(SECRET)
  })

  test('普通业务参数不受牵连（不得为了脱敏把排障信息也删掉）', () => {
    const kept = redactUrl('/list?page=2&keyword=' + SECRET + '&next=/cb')
    expect(kept).toContain('page=2')
    expect(kept).toContain('keyword=' + SECRET)
    expect(kept).toContain('next=/cb')
  })
})

/**
 * 认证头与复合键的剩余形态（第 17 轮 r17-web F4/F5）。
 *
 * F4：Digest 的凭据在参数列表里（response="…"），旧的通用方案规则只吃「方案 + 一个 token」，
 *     于是 response 明文存活；F5：deviceToken 这类新复合键在字符串形态不命中，
 *     而同样的键写进 URL 会被打码——又是「同一凭据换个书写位置」。
 */
describe('认证头与复合键的剩余形态（F4/F5）', () => {
  const SECRET = 'AUTHSECRETVALUE'

  beforeEach(() => {
    initErrorHandling(app)
    clearLoggedErrors()
    vi.spyOn(console, 'error').mockImplementation(() => {})
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  const cases = [
    [
      'Digest 完整参数列表',
      'Authorization: Digest username="u", realm="r", nonce="n", response="' + SECRET + '"',
    ],
    ['Digest 仅 response', 'Digest response="' + SECRET + '"'],
    ['deviceToken 赋值', 'deviceToken=' + SECRET],
    ['x-device-token 头', 'x-device-token: ' + SECRET],
    ['device_token 赋值', 'device_token=' + SECRET],
  ]

  cases.forEach(([label, text]) => {
    test('凭据不得明文存活：' + label, () => {
      reportDegradation(text)
      expect(JSON.stringify(getLoggedErrors())).not.toContain(SECRET)
    })
  })

  test('前提自证：Bearer 仍按原口径打码（Digest 那条不得把通用方案规则挤掉）', () => {
    reportDegradation('Authorization: Bearer ' + SECRET)
    expect(JSON.stringify(getLoggedErrors())).not.toContain(SECRET)
  })

  test('Digest 之后的正常文本不得被整段吃掉（脱敏不得毁掉排障信息）', () => {
    reportDegradation('Digest response="' + SECRET + '" failed at 12:00')
    expect(JSON.stringify(getLoggedErrors())).toContain('failed at')
  })
})
