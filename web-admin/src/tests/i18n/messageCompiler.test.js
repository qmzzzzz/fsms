/**
 * i18n 消息编译器回归（P1-9）
 *
 * 缺陷回顾：编译器原实现会把词表里残留的 JS 模板字符串源码里的 {expr} 当作
 * 插值占位符——参数命中时产出「$ + 参数值」（如 $<format>），未命中时原样直出
 * 模板源码。两种结果都是破相文案。本轮修复：编译器跳过前导 $ 的花括号
 * （只认 {name}），词表侧把 18 个键的模板源码统一改写为 {参数名}（参数名对齐
 * 后端 ApiResponse.codeError 的 params 键）。其中 16 个是后端实际发射的码；
 * ipFullRangeSuperAdminOnly / ipFullRangeRemoveSuperAdminOnly 两键当前无码发射
 * （后端 ipListController 用的是 FULL_RANGE_FORBIDDEN），属词表欠账，一并归一化
 * 以免将来接码时以旧形态复活。
 *
 * 本套件锁定三件事：
 *  1. {name} 具名插值仍按语义工作（不因排除 $ 而误伤）；
 *  2. 模板源码形态原样保留（不再被替换、也不再吞掉参数值）；
 *  3. 两个 locale 的词表里所有含 { 的值，渲染后不残留模板痕迹。
 *
 * 实测基线（修复前，逐键渲染对比 HEAD 版编译器）：36 处破相，两个 locale 各 18 键；
 * 形态上「被误替换（$+值）」25 处、「模板源码直出」11 处（zh-CN 以直出为主 11 处，
 * en-US 全部为误替换 18 处）。修复后 0 处异常。
 */
import { describe, test, expect } from 'vitest'
import i18n from '@/i18n'
import zh from '@/i18n/locales/zh-CN'
import en from '@/i18n/locales/en-US'

/** 在指定 locale 下解析 key，结束后恢复原 locale */
const render = (locale, key, params) => {
  const saved = i18n.global.locale.value
  try {
    i18n.global.locale.value = locale
    return i18n.global.t(key, params)
  } finally {
    i18n.global.locale.value = saved
  }
}

/** 递归收集词表所有字符串值（含嵌套命名空间） */
const walk = (obj, prefix, out) => {
  for (const [k, v] of Object.entries(obj)) {
    const key = prefix ? prefix + '.' + k : k
    if (typeof v === 'string') out.push([key, v])
    else if (v && typeof v === 'object') walk(v, key, out)
  }
  return out
}

/** 词表值里出现的插值占位符名（只认非前导 $ 的 {name}） */
const placeholderNames = (value) =>
  [...value.matchAll(/(?<!\$)\{([A-Za-z_$][\w$]*)\}/g)].map((m) => m[1])

describe('消息编译器：{name} 语义解析（P1-9）', () => {
  test('{name} 具名插值被填充（编译期正则未因排除 $ 而破坏具名语义）', () => {
    // inspectionResult.issueNo = '问题 {n}'
    expect(render('zh-CN', 'inspectionResult.issueNo', { n: 2 })).toBe('问题 2')
    expect(render('en-US', 'inspectionResult.issueNo', { n: 7 })).toContain('7')
  })

  test('未传参数时 {name} 原样保留（不误吞、不报错）', () => {
    expect(render('zh-CN', 'inspectionResult.issueNo', {})).toBe('问题 {n}')
  })

  test('词表改写后的键能取到后端 params（含多占位符）', () => {
    expect(render('zh-CN', 'errors.exportFormatUnsupported', { format: 'csv' })).toBe(
      '不支持的导出格式: csv'
    )
    expect(render('en-US', 'errors.uploadFileTooLarge', { filename: 'a.zip', maxSize: 5 })).toBe(
      'File a.zip exceeds the maximum size of 5MB'
    )
  })
})

describe('消息编译器：模板源码形态不再被误匹配（P1-9 核心）', () => {
  // 修复前的编译器对同样的消息会产出 'x $V z'（把 {y} 当占位符替换）
  test('前导 $ 的花括号被跳过，模板源码原样保留', () => {
    const probe = { p1: 'x ${y} z', p2: '保留 {n} 与 ${n}' }
    i18n.global.setLocaleMessage('zh-CN', { ...zh, __probe: probe })
    try {
      expect(render('zh-CN', '__probe.p1', { y: 'V' })).toBe('x ${y} z')
      // 同一消息里 {n} 仍要正常插值，模板形态的 ${n} 保持原样——两者互不干扰
      expect(render('zh-CN', '__probe.p2', { n: 3 })).toBe('保留 3 与 ${n}')
    } finally {
      i18n.global.setLocaleMessage('zh-CN', zh)
    }
  })
})

describe('词表：含 { 的键渲染后无模板残留（P1-9 端到端）', () => {
  const locales = [
    ['zh-CN', zh],
    ['en-US', en],
  ]

  test.each(locales)('%s：全部含 { 的键填充后无模板残留、无未替换占位符', (locale, dict) => {
    const entries = walk(dict, '', []).filter(([, v]) => v.includes('{'))
    expect(entries.length).toBeGreaterThan(0)
    const broken = []
    for (const [key, value] of entries) {
      const params = {}
      for (const name of placeholderNames(value)) params[name] = `<${name}>`
      const out = render(locale, key, params)
      if (out.includes('${') || out.includes('$<') || /\{[A-Za-z_$][^}]*\}/.test(out)) {
        broken.push(`${key} => ${out}`)
      }
    }
    expect(broken).toEqual([])
  })

  test('18 个已改写错误码在两语言下都能取到参数（后端 params 键名对齐）', () => {
    const cases = [
      ['errors.ipFullRangeSuperAdminOnly', { ip: '0.0.0.0/0' }, '0.0.0.0/0'],
      ['errors.ipCoveredByWhitelist', { coveredBy: '10.0.0.0/8' }, '10.0.0.0/8'],
      ['errors.ipFullRangeRemoveSuperAdminOnly', { ip: '::/0' }, '::/0'],
      ['errors.exportFormatUnsupported', { format: 'pdf' }, 'pdf'],
      ['errors.permissionGrantForbidden', { permissions: 'user:delete' }, 'user:delete'],
      ['errors.roleInUse', { userCount: 4 }, '4'],
      ['errors.permissionAssignForbidden', { permissions: 'role:assign' }, 'role:assign'],
      ['errors.ipRulesFormatInvalid', { rules: '1.2.3' }, '1.2.3'],
      ['errors.roleAssignForeignPeerForbidden', { foreignRoles: 'AUDITOR' }, 'AUDITOR'],
      ['errors.batchDeleteLimitExceeded', { max: 50 }, '50'],
      ['errors.userIdFormatInvalidInList', { invalidIds: 'abc' }, 'abc'],
      ['errors.batchDeletePeerOrHigherForbidden', { username: 'alice' }, 'alice'],
      ['errors.httpMethodUnsupported', { method: 'TRACE' }, 'TRACE'],
      ['errors.contentTypeUnsupported', { mediaType: 'text/plain' }, 'text/plain'],
      ['errors.uploadFileTooLarge', { filename: 'a.bin', maxSize: 5 }, 'a.bin'],
      ['errors.uploadTypeNotAllowed', { mimetype: 'x/y' }, 'x/y'],
      ['errors.uploadExtNotAllowed', { ext: 'exe' }, 'exe'],
      ['errors.paramMustBeValidObjectId', { name: 'id' }, 'id'],
    ]
    for (const [key, params, expected] of cases) {
      for (const locale of ['zh-CN', 'en-US']) {
        const out = render(locale, key, params)
        expect(out, `${locale} ${key}`).toContain(expected)
        expect(out, `${locale} ${key} 不应残留模板源码`).not.toContain('${')
      }
    }
  })
})
