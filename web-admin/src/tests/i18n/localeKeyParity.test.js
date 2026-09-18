/**
 * 词表双语键对齐（真实缺口守卫）
 *
 * 背景：本轮全仓核对 zh-CN 与 en-US 的叶子键时发现二者**并不对齐**——
 *   zh 叶子键 1103 个，en 只有 1101 个；差额来自 zh-CN 独有的两个裸键
 *   `common.全屏` 与 `common.未登录`（en 侧根本没有这两个键）。
 *
 * 为什么现有测试抓不到：`src/tests/i18n/rawKeys.test.js` 的「词表源文件无顶层
 * 中文键」只扫**缩进 2 空格**的行（`/^ {2}'?[\u4e00-\u9fa5]/`），而这两个键在
 * `common` 段内部、缩进 4 空格，正好漏网；另一边「规范键双语可解析」是抽样列举，
 * 不覆盖全量键。
 *
 * 本文件把「双语叶子键集合必须相等」作为不变量钉住。它能失败的真实场景：
 *  - 新增文案只改一侧词表（另一侧漏加）→ 该语言下界面显示裸键或英文回退；
 *  - 删除某键时只删一侧（残留孤儿键）；
 *  - 再次混入中文裸键（裸键天然只在 zh 侧存在，故必然造成双边不对称）。
 *
 * 说明：断言的是**键集合**而非值——某些键在中英文下取值相同是合理的
 * （例如 "API"、纯符号），故不比对文案内容。
 */
import { describe, test, expect } from 'vitest'
import zhCN from '@/i18n/locales/zh-CN'
import enUS from '@/i18n/locales/en-US'

/** 展平为点号路径的叶子键（对象视为分支，其余一律视为叶子） */
const leafKeys = (node, prefix = '') => {
  const out = []
  for (const [key, value] of Object.entries(node)) {
    const path = prefix ? prefix + '.' + key : key
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      out.push(...leafKeys(value, path))
    } else {
      out.push(path)
    }
  }
  return out
}

const zhKeys = leafKeys(zhCN)
const enKeys = leafKeys(enUS)

describe('i18n 词表双语键对齐', () => {
  test('zh-CN 与 en-US 的叶子键集合完全一致（缺键在下游表现为裸键或英文回退）', () => {
    const onlyZh = zhKeys.filter((k) => !enKeys.includes(k)).sort()
    const onlyEn = enKeys.filter((k) => !zhKeys.includes(k)).sort()
    const detail =
      (onlyZh.length ? '仅 zh-CN 有：\n  ' + onlyZh.join('\n  ') + '\n' : '') +
      (onlyEn.length ? '仅 en-US 有：\n  ' + onlyEn.join('\n  ') + '\n' : '')
    expect(detail || '两侧键集合一致').toBe('两侧键集合一致')
  })

  test('任一侧不得出现中文裸键（含嵌套层，不限顶层缩进）', () => {
    // 裸键 = 键名本身含中文。这类键名只在中文侧可能出现，天然破坏双语对称，
    // 且无法被「规范化点号键」的调用点引用（真正的引用点都写点号路径）。
    const nakedZh = zhKeys.filter((k) => /[\u4e00-\u9fa5]/.test(k))
    const nakedEn = enKeys.filter((k) => /[\u4e00-\u9fa5]/.test(k))
    expect({ zh: nakedZh, en: nakedEn }).toEqual({ zh: [], en: [] })
  })

  test('两侧均无空值叶子（空串/ null 会让界面出现空白而非文案）', () => {
    const pick = (node, keys) =>
      keys.filter((k) => {
        let cur = node
        for (const part of k.split('.')) cur = cur[part]
        return cur === '' || cur === null || cur === undefined
      })
    expect({ zh: pick(zhCN, zhKeys), en: pick(enUS, enKeys) }).toEqual({ zh: [], en: [] })
  })

  test('键数量级自检：词表被整体清空/截断时本条即红', () => {
    // 防止「把词表 import 成空对象」导致上面三条恒真（空 vs 空 = 对齐）
    expect(zhKeys.length).toBeGreaterThan(1000)
    expect(enKeys.length).toBeGreaterThan(1000)
    expect(zhKeys.length).toBe(enKeys.length)
  })
})
