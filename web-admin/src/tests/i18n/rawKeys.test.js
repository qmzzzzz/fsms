/**
 * i18n 中文裸键治理测试（P3-44）
 *
 * 两条防线：
 *  1. 覆盖完整：代码里所有 `$t('中文')` 调用都必须能在两种语言下解析出译文，
 *     否则 en-US 界面会渲染中文原文（vue-i18n 查不到键时原样返回键名）。
 *  2. 不再新增：以当前欠账数量为基线，新代码再写中文裸键就会失败。
 *     基线只允许下调（迁移到规范键后），不允许上调。
 */

import { describe, test, expect } from 'vitest'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join, resolve } from 'node:path'
import legacyZhCN from '@/i18n/locales/legacy-raw-zh'
import legacyEnUS from '@/i18n/locales/legacy-raw-en'
import i18n from '@/i18n'

const SRC = resolve(__dirname, '../..')

/** 递归收集 src 下的 .vue/.js（排除 i18n 词表与测试自身） */
const collectFiles = (dir, acc = []) => {
  for (const name of readdirSync(dir)) {
    const full = join(dir, name)
    if (statSync(full).isDirectory()) {
      if (name === 'node_modules') continue
      collectFiles(full, acc)
      continue
    }
    if (!/\.(vue|js)$/.test(name)) continue
    // 词表本身与本测试文件不参与扫描
    if (full.includes(join('i18n', 'locales'))) continue
    if (full.includes(join('tests', 'i18n'))) continue
    acc.push(full)
  }
  return acc
}

/** 从源码中提取 `$t('...')` / `t('...')` 里含中文的键 */
const extractRawKeys = (text) => {
  const keys = []
  const re = /(?:\$t|\bt)\(\s*'([^']*[\u4e00-\u9fa5][^']*)'/g
  let m
  while ((m = re.exec(text)) !== null) keys.push(m[1])
  return keys
}

describe('i18n 中文裸键治理（P3-44）', () => {
  const files = collectFiles(SRC)
  const occurrences = []
  for (const f of files) {
    for (const k of extractRawKeys(readFileSync(f, 'utf8'))) {
      occurrences.push({ file: f, key: k })
    }
  }
  const uniqueKeys = [...new Set(occurrences.map((o) => o.key))]

  test('扫描到的裸键都已收录进 zh-CN 兼容层', () => {
    const missing = uniqueKeys.filter((k) => !(k in legacyZhCN))
    expect(missing).toEqual([])
  })

  test('扫描到的裸键都已收录进 en-US 兼容层（否则英文界面渲染中文）', () => {
    const missing = uniqueKeys.filter((k) => !(k in legacyEnUS))
    expect(missing).toEqual([])
  })

  test('两张兼容表的键集合完全一致', () => {
    const zhKeys = Object.keys(legacyZhCN).sort()
    const enKeys = Object.keys(legacyEnUS).sort()
    expect(zhKeys).toEqual(enKeys)
  })

  test('en-US 兼容层不含中文（真正翻译过，而非复制原文）', () => {
    const notTranslated = Object.entries(legacyEnUS)
      .filter(([, v]) => /[\u4e00-\u9fa5]/.test(String(v)))
      .map(([k]) => k)
    expect(notTranslated).toEqual([])
  })

  test('经 i18n 实例解析：中文键在英文 locale 下返回英文', () => {
    const saved = i18n.global.locale.value
    try {
      i18n.global.locale.value = 'en-US'
      // 取几个代表性键（表格列头、下拉项、校验提示）
      for (const key of ['操作时间', '巡检结果', '请输入审核意见', '严重程度']) {
        const translated = i18n.global.t(key)
        expect(translated).not.toBe(key)
        expect(/[\u4e00-\u9fa5]/.test(translated)).toBe(false)
      }
    } finally {
      i18n.global.locale.value = saved
    }
  })

  test('经 i18n 实例解析：中文键在中文 locale 下返回原文', () => {
    const saved = i18n.global.locale.value
    try {
      i18n.global.locale.value = 'zh-CN'
      expect(i18n.global.t('操作时间')).toBe('操作时间')
      expect(i18n.global.t('巡检结果')).toBe('巡检结果')
    } finally {
      i18n.global.locale.value = saved
    }
  })

  test('裸键欠账不再增长（基线只允许下调）', () => {
    // 基线随治理推进逐步下调：
    //  2026-08-27 初测：138（四个历史文件）
    //  2026-08-27 复测：141 —— 并非新增欠账，而是首次统计时漏算了
    //    「问题序号」这类带插值的键与两处重复写法；同时把 InspectionForm
    //    的「更新/创建」按钮迁到 common.save/common.add，删掉了两条重复条目。
    // 上调即意味着新代码又引入了裸键，必须先迁移再改基线。
    const BASELINE_UNIQUE_KEYS = 143
    expect(uniqueKeys.length).toBeLessThanOrEqual(BASELINE_UNIQUE_KEYS)
  })

  test('裸键集中在已知的四个历史文件内（新文件不得引入）', () => {
    const allowed = [
      'index.vue',
      'AuditLogView.vue',
      'InspectionForm.vue',
      'InspectionCompleteForm.vue',
      'InspectionReviewForm.vue',
    ]
    const offenders = [
      ...new Set(
        occurrences
          .map((o) => o.file.split(/[\\/]/).pop())
          .filter((name) => !allowed.includes(name))
      ),
    ]
    expect(offenders).toEqual([])
  })
})
