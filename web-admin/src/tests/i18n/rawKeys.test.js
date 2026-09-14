/**
 * i18n 中文裸键治理测试（P3-44 收官）
 *
 * 历史与现状：
 *  - 曾以「中文原文当键」（裸键）+ legacy-raw-* 兼容层兜底，欠账 143 键；
 *  - 2026-09-14 全部迁移到规范点号键（layout/auditLog/inspection/
 *    inspectionResult/inspectionReview 等命名空间），兼容层已删除。
 *
 * 现在的防线：源码中不允许存在任何 `$t('中文')` / `t('中文')` 裸键——
 * 出现即本测试失败，新代码必须使用规范键并双语补齐词表。
 */

import { describe, test, expect } from 'vitest'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join, resolve } from 'node:path'
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

/** 从源码中提取 `$t('...')` / `t('...')` 里含中文的键（含跨行调用前的单行形态） */
const extractRawKeys = (text) => {
  const keys = []
  const re = /(?:\$t|\bt)\(\s*'([^']*[\u4e00-\u9fa5][^']*)'/g
  let m
  while ((m = re.exec(text)) !== null) keys.push(m[1])
  return keys
}

describe('i18n 中文裸键清零（P3-44 收官防线）', () => {
  const files = collectFiles(SRC)
  const occurrences = []
  for (const f of files) {
    for (const k of extractRawKeys(readFileSync(f, 'utf8'))) {
      occurrences.push({ file: f, key: k })
    }
  }
  const uniqueKeys = [...new Set(occurrences.map((o) => o.key))]

  test('全源码零中文裸键（曾经 143 键欠账已全部迁移规范键）', () => {
    const detail = occurrences
      .slice(0, 10)
      .map((o) => `${o.file.split(/[\\/]/).pop()} :: ${o.key}`)
      .join('\n')
    expect(`${uniqueKeys.length} 处裸键\n${detail}`).toBe('0 处裸键\n')
  })

  test('词表源文件无顶层中文键（兼容层遗留已清除）', () => {
    for (const dict of ['zh-CN.js', 'en-US.js']) {
      const src = readFileSync(join(SRC, 'i18n', 'locales', dict), 'utf8')
      const topCnLines = src
        .split(/\r?\n/)
        .filter((l) => /^ {2}'?[\u4e00-\u9fa5]/.test(l) && /:\s/.test(l))
      expect(topCnLines).toEqual([])
    }
  })

  test('规范键双语可解析（抽样新迁移的命名空间）', () => {
    const saved = i18n.global.locale.value
    try {
      i18n.global.locale.value = 'en-US'
      for (const key of [
        'auditLog.opTime',
        'inspectionResult.issueNo',
        'inspectionReview.title',
        'layout.fullscreen',
        'common.levelHigh',
      ]) {
        const translated = i18n.global.t(key)
        expect(translated).not.toBe(key)
        expect(/[\u4e00-\u9fa5]/.test(translated)).toBe(false)
      }
      // 插值参数（问题序号 {n}）
      expect(i18n.global.t('inspectionResult.issueNo', { n: 2 })).toContain('2')
    } finally {
      i18n.global.locale.value = saved
    }
  })

  test('规范键在中文 locale 下返回中文', () => {
    const saved = i18n.global.locale.value
    try {
      i18n.global.locale.value = 'zh-CN'
      expect(i18n.global.t('auditLog.opTime')).toBe('操作时间')
      expect(i18n.global.t('inspection.normal')).toBe('正常')
      expect(i18n.global.t('layout.fullscreen')).toBe('全屏')
    } finally {
      i18n.global.locale.value = saved
    }
  })
})
