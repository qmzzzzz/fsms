/**
 * 恒真断言 / 被跳用例静态闸（B5 测试体系）
 *
 * 背景（第 33 轮 B5 + 第 34 轮 §1.1 实证）：routePrefetch.test.js 曾有三条
 * expect(true).toBe(true)——不验证任何行为。第 34 轮把 prefetchers 的键
 * '/dashboard' 改成 '/dashboard-TYPO' 后，该套件与 routeTable 共 11 例全绿，
 * 守护为零。那三条空断言已重写为真断言（2026-10-09 入库），但「写出一条不可
 * 证伪的断言」这件事本身没有防线：全局覆盖率会被真实用例摊薄，删改一两处断言
 * 反映不到门槛上；而字面量断言所在行"执行过"，覆盖率照绿。
 *
 * 本闸拦两类静态可判的形态：
 *  1. 字面量对字面量的断言（expect(true).toBe(true) / expect(1).toEqual(1) /
 *     expect(null).toBeNull() …）：结果与代码行为无关，恒真或恒假；
 *  2. 被跳过或独占的用例（test.skip / it.skip / describe.skip / test.only /
 *     xit / xdescribe / test.todo）：跳过即静默少一块回归防线，only 则让同文件
 *     其余用例在本地看不见、在 CI 全量跑时行为不一致。
 *
 * 扫描范围：web-admin/src/tests 整棵树下的一切 *.test.js（本文件除外——它自带的
 * 检测样本会命中判据；样本经字符串拼接构造，注释里的历史引述在扫描前被剥掉）。
 *
 * 检测器自身有可证伪性自检（正/负样本 + 注释引述用例）：detector 坏了会比没有闸
 * 更危险（永久放行），故先把「能抓到这个形态」钉死再扫树。
 */
import { describe, test, expect } from 'vitest'
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, resolve } from 'node:path'

const TESTS_DIR = resolve(__dirname, '..')
const SELF = resolve(__filename)

/** 递归收集测试树里的 *.test.js（跳过 node_modules / coverage 与本文件自身） */
const collectTestFiles = (dir, acc = []) => {
  for (const name of readdirSync(dir)) {
    const full = join(dir, name)
    if (statSync(full).isDirectory()) {
      if (name === 'node_modules' || name === 'coverage') continue
      collectTestFiles(full, acc)
      continue
    }
    if (!name.endsWith('.test.js')) continue
    // 本文件自带检测样本字符串，扫自己必误报；注释里的历史引述已由 stripComments 剥掉
    if (resolve(full) === SELF) continue
    acc.push(full)
  }
  return acc
}

/**
 * 剥掉块注释与行注释后再扫描。
 * 为什么必须剥：routePrefetch.test.js 的文件头注释引述过这段历史缺陷形态
 * （「三条 expect(true).toBe(true) 空断言」）——不剥注释的话，说明文字本身会被
 * 当成违规命中（本闸原型实测即踩该坑，0 误报是硬要求）。
 * 块注释按等长空白替换（保留行列结构），行注释清到行尾；URL 字符串里 :// 前的
 * // 不动（判据要求前字符不是冒号/引号/反引号）。
 */
const stripComments = (src) =>
  src
    .replace(/\/\*[\s\S]*?\*\//g, (block) => block.replace(/[^\n]/g, ' '))
    .replace(/(^|[^:'"`])\/\/[^\n]*/g, '$1')

/**
 * 字面量原子。必须用 String.raw：普通字符串里的 \d 不是合法转义，反斜杠会被
 * 吃掉变成字面 d——第一版就这么写的，后果是 expect(1).toEqual(1) 抓不到、
 * 而 expect(d).toBeTruthy()（单字母变量）被误命中（实测复现）。
 */
const LITERAL = String.raw`(?:true|false|null|undefined|-?\d+(?:\.\d+)?)`

/** 双侧字面量：expect(true).toBe(true) / expect(1).toEqual(1) … */
const BOTH_LITERAL_RE = new RegExp(
  String.raw`expect\(\s*` +
    LITERAL +
    String.raw`\s*\)\s*\.\s*(?:not\s*\.\s*)?to(?:Be|Equal|StrictEqual)\(\s*` +
    LITERAL +
    String.raw`\s*\)`,
  'g'
)

/** 单侧字面量 + 无参断言：expect(true).toBeTruthy() / expect(null).toBeNull() … */
const UNARY_RE = new RegExp(
  String.raw`expect\(\s*` +
    LITERAL +
    String.raw`\s*\)\s*\.\s*(?:not\s*\.\s*)?toBe(?:Truthy|Falsy|Null|Undefined|Defined|NaN)\s*\(\s*\)`,
  'g'
)

/** 跳过 / 独占 / 占位用例：test.skip / it.only / xit / test.todo … */
const SKIP_OR_ONLY_RE =
  /\b(?:test|it|describe)\s*\.\s*(?:skip|only|todo)\s*\(|\bx(?:test|it|describe)\s*\(/g

const countMatches = (re, src) => [...src.matchAll(re)].length

const rel = (file) => file.split(/[\\/]/).slice(-2).join('/')

/** 在（剥注释后的）源码上跑两类判据，返回可读的命中清单 */
const scanSource = (src) => {
  const hits = []
  for (const m of src.matchAll(BOTH_LITERAL_RE)) hits.push('恒真断言 :: ' + m[0])
  for (const m of src.matchAll(UNARY_RE)) hits.push('恒真断言 :: ' + m[0])
  for (const m of src.matchAll(SKIP_OR_ONLY_RE)) hits.push('跳过/独占用例 :: ' + m[0])
  return hits
}

describe('恒真断言 / 被跳用例静态闸（B5）', () => {
  test('检测器可证伪：抓得到历史缺陷形态，且不误伤真实断言', () => {
    // 正向样本（字符串拼接构造，避免本文件源码自带命中形态）
    const badBinary = 'expect(' + 'true).toBe(' + 'true)'
    const badUnary = 'expect(' + 'null).toBe' + 'Null()'
    const badNumeric = 'expect(' + '1).toEqual(' + '1)'
    expect(countMatches(BOTH_LITERAL_RE, badBinary)).toBe(1)
    expect(countMatches(BOTH_LITERAL_RE, badNumeric)).toBe(1)
    expect(countMatches(UNARY_RE, badUnary)).toBe(1)

    // 负样本：真实断言形态一律不得命中（含单字母变量——\d 转义事故的误命中形态）
    const good = [
      'expect(result).toBe(true)',
      'expect(spy).toHaveBeenCalledTimes(1)',
      'expect(list).toEqual([])',
      'expect(el).toBeTruthy()',
      'expect(d).toBeTruthy()',
      'expect(overlay()).toBeNull()',
    ].join('\n')
    expect(countMatches(BOTH_LITERAL_RE, good)).toBe(0)
    expect(countMatches(UNARY_RE, good)).toBe(0)

    // 注释里的引述不得命中（routePrefetch.test.js 文件头踩过的坑）
    const commented =
      '// expect(' + 'true).toBe(' + 'true)\n/* expect(1).toEqual(1) */\nexpect(real).toBe(true)'
    expect(countMatches(BOTH_LITERAL_RE, stripComments(commented))).toBe(0)
  })

  test('检测器可证伪：认得出 test.skip / it.only / xit / test.todo', () => {
    const bad = [
      'test.skip(',
      'it.skip(',
      'describe.skip(',
      'test.only(',
      'it.only(',
      'test.todo(',
      'xit(',
      'xdescribe(',
    ].join('\n')
    expect(countMatches(SKIP_OR_ONLY_RE, bad)).toBe(8)
    const good = ['test(', 'it(', 'describe(', 'test.each(', 'it.concurrent('].join('\n')
    expect(countMatches(SKIP_OR_ONLY_RE, good)).toBe(0)
  })

  test('测试树零恒真断言、零跳过/独占用例', () => {
    const files = collectTestFiles(TESTS_DIR)
    expect(files.length).toBeGreaterThan(50)
    const hits = []
    for (const file of files) {
      const src = stripComments(readFileSync(file, 'utf8'))
      for (const hit of scanSource(src)) hits.push(rel(file) + ' :: ' + hit)
    }
    expect('恒真/跳过命中 ' + hits.length + ' 处：\n' + hits.join('\n')).toBe(
      '恒真/跳过命中 0 处：\n'
    )
  })
})
