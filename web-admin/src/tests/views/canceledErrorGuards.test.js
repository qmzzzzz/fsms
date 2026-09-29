/**
 * 路由切换取消的假错误防线（P1-16）
 *
 * 背景：router/index.js 的 beforeEach 调 cancelAllPendingRequests()，
 * 它只 abort GET（api.js 的 UNCANCELABLE_METHODS 保留写请求）。被 abort 的请求
 * 会在视图 catch 里抛 ERR_CANCELED，若不做判定就会弹「加载失败」——
 * 用户已经切到新页面，却看到上一页的红框，属于典型的假错误。
 *
 * 实测口径（2026-09-29 重测，全 src 扫描）：catch 体含 ElMessage 的块共 16 处，
 * 其中 try 体直接含 GET 的 3 处已全部加守卫。
 *
 * **目标集从 12 缩到 3 是预期内的收缩，不是漏网**：P2-3 统一了「不双提示」契约——
 * 加载失败的 catch 不再自己弹 toast（提示改由 api.js 响应拦截器统一负责），这些块
 * 因「catch 体不再含 ElMessage」而退出本目标集。目标集的判据本身就是「catch 体含
 * ElMessage」，不再弹 toast 的块已无法产生假错误提示，退出是定义使然。
 * 它们的状态清理仍保留 isCanceledError + isCurrent 双守卫（见各视图 catch），
 * 唯一例外是 ReportView.loadChartData：其 catch 体已空（不清态、不提示），守卫
 * 随之删除——空 catch 不产生任何副作用，不存在需要防的假错误。
 *
 * 现存的 3 处（导出/下载失败、审核表单提交）都属「失败要弹具体原因」的块，故
 * 仍须守卫。其余 13 处含 ElMessage 的 catch 属以下三类，均不加守卫：
 *   1. 写请求（post/put/delete）——不会被 cancelAllPendingRequests 取消；
 *   2. 确认框分支（ElMessageBox.confirm 的 'cancel'/'close'）——另有既有判定；
 *   3. 加密等非请求调用（如 encryptPassword 抛错）。
 * 注意：另有若干 catch 的 try 体内仅**间接**调用含 GET 的加载函数（如成功后
 * loadData() 刷新列表）且未 await：abort 只会让那个游离的 GET 静默失败，不影响
 * 本 catch 的判定，故同样不加守卫（实测未纳入）。
 *
 * 本套件做两件事：
 *  1. 行为级：isCanceledError 对 axios 取消错误与普通错误的判定；
 *  2. 源码级：凡 catch 体含 ElMessage 且 try 体含 GET 的块，catch 体内必须有
 *     isCanceledError 守卫——新增视图若漏加，这里会红。
 */
import { describe, test, expect } from 'vitest'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { isCanceledError } from '@/utils/api'

const SRC = resolve(__dirname, '../..')

/** 递归收集 src 下的 .vue/.js（排除测试目录与 node_modules） */
const collectFiles = (dir, acc = []) => {
  for (const name of readdirSync(dir)) {
    const full = join(dir, name)
    if (statSync(full).isDirectory()) {
      if (name === 'node_modules' || name === 'tests') continue
      collectFiles(full, acc)
      continue
    }
    if (/\.(vue|js)$/.test(name)) acc.push(full)
  }
  return acc
}

/** 从 utils/api.js 解析 命名空间.方法 → HTTP 动词 的映射 */
const buildVerbMap = () => {
  const src = readFileSync(join(SRC, 'utils/api.js'), 'utf8')
  const start = src.indexOf('export const api = {')
  let i = src.indexOf('{', start),
    depth = 0,
    end = -1
  for (let j = i; j < src.length; j += 1) {
    if (src[j] === '{') depth += 1
    else if (src[j] === '}') {
      depth -= 1
      if (depth === 0) {
        end = j
        break
      }
    }
  }
  const body = src.slice(i + 1, end)
  const map = new Map()
  const nsRe = /^ {2}(\w+):\s*\{/gm
  let m
  const starts = []
  while ((m = nsRe.exec(body)) !== null) starts.push([m[1], m.index])
  for (const [name, at] of starts) {
    const b0 = body.indexOf('{', at)
    let d = 0
    let e = -1
    for (let j = b0; j < body.length; j += 1) {
      if (body[j] === '{') d += 1
      else if (body[j] === '}') {
        d -= 1
        if (d === 0) {
          e = j
          break
        }
      }
    }
    const text = body.slice(b0 + 1, e)
    const methods = new Map()
    for (const x of text.matchAll(
      /(\w+):\s*\([^)]*\)\s*=>\s*\n?\s*apiClient\.(get|post|put|patch|delete)\(/g
    )) {
      methods.set(x[1], x[2])
    }
    map.set(name, methods)
  }
  return map
}

/** 取 catch 关键字后成对的 { } 块内容 */
const catchBodyAt = (text, at) => {
  const braceStart = text.indexOf('{', at)
  let d = 0
  for (let j = braceStart; j < text.length; j += 1) {
    if (text[j] === '{') d += 1
    else if (text[j] === '}') {
      d -= 1
      if (d === 0) return text.slice(braceStart + 1, j)
    }
  }
  return ''
}

describe('isCanceledError 判定（行为级）', () => {
  test('axios 取消的两种形态都判真', () => {
    expect(isCanceledError({ code: 'ERR_CANCELED' })).toBe(true)
    expect(isCanceledError({ name: 'CanceledError' })).toBe(true)
  })

  test('普通错误 / null / undefined 判假（不得误吞真实失败）', () => {
    expect(isCanceledError(new Error('boom'))).toBe(false)
    expect(isCanceledError({ code: 'ECONNABORTED' })).toBe(false)
    expect(isCanceledError(null)).toBe(false)
    expect(isCanceledError(undefined)).toBe(false)
    // 确认框的 cancel/close 是字符串，不属于本判定范围（各视图另有分支）
    expect(isCanceledError('cancel')).toBe(false)
  })
})

describe('视图 catch 守卫（源码级）', () => {
  const verbMap = buildVerbMap()
  const files = collectFiles(SRC)

  /** 收集「catch 体含 ElMessage 且 try 体含 GET」的全部块 */
  const collectGuardedTargets = () => {
    const found = []
    for (const file of files) {
      const text = readFileSync(file, 'utf8')
      const re = /catch\s*(?:\(\s*(\w+)\s*\))?\s*\{/g
      let m
      while ((m = re.exec(text)) !== null) {
        const body = catchBodyAt(text, m.index)
        if (!body.includes('ElMessage')) continue
        const before = text.slice(0, m.index)
        const tryIdx = before.lastIndexOf('try')
        if (tryIdx === -1) continue
        const tryBody = catchBodyAt(text, tryIdx + 3)
        const hasDirectGet =
          /\bapiClient\.get\s*\(/.test(tryBody) ||
          [...tryBody.matchAll(/\bapi\.(\w+)\.(\w+)\s*\(/g)].some(
            (cm) => (verbMap.get(cm[1]) || new Map()).get(cm[2]) === 'get'
          )
        if (!hasDirectGet) continue
        const rel = file.slice(SRC.length + 1).replace(/\\/g, '/')
        found.push({ file: rel, line: text.slice(0, m.index).split(/\r?\n/).length, body })
      }
    }
    return found
  }

  test('实测目标块数与清单（新增视图漏加守卫时本测试会红）', () => {
    const targets = collectGuardedTargets()
    const unguarded = targets.filter((t) => !t.body.includes('isCanceledError'))
    const detail = unguarded.map((t) => `${t.file}:${t.line}`).join(', ')
    expect(detail).toBe('')
    // 锁定实测基线：3 处「catch 体含 ElMessage 且 try 体直接含 GET」的块。
    // 用 >= 而非 ===：新增「带守卫」的视图是正确演进，不该被计数卡住；
    // 真正的防线是上面的零漏网断言。基线随 P2-3 由 12 降到 3（见文件头说明）。
    expect(targets.length).toBeGreaterThanOrEqual(3)
  })

  test('守卫必须位于 ElMessage 之前（放在之后等于没防住）', () => {
    const targets = collectGuardedTargets()
    const misplaced = targets.filter((t) => {
      const guardAt = t.body.indexOf('isCanceledError')
      const msgAt = t.body.indexOf('ElMessage')
      return guardAt > msgAt
    })
    expect(misplaced.map((t) => `${t.file}:${t.line}`)).toEqual([])
  })
})
