/**
 * WB-2：本地存储敏感字段卫生检查（静态不变量）
 *
 * 令牌已走 httpOnly cookie（I-01），JS 可读存储里不应再出现任何凭据类写入。
 * jsdom 断不出「未来会不会有人写坏」，用源码扫描兜住这条底线：
 * 任何向 localStorage / sessionStorage 写入 token / password / secret 键的代码
 * 都会在合并前红灯。
 */
import { describe, test, expect } from 'vitest'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { resolve, join } from 'node:path'

const SRC_ROOT = resolve(__dirname, '../..')

function collectSourceFiles(dir, acc = []) {
  for (const name of readdirSync(dir)) {
    const full = join(dir, name)
    const st = statSync(full)
    if (st.isDirectory()) {
      if (name === 'tests' || name === 'node_modules') continue
      collectSourceFiles(full, acc)
    } else if (/\.(js|vue)$/.test(name)) {
      acc.push(full)
    }
  }
  return acc
}

const SENSITIVE_KEY_PATTERN =
  /(?:localStorage|sessionStorage|safeLocal|safeStorage)\.(?:set|setJSON|setItem)\(\s*['"`]([^'"`]*(?:token|password|secret|mfa)[^'"`]*)['"`]/gi

describe('WB-2 本地存储卫生', () => {
  test('无凭据类键写入 localStorage/sessionStorage', () => {
    const files = collectSourceFiles(SRC_ROOT)
    const offenders = []
    for (const file of files) {
      const source = readFileSync(file, 'utf8')
      for (const match of source.matchAll(SENSITIVE_KEY_PATTERN)) {
        offenders.push(`${file}: 写入键 "${match[1]}"`)
      }
    }
    // 例外白名单：确认为非敏感的既有键在此登记并说明理由
    expect(offenders).toEqual([])
  })
})
