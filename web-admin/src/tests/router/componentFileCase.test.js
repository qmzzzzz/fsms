/**
 * 路由懒加载组件路径的**大小写逐字**门禁（2026-10-01）
 *
 * 起因：本机工作树里落盘名是 `src/views/ipListView.vue`，而 git 索引与所有 import
 * 写的都是 `IpListView.vue`。Windows NTFS 大小写不敏感 + `core.ignorecase=true`
 * ⇒ `git status` 干净、vitest 全绿、`existsSync` 也说"在"——三条常规判据全部失明。
 * 但 Linux 上的构建（docker COPY 的是这棵工作树，不是 git clone）是大小写敏感的：
 * `import('@/views/IpListView.vue')` 解析不到 `ipListView.vue` ⇒ 构建期才炸。
 *
 * 为什么用 `readdirSync` 而不是 `existsSync`：后者在 NTFS 上对任意大小写都返回 true，
 * 拿它做判据等于没有判据。前者返回**真实落盘名**，逐段比对才与 Linux 的解析规则同构。
 * 这条判据在 Windows 上也能变红——这正是它存在的理由（缺陷就只在 Windows 上产生）。
 */
import { readdirSync, readFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import { describe, expect, test } from 'vitest'

const SRC_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../')
const ROUTER_FILE = path.join(SRC_DIR, 'router/index.js')

/**
 * 路径是否以**逐字大小写**存在：每一段都必须在父目录的 readdirSync 结果里精确出现。
 * @returns {false | string} 命中则回真实路径，任一段大小写不符即 false
 */
function existsWithExactCase(absPath) {
  const relativeToSrc = path.relative(SRC_DIR, absPath)
  if (relativeToSrc.startsWith('..')) return false // 越出 src，本闸不管
  let dir = SRC_DIR
  for (const segment of relativeToSrc.split(path.sep)) {
    let entries
    try {
      entries = readdirSync(dir)
    } catch {
      return false
    }
    if (!entries.includes(segment)) return false
    dir = path.join(dir, segment)
  }
  return dir
}

/**
 * 把 import 说明符解析成 src 下的绝对路径。
 * `@` → src（vite.config.js 的 alias）；相对路径**按引用方所在目录**解析——
 * 写成"相对 src"是错的：`../views/LoginView.vue` 出自 src/router/，
 * 相对 src 会跳到 web-admin/views 而判成不存在（本闸第一版就这么错过，
 * 恰好说明它确实在按目录核验而不是空转）。
 */
function resolveSpecifier(specifier, importerDir) {
  if (specifier.startsWith('@/')) return path.join(SRC_DIR, specifier.slice(2))
  if (specifier.startsWith('.')) return path.resolve(importerDir, specifier)
  return null // 裸包名（element-plus 等）不在本闸范围
}

function lazyImportsOf(file) {
  const src = readFileSync(file, 'utf8')
  const matches = [...src.matchAll(/import\(\s*['"]([^'"]+)['"]\s*\)/g)]
  return matches.map((m) => m[1])
}

describe('路由懒加载路径与落盘名大小写一致', () => {
  const specifiers = lazyImportsOf(ROUTER_FILE)

  test('反向自证：确实解析到了足够多的懒加载说明符（闸不是空转）', () => {
    expect(specifiers.length).toBeGreaterThanOrEqual(12)
    // 再钉一条"判据本身有效"：把一个不存在的大小写喂进去必须判 false。
    // 没有这一条，existsWithExactCase 写反成"总是 true"也照样全绿。
    expect(existsWithExactCase(path.join(SRC_DIR, 'router/index.js'))).not.toBe(false)
    expect(existsWithExactCase(path.join(SRC_DIR, 'router/Index.js'))).toBe(false)
    expect(existsWithExactCase(path.join(SRC_DIR, 'Router/index.js'))).toBe(false)
  })

  test.each(specifiers.map((s, i) => [i, s]))('%i → %s 逐字命中落盘名', (_i, specifier) => {
    const target = resolveSpecifier(specifier, path.dirname(ROUTER_FILE))
    if (target === null) return // 裸包名由构建器管
    const hit = existsWithExactCase(target)
    const parent = path.dirname(target)
    const near = (() => {
      try {
        return readdirSync(parent).filter(
          (e) => e.toLowerCase() === path.basename(target).toLowerCase()
        )
      } catch {
        return ['<目录本身不存在>']
      }
    })()
    expect(
      hit !== false,
      `${specifier} 在磁盘上的实际名字是 ${JSON.stringify(near)}；` +
        'NTFS 上 vitest 与 git status 都看不出来，Linux 构建会解析失败'
    ).toBe(true)
  })

  test('views 目录下不存在同名仅大小写不同的两个文件（防止修复时留下孪生）', () => {
    const viewsDir = path.join(SRC_DIR, 'views')
    const names = readdirSync(viewsDir)
    const byLower = new Map()
    for (const name of names) {
      const key = name.toLowerCase()
      byLower.set(key, [...(byLower.get(key) || []), name])
    }
    const twins = [...byLower.entries()].filter(([, list]) => list.length > 1)
    expect(twins.map(([key, list]) => `${key}: ${list.join(' | ')}`)).toEqual([])
  })
})
