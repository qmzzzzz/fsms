/**
 * WB-2：本地存储敏感字段卫生检查（静态不变量 + 扫描器自证）
 *
 * 令牌已走 httpOnly cookie（I-01），JS 可读存储里不应再出现任何凭据类写入。
 * jsdom 断不出「未来会不会有人写坏」，用源码扫描兜住这条底线：
 * 任何向 localStorage / sessionStorage 写入 token / password / secret / mfa 键的代码
 * 都会在合并前红灯。
 *
 * ⚠️ 扫描器自证（2026-09-18 补强）：此前本文件只有「仓库当前无违例」一条断言，
 * 而这条断言对扫描器自身的失效是盲的——手工变异实测：
 *   - 把正则里的 token 改成 tokenn（正则写坏）
 *   - 把 collectSourceFiles 改成直接 return acc（文件收集失效）
 *   - 去掉 i 标志（大小写漏判）
 *   - 把 safeLocal.set / safeStorage.setJSON 从 API 列表里删掉
 * 以上四种「守卫已经瞎了」的改动，原测试**全部保持绿色**。也就是说守卫的
 * 有效性只能靠人读代码确认，这本身就是一个不可证伪的断言。
 * 现在把扫描逻辑抽成纯函数 findOffenders，用内联样例反向证明它确实能抓到违例；
 * 同时断言文件收集真的收回了源码（而不是空集合导致的「无违例」）。
 */
import { describe, test, expect } from 'vitest'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { resolve, join, sep } from 'node:path'

const SRC_ROOT = resolve(__dirname, '../..')

const SENSITIVE_KEY_PATTERN =
  /(?:localStorage|sessionStorage|safeLocal|safeStorage)\.(?:set|setJSON|setItem)\(\s*['"`]([^'"`]*(?:token|password|secret|mfa)[^'"`]*)['"`]/gi

/**
 * 纯函数：在一段源码文本里找出凭据类存储写入
 * @param {string} source 源码文本
 * @param {string} [fileLabel] 出现在结果里的文件名（排障用）
 * @returns {Array<{file: string, key: string}>} 命中列表；无命中为空数组
 */
function findOffenders(source, fileLabel = '<inline>') {
  const offenders = []
  // matchAll 内部会克隆正则（不共享 lastIndex），跨调用无状态残留
  for (const match of source.matchAll(SENSITIVE_KEY_PATTERN)) {
    offenders.push({ file: fileLabel, key: match[1] })
  }
  return offenders
}

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

describe('WB-2 本地存储卫生', () => {
  describe('扫描器自证（守卫必须先证明自己抓得到违例）', () => {
    test('四种存储 API 的凭据键写入都能被抓到', () => {
      expect(findOffenders(`sessionStorage.setItem('token', t)`)).toEqual([
        { file: '<inline>', key: 'token' },
      ])
      expect(findOffenders(`localStorage.setItem('password', p)`)).toEqual([
        { file: '<inline>', key: 'password' },
      ])
      expect(findOffenders(`safeLocal.set('refreshToken', r)`)).toEqual([
        { file: '<inline>', key: 'refreshToken' },
      ])
      expect(findOffenders(`safeStorage.setJSON('mfaSecret', s)`)).toEqual([
        { file: '<inline>', key: 'mfaSecret' },
      ])
      expect(findOffenders(`safeLocal.setJSON('api_secret', s)`)).toEqual([
        { file: '<inline>', key: 'api_secret' },
      ])
    })

    test('大小写不敏感：Token / PASSWORD / Mfa 同样命中（不得只认全小写）', () => {
      expect(findOffenders(`safeLocal.set('Token', t)`)).toHaveLength(1)
      expect(findOffenders(`safeLocal.set('PASSWORD', p)`)).toHaveLength(1)
      expect(findOffenders(`safeLocal.set('MfaRecovery', m)`)).toHaveLength(1)
    })

    test('一次扫描能同时报出多处违例（不是「只报第一条」）', () => {
      const src = [
        `safeLocal.set('token', a)`,
        `safeStorage.setItem('password', b)`,
        `localStorage.setJSON('secretKey', c)`,
      ].join('\n')
      expect(findOffenders(src).map((o) => o.key)).toEqual(['token', 'password', 'secretKey'])
    })

    test('不误报：读取/删除、非敏感键、普通对象的同名方法都不算违例', () => {
      expect(findOffenders(`localStorage.getItem('token')`)).toEqual([])
      expect(findOffenders(`sessionStorage.removeItem('token')`)).toEqual([])
      expect(findOffenders(`safeLocal.get('password')`)).toEqual([])
      expect(findOffenders(`safeStorage.remove('mfaTicket')`)).toEqual([])
      expect(findOffenders(`safeLocal.set('currentUser', u)`)).toEqual([])
      expect(findOffenders(`safeLocal.setJSON('permissions', p)`)).toEqual([])
      // 普通对象上的 .set（非存储 API）不得被当成违例
      expect(findOffenders(`myMap.set('token', t)`)).toEqual([])
    })

    test('命中结果带文件名，便于定位（不是只返回布尔）', () => {
      const offenders = findOffenders(`safeLocal.set('token', t)`, 'src/store/example.js')
      expect(offenders[0].file).toBe('src/store/example.js')
    })
  })

  describe('仓库扫描', () => {
    test('源码收集有效：确实扫到了源文件（防止空集合伪造「无违例」）', () => {
      const files = collectSourceFiles(SRC_ROOT)
      // 当前仓库有 60+ 个源文件；阈值取 50 只为证明「不是空集合/不是个位数」
      expect(files.length).toBeGreaterThan(50)
      // 且必须包含已知的、含存储写入的源文件（存在性校验，防路径拼接写错）
      const rel = files.map((f) => f.split(sep).join('/'))
      expect(rel.some((f) => f.endsWith('src/store/auth.js'))).toBe(true)
      expect(rel.some((f) => f.endsWith('src/store/storage.js'))).toBe(true)
      // tests 目录必须被排除，否则用例里的历史残留夹具会被误判
      expect(rel.some((f) => f.includes('/tests/'))).toBe(false)
    })

    test('无凭据类键写入 localStorage/sessionStorage', () => {
      const files = collectSourceFiles(SRC_ROOT)
      const offenders = files.flatMap((file) => findOffenders(readFileSync(file, 'utf8'), file))
      // 实现是「命中即失败」（offenders 必须为空数组），**没有**白名单数组。
      // 若将来确实需要放行某个非敏感键，请在此处显式登记并写明理由——
      // 但不要误以为现有代码已提供该机制（原注释如此声称，与实现不符）。
      expect(offenders).toEqual([])
    })
  })
})
