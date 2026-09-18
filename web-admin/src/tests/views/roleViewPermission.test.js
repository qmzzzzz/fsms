/**
 * 权限判定来源统一性（P1-8 收尾不变量）
 *
 * 【为什么这条必须是静态断言】
 * 「hasPerm 必须来自 usePermission 组合式函数」是**架构约定**，行为测试表达不了：
 * 一个视图完全可以自己 `matchPermission(authStore.permissions, p)` 造一个
 * hasPerm，行为逐位等价，所有渲染断言照样通过。本仓已实测：把 UserView 改成
 * 自造 hasPerm 后，userView.test.js（43 例）+ permission.test.js（8 例）+
 * usePermission.test.js（3 例）**全部 PASS**，没有任何行为用例能发现。
 *
 * 为什么值得守：usePermission 是权限判定的**唯一入口**（内部复用
 * utils/permission.js 的 matchPermission）。一旦各视图各自实现，判定逻辑
 * （通配 `*:*` / `module:*`）就会多处漂移——某处漏掉通配分支时，持有
 * `user:*` 的用户会在该视图里莫名失去按钮，而行为用例只喂精确权限码，
 * 照不出来。
 *
 * 【本文件曾经包含、现已删除的断言及其替代用例（逐个变异实测杀死）】
 *   - role:create / role:assign（RoleView 按钮）      → roleView.test.js（停发 can-delete → 3 例变红）
 *   - RoleListPanel 只接收 canDelete prop 不自行读权限 → roleListPanel.test.js（自造 hasPerm → 3 例变红）
 *   - 删除按钮不得用 v-else 兜底                      → roleListPanel.test.js（改 v-else → 2 例变红）
 *   - IpListView 刻意不加 hasPerm 门控                → ipListView.test.js（加门控 → 4 例变红）
 *   - RoleView 下发 :can-delete="hasPerm('role:delete')" → roleView.test.js（改恒真 → 3 例变红）
 */
import { describe, test, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'

const readSrc = (rel) => readFileSync(resolve(__dirname, '../..', rel), 'utf8')

describe('权限判定来源统一（架构不变量，行为测试不可表达）', () => {
  test('UserView / ReportView 的 hasPerm 一律来自 usePermission 组合式函数', () => {
    for (const rel of ['views/UserView.vue', 'views/ReportView.vue']) {
      const src = readSrc(rel)
      expect(src, `${rel} 未从 @/composables/usePermission 取用`).toContain(
        '@/composables/usePermission'
      )
      expect(src, `${rel} 未以解构方式取得 hasPerm`).toContain(
        'const { hasPerm } = usePermission()'
      )
      // 反向：不得直接 import 权限匹配纯函数来自造判定（那是 usePermission 的职责）
      expect(src, `${rel} 绕开组合式函数自行调用 matchPermission`).not.toMatch(
        /import\s*\{[^}]*matchPermission[^}]*\}\s*from/
      )
    }
  })
})
