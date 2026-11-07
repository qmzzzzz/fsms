/**
 * AttackEvidenceTable 渲染测试（审计整改补覆盖批次）
 *
 * 纯投影子组件：把 evidence 行数组渲染成表格，空数组走空态。
 * 词表同 AttackProfileResult——由测试侧显式 mergeLocaleMessage。
 */
import { describe, test, expect } from 'vitest'
import { mountComponent, flush } from '../helpers/componentHarness'
import AttackEvidenceTable from '@/components/AttackEvidenceTable.vue'
import i18n from '@/i18n'
import attackProfileZhCN from '@/i18n/locales/attackProfile.zh-CN'
import attackProfileEnUS from '@/i18n/locales/attackProfile.en-US'

i18n.global.mergeLocaleMessage('zh-CN', { attackProfile: attackProfileZhCN })
i18n.global.mergeLocaleMessage('en-US', { attackProfile: attackProfileEnUS })

describe('AttackEvidenceTable 渲染', () => {
  test('空数组走空态，不渲染行', async () => {
    const vm = mountComponent(AttackEvidenceTable, { props: { evidence: [] } })
    await flush()
    expect(vm.findAll('.el-table__row').length).toBe(0)
    vm.unmount()
  })

  test('有数据时逐行渲染且动作码经 actionLabel 投影', async () => {
    const vm = mountComponent(AttackEvidenceTable, {
      props: {
        evidence: [
          {
            action: 'login_failed',
            method: 'POST',
            path: '/api/auth/login',
            status: 401,
            username: 'u1',
            createdAt: '2026-11-04T00:10:00.000Z',
          },
        ],
      },
    })
    await flush()
    expect(vm.findAll('.el-table__row').length).toBe(1)
    expect(vm.text()).not.toContain('undefined')
    vm.unmount()
  })

  test('多行异形证据：缺省可选字段不炸、HEAD 方法与 2xx 状态照实投影', async () => {
    const vm = mountComponent(AttackEvidenceTable, {
      props: {
        evidence: [
          {
            action: 'honeypot_probe',
            method: 'HEAD',
            path: '/api/avatars/hp-u1',
            status: 200,
            createdAt: '2026-11-04T00:20:00.000Z',
          },
          {
            action: 'login_failed',
            method: 'GET',
            path: '/api/devices',
            status: 403,
            username: 'u2',
            createdAt: '2026-11-04T00:21:00.000Z',
          },
        ],
      },
    })
    await flush()
    expect(vm.findAll('.el-table__row').length).toBe(2)
    expect(vm.text()).not.toContain('undefined')
    vm.unmount()
  })
})
