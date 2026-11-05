/**
 * AttackProfileResult 行为测试（攻击画像结果卡，审计整改补覆盖批次）
 *
 * 组件定位：AttackProfileResult 是画像查询结果的纯投影层——所有判定都是对
 * profile prop 的派生 computed，无内部状态、无异步链路，渲染只需 nextTick。
 * 本套件锁定判定的分支两侧（覆盖门禁缺口在此）：no_data 渲染、containment
 * 四态标签、statCells 条件格、containment 缺席回落。
 * 期望文案取自 attackProfile zh-CN 词表（对本套件是外部事实）。
 */
import { describe, test, expect, afterEach } from 'vitest'
import { mountComponent, flush } from '../helpers/componentHarness'
import AttackProfileResult from '@/components/AttackProfileResult.vue'
import i18n from '@/i18n'
import attackProfileZhCN from '@/i18n/locales/attackProfile.zh-CN'
import attackProfileEnUS from '@/i18n/locales/attackProfile.en-US'

// 结果组件自己不带词表：attackProfile.* 由视图组件（AttackProfileView）在运行时
// mergeLocaleMessage 合并。直接挂结果组件时必须先做同款合并，否则渲染出裸键。
i18n.global.mergeLocaleMessage('zh-CN', { attackProfile: attackProfileZhCN })
i18n.global.mergeLocaleMessage('en-US', { attackProfile: attackProfileEnUS })

/** containment 三态的最小 profile 形状（分支测试共用） */
const makeProfile = (over = {}) => ({
  verdict: 'attack',
  total: 3,
  stats: {
    failedRequests: 2,
    failedLogins: 2,
    successfulLogins: 1,
    distinctAccountsTried: 2,
    distinctUserAgents: 1,
    firstSeen: '2026-11-04T00:10:00.000Z',
    lastSeen: '2026-11-04T00:30:00.005Z',
    ...over.stats,
  },
  categories: over.categories ?? [
    { code: 'credential_stuffing', count: 3, score: 30, samples: [] },
    { code: 'brute_force', count: 1, score: 12, samples: [] },
  ],
  uncategorized: over.uncategorized,
  timeline: over.timeline ?? { unit: 'day', buckets: [{ label: '11-04', count: 3 }] },
  containment: over.containment,
})

describe('AttackProfileResult 分支两侧', () => {
  afterEach(() => {
    i18n.global.locale.value = 'zh-CN'
  })

  test('verdict=no_data：正文与导航不渲染（isNoData 的 true 侧）', async () => {
    const vm = mountComponent(AttackProfileResult, {
      props: { profile: { verdict: 'no_data', total: 0 } },
    })
    await flush()
    expect(vm.find('[data-test="section-nav"]')).toBeNull()
  })

  test('containment 四态标签各走一条分支', async () => {
    const states = [
      {
        containment: { blacklisted: true, whitelisted: false, degraded: false, entries: [] },
        text: '该 IP 已在黑名单中',
      },
      {
        containment: { blacklisted: false, whitelisted: true, degraded: false, entries: [] },
        text: '该 IP 在白名单中',
      },
      {
        containment: { blacklisted: false, whitelisted: false, degraded: false, entries: [] },
        text: '该 IP 当前不在任何名单中',
      },
      {
        containment: { blacklisted: false, whitelisted: false, degraded: true, entries: [] },
        text: '暂时无法读取黑/白名单状态',
      },
    ]
    for (const s of states) {
      const vm = mountComponent(AttackProfileResult, {
        props: { profile: makeProfile({ containment: s.containment }) },
      })
      await flush()
      expect(vm.text()).toContain(s.text)
      vm.unmount()
    }
  })

  test('statCells 条件格：峰值按 unit 分 hour/day、高危行与疑似突破时间在场才出现', async () => {
    const vm = mountComponent(AttackProfileResult, {
      props: {
        profile: makeProfile({
          stats: {
            failedRequests: 2,
            failedLogins: 2,
            successfulLogins: 1,
            distinctAccountsTried: 2,
            distinctUserAgents: 1,
            firstSeen: '2026-11-04T00:10:00.000Z',
            lastSeen: '2026-11-04T00:30:00.005Z',
            peakBucketRequests: 5,
            criticalRows: 2,
            suspiciousSuccessAt: '2026-10-30T00:00:00.000Z',
          },
          timeline: { unit: 'hour', buckets: [] },
        }),
      },
    })
    await flush()
    const text = vm.text()
    expect(text).toContain('峰值请求数')
    expect(text).toContain('次/小时')
    expect(text).toContain('高危记录')
    expect(text).toContain('疑似突破时间')
    vm.unmount()

    const vm2 = mountComponent(AttackProfileResult, {
      props: {
        profile: makeProfile({
          stats: { peakBucketRequests: 5 },
          timeline: { unit: 'day', buckets: [] },
        }),
      },
    })
    await flush()
    expect(vm2.text()).toContain('次/天')
    vm2.unmount()
  })

  test('containment 对象缺席 ⇒ computed 回落 degraded 默认（`||` else 侧）', async () => {
    const vm = mountComponent(AttackProfileResult, {
      props: { profile: makeProfile({ containment: undefined }) },
    })
    await flush()
    expect(vm.text()).toContain('暂时无法读取黑/白名单状态')
  })
})
