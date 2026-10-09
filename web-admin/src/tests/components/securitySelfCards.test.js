/**
 * B 组自助面三卡片行为测试（SecurityInfoCard / AccountBindingsCard / MyLogsCard）
 *
 * 这三个组件是「后端已有、前端此前零引用」的三个本人数据端点的界面入口：
 *   GET /security/my-info   -> 安全评分 / 建议 / 最近登录
 *   GET /security/bindings  -> 邮箱/手机号/部门的绑定状态
 *   GET /security/my-logs   -> 本人操作日志（按时间范围收窄）
 *
 * 为什么值得测：三者的失败形态都是**静默**的——接口挂掉时若把上一次的数据
 * 留在界面上，用户会把过期的安全画像当成当前状态（比空白更误导）；而
 * my-logs 的 days 参数若没接上，用户切换范围却看到同一批数据，也毫无提示。
 * 故用例逐条钉住：成功渲染、失败落错误态、重试可恢复、参数正确上行。
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { mountComponent, click, flush, waitFor } from '../helpers/componentHarness'

const getMySecurityInfo = vi.fn()
const getAccountBindings = vi.fn()
const getMyLogs = vi.fn()

vi.mock('@/utils/api', () => ({
  api: {
    security: {
      getMySecurityInfo: (...a) => getMySecurityInfo(...a),
      getAccountBindings: (...a) => getAccountBindings(...a),
      getMyLogs: (...a) => getMyLogs(...a),
    },
    // 挂载 ProfileView（B 组接线用例）时，同栏的既有卡片也会各自取数；
    // 给桩以免它们因缺方法而抛，把「接线是否成立」的断言搅浑。
    auth: {
      getMe: () => Promise.resolve({ data: { success: true, data: { user: {} } } }),
      updateProfile: vi.fn(),
      listSessions: () =>
        Promise.resolve({ data: { data: { sessions: [], currentSidPresent: true } } }),
      getMfaStatus: () => Promise.resolve({ data: { data: { enabled: false } } }),
    },
  },
  isCanceledError: () => false,
}))

import SecurityInfoCard from '@/components/SecurityInfoCard.vue'
import AccountBindingsCard from '@/components/AccountBindingsCard.vue'
import MyLogsCard from '@/components/MyLogsCard.vue'
import ProfileView from '@/views/ProfileView.vue'

let active = null

const open = async (Comp, options = {}) => {
  active = mountComponent(Comp, {
    initialRoute: '/profile',
    routes: [{ path: '/profile', component: { render: () => null } }],
    ...options,
  })
  await flush(12)
  return active
}

const rows = (c) => c.findAll('.el-table__body-wrapper .el-table__row')

/** 点重试按钮（错误态里的「刷新」） */
const clickRetry = (c) => {
  const btn = c.findAll('button').find((b) => b.textContent.trim() === '刷新')
  expect(btn).toBeTruthy()
  click(btn)
}

/** 打开 el-select 并点选指定文案的选项（同 auditLogView 用例的判据） */
const pickOption = async (wrapper, label) => {
  click(wrapper)
  await flush(6)
  const combo = wrapper.querySelector('input[role=combobox]')
  expect(combo).toBeTruthy()
  const listbox = Array.from(document.body.querySelectorAll('[role=listbox]')).find(
    (lb) => lb.id === combo.getAttribute('aria-controls')
  )
  expect(listbox).toBeTruthy()
  const option = Array.from(listbox.querySelectorAll('.el-select-dropdown__item')).find(
    (o) => o.textContent.trim() === label
  )
  expect(option).toBeTruthy()
  click(option)
  await flush(8)
}

afterEach(() => {
  active?.handle.unmount()
  active = null
  getMySecurityInfo.mockReset()
  getAccountBindings.mockReset()
  getMyLogs.mockReset()
  document.body.querySelectorAll('.el-popper').forEach((n) => n.remove())
})

describe('SecurityInfoCard（我的安全信息）', () => {
  test('成功：渲染评分、建议与最近登录行（含未知 action 回退原始名）', async () => {
    getMySecurityInfo.mockResolvedValue({
      data: {
        data: {
          securityScore: 92,
          // 后端出**稳定码**（i18n 修复后），文案由前端词表映射；
          // 混一个未知码，验证回退路径
          suggestions: ['repeated_login_failures', 'zz_unknown_suggestion'],
          recentLogins: [
            {
              action: 'login_success',
              ip: '203.0.113.7',
              time: '2026-10-09T02:00:00.000Z',
              success: true,
            },
            {
              action: 'zz_unknown_action',
              ip: '203.0.113.8',
              time: '2026-10-08T02:00:00.000Z',
              success: false,
            },
          ],
        },
      },
    })

    const c = await open(SecurityInfoCard)
    await waitFor(() => c.find('.score-value')?.textContent.trim() === '92', {
      message: '评分渲染',
    })

    expect(c.find('.score-value').textContent.trim()).toBe('92')
    // 已知建议码 → 中文词表文案（英文界面下会显示英文，见 i18n 用例）
    expect(c.text()).toContain('检测到多次登录失败，建议修改密码')
    // 不得把裸码当正文渲染
    expect(c.text()).not.toContain('repeated_login_failures')
    // 未知建议码原样回退（便于发现后端新增建议，而不是整条消失）
    expect(c.text()).toContain('zz_unknown_suggestion')

    await waitFor(() => rows(c).length === 2, { message: '两条登录记录' })
    // 已知 action 走词表，未知 action 回退原始动作名（便于发现后端新增枚举）
    expect(c.text()).toContain('登录成功')
    expect(c.text()).toContain('zz_unknown_action')
    expect(c.text()).toContain('203.0.113.7')
  })

  test('英文界面：建议码渲染成英文文案（i18n 缺口回归）', async () => {
    // 缺陷形状：suggestions 原是后端拼好的中文句子，切到 en-US 后这一块仍是中文。
    // 修法是后端出码、前端翻；本用例从**组件真实渲染**验证这条链路通了。
    getMySecurityInfo.mockResolvedValue({
      data: {
        data: { securityScore: 90, suggestions: ['repeated_login_failures'], recentLogins: [] },
      },
    })

    const c = await open(SecurityInfoCard, { locale: 'en-US' })
    await waitFor(() => c.find('.suggest-list li') !== null, { message: '建议渲染' })

    expect(c.text()).toContain('Multiple failed sign-in attempts detected')
    // 反向：不得残留中文，也不得显示裸码
    expect(c.text()).not.toContain('检测到多次登录失败')
    expect(c.text()).not.toContain('repeated_login_failures')
  })

  test('失败：落错误态（不渲染评分）；点刷新可恢复', async () => {
    getMySecurityInfo.mockRejectedValueOnce(new Error('boom'))
    const c = await open(SecurityInfoCard)
    await waitFor(() => c.find('.self-error') !== null, { message: '错误态出现' })
    // 失败时不得渲染评分（避免用户把占位/过期值当当前分数）
    expect(c.find('.score-value')).toBeNull()

    // 点刷新：恢复正常
    getMySecurityInfo.mockResolvedValueOnce({
      data: { data: { securityScore: 70, suggestions: [], recentLogins: [] } },
    })
    clickRetry(c)
    await waitFor(() => c.find('.score-value')?.textContent.trim() === '70', {
      message: '重试恢复',
    })
  })
})

describe('AccountBindingsCard（账户绑定）', () => {
  test('成功：逐项渲染类型文案与绑定/未绑定/必填标签', async () => {
    getAccountBindings.mockResolvedValue({
      data: {
        data: {
          bindings: [
            { type: 'email', value: 'a***@example.com', verified: true, required: true },
            { type: 'phone', value: '', verified: false, required: false },
            // 后端不再下发中文占位「未设置」（那会在英文界面里露中文），
            // 未设置即空串 + verified:false；占位符由前端渲染
            { type: 'department', value: '', verified: false, required: false },
          ],
        },
      },
    })

    const c = await open(AccountBindingsCard)
    await waitFor(() => c.findAll('.binding-item').length === 3, { message: '三条绑定项' })

    expect(c.text()).toContain('邮箱')
    expect(c.text()).toContain('手机号')
    expect(c.text()).toContain('部门')
    expect(c.text()).toContain('a***@example.com')
    // 未绑定项 value 为空 -> 展示占位符而非空串
    expect(c.findAll('.binding-item')[1].textContent).toContain('—')
    // 未设置的部门同样落占位符，且**不得**出现后端旧的中文占位串
    expect(c.findAll('.binding-item')[2].textContent).toContain('—')
    expect(c.text()).not.toContain('未设置')
    expect(c.text()).toContain('已绑定')
    expect(c.text()).toContain('未绑定')
    expect(c.text()).toContain('必填')
  })

  test('失败：落错误态且不渲染任何绑定行', async () => {
    getAccountBindings.mockRejectedValue(new Error('boom'))
    const c = await open(AccountBindingsCard)
    await waitFor(() => c.find('.self-error') !== null, { message: '错误态出现' })
    expect(c.findAll('.binding-item')).toHaveLength(0)
  })
})

describe('MyLogsCard（我的操作日志）', () => {
  test('成功：默认按近 7 天请求，渲染日志行与条数', async () => {
    getMyLogs.mockResolvedValue({
      data: {
        data: [
          {
            action: 'login_success',
            category: 'auth',
            ip: '203.0.113.7',
            timestamp: '2026-10-09T02:00:00.000Z',
            success: true,
          },
          {
            action: 'device_update',
            category: 'device',
            ip: '203.0.113.9',
            timestamp: '2026-10-08T02:00:00.000Z',
            success: false,
          },
        ],
      },
    })

    const c = await open(MyLogsCard)
    await waitFor(() => rows(c).length === 2, { message: '两条日志' })

    // 默认窗口必须上行（否则用户看到的是后端默认值而非界面所示范围）
    expect(getMyLogs).toHaveBeenCalledWith({ days: 7, limit: 50 })
    expect(c.text()).toContain('登录成功')
    expect(c.text()).toContain('共 2 条')
  })

  test('切换时间范围：以新的 days 重新拉取', async () => {
    getMyLogs.mockResolvedValue({ data: { data: [] } })
    const c = await open(MyLogsCard)
    await waitFor(() => getMyLogs.mock.calls.length >= 1, { message: '首次请求' })

    await pickOption(c.find('.el-select__wrapper'), '近 30 天')
    await waitFor(() => getMyLogs.mock.calls.some((a) => a[0]?.days === 30), {
      message: '按 30 天重新拉取',
    })
  })

  test('空结果：展示空态文案而非空表格', async () => {
    getMyLogs.mockResolvedValue({ data: { data: [] } })
    const c = await open(MyLogsCard)
    await waitFor(() => c.find('.empty-hint') !== null, { message: '空态出现' })
    expect(rows(c)).toHaveLength(0)
    expect(c.text()).toContain('暂无操作记录')
  })

  test('已有数据后切换范围失败：错误态取代表格与条数，界面上不残留旧行；点刷新可恢复', async () => {
    // ⚠️ 变异实测（M20，2026-10-09）校正了本用例原先的**名实不符**。
    // 原断言是 `expect(rows(c)).toHaveLength(0)`，即「清空旧行被守住了」——但它是**空洞**的：
    // MyLogsCard 的模板是
    //   <GlassSkeleton v-if="loading"/> / <div v-else-if="error"> / <template v-else>
    // 错误态下整个表格分支不渲染，rows 恒为 0，与 `logs.value` 清没清毫无关系。
    // 实测：把 catch 里的 `logs.value = []` 删掉，本用例**仍绿**（变异存活）——
    // 即该断言挡不住它自称要挡的回归。
    //
    // 结论分两层，分别写清：
    //  · 可观测（本用例守）：失败后错误态**取代**了整个表格区，用户看不到旧行；
    //  · 不可观测（本用例不守、也不假称守）：catch 里的 `logs.value = []` 是
    //    模板之外观测不到的防御性写法——只要模板改成「错误态与表格并存」，
    //    它才会成为唯一防线。此处明确标注，避免后来者以为它已被测试覆盖。
    getMyLogs.mockResolvedValueOnce({
      data: {
        data: [
          {
            action: 'login_success',
            category: 'auth',
            ip: '203.0.113.7',
            timestamp: '2026-10-09T02:00:00.000Z',
            success: true,
          },
        ],
      },
    })
    const c = await open(MyLogsCard)
    await waitFor(() => rows(c).length === 1, { message: '首屏一行' })
    expect(c.text()).toContain('共 1 条')

    // 切范围时请求失败
    getMyLogs.mockRejectedValueOnce(new Error('boom'))
    await pickOption(c.find('.el-select__wrapper'), '近 30 天')
    await waitFor(() => c.find('.self-error') !== null, { message: '错误态出现' })

    // 可观测口径：表格与条数整块消失（不是「表格还在但空了」）
    expect(c.find('.el-table')).toBeNull()
    expect(c.text()).not.toContain('共 1 条')
    expect(rows(c)).toHaveLength(0)

    // 点刷新恢复：重新拉取并渲染
    getMyLogs.mockResolvedValueOnce({ data: { data: [] } })
    clickRetry(c)
    await waitFor(() => c.find('.self-error') === null, { message: '错误态退出' })
    expect(rows(c)).toHaveLength(0)
  })
})

describe('B 组接线（ProfileView 真实挂载）', () => {
  // 组件级用例只证明「卡片自己会取数」；本用例证明**接线成立**——
  // 卡片真的挂在个人资料页上，且挂载后各自打到对应端点。
  // 若哪天有人把三张卡从 ProfileView 摘掉，组件级用例仍会全绿，只有本用例会红。
  test('个人资料页挂载三张自助卡，且各自发起对应端点请求', async () => {
    getMySecurityInfo.mockResolvedValue({
      data: { data: { securityScore: 100, suggestions: [], recentLogins: [] } },
    })
    getAccountBindings.mockResolvedValue({ data: { data: { bindings: [] } } })
    getMyLogs.mockResolvedValue({ data: { data: [] } })

    const c = await open(ProfileView)

    await waitFor(
      () =>
        getMySecurityInfo.mock.calls.length >= 1 &&
        getAccountBindings.mock.calls.length >= 1 &&
        getMyLogs.mock.calls.length >= 1,
      { message: '三个自助端点各被调用一次' }
    )

    // 卡片标题确实渲染在页面上
    expect(c.text()).toContain('我的安全信息')
    expect(c.text()).toContain('账户绑定')
    expect(c.text()).toContain('我的操作日志')
  })
})
