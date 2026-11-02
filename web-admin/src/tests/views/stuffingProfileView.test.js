/**
 * StuffingProfileView 组件级行为测试
 *
 * 覆盖画像页的主路径与「空表不许冒充没有攻击」的三类空态：
 *  - 默认业务日与请求参数、结果表渲染（含枚举翻译与未知值回落）；
 *  - 保留期外 / 数据范围受限 / 样本不足三种空态各自的可读解释；
 *  - 失败时保留上次结果并标注旧数据，绝不画成干净画像；
 *  - 审计读取 401 时弹二次验证并重放，重置后结果区清空。
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { mountComponent, flush, click, waitFor } from '../helpers/componentHarness'

const getProfile = vi.fn()
const createTicket = vi.fn()

vi.mock('@/utils/api', () => ({
  api: {
    security: {
      getStuffingProfile: (...args) => getProfile(...args),
      createReauthTicket: (...args) => createTicket(...args),
    },
  },
  isCanceledError: (e) => Boolean(e && e.code === 'ERR_CANCELED'),
}))
vi.mock('@/utils/loginCipher', () => ({
  encryptPassword: (value) => Promise.resolve('ENC:' + value),
}))
vi.mock('element-plus/es/components/message/index.mjs', () => ({
  ElMessage: { success: vi.fn(), error: vi.fn(), warning: vi.fn() },
}))

import StuffingProfileView from '@/views/StuffingProfileView.vue'

let active = null

beforeEach(() => {
  vi.clearAllMocks()
})

afterEach(() => {
  if (active) {
    active.handle.unmount()
    active = null
  }
})

// 本地业务日：期望值独立计算，不调用被测组件的 localDateStr
const todayLocal = () => {
  const d = new Date()
  const p = (n) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`
}

const entry = (over = {}) => ({
  sourceKey: '203.0.113.0/24',
  credentialStemHits: 12,
  lengthBucket: '8-11',
  charsetClass: 'ld',
  attempts: 42,
  successes: 1,
  accountCardinality: 17,
  businessDay: '2026-11-01',
  windowStart: '2026-11-01T00:00:00.000Z',
  windowEnd: '2026-11-02T00:00:00.000Z',
  ...over,
})

const meta = (over = {}) => ({
  businessDay: '2026-11-01',
  windowStart: '2026-11-01T00:00:00.000Z',
  windowEnd: '2026-11-02T00:00:00.000Z',
  expired: false,
  droppedUnparsable: 0,
  droppedBelowMin: 0,
  minSamples: 30,
  count: 1,
  dataScopeType: 'all',
  ...over,
})

const okBody = (entries = [entry()], metaOver = {}) => ({
  data: { success: true, message: 'ok', data: entries, meta: meta(metaOver) },
})

const mountView = () => {
  active = mountComponent(StuffingProfileView)
  return active
}

const buttonByText = (root, text) =>
  Array.from(root.querySelectorAll('button')).find((el) => el.textContent.trim() === text)

const runQuery = async (c) => {
  click(buttonByText(c.root, '生成画像'))
  await waitFor(() => getProfile.mock.calls.length >= 1, { message: '画像请求发出' })
}

const table = (c) => c.find('[data-test="stuffing-table"]')

// el-table 先挂根节点、下一轮才铺行：只等根节点出现会读到空 textContent
const waitTableText = async (c, text) => {
  await waitFor(() => table(c)?.textContent.includes(text), {
    message: '画像表格渲染：' + text,
  })
  return table(c)
}

describe('StuffingProfileView 查询主路径', () => {
  test('默认业务日＝本地今天：按该日查询并渲染来源段/尝试/成功/账号/字典命中', async () => {
    getProfile.mockResolvedValue(okBody())
    const c = mountView()
    await runQuery(c)

    expect(getProfile).toHaveBeenCalledWith({ businessDay: todayLocal() })
    const text = (await waitTableText(c, '203.0.113.0/24')).textContent

    expect(text).toContain('203.0.113.0/24')
    expect(text).toContain('42')
    expect(text).toContain('1')
    expect(text).toContain('17')
    expect(text).toContain('12')
    expect(text).toContain('8-11 位')
    expect(text).toContain('小写+数字')
    expect(c.text()).toContain('1 个来源段')
    expect(c.errors).toEqual([])
  })

  test('枚举值漂移：长度档与字符集回落后端原值，不编造文案', async () => {
    getProfile.mockResolvedValue(okBody([entry({ lengthBucket: '99', charsetClass: 'x' })]))
    const c = mountView()
    await runQuery(c)
    const text = (await waitTableText(c, '99')).textContent

    expect(text).toContain('99')
    expect(text).toContain('x')
  })
})

describe('StuffingProfileView 空态解释', () => {
  test('保留期外：明确说明已无审计证据，空表不代表没有攻击', async () => {
    getProfile.mockResolvedValue(okBody([], { expired: true, count: 0 }))
    const c = mountView()
    await runQuery(c)
    await waitFor(() => c.find('.meta-alert'), { message: '保留期空态渲染' })

    expect(c.text()).toContain('已超出审计保留期')
    expect(table(c)).toBeNull()
    // 与「样本不足」空态互斥：不能同时给出两种原因
    expect(c.text()).not.toContain('没有达到门槛')
  })

  test('数据范围受限：说明蜜罐行无归属，该范围画像恒为空', async () => {
    getProfile.mockResolvedValue(okBody([], { dataScopeType: 'self', count: 0 }))
    const c = mountView()
    await runQuery(c)
    await waitFor(() => c.find('.meta-alert'), { message: '范围空态渲染' })

    expect(c.text()).toContain('当前数据范围为「本人」')
    expect(c.text()).toContain('该范围下的画像恒为空')
    expect(table(c)).toBeNull()
  })

  test('全局范围且窗口内无样本：给出「不等于没有攻击」的解释', async () => {
    getProfile.mockResolvedValue(okBody([], { count: 0 }))
    const c = mountView()
    await runQuery(c)
    await waitFor(() => c.find('.meta-alert'), { message: '样本空态渲染' })

    expect(c.text()).toContain('没有达到门槛')
    expect(c.text()).toContain('这不等于「没有攻击」')
    expect(table(c)).toBeNull()
  })

  test('有丢弃样本：如实报告丢弃数量与门槛', async () => {
    getProfile.mockResolvedValue(okBody([entry()], { droppedBelowMin: 5, droppedUnparsable: 2 }))
    const c = mountView()
    await runQuery(c)
    await waitTableText(c, '203.0.113.0/24')

    expect(c.text()).toContain('5 个来源段因样本不足被丢弃（门槛 30 次）')
    expect(c.text()).toContain('2 条记录的来源地址无法解析')
  })
})

describe('StuffingProfileView 失败与重放', () => {
  test('首次失败：显示加载失败，不伪装成「没有攻击」', async () => {
    getProfile.mockRejectedValue({
      response: { data: { errors: { errorCode: 'AUDIT_QUERY_FAILED' } } },
    })
    const c = mountView()
    await runQuery(c)
    await waitFor(() => c.find('.load-alert'), { message: '失败提示出现' })

    expect(c.find('.load-alert').textContent).toContain('画像加载失败')
    expect(table(c)).toBeNull()
    expect(c.text()).not.toContain('没有达到门槛')
  })

  test('刷新失败但已有结果：保留上次结果并标注为旧数据', async () => {
    getProfile.mockResolvedValueOnce(okBody()).mockRejectedValueOnce({
      response: { data: { errors: { errorCode: 'AUDIT_QUERY_FAILED' } } },
    })
    const c = mountView()
    await runQuery(c)
    await waitTableText(c, '203.0.113.0/24')

    click(buttonByText(c.root, '生成画像'))
    await waitFor(() => getProfile.mock.calls.length === 2, { message: '第二次请求发出' })
    await waitFor(() => c.find('.load-alert')?.textContent.includes('上次结果'), {
      message: '旧数据提示出现',
    })
    expect(table(c).textContent).toContain('203.0.113.0/24')
  })

  test('401 REAUTH_TICKET_REQUIRED：验过后重放同一查询', async () => {
    createTicket.mockResolvedValue({ data: { data: { ticket: 't1', expiresIn: 300 } } })
    let attempts = 0
    getProfile.mockImplementation(() => {
      attempts += 1
      if (attempts === 1) {
        return Promise.reject({
          response: { data: { errors: { errorCode: 'REAUTH_TICKET_REQUIRED' } } },
        })
      }
      return Promise.resolve(okBody())
    })
    const c = mountView()
    await runQuery(c)
    await waitFor(() => document.body.querySelector('.el-dialog'), { message: '二次验证弹层打开' })

    const dialog = document.body.querySelector('.el-dialog')
    const input = dialog.querySelector('input')
    input.value = 'secret'
    input.dispatchEvent(new window.Event('input', { bubbles: true }))
    await flush(2)
    click(buttonByText(dialog, '确定'))

    await waitFor(() => getProfile.mock.calls.length === 2, { message: '验证后重放查询' })
    expect(createTicket).toHaveBeenCalledWith({ encCurrentPassword: 'ENC:secret' })
    await waitTableText(c, '203.0.113.0/24')
  })

  test('重置：清空结果区并回到今天的业务日', async () => {
    getProfile.mockResolvedValue(okBody())
    const c = mountView()
    await runQuery(c)
    await waitTableText(c, '203.0.113.0/24')

    click(buttonByText(c.root, '重置'))
    await flush(3)
    expect(table(c)).toBeNull()
    expect(c.find('.load-alert')).toBeNull()

    await runQuery(c)
    expect(getProfile).toHaveBeenLastCalledWith({ businessDay: todayLocal() })
  })
})
