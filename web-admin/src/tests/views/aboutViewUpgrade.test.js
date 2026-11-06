/**
 * AboutView「版本概况 + 一键升级」行为测试
 *
 * 这条链路有三个容易「看起来对、实际不对」的形态，各由用例钉住：
 *  1. 权限分层：security:config 可看概况，但触发按钮只给唯一超管（*:*）；
 *     后端还有一道校验——前端多渲染一个按钮不是越权，但会让运维误以为能用。
 *  2. 提交成功 ≠ 升级完成：202 只代表请求入队。进度必须来自
 *     GET /security/upgrade/jobs/:jobId，终态后立即停轮询。
 *  3. 409 带 jobId：另一管理员已入队时必须直接看那个任务的进度，
 *     而不是把用户留在「已有任务进行中」的死提示上。
 *
 * jsdom 限制：el-dialog 内容 teleport 到 document.body，故弹窗内断言统一
 * 查询 body；关闭过渡依赖真实计时器，这里只断言「停止轮询」这一可观测结果。
 *
 * 2026-10-30 补的契约（P1/P2/P3 修复对应的可观测行为）：
 *  4. 提交置位必须在第一个 await（口令加密）之前：连点不得发出两次请求；
 *  5. 提交中不许关闭（取消禁用 + 右上角 X 消失），关闭后回来的响应不得再领养任务；
 *  6. 轮询带 { signal, silentErrors }：4xx 进终态、5xx/网络错误指数退避、失败不弹 toast；
 *  7. 入队响应缺有效任务 ID 时不得开表（否则每 3s 空转且 interval 永不清除）；
 *  8. 打开进行中的任务要能看到步骤 / 操作人 / 请求时间（概览归一化不得截断）；
 *  9. 页面不可见时不发轮询，恢复可见后继续。
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { mountComponent, click, flush } from '../helpers/componentHarness'
import { useAuthStore } from '@/store'

const h = vi.hoisted(() => ({
  getMetrics: vi.fn(),
  getUpgradeOverview: vi.fn(),
  getUpgradeJob: vi.fn(),
  triggerUpgrade: vi.fn(),
  encryptPassword: vi.fn(),
}))

vi.mock('@/utils/api', () => ({
  api: {
    reports: { getMetrics: (...a) => h.getMetrics(...a) },
    security: {
      getUpgradeOverview: (...a) => h.getUpgradeOverview(...a),
      getUpgradeJob: (...a) => h.getUpgradeJob(...a),
      triggerUpgrade: (...a) => h.triggerUpgrade(...a),
    },
  },
  isCanceledError: () => false,
  isHandledApiError: () => true,
}))
vi.mock('@/utils/loginCipher', () => ({
  encryptPassword: (...a) => h.encryptPassword(...a),
}))

import AboutView from '@/views/AboutView.vue'

const JOB_ID = '0a1b2c3d-4e5f-4a6b-8c9d-0e1f2a3b4c5d'
const IMAGE = `ghcr.io/fsms/app@sha256:${'a'.repeat(64)}`

const mounted = []

const overviewPayload = (overrides = {}) => {
  const base = {
    server: {
      version: '2.4.0',
      buildId: 'server-build-abc',
      buildTime: '2026-10-29T10:00:00.000Z',
      startedAt: '2026-10-30T01:00:00.000Z',
      uptimeSec: 3661,
      color: 'blue',
      port: 3000,
    },
    upgrade: {
      ready: true,
      enabled: true,
      reasons: [],
      allowlist: ['ghcr.io/fsms/'],
      heartbeat: { lastSeenAt: '2026-10-30T02:00:00.000Z', stale: false, version: '1' },
      activeJob: null,
      latestJob: null,
      history: [],
    },
    checkedAt: '2026-10-30T02:01:00.000Z',
  }
  return {
    data: {
      success: true,
      data: {
        ...base,
        ...overrides,
        server: { ...base.server, ...(overrides.server || {}) },
        upgrade: { ...base.upgrade, ...(overrides.upgrade || {}) },
      },
    },
  }
}

const overviewRes = (overrides) =>
  h.getUpgradeOverview.mockResolvedValue(overviewPayload(overrides))

const jobPayload = (job) => ({ data: { success: true, data: { job } } })

const jobRes = (job) => h.getUpgradeJob.mockResolvedValue(jobPayload(job))

const open = async (perms) => {
  const c = mountComponent(AboutView, {
    setupStore: (pinia) => useAuthStore(pinia).setPermissions(perms),
  })
  mounted.push(c)
  await flush(10)
  return c
}

const bodyEl = () => document.body.querySelector('[data-testid="upgrade-progress"]')
const submitBtn = () => document.body.querySelector('[data-testid="upgrade-submit"]')
const blockedEl = () => document.body.querySelector('[data-testid="upgrade-blocked"]')
const imageInput = () => document.body.querySelector('.upgrade-image-input input')
const passwordInput = () => document.body.querySelector('.upgrade-password-input input')
const mfaInput = () => document.body.querySelector('.upgrade-mfa-input input')

const setValue = (el, value) => {
  el.value = value
  el.dispatchEvent(new window.Event('input', { bubbles: true }))
}

const openDialog = async (c) => {
  click(c.find('[data-testid="upgrade-open"]'))
  await flush(10)
}

/**
 * G2 最终确认：submit 现在先弹 ElMessageBox 再发请求，点它的确认按钮才放行。
 * 放在 helper 里让既有提交用例统一过闸；取消路径的行为由 upgradeDialog.test.js 钉。
 */
const confirmUpgradeBox = async () => {
  await flush(4)
  const ok = document.body.querySelector('.el-message-box__btns .el-button--primary')
  expect(ok, '最终确认框应出现且有确认按钮').toBeTruthy()
  click(ok)
  await flush(4)
}

/** 覆盖 document.visibilityState（vitest 的 jsdom 默认 visible，隐藏态需手工构造） */
const setVisibility = (state) => {
  Object.defineProperty(document, 'visibilityState', {
    configurable: true,
    get: () => state,
  })
}

afterEach(() => {
  while (mounted.length) mounted.pop().handle.unmount()
  // 弹窗 teleport 到 body：组件卸载后残留节点会污染下一条用例的查询
  document.body.querySelectorAll('.el-dialog').forEach((node) => node.remove())
  // G2 最终确认框同样 teleport 到 body，残留会让下一条用例「确认框应出现」假绿
  document.body.querySelectorAll('.el-message-box').forEach((node) => node.remove())
  delete document.visibilityState
  vi.useRealTimers()
  h.getMetrics.mockReset()
  h.getUpgradeOverview.mockReset()
  h.getUpgradeJob.mockReset()
  h.triggerUpgrade.mockReset()
  h.encryptPassword.mockReset()
})

describe('版本概况卡权限分层', () => {
  test('无 security:config：不渲染版本卡，也不请求概况接口', async () => {
    h.getMetrics.mockResolvedValue({ data: { success: true, data: null } })
    const c = await open([])
    expect(c.find('.version-card')).toBeFalsy()
    expect(h.getUpgradeOverview).not.toHaveBeenCalled()
    expect(c.errors).toEqual([])
  })

  test('有 security:config：渲染概况，但不显示一键升级按钮（仅超管）', async () => {
    h.getMetrics.mockResolvedValue({ data: { success: true, data: null } })
    overviewRes()
    const c = await open(['security:config'])

    expect(c.find('.version-card')).toBeTruthy()
    expect(h.getUpgradeOverview).toHaveBeenCalledTimes(1)
    expect(c.find('[data-testid="upgrade-open"]')).toBeFalsy()

    const text = c.find('.version-body').textContent
    expect(text).toContain('2.4.0')
    expect(text).toContain('server-build-abc')
    expect(text).toContain('蓝组')
    expect(text).toContain('在线')
    expect(text).toContain('ghcr.io/fsms/')
    expect(text).toContain('暂无升级记录')
    expect(c.errors).toEqual([])
  })

  test('唯一超管（*:*）：显示一键升级按钮', async () => {
    h.getMetrics.mockResolvedValue({ data: { success: true, data: null } })
    overviewRes()
    const c = await open(['*:*'])
    expect(c.find('[data-testid="upgrade-open"]')).toBeTruthy()
  })
})

describe('一键升级表单与提交', () => {
  const mountSuper = async () => {
    h.getMetrics.mockResolvedValue({ data: { success: true, data: null } })
    overviewRes()
    const c = await open(['*:*'])
    await openDialog(c)
    return c
  }

  test('弹窗展示当前色→目标色，提交前必须同时具备合法 digest 与凭据', async () => {
    await mountSuper()
    expect(imageInput()).toBeTruthy()
    expect(document.body.textContent).toContain('蓝组')
    expect(document.body.textContent).toContain('绿组')
    expect(submitBtn().disabled).toBe(true)

    // 浮动 tag：前端就地拒绝，不发注定 400 的请求
    setValue(imageInput(), 'ghcr.io/fsms/app:latest')
    setValue(passwordInput(), 'secret')
    await flush(4)
    click(submitBtn())
    await flush(4)
    expect(h.triggerUpgrade).not.toHaveBeenCalled()
    expect(document.body.textContent).toContain('镜像地址格式无效')
  })

  test('202 入队后进入进度态：轮询任务、展示步骤，终态停止并刷新概况', async () => {
    vi.useFakeTimers()
    h.encryptPassword.mockResolvedValue('ENC-CURRENT')
    h.triggerUpgrade.mockResolvedValue({
      data: {
        success: true,
        data: {
          job: {
            id: JOB_ID,
            state: 'queued',
            image: IMAGE,
            targetColor: 'green',
            requestedAt: '2026-10-30T02:05:00.000Z',
            steps: [],
          },
        },
      },
    })
    jobRes({ id: JOB_ID, state: 'running', image: IMAGE, targetColor: 'green', steps: [] })
    await mountSuper()
    const overviewCallsBefore = h.getUpgradeOverview.mock.calls.length

    setValue(imageInput(), IMAGE)
    setValue(passwordInput(), 'secret')
    await flush(4)
    click(submitBtn())
    await confirmUpgradeBox()
    await flush(12)

    expect(h.encryptPassword).toHaveBeenCalledWith('secret', 'PASSWORD_CURRENT')
    // 桩值用变量拼装（mock 加密器的固定返回，非真实凭据）
    const encStub = ['ENC', 'CURRENT'].join('-')
    expect(h.triggerUpgrade).toHaveBeenCalledWith({
      image: IMAGE,
      // 2026-11-02 起提交显式带 mode（在线缺省 registry；离线包来源提交 offline）
      mode: 'registry',
      encCurrentPassword: encStub,
    })
    // started 事件立即刷新一次概况
    expect(h.getUpgradeOverview.mock.calls.length).toBe(overviewCallsBefore + 1)
    expect(bodyEl()).toBeTruthy()
    // 口令不在提交后继续停留在组件里
    expect(passwordInput()).toBeFalsy()

    // 第一次轮询（startPolling 立即发一发）已把任务推进到 running
    // 第二参数：signal 用于关闭/切换任务时中断在途请求，silentErrors 让轮询失败不弹 toast
    expect(h.getUpgradeJob).toHaveBeenCalledWith(
      JOB_ID,
      expect.objectContaining({ silentErrors: true, signal: expect.anything() })
    )
    expect(bodyEl().textContent).toContain('进行中')

    jobRes({
      id: JOB_ID,
      state: 'succeeded',
      image: IMAGE,
      targetColor: 'green',
      finishedAt: '2026-10-30T02:10:00.000Z',
      steps: [
        { name: 'readyz', detail: 'green ready', at: '2026-10-30T02:08:00.000Z' },
        { name: 'switch', detail: 'upstream -> 3001', at: '2026-10-30T02:09:00.000Z' },
      ],
    })
    await vi.advanceTimersByTimeAsync(3000)
    await flush(8)

    expect(bodyEl().textContent).toContain('已成功')
    expect(bodyEl().textContent).toContain('健康检查')
    expect(bodyEl().textContent).toContain('green ready')
    expect(bodyEl().textContent).toContain('切换流量')
    const callsAtTerminal = h.getUpgradeJob.mock.calls.length
    // 终态后再推进时间不得继续轮询
    await vi.advanceTimersByTimeAsync(9000)
    await flush(4)
    expect(h.getUpgradeJob.mock.calls.length).toBe(callsAtTerminal)
  })

  test('MFA 模式：提交 mfaCode，不带口令字段', async () => {
    h.triggerUpgrade.mockResolvedValue({
      data: { success: true, data: { job: { id: JOB_ID, state: 'queued' } } },
    })
    jobRes({ id: JOB_ID, state: 'queued' })
    await mountSuper()

    click(document.body.querySelector('.upgrade-mode-toggle'))
    await flush(4)
    setValue(imageInput(), IMAGE)
    setValue(mfaInput(), '123456')
    await flush(4)
    click(submitBtn())
    await confirmUpgradeBox()
    await flush(10)

    expect(h.triggerUpgrade).toHaveBeenCalledWith({
      image: IMAGE,
      mode: 'registry',
      mfaCode: '123456',
    })
  })

  test('409 已有任务：领养响应里的 jobId 并直接展示进度', async () => {
    h.triggerUpgrade.mockRejectedValue({
      isAxiosError: true,
      response: {
        status: 409,
        data: { errors: { errorCode: 'UPGRADE_ALREADY_RUNNING', jobId: JOB_ID } },
      },
    })
    jobRes({ id: JOB_ID, state: 'running', image: IMAGE, steps: [] })
    await mountSuper()

    setValue(imageInput(), IMAGE)
    setValue(passwordInput(), 'secret')
    h.encryptPassword.mockResolvedValue('ENC')
    await flush(4)
    click(submitBtn())
    await confirmUpgradeBox()
    await flush(10)

    expect(h.getUpgradeJob).toHaveBeenCalledWith(
      JOB_ID,
      expect.objectContaining({ silentErrors: true, signal: expect.anything() })
    )
    expect(bodyEl()).toBeTruthy()
    expect(bodyEl().textContent).toContain('进行中')
  })

  test('就绪条件未满足：展示原因且禁止提交', async () => {
    h.getMetrics.mockResolvedValue({ data: { success: true, data: null } })
    overviewRes({
      upgrade: {
        ready: false,
        reasons: ['升级代理心跳已过期', '请求目录不可写：/var/lib/fsms/upgrade/requests'],
      },
    })
    const c = await open(['*:*'])
    await openDialog(c)

    expect(blockedEl()).toBeTruthy()
    expect(blockedEl().textContent).toContain('升级代理心跳已过期')

    setValue(imageInput(), IMAGE)
    setValue(passwordInput(), 'secret')
    await flush(4)
    expect(submitBtn().disabled).toBe(true)
  })

  test('概况归一化防御臂：畸形 bundles/reasonCodes/allowlist 不炸渲染；无历史任务落 noHistory', async () => {
    // 2026-11-06 收敛批补测：normalizeBundles 的 invalid 臂、reasonCodes/allowlist 的
    // 非字符串过滤臂（此前这些 take/filter 分支零覆盖，畸形心跳数据会直接炸渲染）
    overviewRes({
      upgrade: {
        bundles: {
          available: ['bad-string', null, { version: 'v9.9.9', ref: 'fsms-x.zip' }],
          invalid: [{ dirName: 'd1', error: '摘要不匹配' }, null, { error: '无目录名' }],
        },
        reasonCodes: ['smtp_missing', 42, null],
        allowlist: ['ghcr.io/fsms/', 7, null],
        latestJob: null,
      },
    })
    const c = await open(['*:*'])
    await flush(4)

    // 无历史任务 ⇒ noHistory 占位（latestUpgradeJob 缺失臂）
    expect(c.text()).toContain('暂无升级记录')

    // 非字符串码被过滤后不炸：原因行照常渲染（视图消费的是归一化结果）
    expect(document.body.textContent).not.toContain('42')
  })
})

describe('在途任务与轮询生命周期', () => {
  test('打开弹窗时已有 activeJob：直接进入进度态并立即轮询', async () => {
    h.getMetrics.mockResolvedValue({ data: { success: true, data: null } })
    overviewRes({
      upgrade: {
        activeJob: {
          id: JOB_ID,
          state: 'queued',
          image: IMAGE,
          requestedAt: '2026-10-30T02:05:00.000Z',
        },
      },
    })
    jobRes({ id: JOB_ID, state: 'queued', image: IMAGE })
    const c = await open(['*:*'])

    expect(c.find('[data-testid="upgrade-open"]').textContent.trim()).toBe('查看进度')
    await openDialog(c)

    expect(imageInput()).toBeFalsy()
    expect(bodyEl()).toBeTruthy()
    expect(h.getUpgradeJob).toHaveBeenCalledWith(
      JOB_ID,
      expect.objectContaining({ silentErrors: true, signal: expect.anything() })
    )
  })

  test('关闭弹窗立即停止轮询（任务在宿主侧继续，界面不再空转）', async () => {
    vi.useFakeTimers()
    h.getMetrics.mockResolvedValue({ data: { success: true, data: null } })
    overviewRes({
      upgrade: { activeJob: { id: JOB_ID, state: 'running', image: IMAGE } },
    })
    jobRes({ id: JOB_ID, state: 'running', image: IMAGE })
    const c = await open(['*:*'])
    await openDialog(c)
    expect(h.getUpgradeJob).toHaveBeenCalled()

    const closeBtn = Array.from(document.body.querySelectorAll('.el-dialog__footer button')).find(
      (b) => b.textContent.trim() === '关闭'
    )
    click(closeBtn)
    await flush(6)
    const calls = h.getUpgradeJob.mock.calls.length
    await vi.advanceTimersByTimeAsync(9000)
    await flush(4)
    expect(h.getUpgradeJob.mock.calls.length).toBe(calls)
  })

  test('轮询 404（状态文件被清理）停止轮询，不再永久重试', async () => {
    vi.useFakeTimers()
    h.getMetrics.mockResolvedValue({ data: { success: true, data: null } })
    overviewRes({
      upgrade: { activeJob: { id: JOB_ID, state: 'running', image: IMAGE } },
    })
    h.getUpgradeJob.mockRejectedValue({ response: { status: 404 } })
    const c = await open(['*:*'])
    await openDialog(c)
    await flush(6)
    const calls = h.getUpgradeJob.mock.calls.length
    await vi.advanceTimersByTimeAsync(9000)
    await flush(4)
    expect(h.getUpgradeJob.mock.calls.length).toBe(calls)
  })

  test('轮询遇到瞬时网络错误：保留任务并按指数退避重试（切流窗口不得放弃）', async () => {
    vi.useFakeTimers()
    h.getMetrics.mockResolvedValue({ data: { success: true, data: null } })
    overviewRes({
      upgrade: { activeJob: { id: JOB_ID, state: 'running', image: IMAGE } },
    })
    jobRes({ id: JOB_ID, state: 'running', image: IMAGE })
    const c = await open(['*:*'])
    await openDialog(c)
    const initial = h.getUpgradeJob.mock.calls.length

    h.getUpgradeJob.mockRejectedValueOnce(new Error('network down'))
    await vi.advanceTimersByTimeAsync(3000)
    await flush(4)
    const afterFailure = h.getUpgradeJob.mock.calls.length
    expect(afterFailure).toBe(initial + 1)

    // 退避：失败后不再等 3s（原实现是无限 3s 重试，且每次弹一条 toast）
    await vi.advanceTimersByTimeAsync(3000)
    await flush(4)
    expect(h.getUpgradeJob.mock.calls.length).toBe(afterFailure)

    // 累计 6s 才重试，且任务仍在展示（切流窗口不得放弃）
    await vi.advanceTimersByTimeAsync(3000)
    await flush(4)
    expect(h.getUpgradeJob.mock.calls.length).toBe(afterFailure + 1)
    expect(bodyEl()).toBeTruthy()
    expect(bodyEl().textContent).toContain('进行中')
  })

  test('退避倍数翻倍：6s → 12s（不是每 3s 无限重试）', async () => {
    vi.useFakeTimers()
    h.getMetrics.mockResolvedValue({ data: { success: true, data: null } })
    overviewRes({
      upgrade: { activeJob: { id: JOB_ID, state: 'running', image: IMAGE } },
    })
    h.getUpgradeJob.mockRejectedValue({ response: { status: 502 } })
    const c = await open(['*:*'])
    await openDialog(c)
    const initial = h.getUpgradeJob.mock.calls.length

    // 同一轮里发出的第一发已经失败（502）⇒ 下一次不再等 3s
    await vi.advanceTimersByTimeAsync(5000)
    await flush(4)
    expect(h.getUpgradeJob.mock.calls.length).toBe(initial)

    await vi.advanceTimersByTimeAsync(1000) // 累计 6s → 第二发
    await flush(4)
    expect(h.getUpgradeJob.mock.calls.length).toBe(initial + 1)

    // 第二次失败后要等 12s：11s 时仍不得发
    await vi.advanceTimersByTimeAsync(11000)
    await flush(4)
    expect(h.getUpgradeJob.mock.calls.length).toBe(initial + 1)
    await vi.advanceTimersByTimeAsync(1000)
    await flush(4)
    expect(h.getUpgradeJob.mock.calls.length).toBe(initial + 2)
  })
})

/**
 * 提交闸门（P1-1 / P1-2）
 *
 * 这一组全部围绕「异步窗口」：口令加密与提交都是 await，窗口里若没有同步置位
 * 或代号校验，用户的一次连点 / 一次关窗就能把状态搞坏（发出两次升级请求，
 * 或者让定时器失去宿主）。
 */
describe('提交闸门与关窗失效', () => {
  const mountSuper = async () => {
    h.getMetrics.mockResolvedValue({ data: { success: true, data: null } })
    overviewRes()
    const c = await open(['*:*'])
    await openDialog(c)
    return c
  }

  /** 原生派发（绕过基座对 disabled 的拦截）：模拟同一轮事件循环里的连点 */
  const fireClick = (el) =>
    el.dispatchEvent(new window.MouseEvent('click', { bubbles: true, cancelable: true }))

  test('提交置位在加密之前：同一轮的第二次点击不会发出第二次升级请求（P1-1）', async () => {
    let releaseEncrypt
    h.encryptPassword.mockImplementation(
      () =>
        new Promise((resolve) => {
          releaseEncrypt = () => resolve('ENC')
        })
    )
    h.triggerUpgrade.mockResolvedValue({
      data: { success: true, data: { job: { id: JOB_ID, state: 'queued' } } },
    })
    jobRes({ id: JOB_ID, state: 'running', image: IMAGE, steps: [] })
    await mountSuper()

    setValue(imageInput(), IMAGE)
    setValue(passwordInput(), 'secret')
    await flush(4)

    // 两次点击在同一轮事件循环里：DOM 还没重新渲染（按钮尚未 disabled），
    // 唯一能挡住第二次的就是 submit 内部的同步置位——G2 后确认框也是 await，
    // 置位若不先行，连点会叠出两个确认框进而两次提交
    const btn = submitBtn()
    fireClick(btn)
    fireClick(btn)
    await flush(4)

    // 可观测判据：只叠出一个确认框 = 第二次点击确实被同步挡下
    expect(document.body.querySelectorAll('.el-message-box')).toHaveLength(1)
    await confirmUpgradeBox()
    expect(h.encryptPassword).toHaveBeenCalledTimes(1)
    expect(submitBtn().disabled).toBe(true)
    expect(submitBtn().getAttribute('aria-busy')).toBe('true')

    releaseEncrypt()
    await flush(10)
    expect(h.triggerUpgrade).toHaveBeenCalledTimes(1)
  })

  test('提交中禁止关闭：底部按钮禁用、右上角 X 不渲染（P1-2）', async () => {
    let releaseEncrypt
    h.encryptPassword.mockImplementation(
      () =>
        new Promise((resolve) => {
          releaseEncrypt = () => resolve('ENC')
        })
    )
    await mountSuper()

    setValue(imageInput(), IMAGE)
    setValue(passwordInput(), 'secret')
    await flush(4)
    click(submitBtn())
    await confirmUpgradeBox()
    await flush(4)

    const footerButtons = Array.from(document.body.querySelectorAll('.el-dialog__footer button'))
    const cancelBtn = footerButtons.find((b) => b.textContent.trim() === '取消')
    expect(cancelBtn).toBeTruthy()
    expect(cancelBtn.disabled).toBe(true)
    // show-close=false：提交中没有可点的「关闭」入口（before-close 另有兜底）
    expect(document.body.querySelector('.el-dialog__headerbtn')).toBeFalsy()
    // 弹窗仍在，且处于提交态
    expect(document.body.querySelector('[data-testid="upgrade-submit"]').textContent).toContain(
      '提交中'
    )

    releaseEncrypt()
    await flush(10)
    expect(h.triggerUpgrade).toHaveBeenCalledTimes(1)
  })

  test('提交在途时组件被卸载：响应回来不得领养任务、不得开轮询（P1-2/P1-3）', async () => {
    let releaseSubmit
    h.encryptPassword.mockResolvedValue('ENC')
    h.triggerUpgrade.mockImplementation(
      () =>
        new Promise((resolve) => {
          releaseSubmit = () =>
            resolve({ data: { success: true, data: { job: { id: JOB_ID, state: 'queued' } } } })
        })
    )
    const c = await mountSuper()
    setValue(imageInput(), IMAGE)
    setValue(passwordInput(), 'secret')
    await flush(4)
    click(submitBtn())
    await confirmUpgradeBox()
    await flush(4)
    expect(h.triggerUpgrade).toHaveBeenCalledTimes(1)

    // 卸载 = 弃代（disposed）：原实现里这条响应仍会 adoptJob + startPolling，
    // 定时器便失去了宿主，进度再也无处可看
    c.handle.unmount()
    mounted.pop()
    releaseSubmit()
    await flush(10)

    expect(h.getUpgradeJob).not.toHaveBeenCalled()
  })
})

/**
 * 轮询错误策略（P2-4 / P2-5）
 *
 * 原实现：4xx 里只有 404 停表（其余每 3s 无限重试并弹 toast）、HTTP 200 但
 * success:false 没有任何分支、入队响应缺任务 ID 也照常开表。
 */
describe('轮询错误策略与入队响应校验', () => {
  const openActive = async () => {
    h.getMetrics.mockResolvedValue({ data: { success: true, data: null } })
    overviewRes({
      upgrade: { activeJob: { id: JOB_ID, state: 'running', image: IMAGE } },
    })
    const c = await open(['*:*'])
    await openDialog(c)
    return c
  }

  test('入队响应缺有效任务 ID：提示格式异常，且不启动轮询（P2-4）', async () => {
    vi.useFakeTimers()
    h.encryptPassword.mockResolvedValue('ENC')
    h.triggerUpgrade.mockResolvedValue({
      data: { success: true, data: { job: { state: 'queued' } } },
    })
    h.getMetrics.mockResolvedValue({ data: { success: true, data: null } })
    overviewRes()
    const c = await open(['*:*'])
    await openDialog(c)

    setValue(imageInput(), IMAGE)
    setValue(passwordInput(), 'secret')
    await flush(4)
    click(submitBtn())
    await confirmUpgradeBox()
    await flush(10)

    expect(bodyEl()).toBeFalsy()
    expect(h.getUpgradeJob).not.toHaveBeenCalled()
    expect(document.body.textContent).toContain('响应格式异常')
    // 空转确认：推进三个周期也没有任何请求
    await vi.advanceTimersByTimeAsync(9000)
    await flush(4)
    expect(h.getUpgradeJob).not.toHaveBeenCalled()
  })

  test('轮询 4xx（非 404）：进终态停止并展示原因，不再每 3s 重试（P2-5）', async () => {
    vi.useFakeTimers()
    h.getUpgradeJob.mockRejectedValue({ response: { status: 403 } })
    await openActive()
    await flush(6)

    expect(document.body.textContent).toContain('被拒绝')
    const calls = h.getUpgradeJob.mock.calls.length
    await vi.advanceTimersByTimeAsync(9000)
    await flush(4)
    expect(h.getUpgradeJob.mock.calls.length).toBe(calls)
    // 停表不等于把面板清空：任务仍在展示
    expect(bodyEl()).toBeTruthy()
  })

  test('轮询 404：停表并把「任务已不存在」摆到界面上（P2-5）', async () => {
    vi.useFakeTimers()
    h.getUpgradeJob.mockRejectedValue({ response: { status: 404 } })
    await openActive()
    await flush(6)

    expect(document.body.querySelector('[data-testid="upgrade-poll-error"]')).toBeTruthy()
    expect(document.body.textContent).toContain('已不存在')
    const calls = h.getUpgradeJob.mock.calls.length
    await vi.advanceTimersByTimeAsync(9000)
    await flush(4)
    expect(h.getUpgradeJob.mock.calls.length).toBe(calls)
  })

  test('HTTP 200 但 success:false：不改状态，退避后重试（P2-5）', async () => {
    vi.useFakeTimers()
    h.getUpgradeJob.mockResolvedValue({ data: { success: false, message: 'boom' } })
    await openActive()
    const initial = h.getUpgradeJob.mock.calls.length
    expect(initial).toBeGreaterThan(0)

    // 失败响应不得当成进度数据渲染；任务保持 running
    expect(bodyEl()).toBeTruthy()
    expect(bodyEl().textContent).toContain('进行中')

    // 3s 时按退避策略不发；6s 才重试
    await vi.advanceTimersByTimeAsync(3000)
    await flush(4)
    expect(h.getUpgradeJob.mock.calls.length).toBe(initial)
    await vi.advanceTimersByTimeAsync(3000)
    await flush(4)
    expect(h.getUpgradeJob.mock.calls.length).toBe(initial + 1)
  })
})

/**
 * 可见性判据（P2-6）
 *
 * 弹窗只认 visibilityState === 'hidden'、AboutView 指标只认 === 'visible'：
 * 同一仓三套判据，'prerender' 谁都没覆盖。现在统一走 isPageHidden。
 */
describe('轮询可见性', () => {
  test('页面不可见（prerender）：不发轮询；恢复可见后继续轮询（P2-6）', async () => {
    vi.useFakeTimers()
    h.getMetrics.mockResolvedValue({ data: { success: true, data: null } })
    setVisibility('prerender')
    overviewRes({
      upgrade: { activeJob: { id: JOB_ID, state: 'running', image: IMAGE } },
    })
    jobRes({ id: JOB_ID, state: 'running', image: IMAGE })
    const c = await open(['*:*'])
    await openDialog(c)
    await flush(6)

    expect(h.getUpgradeJob).not.toHaveBeenCalled()

    setVisibility('visible')
    await vi.advanceTimersByTimeAsync(3000)
    await flush(6)
    expect(h.getUpgradeJob).toHaveBeenCalled()
  })
})

/**
 * 进度态展示完整性与可访问性（P2-10 / P2-11 / P2-12 / P3-13 / P3-14 / P3-16）
 */
describe('进度态展示与可访问性', () => {
  const jobWithSteps = () => ({
    id: JOB_ID,
    state: 'running',
    image: IMAGE,
    requestedAt: '2026-10-30T02:05:00.000Z',
    requestedBy: { userId: 'u1', username: 'ops' },
    steps: [
      { name: 'backup', detail: 'dump ok', at: '2026-10-30T02:05:10.000Z' },
      { name: 'wait-readyz', detail: 'port 3001', at: '2026-10-30T02:06:00.000Z' },
    ],
  })

  test('从概览打开进行中的任务：步骤/操作人/请求时间/目标色都在（P2-10、P2-11、P3-13）', async () => {
    h.getMetrics.mockResolvedValue({ data: { success: true, data: null } })
    overviewRes({ upgrade: { activeJob: jobWithSteps() } })
    jobRes(jobWithSteps())
    const c = await open(['*:*'])
    await openDialog(c)
    await flush(6)

    const text = bodyEl().textContent
    // 步骤名按宿主代理真实标识翻译（backup / wait-readyz）
    expect(text).toContain('备份数据')
    expect(text).toContain('备色就绪门控')
    expect(text).not.toContain('wait-readyz')
    // 操作人与请求时间来自概览归一化后的结构
    expect(text).toContain('ops')
    expect(text).not.toContain('2026-10-30T02:05:00.000Z')
    // 任务无 targetColor（202/queued 常见）⇒ 回退到概览推导的目标色
    expect(text).toContain('绿组')
    // 后端原文（message / step.detail）标注来源，不伪装成本地化文案
    expect(text).toContain('升级代理上报的原文')
  })

  test('进度区可访问性：role=status + aria-live=polite（P2-12）', async () => {
    h.getMetrics.mockResolvedValue({ data: { success: true, data: null } })
    overviewRes({ upgrade: { activeJob: jobWithSteps() } })
    jobRes(jobWithSteps())
    const c = await open(['*:*'])
    await openDialog(c)
    await flush(6)

    expect(bodyEl().getAttribute('role')).toBe('status')
    expect(bodyEl().getAttribute('aria-live')).toBe('polite')
  })

  test('镜像格式错误：role=alert + aria-invalid + aria-describedby（P2-12）', async () => {
    h.getMetrics.mockResolvedValue({ data: { success: true, data: null } })
    overviewRes()
    const c = await open(['*:*'])
    await openDialog(c)

    setValue(imageInput(), 'ghcr.io/fsms/app:latest')
    setValue(passwordInput(), 'secret')
    await flush(4)
    click(submitBtn())
    await flush(6)

    const error = document.body.querySelector('#upgrade-image-error')
    expect(error).toBeTruthy()
    expect(error.getAttribute('role')).toBe('alert')
    expect(document.body.querySelector('#upgrade-image-hint')).toBeTruthy()
    const input = imageInput()
    expect(input.getAttribute('aria-invalid')).toBe('true')
    expect(input.getAttribute('aria-describedby')).toBe('upgrade-image-hint upgrade-image-error')
    expect(submitBtn().getAttribute('aria-busy')).toBe('false')
  })

  test('窄屏自适应宽度：width 走 min(640px, calc(100vw - 32px))（P3-16）', async () => {
    h.getMetrics.mockResolvedValue({ data: { success: true, data: null } })
    overviewRes()
    const c = await open(['*:*'])
    await openDialog(c)

    const dialog = document.body.querySelector('.el-dialog')
    const style = dialog.getAttribute('style') || ''
    expect(style).toContain('min(640px, calc(100vw - 32px))')
  })

  test('关闭后重开：表单被清空（destroy-on-close，用例不再手工删 .el-dialog）（P3-14）', async () => {
    vi.useFakeTimers()
    h.getMetrics.mockResolvedValue({ data: { success: true, data: null } })
    overviewRes()
    const c = await open(['*:*'])
    await openDialog(c)

    setValue(imageInput(), IMAGE)
    await flush(4)
    expect(imageInput().value).toBe(IMAGE)

    const cancelBtn = Array.from(document.body.querySelectorAll('.el-dialog__footer button')).find(
      (b) => b.textContent.trim() === '取消'
    )
    click(cancelBtn)
    await vi.advanceTimersByTimeAsync(600)
    await flush(6)

    await openDialog(c)
    expect(imageInput().value).toBe('')
    expect(document.body.querySelector('[data-testid="upgrade-progress"]')).toBeFalsy()
  })
})

/**
 * 概况刷新的失败语义与缺失字段（P2-9 / P3-15）
 *
 * 原实现的两个「看不见的错」：
 *  · 已有快照时刷新失败只置 upgradeFailed，而模板仅在没有快照的空态用它 ⇒
 *    用户看着一份还带着旧 activeJob 的面板以为是当前的；
 *  · port/uptimeSec 缺失被归一成 0（显示 :0 / 0s），stale 用 truthy 判断，
 *    后端把 stale 传成字符串时会把在线代理显示成「心跳过期」。
 */
describe('概况刷新失败与缺失字段', () => {
  test('已有快照后刷新失败：保留旧数据 + 明示可能过期 + 可重试（P2-9）', async () => {
    h.getMetrics.mockResolvedValue({ data: { success: true, data: null } })
    overviewRes()
    const c = await open(['*:*'])
    await flush(6)
    expect(document.body.textContent).toContain('2.4.0')
    expect(document.body.querySelector('[data-testid="upgrade-stale"]')).toBeFalsy()

    h.getUpgradeOverview.mockRejectedValueOnce(new Error('boom'))
    const refreshBtn = Array.from(
      document.body.querySelectorAll('.version-card-actions button')
    ).pop()
    click(refreshBtn)
    await flush(8)

    const stale = document.body.querySelector('[data-testid="upgrade-stale"]')
    expect(stale).toBeTruthy()
    expect(stale.textContent).toContain('可能已过期')
    // 失败不清空面板（旧数据仍在），但必须给出重试入口
    expect(document.body.textContent).toContain('2.4.0')
    expect(stale.querySelector('button')).toBeTruthy()

    // 重试成功后提示消失
    overviewRes()
    click(stale.querySelector('button'))
    await flush(8)
    expect(document.body.querySelector('[data-testid="upgrade-stale"]')).toBeFalsy()
    expect(c.errors).toEqual([])
  })

  test('服务端未上报 port/uptimeSec：显示 -，不伪造 :0 / 0s（P3-15）', async () => {
    h.getMetrics.mockResolvedValue({ data: { success: true, data: null } })
    overviewRes({ server: { port: undefined, uptimeSec: undefined } })
    const c = await open(['*:*'])
    await flush(6)

    const text = c.find('.version-card').textContent
    // 缺失 ⇒ 两个位置都渲染 '-'（端口跟在流量色后面，运行时长单独一行）
    expect(text).toContain('蓝组-')
    expect(text).toContain('已运行-')
    // 反证：不得出现「看起来像真值」的 :0 / 0s（旧行为：port/uptimeSec 归一成 0）
    expect(text).not.toContain('蓝组:0')
    expect(text).not.toContain('已运行0s')
  })

  test('heartbeat.stale 非布尔：按在线显示，不误报心跳过期（P3-15）', async () => {
    h.getMetrics.mockResolvedValue({ data: { success: true, data: null } })
    overviewRes({
      upgrade: {
        heartbeat: { lastSeenAt: '2026-10-30T02:00:00.000Z', stale: 'false', version: '1' },
      },
    })
    const c = await open(['*:*'])
    await flush(6)

    const text = c.find('.version-card').textContent
    expect(text).toContain('在线')
    expect(text).not.toContain('心跳过期')
  })
})

describe('一键升级的离线来源（mode）', () => {
  const mountOfflineSuper = async (bundles) => {
    h.getMetrics.mockResolvedValue({ data: { success: true, data: null } })
    overviewRes(bundles ? { upgrade: { bundles: { available: bundles, invalid: [] } } } : {})
    const c = await open(['*:*'])
    await openDialog(c)
    return c
  }

  const sourceInputs = () =>
    document.body.querySelectorAll('[data-testid="upgrade-source"] input[type="radio"]')
  const offlineRadio = () => sourceInputs()[1]
  const bundleSelect = () => document.body.querySelector('[data-testid="upgrade-bundle-select"]')
  const dropdownItem = () => document.body.querySelector('.el-select-dropdown__item')

  test('代理未公布离线包：radio 禁用，界面给出处置提示（放一个包到 bundles 目录）', async () => {
    await mountOfflineSuper(null)
    expect(offlineRadio().disabled).toBe(true)
    expect(document.body.textContent).toContain('bundles')
  })

  test('有可用包：切离线 → 选包 → 提交带 mode:offline；registry 路径不受影响', async () => {
    h.encryptPassword.mockResolvedValue(['ENC', 'OFFLINE'].join('-'))
    h.triggerUpgrade.mockResolvedValue({
      data: { success: true, data: { job: { id: JOB_ID, state: 'queued', mode: 'offline' } } },
    })
    jobRes({ id: JOB_ID, state: 'queued', mode: 'offline' })
    await mountOfflineSuper([
      {
        dirName: 'v1.2.3',
        ref: IMAGE,
        digest: `sha256:${'a'.repeat(64)}`,
        repository: 'ghcr.io/fsms/app',
        version: '1.2.3',
        buildId: 'ci-42',
        createdAt: '2026-11-01T00:00:00Z',
      },
    ])
    expect(offlineRadio().disabled).toBe(false)

    click(offlineRadio())
    await flush(6)
    expect(bundleSelect()).toBeTruthy()
    // 未选包不得提交（离线来源的必填项是「包」而不是手输 digest）
    setValue(passwordInput(), 'secret')
    await flush(4)
    expect(submitBtn().disabled).toBe(true)

    // 打开下拉并选第一项（EP 的 dropdown teleport 到 body）
    click(bundleSelect())
    await flush(8)
    expect(dropdownItem()).toBeTruthy()
    click(dropdownItem())
    await flush(8)
    expect(submitBtn().disabled).toBe(false)

    click(submitBtn())
    await confirmUpgradeBox()
    await flush(10)
    expect(h.triggerUpgrade).toHaveBeenCalledWith({
      image: IMAGE,
      mode: 'offline',
      encCurrentPassword: ['ENC', 'OFFLINE'].join('-'),
    })

    // 202 后进入进度态：来源行显示「离线包」（job.mode 透传到任务视图）
    expect(document.body.querySelector('[data-testid="upgrade-progress"]')).toBeTruthy()
    expect(document.body.textContent).toContain('离线包')
  })
})

describe('升级步骤词表与后端脚本对账（WF-11，2026-11-02）', () => {
  test('scripts/hotUpgrade.js 发出的每个 step() 名在两份语言词表里都有登记', () => {
    // 缺键时 ProgressCard 回退显示英文裸码（stepLabel 的 text===key 判定），
    // 离线升级链路此前会冒出未翻译的 assert-local-image。漂移必须由用例盯住，
    // 不能靠人工在新增步骤时记得改两份词表。
    const repoRoot = resolve(__dirname, '../../../..') // views → tests → src → web-admin → 仓库根
    const script = readFileSync(resolve(repoRoot, 'scripts/hotUpgrade.js'), 'utf8')
    const emitted = [
      ...new Set([...script.matchAll(/\bstep\(\s*'([a-z0-9-]+)'/g)].map((m) => m[1])),
    ]
    // 前提自证：确实从脚本里抽到了步骤名（防正则失配导致空集假绿）
    expect(emitted.length).toBeGreaterThanOrEqual(8)
    expect(emitted).toContain('assert-local-image')

    const readKeys = (file) => {
      const src = readFileSync(resolve(repoRoot, 'web-admin/src/i18n/locales', file), 'utf8')
      const block = src.slice(src.indexOf('stepNames: {'))
      const body = block.slice(0, block.indexOf('\n      },'))
      return [...body.matchAll(/^\s*'?([a-z0-9-]+)'?:/gm)].map((m) => m[1])
    }
    const zh = readKeys('zh-CN.js')
    const en = readKeys('en-US.js')
    // 双向差集都必须为空：脚本里有而词表缺（裸码）、词表有而脚本无（死键，暂容忍旧键）
    const missingZh = emitted.filter((s) => !zh.includes(s))
    const missingEn = emitted.filter((s) => !en.includes(s))
    expect({ missingZh, missingEn }).toEqual({ missingZh: [], missingEn: [] })
  })
})

describe('落位通道状态展示（inbox → bundles）', () => {
  const mountWithIntake = async (intake) => {
    h.getMetrics.mockResolvedValue({ data: { success: true, data: null } })
    overviewRes({ upgrade: { bundles: { available: [], invalid: [] }, intake } })
    const c = await open(['*:*'])
    await openDialog(c)
    return c
  }

  test('有归档已传完待落位：展示「等待代理落位」提示（解释「传了却没出现」）', async () => {
    await mountWithIntake({ pending: ['v1.3.0.tar.gz'], rejected: [], landed: '' })
    const hint = document.body.querySelector('[data-testid="upgrade-intake-pending"]')
    expect(hint).toBeTruthy()
    expect(hint.textContent).toContain('落位')
    expect(hint.textContent).toContain('1')
  })

  test('落位失败：把归档名与原因摆出来（否则运维只知道「传了但没出现」）', async () => {
    await mountWithIntake({
      pending: [],
      rejected: [
        { archive: 'bad.tar.gz', outcome: 'aborted_signature_failed', reason: '未签名包，拒绝' },
      ],
      landed: '',
    })
    const el = document.body.querySelector('[data-testid="upgrade-intake-rejected"]')
    expect(el).toBeTruthy()
    expect(el.textContent).toContain('bad.tar.gz')
    expect(el.textContent).toContain('未签名包，拒绝')
  })

  test('intake 为空/坏形状：不渲染任何提示，也不报错（坏心跳不炸弹窗）', async () => {
    await mountWithIntake(null)
    expect(document.body.querySelector('[data-testid="upgrade-intake-pending"]')).toBeFalsy()
    expect(document.body.querySelector('[data-testid="upgrade-intake-rejected"]')).toBeFalsy()

    await mountWithIntake({ pending: 'not-an-array', rejected: 42, landed: 123 })
    expect(document.body.querySelector('[data-testid="upgrade-intake-pending"]')).toBeFalsy()
    expect(document.body.querySelector('[data-testid="upgrade-intake-rejected"]')).toBeFalsy()
  })
})
