/**
 * P2-56：审计日志导出必须识别 JSON 错误响应（不得落盘损坏的 xlsx）
 *
 * 缺陷：/reports/export 成功时返回 xlsx，失败时返回 JSON 包络，而调用方用
 * responseType:'blob'。axios 会把 JSON 错误体也包成 Blob，原实现无条件
 * createObjectURL + link.click() + ElMessage.success——用户拿到一个内容
 * 是 JSON 的「.xlsx」，界面还报「导出成功」。
 *
 * 本套件执行 AuditLogView.vue 里**真实发布的** exportLogs / extractBlobErrorMessage
 * 源码（本仓无 @vue/test-utils，视图无法挂载，故按场景注入依赖后直接调用），
 * 断言可观测行为：
 *   - JSON 错误体：不触发下载（createObjectURL 不被调用）、不报成功、走错误提示
 *   - 正常 xlsx：正常下载并提示成功
 * 把 exportLogs 里的 JSON 检测分支删掉，前两条即变红。
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { resolveErrorMessage } from '@/utils/api'

const SRC = resolve(__dirname, '../..')

/** 从 SFC 源码中切出指定顶层 const 函数（含花括号配平） */
const extractFn = (source, name) => {
  const start = source.indexOf('const ' + name + ' = ')
  if (start === -1) throw new Error('not found: ' + name)
  const open = source.indexOf('{', source.indexOf('=', start))
  let depth = 0
  for (let i = open; i < source.length; i += 1) {
    if (source[i] === '{') depth += 1
    else if (source[i] === '}') {
      depth -= 1
      if (depth === 0) return source.slice(start, i + 1)
    }
  }
  throw new Error('unbalanced: ' + name)
}

const sfc = readFileSync(resolve(SRC, 'views/AuditLogView.vue'), 'utf8')

/**
 * 取出 SFC 里真实发布的 exportLogs 并注入外部依赖后调用。
 *
 * 为何不直接 import 组件：本仓无 @vue/test-utils（无法挂载视图），而直接
 * import SFC 会经 Node 原生 ESM 解析 element-plus 的 .css，报
 * Unknown file extension ".css"（本轮实测）。因此改为从源码取出函数体、
 * 以参数注入依赖执行——被断言的仍是运行时行为，而非文本匹配。
 */
const makeExportLogs = (deps) =>
  // eslint-disable-next-line no-new-func -- 见上方说明：无挂载器，只能以此 driver 执行真实函数体
  new Function(
    ...Object.keys(deps),
    extractFn(sfc, 'extractBlobErrorMessage') +
      '\n' +
      extractFn(sfc, 'exportLogs') +
      '\nreturn exportLogs'
  )(...Object.values(deps))

const XLSX_TYPE = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'

const setupHarness = ({ response, thrown }) => {
  const ElMessage = { error: vi.fn(), success: vi.fn(), warning: vi.fn() }
  const createObjectURL = vi.fn(() => 'blob:probe')
  const revokeObjectURL = vi.fn()
  const click = vi.fn()
  const apiClient = {
    get: vi.fn(() => (thrown ? Promise.reject(thrown) : Promise.resolve(response))),
  }
  const exportLogs = makeExportLogs({
    apiClient,
    isCanceledError: (e) => e?.code === 'ERR_CANCELED',
    resolveErrorMessage,
    ElMessage,
    t: (k) => k,
    localDateStr: () => '2026-09-17',
    buildFilterParams: () => ({}),
    exporting: { value: false },
    window: { URL: { createObjectURL, revokeObjectURL } },
    document: { createElement: () => ({ href: '', download: '', click }) },
  })
  return { exportLogs, ElMessage, createObjectURL, revokeObjectURL, click, apiClient }
}

const jsonErrorBlob = (body) => new Blob([JSON.stringify(body)], { type: 'application/json' })

describe('P2-56 AuditLogView 导出：JSON 错误体不得当成 xlsx 落盘', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
  })

  test('200 + application/json 错误体（blob 类型为 json）：不下载、不报成功、弹错误', async () => {
    const h = setupHarness({
      response: {
        data: jsonErrorBlob({ success: false, message: '无权限导出审计日志' }),
        headers: { 'content-type': 'application/json' },
      },
    })

    await h.exportLogs()

    expect(h.createObjectURL).not.toHaveBeenCalled()
    expect(h.click).not.toHaveBeenCalled()
    expect(h.ElMessage.success).not.toHaveBeenCalled()
    expect(h.ElMessage.error).toHaveBeenCalledWith('无权限导出审计日志')
  })

  test('码化错误：errors.errorCode 走 resolveErrorMessage 翻译而非回显后端文案', async () => {
    // AUDIT_EXPORT_FAILED 是 ERROR_CODE_I18N_MAP 里真实存在的码（zh：审计日志导出失败），
    // 用它区分「码化翻译生效」与「原样回显后端 message」两种情况
    const h = setupHarness({
      response: {
        data: jsonErrorBlob({
          success: false,
          message: 'AUDIT_EXPORT_FAILED',
          errors: { errorCode: 'AUDIT_EXPORT_FAILED' },
        }),
        headers: { 'content-type': 'application/json' },
      },
    })

    await h.exportLogs()

    expect(h.createObjectURL).not.toHaveBeenCalled()
    const shown = h.ElMessage.error.mock.calls[0][0]
    expect(shown).not.toBe('AUDIT_EXPORT_FAILED')
    expect(shown).toBe(resolveErrorMessage({ errors: { errorCode: 'AUDIT_EXPORT_FAILED' } }))
  })

  test('Content-Type 声明 JSON：即便 Blob 类型缺失也按错误处理', async () => {
    const h = setupHarness({
      response: {
        data: new Blob([JSON.stringify({ message: '服务端拒绝' })], { type: '' }),
        headers: { 'content-type': 'application/json; charset=utf-8' },
      },
    })

    await h.exportLogs()

    expect(h.createObjectURL).not.toHaveBeenCalled()
    expect(h.ElMessage.success).not.toHaveBeenCalled()
    expect(h.ElMessage.error).toHaveBeenCalledWith('服务端拒绝')
  })

  test('非 Blob 响应体（适配器未启用 responseType）：按错误处理，不下载', async () => {
    const h = setupHarness({
      response: { data: { message: '未预期形状' }, headers: {} },
    })

    await h.exportLogs()

    expect(h.createObjectURL).not.toHaveBeenCalled()
    expect(h.ElMessage.error).toHaveBeenCalledWith('未预期形状')
  })

  test('catch 路径：响应体是 JSON 错误 Blob 时提取 message（而非泛化「导出失败」）', async () => {
    const h = setupHarness({
      thrown: {
        response: { data: jsonErrorBlob({ message: '审计权限不足' }), status: 403 },
      },
    })

    await h.exportLogs()

    expect(h.ElMessage.error).toHaveBeenCalledWith('审计权限不足')
  })

  test('正常 xlsx：下载触发、报成功、无错误提示', async () => {
    const h = setupHarness({
      response: {
        data: new Blob(['PK\u0003\u0004 binary'], { type: XLSX_TYPE }),
        headers: { 'content-type': XLSX_TYPE },
      },
    })

    await h.exportLogs()

    expect(h.createObjectURL).toHaveBeenCalledTimes(1)
    expect(h.click).toHaveBeenCalledTimes(1)
    expect(h.revokeObjectURL).toHaveBeenCalledWith('blob:probe')
    expect(h.ElMessage.success).toHaveBeenCalledWith('messages.exportSuccess')
    expect(h.ElMessage.error).not.toHaveBeenCalled()
  })

  test('路由切换取消（ERR_CANCELED）仍静默，不弹错误', async () => {
    const h = setupHarness({
      thrown: Object.assign(new Error('canceled'), { code: 'ERR_CANCELED' }),
    })

    await h.exportLogs()

    expect(h.ElMessage.error).not.toHaveBeenCalled()
    expect(h.createObjectURL).not.toHaveBeenCalled()
  })
})
