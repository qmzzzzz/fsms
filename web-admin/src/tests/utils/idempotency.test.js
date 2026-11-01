/**
 * 前端幂等键（审计一-1）
 *
 * 后端默认**不强制** `Idempotency-Key`（8 个创建端点有 105 处既有调用，强制会一次性
 * 打断所有脚本与第三方接入），所以「浏览器里的双击」是否真的受保护，取决于前端有没有
 * 老实带键、以及重试时是否复用同一个键。这两件事都只在本文件里可证伪。
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { newIdempotencyKey, createSubmissionKey } from '@/utils/idempotency'

/** 后端 KEY_PATTERN 的镜像：8-64 位可见 ASCII（!-~） */
const BACKEND_KEY_PATTERN = /^[\x21-\x7e]{8,64}$/

afterEach(() => {
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('newIdempotencyKey', () => {
  test('生成值落在后端可接受的形态内，且两次生成不相同', () => {
    const a = newIdempotencyKey()
    const b = newIdempotencyKey()
    expect(a).toMatch(BACKEND_KEY_PATTERN)
    expect(b).toMatch(BACKEND_KEY_PATTERN)
    expect(a).not.toBe(b)
  })

  test('优先使用 crypto.randomUUID（安全上下文）', () => {
    const uuid = '123e4567-e89b-42d3-a456-426614174000'
    const randomUUID = vi.fn(() => uuid)
    vi.stubGlobal('crypto', { randomUUID, getRandomValues: vi.fn() })
    expect(newIdempotencyKey()).toBe(uuid)
    expect(randomUUID).toHaveBeenCalledTimes(1)
  })

  test('非安全上下文（HTTP 内网）回落 getRandomValues，仍是 32 位十六进制', () => {
    // randomUUID 只在安全上下文可用：内网 http:// 部署下它整个不存在，
    // 若不回落，前端会在这里抛错——建号按钮直接失效，而错误与"幂等"毫无关系。
    const getRandomValues = vi.fn((bytes) => {
      for (let i = 0; i < bytes.length; i += 1) bytes[i] = (i * 17) % 256
      return bytes
    })
    vi.stubGlobal('crypto', { getRandomValues })
    const key = newIdempotencyKey()
    expect(key).toMatch(/^[0-9a-f]{32}$/)
    expect(key).toMatch(BACKEND_KEY_PATTERN)
    expect(getRandomValues).toHaveBeenCalledTimes(1)
  })

  test('既无 randomUUID 也无 getRandomValues 时仍能产出合法键（老运行时兜底）', () => {
    vi.stubGlobal('crypto', {})
    expect(newIdempotencyKey()).toMatch(BACKEND_KEY_PATTERN)
  })
})

describe('createSubmissionKey', () => {
  test('header() 稳定复用同一个键：重试同一次提交不会变成新提交', () => {
    const submission = createSubmissionKey()
    const first = submission.header()
    // 每次调用都返回新对象（调用方可以随手改），但键值必须一致
    expect(submission.header()).not.toBe(first)
    expect(submission.header()).toEqual(first)
    expect(Object.keys(first)).toEqual(['Idempotency-Key'])
  })

  test('renew() 换新键：用户改完内容再提交是一次新的提交意图', () => {
    const submission = createSubmissionKey()
    const before = submission.value()
    const after = submission.renew()
    expect(after).not.toBe(before)
    expect(submission.value()).toBe(after)
    expect(submission.header()['Idempotency-Key']).toBe(after)
    expect(after).toMatch(BACKEND_KEY_PATTERN)
  })

  test('两个实例互不共用键（不同页面同时提交不会互相污染）', () => {
    expect(createSubmissionKey().value()).not.toBe(createSubmissionKey().value())
  })
})
