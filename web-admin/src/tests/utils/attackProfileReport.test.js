/**
 * 单 IP 行为画像报告生成器（utils/attackProfileReport）
 *
 * 报告是给客户复制进工单/归档的交付物，本文件只钉两件事：
 *  1. 报告带上了用户需要的关键事实（判定、评分、统计、分类、证据、建议）；
 *  2. 原始值不会破坏 Markdown 结构（竖线/换行），双语切换后文案确实跟随。
 */
import { describe, test, expect, beforeEach } from 'vitest'
import i18n from '@/i18n'
import zhProfile from '@/i18n/locales/attackProfile.zh-CN'
import enProfile from '@/i18n/locales/attackProfile.en-US'
import { attackReportFileName, buildAttackReport } from '@/utils/attackProfileReport'

// 画像词表随页面懒加载，报告单测直接消费同一组模块，与运行时口径一致
i18n.global.mergeLocaleMessage('zh-CN', { attackProfile: zhProfile })
i18n.global.mergeLocaleMessage('en-US', { attackProfile: enProfile })

const formatTime = (value) => (value === null || value === undefined ? '-' : 'FMT(' + value + ')')
const t = (key, params) => i18n.global.t(key, params)
const te = (key) => i18n.global.te(key)

const profile = (over = {}) => ({
  ip: '203.0.113.10',
  window: {
    hours: 168,
    since: '2026-10-01T00:00:00.000Z',
    until: '2026-10-08T00:00:00.000Z',
  },
  total: 42,
  analyzed: 42,
  truncated: false,
  firstSeen: '2026-10-02T00:00:00.000Z',
  lastSeen: '2026-10-07T00:00:00.000Z',
  score: 65,
  verdict: 'attack',
  riskLevel: 'high',
  scopeLimited: false,
  isPrivate: false,
  stats: {
    failedRequests: 38,
    failedLogins: 30,
    successfulLogins: 0,
    distinctAccountsTried: 12,
    distinctUserAgents: 2,
    firstSeen: '2026-10-02T00:00:00.000Z',
    lastSeen: '2026-10-07T00:00:00.000Z',
  },
  categories: [
    {
      code: 'credential_stuffing',
      count: 30,
      blockedCount: 28,
      successCount: 2,
      severity: 'high',
      evidence: [
        {
          timestamp: '2026-10-03T00:00:00.000Z',
          action: 'login_failed',
          method: 'POST',
          path: '/api/auth/login',
          statusCode: 401,
          username: 'alice',
          refusalReason: '密码错误',
          logId: '507f1f77bcf86cd799439011',
        },
      ],
    },
  ],
  topPaths: [],
  topActions: [],
  topTargetAccounts: [],
  topUserAgents: [],
  timeline: { unit: 'day', buckets: [] },
  containment: { degraded: false, blacklisted: true, whitelisted: false, entries: [] },
  suggestions: ['block_ip', 'enable_mfa'],
  ...over,
})

beforeEach(() => {
  i18n.global.locale.value = 'zh-CN'
})

describe('buildAttackReport', () => {
  test('中文报告包含判定、评分、统计、分类、证据与建议', () => {
    const text = buildAttackReport(profile(), {
      t,
      te,
      formatTime,
      now: new Date('2026-11-02T10:00:00'),
    })

    expect(text).toContain('# IP 行为溯源报告')
    expect(text).toContain('203.0.113.10')
    expect(text).toContain('FMT(2026-10-01T00:00:00.000Z)')
    expect(text).toContain('发现攻击行为')
    expect(text).toContain('65')
    expect(text).toContain('风险等级: 高')
    expect(text).toContain('撞库攻击')
    expect(text).toContain('共 30 次')
    expect(text).toContain('| FMT(2026-10-03T00:00:00.000Z) | 登录失败 |')
    expect(text).toContain('POST')
    expect(text).toContain('/api/auth/login')
    expect(text).toContain('401')
    expect(text).toContain('alice')
    // 记录ID 是溯源钻取的唯一入口：缺了它，报告只能「看」不能「查」
    expect(text).toContain('记录ID')
    expect(text).toContain('507f1f77bcf86cd799439011')
    expect(text).toContain('立即封禁该 IP')
    expect(text).toContain('为相关账号开启两步验证')
    expect(text).toContain('不能作为入侵定责的唯一依据')
    expect(text).toContain('证据行均带审计记录ID')
    // 只出现人类可读文案，不得把建议码原样漏进报告
    expect(text).not.toContain('block_ip')
    expect(text).not.toContain('[object Object]')
  })

  test('峰值、高危与疑似突破时间进入关键数据', () => {
    const base = profile()
    const text = buildAttackReport(
      profile({
        stats: {
          ...base.stats,
          peakBucketRequests: 30,
          criticalRows: 2,
          suspiciousSuccessAt: '2026-10-05T00:00:00.000Z',
        },
      }),
      { t, te, formatTime }
    )
    expect(text).toContain('峰值请求数: 30 次/天')
    expect(text).toContain('高危记录: 2')
    expect(text).toContain('疑似突破时间: FMT(2026-10-05T00:00:00.000Z)')
  })

  test('证据里的竖线与换行不会破坏 Markdown 表格', () => {
    const text = buildAttackReport(
      profile({
        categories: [
          {
            code: 'path_scanning',
            count: 1,
            blockedCount: 1,
            successCount: 0,
            severity: 'low',
            evidence: [
              {
                timestamp: '2026-10-03T00:00:00.000Z',
                action: 'malformed_request_blocked',
                path: '/a|b',
                statusCode: 400,
                username: null,
                refusalReason: 'line1\nline2',
              },
            ],
          },
        ],
      }),
      { t, te, formatTime }
    )
    expect(text).toContain('/a\\|b')
    expect(text).toContain('line1 line2')
    expect(text).not.toContain('line1\nline2')
  })

  test('未归类的记录单列成节：带数量、动作、记录ID，供逐条回查（取证完整性）', () => {
    const text = buildAttackReport(
      profile({
        uncategorized: {
          count: 2,
          evidence: [
            {
              timestamp: '2026-10-04T00:00:00.000Z',
              action: 'ip_blacklist_blocked',
              method: 'POST',
              path: '/api/auth/login',
              statusCode: 403,
              username: null,
              reason: '黑名单拦截',
              logId: '507f1f77bcf86cd799439012',
            },
          ],
        },
      }),
      { t, te, formatTime }
    )
    expect(text).toContain('未归类的记录')
    expect(text).toContain('未归类的记录（2 条）')
    expect(text).toContain('IP 黑名单拦截')
    expect(text).toContain('507f1f77bcf86cd799439012')
    expect(text).toContain('黑名单拦截')
    // 该行确实落在「未归类的记录」一节之下（而不是被塞进行为分类）
    expect(text.indexOf('未归类的记录')).toBeGreaterThan(text.indexOf('行为分类与证据'))
    expect(text.indexOf('未归类的记录')).toBeLessThan(text.indexOf('处置建议'))
  })

  test('受限范围/截断/内网地址会写进证据边界', () => {
    const text = buildAttackReport(
      profile({ scopeLimited: true, truncated: true, analyzed: 5000, isPrivate: true }),
      { t, te, formatTime }
    )
    expect(text).toContain('本次只分析了最近 5000 条')
    expect(text).toContain('数据范围受限')
    expect(text).toContain('内网或本机地址')
  })

  test('英文界面生成英文报告（同一份数据、同一组码）', () => {
    i18n.global.locale.value = 'en-US'
    const text = buildAttackReport(profile(), { t, te, formatTime })
    expect(text).toContain('# IP Behavior Traceability Report')
    expect(text).toContain('Attack detected')
    expect(text).toContain('Credential stuffing')
    expect(text).toContain('Block this IP now')
    expect(text).toContain('203.0.113.10')
  })

  test('空分类/空建议也有明确文案，不留空白', () => {
    const text = buildAttackReport(
      profile({ categories: [], suggestions: [], verdict: 'no_data', riskLevel: 'none' }),
      { t, te, formatTime }
    )
    expect(text).toContain('未识别出具体攻击类型')
    expect(text).toContain('暂无处置建议')
    expect(text).toContain('没有记录')
    // 未归类一节在无证据时也要明确说「没有」，不能只剩一个空标题
    expect(text).toContain('没有未归类的记录')
    // 没有任何证据行时不提示「按记录ID回查」（避免给客户一条不存在的路径）
    expect(text).not.toContain('证据行均带审计记录ID')
  })
})

describe('attackReportFileName', () => {
  test('IPv4 直接可用，IPv6 的冒号被替换成跨平台安全字符', () => {
    expect(attackReportFileName({ ip: '203.0.113.10' }, new Date('2026-11-02T10:00:00'))).toBe(
      'attack-profile-203.0.113.10-2026-11-02.md'
    )
    expect(attackReportFileName({ ip: '2001:db8::1' }, new Date('2026-11-02T10:00:00'))).toBe(
      'attack-profile-2001_db8__1-2026-11-02.md'
    )
  })

  test('缺 IP 时给 unknown，不生成空文件名', () => {
    expect(attackReportFileName({}, new Date('2026-11-02T10:00:00'))).toBe(
      'attack-profile-unknown-2026-11-02.md'
    )
  })
})

describe('buildAttackReport 分支矩阵（2026-11-06 收敛批补测）', () => {
  /** 去掉分类/建议的骨架：让 containment 与边界旗标成为唯一变量 */
  const minimal = (over = {}) =>
    profile({
      categories: [],
      suggestions: [],
      uncategorized: {},
      ...over,
    })
  const run = (over) => buildAttackReport(minimal(over), { t, te, formatTime })

  test('containment 四态：degraded 优先于拉黑；名单状态读不到（null）也按降级保守口径', () => {
    const degraded = t('attackProfile.containmentDegraded')
    const blacklisted = t('attackProfile.containmentBlacklisted')
    const whitelisted = t('attackProfile.containmentWhitelisted')
    const none = t('attackProfile.containmentNone')

    expect(run({ containment: { degraded: true, blacklisted: true } })).toContain(degraded)
    expect(run({ containment: { degraded: false, blacklisted: true } })).toContain(blacklisted)
    expect(run({ containment: { whitelisted: true } })).toContain(whitelisted)
    expect(run({ containment: {} })).toContain(none)
    // containment 整体缺失 = 读不到名单状态 ⇒ 保守走「降级」口径，而不是谎称「无遏制」
    expect(run({ containment: null })).toContain(degraded)
  })

  test('cell 空值臂 + actionLabel 空码臂：证据行缺字段落 "-"，空动作码落 "-"', () => {
    const report = buildAttackReport(
      minimal({
        categories: [
          {
            code: 'credential_stuffing',
            severity: 'high',
            count: 1,
            evidence: [
              {
                timestamp: '2026-10-03T00:00:00.000Z',
                action: '',
                method: '',
                path: null,
                statusCode: undefined,
                username: undefined,
                logId: '',
                refusalReason: '',
              },
            ],
          },
        ],
      }),
      { t, te, formatTime }
    )
    const lines = report.split('\n').filter((l) => l.startsWith('| FMT'))
    expect(lines.length).toBe(1)
    // 除时间列外的每一个格子都落在 "-" 占位
    const cells = lines[0].split('|').map((c) => c.trim())
    expect(cells.filter((c) => c === '-').length).toBeGreaterThanOrEqual(7)
  })

  test('evidence 空数组臂：分类存在但证据为空 → 显式「无证据行」占位', () => {
    const report = buildAttackReport(
      minimal({
        categories: [{ code: 'credential_stuffing', severity: 'high', count: 0, evidence: [] }],
      }),
      { t, te, formatTime }
    )
    expect(report).toContain(t('attackProfile.evidenceEmpty'))
  })

  test('uncategorized count 兜底臂：bucket.count 缺失时用 rows.length', () => {
    const report = buildAttackReport(
      minimal({
        uncategorized: {
          evidence: [
            {
              timestamp: '2026-10-03T00:00:00.000Z',
              action: 'login_failed',
              method: 'POST',
              path: '/api/auth/login',
              statusCode: 401,
              username: 'alice',
              logId: 'x',
            },
            {
              timestamp: '2026-10-04T00:00:00.000Z',
              action: 'login_failed',
              method: 'POST',
              path: '/api/auth/login',
              statusCode: 401,
              username: 'bob',
              logId: 'y',
            },
          ],
        },
      }),
      { t, te, formatTime }
    )
    // t('attackProfile.uncategorizedTitle', { count: 2 })——真实 i18n 渲染出数字 2
    expect(report).toContain('2')
  })
})
