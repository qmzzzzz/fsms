/**
 * 单 IP 行为画像 → 可复制的 Markdown 溯源报告（纯函数）。
 *
 * 文案全部经注入的 t 读取：报告与页面共用同一份词表，语言随界面切换。
 * 实现里不碰 DOM / 网络 / 全局 i18n 实例，报告内容因此可以在单测里逐行断言。
 */
import { localDateStr } from '@/utils/datetime'

/** 表格单元格：换行会拆行、竖线会拆列，先归一成安全文本 */
const cell = (value) => {
  const text = value === null || value === undefined || value === '' ? '-' : String(value)
  return text.replace(/\r?\n/g, ' ').replace(/\|/g, '\\|')
}

const statLine = (t, key, value) => `- ${t('attackProfile.' + key)}: ${cell(value)}`

/** 动作码 → 审计页同一套人话标签；词表缺键时退回码本身，不显示裸键 */
const actionLabel = (t, te, code) => {
  if (!code) return '-'
  const key = `audit.action.${code}`
  return te(key) ? t(key) : code
}

const containmentText = (t, containment) => {
  if (!containment || containment.degraded) return t('attackProfile.containmentDegraded')
  if (containment.blacklisted) return t('attackProfile.containmentBlacklisted')
  if (containment.whitelisted) return t('attackProfile.containmentWhitelisted')
  return t('attackProfile.containmentNone')
}

const evidenceTable = (t, te, cat, formatTime) => {
  const rows = cat.evidence || []
  if (rows.length === 0) return [t('attackProfile.evidenceEmpty'), '']
  const out = [
    `| ${t('attackProfile.evidenceTime')} | ${t('attackProfile.evidenceAction')} | ` +
      `${t('attackProfile.evidenceMethod')} | ${t('attackProfile.evidencePath')} | ` +
      `${t('attackProfile.evidenceStatus')} | ${t('attackProfile.evidenceAccount')} | ` +
      `${t('attackProfile.evidenceTrace')} | ${t('attackProfile.evidenceReason')} |`,
    '| --- | --- | --- | --- | --- | --- | --- | --- |',
  ]
  for (const row of rows) {
    out.push(
      `| ${formatTime(row.timestamp)} | ${cell(actionLabel(t, te, row.action))} | ` +
        `${cell(row.method)} | ${cell(row.path)} | ${cell(row.statusCode)} | ` +
        `${cell(row.username)} | ${cell(row.logId)} | ` +
        `${cell(row.refusalReason || row.reason)} |`
    )
  }
  out.push('')
  return out
}

const categorySection = (t, te, profile, formatTime) => {
  const categories = profile.categories || []
  if (categories.length === 0) return [t('attackProfile.reportNoCategories'), '']
  const out = []
  categories.forEach((cat, index) => {
    out.push(
      `### ${index + 1}. ${t(`attackProfile.category.${cat.code}.label`)}` +
        ` (${t(`attackProfile.severity.${cat.severity}`)}) - ` +
        t('attackProfile.categoryCount', { count: cat.count }),
      '',
      t(`attackProfile.category.${cat.code}.description`),
      '',
      ...evidenceTable(t, te, cat, formatTime)
    )
  })
  return out
}

const uncategorizedSection = (t, te, profile, formatTime) => {
  const bucket = profile.uncategorized || {}
  const rows = bucket.evidence || []
  const out = [`## ${t('attackProfile.reportSectionUncategorized')}`, '']
  if (rows.length === 0) return [...out, t('attackProfile.reportNoUncategorized'), '']
  out.push(t('attackProfile.uncategorizedTitle', { count: bucket.count ?? rows.length }), '')
  out.push(...evidenceTable(t, te, { evidence: rows }, formatTime))
  return out
}

const suggestionSection = (t, profile) => {
  const suggestions = profile.suggestions || []
  if (suggestions.length === 0) return [t('attackProfile.reportNoSuggestions'), '']
  return [...suggestions.map((code, i) => `${i + 1}. ${t(`attackProfile.suggestion.${code}`)}`), '']
}

const boundarySection = (t, profile) => {
  const out = [t('attackProfile.reportBoundaryBody')]
  if (profile.truncated) {
    out.push('', `- ${t('attackProfile.truncated', { count: profile.analyzed ?? 0 })}`)
  }
  if (profile.scopeLimited) out.push('', `- ${t('attackProfile.scopeLimited')}`)
  if (profile.isPrivate) out.push('', `- ${t('attackProfile.privateIp')}`)
  const hasEvidence =
    (profile.categories || []).some((cat) => cat.evidence?.length) ||
    profile.uncategorized?.evidence?.length > 0
  if (hasEvidence) out.push('', `- ${t('attackProfile.reportTraceHint')}`)
  out.push('')
  return out
}

/**
 * @param {object} profile 画像接口的 data
 * @param {object} deps   { t, te, formatTime, now? }
 * @returns {string} Markdown 报告
 */
export const buildAttackReport = (profile, { t, te, formatTime, now = new Date() }) => {
  const window = profile.window || {}
  const stats = profile.stats || {}
  const hours = window.hours ? ` (${t('attackProfile.windowHours', { hours: window.hours })})` : ''
  return [
    `# ${t('attackProfile.reportTitle')}`,
    '',
    `- ${t('attackProfile.reportGeneratedAt')}: ${formatTime(now)}`,
    `- ${t('attackProfile.reportIp')}: ${cell(profile.ip)}`,
    `- ${t('attackProfile.reportWindow')}: ${formatTime(window.since)} - ${formatTime(window.until)}${hours}`,
    `- ${t('attackProfile.reportVerdict')}: ${t(`attackProfile.verdict.${profile.verdict}`)}` +
      ` / ${t('attackProfile.reportScore')}: ${profile.score ?? 0}` +
      ` / ${t('attackProfile.riskLabel')}: ${t(`attackProfile.risk.${profile.riskLevel || 'none'}`)}`,
    `- ${t('attackProfile.reportContainment')}: ${containmentText(t, profile.containment)}`,
    '',
    `## ${t('attackProfile.reportSectionConclusion')}`,
    '',
    t(`attackProfile.verdictHint.${profile.verdict}`),
    '',
    `## ${t('attackProfile.reportSectionStats')}`,
    '',
    statLine(t, 'statTotal', profile.total),
    statLine(t, 'statBlocked', stats.failedRequests),
    statLine(t, 'statFailedLogins', stats.failedLogins),
    statLine(t, 'statSuccessLogins', stats.successfulLogins),
    statLine(t, 'statAccounts', stats.distinctAccountsTried),
    statLine(t, 'statUserAgents', stats.distinctUserAgents),
    ...(stats.peakBucketRequests
      ? [
          statLine(
            t,
            'statPeakRequests',
            `${stats.peakBucketRequests} ${t(
              'attackProfile.' + (profile.timeline?.unit === 'hour' ? 'perHour' : 'perDay')
            )}`
          ),
        ]
      : []),
    ...(stats.criticalRows > 0 ? [statLine(t, 'statHighRiskRows', stats.criticalRows)] : []),
    ...(stats.suspiciousSuccessAt
      ? [statLine(t, 'statSuspiciousSuccess', formatTime(stats.suspiciousSuccessAt))]
      : []),
    statLine(t, 'statFirstSeen', formatTime(stats.firstSeen || profile.firstSeen)),
    statLine(t, 'statLastSeen', formatTime(stats.lastSeen || profile.lastSeen)),
    '',
    `## ${t('attackProfile.reportSectionCategories')}`,
    '',
    ...categorySection(t, te, profile, formatTime),
    ...uncategorizedSection(t, te, profile, formatTime),
    `## ${t('attackProfile.reportSectionSuggestions')}`,
    '',
    ...suggestionSection(t, profile),
    `## ${t('attackProfile.reportSectionBoundary')}`,
    '',
    ...boundarySection(t, profile),
  ].join('\n')
}

/** 文件名只保留跨平台安全的字符（IPv6 的冒号在 Windows 上非法） */
export const attackReportFileName = (profile, now = new Date()) => {
  const ip = String(profile?.ip || 'unknown').replace(/[^A-Za-z0-9.-]/g, '_')
  return `attack-profile-${ip}-${localDateStr(now)}.md`
}
