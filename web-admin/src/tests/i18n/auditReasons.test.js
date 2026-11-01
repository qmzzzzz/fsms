/**
 * 审计 reason 展示期翻译的覆盖闸
 *
 * 反面场景（本文件要防）：英文界面打开一条审计详情，reason 仍是中文整句——
 * 界面其余部分全英文，只有这一段「证据原文」是中文，读的人以为导出/显示坏了。
 *
 * 判据不是「函数能跑」，而是**逐条模板都对得上**：每条样例都取自在
 * src/ 下真实写入 AuditLog.reason 的模板（文件与行号见各条注释），
 * 译文必须 (a) 不再是中文，(b) 参数被搬到英文句子里。
 */
import { describe, test, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { translateAuditReason, AUDIT_REASON_RULE_COUNT } from '@/i18n/auditReasons'

const CJK = /[\u4e00-\u9fff]/

// 每条：中文原文（含参数实例）→ 期望英文里必须出现的关键片段
const CASES = [
  [
    '启动配置校验通过：JWT/JWT_REFRESH/AES/HMAC 密钥均满足强度要求',
    'Startup configuration validation passed',
  ],
  ['尝试将 10.0.0.1 加入黑名单（加入后覆盖全部 10.0.0.0/8 地址），权限不足', 'blocklist'],
  ['尝试将 10.0.0.1 加入白名单（加入后覆盖全部 10.0.0.0/8 地址），权限不足', 'allowlist'],
  [
    '尝试移除铺满 10.0.0.0/8 地址的名单条目 10.0.0.1（该条目是全覆盖的组成部分），权限不足',
    'part of full coverage',
  ],
  ['查询参数值超过 200 字符：keyword', 'exceeds 200 characters'],
  ['查询参数收到对象/数组形态取值：filter', 'object/array'],
  ['请求 IP 命中黑名单，已拒绝访问', 'blacklisted'],
  ['请求 IP 命中黑名单降级缓存（数据库查询失败），已拒绝访问', 'fallback cache'],
  ['登录 IP 不在允许范围内（not_in_allowlist）', 'Sign-in IP'],
  ['请求 IP 不在允许范围内（not_in_allowlist）', 'Request IP'],
  ['写操作 Origin 头为空串（异常来源）', 'empty Origin header'],
  ['写操作来源 https://evil.example 不在白名单内', 'not in the allowlist'],
  ['管理员注销用户并匿名化其个人身份信息', 'anonymized'],
  ['管理员批量注销 5 个用户并匿名化', '5 accounts in bulk'],
  ['管理员重置用户 alice 的两步验证并强制下线', 'reset two-factor authentication for alice'],
  ['管理员重置用户 alice 的口令，并要求首次登录改密', 'reset the password for alice'],
  ['重新生成恢复码失败：动态口令错误', 'invalid one-time code'],
  ['重新生成恢复码被拒：动态口令所属时间窗已被消费（重放）', 'already used (replay)'],
  ['重新生成 10 个备用恢复码（旧码作废）', '10 backup recovery codes'],
  ['生成两步验证密钥（待确认）', 'pending confirmation'],
  ['开启两步验证并生成 10 个备用恢复码', 'Enabled two-factor authentication'],
  ['关闭两步验证身份验证失败（方式：totp）', 'method: totp'],
  ['使用备用恢复码关闭两步验证（已消费一枚恢复码）', 'one code consumed'],
  ['关闭两步验证', 'Disabled two-factor authentication'],
  ['密码已验证，等待两步验证码', 'Password verified'],
  ['MFA 验证通道锁定期间尝试登录', 'channel was locked'],
  ['两步验证码重放', 'replay'],
  ['两步验证码错误', 'Invalid two-factor code'],
  ['使用备用恢复码登录（剩余 8 个）', '8 remaining'],
]

describe('审计 reason 英文展示', () => {
  test('模板条数与实现一致（新增模板必须同步加断言）', () => {
    // 28 条规则 ↔ 上面 29 条样例：黑/白名单两例共用同一条规则（按捕获组选词）
    expect(AUDIT_REASON_RULE_COUNT).toBe(28)
  })

  test.each(CASES)('译出英文且参数保留：%s', (zh, expected) => {
    const en = translateAuditReason(zh)
    expect(en).not.toBe(zh)
    expect(en).not.toMatch(CJK)
    expect(en).toContain(expected)
  })

  test('未登记的模板原样返回中文（不猜测改写证据原文）', () => {
    const raw = '某个尚未登记的新审计说明（含参数 12）'
    expect(translateAuditReason(raw)).toBe(raw)
  })

  test('非字符串/空值不炸：null、undefined、数字、空串原样返回', () => {
    for (const v of [null, undefined, 0, '', 123]) expect(translateAuditReason(v)).toBe(v)
  })

  test('参数不会被再次套壳：译文里不残留中文括号或中文冒号', () => {
    const en = translateAuditReason('查询参数值超过 200 字符：keyword')
    expect(en).not.toMatch(/[（）：；，]/)
  })
})

describe('接线闸：详情对话框真的用上了翻译（只登记不接线 = 缺陷）', () => {
  const src = fs.readFileSync(path.resolve(__dirname, '../../views/AuditLogView.vue'), 'utf8')
  const squash = src.replace(/\/\/[^\n]*/g, '').replace(/\s+/g, '')

  test('模板绑定的是 auditReasonText，不是裸 reason', () => {
    expect(squash).toContain('auditReasonText(detailDialog.data.reason)')
    expect(squash).not.toContain('{{detailDialog.data.reason}}')
  })

  test('只有英文界面才翻译；中文界面原样返回（证据原文不改写）', () => {
    expect(squash).toContain('translateAuditReason(reason):reason')
    expect(squash).toContain("String(locale.value||'').startsWith('en')")
  })

  test('模板里不再有中文片段的 reason 兜底渲染', () => {
    expect(squash).not.toContain('reason||')
  })
})
