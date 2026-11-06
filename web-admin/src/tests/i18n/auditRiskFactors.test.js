/**
 * 风险因素翻译层（i18n/auditRiskFactors.js）的行为钉。
 *
 * 三条硬约束：
 *   1) 登记集必须成对完整：每个码的 zh/en 标签与解释都不能缺，也不能回退成码；
 *   2) 未知码必须原样露出（宁可看到机器码，也不猜一个语义）；
 *   3) 中文自由文本只在英文界面翻译，中文界面不得二次加工。
 * 后端词表与本登记集的互相校验在 src/tests/ci/riskFactorVocabularyGate.test.js。
 */
import { describe, test, expect } from 'vitest'
import defaultLabel, {
  riskFamilyLabel,
  riskFactorLabel,
  riskFactorDesc,
  RISK_FACTOR_CODES,
  RISK_FACTOR_COUNT,
} from '@/i18n/auditRiskFactors'

describe('风险因素翻译层', () => {
  test('登记集非空，计数与列表长度一致（钉条数：新增码必须显式改这里）', () => {
    // 49→53：2026-11-05 攻击检测面四码（injection_signature / mongo_operator_strip /
    // scanner_path / unmatched_path_storm），与 riskFactorVocabularyGate 的后端码集对齐。
    expect(RISK_FACTOR_COUNT).toBe(53)
    expect(RISK_FACTOR_CODES.length).toBe(RISK_FACTOR_COUNT)
    expect(RISK_FACTOR_CODES).toEqual([...RISK_FACTOR_CODES].sort())
  })

  test('抽查：已知码的 zh/en 标签与悬浮解释', () => {
    expect(riskFactorLabel('ip_blacklisted', 'zh-CN')).toBe('IP 命中黑名单')
    expect(riskFactorLabel('ip_blacklisted', 'en-US')).toBe('IP blacklisted')
    expect(riskFactorDesc('ip_blacklisted', 'zh-CN')).toContain('黑名单')
    expect(riskFactorDesc('ip_blacklisted', 'en-US')).toContain('blacklist')
    expect(riskFactorLabel('full_range_cidr_attempt', 'zh-CN')).toBe('试图加入全网段')
    expect(riskFactorLabel('full_range_cidr_attempt', 'en-US')).toBe('Full-range CIDR attempt')
  })

  test('蜜罐链阶段码族：chain_stage_* 按前缀族翻译，未收录阶段原样露出', () => {
    // 后端是 chain_stage_ 前缀 + 阶段名动态拼接（services/honeypotChainWatch.js），
    // 没有可预先列举的清单——这族漏一个，客户就看到一串 chain_stage_xxx
    expect(riskFactorLabel('chain_stage_login_failed', 'zh-CN')).toBe('蜜罐链阶段：登录失败')
    expect(riskFactorLabel('chain_stage_canary_username_attempt', 'zh-CN')).toBe(
      '蜜罐链阶段：金丝雀账户尝试'
    )
    expect(riskFactorLabel('chain_stage_honeypot_probe', 'en-US')).toBe(
      'Honeypot chain stage: honeypot probing'
    )
    expect(riskFactorDesc('chain_stage_honeypot_login', 'zh-CN')).toContain('蜜罐链')
    // 未收录阶段：不得整条消失，也不得编语义
    expect(riskFactorLabel('chain_stage_brand_new_stage', 'zh-CN')).toBe(
      '蜜罐链阶段：brand_new_stage'
    )
    // 非该族的码不受前缀规则影响
    expect(riskFamilyLabel('honeypot_chain_escalated', 'zh-CN')).toBeNull()
  })
  test('IP 归属码族：ip_attribution_* 按前缀族翻译，未收录裁定原样露出', () => {
    // 后端是反引号模板 ip_attribution_${attributionKind}，取值来自 IP_ATTRIBUTION_KINDS
    expect(riskFactorLabel('ip_attribution_trusted_proxy', 'zh-CN')).toBe('IP 归属：受信任代理')
    expect(riskFactorLabel('ip_attribution_public_peer_header', 'en-US')).toBe(
      'IP attribution: public peer header'
    )
    expect(riskFactorDesc('ip_attribution_trusted_proxy', 'zh-CN')).toContain('裁定')
    expect(riskFactorLabel('ip_attribution_future_kind', 'zh-CN')).toBe('IP 归属：future_kind')
  })
  test('未知码原样返回、无解释（不猜语义）', () => {
    expect(riskFactorLabel('some_future_code', 'zh-CN')).toBe('some_future_code')
    expect(riskFactorLabel('some_future_code', 'en-US')).toBe('some_future_code')
    expect(riskFactorDesc('some_future_code', 'zh-CN')).toBe('')
  })

  test('中文自由文本：中文界面原样，英文界面按模板翻译且参数不变', () => {
    expect(riskFactorLabel('批量数据操作', 'zh-CN')).toBe('批量数据操作')
    expect(riskFactorLabel('批量数据操作', 'en-US')).toBe('Batch data operation')
    expect(riskFactorLabel('限流持续触顶', 'en-US')).toBe('Rate limit continuously saturated')
    expect(riskFactorLabel('登录失败次数超标（账户:3, IP:7）', 'en-US')).toBe(
      'Excessive failed sign-ins (account: 3, IP: 7)'
    )
    // 后端 securityAlert.js:139 的真实形态是**半角**括号——只有全角规则会让英文界面静默回退裸中文
    expect(riskFactorLabel('登录失败次数超标 (账户:3, IP:7)', 'en-US')).toBe(
      'Excessive failed sign-ins (account: 3, IP: 7)'
    )
  })

  test('每个登记项都配齐 zh/en 标签与解释（缺一即红）', () => {
    for (const code of RISK_FACTOR_CODES) {
      for (const locale of ['zh-CN', 'en-US']) {
        const label = riskFactorLabel(code, locale)
        const desc = riskFactorDesc(code, locale)
        // 不得静默回退成机器码
        expect(label, code + ' @ ' + locale + ' label').not.toBe(code)
        expect(desc.length, code + ' @ ' + locale + ' desc').toBeGreaterThan(10)
      }
      // 中英标签必须真的不同（防一边复制粘贴另一边）
      expect(riskFactorLabel(code, 'zh-CN')).not.toBe(riskFactorLabel(code, 'en-US'))
    }
  })

  test('默认导出与命名导出一致', () => {
    expect(defaultLabel('ip_blacklisted', 'zh-CN')).toBe(riskFactorLabel('ip_blacklisted', 'zh-CN'))
  })

  describe('码族前缀翻译（chain_stage_ / ip_attribution_）与英文自由文本规则', () => {
    test('chain_stage_：zh/en 已知阶段各走一份词表，未知阶段露出尾部名字', () => {
      expect(riskFamilyLabel('chain_stage_honeypot_login', 'zh-CN')).toBe(
        '蜜罐链阶段：蜜罐账户登录'
      )
      expect(riskFamilyLabel('chain_stage_honeypot_login', 'en-US')).toBe(
        'Honeypot chain stage: honeypot sign-in'
      )
      expect(riskFamilyLabel('chain_stage_zzz_stage', 'zh-CN')).toBe('蜜罐链阶段：zzz_stage')
      expect(riskFactorDesc('chain_stage_zzz_stage', 'en-US')).toContain('zzz_stage')
      expect(riskFactorDesc('chain_stage_login_failed', 'zh-CN')).toContain('登录失败')
    })

    test('ip_attribution_：zh/en 三种裁定；非码族返回 null', () => {
      expect(riskFamilyLabel('ip_attribution_direct', 'zh-CN')).toBe('IP 归属：直连对端')
      expect(riskFamilyLabel('ip_attribution_trusted_proxy', 'en-US')).toBe(
        'IP attribution: trusted proxy'
      )
      expect(riskFamilyLabel('ip_attribution_public_peer_header', 'en-US')).toBe(
        'IP attribution: public peer header'
      )
      expect(riskFamilyLabel('ip_attribution_zzz', 'zh-CN')).toBe('IP 归属：zzz')
      expect(riskFamilyLabel('rate_limit_attempt', 'zh-CN')).toBe(null) // 已登记码不属于任何族
      expect(riskFamilyLabel('', 'zh-CN')).toBe(null)
    })

    test('中文自由文本 → 英文模板：四条规则逐条命中；zh 界面不二次加工', () => {
      expect(riskFactorLabel('批量数据操作', 'en-US')).toBe('Batch data operation')
      expect(riskFactorLabel('限流持续触顶', 'en-US')).toBe('Rate limit continuously saturated')
      expect(riskFactorLabel('限流持续触顶（账户:2）', 'en-US')).toBe(
        'Rate limit continuously saturated (账户:2)'
      )
      expect(riskFactorLabel('登录失败次数超标 (账户:3, IP:5)', 'en-US')).toBe(
        'Excessive failed sign-ins (account: 3, IP: 5)'
      )
      // 对不上规则的中文串：原样保留（不猜语义）
      expect(riskFactorLabel('某句没登记的中文', 'en-US')).toBe('某句没登记的中文')
      // zh 界面：自由文本不翻译
      expect(riskFactorLabel('批量数据操作', 'zh-CN')).toBe('批量数据操作')
    })
  })
})
