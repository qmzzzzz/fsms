/**
 * systemLabels 本地化词表测试（i18n/systemLabels.js）
 *
 * 模块定位：内置角色 / 权限 / 升级就绪原因的**英文侧**映射——中文侧刻意
 * 保留后端原文（用户数据与系统预设不混译），因此本测试的主战场是英文路径
 * 与各层兜底链。labelMapsSemantics.test.js 里 t-only 的 useI18n 替身只会走
 * 到 zh-CN 分支（isEnglish 的 ?? 'zh-CN' 兜底），英文侧与未知码回退此前
 * 无人钉住——本文件用**locale 可控**的替身补齐另一半。
 *
 * 钉住的语义（断言是契约不是抄写）：
 *   · 英文侧命中稳定 code → 内置映射；中文侧任何输入都回后端原文；
 *   · 未知 code / 自建角色：英文侧也不造词，按「有 name 用 name，否则裸 code」；
 *   · upgradeReason 的 AGENT_NOT_READY 嵌套解析：前缀 + 全角分号分隔 +
 *     逐段查代理原文映射，任何一段不认识就原样保留。
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'
import { useSystemLabels } from '@/i18n/systemLabels'

// locale 可控的 useI18n 替身：isEnglish 只读 ctx.locale.value
const i18nState = vi.hoisted(() => ({ locale: { value: 'zh-CN' } }))
vi.mock('vue-i18n', async (importOriginal) => {
  const actual = await importOriginal()
  return { ...actual, useI18n: () => ({ locale: i18nState.locale, t: (k) => k }) }
})

const setEnglish = (en) => {
  i18nState.locale.value = en ? 'en-US' : 'zh-CN'
}

beforeEach(() => {
  setEnglish(false)
})

describe('roleName 角色名映射', () => {
  test('中文侧：对象回后端 name，字符串 code 回内置中文名', () => {
    const { roleName } = useSystemLabels()
    expect(roleName({ code: 'SUPER_ADMIN', name: '后端下发名' })).toBe('后端下发名')
    expect(roleName('GUEST')).toBe('访客')
  })

  test('中文侧未知 code 与缺 name 对象：回 code 本身，不造词', () => {
    const { roleName } = useSystemLabels()
    expect(roleName('CUSTOM_ROLE')).toBe('CUSTOM_ROLE')
    expect(roleName({ code: 'CUSTOM_ROLE' })).toBe('CUSTOM_ROLE')
    expect(roleName(undefined)).toBe('')
  })

  test('英文侧：内置角色按 code 映射 name 与裸 code 输入', () => {
    setEnglish(true)
    const { roleName } = useSystemLabels()
    expect(roleName('SUPER_ADMIN')).toBe('Super Administrator')
    expect(roleName({ code: 'AUDIT_VIEWER', name: '后端下发名' })).toBe('Audit Supervisor')
  })

  test('英文侧自建角色：有 name 用 name，无 name 落裸 code', () => {
    setEnglish(true)
    const { roleName } = useSystemLabels()
    expect(roleName({ code: 'CUSTOM_ROLE', name: '作者自命名' })).toBe('作者自命名')
    expect(roleName({ code: 'CUSTOM_ROLE' })).toBe('CUSTOM_ROLE')
  })
})

describe('roleDescription 角色描述', () => {
  test('英文侧内置角色回映射描述；字符串输入无描述可取', () => {
    setEnglish(true)
    const { roleDescription } = useSystemLabels()
    expect(roleDescription('FIRE_SUPERVISOR')).toBe('Alarm handling and inspection review')
    expect(roleDescription('CUSTOM_ROLE')).toBe('')
  })

  test('中文侧：对象自带 description 原样保留（作者原文不翻译），无则空串', () => {
    const { roleDescription } = useSystemLabels()
    expect(roleDescription({ code: 'CUSTOM_ROLE', description: '只看本班组' })).toBe('只看本班组')
    expect(roleDescription({ code: 'CUSTOM_ROLE' })).toBe('')
  })
})

describe('permissionName 权限名', () => {
  test('空值与字符串原样', () => {
    const { permissionName } = useSystemLabels()
    expect(permissionName(null)).toBe('')
    expect(permissionName('alarm:read')).toBe('alarm:read')
  })

  test('中文侧：一律回后端 name（未知码与已知码同口径）', () => {
    const { permissionName } = useSystemLabels()
    expect(permissionName({ code: 'alarm:handle', name: '报警处置' })).toBe('报警处置')
    expect(permissionName({ code: 'no:such', name: '自建权限' })).toBe('自建权限')
  })

  test('英文侧：已知 code 映射，未知 code 有 name 用 name、无 name 落裸 code', () => {
    setEnglish(true)
    const { permissionName } = useSystemLabels()
    expect(permissionName({ code: 'alarm:handle', name: '报警处置' })).toBe('Handle Alarm')
    expect(permissionName({ code: 'no:such', name: '自建权限' })).toBe('自建权限')
    expect(permissionName({ code: 'no:such' })).toBe('no:such')
    expect(permissionName({ name: '无 code 权限' })).toBe('无 code 权限')
  })
})

describe('upgradeReason 升级就绪原因', () => {
  test('中文侧：原文原样返回；非字符串输入回空串', () => {
    const { upgradeReason } = useSystemLabels()
    expect(upgradeReason('心跳已过期', 'AGENT_HEARTBEAT_STALE')).toBe('心跳已过期')
    expect(upgradeReason(null, 'UPGRADE_DISABLED')).toBe('')
  })

  test('英文侧：已知 code 直接映射，未知 code 落原文兜底', () => {
    setEnglish(true)
    const { upgradeReason } = useSystemLabels()
    expect(upgradeReason('任意中文', 'UPGRADE_DISABLED')).toBe('UPGRADE_ENABLED is not enabled')
    expect(upgradeReason('任意中文', 'NO_SUCH_CODE')).toBe('任意中文')
  })

  test('英文侧 AGENT_NOT_READY：嵌套原因逐段翻译（全角分号分隔）', () => {
    setEnglish(true)
    const { upgradeReason } = useSystemLabels()
    expect(upgradeReason('升级代理未就绪：缺少 HMAC 密钥；自检尚未完成', 'AGENT_NOT_READY')).toBe(
      'Upgrade agent not ready: HMAC secret is missing (HMAC_SECRET / HMAC_SECRET_FILE); Self-check has not completed yet'
    )
  })

  test('英文侧 AGENT_NOT_READY：无前缀原文回默认文案', () => {
    setEnglish(true)
    const { upgradeReason } = useSystemLabels()
    expect(upgradeReason('完全未知的中文原文', 'AGENT_NOT_READY')).toBe('Upgrade agent not ready')
  })

  test('英文侧无 code：已知代理原文按正则映射，未知原样保留', () => {
    setEnglish(true)
    const { upgradeReason } = useSystemLabels()
    expect(upgradeReason('镜像仓库白名单为空', null)).toBe(
      'Image registry allowlist is empty (HOT_UPGRADE_REGISTRY_ALLOWLIST is empty; an empty allowlist denies all upgrades)'
    )
    expect(upgradeReason('前所未见的原文', null)).toBe('前所未见的原文')
  })
})
