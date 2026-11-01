/**
 * 系统内置文案的本地化词表（角色 / 权限 / 升级就绪原因）
 *
 * 为什么单独成文件而不是写进 locales/*.js：
 *  - 这三类文案的**取值来源**是后端或部署环境（角色表 code、权限目录 code、
 *    upgradeService 的 readiness），不是前端静态界面文案库；
 *  - 中文侧必须与既有行为逐字一致（后端下发的 name 原样展示），因此只在
 *    英文界面下按稳定 code / 原因码做映射，中文侧继续用后端原文，
 *    避免把「系统预设」和「用户数据」混为一谈（用户自建角色/权限不翻译）。
 *
 * 响应式约定：本模块的函数在渲染期读取 locale，页内切换语言即时生效；
 * 不要在模块顶层把 locale 固化进字符串。
 */
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'

/** 内置角色（roles.js defaultRoles）：name / description 按 code 映射 */
const ROLE_LABELS = {
  'zh-CN': {
    SUPER_ADMIN: { name: '超级管理员', description: '拥有系统全部权限' },
    SECURITY_ADMIN: { name: '安全管理员', description: '负责用户管理和权限分配' },
    AUDIT_VIEWER: {
      name: '审计监督员',
      description: '只读审计日志与安全统计，供外部审计/上级监督使用（无任何写权限）',
    },
    FIRE_SUPERVISOR: { name: '消防主管', description: '负责报警处理和巡检审核' },
    FIREFIGHTER: { name: '普通消防员', description: '执行巡检和设备查看' },
    GUEST: { name: '访客', description: '只读基础信息' },
  },
  'en-US': {
    SUPER_ADMIN: { name: 'Super Administrator', description: 'Full system permissions' },
    SECURITY_ADMIN: {
      name: 'Security Administrator',
      description: 'User management and permission assignment',
    },
    AUDIT_VIEWER: {
      name: 'Audit Supervisor',
      description:
        'Read-only audit logs and security statistics for external audit or oversight (no write permissions)',
    },
    FIRE_SUPERVISOR: {
      name: 'Fire Supervisor',
      description: 'Alarm handling and inspection review',
    },
    FIREFIGHTER: { name: 'Firefighter', description: 'Inspection execution and device viewing' },
    GUEST: { name: 'Guest', description: 'Read-only access to basic information' },
  },
}

/**
 * 权限目录（permissionsSystem.js + permissionsBusiness.js）的英文名。
 * 中文侧不使用本表：后端 name 是唯一事实来源，改了目录中文名这里不会漂移。
 */
const PERMISSION_LABELS_EN = {
  'system:*': 'System Management',
  'system:read': 'View Sensitive Information',
  'user:*': 'User Management',
  'user:read': 'View Users',
  'user:create': 'Create User',
  'user:update': 'Edit User',
  'user:delete': 'Delete User',
  'user:assign_role': 'Assign Roles',
  'user:lock': 'Lock / Unlock User',
  'user:reset_password': 'Reset User Password',
  'role:*': 'Role Management',
  'role:read': 'View Roles',
  'role:create': 'Create Role',
  'role:update': 'Edit Role',
  'role:delete': 'Delete Role',
  'role:assign': 'Assign Permissions',
  'permission:*': 'Permission Management',
  'permission:read': 'View Permissions',
  'permission:tree': 'Get Permission Tree',
  'permission:create': 'Create Permission',
  'permission:update': 'Update Permission',
  'permission:delete': 'Delete Permission',
  'security:*': 'Security Management',
  'security:stats': 'View Security Statistics',
  'security:audit': 'View Audit Logs',
  'security:config': 'Security Configuration',
  'privilege:*': 'Temporary Privilege Grants',
  'privilege:read': 'View Temporary Grants',
  'privilege:grant': 'Request Temporary Grant',
  'privilege:approve': 'Approve Temporary Grant',
  'device:*': 'Device Management',
  'device:read': 'View Devices',
  'device:create': 'Create Device',
  'device:update': 'Edit Device',
  'device:delete': 'Delete Device',
  'device:maintain': 'Device Maintenance',
  'device:scrap': 'Scrap Device',
  'device:stats': 'Device Statistics',
  'alarm:*': 'Alarm Management',
  'alarm:read': 'View Alarms',
  'alarm:create': 'Report Alarm',
  'alarm:dispatch': 'Dispatch Alarm',
  'alarm:handle': 'Handle Alarm',
  'alarm:stats': 'Alarm Statistics',
  'inspection:*': 'Inspection Management',
  'inspection:read': 'View Inspections',
  'inspection:create': 'Create Inspection Plan',
  'inspection:execute': 'Execute Inspection',
  'inspection:review': 'Review Inspection',
  'inspection:delete': 'Delete Inspection',
  'report:*': 'Reports',
  'report:read': 'View Reports',
  'report:export': 'Export Reports',
  'pii:*': 'Unmasked Export',
  'pii:export': 'Export Unmasked Personal Data',
  '*:*': 'All Permissions',
}

/**
 * 升级就绪原因：后端 readiness.codes 优先；老版本后端没有 codes 时按
 * 中文原文/前缀兜底，避免出现「英文界面下只剩一段中文」。
 */
const UPGRADE_REASON_CODES_EN = {
  UPGRADE_DISABLED: 'UPGRADE_ENABLED is not enabled',
  ALLOWLIST_EMPTY:
    'HOT_UPGRADE_REGISTRY_ALLOWLIST is empty (an empty allowlist denies all upgrades)',
  HMAC_SECRET_MISSING: 'HMAC_SECRET is not configured (cannot sign upgrade requests)',
  REQUESTS_DIR_UNWRITABLE:
    'Upgrade queue request directory is not writable (UPGRADE_QUEUE_DIR not mounted or permission denied)',
  STATUS_DIR_UNREADABLE:
    'Upgrade queue status directory is not readable (UPGRADE_QUEUE_DIR not mounted or permission denied)',
  AGENT_NEVER_REPORTED: 'Upgrade agent has never reported a heartbeat',
  AGENT_HEARTBEAT_STALE: 'Upgrade agent heartbeat has expired',
  CLOCK_SKEW:
    'Heartbeat time is ahead of the current time (host and application clocks are not synchronized)',
  AGENT_NOT_READY: 'Upgrade agent not ready',
}

const AGENT_REASON_TEXT_EN = [
  [
    /^镜像仓库白名单为空/,
    'Image registry allowlist is empty (HOT_UPGRADE_REGISTRY_ALLOWLIST is empty; an empty allowlist denies all upgrades)',
  ],
  [/^缺少 HMAC 密钥/, 'HMAC secret is missing (HMAC_SECRET / HMAC_SECRET_FILE)'],
  [/^HMAC 密钥短于 16 字符/, 'HMAC secret is shorter than 16 characters and cannot be verified'],
  [/^HMAC 密钥文件/, 'HMAC secret file is unreadable or invalid (HMAC_SECRET_FILE)'],
  [
    /^nginx 主配置不存在/,
    'nginx main configuration not found (file specified by --nginx-conf / HOT_UPGRADE_NGINX_CONF)',
  ],
  [/^另一个代理实例正在执行升级/, 'Another agent instance is running an upgrade'],
  [/^自检尚未完成/, 'Self-check has not completed yet'],
  [/^心跳时间晚于当前时间/, UPGRADE_REASON_CODES_EN.CLOCK_SKEW],
]

const translateAgentReason = (text) => {
  for (const [re, en] of AGENT_REASON_TEXT_EN) {
    if (re.test(text)) return en
  }
  return text
}

/** 当前语言是否英文（只认前缀，与 i18n 入口的判定口径一致） */
export const useSystemLabels = () => {
  // 只依赖 locale，且对缺位兜底：部分测试基座把 useI18n() 换成仅含 t 的替身
  // （见 useRolePermissionsToggle.test.js），若直接读 locale.value 会抛 TypeError，
  // 让「权限搜索/名称渲染」整条链断在本地化辅助函数里。
  const ctx = useI18n()
  const isEnglish = computed(() => String(ctx?.locale?.value ?? 'zh-CN').startsWith('en'))

  /**
   * 角色名：对象带 code 时英文按 code 映射；中文侧保留后端 name；
   * 仅当调用方只拿到 code 字符串（登录响应 user.roles 是 code 数组）时，
   * 用内置角色表补中文名。
   */
  const roleName = (role) => {
    const code = typeof role === 'string' ? role : role?.code
    const dict = ROLE_LABELS[isEnglish.value ? 'en-US' : 'zh-CN']
    const mapped = code ? dict[code] : null
    if (typeof role === 'string') return mapped?.name || role
    if (isEnglish.value && mapped?.name) return mapped.name
    return role?.name || code || ''
  }

  /** 角色描述：同样只在英文侧映射内置角色；自定义角色保留作者原文 */
  const roleDescription = (role) => {
    const code = typeof role === 'string' ? role : role?.code
    const mapped = code ? ROLE_LABELS['en-US'][code] : null
    if (isEnglish.value && mapped?.description) return mapped.description
    return (typeof role === 'object' && role?.description) || ''
  }

  /** 权限名：英文侧按 code 映射，中文与未知 code 一律用后端 name（唯一事实来源） */
  const permissionName = (perm) => {
    if (!perm) return ''
    if (typeof perm === 'string') return perm
    if (isEnglish.value && perm.code && PERMISSION_LABELS_EN[perm.code]) {
      return PERMISSION_LABELS_EN[perm.code]
    }
    return perm.name || perm.code || ''
  }

  /** 升级就绪原因：code 优先，其次按已知代理原文翻译；未知原文原样保留 */
  const upgradeReason = (reason, code) => {
    const text = typeof reason === 'string' ? reason : ''
    if (!isEnglish.value) return text
    if (code && code !== 'AGENT_NOT_READY' && UPGRADE_REASON_CODES_EN[code]) {
      return UPGRADE_REASON_CODES_EN[code]
    }
    if (code === 'AGENT_NOT_READY') {
      const match = text.match(/^升级代理未就绪[：:](.*)$/s)
      const nested = match
        ? match[1]
            .split('；')
            .map((s) => s.trim())
            .filter(Boolean)
            .map(translateAgentReason)
        : []
      return nested.length
        ? `Upgrade agent not ready: ${nested.join('; ')}`
        : UPGRADE_REASON_CODES_EN.AGENT_NOT_READY
    }
    return translateAgentReason(text)
  }

  return { isEnglish, roleName, roleDescription, permissionName, upgradeReason }
}

export default useSystemLabels
