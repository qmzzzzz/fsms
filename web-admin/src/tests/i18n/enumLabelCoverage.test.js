/**
 * 枚举 → 前端标签映射的跨端覆盖闸（第 17 轮 r17-web F3）
 *
 * 缺陷形态：后端枚举是唯一事实来源，前端却**手抄**成各自的映射表；缺键时界面不是报错而是
 * **静默渲染空**（InspectionView.vue:108 的 \`{{ typeMap[row.inspectionType] }}\`），
 * 于是「新增一档巡检类型」在前端表现为"这一列莫名其妙空着"，没有任何一处会红。
 * 变异实测（r17-web §F3）：后端枚举 +1 后跑相关前端用例 **全绿**；对照组把
 * AUDIT_LOG_ACTIONS +1 则 auditActionCoverage 立刻 3 failed/5 —— 证明"闸是真的、可证伪的"，
 * 缺的只是覆盖面。本文件把覆盖面补到巡检/报警两族。
 *
 * 判据取 **⊇**（前端映射必须覆盖后端全集）而不是等值：前端映射里允许存在视图专用的
 * 附加键（如 resultMap 的展示档），但后端每一个值都必须有落点。反向的死键检查另有
 * 一处成本：前端可能有跨枚举复用的标签，故这里只对"键即枚举值"的映射做双向核对。
 *
 * 后端枚举**直接 require**，不在本文件手抄——手抄等于把对账退化成复制。
 */
import { describe, test, expect } from 'vitest'
import { createRequire } from 'node:module'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, resolve } from 'node:path'
import { makeAlarmTypeLabels, makeAlarmStatusLabels } from '@/utils/labelMaps'

const require = createRequire(import.meta.url)
const { ALARM_TYPES, ALARM_STATUSES, ALARM_CAUSES } = require('../../../../src/constants/alarm.js')
const {
  INSPECTION_TYPES,
  INSPECTION_STATUSES,
  INSPECTION_RESULTS,
} = require('../../../../src/constants/inspection.js')
const { PRIVILEGE_GRANT_STATUSES } = require('../../../../src/constants/privilegeGrant.js')

const HERE = dirname(fileURLToPath(import.meta.url))
const webSrc = (rel) => readFileSync(resolve(HERE, '../../', rel), 'utf8')

/**
 * 从源码里抠出「对象字面量的顶层键」。
 * anchor 找不到时**抛出**而不是返回空集——返回空集会让上面的覆盖断言在解析失败时静默通过。
 */
const keysAfter = (src, anchor) => {
  const at = src.indexOf(anchor)
  if (at < 0) throw new Error(`锚点未命中（映射被改名/挪走后本闸必须红）：${anchor}`)
  const start = src.indexOf('{', at + anchor.length - 1)
  if (start < 0) throw new Error(`锚点之后没有对象字面量：${anchor}`)
  let depth = 0
  let end = -1
  for (let i = start; i < src.length; i += 1) {
    const c = src[i]
    if (c === '{') depth += 1
    else if (c === '}') {
      depth -= 1
      if (depth === 0) {
        end = i
        break
      }
    }
  }
  if (end < 0) throw new Error(`对象字面量未闭合：${anchor}`)
  const body = src.slice(start + 1, end)
  const keys = []
  let d = 0
  for (const line of body.split('\n')) {
    const trimmed = line.trim()
    if (d === 0) {
      const m = /^([A-Za-z_$][\w$]*):/.exec(trimmed)
      if (m) keys.push(m[1])
    }
    d += (line.match(/[{([]/g) || []).length - (line.match(/[})\]]/g) || []).length
  }
  return keys
}

/**
 * 剥掉模板注释 `<!-- ... -->`：按**等长空白**替换（保留偏移与行列结构，出错时便于定位）。
 * 为什么必须是整文件正则而不是按行过滤：注释块可以跨行，而 optionValues 的判据就是整文件正则
 * ——按行过滤只挡得住「一行里既有 `<!--` 又有 `-->`」这一种形态，跨行块会被漏掉一半。
 * 与 \`ci/tautologyGuard.test.js\` 的 stripComments 同族（那个剥 JS 注释），但**不并入它**：
 * 两处扫描面不同（模板 vs JS），合并会把 JS 注释口径带到模板文本上。
 */
const stripHtmlComments = (src) =>
  src.replace(/<!--[\s\S]*?-->/g, (block) => block.replace(/[^\n]/g, ' '))

/**
 * `<el-option value="daily">` 形态的取值集合。
 * 扫描前先剥模板注释——注释掉的选项在运行时不产生条目，不剥就会把「被注释掉的这一档」算成还在。
 * 同文件的口径分叉（留个说明，免得下次再并错）：keysAfter / valuesAfter 走对象字面量与数组字面量，
 * 整行注释天然被它们的行级判断跳过；本函数扫的是模板文本，只能显式剥注释。
 * ⇒ 「注释掉」在两种载体上的表现不同，两处判据的注释口径**不可互相套用**。
 */
const optionValues = (src) =>
  [...stripHtmlComments(src).matchAll(/<el-option\b[^>]*value="([^"]+)"/g)].map((m) => m[1])

/**
 * 视图内手写选项数组（`{ value: 'pending', label: ... }`）的 value 取值集合。
 * 这是 `<el-option>` 之外的第二种手抄形态：整表写在 `<script setup>` 里，模板里看不见。
 * 整行注释跳过——否则「把某档注释掉」会被算成「这一档还在」（注释里的值在运行时不产生条目）。
 * 与 keysAfter 一样，锚点找不到时**抛出**而不是返回空集。
 */
const valuesAfter = (src, anchor) => {
  const at = src.indexOf(anchor)
  if (at < 0) throw new Error('锚点未命中（选项表被改名/挪走后本闸必须红）：' + anchor)
  const start = src.indexOf('[', at + anchor.length - 1)
  if (start < 0) throw new Error('锚点之后没有数组字面量：' + anchor)
  const stack = []
  const pair = { '[': ']', '{': '}', '(': ')' }
  let end = -1
  for (let i = start; i < src.length; i += 1) {
    const c = src[i]
    if (pair[c]) stack.push(pair[c])
    else if (c === ']' || c === '}' || c === ')') {
      if (stack.pop() !== c) throw new Error('括号不配对，解析已不可信：' + anchor)
      if (stack.length === 0) {
        end = i
        break
      }
    }
  }
  if (end < 0) throw new Error('数组字面量未闭合：' + anchor)
  const out = []
  for (const line of src.slice(start + 1, end).split('\n')) {
    const code = line.trim()
    if (code.startsWith('//') || code.startsWith('/*') || code.startsWith('*')) continue
    for (const m of line.matchAll(/value:\s*'([^']*)'/g)) out.push(m[1])
  }
  return out
}

const missingOf = (expected, actual) => expected.filter((v) => !actual.includes(v)).sort()

describe('前端枚举映射覆盖后端全集（伪装成"渲染空"的静默漂移）', () => {
  const inspectionView = webSrc('views/InspectionView.vue')
  const inspectionForm = webSrc('components/InspectionForm.vue')
  const alarmView = webSrc('views/AlarmView.vue')
  const grantView = webSrc('views/PrivilegeGrantView.vue')

  test('前提自证：七族枚举都非空且唯一（对账对象被清空时不得静默通过）', () => {
    const families = [
      INSPECTION_TYPES,
      INSPECTION_STATUSES,
      INSPECTION_RESULTS,
      ALARM_TYPES,
      ALARM_STATUSES,
      ALARM_CAUSES,
      PRIVILEGE_GRANT_STATUSES,
    ]
    families.forEach((f) => {
      expect(Array.isArray(f)).toBe(true)
      expect(f.length).toBeGreaterThan(1)
      expect(new Set(f).size).toBe(f.length)
    })
  })

  test('解析器自证：真源码能抠出键，少一个键立刻被 diff 抓到', () => {
    const real = keysAfter(inspectionView, 'const typeMap = computed(() => (')
    expect(real).toContain('daily')
    expect(missingOf(INSPECTION_TYPES, real)).toEqual([])
    // 反向对照：把 daily 从副本里删掉，同一条判据必须报出 daily
    const mutated = inspectionView.replace(/\n\s*daily: t\('inspection\.typeDaily'\),/, '\n')
    expect(
      missingOf(INSPECTION_TYPES, keysAfter(mutated, 'const typeMap = computed(() => ('))
    ).toEqual(['daily'])
  })

  test('巡检类型：视图表 + 表单选项都覆盖 INSPECTION_TYPES', () => {
    expect(
      missingOf(INSPECTION_TYPES, keysAfter(inspectionView, 'const typeMap = computed(() => ('))
    ).toEqual([])
    expect(missingOf(INSPECTION_TYPES, optionValues(inspectionForm))).toEqual([])
  })

  // 本文件「解析器自证」(:153) 的对应项：剥注释这一步必须**自己**被测到——
  // 只加一个没人管的新函数，等于把闸从「正则扫全文」换成「正则扫一个未经检验的字符串」，
  // 闸的名字还在、牙齿没了。
  test('判据可失败：被 <!-- --> 注释掉的 el-option 不得算成「选项还在」', () => {
    // ① 正面对照：未注释的真源码必须照常采到（一刀切采空会让上面的覆盖断言静默通过）
    expect(optionValues(inspectionForm)).toContain('daily')
    expect(new Set(optionValues(inspectionForm)).size).toBeGreaterThanOrEqual(
      INSPECTION_TYPES.length
    )
    // ② 整行注释：daily 那行被 <!-- --> 包起来（运行时它不再渲染出任何选项）
    const lineCommented = inspectionForm.replace(
      /(\r?\n)([ \t]*)(<el-option[^>]*value="daily"[^>]*\/>)/,
      '$1$2<!-- $3 -->'
    )
    expect(missingOf(INSPECTION_TYPES, optionValues(lineCommented))).toContain('daily')
    // ③ 跨行注释块：判据是整文件正则，按行过滤的形态在这里会漏（见 stripHtmlComments 的说明）
    const blockCommented = inspectionForm.replace(
      /(\r?\n)([ \t]*)(<el-option[^>]*value="weekly"[^>]*\/>)/,
      '$1<!--$1$2$3$1-->'
    )
    expect(missingOf(INSPECTION_TYPES, optionValues(blockCommented))).toContain('weekly')
    // ④ 剥注释不得把后文一起吃掉：注释块**之后**的真选项仍须采到
    expect(optionValues(blockCommented)).toContain('monthly')
    // ⑤ 剥注释保留行列结构（等长空白替换）：注释块占几行，剥完仍占几行。
    // 这条把「按空白替换」这一实现约定也钉住——否则它只是注释里的一句话，谁都能改成直接删掉。
    expect(stripHtmlComments(blockCommented).split('\n').length).toBe(
      blockCommented.split('\n').length
    )
  })
  test('巡检状态与结果：视图表覆盖后端全集', () => {
    expect(
      missingOf(
        INSPECTION_STATUSES,
        keysAfter(inspectionView, 'const statusMap = computed(() => (')
      )
    ).toEqual([])
    expect(
      missingOf(INSPECTION_RESULTS, keysAfter(inspectionView, 'const resultMap = computed(() => ('))
    ).toEqual([])
  })

  test('报警原因：AlarmView 的 CAUSE_OPTIONS 覆盖 ALARM_CAUSES', () => {
    const values = [...alarmView.matchAll(/\{\s*value:\s*'([^']+)'/g)].map((m) => m[1])
    expect(values.length).toBeGreaterThanOrEqual(ALARM_CAUSES.length)
    expect(missingOf(ALARM_CAUSES, values)).toEqual([])
  })

  test('报警类型与状态：labelMaps 的键覆盖后端全集（键即枚举值）', () => {
    expect(missingOf(ALARM_TYPES, Object.keys(makeAlarmTypeLabels((k) => k)))).toEqual([])
    expect(missingOf(ALARM_STATUSES, Object.keys(makeAlarmStatusLabels((k) => k)))).toEqual([])
  })

  test('反向：labelMaps 里没有后端不认识的键（死键永远不会被渲染）', () => {
    const deadTypes = Object.keys(makeAlarmTypeLabels((k) => k)).filter(
      (k) => !ALARM_TYPES.includes(k)
    )
    const deadStatus = Object.keys(makeAlarmStatusLabels((k) => k)).filter(
      (k) => !ALARM_STATUSES.includes(k)
    )
    expect({ deadTypes, deadStatus }).toEqual({ deadTypes: [], deadStatus: [] })
  })

  // ── 授权状态族（第 17 轮交付时漏掉的第三族）────────────────────────────
  // 后端 src/constants/privilegeGrant.js:5 是 5 档的单一来源，视图却手抄了三处。
  // 缺键的后果与巡检族同型：statusLabel() 走 statusUnknown 兜底 ⇒ 新档在界面上
  // 显示「未知状态」，而没有任何一处会红（端到端实测：后端 +1 档，视图套件零红）。
  // 三处**都要断言**：只查其中一处，就是「同一不变量查两处、闸只查一处」——
  // 正是本闸要消灭的那个形态本身。
  test('授权状态：视图的三处手抄表都覆盖 PRIVILEGE_GRANT_STATUSES', () => {
    expect(
      missingOf(PRIVILEGE_GRANT_STATUSES, keysAfter(grantView, 'const STATUS_LABEL_KEYS = {'))
    ).toEqual([])
    expect(
      missingOf(PRIVILEGE_GRANT_STATUSES, keysAfter(grantView, 'const STATUS_TAG_TYPES = {'))
    ).toEqual([])
    expect(
      missingOf(
        PRIVILEGE_GRANT_STATUSES,
        valuesAfter(grantView, 'const statusOptions = computed(() =>')
      )
    ).toEqual([])
  })

  test('反向：授权状态的两张键值表没有后端不认识的档（死键渲染不出来）', () => {
    const labelKeys = keysAfter(grantView, 'const STATUS_LABEL_KEYS = {')
    const tagKeys = keysAfter(grantView, 'const STATUS_TAG_TYPES = {')
    expect({
      deadLabelKeys: labelKeys.filter((k) => !PRIVILEGE_GRANT_STATUSES.includes(k)),
      deadTagKeys: tagKeys.filter((k) => !PRIVILEGE_GRANT_STATUSES.includes(k)),
    }).toEqual({ deadLabelKeys: [], deadTagKeys: [] })
  })

  // 与「解析器自证」同款的反向对照：**三处表各自**少一档都必须被同一条判据抓到。
  // 少了这条，上面那条用例可能只是「三处里恰好有一处齐」，另两处的断言是装饰。
  // 断言用 toContain 而不是 toEqual：本用例只对「被删掉的那一档有没有被报出来」负责。
  // 若写成 toEqual，后端枚举自身发生变化时（例如 §5 注入变异）它会因多出一个缺失项而**次生红**，
  // 把唯一的真信号埋进噪声——对照面必须在外部变异下也稳定。
  test('判据可失败：三处表各自少一档都必须被同一条判据抓到', () => {
    // ① STATUS_LABEL_KEYS 少 revoked
    const noLabel = grantView.replace(/\r?\n\s*revoked: 'privilegeGrant\.statusRevoked',/, '')
    expect(
      missingOf(PRIVILEGE_GRANT_STATUSES, keysAfter(noLabel, 'const STATUS_LABEL_KEYS = {'))
    ).toContain('revoked')
    // ② STATUS_TAG_TYPES 少 expired（该行值是 info，与另外两张表不撞车）
    const noTag = grantView.replace(/\r?\n\s*expired: 'info',/, '')
    expect(
      missingOf(PRIVILEGE_GRANT_STATUSES, keysAfter(noTag, 'const STATUS_TAG_TYPES = {'))
    ).toContain('expired')
    // ③ statusOptions 少 rejected（整行注释掉：注释不产生条目）
    const noOption = grantView.replace(/\r?\n(\s*)({ value: 'rejected',)/, '\r\n$1// $2')
    expect(
      missingOf(
        PRIVILEGE_GRANT_STATUSES,
        valuesAfter(noOption, 'const statusOptions = computed(() =>')
      )
    ).toContain('rejected')
  })
})
