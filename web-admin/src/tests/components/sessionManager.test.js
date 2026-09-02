/**
 * 登录会话（设备级会话管理）前端回归
 *
 * 分三组，各自防的是不同类型的静默失效：
 *
 *  1. schema 组：会话列表的 sid / current 是**功能正确性**依赖字段。
 *     sid 缺失 → 踢除按钮拿不到目标，点了没反应；current 缺失 →「本设备」
 *     标记消失，用户可能试图把自己踢下线。两者都不会报错，只会行为不对。
 *
 *  2. 组件静态不变量：jsdom 无法断言 CSS 变量与真实交互链路，改用源码约束
 *     兜住几条易回退的决定——当前设备禁用踢除、失败清空列表、
 *     currentSidPresent 用 !== false 判断、色值走 --xf-* 变量。
 *
 *  3. api 封装：`others` 必须是固定字面量而非走 :sid 分支；sid 拼接必须
 *     encodeURIComponent。走错分支会被后端 UUID 校验拒为 400。
 */
import { describe, test, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { SessionItemSchema, SessionListResponseSchema } from '@/schemas'

const readSrc = (rel) => readFileSync(resolve(__dirname, '../..', rel), 'utf8')

/** 一条完整的会话项（对应后端 UserSession.toClientJSON 的输出） */
const validItem = () => ({
  sid: '550e8400-e29b-41d4-a716-446655440000',
  current: true,
  deviceType: 'desktop',
  browser: 'Chrome',
  browserVersion: '120',
  os: 'Windows',
  osVersion: '10',
  deviceVendor: '',
  deviceModel: '',
  engine: 'Blink',
  cpu: 'amd64',
  userAgent:
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
  ip: '203.0.113.45',
  lastIp: '203.0.113.45',
  createdAt: '2026-08-28T01:00:00.000Z',
  lastSeenAt: '2026-08-28T02:00:00.000Z',
  expiresAt: '2026-09-04T01:00:00.000Z',
})

describe('SessionItemSchema（会话项形状）', () => {
  test('接受后端完整输出', () => {
    expect(SessionItemSchema.safeParse(validItem()).success).toBe(true)
  })

  test('sid 缺失/空串必须报漂移（踢除按钮会拿不到目标）', () => {
    const noSid = { ...validItem() }
    delete noSid.sid
    expect(SessionItemSchema.safeParse(noSid).success).toBe(false)
    expect(SessionItemSchema.safeParse({ ...validItem(), sid: '' }).success).toBe(false)
  })

  test('current 缺失或非布尔必须报漂移（「本设备」标记会消失）', () => {
    const noCurrent = { ...validItem() }
    delete noCurrent.current
    expect(SessionItemSchema.safeParse(noCurrent).success).toBe(false)
    expect(SessionItemSchema.safeParse({ ...validItem(), current: 'true' }).success).toBe(false)
  })

  test('展示字段缺失或为 null 不报漂移（界面显示「未知」即可）', () => {
    // 宽进严出：这些字段只影响展示，为它们告警等于制造噪音
    const partial = { sid: validItem().sid, current: false }
    expect(SessionItemSchema.safeParse(partial).success).toBe(true)
    expect(
      SessionItemSchema.safeParse({
        ...partial,
        browser: null,
        os: null,
        ip: null,
        lastSeenAt: null,
      }).success
    ).toBe(true)
    // 新增的详细字段同样一律可缺失：旧后端不返回它们时不应告警
    expect(
      SessionItemSchema.safeParse({
        ...partial,
        browserVersion: null,
        osVersion: null,
        deviceVendor: null,
        deviceModel: null,
        engine: null,
        cpu: null,
        userAgent: null,
      }).success
    ).toBe(true)
  })

  test('详细字段类型错误仍要报漂移（拼接设备名会得到 "[object Object]"）', () => {
    const base = validItem()
    for (const key of [
      'browserVersion',
      'osVersion',
      'deviceVendor',
      'deviceModel',
      'engine',
      'cpu',
      'userAgent',
    ]) {
      expect(SessionItemSchema.safeParse({ ...base, [key]: { v: 1 } }).success).toBe(false)
    }
    // 版本号后端一律以字符串下发（主版本号），给数字即为口径漂移
    expect(SessionItemSchema.safeParse({ ...base, browserVersion: 120 }).success).toBe(false)
  })

  test('允许后端新增字段（不因多一个字段就告警）', () => {
    const r = SessionItemSchema.safeParse({ ...validItem(), riskScore: 3 })
    expect(r.success).toBe(true)
    expect(r.data.riskScore).toBe(3)
  })
})

describe('SessionListResponseSchema（列表响应）', () => {
  const envelope = (data) => ({ success: true, message: '获取成功', data })

  test('接受正常列表响应', () => {
    const r = SessionListResponseSchema.safeParse(
      envelope({ sessions: [validItem()], total: 1, currentSidPresent: true })
    )
    expect(r.success).toBe(true)
  })

  test('空列表合法（用户刚清空其他设备时就是这个形状）', () => {
    expect(SessionListResponseSchema.safeParse(envelope({ sessions: [] })).success).toBe(true)
  })

  test('sessions 非数组必须报漂移（组件会按数组渲染）', () => {
    expect(SessionListResponseSchema.safeParse(envelope({ sessions: {} })).success).toBe(false)
    expect(SessionListResponseSchema.safeParse(envelope({})).success).toBe(false)
  })

  test('数组中任一条目缺 sid 即整体报漂移', () => {
    const bad = { ...validItem() }
    delete bad.sid
    expect(
      SessionListResponseSchema.safeParse(envelope({ sessions: [validItem(), bad] })).success
    ).toBe(false)
  })

  test('currentSidPresent 可缺失（旧后端不返回该字段）', () => {
    expect(SessionListResponseSchema.safeParse(envelope({ sessions: [validItem()] })).success).toBe(
      true
    )
  })
})

describe('SessionManager 组件不变量', () => {
  const source = readSrc('components/SessionManager.vue')

  test('当前设备的踢除按钮被禁用，且给出原因提示', () => {
    // 后端也会拒（400），但用户拿到的会是一句莫名的报错而非「这是当前设备」
    expect(source).toContain(':disabled="item.current || revoking === item.sid"')
    expect(source).toContain("t('session.cannotRevokeCurrent')")
  })

  test('revokeOne 对当前设备直接返回，不发请求', () => {
    expect(source).toContain('if (item.current) return')
  })

  test('currentSidPresent 用 !== false 判断（旧后端字段缺失不应误提示）', () => {
    expect(source).toContain('resp.data?.currentSidPresent !== false')
    // 只看赋值语句本身：注释里刻意引用了错误写法作为反例，
    // 直接对全文做 not.toContain 会被注释命中（这条断言第一版就是这么误报的）
    const assignment = source
      .split('\n')
      .find((line) => /^\s*currentSidPresent\.value\s*=/.test(line))
    expect(assignment).toBeTruthy()
    // 反面写法会把 undefined 也当成「不含 sid」，对正常用户弹出无意义的提示
    expect(assignment).not.toContain('!resp.data?.currentSidPresent')
  })

  test('otherCount 排除当前设备（它只能通过退出登录结束）', () => {
    expect(source).toContain('sessions.value.filter((s) => !s.current).length')
    expect(source).toContain('otherCount === 0')
  })

  test('吊销成功后重新拉取列表而非本地剔除', () => {
    // 本地删一条会让列表与服务端不一致，而这个列表的全部价值就是反映真实情况
    const revokeBlock = source.slice(
      source.indexOf('const revokeOne'),
      source.indexOf('const revokeOthers')
    )
    expect(revokeBlock).toContain('await load()')
    expect(revokeBlock).not.toContain('splice')
  })

  test('两处危险操作都有二次确认', () => {
    expect(source).toContain("t('session.revokeConfirm'")
    expect(source).toContain("t('session.revokeOthersConfirm'")
  })

  test('请求失败清空列表，不展示上一次的过期数据', () => {
    const loadBlock = source.slice(
      source.indexOf('const load ='),
      source.indexOf('const revokeOne')
    )
    expect(loadBlock).toContain('sessions.value = []')
  })

  test('主标题优先用设备型号（多台同系统设备的唯一区分依据）', () => {
    // 三条「Chrome · Android」并排时用户无法判断哪台不是自己的，
    // 而「Xiaomi 13」一眼可辨
    expect(source).toContain('const deviceName = (item) =>')
    const block = source.slice(
      source.indexOf('const deviceName'),
      source.indexOf('const softwareLine')
    )
    expect(block).toContain('item.deviceVendor')
    expect(block).toContain('item.deviceModel')
    // 型号缺失（桌面浏览器常见）必须回退到浏览器+系统，不能显示空白
    expect(block).toContain('item.browser')
    expect(block).toContain("t('session.unknownDevice')")
  })

  test('软件环境行无内容时整行不渲染（避免空行看似渲染失败）', () => {
    expect(source).toContain('v-if="softwareLine(item)"')
  })

  test('技术详情默认折叠，且展开状态不随刷新丢失', () => {
    // 挂在数据上的 expanded 字段会被 load() 整体替换掉，用户点开又刷新就白点了
    expect(source).toContain('const expanded = ref(new Set())')
    expect(source).toContain('v-if="expanded.has(item.sid)"')
    // 重建 Set 而非原地 add/delete：ref 包 Set 时原地修改不触发更新
    expect(source).toContain('const next = new Set(expanded.value)')
  })

  test('详情开关暴露 aria-expanded（折叠状态对辅助技术可见）', () => {
    expect(source).toContain(':aria-expanded="String(expanded.has(item.sid))"')
  })

  test('详情用 dl/dt/dd 表达「字段名—值」关系', () => {
    // 用 div 堆叠时屏幕阅读器无法把标签与取值关联起来
    expect(source).toContain('<dl')
    expect(source).toContain('<dt>')
    expect(source).toContain('<dd')
  })

  test('登录 IP 仅在与最近活动 IP 不同时展示', () => {
    // 相同时展示只是重复噪音；不同则是「令牌被挪到别处使用」的关键线索
    expect(source).toContain('item.ip !== item.lastIp')
  })

  test('原始 UA 允许断行（否则会把列表撑出横向滚动条）', () => {
    const uaBlock = source.slice(
      source.indexOf('.session-ua {'),
      source.indexOf('.session-revoke {')
    )
    expect(uaBlock).toContain('word-break: break-all')
  })

  test('非浏览器客户端打警示标签（不能伪装成正常浏览器登录）', () => {
    expect(source).toContain("item.deviceType === 'bot'")
    expect(source).toContain("t('session.botDevice')")
  })

  test('不写死背景色值：样式一律走 --xf-* 变量', () => {
    const hardcoded = source
      .split('\n')
      .filter((line) => /^\s*background(-color)?\s*:/.test(line))
      .filter((line) => /#[0-9a-fA-F]{3,8}\b/.test(line))
    expect(hardcoded).toEqual([])
  })

  test('不引入中文裸键（新代码必须用规范键）', () => {
    expect(/(?:\$t|\bt)\(\s*'[^']*[\u4e00-\u9fa5]/.test(source)).toBe(false)
  })
})

describe('ProfileView 挂载登录会话卡片', () => {
  const source = readSrc('views/ProfileView.vue')

  test('引入并渲染 SessionManager', () => {
    expect(source).toContain("import SessionManager from '@/components/SessionManager.vue'")
    expect(source).toContain('<SessionManager />')
    expect(source).toContain("$t('session.title')")
  })

  test('登录会话卡片位于「安全设置」栏（与改密、两步验证同栏）', () => {
    // 分栏错位会让用户在「基本信息」里找账号安全设置，
    // 这类问题 jsdom 断言不出来（栅格是 CSS 行为），只能以结构顺序约束
    //
    // D-2 组件化后：两步验证卡片已抽为 MfaSettingsCard.vue，
    // 其标题键在该组件内；顺序断言拆为「视图内渲染顺序」+「组件内标题键」
    const securityTitleIdx = source.indexOf("$t('profile.security')")
    const sessionCardIdx = source.indexOf("$t('session.title')")
    const mfaCardIdx = source.indexOf('<MfaSettingsCard')
    expect(securityTitleIdx).toBeGreaterThan(-1)
    expect(securityTitleIdx).toBeLessThan(sessionCardIdx)
    expect(sessionCardIdx).toBeLessThan(mfaCardIdx)
    const mfaCardSource = readSrc('components/MfaSettingsCard.vue')
    expect(mfaCardSource).toContain("t('profile.mfaTitle')")
  })
})

describe('ProfileView 两栏布局不变量', () => {
  const source = readSrc('views/ProfileView.vue')

  test('两栏各有分区标题，且用真实标题元素（可按标题导航）', () => {
    const titles = source.match(/<h2 class="profile-section-title">/g) || []
    expect(titles).toHaveLength(2)
    expect(source).toContain("$t('profile.basicInfo')")
    expect(source).toContain("$t('profile.security')")
  })

  test('左右两栏栅格相加为 24（否则右栏会被挤到下一行）', () => {
    // md 与 lg 两档都要成立：漏配一档时该断点下布局会突然折行，
    // 而开发通常只在一种窗口宽度下看效果，很容易漏
    const mdValues = [...source.matchAll(/:md="(\d+)"/g)].map((m) => Number(m[1]))
    const lgValues = [...source.matchAll(/:lg="(\d+)"/g)].map((m) => Number(m[1]))
    expect(mdValues).toHaveLength(2)
    expect(lgValues).toHaveLength(2)
    expect(mdValues.reduce((a, b) => a + b, 0)).toBe(24)
    expect(lgValues.reduce((a, b) => a + b, 0)).toBe(24)
  })

  test('窄屏两栏均为整行（xs=24），不出现横向挤压', () => {
    const xsValues = [...source.matchAll(/:xs="(\d+)"/g)].map((m) => Number(m[1]))
    expect(xsValues).toEqual([24, 24])
  })

  test('卡片间距与表单宽度走统一类，不再逐处内联 style', () => {
    // 内联写法此前散落四处 margin-top 与两个不同的 max-width 值，
    // 改一处漏三处是必然的
    expect(source).not.toContain('style="margin-top: 16px;"')
    expect(source).not.toContain('style="max-width: 500px"')
    expect(source).not.toContain('style="max-width: 560px"')
    expect(source).toContain('.profile-block')
    expect(source).toContain('.profile-form')
  })

  test('单栏折叠断点与 Element Plus 的 md 起点一致（≥992px）', () => {
    // 本页只声明 xs/md/lg，768~991px 实际仍是单栏；
    // 按 768px 写媒体查询会让这段区间的两个分区黏在一起
    expect(source).toContain('@media (max-width: 991px)')
  })

  test('分区标题与间距不写死色值/字号，走 --xf-* 变量', () => {
    const block = source.slice(
      source.indexOf('.profile-section-title {'),
      source.indexOf('.profile-block {')
    )
    expect(block).toContain('var(--xf-')
    expect(/#[0-9a-fA-F]{3,8}\b/.test(block)).toBe(false)
  })
})

describe('api.auth 会话方法', () => {
  const source = readSrc('utils/api.js')

  test('sid 经 encodeURIComponent 后拼接（路径参数不裸拼）', () => {
    expect(source).toContain('`/auth/sessions/${encodeURIComponent(sid)}`')
  })

  test('退出其他设备走固定字面量路径，不复用 :sid 分支', () => {
    // 走 :sid 分支会被后端 UUID 校验拒为 400
    expect(source).toContain("revokeOtherSessions: () => apiClient.delete('/auth/sessions/others')")
  })

  test('schema 路由表里 /auth/sessions 声明在 /auth/session 之前', () => {
    // includes 匹配没有边界概念：'/auth/session' 是 '/auth/sessions' 的前缀，
    // 顺序颠倒会让会话列表按「只含 authenticated 布尔」的 schema 校验并全部报漂移
    const sessionsIdx = source.indexOf("match: '/auth/sessions'")
    const sessionIdx = source.indexOf("match: '/auth/session'")
    expect(sessionsIdx).toBeGreaterThan(-1)
    expect(sessionsIdx).toBeLessThan(sessionIdx)
  })

  test('会话列表 schema 绑定 GET 方法（DELETE 返回 { sid } 形状不同）', () => {
    // 不区分方法会让每次踢除设备都误报一次漂移；告警一旦出现假阳性，
    // 真正的漂移就会被当成噪音忽略
    expect(source).toContain("match: '/auth/sessions', method: 'get'")
    expect(source).toContain("String(response.config?.method || 'get').toLowerCase() === r.method")
  })
})

describe('i18n session 命名空间', () => {
  test('组件引用的每个 session.* 键在两种语言下都存在', async () => {
    const zh = (await import('@/i18n/locales/zh-CN')).default
    const en = (await import('@/i18n/locales/en-US')).default
    const source = readSrc('components/SessionManager.vue') + readSrc('views/ProfileView.vue')

    const used = [
      ...new Set(
        [...source.matchAll(/(?:\$t|\bt)\(\s*'(session\.[A-Za-z0-9_]+)'/g)].map((m) =>
          m[1].slice('session.'.length)
        )
      ),
    ]
    expect(used.length).toBeGreaterThan(0)

    // 缺键时 vue-i18n 原样返回键名，界面会渲染出 "session.title" 这种字面量
    expect(used.filter((k) => !(k in (zh.session || {})))).toEqual([])
    expect(used.filter((k) => !(k in (en.session || {})))).toEqual([])
  })

  test('两种语言的 session 键集合完全一致', async () => {
    const zh = (await import('@/i18n/locales/zh-CN')).default
    const en = (await import('@/i18n/locales/en-US')).default
    expect(Object.keys(zh.session).sort()).toEqual(Object.keys(en.session).sort())
  })

  test('英文词条不含中文（真正翻译过而非复制原文）', async () => {
    const en = (await import('@/i18n/locales/en-US')).default
    const untranslated = Object.entries(en.session)
      .filter(([, v]) => /[\u4e00-\u9fa5]/.test(String(v)))
      .map(([k]) => k)
    expect(untranslated).toEqual([])
  })

  test('带插值的词条两端占位符一致（缺失会渲染成空白）', async () => {
    const zh = (await import('@/i18n/locales/zh-CN')).default
    const en = (await import('@/i18n/locales/en-US')).default
    for (const key of ['activeCount', 'revokeOthersConfirm', 'revokedOthers']) {
      expect(zh.session[key]).toContain('{count}')
      expect(en.session[key]).toContain('{count}')
    }
    expect(zh.session.revokeConfirm).toContain('{device}')
    expect(en.session.revokeConfirm).toContain('{device}')
  })

  test('四个会话审计 action 在两种语言下都有名称', async () => {
    const zh = (await import('@/i18n/locales/zh-CN')).default
    const en = (await import('@/i18n/locales/en-US')).default
    for (const action of [
      'auth_sessions',
      'auth_sessions_others',
      'session_revoked',
      'session_revoked_others',
    ]) {
      // 白名单里有但词表里没有 → 审计页显示原始 action 码
      expect(zh.audit.action[action]).toBeTruthy()
      expect(en.audit.action[action]).toBeTruthy()
    }
  })
})
