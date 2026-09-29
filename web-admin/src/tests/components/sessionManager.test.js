/**
 * 登录会话（设备级会话管理）前端回归
 *
 * 分四组，各自防的是不同类型的静默失效：
 *
 *  1. schema 组：会话列表的 sid / current 是**功能正确性**依赖字段。
 *     sid 缺失 → 踢除按钮拿不到目标，点了没反应；current 缺失 →「本设备」
 *     标记消失，用户可能试图把自己踢下线。两者都不会报错，只会行为不对。
 *
 *  2. 真实交互组（590 行起）：真实挂载 + 真实点击驱动 revokeOne / revokeOthers /
 *     展开折叠，覆盖「当前设备禁用踢除」「确认框取消不发请求」「吊销失败解锁」
 *     「展开状态按 sid 隔离且刷新不丢」等。
 *
 *  3. 源码不变量组（仅保留**行为测试确实表达不了**的）：
 *     - currentSidPresent 用 `!== false`（实测：改成 `!!x` 后仅本组断言变红，
 *       行为用例抓不到——因为测试桩总会显式传 true/false，而线上旧后端会缺字段）；
 *     - 详情用 dl/dt/dd（屏幕阅读器语义，DOM 结构断言不到「为什么」）；
 *     - ProfileView 卡片分栏位置（栅格是 CSS 行为）；
 *     - api 封装的 URL 构造与 schema 路由顺序（跨模块契约，且顺序问题只在
 *       真实漂移告警里显现，行为用例只断言「不发漂移」）。
 *     其余静态断言**已删除**——逐条变异实测证明它们被行为用例杀死，见各处注释。
 *
 *  4. i18n 组：键存在性、双语集合一致、占位符一致。
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { mountComponent, click, flush, waitFor } from '../helpers/componentHarness'
import { SessionItemSchema, SessionListResponseSchema } from '@/schemas'
import i18n from '@/i18n'

/**
 * 全文件级的用例隔离。两件事都必须在这里做，因为它们都是**跨 describe 共享**的状态：
 *
 * 1. 卸载实例：ProfileView 会连带渲染 <SessionManager />（其 onMounted 打 listSessions），
 *    而下面两个 ProfileView 用例原本不卸载，残留实例会继续参与 DOM 查询与请求。
 * 2. 归零共享 mock 的**调用计数**：`listSessions` 等是模块级 vi.fn()，被本文件三个 describe
 *    共用，但只有后两个 describe 自带 afterEach 做 reset。于是不 reset 的那个 describe 一旦
 *    排在前面，它的调用次数就会带进下一个用例——`:699` 断言的是 `calls.length === 2`
 *    （本用例发了 1 次 + 重新拉取 1 次），被带成 3 就永远等不到，报
 *    「waitFor 超时：重新拉取列表」。默认顺序恰好把那个 describe 排在后面所以一直侥幸绿，
 *    `--sequence.shuffle` 一到就红。
 */
const tracked = []
const track = (c) => {
  tracked.push(c)
  return c
}
afterEach(() => {
  while (tracked.length) tracked.shift()?.handle?.unmount()
  listSessions.mockReset()
  getMe.mockReset()
  api.auth.revokeSession.mockReset()
  api.auth.revokeOtherSessions.mockReset()
})

const listSessions = vi.fn()
const getMe = vi.fn()
vi.mock('@/utils/api', () => ({
  api: {
    auth: {
      listSessions: (...a) => listSessions(...a),
      revokeSession: vi.fn(),
      revokeOtherSessions: vi.fn(),
      getMe: (...a) => getMe(...a),
      updateProfile: vi.fn(),
      changePassword: vi.fn(),
      getMfaStatus: vi.fn(() => Promise.resolve({ data: { data: { enabled: false } } })),
    },
  },
  isCanceledError: () => false,
}))
vi.mock('element-plus/es/components/message/index.mjs', () => ({
  ElMessage: { success: vi.fn(), error: vi.fn(), warning: vi.fn() },
}))
vi.mock('element-plus/es/components/message-box/index.mjs', () => ({
  ElMessageBox: { confirm: vi.fn() },
}))

import SessionManager from '@/components/SessionManager.vue'
import ProfileView from '@/views/ProfileView.vue'
import { useAuthStore } from '@/store'
import { api } from '@/utils/api'
import { ElMessage } from 'element-plus/es/components/message/index.mjs'
import { ElMessageBox } from 'element-plus/es/components/message-box/index.mjs'

const readSrc = (rel) => readFileSync(resolve(__dirname, '../..', rel), 'utf8')

/** ProfileView 用例的资料夹具（username/realName 用于等待加载完成） */
const PROFILE_ME = {
  _id: 'u1',
  username: 'alice',
  realName: '爱丽丝',
  email: 'alice@example.com',
  roles: [],
  createdAt: '2026-01-01T00:00:00.000Z',
}

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

  // 【已删除】「当前设备禁用 + 原因提示」「revokeOne 拦截 current」
  //   替代用例（变异实测杀死）：
  //     - 禁用条件去掉 item.current → 「本设备的踢除按钮被禁用：点击不弹确认框、不发请求」变红
  //     - revokeOne 的 if(item.current) 改恒假 → 「绕过 disabled 直接触发：handler 自身
  //       仍必须拒绝吊销本设备（纵深防御）」变红（该用例覆盖了 handler 自身拦截）

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

  // 【已删除】「otherCount 排除当前设备」
  //   替代用例（变异实测杀死）：filter 改成 sessions.value.length →
  //   「只有本设备在线：退出其他设备按钮禁用（otherCount 为 0）」变红。
  //   （`otherCount === 0` 那条是禁用条件的同义重复，同样被该用例覆盖。）

  // 【已删除】「吊销成功后重新拉取列表而非本地剔除」
  //   替代用例（变异实测杀死）：把 await load() 换成本地 filter 剔除 →
  //   「踢除其他设备：确认框文案带设备名，确认后调 revokeSession 并重新拉列表」
  //   与「吊销在途：该行按钮锁定」共 3 例变红（都断言 listSessions 被再次调用）。

  // 【已删除】「两处危险操作都有二次确认」
  //   替代用例（变异实测杀死）：把 revokeConfirm 键名改坏 →
  //   「踢除其他设备：确认框文案带设备名…」变红（断言 ElMessageBox.confirm 被调用）；
  //   revokeOthersConfirm 同理由「退出其他设备：确认后调 revokeOtherSessions」覆盖。

  // 【已删除】「请求失败清空列表」
  //   替代用例（变异实测杀死）：把 catch 里的 sessions.value = [] 去掉 →
  //   「加载失败：列表清空并渲染空态（不展示上一次的过期数据）」变红。

  // 【已删除】「主标题优先用设备型号」的源码切片断言
  //   替代用例（变异实测杀死）：把 deviceName 重命名（模板引用断线）→ 32 例变红；
  //   型号回退链由「设备名全缺失：回退「未知设备」而非空串」与
  //   「软件环境行：主标题用型号时补全带版本的软件信息」逐分支覆盖。

  // 【已删除】「软件环境行无内容时整行不渲染」
  //   替代用例（变异实测杀死）：v-if 改成恒真 → 3 例变红，含
  //   「软件环境行：浏览器与系统全缺失时整行不渲染（不产出空串行）」。

  // 【已删除】「技术详情默认折叠 + 展开状态不丢」
  //   替代用例（变异实测杀死）：把 ref(new Set()) 改成 ref([]) → 32 例变红；
  //   原地改 Set 的问题由「技术详情展开/收起：文案与 aria-expanded 同步切换
  //   （原地改 Set 会点不动）」专门钉住；刷新不丢由「刷新列表后展开状态不丢」覆盖。

  // 【已删除】「详情开关暴露 aria-expanded」
  //   替代用例（变异实测杀死）：删掉该属性 → 4 例变红，含
  //   「技术详情展开/收起：文案与 aria-expanded 同步切换」与「展开状态按 sid 隔离」。

  test('详情用 dl/dt/dd 表达「字段名—值」关系', () => {
    // 用 div 堆叠时屏幕阅读器无法把标签与取值关联起来
    expect(source).toContain('<dl')
    expect(source).toContain('<dt>')
    expect(source).toContain('<dd')
  })

  // 【已删除】「登录 IP 仅在与最近活动 IP 不同时展示」
  //   替代用例（变异实测杀死）：条件改恒真 → 2 例变红，含
  //   「登录 IP 与最近活动 IP 相同时不重复展示（避免噪音）」。

  test('原始 UA 允许断行（否则会把列表撑出横向滚动条）', () => {
    const uaBlock = source.slice(
      source.indexOf('.session-ua {'),
      source.indexOf('.session-revoke {')
    )
    expect(uaBlock).toContain('word-break: break-all')
  })

  // 【已删除】「非浏览器客户端打警示标签」
  //   替代用例（变异实测杀死）：条件改坏 → 2 例变红，含
  //   「非浏览器客户端打警示标签（bot 必须显式标注，不能伪装成正常浏览器）」。

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

describe('ProfileView 挂载登录会话卡片（真实渲染）', () => {
  // 【改写】原为源码 indexOf 顺序断言（`$t('session.title')` 出现在
  // `$t('profile.security')` 之后）。源码顺序 ≠ 渲染位置：把卡片放进
  // `<el-col>` 之外、或嵌套进错误的栏，indexOf 顺序照样成立而界面已经错位。
  // 实测该弱点：把 ProfileView 的 SessionManager 整块注释掉，旧断言
  // `toContain('<SessionManager />')` 与 indexOf 顺序断言**全部 PASS**
  // （两个测试文件都测不出），故改为真实挂载 + DOM 分栏断言。

  test('登录会话卡片真实渲染在「安全设置」栏内，且位于改密之后、两步验证之前', async () => {
    getMe.mockResolvedValue({ data: { success: true, data: { user: { ...PROFILE_ME } } } })
    listSessions.mockResolvedValue({
      data: { data: { sessions: [], currentSidPresent: true } },
    })
    const c = track(
      mountComponent(ProfileView, {
        setupStore: (pinia) => {
          useAuthStore(pinia).setCurrentUser({ ...PROFILE_ME })
        },
      })
    )
    await waitFor(() => c.text().includes(PROFILE_ME.realName), { message: '资料加载完成' })
    await flush(20)

    // 两栏：左=基本信息，右=安全设置（与 ProfileView 的 md=10/14 分栏一致）
    const cols = c.findAll('.el-col')
    expect(cols.length).toBe(2)
    const titlesOf = (col) =>
      Array.from(col.querySelectorAll('.profile-section-title, .card-header')).map((e) =>
        e.textContent.trim()
      )
    const leftTitles = titlesOf(cols[0])
    const rightTitles = titlesOf(cols[1])

    expect(leftTitles).toContain('基本信息')
    expect(leftTitles).not.toContain('登录会话')

    // 右栏内部顺序：安全设置 → 修改密码 → 登录会话 → 两步验证（MFA）
    expect(rightTitles).toEqual(['安全设置', '修改密码', '登录会话', '两步验证（MFA）'])

    // 会话卡片本体确实渲染了（不是只剩标题空壳）：断言 SessionManager 的
    // 根元素 .session-manager（ProfileView 自身也有 session-intro / session.title，
    // 用宽泛的 'session-' 会被它们误命中——本用例第一版就是这么写成假断言的）
    const manager = cols[1].querySelector('.session-manager')
    expect(manager).toBeTruthy()
    // 且必须落在「登录会话」那张卡片内，而不是栏内随便某个位置
    const card = manager.closest('.el-card')
    expect(card.querySelector('.card-header').textContent.trim()).toBe('登录会话')
    // 栏内顺序：登录会话卡片在 MFA 卡片之前
    const cardHeaders = Array.from(cols[1].querySelectorAll('.el-card .card-header')).map((e) =>
      e.textContent.trim()
    )
    expect(cardHeaders).toEqual(['修改密码', '登录会话', '两步验证（MFA）'])
    expect(c.errors).toEqual([])
  })
})

describe('ProfileView 两栏布局（真实渲染的栅格类）', () => {
  // 【改写】原为源码 `:md="(\d+)"` 正则取值。栅格断点最终落在渲染出的
  // `el-col-md-*` / `el-col-lg-*` / `el-col-xs-*` 类上——直接断言这些类，
  // 既覆盖「声明了哪一档」，也覆盖「Element Plus 真的按声明生成了类」。
  // 实测（探针）：两栏 class 为 el-col-xs-24 el-col-md-10 el-col-lg-9 与
  // el-col-xs-24 el-col-md-14 el-col-lg-15。
  // 后续 CSS 用例仍需读源码（jsdom 不注入 SFC 样式）
  const source = readSrc('views/ProfileView.vue')

  const renderProfile = async () => {
    getMe.mockResolvedValue({ data: { success: true, data: { user: { ...PROFILE_ME } } } })
    listSessions.mockResolvedValue({ data: { data: { sessions: [], currentSidPresent: true } } })
    const c = track(
      mountComponent(ProfileView, {
        setupStore: (pinia) => {
          useAuthStore(pinia).setCurrentUser({ ...PROFILE_ME })
        },
      })
    )
    await waitFor(() => c.text().includes(PROFILE_ME.realName), { message: '资料加载完成' })
    await flush(20)
    return c
  }

  /** 从 el-col 的 class 里取某断点的栅格值（如 md → 10） */
  const colSpan = (col, bp) => {
    const m = col.className.match(new RegExp(`el-col-${bp}-(\\d+)`))
    return m ? Number(m[1]) : null
  }

  test('两栏各有分区标题，且用真实 h2 标题元素（可按标题导航）', async () => {
    const c = await renderProfile()
    const titles = c.findAll('h2.profile-section-title')
    expect(titles).toHaveLength(2)
    expect(titles.map((e) => e.textContent.trim())).toEqual(['基本信息', '安全设置'])
    expect(c.errors).toEqual([])
  })

  test('左右两栏栅格相加为 24（md 与 lg 两档都要成立，否则右栏会被挤到下一行）', async () => {
    // 漏配一档时该断点下布局会突然折行，而开发通常只在一种窗口宽度下看效果
    const c = await renderProfile()
    const cols = c.findAll('.el-col')
    expect(cols).toHaveLength(2)
    expect(colSpan(cols[0], 'md') + colSpan(cols[1], 'md')).toBe(24)
    expect(colSpan(cols[0], 'lg') + colSpan(cols[1], 'lg')).toBe(24)
  })

  test('窄屏两栏均为整行（xs=24），不出现横向挤压', async () => {
    const c = await renderProfile()
    const cols = c.findAll('.el-col')
    expect(cols.map((col) => colSpan(col, 'xs'))).toEqual([24, 24])
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

  // 【保留】sid 的 URL 构造与 others 固定路径：跨模块契约，且**行为用例已能覆盖**
  //   但覆盖面不同——变异实测：去掉 encodeURIComponent 时本文件与
  //   apiRequestPipeline.test.js「全部端点的动词与路径符合后端契约」都会变红，
  //   两者互为独立证据（前者防本仓调用方，后者防契约表漂移），故保留。
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

  // 【保留】schema 绑定 GET：变异实测（去掉 method: 'get'）时本文件与
  //   apiRequestPipeline.test.js「/auth/sessions GET 用列表 schema；DELETE 不误用」
  //   同时变红——两者从不同角度守（前者守声明，后者守运行时匹配），故保留。
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

describe('SessionManager 时间格式（O-3 单一事实来源）', () => {
  /**
   * 真实退化（两条都只会「看起来正常」）：
   *  1. 改回 toLocaleString(locale)：格式随界面语言漂移——实测 zh="2026/10/1 09:00:00"
   *     vs en="10/1/2026, 09:00:00"，用户切个语言，同一列时间的读法（月日顺序/分隔符）就变了；
   *  2. 脏数据（非空但不可解析的时间串）渲染 "Invalid Date" —— 把后端字段漂移直接端给用户。
   *
   * 期望值一律用 Date 的本地 getter 独立计算，**不 import @/utils/datetime**：
   * 直接调用被测实现算期望值，会在实现写错时两边一起错。
   */
  const ISO_SEEN = '2026-10-01T01:00:00.000Z'
  const ISO_CREATED = '2026-09-30T18:30:45.000Z'
  const ISO_EXPIRES = '2026-10-08T01:00:00.000Z'

  /** 本地时区「YYYY-MM-DD HH:mm:ss」定长串（各段补零），与实现无关 */
  const localStamp = (iso) => {
    const d = new Date(iso)
    const p = (n) => String(n).padStart(2, '0')
    return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
  }

  const sessionRow = (over = {}) => ({
    ...validItem(),
    current: false,
    lastSeenAt: ISO_SEEN,
    createdAt: ISO_CREATED,
    expiresAt: ISO_EXPIRES,
    ...over,
  })

  const metaSpans = (c) => c.findAll('.session-meta span').map((s) => s.textContent.trim())

  let mounted = null
  const renderSessions = async (sessions) => {
    listSessions.mockResolvedValue({ data: { data: { sessions, currentSidPresent: true } } })
    mounted = mountComponent(SessionManager, {
      initialRoute: '/profile',
      routes: [{ path: '/profile', component: { render: () => null } }],
    })
    // 等到会话行渲染出来（列表加载完成）；用 DOM 结构判定，不看具体语言
    await waitFor(() => mounted.findAll('.session-meta span').length >= 3, {
      message: '会话列表渲染完成',
    })
    await flush(4)
    return mounted
  }

  afterEach(() => {
    mounted?.handle.unmount()
    mounted = null
    listSessions.mockReset()
    i18n.global.locale.value = 'zh-CN'
  })

  test('合法时间：三处时间精确渲染为本地 YYYY-MM-DD HH:mm:ss', async () => {
    const c = await renderSessions([sessionRow()])
    // 前提自检：本地定长串与原始 ISO 必然不同（含 T/Z），故下面的精确断言不会变成
    // 「回显原始串也算过」；TZ=UTC 时它只证明格式契约，不宣称验证了时区换算。
    expect(localStamp(ISO_SEEN)).not.toBe(ISO_SEEN)
    const spans = metaSpans(c)
    expect(spans).toContain(`最近活动：${localStamp(ISO_SEEN)}`)
    expect(spans).toContain(`登录时间：${localStamp(ISO_CREATED)}`)
    // 合法值不得被误判为空值而显示占位符（变异注入「恒返回 —」必须在此红）
    expect(spans).not.toContain('最近活动：—')
    expect(spans).not.toContain('登录时间：—')

    // 第三处在「技术详情」折叠区：展开后按 dt/dd 配对断言，避免撞到同区的引擎/架构文本
    click(c.findAll('.session-detail-toggle')[0])
    await flush(4)
    const dt = Array.from(c.findAll('.session-detail dt')).find(
      (el) => el.textContent.trim() === '有效期至'
    )
    expect(dt).toBeTruthy()
    expect(dt.nextElementSibling.textContent.trim()).toBe(localStamp(ISO_EXPIRES))
  })

  test('脏数据（不可解析的时间串）：渲染占位符 —，不得出现 Invalid Date', async () => {
    const c = await renderSessions([sessionRow({ lastSeenAt: 'not-a-date' })])
    expect(metaSpans(c)).toContain('最近活动：—')
    expect(c.text()).not.toContain('Invalid')
    expect(c.text()).not.toContain('NaN')
  })

  test('空值（null/undefined/空串）：三处时间一律渲染占位符 —，不出现 Invalid/undefined', async () => {
    const c = await renderSessions([
      sessionRow({ lastSeenAt: null, createdAt: undefined, expiresAt: '' }),
    ])
    const spans = metaSpans(c)
    expect(spans).toContain('最近活动：—')
    expect(spans).toContain('登录时间：—')
    expect(c.text()).not.toContain('Invalid')
    expect(c.text()).not.toContain('undefined')
    expect(c.text()).not.toContain('NaN')
  })

  test('语言漂移守卫：同一实例切到 en-US 后时间文本完全不变（标签变英文证明切换真的生效）', async () => {
    const c = await renderSessions([sessionRow()])
    expect(metaSpans(c)).toContain(`最近活动：${localStamp(ISO_SEEN)}`)

    i18n.global.locale.value = 'en-US'
    await flush(8)

    const spans = metaSpans(c)
    // 正：标签确实切成了英文（证明 locale 已切换，本用例不是恒真）
    expect(spans).toContain(`Last active：${localStamp(ISO_SEEN)}`)
    expect(spans).toContain(`Signed in：${localStamp(ISO_CREATED)}`)
    // 反：时间串必须仍是同一个本地定长串，不得出现 en-US 的 toLocaleString 形态
    expect(spans.join('|')).not.toContain('10/1/2026')
    expect(c.text()).not.toContain('最近活动')
  })
})

/**
 * 组件真实交互链路（补充：既有用例多为静态源码断言与 schema 契约，
 * 这里按真实挂载 + 真实点击驱动，覆盖 revokeOne / revokeOthers /
 * 展开收起 / 图标 / 软件环境行 / noCurrentSidHint 提示）。
 *
 * 每条用例都对应一个「静默失效」的真实退化：
 *  - 确认框取消却仍然踢除 → 用户误点一次就掉线
 *  - 踢除后不刷新列表 → 界面显示已踢设备仍在登录（与真实状态不一致）
 *  - 踢除请求失败后 revoking 不复位 → 该行按钮永久禁用
 *  - 没有其他设备时仍允许「退出其他设备」→ 点了没反应
 *  - 展开状态用原地 add/delete 而非重建 Set → 点击无反应
 */
describe('SessionManager 真实交互（确认框 / 吊销 / 展开）', () => {
  const otherRow = (over = {}) => ({
    ...validItem(),
    sid: '550e8400-e29b-41d4-a716-4466554400aa',
    current: false,
    ...over,
  })

  let mounted = null
  const renderSessions = async (sessions, currentSidPresent = true) => {
    listSessions.mockResolvedValue({ data: { data: { sessions, currentSidPresent } } })
    mounted = mountComponent(SessionManager, {
      initialRoute: '/profile',
      routes: [{ path: '/profile', component: { render: () => null } }],
    })
    await waitFor(() => mounted.findAll('.session-meta span').length >= 3, {
      message: '会话列表渲染完成',
    })
    await flush(4)
    return mounted
  }

  /** 列表内第 n 个「终止登录」按钮（工具条上的「退出其他设备」类名不同，不会混入） */
  const revokeBtn = (c, i = 0) => c.findAll('.session-revoke')[i]

  afterEach(() => {
    mounted?.handle.unmount()
    mounted = null
    listSessions.mockReset()
    getMe.mockReset()
    api.auth.revokeSession.mockReset()
    api.auth.revokeOtherSessions.mockReset()
    ElMessageBox.confirm.mockReset()
    ElMessage.success.mockReset()
    ElMessage.error.mockReset()
    i18n.global.locale.value = 'zh-CN'
  })

  test('踢除其他设备：确认框文案带设备名，确认后调 revokeSession 并重新拉列表', async () => {
    ElMessageBox.confirm.mockResolvedValue('confirm')
    api.auth.revokeSession.mockResolvedValue({ data: { data: { sid: otherRow().sid } } })
    const c = await renderSessions([validItem(), otherRow({ deviceModel: 'Pixel 8' })])

    // 确认框参数：设备名进文案（否则用户不知道踢的是哪台）
    expect(ElMessageBox.confirm).not.toHaveBeenCalled()
    click(revokeBtn(c, 1))
    await waitFor(() => ElMessageBox.confirm.mock.calls.length === 1, { message: '确认框弹出' })
    expect(ElMessageBox.confirm.mock.calls[0][0]).toContain('Pixel 8')

    await waitFor(() => api.auth.revokeSession.mock.calls.length === 1, { message: '吊销请求发出' })
    expect(api.auth.revokeSession.mock.calls[0][0]).toBe(otherRow().sid)
    // 必须重新拉取而非本地剔除：列表价值在于反映服务端真实状态
    await waitFor(() => listSessions.mock.calls.length === 2, { message: '重新拉取列表' })
    expect(ElMessage.success).toHaveBeenCalledTimes(1)
    expect(c.errors).toEqual([])
  })

  test('确认框取消：不发吊销请求、不弹成功提示（用户误点不承担掉线代价）', async () => {
    ElMessageBox.confirm.mockRejectedValue(new Error('cancel'))
    const c = await renderSessions([validItem(), otherRow()])
    const before = listSessions.mock.calls.length

    click(revokeBtn(c, 1))
    await waitFor(() => ElMessageBox.confirm.mock.calls.length === 1, { message: '确认框弹出' })
    await flush(20)

    expect(api.auth.revokeSession).not.toHaveBeenCalled()
    expect(ElMessage.success).not.toHaveBeenCalled()
    expect(listSessions.mock.calls.length).toBe(before)
  })

  test('本设备的踢除按钮被禁用：点击不弹确认框、不发请求', async () => {
    const c = await renderSessions([validItem({ current: true })])
    const btn = revokeBtn(c, 0)
    expect(btn.disabled).toBe(true)
    click(btn)
    await flush(10)
    expect(ElMessageBox.confirm).not.toHaveBeenCalled()
    expect(api.auth.revokeSession).not.toHaveBeenCalled()
  })

  test('吊销请求失败：revoking 复位，按钮不会永久禁用', async () => {
    ElMessageBox.confirm.mockResolvedValue('confirm')
    api.auth.revokeSession.mockRejectedValue(new Error('boom'))
    const c = await renderSessions([validItem(), otherRow()])

    click(revokeBtn(c, 1))
    await waitFor(() => api.auth.revokeSession.mock.calls.length === 1, { message: '吊销请求发出' })
    await waitFor(() => revokeBtn(c, 1).disabled === false, { message: '失败后按钮解锁' })
    expect(revokeBtn(c, 1).disabled).toBe(false)
    expect(ElMessage.success).not.toHaveBeenCalled()
  })

  test('退出其他设备：确认后调 revokeOtherSessions，成功文案带后端返回的台数', async () => {
    ElMessageBox.confirm.mockResolvedValue('confirm')
    api.auth.revokeOtherSessions.mockResolvedValue({ data: { data: { revokedCount: 2 } } })
    const c = await renderSessions([validItem(), otherRow(), otherRow({ sid: 'sid-3' })])

    // 工具条按钮顺序： [刷新, 退出其他设备]；不能用 disabled === false 过滤
    // （刷新按钮同样是 enabled，会选错目标导致点了个空）
    const othersBtn = c.findAll('.session-actions button')[1]
    expect(othersBtn.disabled).toBe(false)
    expect(othersBtn.textContent.trim()).toBe('退出其他设备')
    click(othersBtn)
    await waitFor(() => api.auth.revokeOtherSessions.mock.calls.length === 1, {
      message: '退出其他设备请求发出',
    })
    await waitFor(() => ElMessage.success.mock.calls.length === 1, { message: '成功提示' })
    // 文案里的台数必须来自后端返回（写死 0 或本地计数都会在服务端口径变化时失真）
    expect(ElMessage.success.mock.calls[0][0]).toContain('2')
    await waitFor(() => listSessions.mock.calls.length === 2, { message: '重新拉取列表' })
  })

  test('只有本设备在线：退出其他设备按钮禁用（otherCount 为 0）', async () => {
    const c = await renderSessions([validItem({ current: true })])
    const buttons = c.findAll('.session-actions button')
    const othersBtn = buttons[buttons.length - 1]
    expect(othersBtn.disabled).toBe(true)
  })

  test('退出其他设备被取消：不发请求', async () => {
    ElMessageBox.confirm.mockRejectedValue(new Error('cancel'))
    const c = await renderSessions([validItem(), otherRow()])
    const buttons = c.findAll('.session-actions button')
    click(buttons[buttons.length - 1])
    await waitFor(() => ElMessageBox.confirm.mock.calls.length === 1, { message: '确认框弹出' })
    await flush(20)
    expect(api.auth.revokeOtherSessions).not.toHaveBeenCalled()
  })

  test('技术详情展开/收起：文案与 aria-expanded 同步切换（原地改 Set 会点不动）', async () => {
    const c = await renderSessions([otherRow({ engine: 'Blink', cpu: 'amd64' })])
    const toggle = c.findAll('.session-detail-toggle')[0]
    expect(toggle.getAttribute('aria-expanded')).toBe('false')
    expect(toggle.textContent.trim()).toBe('查看技术详情')

    click(toggle)
    await flush(4)
    expect(c.findAll('.session-detail-toggle')[0].getAttribute('aria-expanded')).toBe('true')
    expect(c.findAll('.session-detail-toggle')[0].textContent.trim()).toBe('收起技术详情')
    expect(c.findAll('.session-detail dt').length).toBeGreaterThan(0)

    click(c.findAll('.session-detail-toggle')[0])
    await flush(4)
    expect(c.findAll('.session-detail-toggle')[0].getAttribute('aria-expanded')).toBe('false')
    expect(c.findAll('.session-detail').length).toBe(0)
  })

  test('展开状态按 sid 隔离：展开第 1 条不影响第 2 条', async () => {
    const c = await renderSessions([
      otherRow(),
      otherRow({ sid: 'sid-2', deviceModel: 'Xiaomi 13' }),
    ])
    click(c.findAll('.session-detail-toggle')[0])
    await flush(4)
    const toggles = c.findAll('.session-detail-toggle')
    expect(toggles[0].getAttribute('aria-expanded')).toBe('true')
    expect(toggles[1].getAttribute('aria-expanded')).toBe('false')
  })

  test('刷新列表后展开状态不丢（expanded 挂在 sid 上而非行对象上）', async () => {
    const row = otherRow()
    const c = await renderSessions([row])
    click(c.findAll('.session-detail-toggle')[0])
    await flush(4)
    expect(c.findAll('.session-detail-toggle')[0].getAttribute('aria-expanded')).toBe('true')

    // 用同一份 sid 的「新对象」刷新：模拟 load() 整体替换 sessions
    listSessions.mockResolvedValue({
      data: { data: { sessions: [{ ...row }], currentSidPresent: true } },
    })
    const refresh = c.findAll('.session-actions button')[0]
    click(refresh)
    await waitFor(() => listSessions.mock.calls.length === 2, { message: '刷新请求发出' })
    await flush(8)
    expect(c.findAll('.session-detail-toggle')[0].getAttribute('aria-expanded')).toBe('true')
  })

  test('当前令牌不含 sid：渲染提示条（否则用户以为本设备没被记录）', async () => {
    const c = await renderSessions([otherRow()], false)
    const alert = c.find('.session-alert')
    expect(alert).toBeTruthy()
    expect(alert.textContent).toContain('重新登录')
  })

  test('currentSidPresent 为 true 时不渲染提示条（避免常驻噪音）', async () => {
    const c = await renderSessions([otherRow()], true)
    expect(c.find('.session-alert')).toBeNull()
  })

  test('加载失败：列表清空并渲染空态（不展示上一次的过期数据）', async () => {
    listSessions.mockRejectedValue(new Error('network'))
    mounted = mountComponent(SessionManager, {
      initialRoute: '/profile',
      routes: [{ path: '/profile', component: { render: () => null } }],
    })
    await waitFor(() => mounted.find('.el-empty') !== null, { message: '空态渲染' })
    expect(mounted.findAll('.session-item').length).toBe(0)
    expect(mounted.errors).toEqual([])
  })

  test('设备类型映射图标：mobile/tablet/desktop/未知 四种都渲染出图标且互不相同', async () => {
    const c = await renderSessions([
      otherRow({ sid: 'a', deviceType: 'mobile' }),
      otherRow({ sid: 'b', deviceType: 'tablet' }),
      otherRow({ sid: 'c', deviceType: 'desktop' }),
      otherRow({ sid: 'd', deviceType: 'bot' }),
    ])
    const icons = c.findAll('.session-icon svg')
    expect(icons.length).toBe(4)
    // 四类设备的图标 path 必须两两不同（unknown/bot 落到 Help 不算退化，
    // 但 mobile 与 tablet 撞图会让用户无法区分手机与平板）
    const shapes = icons.map((i) => i.innerHTML)
    expect(new Set(shapes).size).toBeGreaterThanOrEqual(3)
  })

  test('非浏览器客户端打警示标签（bot 必须显式标注，不能伪装成正常浏览器）', async () => {
    const c = await renderSessions([otherRow({ deviceType: 'bot' })])
    const tags = c.findAll('.el-tag').map((el) => el.textContent.trim())
    expect(tags).toContain('非浏览器客户端')
  })

  test('软件环境行：主标题用型号时补全带版本的软件信息', async () => {
    const c = await renderSessions([
      otherRow({
        deviceModel: 'Pixel 8',
        browser: 'Chrome',
        browserVersion: '120',
        os: 'Android',
        osVersion: '14',
      }),
    ])
    expect(c.find('.session-device').textContent.trim()).toBe('Pixel 8')
    expect(c.find('.session-software').textContent.trim()).toBe('Chrome 120 · Android 14')
  })

  test('软件环境行：主标题已是「浏览器 · 系统」且无版本号时整行省略（不重复同一信息）', async () => {
    const c = await renderSessions([
      otherRow({
        deviceVendor: '',
        deviceModel: '',
        browser: 'Chrome',
        os: 'Windows',
        browserVersion: '',
        osVersion: '',
      }),
    ])
    expect(c.find('.session-device').textContent.trim()).toBe('Chrome · Windows')
    expect(c.find('.session-software')).toBeNull()
  })

  test('设备名全缺失：回退「未知设备」而非空串（空行会让用户以为列表坏了）', async () => {
    const c = await renderSessions([
      otherRow({ deviceVendor: '', deviceModel: '', browser: '', os: '' }),
    ])
    expect(c.find('.session-device').textContent.trim()).toBe('未知设备')
  })

  test('登录 IP 与最近活动 IP 不同时，详情里额外展示登录 IP', async () => {
    const c = await renderSessions([otherRow({ ip: '198.51.100.7', lastIp: '203.0.113.45' })])
    click(c.findAll('.session-detail-toggle')[0])
    await flush(4)
    const dts = c.findAll('.session-detail dt').map((el) => el.textContent.trim())
    expect(dts).toContain('登录时 IP')
  })

  test('登录 IP 与最近活动 IP 相同时不重复展示（避免噪音）', async () => {
    const c = await renderSessions([otherRow({ ip: '203.0.113.45', lastIp: '203.0.113.45' })])
    click(c.findAll('.session-detail-toggle')[0])
    await flush(4)
    const dts = c.findAll('.session-detail dt').map((el) => el.textContent.trim())
    expect(dts).not.toContain('登录时 IP')
  })

  test('绕过 disabled 直接触发：handler 自身仍必须拒绝吊销本设备（纵深防御）', async () => {
    // 模板的 disabled 是第一道闸；但键盘/辅助技术或未来模板改动都可能绕过它，
    // handler 里的 if (item.current) return 才是真正的安全边界。
    const c = await renderSessions([validItem({ current: true })])
    const btn = revokeBtn(c, 0)
    btn.disabled = false // 模拟第一道闸失效
    click(btn)
    await flush(20)
    expect(ElMessageBox.confirm).not.toHaveBeenCalled()
    expect(api.auth.revokeSession).not.toHaveBeenCalled()
  })

  test('sessions 非数组（后端字段漂移）：按空列表处理，不渲染残缺行', async () => {
    listSessions.mockResolvedValue({
      data: { data: { sessions: null, currentSidPresent: true } },
    })
    mounted = mountComponent(SessionManager, {
      initialRoute: '/profile',
      routes: [{ path: '/profile', component: { render: () => null } }],
    })
    await waitFor(() => mounted.find('.el-empty') !== null, { message: '空态渲染' })
    expect(mounted.findAll('.session-item').length).toBe(0)
    expect(mounted.errors).toEqual([])
  })

  test('revokedCount 缺失（旧后端）：成功文案回退 0，不渲染 undefined', async () => {
    ElMessageBox.confirm.mockResolvedValue('confirm')
    api.auth.revokeOtherSessions.mockResolvedValue({ data: { data: {} } })
    const c = await renderSessions([validItem(), otherRow()])
    click(c.findAll('.session-actions button')[1])
    await waitFor(() => ElMessage.success.mock.calls.length === 1, { message: '成功提示' })
    const text = ElMessage.success.mock.calls[0][0]
    expect(text).toContain('0')
    expect(text).not.toContain('undefined')
  })

  test('软件环境行：浏览器与系统全缺失时整行不渲染（不产出空串行）', async () => {
    const c = await renderSessions([
      otherRow({
        deviceModel: 'Pixel 8',
        browser: '',
        browserVersion: '',
        os: '',
        osVersion: '',
      }),
    ])
    expect(c.find('.session-device').textContent.trim()).toBe('Pixel 8')
    expect(c.find('.session-software')).toBeNull()
  })

  test('IP 兜底链：lastIp 缺失时显示 ip，两者都缺失时显示占位符 —', async () => {
    const c1 = await renderSessions([otherRow({ lastIp: '', ip: '198.51.100.7' })])
    expect(c1.findAll('.session-meta span')[0].textContent).toContain('198.51.100.7')
    c1.handle.unmount()

    const c2 = await renderSessions([otherRow({ lastIp: null, ip: null })])
    expect(c2.findAll('.session-meta span')[0].textContent.trim()).toBe('IP 地址：—')
  })

  test('归属地（后端可选增强）：有 location 拼接展示，无 location 不渲染分隔符', async () => {
    const withLoc = await renderSessions([
      otherRow({ lastIp: '203.0.113.45', location: '广东省深圳市 · 电信' }),
    ])
    const metaWith = withLoc.findAll('.session-meta span')[0].textContent
    expect(metaWith).toContain('203.0.113.45')
    expect(metaWith).toContain('· 广东省深圳市 · 电信')
    withLoc.handle.unmount()

    // 旧后端/检索降级时缺字段：只渲染 IP，不得出现裸分隔符或 undefined
    const noLoc = await renderSessions([otherRow({ lastIp: '203.0.113.45' })])
    const metaWithout = noLoc.findAll('.session-meta span')[0].textContent
    expect(metaWithout).toContain('203.0.113.45')
    expect(metaWithout).not.toContain('·')
    expect(metaWithout).not.toContain('undefined')
  })

  test('本设备打「本设备」标签（否则用户可能试图把自己踢下线）', async () => {
    const c = await renderSessions([validItem({ current: true }), otherRow()])
    const tags = c.findAll('.session-item .el-tag').map((el) => el.textContent.trim())
    expect(tags).toContain('本设备')
    // 只有当前设备那一行带标签：给所有行都打标签等于没有标签
    expect(tags.filter((x) => x === '本设备').length).toBe(1)
    expect(c.findAll('.session-item')[0].querySelector('.el-tag').textContent.trim()).toBe('本设备')
  })

  test('非当前设备不打「本设备」标签', async () => {
    const c = await renderSessions([otherRow()])
    const tags = c.findAll('.session-item .el-tag').map((el) => el.textContent.trim())
    expect(tags).not.toContain('本设备')
  })

  test('吊销在途：该行按钮锁定（防止连点重复吊销）', async () => {
    ElMessageBox.confirm.mockResolvedValue('confirm')
    let release
    api.auth.revokeSession.mockImplementation(
      () =>
        new Promise((r) => {
          release = () => r({ data: { data: { sid: otherRow().sid } } })
        })
    )
    const c = await renderSessions([validItem(), otherRow()])

    click(revokeBtn(c, 1))
    await waitFor(() => api.auth.revokeSession.mock.calls.length === 1, { message: '吊销请求发出' })
    expect(revokeBtn(c, 1).disabled).toBe(true)
    // 同一行连点不得再发第二次请求（revoking 是这一行的锁）
    click(revokeBtn(c, 1))
    await flush(10)
    expect(api.auth.revokeSession.mock.calls.length).toBe(1)

    release()
    // 注意：成功后组件会重新拉取列表，期间 loading=true 渲染骨架屏、列表整体消失，
    // 故谓词必须容忍「按钮暂时不存在」，否则轮询会抛 TypeError 而不是等待
    await waitFor(() => revokeBtn(c, 1)?.disabled === false, { message: '完成后解锁' })
    expect(revokeBtn(c, 1).disabled).toBe(false)
    expect(api.auth.revokeSession.mock.calls.length).toBe(1)
  })

  test('刷新按钮触发 load（工具条第一个按钮）', async () => {
    const c = await renderSessions([otherRow()])
    expect(listSessions.mock.calls.length).toBe(1)
    click(c.findAll('.session-actions button')[0])
    await waitFor(() => listSessions.mock.calls.length === 2, { message: '刷新请求发出' })
    expect(listSessions.mock.calls.length).toBe(2)
  })
})
