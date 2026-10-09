/**
 * IP 归属地数据段词典：覆盖度闸 + 映射行为
 *
 * 【这条闸在防什么】
 * 公网 IP 的归属地是 ip2region xdb 的**数据原文**（中文），英文界面要显示英文就得有
 * 一本中英对照词典（src/data/ipLocationDictionary.json）。词典是手工校对的，有两种
 * 腐烂方式，都会让英文界面悄悄退回中文而没有任何用例变红：
 *   A) 数据刷新（scripts/update-ip2region.js）带入新地名/新运营商，词典没跟上；
 *   B) 词典里留着数据中已不存在的陈旧键（下一次刷新也不会发现它）。
 * 因此判据直接对**真实 xdb** 取数，而不是对一份手抄清单。
 *
 * 【豁免台账（EXEMPT）】
 * 高频段允许未收录，但必须逐个登记理由：宁可以英文界面回退中文，也不把没把握的
 * 译名写进词典——**错的译名比中文更难发现**（用户看不出那是错的）。台账有上限，
 * 且每条键必须仍在数据里（数据变了要删条目），防止它变成垃圾场。
 *
 * 【阈值口径】
 * 国家/省州是封闭集（国家代码、行政区划不会天天变）⇒ 要求 100%；
 * 城市/运营商是开放集 ⇒ 只要求高频段（出现次数 ≥ 阈值）全覆盖，长尾允许回退中文。
 * 整体再加一条 CJK 出现次数覆盖率下限，防止"只补高频、整体塌方"。
 */
import { readFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { describe, test, expect } from 'vitest'
import { ipLocationLabel } from '@/utils/ipLocationLabels'
import i18n from '@/i18n'
import dictionary from '@/data/ipLocationDictionary.json'

const require = createRequire(import.meta.url)
const { DATA_FILE, loadFromBuffer } = require('../../../../src/utils/ip2regionSearcher.js')

/** 高频段阈值（出现次数）：低于它的段允许回退中文 */
const THRESHOLD = { country: Infinity, province: 100, city: 100, isp: 20 }

/** 整体 CJK 出现次数覆盖率下限（只紧不松：补词条时随之上调） */
const COVERAGE_FLOOR = 0.98

/** 豁免台账上限：超过即红，防这里变成"懒得翻"的倾倒场 */
const EXEMPT_CAP = 12

const EXEMPT = {
  内网IP: '后端 formatRegion 已把它收敛成稳定码 private，前端永远看不到这个串',
  蒙特利: '译名不确定（Montréal / Montreuil 均可能），数据未给足线索',
  纳罗利: '印度小城，无通行中译名',
  赛城: '加拿大安大略小镇，中文资料指向 Markham 但无确证',
  巴里: '加拿大安大略 Barrie 与澳美多处重名，不给唯一译名',
  蒙古顿: '疑为 Milton 的数据笔误，不按猜测入词典',
  皓宽网络: '区域性小运营商，无通行英文名',
  层峰网络: '区域性小运营商，无通行英文名',
  互联网泰国: '对应 TOT 还是 Internet Thailand 无法确证',
  有线通: '上海有线通品牌名，无通行英文名',
}

const isCjk = (s) => /[\u4e00-\u9fa5]/.test(s)

/**
 * 枚举 xdb 全部地区段及其出现次数（按字段位分组）。
 *
 * 复用后端检索器的 loadFromBuffer 做结构校验与指针解析，避免在这里复刻一份
 * xdb 布局知识；段索引的遍历是加载器没有暴露的唯一一件事，就地写。
 */
const enumerate = () => {
  const { buffer, startIndexPtr, endIndexPtr } = loadFromBuffer(readFileSync(DATA_FILE))
  const byPos = [{}, {}, {}, {}, {}]
  for (let p = startIndexPtr; p < endIndexPtr; p += 14) {
    const dataLen = buffer.readUInt16LE(p + 8)
    const dataPtr = buffer.readUInt32LE(p + 10)
    if (dataPtr + dataLen > buffer.length) continue
    buffer
      .toString('utf8', dataPtr, dataPtr + dataLen)
      .split('|')
      .forEach((seg, i) => {
        if (seg && seg !== '0') byPos[i][seg] = (byPos[i][seg] || 0) + 1
      })
  }
  return byPos
}

const data = enumerate()
const names = ['country', 'region', 'province', 'city', 'isp']
const cjkByPos = names.map((_n, i) =>
  Object.entries(data[i])
    .filter(([seg]) => isCjk(seg))
    .sort((a, b) => b[1] - a[1])
)
const allCjk = new Map()
cjkByPos.forEach((entries) =>
  entries.forEach(([seg, n]) => allCjk.set(seg, (allCjk.get(seg) || 0) + n))
)
const totalCjkOcc = [...allCjk.values()].reduce((a, b) => a + b, 0)
const coveredOcc = [...allCjk.entries()]
  .filter(([seg]) => dictionary.segments[seg])
  .reduce((a, [, n]) => a + n, 0)

/** 用真实 i18n 实例取 t：语言判定读的是它的 locale，本地实例说了不算 */
const t = () => (key) => i18n.global.t(key)
const setLocale = (locale) => {
  i18n.global.locale.value = locale
}

describe('IP 归属地词典：对真实数据的覆盖度闸', () => {
  test('枚举器有牙：能从 xdb 里取出预期规模的中文段（否则下面全是恒真）', () => {
    expect(names.map((n, i) => [n, cjkByPos[i].length])).toEqual([
      ['country', 244],
      ['region', 0],
      ['province', 528],
      ['city', 685],
      ['isp', 129],
    ])
    expect(totalCjkOcc).toBeGreaterThan(1_000_000)
  })

  test('国家段 100% 覆盖（封闭集：ISO 3166-1，漏一个就是一个国家在英文界面显示中文）', () => {
    const missing = cjkByPos[0].filter(([seg]) => !dictionary.segments[seg]).map(([seg]) => seg)
    expect(missing).toEqual([])
  })

  test.each(names.map((n, i) => [n, i]))('%s 位的高频段（≥阈值）除登记豁免外全覆盖', (name, i) => {
    const missing = cjkByPos[i]
      .filter(([, n]) => n >= THRESHOLD[name])
      .filter(([seg]) => !dictionary.segments[seg] && !EXEMPT[seg])
      .map(([seg, n]) => `${seg}(${n})`)
    expect(missing).toEqual([])
  })

  test('整体 CJK 出现次数覆盖率不低于下限（只紧不松）', () => {
    expect(coveredOcc / totalCjkOcc).toBeGreaterThanOrEqual(COVERAGE_FLOOR)
  })

  test('豁免台账不越上限（防"懒得翻"往里倾倒）', () => {
    expect(Object.keys(EXEMPT).length).toBeLessThanOrEqual(EXEMPT_CAP)
  })

  test('豁免台账无陈旧条目：每条键必须仍在当前数据里', () => {
    const stale = Object.keys(EXEMPT).filter((key) => !allCjk.has(key))
    expect(stale).toEqual([])
  })

  test('豁免项确实还没进词典（登记了又翻了 = 台账撒谎）', () => {
    const covered = Object.keys(EXEMPT).filter((seg) => dictionary.segments[seg])
    expect(covered).toEqual([])
  })

  test('词典无陈旧键：每个键都必须在当前数据里真实存在', () => {
    const stale = Object.keys(dictionary.segments).filter((seg) => !allCjk.has(seg))
    expect(stale).toEqual([])
  })

  test('词典自身卫生：键非空、译文非空且不含中文（英文界面不许再漏中文）', () => {
    const bad = Object.entries(dictionary.segments).filter(([zh, en]) => !zh || !en || isCjk(en))
    expect(bad).toEqual([])
  })
})

describe('IP 归属地映射行为', () => {
  test('中文界面原样透传（数据本就是中文，不过词典）', () => {
    setLocale('zh-CN')
    expect(ipLocationLabel(t(), '中国·浙江省·杭州市·阿里云')).toBe('中国·浙江省·杭州市·阿里云')
  })

  test('英文界面逐段译名，未收录的段原样保留', () => {
    setLocale('en-US')
    expect(ipLocationLabel(t(), '中国·浙江省·杭州市·阿里云')).toBe(
      'China·Zhejiang·Hangzhou·Alibaba Cloud'
    )
    // 豁免段：整段透传，而不是把整块归属地抹掉
    expect(ipLocationLabel(t(), '美国·蒙特利')).toBe('United States·蒙特利')
  })

  test('数据里本来就是英文的段原样保留（Level3 / Ontario 之类）', () => {
    setLocale('en-US')
    expect(ipLocationLabel(t(), '美国·Level3')).toBe('United States·Level3')
  })

  test('老后端发来的中文「内网」原样透传（不回退成空白，也不译成别的）', () => {
    setLocale('en-US')
    expect(ipLocationLabel(t(), '内网')).toBe('内网')
    setLocale('zh-CN')
    expect(ipLocationLabel(t(), '内网')).toBe('内网')
  })

  test('私网稳定码走词表：中文「内网」/ 英文 Internal network', () => {
    setLocale('zh-CN')
    expect(ipLocationLabel(t(), 'private')).toBe('内网')
    setLocale('en-US')
    expect(ipLocationLabel(t(), 'private')).toBe('Internal network')
  })

  test('空值返回空串（调用方据此省略分隔符）', () => {
    setLocale('en-US')
    for (const empty of [null, undefined, '']) {
      expect(ipLocationLabel(t(), empty)).toBe('')
    }
  })

  test('段名不会命中对象原型（把数据当键查表必须防 constructor 之类）', () => {
    setLocale('en-US')
    expect(ipLocationLabel(t(), 'constructor')).toBe('constructor')
    expect(ipLocationLabel(t(), '__proto__')).toBe('__proto__')
  })

  test('切语言后同一输入给出不同译文（跟随语言，而不是启动时定死）', () => {
    const input = '中国·广东省·深圳市·电信'
    setLocale('zh-CN')
    const zh = ipLocationLabel(t(), input)
    setLocale('en-US')
    const en = ipLocationLabel(t(), input)
    setLocale('zh-CN')
    expect(zh).toBe(input)
    expect(en).toBe('China·Guangdong·Shenzhen·China Telecom')
    expect(en).not.toBe(zh)
  })
})
