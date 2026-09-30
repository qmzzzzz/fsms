/**
 * P2-52 回归：manualChunks 的 echarts 判定改为分隔符无关的完整路径段匹配
 *
 * 实测更正（本套件逐条验证，与报告口径有两处不同）：
 * 原实现为
 *   id.includes('node_modules/echarts') ||
 *   id.includes('node_modules\\.pnpm\\echarts')
 *
 *  ① 报告称「pnpm 分支永不命中」。实测：该分支（字符串值为
 *     'node_modules\.pnpm\echarts'，单反斜杠）对**反斜杠分隔**的 pnpm 路径
 *     会命中，对正斜杠路径不命中——而本机构建实测传入的 1277 个 id 全为正斜杠，
 *     所以它在本环境下从未命中（属「与实际传入形态不匹配的冗余分支」，
 *     而非逻辑上不可达）。
 *  ② 更关键的是：即使该分支永不命中，也**没有**丢失 pnpm 布局下的 echarts 分组——
 *     pnpm 真实路径 <root>/node_modules/.pnpm/echarts@x.y.z/node_modules/echarts/lib/...
 *     的末段仍含子串 'node_modules/echarts'，被第一个分支命中。
 *
 * 因此本次收敛的真实动因是：
 *  1. 无边界子串匹配：node_modules/echarts-extra/... 会被误判进 echarts chunk
 *     （当前依赖树只有 echarts，属 latent 缺陷，规则不应依赖这一点）；
 *  2. 分隔符不一致：id 若为反斜杠（Windows 原生风格），两个 includes 对
 *     npm 布局会同时失败（实测 false/false）；
 *  3. 冗余分支收敛为一条与下方 vue-vendor 同风格的正则。
 *
 * 本测试直接 import 真实的 vite.config.js 并调用其 manualChunks（与构建同源的
 * 唯一事实来源），而不是在测试里复制一份正则——复制会与配置漂移。
 * 反证记录：临时改回原两个 includes 后，本套件 2/4 用例转红（反斜杠 npm 布局、
 * echarts-extra 误伤）；pnpm 两条用例仍绿，正是上面 ①② 的实测结论。
 */
import { describe, test, expect, beforeAll } from 'vitest'
import config from '../../../vite.config.js'

let manualChunks

beforeAll(async () => {
  const resolved = await config({ command: 'build', mode: 'production' })
  manualChunks = resolved.build.rollupOptions.output.manualChunks
  expect(typeof manualChunks).toBe('function')
})

describe('manualChunks echarts 分支（P2-52）', () => {
  test('pnpm 布局命中 echarts chunk（原实现靠第一个 includes 命中，此处防回归）', () => {
    expect(
      manualChunks('D:/p/node_modules/.pnpm/echarts@5.4.0/node_modules/echarts/lib/chart/bar.js')
    ).toBe('echarts')
  })

  test('pnpm 布局 + 反斜杠 id 同样命中', () => {
    expect(
      manualChunks('D:\\p\\node_modules\\.pnpm\\echarts@5.4.0\\node_modules\\echarts\\lib\\x.js')
    ).toBe('echarts')
  })

  test('npm 布局不回归（正斜杠与反斜杠两种 id 形态）', () => {
    expect(manualChunks('D:/p/node_modules/echarts/lib/a.js')).toBe('echarts')
    expect(manualChunks('D:\\p\\node_modules\\echarts\\lib\\a.js')).toBe('echarts')
  })

  test('不误伤：echarts-extra / echarts-gl 等前缀包不得进 echarts chunk', () => {
    expect(manualChunks('D:/p/node_modules/echarts-extra/a.js')).toBeUndefined()
    expect(manualChunks('D:/p/node_modules/echarts-gl/a.js')).toBeUndefined()
    expect(manualChunks('D:/p/node_modules/vue/dist/vue.js')).toBe('vue-vendor')
    expect(manualChunks('D:/p/node_modules/@vue/runtime-core/dist/x.js')).toBe('vue-vendor')
  })
})
