/**
 * RegisterSummary 行为测试（注册第 3 步「信息核对」列表）
 *
 * 组件极薄，但有一处真实退化会直接影响用户决策：**空值必须显示「未填写」并
 * 走弱化样式**。注册是可匿名写库的一次性动作，用户在核对页若看到一行空白，
 * 无法区分「我没填」与「界面漏渲染了我的输入」——后者会让人以为数据丢了。
 * 因此本套件钉住：
 *
 *  1. items 逐行渲染，label 原样展示（label 已由父级完成 i18n，组件不得二次翻译）；
 *  2. 空值三形态（''/null/undefined）都显示 summaryEmpty 文案且带 is-empty class；
 *     非空值不加 is-empty，且按原值显示（不 trim、不改写）；
 *  3. 值 '0' / 'false' 这类**字符串**是有效输入，不能按 falsy 判成空
 *     （与 `!item.value` 的写法对照：数字 0 与布尔 false 也是合法值）；
 *  4. 空列表不渲染任何行、不抛错（注册页在字段全空的极端情况下仍要能渲染）；
 *  5. 双语：切换 locale 后标题与空值占位跟随。
 *
 * 样式类 is-empty 是「弱化显示」的唯一钩子（RegisterSummary.vue:53 的
 * `.summary__row dd.is-empty`），漏掉它用户就分不清「空」与「有值」。
 */
import { describe, test, expect, afterEach } from 'vitest'
import { mountComponent, flush } from '../helpers/componentHarness'
import i18n from '@/i18n'
import RegisterSummary from '@/components/RegisterSummary.vue'

let active = null
const open = async (items, locale = 'zh-CN') => {
  active = mountComponent(RegisterSummary, { props: { items }, locale })
  await flush(4)
  return active
}
afterEach(() => {
  active?.handle.unmount()
  active = null
})

const rows = (c) =>
  c.findAll('.summary__row').map((row) => ({
    label: row.querySelector('dt').textContent,
    value: row.querySelector('dd').textContent,
    empty: row.querySelector('dd').classList.contains('is-empty'),
  }))

describe('RegisterSummary 渲染', () => {
  test('逐行渲染 label 与 value；label 原样展示不做二次翻译', async () => {
    // 第二个样本刻意用「看起来像词表键」的字符串：组件若对 label 再调一次
    // $t（把「已由父级完成 i18n」的契约搞错），它会被翻译成「用户名」，
    // 而正确的行为是原样透传——父级传什么就显示什么。
    const c = await open([
      { label: '用户名', value: 'alice' },
      { label: 'auth.username', value: 'alice@example.com' },
      { label: '部门', value: '运维部' },
    ])
    expect(rows(c)).toEqual([
      { label: '用户名', value: 'alice', empty: false },
      { label: 'auth.username', value: 'alice@example.com', empty: false },
      { label: '部门', value: '运维部', empty: false },
    ])
    expect(c.find('.summary__title').textContent.trim()).toBe('信息核对')
    expect(c.errors).toEqual([])
  })

  test('空值三形态都显示占位文案并带 is-empty（用户能区分「没填」与「漏渲染」）', async () => {
    const c = await open([
      { label: '姓名', value: '' },
      { label: '手机', value: null },
      { label: '部门', value: undefined },
    ])
    for (const r of rows(c)) {
      expect(r.value).toBe('未填写')
      expect(r.empty).toBe(true)
    }
  })

  test('有值行不带 is-empty（样式钩子不能常亮）', async () => {
    const c = await open([
      { label: 'A', value: 'x' },
      { label: 'B', value: '' },
    ])
    expect(rows(c).map((r) => r.empty)).toEqual([false, true])
  })

  test('字符串 "0" / "false" / " " 都是非空输入，不得判成「未填写」', async () => {
    // 真实取值域是表单字符串（RegisterView 的 summaryItems 全部来自
    // registerForm 的字符串字段）：用户填的手机号尾号 '0'、部门名 'false'
    // 都是有效输入，用 trim() 之类的额外判据把它们清空就是数据被界面吞掉。
    // 数字 0 / 布尔 false 属父级类型漂移（当前调用点不可能出现），
    // 组件按空处理是保守行为，不为其编造断言。
    const c = await open([
      { label: 'a', value: '0' },
      { label: 'b', value: 'false' },
      { label: 'c', value: ' ' },
    ])
    expect(rows(c)).toEqual([
      { label: 'a', value: '0', empty: false },
      { label: 'b', value: 'false', empty: false },
      { label: 'c', value: ' ', empty: false },
    ])
  })

  test('空数组：不渲染任何行也不抛错', async () => {
    const c = await open([])
    expect(c.findAll('.summary__row')).toEqual([])
    expect(c.find('.summary__title').textContent.trim()).toBe('信息核对')
    expect(c.errors).toEqual([])
  })

  test('值按原样显示（不 trim、不改写：用户输入的空格可能是有意的）', async () => {
    const c = await open([{ label: 'a', value: '  spaced  ' }])
    expect(rows(c)[0].value).toBe('  spaced  ')
  })

  test('卸载后不残留 DOM（跨用例不污染；unmount 不再移除挂载根时会失败）', async () => {
    // 进入本用例时前序用例必须已清场（afterEach 的 unmount 若被删，这里先红）
    expect(document.body.querySelectorAll('.summary').length).toBe(0)
    const before = document.body.querySelectorAll('.summary').length
    const c = await open([{ label: 'A', value: 'x' }])
    expect(document.body.querySelectorAll('.summary').length).toBe(before + 1)
    c.handle.unmount()
    active = null
    expect(document.body.querySelectorAll('.summary').length).toBe(before)
  })

  test('切到英文后标题与空值占位跟随（渲染期求值）', async () => {
    const c = await open([{ label: 'Name', value: '' }], 'en-US')
    expect(c.find('.summary__title').textContent.trim()).toBe('Review Details')
    expect(rows(c)[0].value).toBe('Not provided')

    i18n.global.locale.value = 'zh-CN'
    await flush(4)
    expect(c.find('.summary__title').textContent.trim()).toBe('信息核对')
    expect(rows(c)[0].value).toBe('未填写')
    await flush(2)
    expect(c.errors).toEqual([])
  })
})
