// 液态玻璃分段控件：JS 驱动滑动指示器。
// 设计说明：
// - 模板保持 el-radio-group + el-radio-button 不变（测试按 .el-radio-button 定位），
//   本指令只在 group 内追加一个绝对定位滑块 .seg-glass__thumb，
//   通过测量当前 .is-active 段的 offsetLeft/offsetWidth 做平移，得到 iOS 式"滑过去"效果。
// - 首次定位不加过渡（避免挂载时从左侧滑入的闪现），此后变更才启用滑动动画。
// - jsdom 无 ResizeObserver，相关 API 全部做存在性守卫；本指令不改变数据流，纯视觉层。

export const vSegGlass = {
  mounted(el) {
    const thumb = document.createElement('div')
    thumb.className = 'seg-glass__thumb'
    thumb.setAttribute('aria-hidden', 'true')
    el.appendChild(thumb)

    const update = () => {
      const active = el.querySelector('.el-radio-button.is-active')
      if (!active) {
        thumb.style.opacity = '0'
        return
      }
      thumb.style.opacity = '1'
      thumb.style.width = `${active.offsetWidth}px`
      thumb.style.height = `${active.offsetHeight}px`
      thumb.style.transform = `translate(${active.offsetLeft}px, ${active.offsetTop}px)`
    }

    // is-active 迁移由 EP 改 class 完成，MutationObserver 捕获即重定位
    const mo = new MutationObserver(update)
    mo.observe(el, { subtree: true, attributes: true, attributeFilter: ['class'] })
    const ro = typeof ResizeObserver !== 'undefined' ? new ResizeObserver(update) : null
    ro?.observe(el)

    // 首帧定位后再开启动画类（--live），避免初次从 0 位滑入
    requestAnimationFrame(() => {
      update()
      el.classList.add('seg-glass--live')
    })
    // 字体异步加载完成会改变分段文字宽度，字体就绪后重测一次
    if (document.fonts?.ready) {
      document.fonts.ready.then(update).catch(() => {})
    }

    el.__segGlass = { mo, ro, thumb }
  },
  unmounted(el) {
    const ctx = el.__segGlass
    if (!ctx) return
    ctx.mo.disconnect()
    ctx.ro?.disconnect()
    ctx.thumb.remove()
    delete el.__segGlass
  },
}

export default vSegGlass
