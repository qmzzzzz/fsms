;(function () {
  try {
    var mode = localStorage.getItem('themeMode') || 'system'
    // 兼容迁移旧版 sessionStorage 偏好（与 store.initTheme 迁移逻辑一致）
    if (!localStorage.getItem('themeMode')) {
      var legacy = sessionStorage.getItem('darkMode')
      if (legacy === 'true') mode = 'dark'
      else if (legacy === 'false') mode = 'light'
    }
    var dark =
      mode === 'dark' ||
      (mode === 'system' && window.matchMedia('(prefers-color-scheme: dark)').matches)
    var el = document.documentElement
    el.classList.toggle('dark', dark)
    el.style.colorScheme = dark ? 'dark' : 'light'
    var meta = document.querySelector('meta[name="theme-color"]')
    if (meta) meta.setAttribute('content', dark ? '#0a0f1a' : '#c1121f')
  } catch (_) {}
})()
