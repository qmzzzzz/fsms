<template>
  <Teleport to="body">
    <Transition name="palette">
      <div
        v-if="open"
        class="search-palette__overlay"
        @click.self="close"
        @keydown.esc.prevent="close"
      >
        <div
          class="search-palette"
          role="dialog"
          aria-modal="true"
          :aria-label="t('common.searchPalette')"
        >
          <div class="search-palette__input-row">
            <el-icon class="search-palette__input-icon"><Search /></el-icon>
            <input
              ref="inputRef"
              v-model="query"
              class="search-palette__input"
              type="text"
              :placeholder="t('common.searchPlaceholder')"
              role="combobox"
              aria-expanded="true"
              aria-controls="search-palette-list"
              :aria-activedescendant="activeDescendantId"
              @keydown.down.prevent="move(1)"
              @keydown.up.prevent="move(-1)"
              @keydown.enter.prevent="runActive"
            />
            <kbd class="search-palette__kbd">ESC</kbd>
          </div>

          <div
            v-if="flatItems.length"
            id="search-palette-list"
            ref="listRef"
            class="search-palette__list"
            role="listbox"
          >
            <template v-if="filteredViews.length">
              <div class="search-palette__group">{{ t('common.searchViews') }}</div>
              <button
                v-for="(item, i) in filteredViews"
                :id="`sp-item-${i}`"
                :key="item.id"
                type="button"
                class="search-palette__item"
                :class="{ 'is-active': i === activeIndex }"
                role="option"
                :aria-selected="i === activeIndex"
                @mouseenter="activeIndex = i"
                @click="run(item)"
              >
                <el-icon class="search-palette__item-icon"><component :is="item.icon" /></el-icon>
                <span class="search-palette__item-title">
                  <template v-for="(part, pi) in highlightParts(item.title)" :key="pi">
                    <mark v-if="part.mark" class="search-palette__mark">{{ part.text }}</mark>
                    <template v-else>{{ part.text }}</template>
                  </template>
                </span>
                <span v-if="item.group" class="search-palette__item-group">{{ item.group }}</span>
              </button>
            </template>

            <template v-if="filteredActions.length">
              <div class="search-palette__group">{{ t('common.searchActions') }}</div>
              <button
                v-for="(item, j) in filteredActions"
                :id="`sp-item-${filteredViews.length + j}`"
                :key="item.id"
                type="button"
                class="search-palette__item"
                :class="{ 'is-active': filteredViews.length + j === activeIndex }"
                role="option"
                :aria-selected="filteredViews.length + j === activeIndex"
                @mouseenter="activeIndex = filteredViews.length + j"
                @click="run(item)"
              >
                <el-icon class="search-palette__item-icon"><component :is="item.icon" /></el-icon>
                <span class="search-palette__item-title">
                  <template v-for="(part, pi) in highlightParts(item.title)" :key="pi">
                    <mark v-if="part.mark" class="search-palette__mark">{{ part.text }}</mark>
                    <template v-else>{{ part.text }}</template>
                  </template>
                </span>
                <el-icon v-if="item.current" class="search-palette__item-check"><Check /></el-icon>
                <span v-else-if="item.hint" class="search-palette__item-group">{{
                  item.hint
                }}</span>
              </button>
            </template>
          </div>

          <div v-else class="search-palette__empty">{{ t('common.searchNoResults') }}</div>

          <div class="search-palette__footer">
            <span class="search-palette__hint">
              <kbd class="search-palette__kbd">↑↓</kbd>{{ t('common.searchHintNavigate') }}
            </span>
            <span class="search-palette__hint">
              <kbd class="search-palette__kbd">↵</kbd>{{ t('common.searchHintOpen') }}
            </span>
            <span class="search-palette__hint">
              <kbd class="search-palette__kbd">ESC</kbd>{{ t('common.searchHintClose') }}
            </span>
          </div>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>

<script setup>
/**
 * ⌘K 全局搜索面板（Spotlight 式）
 *
 * 数据来源：layout 传入的权限过滤后菜单（props.menu），加上主题/语言/刷新快捷操作。
 * 匹配范围：当前语言标题 + 另一语言标题 + 路由路径（如中文界面输入 "users" 也能命中）。
 * 打开方式：⌘K / Ctrl+K 全局热键（组件内自注册），或父组件调用 expose 的 open()。
 */
import { computed, nextTick, ref, watch, onMounted, onUnmounted } from 'vue'
import { useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { Search, Check, Sunny, Moon, Monitor, Operation, Refresh } from '@element-plus/icons-vue'
import { useAppStore } from '@/store'
import { setLocale } from '@/i18n'
import { haptic } from '@/utils/haptic'
import zhCN from '@/i18n/locales/zh-CN'
import enUS from '@/i18n/locales/en-US'

const props = defineProps({
  menu: { type: Array, default: () => [] },
})

const { t, locale } = useI18n()
const router = useRouter()
const appStore = useAppStore()

const open = ref(false)
const query = ref('')
const activeIndex = ref(0)
const inputRef = ref(null)
const listRef = ref(null)

// 另一语言词表：跨语言检索（中文界面搜英文别名/路径，反之亦然）
const altMessages = computed(() => (locale.value === 'zh-CN' ? enUS : zhCN))
const resolveKey = (messages, key) =>
  key.split('.').reduce((acc, k) => (acc && acc[k] !== undefined ? acc[k] : undefined), messages)
const altT = (key) => resolveKey(altMessages.value, key) || ''

// 菜单扁平化：子项带上父级分组名（如 系统管理 / 用户管理）
const viewItems = computed(() => {
  const list = []
  for (const item of props.menu) {
    if (item.children) {
      for (const child of item.children) {
        list.push({
          id: `view:${child.path}`,
          kind: 'view',
          path: child.path,
          icon: child.icon,
          group: t(item.i18nKey),
          title: t(child.i18nKey),
          altTitle: altT(child.i18nKey),
        })
      }
    } else {
      list.push({
        id: `view:${item.path}`,
        kind: 'view',
        path: item.path,
        icon: item.icon,
        group: '',
        title: t(item.i18nKey),
        altTitle: altT(item.i18nKey),
      })
    }
  }
  return list
})

const actionItems = computed(() => [
  {
    id: 'action:theme-light',
    kind: 'action',
    icon: Sunny,
    title: `${t('common.theme')} · ${t('common.lightMode')}`,
    altTitle: `${altT('common.theme')} · ${altT('common.lightMode')}`,
    current: appStore.themeMode === 'light',
    run: () => appStore.setThemeMode('light'),
  },
  {
    id: 'action:theme-dark',
    kind: 'action',
    icon: Moon,
    title: `${t('common.theme')} · ${t('common.darkMode')}`,
    altTitle: `${altT('common.theme')} · ${altT('common.darkMode')}`,
    current: appStore.themeMode === 'dark',
    run: () => appStore.setThemeMode('dark'),
  },
  {
    id: 'action:theme-system',
    kind: 'action',
    icon: Monitor,
    title: `${t('common.theme')} · ${t('common.autoMode')}`,
    altTitle: `${altT('common.theme')} · ${altT('common.autoMode')}`,
    current: appStore.themeMode === 'system',
    run: () => appStore.setThemeMode('system'),
  },
  {
    id: 'action:language',
    kind: 'action',
    icon: Operation,
    title: t('common.language'),
    altTitle: altT('common.language'),
    hint: locale.value === 'zh-CN' ? '中文' : 'English',
    run: () => {
      const next = locale.value === 'zh-CN' ? 'en-US' : 'zh-CN'
      setLocale(next)
      appStore.setLanguage(next)
      locale.value = next
    },
  },
  {
    id: 'action:refresh',
    kind: 'action',
    icon: Refresh,
    title: t('common.refresh'),
    altTitle: altT('common.refresh'),
    run: () => window.location.reload(),
  },
])

const normalized = computed(() => query.value.trim().toLowerCase())
const matches = (item) => {
  if (!normalized.value) return true
  return [item.title, item.altTitle, item.path || '']
    .filter(Boolean)
    .some((field) => field.toLowerCase().includes(normalized.value))
}

const filteredViews = computed(() => viewItems.value.filter(matches))
const filteredActions = computed(() => actionItems.value.filter(matches))
const flatItems = computed(() => [...filteredViews.value, ...filteredActions.value])

const activeDescendantId = computed(() =>
  flatItems.value.length ? `sp-item-${activeIndex.value}` : undefined
)

// 匹配片段高亮：把标题按查询词切成 text/mark 片段，模板用插值渲染（无 v-html，天然防注入）
const highlightParts = (title) => {
  const q = normalized.value
  if (!q) return [{ text: title }]
  const idx = title.toLowerCase().indexOf(q)
  if (idx === -1) return [{ text: title }]
  const parts = []
  if (idx > 0) parts.push({ text: title.slice(0, idx) })
  parts.push({ text: title.slice(idx, idx + q.length), mark: true })
  if (idx + q.length < title.length) parts.push({ text: title.slice(idx + q.length) })
  return parts
}

const openPalette = () => {
  open.value = true
}

const close = () => {
  open.value = false
}

const move = (delta) => {
  const len = flatItems.value.length
  if (!len) return
  activeIndex.value = (activeIndex.value + delta + len) % len
  nextTick(() => {
    listRef.value
      ?.querySelector('.search-palette__item.is-active')
      ?.scrollIntoView({ block: 'nearest' })
  })
}

const run = (item) => {
  haptic(10)
  close()
  if (item.kind === 'view') {
    router.push(item.path)
  } else {
    item.run()
  }
}

const runActive = () => {
  const item = flatItems.value[activeIndex.value]
  if (item) run(item)
}

// 打开时重置状态并聚焦输入框；关闭时归还焦点由浏览器自然处理
watch(open, async (val) => {
  if (val) {
    query.value = ''
    activeIndex.value = 0
    document.body.style.overflow = 'hidden'
    await nextTick()
    inputRef.value?.focus()
  } else {
    document.body.style.overflow = ''
  }
})

// 查询词变化时高亮回到第一项，避免越界
watch(normalized, () => {
  activeIndex.value = 0
})

// 全局热键：⌘K（macOS）/ Ctrl+K（其他平台），再次按下或 ESC 关闭
const isMac =
  typeof navigator !== 'undefined' && /mac/i.test(navigator.platform || navigator.userAgent || '')

const onGlobalKeydown = (e) => {
  const key = e.key.toLowerCase()
  if (key === 'k' && (isMac ? e.metaKey : e.ctrlKey)) {
    e.preventDefault()
    open.value ? close() : openPalette()
  }
}

onMounted(() => {
  window.addEventListener('keydown', onGlobalKeydown)
})

onUnmounted(() => {
  window.removeEventListener('keydown', onGlobalKeydown)
  if (open.value) document.body.style.overflow = ''
})

defineExpose({ open: openPalette, close })
</script>
