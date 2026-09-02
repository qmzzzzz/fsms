<template>
  <div class="auth-prefs">
    <!-- 主题切换：登录前主布局尚未渲染（侧边栏/顶栏都不可用），若认证页不提供入口，
         偏好暗色的用户会被强制亮色。html.dark 由 main.js 的 initTheme 应用，
         切换后整页立即跟随，无需刷新 -->
    <el-dropdown trigger="click" @command="onThemeCommand">
      <button
        type="button"
        class="auth-prefs__btn"
        :title="t('common.theme')"
        :aria-label="t('common.theme')"
      >
        <el-icon class="auth-prefs__icon">
          <Monitor v-if="themeMode === 'system'" />
          <Sunny v-else-if="themeMode === 'light'" />
          <Moon v-else />
        </el-icon>
        <span class="auth-prefs__text">{{ themeLabel }}</span>
        <el-icon class="auth-prefs__arrow">
          <ArrowDown />
        </el-icon>
      </button>
      <template #dropdown>
        <el-dropdown-menu>
          <el-dropdown-item command="system" :class="{ 'is-active': themeMode === 'system' }">
            {{ t('common.autoMode') }}
          </el-dropdown-item>
          <el-dropdown-item command="light" :class="{ 'is-active': themeMode === 'light' }">
            {{ t('common.lightMode') }}
          </el-dropdown-item>
          <el-dropdown-item command="dark" :class="{ 'is-active': themeMode === 'dark' }">
            {{ t('common.darkMode') }}
          </el-dropdown-item>
        </el-dropdown-menu>
      </template>
    </el-dropdown>

    <!-- 语言切换：与主题按钮同规格。裸图标在浅色卡片上几乎不可见，
         加边框、底色与当前取值文字后才具备「这是可点的控件」的可见性 -->
    <el-dropdown trigger="click" @command="onLanguageCommand">
      <button
        type="button"
        class="auth-prefs__btn"
        :title="t('common.language')"
        :aria-label="t('common.language')"
      >
        <el-icon class="auth-prefs__icon">
          <Operation />
        </el-icon>
        <span class="auth-prefs__text">{{ languageLabel }}</span>
        <el-icon class="auth-prefs__arrow">
          <ArrowDown />
        </el-icon>
      </button>
      <template #dropdown>
        <el-dropdown-menu>
          <el-dropdown-item command="zh-CN" :class="{ 'is-active': currentLang === 'zh-CN' }">
            中文
          </el-dropdown-item>
          <el-dropdown-item command="en-US" :class="{ 'is-active': currentLang === 'en-US' }">
            English
          </el-dropdown-item>
        </el-dropdown-menu>
      </template>
    </el-dropdown>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { Monitor, Sunny, Moon, Operation, ArrowDown } from '@element-plus/icons-vue'
import { useAppStore } from '@/store'
import { setLocale } from '@/i18n'

/**
 * 认证页偏好控件（主题 + 语言）
 *
 * 登录页与注册页此前各自实现了一遍同一控件，且类名不同（login 用 lang-switch、
 * register 用 pref-btn），随后还出现了「注册页有主题切换、登录页没有」的功能
 * 不对称——两处实现必然漂移。抽成组件后，两个认证页的偏好控件由构造保证一致，
 * 小屏降级规则也只需在此维护一处。
 */
const { t, locale } = useI18n()
const appStore = useAppStore()

// 主题：三态（system/light/dark），与主布局 handleThemeChange 同口径
const themeMode = computed(() => appStore.themeMode)
const themeLabel = computed(
  () =>
    ({
      system: t('common.autoMode'),
      light: t('common.lightMode'),
      dark: t('common.darkMode'),
    })[themeMode.value] || t('common.autoMode')
)

const onThemeCommand = (mode) => {
  appStore.setThemeMode(mode)
}

// 语言：appStore 为持久化事实来源，locale 负责响应式跟随
const currentLang = computed(() => appStore.language || locale.value)
const languageLabel = computed(() => (currentLang.value === 'en-US' ? 'English' : '中文'))

const onLanguageCommand = (lang) => {
  setLocale(lang)
  appStore.setLanguage(lang)
  locale.value = lang
}
</script>

<style scoped>
.auth-prefs {
  display: flex;
  align-items: center;
  gap: 8px;
}

/* 药丸按钮而非裸图标：裸 14px 灰图标在浅色卡片上几乎察觉不到，
   边框 + 底色 + 当前取值文字三者共同提供「可点击」的可见性。
   底色用 gray-100 而非 gray-50——暗色下卡片本体已接近 gray-50，
   同色会让按钮消失在卡片里 */
.auth-prefs__btn {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  height: 32px;
  padding: 0 9px 0 7px;
  border: 1px solid var(--xf-border-color-strong);
  border-radius: 999px;
  background: var(--xf-gray-100);
  color: var(--xf-text-regular);
  font-family: var(--xf-font-body);
  font-size: var(--xf-font-size-xs);
  font-weight: 600;
  letter-spacing: var(--xf-tracking-wide);
  cursor: pointer;
  transition:
    border-color 0.2s,
    background-color 0.2s,
    color 0.2s,
    transform 0.12s ease-out;
}

.auth-prefs__btn:hover {
  border-color: var(--xf-primary);
  background: var(--xf-primary-alpha-8);
  color: var(--xf-primary-light);
}

/* 按压反馈落在 pointer-down：等到 click 才变化会让控件显得迟钝 */
.auth-prefs__btn:active {
  transform: scale(0.96);
  background: var(--xf-primary-alpha-15);
}

.auth-prefs__btn:focus-visible {
  outline: none;
  box-shadow: var(--xf-focus-ring);
}

.auth-prefs__icon {
  font-size: 14px;
}
.auth-prefs__arrow {
  font-size: 11px;
  opacity: 0.7;
}

/* 小屏收成纯图标：375/390px 机型上，卡片头部「logo + 标题 + 两枚带文字药丸」
   并排会把标题挤到只剩几十像素（标题被压成多行甚至溢出容器）。
   收起文字后标题重新拿回空间；title / aria-label 保留语义与长按提示。
   断点内置在组件内，两个认证页无需各自重复声明 */
@media (max-width: 560px) {
  .auth-prefs {
    gap: 6px;
  }

  .auth-prefs__btn {
    width: 34px;
    padding: 0;
    justify-content: center;
  }

  .auth-prefs__text,
  .auth-prefs__arrow {
    display: none;
  }
}

@media (prefers-reduced-motion: reduce) {
  .auth-prefs__btn {
    transition: none;
  }
  .auth-prefs__btn:active {
    transform: none;
  }
}

/* 下拉菜单被 teleport 到 body，scoped 选择器命中不到，必须用 :global */
:global(.el-dropdown-menu__item.is-active) {
  color: var(--xf-primary);
  font-weight: 600;
}
</style>
