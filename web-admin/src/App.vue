<template>
  <el-config-provider :locale="epLocale">
    <router-view />
  </el-config-provider>
</template>

<script setup>
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import zhCn from 'element-plus/dist/locale/zh-cn.mjs'
import en from 'element-plus/dist/locale/en.mjs'

// Element Plus 组件语言跟随 i18n 当前语言动态切换
const { locale } = useI18n()
const epLocale = computed(() => (locale.value === 'en-US' ? en : zhCn))
</script>

<style>
html,
body,
#app {
  min-height: 100vh;
  min-height: 100dvh;
  margin: 0;
  padding: 0;
}
</style>
