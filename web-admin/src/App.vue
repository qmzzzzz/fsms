<template>
  <el-config-provider :locale="epLocale">
    <router-view />
  </el-config-provider>
</template>

<script setup>
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
// 必须走 es/locale/lang 深路径：Element Plus 的 useLocale 内部已静态引入
// es/locale/lang/en.mjs 作为缺省语言，若这里再从 dist/locale 引入，同一份
// 语言包会在首屏打包两遍（实测 en 重复约 4.7KB 源码，直接顶爆首屏 gzip 预算）。
import zhCn from 'element-plus/es/locale/lang/zh-cn.mjs'
import en from 'element-plus/es/locale/lang/en.mjs'

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
