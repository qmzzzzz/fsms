<template>
  <div
    class="glass-skeleton"
    :class="`glass-skeleton--${variant}`"
    role="status"
    :aria-label="label"
  >
    <!-- detail：头像 + 标题 + 正文（个人资料卡等） -->
    <template v-if="variant === 'detail'">
      <div class="gs-detail">
        <div class="sk-block sk-avatar gs-detail__avatar" :style="avatarStyle" />
        <div class="sk-block gs-detail__name" />
        <div class="sk-block gs-detail__role" />
        <div class="gs-detail__meta">
          <div v-for="i in rows" :key="i" class="gs-detail__row">
            <span class="sk-block gs-detail__icon" />
            <span
              class="sk-block sk-text gs-detail__field"
              :style="{ width: fieldWidths[(i - 1) % fieldWidths.length] }"
            />
          </div>
        </div>
      </div>
    </template>

    <!-- welcome：标题正文居左 + 头像居右（仪表盘欢迎卡） -->
    <template v-else-if="variant === 'welcome'">
      <div class="gs-welcome">
        <div class="gs-welcome__text">
          <div class="sk-block gs-welcome__title" />
          <div class="sk-block gs-welcome__sub" />
        </div>
        <div class="sk-block sk-avatar gs-welcome__avatar" :style="avatarStyle" />
      </div>
    </template>

    <!-- stat：统计卡（标签/数值/趋势 + 图标块） -->
    <template v-else-if="variant === 'stat'">
      <div class="gs-stat">
        <div class="gs-stat__info">
          <div class="sk-block gs-stat__label" />
          <div class="sk-block gs-stat__value" />
          <div class="sk-block gs-stat__trend" />
        </div>
        <div class="sk-block gs-stat__icon" />
      </div>
    </template>

    <!-- chart：图表区整块占位 -->
    <template v-else-if="variant === 'chart'">
      <div class="sk-block gs-chart__block" />
    </template>

    <!-- table：表头 + 数据行（列表页首屏） -->
    <template v-else>
      <div class="gs-table">
        <div class="gs-table__row gs-table__row--head">
          <span
            v-for="(w, i) in cols"
            :key="'h' + i"
            class="sk-block gs-table__cell"
            :style="{ width: w }"
          />
        </div>
        <div v-for="r in rows" :key="r" class="gs-table__row">
          <span
            v-for="(w, i) in cols"
            :key="r + '-' + i"
            class="sk-block gs-table__cell"
            :style="{ width: w }"
          />
        </div>
      </div>
    </template>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'

const props = defineProps({
  /** detail | welcome | stat | chart | table */
  variant: { type: String, default: 'table' },
  /** table/detail 变体的行数 */
  rows: { type: Number, default: 6 },
  /** table 变体各列宽度（对应真实表格列数） */
  cols: {
    type: Array,
    default: () => ['10%', '28%', '22%', '20%', '20%'],
  },
  /** 头像占位直径（px） */
  avatarSize: { type: Number, default: 64 },
})

const { t } = useI18n()
const label = t('common.loading')

const avatarStyle = computed(() => ({
  width: `${props.avatarSize}px`,
  height: `${props.avatarSize}px`,
}))

const fieldWidths = ['62%', '78%', '54%', '70%', '44%']
</script>

<style scoped>
/* 骨架屏全部视觉实现（灰块 .sk-block / ::after 扫光 / .gs-* 布局）统一由
   assets/styles/global.css 提供：
   - 灰色占位块固定几何占用，头像/标题/正文位置与真实内容同构；
   - 柔和亮光由占位块自身 ::after 伪元素从左往右扫过，块本体零位移不缩放不抖动；
   - 内容到达后由父组件用 v-if/v-else 同构布局直接替换，页面不发生跳转。 */
.glass-skeleton {
  width: 100%;
  /* 防止布局跳动：占位块使用固定尺寸，不参与 flex/grid 收缩 */
  contain: layout style;
}
</style>
