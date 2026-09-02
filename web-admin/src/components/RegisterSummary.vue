<template>
  <!-- 信息核对：与口令区同一套分组手法（发丝线分隔），
       由 RegisterView 传入 label/value 列表，本组件只负责呈现 -->
  <div class="summary">
    <div class="summary__title">
      {{ $t('register.summaryTitle') }}
    </div>
    <dl class="summary__list">
      <div v-for="item in items" :key="item.label" class="summary__row">
        <dt>{{ item.label }}</dt>
        <dd :class="{ 'is-empty': !item.value }">
          {{ item.value || $t('register.summaryEmpty') }}
        </dd>
      </div>
    </dl>
  </div>
</template>

<script setup>
defineProps({
  /** [{ label, value }] —— label 已由父级完成 i18n */
  items: { type: Array, required: true },
})
</script>

<style scoped>
/* ===== 信息核对 ===== */
/* 与口令区同一套分组手法：发丝线分隔，而非再画一个盒子 */
.summary {
  padding-top: 18px;
  border-top: 1px solid var(--xf-border-color);
}

.summary__title {
  margin-bottom: 10px;
  font-family: var(--xf-font-body);
  font-size: var(--xf-font-size-xs);
  font-weight: 700;
  color: var(--xf-gray-500);
  letter-spacing: var(--xf-tracking-wider);
  text-transform: uppercase;
}

.summary__list {
  margin: 0;
}

.summary__row {
  display: flex;
  justify-content: space-between;
  gap: 16px;
  padding: 9px 0;
  /* 实线发丝线：虚线读作「未定稿的打印表单」，是界面里最廉价的一种分隔，
     Apple 的分隔一律是 1px 实线，靠留白而非线型制造节奏 */
  border-bottom: 1px solid var(--xf-border-color);
  font-size: var(--xf-font-size-sm);
}

.summary__row:last-child {
  border-bottom: none;
}

.summary__row dt {
  color: var(--xf-gray-500);
  flex-shrink: 0;
}

.summary__row dd {
  margin: 0;
  color: var(--xf-gray-900);
  font-weight: 600;
  word-break: break-all;
  text-align: right;
}

.summary__row dd.is-empty {
  color: var(--xf-text-muted);
  font-weight: 400;
}

/* summary 的内嵌面板在暗色下靠 gray-100(#1e293b) 与
   卡片 gray-50(#0f172a) 的明度差分层，方向与亮色相反但层级关系一致 */
html.dark .summary__row {
  border-bottom-color: var(--xf-border-color-strong);
}
</style>
