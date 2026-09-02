<template>
  <!-- 权限模块卡片（D-2 自 RoleView 拆出）：
       本组件是 useRolePermissions 状态机的纯渲染层，
       判定/切换函数经 ui 属性传入，自身不持有编辑状态 -->
  <div class="glass-module-card" :class="`is-${ui.moduleState(module)}`">
    <div class="glass-module-card__header">
      <span class="glass-module-card__icon">{{ module.icon }}</span>
      <span class="glass-module-card__name">{{ module.name }}</span>
      <span class="glass-module-card__state" :class="`is-${ui.moduleState(module)}`">
        {{ ui.moduleStateText(module) }}
      </span>
      <button
        type="button"
        class="glass-btn glass-btn--link glass-btn--sm module-toggle-btn"
        :class="ui.moduleState(module) === 'full' ? 'glass-btn--default' : 'glass-btn--primary'"
        @click="ui.toggleModule(module)"
      >
        {{ ui.moduleState(module) === 'full' ? $t('role.clearModule') : $t('role.selectModule') }}
      </button>
    </div>

    <!-- 启用比例可视化 -->
    <div class="glass-module-card__progress">
      <div
        class="glass-module-card__progress-fill"
        :class="`is-${ui.moduleState(module)}`"
        :style="{ width: ui.modulePercent(module) + '%' }"
      />
    </div>
    <div class="glass-module-card__count">
      {{ $t('role.permEnabled') }} {{ module.activeCount }} / {{ module.permissions.length }} ({{
        ui.modulePercent(module)
      }}%)
    </div>

    <div class="glass-module-card__body">
      <button
        v-for="perm in module.permissions"
        :key="perm._id"
        type="button"
        class="glass-perm-btn"
        :class="{
          'is-on': ui.isPermChecked(perm._id),
          'is-added': ui.isPermAdded(perm._id),
          'is-removed': ui.isPermRemoved(perm._id),
        }"
        :title="ui.permTooltip(perm)"
        @click="ui.togglePerm(perm._id)"
      >
        <span class="glass-perm-btn__check">
          {{ ui.isPermRemoved(perm._id) ? '↺' : ui.isPermChecked(perm._id) ? '✓' : '' }}
        </span>
        <span class="glass-perm-btn__text">
          <span class="glass-perm-btn__name">{{ perm.name }}</span>
          <span class="glass-perm-btn__code">{{ perm.code }}</span>
        </span>
        <span v-if="ui.isPermAdded(perm._id)" class="glass-perm-btn__badge is-added">{{
          $t('common.add')
        }}</span>
        <span v-else-if="ui.isPermRemoved(perm._id)" class="glass-perm-btn__badge is-removed">{{
          $t('common.remove')
        }}</span>
        <span v-else class="glass-perm-btn__type">{{ ui.typeLabel(perm.type) }}</span>
      </button>
    </div>
  </div>
</template>

<script setup>
defineProps({
  /** 模块对象：{ module, name, icon, permissions, activeCount } */
  module: { type: Object, required: true },
  /**
   * useRolePermissions() 的返回对象：卡片只读取其中的判定函数
   * （isPermChecked/.../moduleState 等），不直接操作任何集合。
   * 函数内部读取响应式引用，模板渲染依赖自动建立，勾选变化实时重绘。
   */
  ui: { type: Object, required: true },
})
</script>

<style scoped>
/* ========== 权限模块卡片 ========== */
.glass-module-card {
  background: var(--xf-bg-glass);
  backdrop-filter: blur(16px) saturate(160%);
  -webkit-backdrop-filter: blur(16px) saturate(160%);
  border: 1px solid var(--xf-border-glass);
  border-radius: var(--xf-radius-lg);
  padding: var(--xf-spacing-lg);
  transition:
    background-color var(--xf-duration-base) var(--xf-ease-standard),
    border-color var(--xf-duration-base) var(--xf-ease-standard),
    box-shadow var(--xf-duration-base) var(--xf-ease-standard),
    transform var(--xf-duration-base) var(--xf-ease-standard);
  box-shadow: var(--xf-shadow-sm);
}

.glass-module-card:hover {
  background: var(--xf-bg-glass-strong);
  box-shadow: var(--xf-shadow-lg);
  transform: translateY(-2px);
}

/* 模块状态：部分/全部启用时边框随主色渐进，层级清晰 */
.glass-module-card.is-partial {
  border-color: var(--xf-primary-alpha-25);
}

.glass-module-card.is-full {
  border-color: var(--xf-primary-alpha-45);
  box-shadow:
    0 6px 24px var(--xf-primary-alpha-12),
    inset 0 1px 0 rgba(255, 255, 255, 0.7);
}

.glass-module-card__header {
  display: flex;
  align-items: center;
  gap: var(--xf-spacing-sm);
  margin-bottom: var(--xf-spacing-md);
}

.glass-module-card__icon {
  font-size: 20px;
  line-height: 1;
}

.glass-module-card__name {
  font-size: var(--xf-font-size-base);
  font-weight: 700;
  color: var(--xf-gray-800);
  flex: 1;
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.glass-module-card__state {
  flex-shrink: 0;
  font-size: 11px;
  font-weight: 600;
  padding: 1px 8px;
  border-radius: 999px;
  color: var(--xf-gray-500);
  background: var(--xf-gray-100);
  border: 1px solid var(--xf-border-color);
}

.glass-module-card__state.is-partial {
  color: var(--xf-primary-strong);
  background: var(--xf-primary-alpha-8);
  border-color: var(--xf-primary-alpha-15);
}

.glass-module-card__state.is-full {
  color: #ffffff;
  background: var(--xf-gradient-primary);
  border-color: var(--xf-primary-alpha-45);
}

.module-toggle-btn {
  flex-shrink: 0;
}

/* 启用比例进度条 */
.glass-module-card__progress {
  height: 4px;
  border-radius: 999px;
  background: var(--xf-gray-100);
  overflow: hidden;
  margin-bottom: 6px;
}

.glass-module-card__progress-fill {
  height: 100%;
  border-radius: 999px;
  background: var(--xf-gradient-primary);
  transition: width var(--xf-duration-slow) var(--xf-ease-glass);
}

.glass-module-card__progress-fill.is-none {
  background: var(--xf-gray-300);
}

.glass-module-card__count {
  font-size: 11px;
  color: var(--xf-gray-500);
  margin-bottom: var(--xf-spacing-md);
}

/* ========== 权限项按钮（已有 / 新增 / 待移除 三态明确） ========== */
.glass-module-card__body {
  display: flex;
  flex-wrap: wrap;
  gap: var(--xf-spacing-sm);
}

.glass-perm-btn {
  display: inline-flex;
  align-items: center;
  gap: var(--xf-spacing-sm);
  padding: 6px 10px;
  max-width: 100%;
  min-width: 0;
  font-size: var(--xf-font-size-xs);
  font-weight: 500;
  border: 1px solid var(--xf-border-glass);
  border-radius: var(--xf-radius-sm);
  cursor: pointer;
  background: rgba(255, 255, 255, 0.42);
  color: var(--xf-text-secondary);
  backdrop-filter: blur(6px);
  -webkit-backdrop-filter: blur(6px);
  box-shadow:
    inset 0 1px 0 rgba(255, 255, 255, 0.7),
    var(--xf-shadow-xs);
  user-select: none;
  transition:
    background-color var(--xf-duration-base) var(--xf-ease-standard),
    background-position var(--xf-duration-slow) var(--xf-ease-standard),
    border-color var(--xf-duration-base) var(--xf-ease-standard),
    box-shadow var(--xf-duration-base) var(--xf-ease-standard),
    transform var(--xf-duration-base) var(--xf-ease-standard),
    color var(--xf-duration-base) var(--xf-ease-standard),
    opacity var(--xf-duration-base) var(--xf-ease-standard);
}

.glass-perm-btn:hover {
  background-color: rgba(255, 255, 255, 0.68);
  border-color: var(--xf-border-glass-strong);
  box-shadow:
    inset 0 1px 0 rgba(255, 255, 255, 0.9),
    var(--xf-shadow-sm);
  transform: translateY(-1px);
}

.glass-perm-btn:active {
  transform: translateY(0);
  box-shadow:
    inset 0 1px 0 rgba(255, 255, 255, 0.6),
    var(--xf-shadow-xs);
  transition-duration: var(--xf-duration-fast);
}

.glass-perm-btn:focus-visible {
  outline: 2px solid var(--xf-primary-alpha-45);
  outline-offset: 1px;
}

/* 已启用：红色染色玻璃（与全局主按钮同源） */
.glass-perm-btn.is-on {
  background-image: var(--xf-gradient-primary);
  background-color: transparent;
  color: #ffffff;
  border-color: var(--xf-primary-alpha-45);
  box-shadow: var(--xf-glass-edge-color), var(--xf-shadow-primary);
  font-weight: 600;
  text-shadow: var(--xf-text-shadow-dark);
}

.glass-perm-btn.is-on:hover {
  background-image: var(--xf-gradient-primary-hover);
  border-color: var(--xf-primary-alpha-55);
  box-shadow: var(--xf-glass-edge-color-hover), var(--xf-shadow-primary-strong);
}

/* 待移除：琥珀虚线 + 半透明，hover 恢复提示明确 */
.glass-perm-btn.is-removed {
  border: 1px dashed var(--xf-warning-alpha-45);
  background: var(--xf-warning-alpha-8);
  color: var(--xf-warning-strong);
  opacity: 0.78;
}

.glass-perm-btn.is-removed:hover {
  opacity: 1;
  border-color: var(--xf-warning);
  transform: translateY(-1px);
  box-shadow: 0 2px 8px var(--xf-warning-alpha-15);
}

/* 选中圈 */
.glass-perm-btn__check {
  width: 16px;
  height: 16px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  border-radius: var(--xf-radius-circle);
  background: rgba(15, 23, 42, 0.08);
  color: transparent;
  font-size: 11px;
  font-weight: 700;
  flex-shrink: 0;
  transition:
    background-color var(--xf-duration-base) var(--xf-ease-standard),
    color var(--xf-duration-base) var(--xf-ease-standard);
}

.glass-perm-btn.is-on .glass-perm-btn__check {
  background: rgba(255, 255, 255, 0.35);
  color: #ffffff;
}

.glass-perm-btn.is-removed .glass-perm-btn__check {
  background: var(--xf-warning-alpha-15);
  color: var(--xf-warning-strong);
}

/* 权限文本：名称 + 编码两行，超宽换行展示不截断（保证已有权限完整可见） */
.glass-perm-btn__text {
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  gap: 1px;
  min-width: 0;
  line-height: 1.3;
}

.glass-perm-btn__name {
  font-weight: 600;
  white-space: normal;
  word-break: break-all;
  max-width: 168px;
}

.glass-perm-btn__code {
  font-size: 10px;
  font-family: 'SF Mono', 'Consolas', 'Fira Code', monospace;
  opacity: 0.72;
  white-space: normal;
  word-break: break-all;
  max-width: 168px;
}

/* 类型标签 / 差异角标 */
.glass-perm-btn__type {
  flex-shrink: 0;
  font-size: 10px;
  font-weight: 600;
  padding: 1px 6px;
  border-radius: 6px;
  color: var(--xf-gray-500);
  background: rgba(15, 23, 42, 0.05);
  border: 1px solid var(--xf-border-color);
}

.glass-perm-btn.is-on .glass-perm-btn__type {
  color: rgba(255, 255, 255, 0.9);
  background: rgba(255, 255, 255, 0.16);
  border-color: rgba(255, 255, 255, 0.35);
}

.glass-perm-btn__badge {
  flex-shrink: 0;
  font-size: 10px;
  font-weight: 700;
  padding: 1px 6px;
  border-radius: 6px;
}

.glass-perm-btn__badge.is-added {
  color: var(--xf-primary-deep);
  background: rgba(255, 255, 255, 0.85);
  border: 1px solid rgba(255, 255, 255, 0.95);
}

.glass-perm-btn__badge.is-removed {
  color: var(--xf-warning-strong);
  background: var(--xf-warning-alpha-15);
  border: 1px solid var(--xf-warning-alpha-30);
}

/* ========== 触屏与减动效兼容 ========== */
@media (hover: none) {
  .glass-perm-btn:hover,
  .glass-module-card:hover {
    transform: none;
  }
}

@media (prefers-reduced-motion: reduce) {
  .glass-perm-btn,
  .glass-module-card,
  .glass-module-card__progress-fill {
    transition: none;
    animation: none;
  }
}
</style>
