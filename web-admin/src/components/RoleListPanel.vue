<template>
  <!-- 角色列表（D-2 自 RoleView 拆出）：只负责渲染与事件上抛，
       选中/删除/加载逻辑仍归视图层 -->
  <div class="role-list">
    <!-- 首屏骨架：角色列表未加载完成时占位 -->
    <GlassSkeleton
      v-if="loading && roles.length === 0"
      variant="table"
      :rows="6"
      :cols="['58%', '30%', '8%']"
    />
    <template v-else>
      <div
        v-for="role in roles"
        :key="role._id"
        class="glass-role-item"
        :class="{ 'glass-role-item--active': currentRole?._id === role._id }"
        @click="$emit('select', role)"
      >
        <div class="glass-role-item__info">
          <span class="glass-role-item__name">{{ role.name }}</span>
          <span class="glass-role-item__code">{{ role.code }}</span>
        </div>
        <div class="glass-role-item__meta">
          <span class="glass-role-item__count"
            >{{ role.userCount || 0 }}{{ $t('user.title') }}</span
          >
          <button
            v-if="!role.isBuiltIn"
            type="button"
            class="glass-btn glass-btn--danger glass-btn--icon role-delete-btn"
            :title="$t('common.delete')"
            @click.stop="$emit('delete', role)"
          >
            ×
          </button>
          <span v-else class="glass-role-item__builtin">{{ $t('role.builtIn') }}</span>
        </div>
      </div>
    </template>
  </div>
</template>

<script setup>
import GlassSkeleton from '@/components/GlassSkeleton.vue'

defineProps({
  roles: { type: Array, default: () => [] },
  /** 当前选中角色，用于高亮；可为 null */
  currentRole: { type: Object, default: null },
  loading: { type: Boolean, default: false },
})

defineEmits(['select', 'delete'])
</script>

<style scoped>
/* ========== 角色列表 ========== */
.role-list {
  display: flex;
  flex-direction: column;
  gap: var(--xf-spacing-sm);
  max-height: 620px;
  overflow-y: auto;
  padding-right: 4px;
}

.role-list::-webkit-scrollbar {
  width: 5px;
}

.role-list::-webkit-scrollbar-thumb {
  background: var(--xf-border-color-strong);
  border-radius: 5px;
}

.glass-role-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 12px 16px;
  border-radius: var(--xf-radius-md);
  background: var(--xf-bg-glass);
  border: 1px solid var(--xf-border-glass);
  cursor: pointer;
  transition:
    background-color var(--xf-duration-base) var(--xf-ease-standard),
    border-color var(--xf-duration-base) var(--xf-ease-standard),
    box-shadow var(--xf-duration-base) var(--xf-ease-standard),
    transform var(--xf-duration-base) var(--xf-ease-standard);
}

.glass-role-item:hover {
  background: var(--xf-bg-glass-strong);
  transform: translateX(3px);
  box-shadow: var(--xf-shadow-md);
}

.glass-role-item--active {
  background: linear-gradient(135deg, var(--xf-primary-alpha-12), var(--xf-primary-alpha-8));
  border-color: var(--xf-primary-alpha-45);
  box-shadow:
    0 4px 20px var(--xf-primary-alpha-15),
    inset 0 1px 0 rgba(255, 255, 255, 0.6);
}

.glass-role-item--active .glass-role-item__name {
  color: var(--xf-primary);
}

.glass-role-item__info {
  display: flex;
  flex-direction: column;
  gap: 2px;
  min-width: 0;
}

.glass-role-item__name {
  font-size: var(--xf-font-size-base);
  font-weight: 600;
  color: var(--xf-gray-800);
}

.glass-role-item__code {
  font-size: 11px;
  color: var(--xf-gray-500);
  font-family: 'SF Mono', 'Consolas', 'Fira Code', monospace;
  overflow: hidden;
  text-overflow: ellipsis;
}

.glass-role-item__meta {
  display: flex;
  align-items: center;
  gap: var(--xf-spacing-sm);
  flex-shrink: 0;
}

.glass-role-item__count {
  font-size: var(--xf-font-size-xs);
  color: var(--xf-gray-600);
  font-weight: 500;
  background: var(--xf-gray-50);
  padding: 2px 8px;
  border-radius: 8px;
  border: 1px solid var(--xf-border-color);
}

.glass-role-item__builtin {
  font-size: 11px;
  color: var(--xf-warning-strong);
  font-weight: 600;
  background: var(--xf-warning-alpha-8);
  padding: 2px 8px;
  border-radius: 8px;
  border: 1px solid var(--xf-warning-alpha-15);
}

.role-delete-btn {
  width: 26px;
  height: 26px;
  font-size: 15px;
}

/* ========== 触屏与减动效兼容 ========== */
@media (hover: none) {
  .glass-role-item:hover {
    transform: none;
  }
}

@media (prefers-reduced-motion: reduce) {
  .glass-role-item {
    transition: none;
    animation: none;
  }
}
</style>
