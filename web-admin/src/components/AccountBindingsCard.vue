<template>
  <!--
    账户绑定（B 组自助面接线）：GET /api/security/bindings
    后端返回 { bindings: [{ type, value, verified, required }] }，value 为服务端
    脱敏后的值（手机号/邮箱）——本卡片只读展示，不提供改绑入口（改绑走资料编辑）。
  -->
  <el-card shadow="never">
    <template #header>
      <span class="card-header">{{ $t('securitySelf.bindingsTitle') }}</span>
    </template>

    <GlassSkeleton v-if="loading" variant="table" :rows="3" />

    <div v-else-if="error" class="self-error">
      <span>{{ $t('securitySelf.loadFailed') }}</span>
      <button type="button" class="glass-btn glass-btn--default glass-btn--sm" @click="load">
        {{ $t('common.refresh') }}
      </button>
    </div>

    <ul v-else-if="bindings.length" class="binding-list">
      <li v-for="item in bindings" :key="item.type" class="binding-item">
        <span class="binding-type">{{ typeLabel(item.type) }}</span>
        <span class="binding-value">{{ item.value || '—' }}</span>
        <span class="binding-tags">
          <el-tag :type="item.verified ? 'success' : 'info'" size="small" effect="plain">
            {{ item.verified ? $t('securitySelf.bound') : $t('securitySelf.unbound') }}
          </el-tag>
          <el-tag v-if="item.required" type="warning" size="small" effect="plain">
            {{ $t('securitySelf.requiredField') }}
          </el-tag>
        </span>
      </li>
    </ul>

    <p v-else class="empty-hint">{{ $t('common.noData') }}</p>
  </el-card>
</template>

<script setup>
/**
 * 账户绑定卡片
 *
 * 端点在 securityRoutes.js:177，此前前端零引用。展示当前账号已绑定的邮箱/
 * 手机号/部门，以及各自的「已绑定/未绑定」与「是否必填」状态。
 *
 * 未知 type 的兜底：直接回显原始 type 字符串（而非空串）——后端将来新增绑定
 * 类型时，用户至少能看到一行「有个东西没被翻译」，而不是整行空白。
 */
import { ref, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { api } from '@/utils/api'
import GlassSkeleton from '@/components/GlassSkeleton.vue'

const { t } = useI18n()

const bindings = ref([])
const loading = ref(true)
const error = ref(false)

const typeLabel = (type) =>
  ({
    email: t('securitySelf.bindingEmail'),
    phone: t('securitySelf.bindingPhone'),
    department: t('securitySelf.bindingDepartment'),
  })[type] || type

const load = async () => {
  loading.value = true
  error.value = false
  try {
    const { data: resp } = await api.security.getAccountBindings()
    bindings.value = Array.isArray(resp.data?.bindings) ? resp.data.bindings : []
  } catch (_) {
    // 错误提示已由拦截器统一处理；清空避免展示过期数据
    bindings.value = []
    error.value = true
  } finally {
    loading.value = false
  }
}

onMounted(load)
defineExpose({ load })
</script>

<style scoped>
.card-header {
  font-family: var(--xf-font-display);
  font-weight: 600;
  letter-spacing: var(--xf-tracking-wide);
}

.self-error {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  font-size: var(--xf-font-size-sm);
  color: var(--xf-text-secondary);
}

.binding-list {
  list-style: none;
  margin: 0;
  padding: 0;
}

.binding-item {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 10px 0;
  border-bottom: 1px solid var(--xf-border-color);
  font-size: var(--xf-font-size-sm);
}

.binding-item:last-child {
  border-bottom: none;
}

.binding-type {
  flex: 0 0 72px;
  color: var(--xf-text-secondary);
}

.binding-value {
  flex: 1;
  min-width: 0;
  color: var(--xf-gray-700);
  word-break: break-all;
}

.binding-tags {
  display: flex;
  gap: 6px;
  flex-shrink: 0;
}

.empty-hint {
  margin: 0;
  font-size: var(--xf-font-size-sm);
  color: var(--xf-text-secondary);
}
</style>
