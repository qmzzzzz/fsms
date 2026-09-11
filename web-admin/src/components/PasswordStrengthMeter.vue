<template>
  <!-- 口令强度实时条：原实现只在 blur 后抛一句「须包含大小写字母、
       数字和特殊字符」，用户得反复试错才知道差哪一项。
       判据复用 evaluatePasswordRules，与提交时的校验同源。 -->
  <div class="pwd-meter">
    <div class="pwd-meter__head">
      <span class="pwd-meter__label">{{ $t('register.pwdStrength') }}</span>
      <span class="pwd-meter__level" :class="`pwd-meter__level--${strength.level}`">
        {{ password ? strength.text : $t('register.pwdEmpty') }}
      </span>
    </div>
    <div class="pwd-meter__track">
      <span
        class="pwd-meter__fill"
        :class="`pwd-meter__fill--${strength.level}`"
        :style="{ transform: `scaleX(${pwdRules.total ? pwdRules.passed / pwdRules.total : 0})` }"
      />
    </div>
    <ul class="pwd-meter__rules">
      <li v-for="r in pwdRuleItems" :key="r.key" :class="{ 'is-ok': r.ok }">
        <el-icon>
          <CircleCheck v-if="r.ok" />
          <Minus v-else />
        </el-icon>
        {{ r.text }}
      </li>
    </ul>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { evaluatePasswordRules } from '@/utils/password'
import { CircleCheck, Minus } from '@element-plus/icons-vue'

const props = defineProps({
  password: { type: String, default: '' },
})

const { t } = useI18n()

/** 口令规则逐条状态（与提交时的 isStrongPassword 同源判据） */
const pwdRules = computed(() => evaluatePasswordRules(props.password))

const pwdRuleItems = computed(() => [
  { key: 'length', ok: pwdRules.value.length, text: t('register.pwdRuleLength') },
  { key: 'upper', ok: pwdRules.value.upper, text: t('register.pwdRuleUpper') },
  { key: 'lower', ok: pwdRules.value.lower, text: t('register.pwdRuleLower') },
  { key: 'digit', ok: pwdRules.value.digit, text: t('register.pwdRuleDigit') },
  { key: 'symbol', ok: pwdRules.value.symbol, text: t('register.pwdRuleSymbol') },
])

// 强度分档：五条全过才算「强」——因为后端的准入线正是「五条全过」，
// 若把 4/5 也标成强，用户会在提交时被拒，界面与结果自相矛盾
const strength = computed(() => {
  const { passed, satisfied } = pwdRules.value
  if (satisfied) return { level: 'strong', text: t('register.pwdStrengthStrong') }
  if (passed >= 3) return { level: 'fair', text: t('register.pwdStrengthFair') }
  return { level: 'weak', text: t('register.pwdStrengthWeak') }
})
</script>

<style scoped>
/* ===== 口令强度 ===== */
/* 口令强度区不再画成内嵌面板，改用一条发丝分隔线与上方字段分组。
   理由：卡片本身已是面板内的第二层表面，再往里套描边灰底盒子就是第三层，
   而三层用的是同一套「描边 + gray-100」手法，层级无法区分。
   发丝线 + 留白足以表达「这是另一组信息」，内部的进度轨与规则清单
   本身已经提供了足够的视觉结构 */
.pwd-meter {
  margin: 4px 0 20px;
  padding-top: 18px;
  border-top: 1px solid var(--xf-border-color);
}

.pwd-meter__head {
  display: flex;
  justify-content: space-between;
  align-items: baseline;
  margin-bottom: 8px;
  font-family: var(--xf-font-body);
  font-size: var(--xf-font-size-xs);
  color: var(--xf-gray-500);
  letter-spacing: var(--xf-tracking-wide);
}

.pwd-meter__level {
  font-weight: 700;
}
.pwd-meter__level--weak {
  color: var(--xf-danger);
}
.pwd-meter__level--fair {
  color: var(--xf-warning);
}
.pwd-meter__level--strong {
  color: var(--xf-success);
}

.pwd-meter__track {
  height: 6px;
  border-radius: 999px;
  background: var(--xf-gray-200);
  overflow: hidden;
}

.pwd-meter__fill {
  display: block;
  width: 100%;
  height: 100%;
  border-radius: 999px;
  transform-origin: left center;
  transition:
    transform 0.25s var(--xf-ease-glass),
    background-color 0.25s;
}

.pwd-meter__fill--weak {
  background: var(--xf-danger);
}
.pwd-meter__fill--fair {
  background: var(--xf-warning);
}
.pwd-meter__fill--strong {
  background: var(--xf-success);
}

.pwd-meter__rules {
  display: flex;
  flex-wrap: wrap;
  gap: 6px 14px;
  list-style: none;
  margin: 10px 0 0;
  padding: 0;
}

.pwd-meter__rules li {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  font-size: var(--xf-font-size-xs);
  color: var(--xf-gray-500);
  transition: color 0.2s;
}

.pwd-meter__rules li.is-ok {
  color: var(--xf-success-strong);
  font-weight: 600;
}

@media (prefers-reduced-motion: reduce) {
  .pwd-meter__fill {
    transition: none;
  }
}
</style>
