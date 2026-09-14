/**
 * web-admin ESLint 扁平配置
 *
 * 策略与后端 eslint.config.js 保持一致的「增量/棘轮」口径：
 * - 安全与正确性类规则保持 error，构成 CI 硬门禁
 * - 存量代码普遍存在的风格/卫生类规则降为 warn，逐步收敛
 *
 * 2026-08-26 已完成全部五档收敛，当前为 flat/recommended 全量 vue3 推荐。
 * 收敛路径见文件末尾的棘轮清单。
 */
import js from '@eslint/js';
import pluginVue from 'eslint-plugin-vue';
import eslintConfigPrettier from 'eslint-config-prettier';
import globals from 'globals';

export default [
  {
    ignores: [
      'node_modules/**',
      'dist/**',
      'coverage/**',
      'dev-dist/**',
      'public/**',
    ],
  },

  js.configs.recommended,
  // vue3-recommended：全量 Vue 3 推荐规则，在 strongly-recommended 基础上再加入
  // 属性顺序、SFC 块顺序、组件选项顺序、冗余 template/this 等约束。
  ...pluginVue.configs['flat/recommended'],
  // 棘轮第五档（2026-08-26 已收敛）：recommended 预设默认 warn，
  // 代码库本就零违例，将预设中所有 warn 级规则统一提为 error 锁死门禁。
  ...pluginVue.configs['flat/recommended']
    .map((cfg) =>
      cfg.rules
        ? {
            rules: Object.fromEntries(
              Object.entries(cfg.rules)
                .filter(([, v]) => v === 'warn' || (Array.isArray(v) && v[0] === 'warn'))
                .map(([k, v]) => [k, Array.isArray(v) ? ['error', ...v.slice(1)] : 'error']),
            ),
          }
        : null,
    )
    .filter(Boolean),

  {
    files: ['**/*.{js,vue}'],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'module',
      globals: {
        ...globals.browser,
        // Vite 注入
        __VITE_ADDITIONAL_SERVER_ALLOWED_HOSTS: 'readonly',
        // unplugin-auto-import 自动注入的 Vue/Pinia/Router API
        // （无 auto-imports.d.ts 时 ESLint 无从得知，需显式声明避免 no-undef 误报）
        ref: 'readonly',
        reactive: 'readonly',
        computed: 'readonly',
        watch: 'readonly',
        watchEffect: 'readonly',
        onMounted: 'readonly',
        onUnmounted: 'readonly',
        onBeforeUnmount: 'readonly',
        nextTick: 'readonly',
        defineProps: 'readonly',
        defineEmits: 'readonly',
        defineExpose: 'readonly',
        withDefaults: 'readonly',
        useRouter: 'readonly',
        useRoute: 'readonly',
        // vitest
        describe: 'readonly',
        it: 'readonly',
        test: 'readonly',
        expect: 'readonly',
        vi: 'readonly',
        beforeAll: 'readonly',
        afterAll: 'readonly',
        beforeEach: 'readonly',
        afterEach: 'readonly',
      },
    },
    rules: {
      // ===== 安全与正确性：error（CI 硬门禁）=====
      'no-eval': 'error',
      'no-implied-eval': 'error',
      'no-new-func': 'error',
      'no-unsafe-negation': 'error',
      'no-const-assign': 'error',
      'no-dupe-keys': 'error',
      'no-dupe-args': 'error',
      'no-unreachable': 'error',
      'no-empty': ['error', { allowEmptyCatch: true }],
      // XSS 主要注入点：v-html 绑定用户可控内容
      'vue/no-v-html': 'error',
      // 模板里引用不存在的组件/拼错的指令属于渲染期崩溃
      'vue/valid-v-for': 'error',
      'vue/require-v-for-key': 'error',

      // ===== 存量较多的卫生类：warn（逐步收敛）=====
      // no-unused-vars 棘轮第一档（2026-08-25 已收敛）：
      // 清理了 14 处未使用的图标/工具函数导入（详见 git log），提为 error
      'no-unused-vars': ['error', {
        argsIgnorePattern: '^_',
        varsIgnorePattern: '^_',
        caughtErrors: 'none',
      }],
      // no-console 棘轮第二档（2026-08-26 已收敛）：
      // 源码中已无 console.log/info/debug，仅保留 warn/error；构建/测试文件豁免
      'no-console': ['error', { allow: ['warn', 'error'] }],
      'no-prototype-builtins': 'error',
      'no-useless-escape': 'error',
      'no-case-declarations': 'error',
      'vue/multi-word-component-names': 'error',
      // vue/no-unused-components / vue/no-mutating-props 棘轮第三档（2026-08-26 已收敛）
      'vue/no-unused-components': 'error',
      'vue/no-mutating-props': 'error',
    },
  },

  {
    // 构建期配置文件运行在 Node 环境（vite.config.js 等）
    files: ['*.config.js', 'vite.config.js', 'vitest.config.js', 'eslint.config.js'],
    languageOptions: {
      sourceType: 'module',
      globals: {
        ...globals.node,
      },
    },
    rules: {
      'no-console': 'off',
    },
  },

  {
    // 测试文件：运行在 vitest（Node 环境），需 Node 全局变量（Buffer/__dirname/process 等）；
    // 允许 console 输出便于排查
    files: ['src/**/*.{test,spec}.js', 'src/tests/**/*.js'],
    languageOptions: {
      globals: {
        ...globals.node,
      },
    },
    rules: {
      'no-console': 'off',
    },
  },

  // O-12：格式化职责交给 prettier 后，关闭所有与其冲突的风格类规则
  // （vue/max-attributes-per-line、vue/html-indent 等）——必须置于数组末尾，
  // 使其对前述棘轮提级的风格规则具有最终裁决权
  eslintConfigPrettier,
];

/*
 * 棘轮收敛清单（每清完一档把对应规则从 warn 提到 error）：
 * 1. no-unused-vars       —— 2026-08-25 已收敛（清掉 14 处未使用导入）
 * 2. no-console           —— 2026-08-26 已收敛（源码无 log/info/debug，仅留 warn/error）
 * 3. vue/no-unused-components / vue/no-mutating-props —— 2026-08-26 已收敛（零违例，提为 error）
 * 4. 切换 flat/essential → flat/strongly-recommended —— 2026-08-26 已收敛（零违例，25 条规则提为 error）
 * 5. 切换 flat/strongly-recommended → flat/recommended —— 2026-08-26 已收敛（零违例，全量 vue3 推荐提为 error）
 */
