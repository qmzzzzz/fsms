/**
 * ESLint 扁平配置（L-06 整改：静态检查接入 CI）
 * 策略：以官方推荐规则为基线；曾将"存量代码普遍存在、非安全类"的规则降级为警告，
 * 按棘轮清单逐档收敛。2026-08-26 五档全部收敛完毕，当前为 recommended 全量 error，
 * 收敛路径见文件末尾的棘轮清单。
 */
const js = require('@eslint/js');

module.exports = [
  js.configs.recommended,
  {
    ignores: [
      'node_modules/**',
      'coverage/**',
      'logs/**',
      'backups/**',
      'web-admin/**',
      'src/docs/openapi.json',
      // k6 脚本运行于 k6 运行时（ESM + k6 专有模块），非 Node 代码
      'scripts/perf/k6-*.js',
    ],
  },
  {
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'commonjs',
      globals: {
        // Node.js 全局
        require: 'readonly',
        module: 'writable',
        exports: 'writable',
        process: 'readonly',
        console: 'readonly',
        global: 'readonly',
        URLSearchParams: 'readonly',
        AbortController: 'readonly',
        TextDecoder: 'readonly',
        TextEncoder: 'readonly',
        __dirname: 'readonly',
        __filename: 'readonly',
        Buffer: 'readonly',
        setTimeout: 'readonly',
        clearTimeout: 'readonly',
        setInterval: 'readonly',
        clearInterval: 'readonly',
        setImmediate: 'readonly',
        URL: 'readonly',
        fetch: 'readonly',
        // Jest
        describe: 'readonly',
        it: 'readonly',
        test: 'readonly',
        expect: 'readonly',
        beforeAll: 'readonly',
        afterAll: 'readonly',
        beforeEach: 'readonly',
        afterEach: 'readonly',
        jest: 'readonly',
      },
    },
    rules: {
      // 安全与正确性相关保持 error
      'no-eval': 'error',
      'no-implied-eval': 'error',
      'no-new-func': 'error',
      'no-unsafe-negation': 'error',
      'no-const-assign': 'error',
      'no-dupe-keys': 'error',
      'no-empty': ['error', { allowEmptyCatch: true }],

      // no-unused-vars 棘轮第一档（2026-08-26 已收敛）：
      // 清理了 13 处未使用的导入/参数（详见 git log），提为 error
      'no-unused-vars': ['error', { argsIgnorePattern: '^_', varsIgnorePattern: '^_', caughtErrors: 'none' }],
      // 棘轮第二档（2026-08-26 已收敛）：代码库已无 new Promise(async ...) 反模式，提为 error
      'no-async-promise-executor': 'error',
      // 棘轮第三档（2026-08-26 已收敛）：全部调用均为 Object.prototype.hasOwnProperty.call 写法，提为 error
      'no-prototype-builtins': 'error',
      // 棘轮第四档（2026-08-26 已收敛）：零违例，提为 error
      'no-useless-escape': 'error',
      'no-regex-spaces': 'error',
      'no-case-declarations': 'error',
      // 棘轮第五档（2026-08-26 已收敛）：零违例，提为 error
      'no-fallthrough': 'error',
      'no-redeclare': 'error',
      'no-global-assign': 'error',
    },
  },
];

/*
 * 棘轮收敛清单（每清完一档把对应规则从 warn 提到 error）：
 * 1. no-unused-vars              —— 2026-08-26 已收敛（清掉 13 处未使用导入/参数）
 * 2. no-async-promise-executor   —— 2026-08-26 已收敛（零违例，提为 error）
 * 3. no-prototype-builtins       —— 2026-08-26 已收敛（零违例，存量均已改为 Object.prototype.hasOwnProperty.call）
 * 4. no-useless-escape / no-regex-spaces / no-case-declarations —— 2026-08-26 已收敛（零违例，提为 error）
 * 5. no-fallthrough / no-redeclare / no-global-assign —— 2026-08-26 已收敛（零违例，提为 error）
 *
 * 至此五档全部收敛：warn 存量清零，推荐规则集全量以 error 级锁死 CI 门禁。
 */
