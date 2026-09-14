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
      'no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_', caughtErrors: 'none' },
      ],
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

      // 棘轮第六档（O-3，2026-09-05）：体积棘轮，warn 级 + 基线锁死不增。
      // 首次基线为 94 个文件共 133 条 warn；经多轮瘦身与 e2e 纳入 lint 后，
      // 当前基线（eslint.ratchet.json）：16 个文件共 17 条 warn，集中在
      // initData/authService/securityController 等大文件与长测试套件——
      // 正是控制器瘦身与拆分的后续目标。与第五档「清零后提 error」不同，
      // 体积债短期清不完，故走 warn + scripts/lint-ratchet.js 逐文件计数
      // 基线：任何文件计数只许降不许升，降后以
      // `npm run lint:ratchet -- --update-baseline` 收紧。
      // 这与 O-1/O-2 的控制器瘦身直接互锁：新增胖 handler 会立刻顶爆基线。
      'max-lines': ['warn', { max: 300, skipBlankLines: true, skipComments: true }],
      'max-lines-per-function': [
        'warn',
        { max: 100, skipBlankLines: true, skipComments: true, IIFEs: true },
      ],
    },
  },
  {
    files: ['src/tests/**/*.js'],
    rules: {
      'max-lines': 'off',
      'max-lines-per-function': 'off',
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
 * 6. max-lines / max-lines-per-function（体积棘轮，O-3 2026-09-05）—— warn 级 +
 *    scripts/lint-ratchet.js 基线锁死不增（eslint.ratchet.json），降后手动收紧基线。
 *    体积债与 linter 错误性质不同：后者清零即收，前者须随瘦身逐步消化，
 *    故不适用「提 error」终点式收敛，而是永久随基线下行。
 *
 * 至此五档全部收敛：warn 存量清零，推荐规则集全量以 error 级锁死 CI 门禁。
 */
