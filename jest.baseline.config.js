/**
 * 覆盖率基线临时配置（仅本地分析用，验证后删除）
 *
 * 继承 jest.config.js，仅覆盖两点：
 * 1. coverageThreshold 全置 0 —— 只跑目标子集时全局阈值必然不达标，避免
 *    非零退出码干扰脚本判断；
 * 2. coverageReporters 只留 json —— 需要 coverage-final.json 的逐行/逐分支
 *    未覆盖位置（json-summary 没有行号粒度）。
 */
const base = require('./jest.config.js');

module.exports = {
  ...base,
  coverageThreshold: {
    global: { branches: 0, functions: 0, lines: 0, statements: 0 },
  },
  coverageReporters: ['json'],
  collectCoverageFrom: [
    'src/controllers/authController.js',
    'src/middleware/security.js',
    'src/middleware/rbac.js',
  ],
  collectCoverage: true,
};
