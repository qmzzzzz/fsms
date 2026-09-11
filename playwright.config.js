/**
 * Playwright 配置（T-2）
 *
 * 设计取向：
 * - 不自带 webServer——E2E 必须打「完整栈」（后端 + 真实 Mongo + 前端产物），
 *   由部署/开发环境先行启动（见 e2e/README.md），避免把内存库冒烟当浏览器回归；
 * - baseURL 可经 E2E_BASE_URL 覆盖（本机默认 3000 端口，生产演练可指反代）；
 * - 凭据一律走环境变量（E2E_USER/E2E_PASS/E2E_MFA_*），用例里无字面量。
 */

const { defineConfig, devices } = require('@playwright/test');

module.exports = defineConfig({
  testDir: './e2e',
  timeout: 60_000,
  fullyParallel: false, // 旅程间可能有数据依赖，串行降低相互干扰
  retries: process.env.CI ? 1 : 0,
  reporter: [['list'], ['html', { open: 'never' }]],
  use: {
    baseURL: process.env.E2E_BASE_URL || 'http://127.0.0.1:3000',
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    // 管理后台以中文为主，锁定语言避免文案选择器漂移
    locale: 'zh-CN',
    timezoneId: 'Asia/Shanghai',
  },
  projects: [
    {
      name: 'desktop-chromium',
      use: { ...devices['Desktop Chrome'] },
    },
    {
      name: 'mobile-chrome',
      use: { ...devices['Pixel 7'] },
    },
  ],
});
