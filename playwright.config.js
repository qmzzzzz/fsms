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
  // 评价报告低危项：CI retries=1 会把偶发失败自动重试成绿，掩盖真实抖动；
  // E2E 是发布门禁，失败应显性暴露并排查，故统一 0 重试。
  retries: 0,
  reporter: [['list'], ['html', { open: 'never' }]],
  use: {
    baseURL: process.env.E2E_BASE_URL || 'http://127.0.0.1:3000',
    // 与 retries:0 联动的不变量（由 src/tests/zzqoder_playwrightConfig.test.js 守住）：
    // 'on-first-retry' 的语义是「仅首次重试时录制并保留 trace」，而 retries:0 意味着
    // 永远不存在第二次尝试——该取值在本配置下等价于「不留任何失败现场」，
    // 与上方「失败应显性暴露并排查」直接矛盾。retain-on-failure 才是 0 重试下
    // 的正确取值（首次失败即保留）。
    trace: 'retain-on-failure',
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
