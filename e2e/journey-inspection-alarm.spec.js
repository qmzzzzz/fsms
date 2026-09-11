/**
 * 旅程 3：巡检与告警的查看链路（T-2）
 *
 * 以「只读巡场」方式覆盖核心业务页：列表能渲染、空态/数据态不白屏。
 * 不做数据变更（写路径由专用演练账号与造数脚本负责，避免污染共享环境）。
 */

const { test, expect } = require('@playwright/test');
const { loginViaUI, expectLoggedIn } = require('./helpers/auth');

const USER = process.env.E2E_USER;
const PASS = process.env.E2E_PASS;

test.beforeEach(async ({ page }) => {
  test.skip(!USER || !PASS, '未配置 E2E_USER/E2E_PASS，跳过业务旅程');
  await loginViaUI(page, USER, PASS);
  await expectLoggedIn(page);
});

test('巡检列表可访问且渲染表格', async ({ page }) => {
  await page.goto('/inspections');
  await expect(page.getByText(/巡检/).first()).toBeVisible({ timeout: 15_000 });
  // 表格骨架（Element Plus 表格）出现即证明未白屏
  await expect(page.locator('.el-table')).toBeVisible({ timeout: 15_000 });
});

test('告警列表可访问且渲染表格', async ({ page }) => {
  await page.goto('/alarms');
  await expect(page.locator('.el-table')).toBeVisible({ timeout: 15_000 });
});

test('设备列表可访问且渲染表格', async ({ page }) => {
  await page.goto('/devices');
  await expect(page.locator('.el-table')).toBeVisible({ timeout: 15_000 });
});
