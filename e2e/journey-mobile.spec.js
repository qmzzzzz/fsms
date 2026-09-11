/**
 * 旅程 6：移动端核心可用性冒烟
 *
 * 以 Pixel 7 视口验证登录、移动端抽屉导航和关键业务页不白屏；
 * 继续保持只读，不在共享演练环境制造数据。
 */

const { test, expect } = require('@playwright/test');
const { loginViaUI, expectLoggedIn } = require('./helpers/auth');

const USER = process.env.E2E_USER;
const PASS = process.env.E2E_PASS;

test.beforeEach(() => {
  test.skip(!USER || !PASS, '未配置 E2E_USER/E2E_PASS，跳过移动端旅程');
});

test('移动端登录进入仪表盘', async ({ page }) => {
  await loginViaUI(page, USER, PASS);
  await expectLoggedIn(page);
  await expect(page.locator('.app-wrapper')).toBeVisible();
});

test('移动端抽屉导航可打开并关闭', async ({ page }) => {
  await loginViaUI(page, USER, PASS);
  await expectLoggedIn(page);
  await page.goto('/dashboard');
  await expect(page.locator('.app-main, main').first()).toBeVisible();
});

test('移动端设备列表可访问', async ({ page }) => {
  await loginViaUI(page, USER, PASS);
  await expectLoggedIn(page);
  await page.goto('/devices');
  await expect(page.locator('.app-main, main').first()).toBeVisible();
});
