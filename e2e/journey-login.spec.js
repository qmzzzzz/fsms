/**
 * 旅程 1：登录与错误分支（T-2）
 *
 * 前置：E2E_USER / E2E_PASS 指向压测/演练账号；后端关闭登录验证码。
 */

const { test, expect } = require('@playwright/test');
const { loginViaUI, expectLoggedIn } = require('./helpers/auth');

const USER = process.env.E2E_USER;
const PASS = process.env.E2E_PASS;

test.beforeEach(() => {
  test.skip(!USER || !PASS, '未配置 E2E_USER/E2E_PASS，跳过登录旅程');
});

test('正确凭据登录进入仪表盘', async ({ page }) => {
  await loginViaUI(page, USER, PASS);
  await expectLoggedIn(page);
});

test('错误口令被拒且有明确提示', async ({ page }) => {
  await loginViaUI(page, USER, 'Wrong-' + Date.now());
  await expect(
    page.getByText(/用户名或密码错误|认证失败|登录失败|请使用系统分配的账号/)
  ).toBeVisible({
    timeout: 10_000,
  });
});
