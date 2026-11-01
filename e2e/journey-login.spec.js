/**
 * 旅程 1：登录与错误分支
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
  // 判据必须是「请求真的发出 + 后端真的拒绝 + 页面上出现拒绝语义的提示」。
  // 不能用一条正则在页面文本里找关键词：LoginView.vue:158-160 恒渲染 login.tip
  // （zh-CN.js:1249 = 请使用系统分配的账号登录本系统），旧正则以 /请使用系统分配的账号/
  // 作兜底，于是"停在登录页"这一事实冒充了"有明确提示"——点击无效、提示被吞、
  // 接口 500 全都照绿（第四轮审计 D1）。
  const loginResponse = page.waitForResponse(
    (resp) => resp.url().includes('/api/auth/login') && resp.request().method() === 'POST',
    { timeout: 20_000 }
  );
  await loginViaUI(page, USER, 'Wrong-' + Date.now());
  const resp = await loginResponse;
  // ① 后端确实拒绝了（401 + success:false），而不是请求没发出或前端短路
  expect(resp.status()).toBe(401);
  const body = await resp.json().catch(() => null);
  expect(body && body.success).toBe(false);
  // ② 仍停在登录页：错误口令没有被放行
  await expect(page).toHaveURL(/\/login(?:[?#].*)?$/);
  // ③ 只认「拒绝语义」的提示，并限定在消息条内——登录页静态提示不在 .el-message 里，
  //    所以"提示被吞掉"时会红，而不是被静态文案救活
  await expect(
    page
      .locator('.el-message--error')
      .filter({ hasText: /用户名或密码错误|登录失败，请核对用户名与密码/ })
  ).toBeVisible({ timeout: 10_000 });
});
