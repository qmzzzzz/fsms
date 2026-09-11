/**
 * E2E 登录助手（T-2）
 *
 * 契约假设（与 LoginView 现状一致，变更时同步）：
 * - 用户名/密码输入框占位符为「用户名」「密码」；
 * - 登录按钮文案「登录」；
 * - 环境须关闭登录验证码（LOGIN_CAPTCHA_ENABLED=false），否则旅程无法自动化；
 * - 登录成功后进入 /dashboard（或路由守卫重定向的首页）。
 */

/** 通过 UI 完成登录（成功断言由调用方按旅程需要做） */
async function loginViaUI(page, username, password) {
  await page.goto('/login');
  await page.getByPlaceholder('用户名').fill(username);
  await page.getByPlaceholder('密码').fill(password);
  await page.getByRole('button', { name: /^登\s*录$/ }).click();
}

/** 等待进入已登录界面（侧边栏/仪表盘任一可见即认为登录成功） */
async function expectLoggedIn(page) {
  await page.waitForURL(/\/dashboard(?:\?.*)?$/, { timeout: 20_000 });
}

module.exports = { loginViaUI, expectLoggedIn };
