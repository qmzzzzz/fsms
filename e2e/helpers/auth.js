/**
 * E2E 登录助手
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

/**
 * 通过敏感读取的 step-up 二次验证（P3-2）。
 *
 * 审计/告警等页面在没有短期票据时会先弹「验证身份」，填当前口令换取票据后才拉数据。
 * 账号无对应权限或已有票据时不会弹层，直接返回即可（后续断言自行处理 403/表格）。
 */
async function passStepUp(page, password) {
  const dialog = page.locator('.el-dialog').filter({ hasText: '验证身份' });
  const appeared = await dialog
    .waitFor({ state: 'visible', timeout: 5_000 })
    .then(() => true)
    .catch(() => false);
  if (!appeared) return;
  await dialog.locator('input[type="password"]').fill(password);
  await dialog.getByRole('button', { name: /^确\s*定$/ }).click();
  await dialog.waitFor({ state: 'hidden', timeout: 20_000 });
}

module.exports = { loginViaUI, expectLoggedIn, passStepUp };
