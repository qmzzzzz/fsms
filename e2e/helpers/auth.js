/**
 * E2E 登录助手
 *
 * 契约假设（与 LoginView 现状一致，变更时同步）：
 * - 用户名/密码输入框占位符为「用户名」「密码」；
 * - 登录按钮文案「登录」；
 * - 环境须关闭登录验证码（LOGIN_CAPTCHA_ENABLED=false），否则旅程无法自动化；
 * - 登录成功后进入 /dashboard（或路由守卫重定向的首页）。
 */

const { test } = require('@playwright/test');

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

/**
 * 前置条件不满足时的统一处置：**本地跳过（留可见原因），CI 一律失败**。
 *
 * 为什么不能只写 `test.skip(true, …)`：Playwright 把跳过计入 skipped，而本仓只有 CI 的
 * 「Assert no skipped journeys」（.github/workflows/ci.yml 的 e2e-browser job）会因此判红。
 * 本地直跑或其他流水线没有这道门 ⇒「前置没满足」被呈现成「全绿」，正是第四轮审计点名的
 * 假绿形态（e2e/README.md:17-27 已把「本地绿 ≠ CI 绿」写在明面上）。
 * CI 上直接失败还比 skip 多一条信息：报错带上原因，而不是只报「有一条旅程被跳过」。
 *
 * @param {string} reason 已写好的原因（进 reporter，同时打到 stdout 便于在日志里搜）
 */
function skipLocallyOrFail(reason) {
  if (process.env.CI) {
    throw new Error('E2E 前置不满足：' + reason + '（CI 上不允许跳过：跳过等于把前置缺口藏起来）');
  }
  console.warn('[e2e] 跳过：' + reason + '（本地允许跳过；CI 上同样的情形会判失败）');
  test.skip(true, reason + '（本地跳过；CI 上不跳过）');
}

/**
 * 前端可达性前置：本地不可达时跳过（留可见原因），CI 一律判失败。
 *
 * 故障注入的前提是页面本身能加载，但「前置没满足」绝不能变成静默跳过：本仓只有 CI 的
 * 「Assert no skipped journeys」把 skipped 判红，本地直跑时一条 test.skip(true) 就把
 * 「0 执行」包装成全绿（第四轮审计 D2）。
 * 响应码也一并检查：前端容器在跑但只剩一个 500 的静态壳（构建失败/产物缺失）同样是
 * 「页面不可用」，只看 goto 是否抛错会漏掉。
 */
async function ensureAppAvailable(page) {
  try {
    const resp = await page.goto('/', { timeout: 10_000 });
    if (!resp || !resp.ok()) throw new Error('HTTP ' + (resp ? resp.status() : '无响应'));
  } catch (err) {
    const detail = err && err.message ? String(err.message).split('\n')[0] : String(err);
    skipLocallyOrFail('前端不可达（' + detail + '）：故障注入的前提是页面能加载');
  }
}
module.exports = { loginViaUI, expectLoggedIn, passStepUp, skipLocallyOrFail, ensureAppAvailable };
