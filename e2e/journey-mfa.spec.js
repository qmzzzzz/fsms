/**
 * 旅程 2：登录 + MFA 两步验证
 *
 * 前置：E2E_MFA_USER / E2E_MFA_PASS / E2E_MFA_SECRET（base32 种子）。
 * 账号需已开启两步验证；未配置时整组跳过（不作为失败）。
 */

const { test, expect } = require('@playwright/test');
const { loginViaUI, expectLoggedIn } = require('./helpers/auth');
const { generateTotp } = require('./helpers/totp');

const USER = process.env.E2E_MFA_USER;
const PASS = process.env.E2E_MFA_PASS;
const SECRET = process.env.E2E_MFA_SECRET;

test.beforeEach(() => {
  test.skip(!USER || !PASS || !SECRET, '未配置 E2E_MFA_*，跳过 MFA 旅程');
});

/**
 * 提交动态码并带 ±1 窗口重试（2026-11-14 审计：30 秒窗口边界的残余 flake 面）。
 *
 * 两个成因：① 生成与提交之间跨过 30 秒窗口边界；② mfaService 的重放防护
 * （claimTotpWindow：同一时间窗只能被认领一次）——上一条用例/上一次 CI 运行
 * 刚好消费掉当前窗口时，「当前窗口」的码会被当重放拒掉。服务端 verifyTotp
 * 本就接受 ±1 窗口（src/utils/totp.js DEFAULT_WINDOW=1），故被拒后按 +1 / -1
 * 重试：三个候选码对应三个不同计数器，互不触发重放判定。
 * 判据是页面文案：见到「两步验证码错误」才换下一个窗口；其它结果（成功跳转、
 * 网络慢）交由调用方的 expectLoggedIn 收口，这里绝不「没等到拒绝就算成功」。
 */
async function submitTotp(page, mfaInput, secret) {
  for (const offset of [0, 1, -1]) {
    await mfaInput.fill(generateTotp(secret, { windowOffset: offset }));
    // 二阶段沿用同一「登录/确认」按钮；按钮文案为「登 录」（中间有空格），
    // 正则须容忍空白——2026-09-14 CI 实证：/登录|确认|验证/ 匹配不到导致 60s 超时
    await page.getByRole('button', { name: /^登\s*录$/ }).click();
    const rejected = page.getByText('两步验证码错误');
    const wasRejected = await rejected
      .waitFor({ state: 'visible', timeout: 5_000 })
      .then(() => true)
      .catch(() => false);
    if (!wasRejected) return;
  }
}

test('口令 + 动态码完成两步登录', async ({ page }) => {
  await loginViaUI(page, USER, PASS);
  const mfaInput = page.getByPlaceholder('动态验证码 / 备用恢复码');
  await expect(mfaInput).toBeVisible({ timeout: 15_000 });
  await submitTotp(page, mfaInput, SECRET);
  await expectLoggedIn(page);
});

test('错误的动态码被拒', async ({ page }) => {
  await loginViaUI(page, USER, PASS);
  const mfaInput = page.getByPlaceholder('动态验证码 / 备用恢复码');
  await expect(mfaInput).toBeVisible({ timeout: 15_000 });
  await mfaInput.fill('000000');
  await page.getByRole('button', { name: /^登\s*录$/ }).click();
  // 判别性断言是这条后端拒绝文案：errorCodes.js MFA_CODE_INVALID「两步验证码错误」
  // 经 api.js 拦截器以 ElMessage 弹出（zh-CN.js errors.mfaCodeInvalid）。
  // 若后端误放行动态码，就不会有拒绝提示，用例立即变红。
  // 原正则 /验证码错误|MFA|两步验证/ 的后两个分支在页面上没有任何渲染文本可命中
  // （「两步验证」只出现在 LoginView.vue 的注释里），保留只会掩盖未来的文案漂移。
  await expect(page.getByText('两步验证码错误')).toBeVisible({ timeout: 10_000 });
  // 且不得建立会话：仍停在登录页、仍是二期动态口令状态
  // （LoginView 的失败分支刻意保留 mfaRequired 只清空输入，让用户直接重输）
  await expect(page).toHaveURL(/\/login/);
  await expect(mfaInput).toBeVisible();
});
