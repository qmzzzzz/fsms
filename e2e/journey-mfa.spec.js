/**
 * 旅程 2：登录 + MFA 两步验证（T-2）
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

test('口令 + 动态码完成两步登录', async ({ page }) => {
  await loginViaUI(page, USER, PASS);
  const mfaInput = page.getByPlaceholder('动态验证码 / 备用恢复码');
  await expect(mfaInput).toBeVisible({ timeout: 15_000 });
  await mfaInput.fill(generateTotp(SECRET));
  // 二阶段沿用同一「登录/确认」按钮；按钮文案为「登 录」（中间有空格），
  // 正则须容忍空白——2026-09-14 CI 实证：/登录|确认|验证/ 匹配不到导致 60s 超时
  await page.getByRole('button', { name: /^登\s*录$/ }).click();
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
