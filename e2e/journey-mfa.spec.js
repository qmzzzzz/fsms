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
  // 二阶段沿用同一「登录/确认」按钮
  await page.getByRole('button', { name: /登录|确认|验证/ }).click();
  await expectLoggedIn(page);
});

test('错误的动态码被拒', async ({ page }) => {
  await loginViaUI(page, USER, PASS);
  const mfaInput = page.getByPlaceholder('动态验证码 / 备用恢复码');
  await expect(mfaInput).toBeVisible({ timeout: 15_000 });
  await mfaInput.fill('000000');
  await page.getByRole('button', { name: /登录|确认|验证/ }).click();
  await expect(page.getByText(/验证码错误|MFA|两步验证/)).toBeVisible({ timeout: 10_000 });
});
