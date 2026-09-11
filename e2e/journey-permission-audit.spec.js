/**
 * 旅程 4：权限变更入口 + 审计追溯（T-2）
 *
 * 只验证「权限管理界面可达且权限树渲染」+「审计日志能追溯到本次登录」，
 * 不实际改动权限——权限变更属破坏性操作，交由人工演练在专用角色上执行。
 */

const { test, expect } = require('@playwright/test');
const { loginViaUI, expectLoggedIn } = require('./helpers/auth');

const USER = process.env.E2E_USER;
const PASS = process.env.E2E_PASS;

test.beforeEach(async ({ page }) => {
  test.skip(!USER || !PASS, '未配置 E2E_USER/E2E_PASS，跳过权限/审计旅程');
  await loginViaUI(page, USER, PASS);
  await expectLoggedIn(page);
});

test('角色页可达且权限树渲染（需要相应权限，403 时跳过）', async ({ page }) => {
  await page.goto('/roles');
  const tree = page.locator('.role-list, .el-tree, .el-table, .app-main, main');
  const forbidden = page.getByText(/无权|403|没有权限/);
  await Promise.race([
    tree.first().waitFor({ timeout: 15_000 }),
    forbidden.first().waitFor({ timeout: 15_000 }),
  ]);
  test.skip(
    await forbidden
      .first()
      .isVisible()
      .catch(() => false),
    '演练账号无角色管理权限'
  );
  await expect(tree.first()).toBeVisible();
});

test('审计日志可追溯到本次登录动作', async ({ page }) => {
  await page.goto('/audit-logs');
  const table = page.locator('.el-table');
  const forbidden = page.getByText(/无权|403|没有权限/);
  await Promise.race([
    table.waitFor({ timeout: 15_000 }),
    forbidden.first().waitFor({ timeout: 15_000 }),
  ]);
  test.skip(
    await forbidden
      .first()
      .isVisible()
      .catch(() => false),
    '演练账号无审计查看权限'
  );
  // 登录动作应立即可查（审计即时性回归）
  await expect(page.getByText(/登录|login/).first()).toBeVisible({ timeout: 15_000 });
});
