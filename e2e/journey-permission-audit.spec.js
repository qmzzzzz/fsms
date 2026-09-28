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
  // 去掉了原先并列在选择器里的 `.app-main, main`：`.app-main` 在前端源码中
  // 出现 0 次，`main` 是布局骨架、任何页面都恒在——保留它等于这条断言
  // 永远通过（连"角色列表有没有渲染"都不看）。现在只认真实内容容器。
  const tree = page.locator('.el-tree, .el-table');
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
  // 登录动作应立即可查（审计即时性回归）。
  // 必须限定在数据行内：AuditLogView.vue:137 的统计卡片标签就是「登录失败」，
  // DOM 顺序先于任何数据行——原来的 getByText(/登录|login/).first() 命中的是
  // 这张静态卡片，即使审计写入完全失效也照样通过。
  // 后端列表按 timestamp 倒序（auditQueryService 的 fetchAuditCursorPage/fetchAuditOffsetPage
  // 都是 .sort({timestamp:-1})），故本次登录必在第 1 页。
  // 文案取中文标签（actionLabel 查 audit.action.* 这组键：auth_login / login_success）；
  // playwright.config.js 已锁定 locale zh-CN，与本套件其余断言同口径。
  const loginRow = page.locator('.el-table__row').filter({ hasText: /用户登录|登录成功/ });
  await expect(loginRow.first()).toBeVisible({ timeout: 15_000 });
});
