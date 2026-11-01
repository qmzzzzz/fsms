/**
 * 旅程 4：权限变更入口 + 审计追溯
 *
 * 只验证「权限管理界面可达且权限树渲染」+「审计日志能追溯到本次登录」，
 * 不实际改动权限——权限变更属破坏性操作，交由人工演练在专用角色上执行。
 */

const { test, expect } = require('@playwright/test');
const { loginViaUI, expectLoggedIn, passStepUp, skipLocallyOrFail } = require('./helpers/auth');

const USER = process.env.E2E_USER;
const PASS = process.env.E2E_PASS;

test.beforeEach(async ({ page }) => {
  test.skip(!USER || !PASS, '未配置 E2E_USER/E2E_PASS，跳过权限/审计旅程');
  await loginViaUI(page, USER, PASS);
  await expectLoggedIn(page);
});

test('角色页可达且权限树渲染（需要相应权限；本地缺权限时跳过，CI 判失败）', async ({ page }) => {
  await page.goto('/roles');
  // 去掉了原先并列在选择器里的 `.app-main, main`：`.app-main` 在前端源码中
  // 出现 0 次，`main` 是布局骨架、任何页面都恒在——保留它等于这条断言
  // 永远通过（连"角色列表有没有渲染"都不看）。现在只认真实内容容器。
  //
  // 锚点必须取自 RoleView.vue 的真实 DOM：该页渲染 <RoleListPanel>（`.role-list` /
  // `.glass-role-item`）与 `.module-grid` 里的 <PermissionModuleCard>（`.glass-module-card`）。
  // 原先用的 `.el-tree, .el-table` 在 /roles 上命中 0 个元素——`.el-tree`/`.el-table`
  // 只出现在 RoleView.vue 两条已失效的 :deep() 样式里，模板中并无对应组件，
  // 所以 waitFor 必然超时（CI 报 waiting for locator('.el-tree, .el-table')）。
  const roleList = page.locator('.role-list .glass-role-item');
  const permModules = page.locator('.glass-module-card');
  // 拒绝语义只认两处**明确载体**，不再用裸 `/无权|403|没有权限/` 去匹配整页文本：
  //   · `.el-message--error` —— 403 由 axios 拦截器弹成「权限不足，无法访问」（zh-CN.js:1416）
  //   · `.perm-unavailable` —— RoleView 缺 permission:read/permission:tree 时的页内降级
  //     （RoleView.vue:665 + permTreeForbidden「当前账号无权查看权限目录…」）
  // 裸 `403` 会命中编号/时间/条数等任意文本，把「页面正常」误判成「无权限」然后跳过；
  // 而 `test.skip(...)` 在本地是静默的假绿（第四轮审计 D3）。
  const denied = page
    .locator('.el-message--error, .perm-unavailable')
    .filter({ hasText: /权限不足|无权查看|无权访问|没有权限/ });
  await Promise.race([
    permModules.first().waitFor({ timeout: 15_000 }),
    denied.first().waitFor({ timeout: 15_000 }),
  ]);
  if (
    await denied
      .first()
      .isVisible()
      .catch(() => false)
  ) {
    // 本地跳过但留可见原因；CI 上直接失败（跳过 = 把账号权限缺口藏成绿）
    skipLocallyOrFail('演练账号无角色管理权限（权限树未渲染）');
  }
  await expect(permModules.first()).toBeVisible();
  await expect(roleList.first()).toBeVisible();
});

test('审计日志可追溯到本次登录动作', async ({ page }) => {
  await page.goto('/audit-logs');
  // 审计读取需要短期票据：先过「验证身份」再等表格，否则只会在弹层背后等 15 秒
  await passStepUp(page, PASS);
  const table = page.locator('.el-table');
  const denied = page
    .locator('.el-message--error')
    .filter({ hasText: /权限不足|无权访问|没有权限/ });
  await Promise.race([
    table.waitFor({ timeout: 15_000 }),
    denied.first().waitFor({ timeout: 15_000 }),
  ]);
  if (
    await denied
      .first()
      .isVisible()
      .catch(() => false)
  ) {
    skipLocallyOrFail('演练账号无审计查看权限（审计表格未渲染）');
  }
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
