/**
 * 旅程 6：移动端核心可用性冒烟
 *
 * 以 412px 视口（Pixel 7 同宽）验证登录、移动端抽屉导航和关键业务页不白屏；
 * 继续保持只读，不在共享演练环境制造数据。
 *
 * 为什么在本文件内显式 setViewportSize，而不是靠项目区分：
 *   移动端布局的唯一判定条件是 layout/index.vue 的 checkMobile() 里那句
 *   `window.innerWidth <= 768`，与 isMobile/触摸仿真无关。
 *   CI 同时跑 desktop-chromium 与 mobile-chrome 两个项目，
 *   而 ci.yml 的「Assert no skipped journeys」把任何 skipped>0 判为门禁失败——
 *   因此「按视口 test.skip」在这条流水线上不可用。直接设视口可让本文件在两个
 *   项目下都真实执行移动端断言，不引入跳过。
 *
 * 选择器契约（类名/标识符即锚点，刻意不写行号——前端行号漂移极快）：
 *   - 抽屉开关：`.collapse-btn`（el-icon，只有图标、无 aria-label/文字，只能按类名定位）
 *   - 打开状态：`.app-wrapper` 上的 `mobile-sidebar-open` 类（绑 mobileSidebarOpen）
 *   - 点击外部关闭：`.mobile-overlay`（仅打开时 v-if 渲染，click 即收起）
 *   - 侧栏位移：`.sidebar` + sidebarStyle 计算属性给的 inline
 *     `transform: translateX(-100%)`（关闭）/ `translateX(0)`（打开）
 *   - 主区域：`main.main-content`
 * 修订原因：`.app-main` 在整个前端源码中出现 0 次。此前用例写成
 * `.app-main, main`，命中的一直是兜底的 `main` 分支，抽屉开合从未被断言过
 * （属于"绿但不设防"，与 70ff0bc 修的那批同一类别）。
 */

const { test, expect } = require('@playwright/test');
const { loginViaUI, expectLoggedIn } = require('./helpers/auth');

const USER = process.env.E2E_USER;
const PASS = process.env.E2E_PASS;

/** 与 Pixel 7 同宽，且必然落入应用的 768px 移动断点 */
const MOBILE_VIEWPORT = { width: 412, height: 915 };

/**
 * 侧栏左边缘的横坐标（负值＝整体在视口左侧之外）。
 * 不用 toBeHidden()/toBeVisible() 判定抽屉开合：translateX(-100%) 只改变位置，
 * 元素仍有非空包围盒，Playwright 一律判为"可见"，用它断言会恒真。
 * 布局切换带 CSS `transition: transform`（layout/index.vue 的 .sidebar 规则），
 * 一次性读取会读到动画
 * 中间值（在 0 与 -240 之间），故经 expect.poll 轮询到满足条件为止。
 */
const sidebarLeftEdge = (sidebar) => async () => {
  const box = await sidebar.boundingBox();
  return box ? box.x : Number.NaN;
};

test.beforeEach(() => {
  test.skip(!USER || !PASS, '未配置 E2E_USER/E2E_PASS，跳过移动端旅程');
});

test('移动端登录进入仪表盘', async ({ page }) => {
  await page.setViewportSize(MOBILE_VIEWPORT);
  await loginViaUI(page, USER, PASS);
  await expectLoggedIn(page);
  await expect(page.locator('.app-wrapper')).toBeVisible();
  await expect(page.locator('main.main-content')).toBeVisible();
});

test('移动端抽屉导航可打开并关闭', async ({ page }) => {
  await page.setViewportSize(MOBILE_VIEWPORT);
  await loginViaUI(page, USER, PASS);
  await expectLoggedIn(page);
  await page.goto('/dashboard');

  const wrapper = page.locator('.app-wrapper');
  const sidebar = page.locator('.sidebar');
  const overlay = page.locator('.mobile-overlay');

  // 关闭态：无状态类、无遮罩、侧栏整体位于视口左边界之外
  await expect(wrapper).not.toHaveClass(/mobile-sidebar-open/);
  await expect(overlay).toHaveCount(0);
  await expect.poll(sidebarLeftEdge(sidebar)).toBeLessThan(0);

  // 打开：状态类 + 遮罩 + 侧栏回到视口内
  await page.locator('.collapse-btn').click();
  await expect(wrapper).toHaveClass(/mobile-sidebar-open/);
  await expect(overlay).toHaveCount(1);
  await expect.poll(sidebarLeftEdge(sidebar)).toBeGreaterThanOrEqual(0);
  // 抽屉里确实渲染了导航条目，而不是一个空的定位容器
  await expect(page.locator('.sidebar-menu li').first()).toBeVisible();

  // 收起：点遮罩关闭是移动端抽屉的标准交互。
  // 但不能用 overlay.click() 的默认中心点：遮罩是 position:fixed; inset:0; z-index:150，
  // 抽屉 .sidebar-mobile 是 fixed; left:0; width:240px; z-index:200 —— 412px 视口下
  // 遮罩的几何中心（x≈206）落在抽屉覆盖范围内，点击会被抽屉里的 <li> 拦截
  // （CI 报 "subtree intercepts pointer events"）。故显式把点击点算到抽屉右缘之外、
  // 仍在遮罩之内：取「抽屉右缘」与「遮罩右缘」的中点。
  const drawer = await sidebar.boundingBox();
  const layer = await overlay.boundingBox();
  const outsideDrawerX = (drawer.x + drawer.width + layer.x + layer.width) / 2 - layer.x;
  await overlay.click({ position: { x: outsideDrawerX, y: layer.height / 2 } });
  await expect(wrapper).not.toHaveClass(/mobile-sidebar-open/);
  await expect(overlay).toHaveCount(0);
  await expect.poll(sidebarLeftEdge(sidebar)).toBeLessThan(0);
});

test('移动端设备列表可访问', async ({ page }) => {
  await page.setViewportSize(MOBILE_VIEWPORT);
  await loginViaUI(page, USER, PASS);
  await expectLoggedIn(page);
  await page.goto('/devices');
  await expect(page.locator('main.main-content')).toBeVisible();
  // 与桌面旅程同口径：表格骨架出现才证明移动端未白屏（el-table 无响应式隐藏规则）
  await expect(page.locator('.el-table')).toBeVisible({ timeout: 15_000 });
});
