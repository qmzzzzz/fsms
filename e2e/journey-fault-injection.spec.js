/**
 * 旅程 5：依赖故障注入（网络超时 / 服务宕机）
 *
 * 背景：超时/宕机类场景此前只有 mock/内存层覆盖（api.js 拦截器单测），
 * 本旅程在真实浏览器里用 Playwright 路由层注入故障，验证**界面级**韧性：
 * 有明确提示、不卡死（按钮恢复）、不白屏、依赖恢复后可自愈。
 *
 * 分两组：
 *  1. 无需真实后端凭据——前端服务可达即可（故障由路由层注入，请求根本
 *     打不到后端），验证登录路径在「连不上 / 超时 / 500」下的表现；
 *  2. 需要 E2E_USER/E2E_PASS 与完整栈——真实登录后掐断依赖再恢复，
 *     验证会话期故障的降级与自愈。未配置时整组跳过（不计失败）。
 *
 * 断言锚点与前端实现对齐（变更时同步）：
 *  - 无响应/超时 → axios 拦截器 error.request 分支 → messages.networkError
 *    「网络错误，请检查网络连接」
 *  - 500 → messages.serverError「服务器内部错误」
 */

const { test, expect } = require('@playwright/test');
const { loginViaUI, expectLoggedIn } = require('./helpers/auth');

const NETWORK_ERROR_TEXT = '网络错误，请检查网络连接';
const SERVER_ERROR_TEXT = '服务器内部错误';

/** 前端服务不可达时跳过（故障注入的前提是页面本身能加载） */
async function skipIfAppUnavailable(page) {
  try {
    await page.goto('/', { timeout: 10_000 });
  } catch (_) {
    test.skip(true, '前端服务未启动，跳过故障注入旅程');
  }
}

/** 填入任意凭据并点击登录（请求已被注入故障，凭据内容无关紧要） */
async function submitLogin(page) {
  await page.getByPlaceholder('用户名').fill('fault-probe');
  await page.getByPlaceholder('密码').fill('fault-probe-pass');
  await page.getByRole('button', { name: '登录' }).click();
}

test.describe('依赖不可达：登录路径的界面韧性', () => {
  test('连接被拒：明确报错、按钮恢复、不白屏', async ({ page }) => {
    await skipIfAppUnavailable(page);
    // 掐断全部 API（登录、验证码开关探测等），静态资源不受影响
    await page.route('**/api/**', (route) => route.abort('connectionrefused'));

    await submitLogin(page);

    await expect(page.getByText(NETWORK_ERROR_TEXT).first()).toBeVisible({ timeout: 15_000 });
    // 不卡死：登录按钮从 loading 恢复为可点击
    await expect(page.getByRole('button', { name: '登录' })).toBeEnabled({ timeout: 10_000 });
    // 不白屏：登录表单仍在
    await expect(page.getByPlaceholder('用户名')).toBeVisible();
  });

  test('服务响应超时（客户端 15s 超时）：同样走网络错误兜底', async ({ page }) => {
    await skipIfAppUnavailable(page);
    // 挂起登录请求 16s，让 axios 的 15s timeout 先触发；
    // 其余 /api 一并掐断，避免旁路请求干扰
    await page.route('**/api/**', async (route) => {
      await new Promise((resolve) => setTimeout(resolve, 16_000));
      try {
        await route.abort();
      } catch (_) {
        // 请求已被客户端超时中止，abort 失败无副作用
      }
    });

    await submitLogin(page);

    // 超时会等满 15s，放宽等待窗口
    await expect(page.getByText(NETWORK_ERROR_TEXT).first()).toBeVisible({ timeout: 25_000 });
    await expect(page.getByRole('button', { name: '登录' })).toBeEnabled({ timeout: 10_000 });
  });

  test('依赖返回 500：提示服务异常且不卡死', async ({ page }) => {
    await skipIfAppUnavailable(page);
    await page.route('**/api/**', (route) =>
      route.fulfill({
        status: 500,
        contentType: 'application/json',
        body: JSON.stringify({ success: false, message: '' }),
      })
    );

    await submitLogin(page);

    // message 为空串时拦截器回退到 messages.serverError
    await expect(page.getByText(SERVER_ERROR_TEXT).first()).toBeVisible({ timeout: 15_000 });
    await expect(page.getByRole('button', { name: '登录' })).toBeEnabled({ timeout: 10_000 });
  });
});

test.describe('会话期依赖故障与自愈（需真实栈）', () => {
  const USER = process.env.E2E_USER;
  const PASS = process.env.E2E_PASS;

  test.beforeEach(() => {
    test.skip(!USER || !PASS, '未配置 E2E_USER/E2E_PASS，跳过会话期故障旅程');
  });

  test('依赖宕机降级、恢复后自愈', async ({ page }) => {
    await loginViaUI(page, USER, PASS);
    await expectLoggedIn(page);

    // 登录成功后掐断全部 API：模拟会话期间后端宕机
    await page.route('**/api/**', (route) => route.abort());
    await page.goto('/devices');
    await expect(page.getByText(NETWORK_ERROR_TEXT).first()).toBeVisible({ timeout: 15_000 });

    // 依赖恢复：撤销路由注入后刷新，数据面应自愈渲染
    await page.unroute('**/api/**');
    await page.reload();
    await expect(page.locator('.el-table')).toBeVisible({ timeout: 20_000 });
  });
});
