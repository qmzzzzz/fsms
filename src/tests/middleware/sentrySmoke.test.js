/**
 * Sentry 依赖 / API 兼容性 smoke（F-11，2026-10-17）
 *
 * 审计事实：`package.json` 声明 `^7.100.0`、lockfile 解析 7.120.4，而某个工作区的
 * node_modules 实际装了 11.4.0（`npm ls` 标 invalid）。代码用的是 v7 的
 * `Sentry.Handlers.*` 与 `Sentry.Integrations.Http`，两者在 v8 都已移除——
 * 于是在那个环境里，**配置了真实 DSN 的部署**会在启动或首个 5xx 时崩，
 * 而在此之前所有测试都是绿的（测试根本没碰过 handler 工厂）。
 *
 * 本套件补的正是这条空白：用**真实 SDK**（不是 mock）验证
 *   ① 安装版本与 lockfile 一致；② dummy DSN 下 init 成功；
 *   ③ 三个 handler 工厂都返回函数；④ 未配 DSN 时不初始化；
 *   ⑤ API 缺失时的报错必须可操作（含版本号与修复路径，而不是 TypeError）。
 *
 * 关于 ⑤ 为什么单独测：判据不是"抛错"，而是"抛出的错能不能让人知道该干什么"。
 * 用 `jest.doMock` 造一个 v8 形态（Handlers/Integrations 全缺）的 SDK，
 * 断言报错里出现版本号、v8、npm ci 这三个线索——否则它在生产上仍然是一条
 * `Cannot read properties of undefined`，与修前没有区别。
 */
'use strict';

const lock = require('../../../package-lock.json');
const LOCKED_VERSION = lock.packages['node_modules/@sentry/node'].version;

/** 取实际安装的版本（读不到就返回 null，由用例判红并给出提示） */
function installedVersion() {
  try {
    return require('@sentry/node/package.json').version;
  } catch {
    return null;
  }
}

describe('F-11 Sentry：安装版本必须与 lockfile 一致', () => {
  test(`安装版本 === lockfile 解析版本（${LOCKED_VERSION}）`, () => {
    const installed = installedVersion();
    // 这条红时**不要**去改断言：它说的是 node_modules 与 lockfile 不是同一棵树。
    // 修复方式是 `npm ci`（不是 npm install——后者会重新解析并可能再漂一次）。
    expect({ installed, hint: '不一致时执行 npm ci' }).toMatchObject({
      installed: LOCKED_VERSION,
    });
  });

  test('package.json 的约束不得放宽到大版本跳跃（^7 允许 7.x，~7.120.4 只允许 patch）', () => {
    const pkg = require('../../../package.json');
    // v7 → v8 移除了 Handlers 与 Integrations.Http。约束写成 ^7.x 时 npm 不会自己跨大版本，
    // 但人为 `npm install @sentry/node`（不带版本）会装 latest ⇒ 约束再紧也挡不住；
    // 真正的防线是上面的版本一致性用例 + CI 的干净 npm ci。
    expect(pkg.dependencies['@sentry/node']).toBe('~7.120.4');
  });
});

describe('F-11 Sentry：dummy DSN 下的初始化与 handler 工厂', () => {
  const savedDsn = process.env.SENTRY_DSN;
  afterEach(() => {
    if (savedDsn === undefined) delete process.env.SENTRY_DSN;
    else process.env.SENTRY_DSN = savedDsn;
  });

  test('未配 SENTRY_DSN ⇒ 不初始化（captureException 前的判据依赖它）', () => {
    delete process.env.SENTRY_DSN;
    jest.isolateModules(() => {
      const sentry = require('../../middleware/sentry');
      expect(sentry.initSentry()).toBe(false);
      expect(sentry.isSentryInitialized()).toBe(false);
    });
  });

  test('dummy DSN（不出网，指向 127.0.0.1:1）⇒ init 成功且标记已初始化', () => {
    // 不出网是关键：DSN 指向本机 1 端口，SDK 只会在真正发送时才连它，
    // 而本用例不发事件，所以不会有任何网络动作，也不会因超时拖慢测试。
    process.env.SENTRY_DSN = 'http://public@127.0.0.1:1/1';
    jest.isolateModules(() => {
      const sentry = require('../../middleware/sentry');
      expect(sentry.initSentry()).toBe(true);
      expect(sentry.isSentryInitialized()).toBe(true);
    });
  });

  test('三个 handler 工厂都返回函数（v7 API 存在性）', () => {
    jest.isolateModules(() => {
      const sentry = require('../../middleware/sentry');
      expect(typeof sentry.sentryRequestHandler()).toBe('function');
      expect(typeof sentry.sentryTracingHandler()).toBe('function');
      expect(typeof sentry.sentryErrorHandler()).toBe('function');
    });
  });
});

describe('F-11 出网收口（不依赖 SDK 版本的纯函数）', () => {
  const { scrubOutboundEvent } = require('../../middleware/sentry');

  test('request 只留 method + url，url 去查询串，user 整块删除', () => {
    const event = {
      request: {
        method: 'POST',
        url: 'https://x/api/auth/login?next=/home',
        headers: { authorization: 'Bearer t' },
        cookies: { sid: 's' },
        data: { password: 'p' },
        query_string: 'next=/home',
      },
      user: { username: 'admin', email: 'a@b.co' },
      transaction: 'POST /api/auth/login?next=/home',
    };
    scrubOutboundEvent(event);
    expect(event.request).toEqual({ method: 'POST', url: 'https://x/api/auth/login' });
    expect(event.user).toBeUndefined();
    expect(event.transaction).toBe('POST /api/auth/login');
  });

  test('未知字段一律不保留（白名单而非黑名单：SDK 新增字段不会自动出网）', () => {
    const event = { request: { method: 'GET', url: '/x', futureFieldFromNewSdk: 'secret' } };
    scrubOutboundEvent(event);
    expect(Object.keys(event.request)).toEqual(['method', 'url']);
  });
});

describe('F-11 API 缺失时的报错必须可操作', () => {
  test('Handlers 缺失（v8+ 形态）⇒ 报错含版本号 / v8 / npm ci 三条线索', () => {
    jest.isolateModules(() => {
      jest.doMock('@sentry/node', () => ({
        Handlers: undefined,
        Integrations: undefined,
        init: () => {},
      }));
      const sentry = require('../../middleware/sentry');
      let message = '';
      try {
        sentry.sentryRequestHandler();
      } catch (err) {
        message = err.message;
      }
      expect(message).toContain('Handlers.requestHandler');
      expect(message).toContain('v8');
      expect(message).toContain('npm ci');
      jest.dontMock('@sentry/node');
    });
  });

  test('Integrations.Http 缺失 ⇒ init 报错同样给迁移路径，而不是 TypeError', () => {
    jest.isolateModules(() => {
      jest.doMock('@sentry/node', () => ({
        Handlers: {},
        Integrations: undefined,
        init: () => {},
      }));
      process.env.SENTRY_DSN = 'http://public@127.0.0.1:1/1';
      const sentry = require('../../middleware/sentry');
      expect(() => sentry.initSentry()).toThrow(/httpIntegration\(\)/);
      delete process.env.SENTRY_DSN;
      jest.dontMock('@sentry/node');
    });
  });
});
