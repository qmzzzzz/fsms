/**
 * 离线请求的两段执行链（hotUpgradeJob.runUpgradeByMode → runOfflineUpgrade）
 *
 * 守的失效形态：
 *   · 离线请求必须**先导入后换装**——顺序反了 = 本地没有镜像就 compose up，
 *     断网机上表现为一次注定失败的联网拉取；
 *   · 定位不到包 / 导入退出码非 0 ⇒ 停在第一段（aborted_import_failed），
 *     绝不能带着「镜像可能不在本地」的状态进入换装；
 *   · 包目录由代理在受管 bundles 目录内按 digest 定位（--bundle-root 钉死），
 *     请求只点名镜像，永远指定不了目录；
 *   · 离线基础设施在位（bundles 有包）也不许把 registry 请求带偏（不加 --offline）。
 *
 * 手法（进程内档板，不落子进程）：**先**替换 child_process.spawn（记录每次调用的
 * file/args/env，按脚本名返回预设退出码），**再** require 被测模块——hotUpgradeJob
 * 顶层解构 spawn 时拿到的就是档板（jest 默认每个测试文件独立模块注册表，替换不会
 * 外溢到其他套件）。这比 --require 预加载少一层子进程，档板行为与
 * src/tests/deploy/helpers/stubExec.js 的 spawn 分支同构。
 */
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const { signUpgradeRequest } = require('../../../src/services/upgradeRequestSignature');

const SECRET = 'test-hmac-secret-0123456789abcdef';
const DIGEST = 'sha256:' + 'b'.repeat(64);
const REF = 'ghcr.io/acme/fsms@' + DIGEST;
const JOB_ID = '33333333-2222-4333-8444-555555555555';
const ALLOWLIST = 'ghcr.io/acme/';

/** 档板记录：每次 spawn 的 file/args；按脚本名区分两段 */
const SPAWN_CALLS = [];
/** 档板行为开关：各段返回的退出码（用例内设置） */
const EXIT_CODES = { import: 0, upgrade: 0 };

childProcess.spawn = function spawnStub(file, args = [], _opts = {}) {
  const name = String(file);
  const joined = (Array.isArray(args) ? args : []).join(' ');
  SPAWN_CALLS.push({ name, joined });
  const { EventEmitter } = require('events');
  const child = new EventEmitter();
  child.pid = 424242;
  child.kill = () => {};
  setImmediate(() => {
    const code =
      joined.indexOf('importOfflineBundle.js') !== -1 ? EXIT_CODES.import : EXIT_CODES.upgrade;
    child.emit('exit', code, null);
    child.emit('close', code, null);
  });
  return child;
};

/** 档板就位后才能加载被测模块（hotUpgradeJob 顶层解构 spawn） */
const agent = require('../../../scripts/hotUpgradeAgent');

function makeEnv() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fsms-offline-dispatch-'));
  const queueDir = path.join(dir, 'upgrade');
  const nginxConf = path.join(dir, 'nginx.conf');
  fs.writeFileSync(
    nginxConf,
    ['http {', '    upstream fsms_app {', '        server 127.0.0.1:3000;', '    }', '}'].join(
      '\n'
    ),
    'utf8'
  );
  for (const sub of ['requests', 'status', 'processing', 'rejected']) {
    fs.mkdirSync(path.join(queueDir, sub), { recursive: true });
  }
  return { dir, queueDir, nginxConf, bundlesDir: path.join(queueDir, 'bundles') };
}

function writeRequest(
  queueDir,
  { id = JOB_ID, image = REF, mode = 'offline', requestedAt = new Date().toISOString() } = {}
) {
  const requestedBy = { userId: 'u-1', username: 'admin' };
  const signature = signUpgradeRequest(SECRET, {
    id,
    image,
    requestedAt,
    userId: requestedBy.userId,
    ...(mode ? { mode } : {}),
  });
  fs.writeFileSync(
    path.join(queueDir, 'requests', `${id}.json`),
    JSON.stringify({
      id,
      image,
      ...(mode ? { mode } : {}),
      requestedAt,
      requestedBy,
      sourceIp: '127.0.0.1',
      signature,
    }),
    { mode: 0o600 }
  );
}

function writeGoodBundle(bundlesDir, ref = REF) {
  // 扫描层只读 manifest、不算 payload 哈希，所以这里不需要真实 tar
  const base = path.resolve(bundlesDir);
  const dir = path.resolve(base, 'v1.2.3');
  if (dir !== base && !dir.startsWith(base + path.sep)) {
    throw new Error('测试用例错误：包目录逃逸出 bundles 根');
  }
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(
    path.join(dir, 'manifest.json'),
    JSON.stringify({
      format: 1,
      version: '1.2.3',
      buildId: 'ci-42',
      createdAt: '2026-11-01T00:00:00Z',
      images: [
        {
          role: 'app',
          ref,
          file: 'payload/fsms-app.tar',
          bytes: 1,
          sha256: 'a'.repeat(6) + 'a'.repeat(58),
        },
      ],
    }),
    'utf8'
  );
}

const readStatus = (queueDir, id = JOB_ID) =>
  JSON.parse(fs.readFileSync(path.join(queueDir, 'status', `${id}.json`), 'utf8'));

const callsFor = (needle) => SPAWN_CALLS.filter((call) => call.joined.indexOf(needle) !== -1);
const importCalls = () => callsFor('importOfflineBundle.js');
const upgradeCalls = () =>
  SPAWN_CALLS.filter(
    (call) => call.joined.indexOf('hotUpgrade.js') !== -1 && call.joined.indexOf('Agent') === -1
  );

describe('离线请求的两段执行链', () => {
  beforeEach(() => {
    SPAWN_CALLS.length = 0;
    EXIT_CODES.import = 0;
    EXIT_CODES.upgrade = 0;
  });

  test('包在位 ⇒ 先导入后换装：顺序不可反，换装段带 --offline', async () => {
    const ctx = makeEnv();
    writeGoodBundle(ctx.bundlesDir);
    writeRequest(ctx.queueDir);
    const code = await agent.runOnce({ env: baseAgentEnv(ctx) });
    expect(code).toBe(0);

    expect(importCalls()).toHaveLength(1);
    expect(upgradeCalls()).toHaveLength(1);
    expect(SPAWN_CALLS.indexOf(importCalls()[0])).toBeLessThan(
      SPAWN_CALLS.indexOf(upgradeCalls()[0])
    );
    // 包目录钉在受管 bundles 根之内（--bundle-root）+ 真正执行
    expect(importCalls()[0].joined).toContain('--bundle-root');
    expect(importCalls()[0].joined).toContain('--apply');
    // 换装段必须带 --offline（本地有镜像才继续；执行期间不接受联网拉取）
    expect(upgradeCalls()[0].joined).toContain('--offline');
    // 档板不写终态 ⇒ 代理必须按 missing_terminal 收尾，不把未知结果当成功
    expect(readStatus(ctx.queueDir).outcome).toBe('missing_terminal');
  });

  test('导入退出码非 0 ⇒ 停在第一段：不进入换装，终态 aborted_import_failed', async () => {
    const ctx = makeEnv();
    writeGoodBundle(ctx.bundlesDir);
    writeRequest(ctx.queueDir);
    EXIT_CODES.import = 3;
    await agent.runOnce({ env: baseAgentEnv(ctx) });
    expect(importCalls()).toHaveLength(1);
    expect(upgradeCalls()).toHaveLength(0);
    const status = readStatus(ctx.queueDir);
    expect(status.state).toBe('failed');
    expect(status.outcome).toBe('aborted_import_failed');
    expect(status.message).toMatch(/导入失败|退出码/);
  });

  test('定位不到包 ⇒ 一段都不执行，aborted_import_failed 且信息指向处置动作', async () => {
    const ctx = makeEnv();
    // 包存在但声明的是另一个 digest：请求点名的镜像必须有对应的包
    writeGoodBundle(ctx.bundlesDir, `ghcr.io/acme/other@${DIGEST}`);
    writeRequest(ctx.queueDir);
    await agent.runOnce({ env: baseAgentEnv(ctx) });
    expect(SPAWN_CALLS).toEqual([]);
    const status = readStatus(ctx.queueDir);
    expect(status.state).toBe('failed');
    expect(status.outcome).toBe('aborted_import_failed');
    expect(status.message).toMatch(/OFFLINE_BUNDLE_DIR|可用包/);
  });

  test('registry 请求不受离线设施影响：不导入、不加 --offline', async () => {
    const ctx = makeEnv();
    writeGoodBundle(ctx.bundlesDir);
    writeRequest(ctx.queueDir, { mode: 'registry' });
    const code = await agent.runOnce({ env: baseAgentEnv(ctx) });
    expect(code).toBe(0);
    expect(importCalls()).toHaveLength(0);
    expect(upgradeCalls()).toHaveLength(1);
    expect(upgradeCalls()[0].joined).not.toContain('--offline');
  });
});

/** 代理进程自身的环境（与 hotUpgradeAgent.test.js 的 makeEnv 同口径） */
function baseAgentEnv(ctx) {
  return {
    UPGRADE_QUEUE_DIR: ctx.queueDir,
    HOT_UPGRADE_REGISTRY_ALLOWLIST: ALLOWLIST,
    HMAC_SECRET: SECRET,
    HOT_UPGRADE_NGINX_CONF: ctx.nginxConf,
  };
}
