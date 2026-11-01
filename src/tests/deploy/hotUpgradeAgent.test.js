/**
 * 宿主升级代理
 *
 * 这些用例守的是队列语义里最容易「看起来成功了」的几条：
 *   · 签名不对/白名单外/超时的请求必须被拒绝并留下原因，而不是执行；
 *   · 代理自检不过时只能写心跳，**不能消费**请求（否则请求凭空消失）；
 *   · 子进程退出 0 但没写终态时不得标记成功；
 *   · 代理崩溃后留下的 processing 任务要能恢复，且不能把仍在运行的任务判死；
 *   · 两个代理实例不能同时认领（人工执行 + timer 的现实场景）。
 *
 * 不跑真实 docker：执行器是可注入的（runOnce 的 executor 参数）。真实切流由
 * deployment/hot-upgrade.md 的真机验收覆盖。
 */
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');

const agent = require('../../../scripts/hotUpgradeAgent');
const queue = require('../../../scripts/hotUpgradeQueue');
const job = require('../../../scripts/hotUpgradeJob');
const { signUpgradeRequest } = require('../../../src/services/upgradeRequestSignature');

const SECRET = 'test-hmac-secret-0123456789abcdef';
const DIGEST = `sha256:${'b'.repeat(64)}`;
const IMAGE = `ghcr.io/acme/fsms@${DIGEST}`;
const JOB_ID = '11111111-2222-4333-8444-555555555555';

function makeEnv() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fsms-upgrade-'));
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
  return {
    dir,
    queueDir,
    nginxConf,
    env: {
      UPGRADE_QUEUE_DIR: queueDir,
      HOT_UPGRADE_REGISTRY_ALLOWLIST: 'ghcr.io/acme/',
      HMAC_SECRET: SECRET,
      HOT_UPGRADE_NGINX_CONF: nginxConf,
      UPGRADE_HISTORY_LIMIT: '5',
    },
  };
}

function writeRequest(
  queueDir,
  { id = JOB_ID, image = IMAGE, requestedAt = new Date().toISOString(), secret = SECRET } = {}
) {
  const requestedBy = { userId: 'u-1', username: 'admin' };
  const signature = signUpgradeRequest(secret, {
    id,
    image,
    requestedAt,
    userId: requestedBy.userId,
  });
  const payload = { id, image, requestedAt, requestedBy, sourceIp: '127.0.0.1', signature };
  fs.writeFileSync(
    path.join(queueDir, 'requests', `${id}.json`),
    JSON.stringify(payload, null, 2),
    { mode: 0o600 }
  );
  return payload;
}

const readStatus = (queueDir, id = JOB_ID) =>
  JSON.parse(fs.readFileSync(path.join(queueDir, 'status', `${id}.json`), 'utf8'));
const readBeat = (queueDir) =>
  JSON.parse(fs.readFileSync(path.join(queueDir, 'heartbeat.json'), 'utf8'));

describe('代理配置与自检', () => {
  test('HMAC 密钥文件去掉 BOM/行尾；含 NUL 时拒绝（会被环境变量静默截断）', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fsms-hmac-'));
    const good = path.join(dir, 'good');
    fs.writeFileSync(good, '\uFEFF' + SECRET + '\r\n', 'utf8');
    expect(queue.readHmacSecret({ HMAC_SECRET_FILE: good })).toEqual({
      secret: SECRET,
      error: '',
    });

    const bad = path.join(dir, 'bad');
    fs.writeFileSync(bad, 'abc\u0000def', 'utf8');
    expect(queue.readHmacSecret({ HMAC_SECRET_FILE: bad }).error).toMatch(/NUL/);
    expect(queue.readHmacSecret({ HMAC_SECRET_FILE: path.join(dir, 'missing') }).error).toMatch(
      /不可读/
    );
  });

  test('自检缺白名单/HMAC/nginx 配置时给出可读原因（不会静默执行）', () => {
    const { env } = makeEnv();
    const readiness = agent.assessReadiness(
      queue.loadConfig({ ...env, HOT_UPGRADE_REGISTRY_ALLOWLIST: '', HMAC_SECRET: '' })
    );
    expect(readiness.ready).toBe(false);
    expect(readiness.reasons.join('\n')).toMatch(/ALLOWLIST 为空/);
    expect(readiness.reasons.join('\n')).toMatch(/缺少 HMAC/);
  });
});

describe('请求判据', () => {
  const base = () => {
    const ctx = makeEnv();
    return { ...ctx, cfg: queue.loadConfig(ctx.env) };
  };

  const requestOf = (overrides = {}) => {
    const id = overrides.id || JOB_ID;
    const image = overrides.image || IMAGE;
    const requestedAt = overrides.requestedAt || new Date().toISOString();
    const requestedBy = { userId: 'u-1', username: 'admin' };
    return {
      id,
      image,
      requestedAt,
      requestedBy,
      signature: signUpgradeRequest(SECRET, {
        id,
        image,
        requestedAt,
        userId: requestedBy.userId,
      }),
      ...overrides,
    };
  };

  test('合法请求通过', () => {
    const { cfg } = base();
    const req = requestOf();
    expect(job.validateRequest(req, cfg, Date.now()).ok).toBe(true);
  });

  test('签名被篡改（改了 image）⇒ 拒绝', () => {
    const { cfg } = base();
    const req = requestOf();
    req.image = `ghcr.io/acme/fsms@sha256:${'c'.repeat(64)}`;
    expect(job.validateRequest(req, cfg, Date.now())).toMatchObject({
      ok: false,
      reason: expect.stringMatching(/签名/),
    });
  });

  test('白名单外的仓库 ⇒ 拒绝（签名有效也不行）', () => {
    const { cfg } = base();
    const req = requestOf();
    expect(
      job.validateRequest({ ...req, image: `ghcr.io/evil/fsms@${DIGEST}` }, cfg, Date.now()).reason
    ).toMatch(/白名单|签名/);
  });

  test('超过 TTL 与 requestedAt 在未来的请求 ⇒ 拒绝', () => {
    const { cfg } = base();
    const old = new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString();
    expect(job.validateRequest(requestOf({ requestedAt: old }), cfg, Date.now()).reason).toMatch(
      /TTL/
    );
    const future = new Date(Date.now() + 10 * 60 * 1000).toISOString();
    expect(job.validateRequest(requestOf({ requestedAt: future }), cfg, Date.now()).reason).toMatch(
      /未来/
    );
  });
});

describe('一轮队列处理（不跑 docker）', () => {
  test('合法请求：认领 → 执行 → 终态写回 → 清理，心跳就绪', async () => {
    const { queueDir, env } = makeEnv();
    writeRequest(queueDir);
    let seenImage = '';
    let sawProcessing = false;
    const executor = async ({ request, statusFile, cfg }) => {
      seenImage = request.image;
      sawProcessing = fs.existsSync(path.join(cfg.processingDir, `${JOB_ID}.json`));
      const current = JSON.parse(fs.readFileSync(statusFile, 'utf8'));
      fs.writeFileSync(
        statusFile,
        JSON.stringify({
          ...current,
          state: 'succeeded',
          outcome: 'success',
          finishedAt: new Date().toISOString(),
          steps: [{ name: 'switch', detail: 'blue -> green', at: new Date().toISOString() }],
        })
      );
      return { code: 0 };
    };

    const code = await agent.runOnce({ env, executor });
    expect(code).toBe(0);
    expect(seenImage).toBe(IMAGE);
    expect(sawProcessing).toBe(true);

    const status = readStatus(queueDir);
    expect(status.state).toBe('succeeded');
    expect(status.outcome).toBe('success');
    expect(status.steps[0].name).toBe('switch');
    expect(fs.existsSync(path.join(queueDir, 'requests', `${JOB_ID}.json`))).toBe(false);
    expect(fs.readdirSync(path.join(queueDir, 'processing'))).toEqual([]);

    const beat = readBeat(queueDir);
    expect(beat.ready).toBe(true);
    expect(beat.lastSeenAt).toBeTruthy();
  });

  test('签名错误：不执行、写 failed/rejected 并移入 rejected/ 留证', async () => {
    const { queueDir, env } = makeEnv();
    writeRequest(queueDir, { secret: 'another-secret-0123456789abcdef' });
    let called = false;
    const code = await agent.runOnce({
      env,
      executor: async () => {
        called = true;
        return { code: 0 };
      },
    });
    expect(code).toBe(0);
    expect(called).toBe(false);
    const status = readStatus(queueDir);
    expect(status.state).toBe('failed');
    expect(status.outcome).toBe('rejected');
    expect(status.message).toMatch(/签名/);
    expect(fs.readdirSync(path.join(queueDir, 'rejected'))).toEqual([`${JOB_ID}.json`]);
    expect(fs.existsSync(path.join(queueDir, 'requests', `${JOB_ID}.json`))).toBe(false);
  });

  test('代理未就绪（白名单空）：只写心跳，请求原样留在队列', async () => {
    const { queueDir, env } = makeEnv();
    writeRequest(queueDir);
    const code = await agent.runOnce({
      env: { ...env, HOT_UPGRADE_REGISTRY_ALLOWLIST: '' },
      executor: async () => {
        throw new Error('不应执行');
      },
    });
    expect(code).toBe(0);
    const beat = readBeat(queueDir);
    expect(beat.ready).toBe(false);
    expect(beat.reasons.join('')).toMatch(/ALLOWLIST 为空/);
    expect(fs.existsSync(path.join(queueDir, 'requests', `${JOB_ID}.json`))).toBe(true);
    expect(fs.existsSync(path.join(queueDir, 'status', `${JOB_ID}.json`))).toBe(false);
  });

  test('子进程退出 0 但没有终态 ⇒ 标记 failed（不把未知结果当成功）', async () => {
    const { queueDir, env } = makeEnv();
    writeRequest(queueDir);
    await agent.runOnce({ env, executor: async () => ({ code: 0 }) });
    const status = readStatus(queueDir);
    expect(status.state).toBe('failed');
    expect(status.outcome).toBe('missing_terminal');
  });

  test('子进程非 0 且未写终态 ⇒ failed/exit_nonzero，并带退出码', async () => {
    const { queueDir, env } = makeEnv();
    writeRequest(queueDir);
    await agent.runOnce({ env, executor: async () => ({ code: 7 }) });
    const status = readStatus(queueDir);
    expect(status.state).toBe('failed');
    expect(status.outcome).toBe('exit_nonzero');
    expect(status.message).toContain('7');
  });
});

describe('崩溃恢复与单实例', () => {
  test('processing 里子进程已死 ⇒ 写 failed/agent_lost 并清理；活着则让路', () => {
    const { queueDir, env } = makeEnv();
    const cfg = queue.loadConfig(env);
    const processingFile = path.join(cfg.processingDir, `${JOB_ID}.json`);
    fs.writeFileSync(
      processingFile,
      JSON.stringify({ id: JOB_ID, image: IMAGE, _agent: { pid: 111111, childPid: 222222 } }),
      'utf8'
    );
    fs.writeFileSync(
      path.join(cfg.statusDir, `${JOB_ID}.json`),
      JSON.stringify({ id: JOB_ID, state: 'running', steps: [] }),
      'utf8'
    );

    const busy = agent.recoverStale(cfg, { isAlive: () => true });
    expect(busy.busy).toBe(true);
    expect(fs.existsSync(processingFile)).toBe(true);

    const recovered = agent.recoverStale(cfg, { isAlive: () => false });
    expect(recovered.busy).toBe(false);
    expect(fs.existsSync(processingFile)).toBe(false);
    expect(readStatus(queueDir).state).toBe('failed');
    expect(readStatus(queueDir).outcome).toBe('agent_lost');
  });

  test('认领超过上限 ⇒ 即使 pid 存活也按中断处理（pid 复用不得让队列永久忙）', () => {
    const { env } = makeEnv();
    const cfg = queue.loadConfig(env);
    const processingFile = path.join(cfg.processingDir, `${JOB_ID}.json`);
    const staleAt = new Date(Date.now() - 4 * 60 * 60 * 1000).toISOString();
    fs.writeFileSync(
      processingFile,
      JSON.stringify({
        id: JOB_ID,
        image: IMAGE,
        _agent: { pid: 111111, childPid: 222222, claimedAt: staleAt },
      }),
      'utf8'
    );
    const recovered = agent.recoverStale(cfg, { isAlive: () => true });
    expect(recovered.busy).toBe(false);
    expect(fs.existsSync(processingFile)).toBe(false);
  });

  test('锁：同一时刻只有一个持有者，释放后可重新获取', () => {
    const { env } = makeEnv();
    const cfg = queue.loadConfig(env);
    const first = queue.acquireLock(cfg);
    expect(first).not.toBeNull();
    try {
      expect(queue.acquireLock(cfg)).toBeNull();
    } finally {
      first.release();
    }
    const second = queue.acquireLock(cfg);
    expect(second).not.toBeNull();
    second.release();
  });

  test('空锁文件（open 与 write 之间崩溃）可被接管，不会让升级永久忙', () => {
    const { queueDir, env } = makeEnv();
    const cfg = queue.loadConfig(env);
    const lockFile = path.join(queueDir, 'processing', '.agent.lock');
    fs.writeFileSync(lockFile, '', 'utf8');
    const got = queue.acquireLock(cfg);
    expect(got).not.toBeNull();
    got.release();
    expect(fs.existsSync(lockFile)).toBe(false);
  });

  test('锁陈旧判定：无 pid / 进程已死 / 锁龄超上限 → 陈旧；活着的持有者 → 忙', () => {
    const alive = () => true;
    const dead = () => false;
    const now = new Date().toISOString();
    expect(queue.isLockStale(null, alive)).toBe(true);
    expect(queue.isLockStale({}, alive)).toBe(true);
    expect(queue.isLockStale({ pid: 0, startedAt: now }, alive)).toBe(true);
    expect(queue.isLockStale({ pid: 4242, startedAt: now }, dead)).toBe(true);
    // 活着的持有者 + 新鲜锁 ⇒ 必须判忙（否则并发执行升级）
    expect(queue.isLockStale({ pid: 4242, startedAt: now }, alive)).toBe(false);
    // 锁龄超过 LOCK_STALE_MS（systemd 单次升级上限 2h + 1h 余量）
    const old = new Date(Date.now() - 4 * 60 * 60 * 1000).toISOString();
    expect(queue.isLockStale({ pid: 4242, startedAt: old }, alive)).toBe(true);
  });

  test('pid 复用时锁必须能接管（只判 kill(pid,0) 会让升级永久显示进行中）', () => {
    // startTime 取自 /proc/<pid>/stat，只有 Linux 有：其他平台该字段为空，判定退化为
    // 「pid 是否存活」（宁可误判为忙），因此这里的断言只在 Linux 上成立。
    if (process.platform !== 'linux' || !queue.procStartTime(process.pid)) return;
    const alive = () => true;
    const holder = {
      pid: process.pid,
      startTime: 'not-the-current-process',
      startedAt: new Date().toISOString(),
    };
    expect(queue.isLockStale(holder, alive)).toBe(true);
  });

  test('历史裁剪保留最新 N 条，但不删仍在 running 的任务', () => {
    const { queueDir, env } = makeEnv();
    const cfg = queue.loadConfig({ ...env, UPGRADE_HISTORY_LIMIT: '2' });
    const write = (id, state, ageMs) => {
      const file = path.join(queueDir, 'status', `${id}.json`);
      fs.writeFileSync(file, JSON.stringify({ id, state }), 'utf8');
      const t = new Date(Date.now() - ageMs);
      fs.utimesSync(file, t, t);
    };
    const ids = [
      'aaaaaaaa-1111-4111-8111-111111111111',
      'aaaaaaaa-2222-4222-8222-222222222222',
      'aaaaaaaa-3333-4333-8333-333333333333',
      'aaaaaaaa-4444-4444-8444-444444444444',
    ];
    write(ids[0], 'succeeded', 0);
    write(ids[1], 'failed', 1000);
    write(ids[2], 'running', 2000);
    write(ids[3], 'succeeded', 3000);

    queue.pruneStatus(cfg);
    const left = fs.readdirSync(path.join(queueDir, 'status')).sort();
    expect(left).toEqual([`${ids[0]}.json`, `${ids[1]}.json`, `${ids[2]}.json`].sort());
  });
});
