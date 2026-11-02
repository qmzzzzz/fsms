/**
 * 升级队列服务（应用侧）
 *
 * 服务只回答三件事：能不能升、请求是否被接受、任务到哪一步。执行侧（host agent）
 * 会重新做同样的校验，所以这里的每条拒绝都必须**给出原因**——只回一个 false，
 * 前端按钮变灰时运维只能猜是开关、白名单、目录权限还是代理离线。
 *
 * 用例刻意不 mock 文件系统：队列契约（目录布局、原子写、请求文件权限）本身就是
 * 被验证的对象，用真实临时目录才能钉住。
 */

const fs = require('fs');
const os = require('os');
const path = require('path');

const DIGEST = `sha256:${'a'.repeat(64)}`;
const IMAGE = `ghcr.io/fsms-test/app@${DIGEST}`;

describe('upgradeService（应用侧队列）', () => {
  let dir;
  let upgradeService;
  let signature;
  let upgradeConfig;

  beforeAll(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fsms-upgrade-'));
    process.env.UPGRADE_QUEUE_DIR = dir;
    process.env.UPGRADE_ENABLED = 'true';
    process.env.HOT_UPGRADE_REGISTRY_ALLOWLIST = 'ghcr.io/fsms-test/';
    process.env.UPGRADE_AGENT_STALE_SECONDS = '600';
    process.env.UPGRADE_REQUEST_TTL_SECONDS = '1800';
    process.env.HMAC_SECRET = process.env.HMAC_SECRET || 'test-hmac-secret-0123456789abcdef';

    // config/upgrade 在 require 时读环境变量：先清缓存再加载，避免与其他套件的
    // 模块实例混用（同进程内 jest 按文件隔离，但 reset 让本文件自证不依赖加载顺序）
    jest.resetModules();
    upgradeConfig = require('../../config/upgrade');
    upgradeService = require('../../services/upgradeService');
    signature = require('../../services/upgradeRequestSignature');

    fs.mkdirSync(upgradeConfig.requestsDir, { recursive: true });
    fs.mkdirSync(upgradeConfig.statusDir, { recursive: true });
    fs.mkdirSync(path.join(upgradeConfig.queueDir, 'processing'), { recursive: true });
  });

  beforeEach(() => {
    // 每个用例从空队列开始；heartbeat 由需要就绪的用例自行写入
    for (const sub of ['requests', 'status', 'processing']) {
      const target = path.join(upgradeConfig.queueDir, sub);
      for (const name of fs.readdirSync(target)) fs.rmSync(path.join(target, name));
    }
    fs.rmSync(upgradeConfig.heartbeatFile, { force: true });
  });

  afterAll(() => {
    fs.rmSync(dir, { recursive: true, force: true });
    delete process.env.UPGRADE_QUEUE_DIR;
    delete process.env.UPGRADE_ENABLED;
    delete process.env.HOT_UPGRADE_REGISTRY_ALLOWLIST;
    delete process.env.UPGRADE_AGENT_STALE_SECONDS;
    delete process.env.UPGRADE_REQUEST_TTL_SECONDS;
  });

  const writeHeartbeat = (lastSeenAt = new Date()) =>
    fs.writeFileSync(
      upgradeConfig.heartbeatFile,
      JSON.stringify({ lastSeenAt: lastSeenAt.toISOString(), version: 'test', ready: true }),
      { mode: 0o644 }
    );

  test('isJobId 只接受小写 UUID，拒绝路径穿越与任意字符串', () => {
    expect(upgradeService.isJobId('550e8400-e29b-41d4-a716-446655440000')).toBe(true);
    expect(upgradeService.isJobId('550E8400-E29B-41D4-A716-446655440000')).toBe(false);
    expect(upgradeService.isJobId('../../etc/passwd')).toBe(false);
    expect(upgradeService.isJobId('550e8400')).toBe(false);
    expect(upgradeService.isJobId(null)).toBe(false);
  });

  test('就绪判据逐条返回原因：开关/白名单/目录/心跳缺一不可', () => {
    const notReady = upgradeService.getReadiness();
    expect(notReady.ready).toBe(false);
    expect(notReady.reasons.join('\n')).toMatch(/心跳/);

    writeHeartbeat();
    const ready = upgradeService.getReadiness();
    expect(ready.ready).toBe(true);
    expect(ready.reasons).toEqual([]);
    expect(ready.allowlist).toEqual(['ghcr.io/fsms-test/']);
    expect(ready.heartbeat.stale).toBe(false);
  });

  test('心跳过期视为代理离线（否则请求会被静默留在队列里）', () => {
    // UPGRADE_AGENT_STALE_SECONDS=600 ⇒ 超过 10 分钟才算离线
    writeHeartbeat(new Date(Date.now() - 601 * 1000));
    const readiness = upgradeService.getReadiness();
    expect(readiness.ready).toBe(false);
    expect(readiness.reasons.join('\n')).toMatch(/心跳已过期/);
  });

  test('心跳缺 ready 字段视为未就绪（不把「不知道」当成「可以发版」）', () => {
    fs.writeFileSync(
      upgradeConfig.heartbeatFile,
      JSON.stringify({ lastSeenAt: new Date().toISOString(), version: '0.0.0' }),
      { mode: 0o644 }
    );
    const readiness = upgradeService.getReadiness();
    expect(readiness.ready).toBe(false);
    expect(readiness.reasons.join('\n')).toMatch(/代理未就绪/);
  });

  test('心跳时间晚于当前时间（时钟不同步）按过期处理，不给就绪', () => {
    writeHeartbeat(new Date(Date.now() + 3600 * 1000));
    const readiness = upgradeService.getReadiness();
    expect(readiness.ready).toBe(false);
    expect(readiness.reasons.join('\n')).toMatch(/心跳已过期/);
  });

  test('代理在线但自检未过：把代理给出的原因带出来（否则按钮可点、任务永远排队）', () => {
    fs.writeFileSync(
      upgradeConfig.heartbeatFile,
      JSON.stringify({
        lastSeenAt: new Date().toISOString(),
        version: 'test',
        ready: false,
        reasons: ['HOT_UPGRADE_REGISTRY_ALLOWLIST 为空（空白名单按全拒处理）'],
      }),
      { mode: 0o644 }
    );
    const readiness = upgradeService.getReadiness();
    expect(readiness.ready).toBe(false);
    expect(readiness.reasons.join('\n')).toMatch(/代理未就绪/);
    expect(readiness.reasons.join('\n')).toMatch(/ALLOWLIST 为空/);
  });

  test('镜像校验：tag 拒绝、白名单外拒绝、空白名单全拒', () => {
    const tag = upgradeService.validateImage('ghcr.io/fsms-test/app:v1');
    expect(tag.ok).toBe(false);
    expect(tag.message).toMatch(/digest/);

    const foreign = upgradeService.validateImage(`ghcr.io/attacker/app@${DIGEST}`);
    expect(foreign.ok).toBe(false);
    expect(foreign.message).toMatch(/白名单/);

    const ok = upgradeService.validateImage(IMAGE);
    expect(ok.ok).toBe(true);
    expect(ok.parsed.ref).toBe(IMAGE);
  });

  test('入队：原子写请求文件、签名可验、0600、镜像被规范化', () => {
    writeHeartbeat();
    const { job } = upgradeService.createUpgradeRequest({
      image: `  ${IMAGE}  `,
      user: { userId: 'u1', username: 'admin' },
      sourceIp: '10.0.0.1',
    });

    const file = path.join(upgradeConfig.requestsDir, `${job.id}.json`);
    expect(fs.existsSync(file)).toBe(true);
    const raw = JSON.parse(fs.readFileSync(file, 'utf8'));
    expect(raw.image).toBe(IMAGE);
    expect(raw.requestedBy).toEqual({ userId: 'u1', username: 'admin' });
    expect(raw.sourceIp).toBe('10.0.0.1');
    expect(
      signature.verifyUpgradeRequest(
        process.env.HMAC_SECRET,
        {
          id: raw.id,
          image: raw.image,
          requestedAt: raw.requestedAt,
          userId: raw.requestedBy.userId,
        },
        raw.signature
      )
    ).toBe(true);

    // 篡改 digest 后签名必须失败（agent 据此拒绝被本机其它用户改过的请求）
    expect(
      signature.verifyUpgradeRequest(
        process.env.HMAC_SECRET,
        {
          id: raw.id,
          image: `ghcr.io/fsms-test/app@sha256:${'b'.repeat(64)}`,
          requestedAt: raw.requestedAt,
          userId: raw.requestedBy.userId,
        },
        raw.signature
      )
    ).toBe(false);

    if (process.platform !== 'win32') {
      expect(fs.statSync(file).mode & 0o077).toBe(0);
    }
  });

  test('同一时间只允许一个任务：请求文件存在即视为排队中', () => {
    writeHeartbeat();
    upgradeService.createUpgradeRequest({
      image: IMAGE,
      user: { userId: 'u1', username: 'admin' },
    });

    expect(() =>
      upgradeService.createUpgradeRequest({
        image: IMAGE,
        user: { userId: 'u2', username: 'admin2' },
      })
    ).toThrow(expect.objectContaining({ code: 'UPGRADE_ALREADY_RUNNING' }));
  });

  test('入队锁：残留的活锁 ⇒ 拒绝且不写请求文件；陈旧锁 ⇒ 回收后放行（check-then-write 不同窗口）', () => {
    writeHeartbeat();
    const lockFile = path.join(upgradeConfig.requestsDir, '.enqueue.lock');

    fs.writeFileSync(lockFile, 'other-pid', { mode: 0o600 });
    const filesBefore = fs
      .readdirSync(upgradeConfig.requestsDir)
      .filter((n) => n.endsWith('.json'));
    expect(() =>
      upgradeService.createUpgradeRequest({ image: IMAGE, user: { userId: 'u3', username: 'a3' } })
    ).toThrow(expect.objectContaining({ code: 'UPGRADE_ALREADY_RUNNING' }));
    expect(fs.readdirSync(upgradeConfig.requestsDir).filter((n) => n.endsWith('.json'))).toEqual(
      filesBefore
    );

    // 进程在临界区内崩溃会留下锁：超过 30s 即视为陈旧，否则升级入口被永久堵死
    const stale = new Date(Date.now() - 31 * 1000);
    fs.utimesSync(lockFile, stale, stale);
    const { job } = upgradeService.createUpgradeRequest({
      image: IMAGE,
      user: { userId: 'u4', username: 'a4' },
    });
    expect(job.state).toBe('queued');
    expect(fs.existsSync(path.join(upgradeConfig.requestsDir, `${job.id}.json`))).toBe(true);
    // 成功路径必须把锁清掉：留着会让下一次入队先被自己挡下
    expect(fs.existsSync(lockFile)).toBe(false);
  });

  test('关闭开关时直接拒绝（概览仍可读，只是 ready=false）', () => {
    writeHeartbeat();
    // 用 isolate 加载一份 disabled 配置，避免改动本文件其余用例的模块实例
    jest.isolateModules(() => {
      process.env.UPGRADE_ENABLED = 'false';
      const disabled = require('../../services/upgradeService');
      expect(() =>
        disabled.createUpgradeRequest({ image: IMAGE, user: { userId: 'u1', username: 'a' } })
      ).toThrow(expect.objectContaining({ code: 'UPGRADE_DISABLED' }));
      process.env.UPGRADE_ENABLED = 'true';
    });
  });

  test('状态目录优先：agent 写的 status 覆盖 queued 视图，步骤被截断到安全长度', () => {
    writeHeartbeat();
    const { job } = upgradeService.createUpgradeRequest({
      image: IMAGE,
      user: { userId: 'u1', username: 'admin' },
    });

    const steps = Array.from({ length: 60 }, (_, i) => ({
      name: `step-${i}`,
      detail: 'x'.repeat(400),
      at: new Date().toISOString(),
    }));
    fs.writeFileSync(
      path.join(upgradeConfig.statusDir, `${job.id}.json`),
      JSON.stringify({
        id: job.id,
        state: 'succeeded',
        image: IMAGE,
        requestedBy: { userId: 'u1', username: 'admin' },
        requestedAt: job.requestedAt,
        outcome: 'ok',
        activeColor: 'blue',
        targetColor: 'green',
        steps,
      })
    );

    const read = upgradeService.readJob(job.id);
    expect(read.state).toBe('succeeded');
    expect(read.outcome).toBe('ok');
    expect(read.targetColor).toBe('green');
    expect(read.steps).toHaveLength(40);
    expect(read.steps[0].detail).toHaveLength(300);
  });

  test('概览返回服务端构建信息、就绪原因与历史（服务端字段名稳定）', () => {
    writeHeartbeat();
    upgradeService.createUpgradeRequest({
      image: IMAGE,
      user: { userId: 'u1', username: 'admin' },
    });

    const overview = upgradeService.getOverview({
      buildInfo: { version: '1.0.0', buildId: 'sha-test', buildTime: null },
    });
    expect(overview.server.version).toBe('1.0.0');
    expect(overview.server.buildId).toBe('sha-test');
    expect(overview.server.color).toBe('blue');
    expect(overview.upgrade.ready).toBe(true);
    expect(overview.upgrade.history).toEqual([]);
    // 202 返回后、代理写 status 之前，概览仍要显示这条 queued 请求
    expect(overview.upgrade.activeJob).toMatchObject({ state: 'queued', image: IMAGE });
    expect(overview.upgrade.latestJob.state).toBe('queued');
    expect(Date.parse(overview.checkedAt)).not.toBeNaN();
  });

  test('备色靠 DEPLOY_COLOR 自报颜色：两色都监听 3000，PORT 分不出来', () => {
    // green 容器内 PORT 同样是 3000，只按端口推断会把备色报成 blue，
    // 「切流后仍显示 blue」会让运维误以为切流没生效。
    const savedPort = process.env.PORT;
    const savedColor = process.env.DEPLOY_COLOR;
    try {
      process.env.PORT = '3000';
      process.env.DEPLOY_COLOR = 'green';
      const overview = upgradeService.getOverview({
        buildInfo: { version: '1.0.0', buildId: 'sha-test', buildTime: null },
      });
      expect(overview.server.color).toBe('green');
      expect(overview.server.port).toBe(3000);

      // 非法值不能悄悄透传（否则前端拿任意字符串去比对颜色）
      process.env.DEPLOY_COLOR = 'purple';
      expect(
        upgradeService.getOverview({
          buildInfo: { version: '1.0.0', buildId: 'sha-test', buildTime: null },
        }).server.color
      ).toBe('blue');
    } finally {
      if (savedPort === undefined) delete process.env.PORT;
      else process.env.PORT = savedPort;
      if (savedColor === undefined) delete process.env.DEPLOY_COLOR;
      else process.env.DEPLOY_COLOR = savedColor;
    }
  });

  test('并发闸控制臂：processing 里的真作业会被看见，并挡住第二次入队', () => {
    writeHeartbeat();
    const jobId = '550e8400-e29b-41d4-a716-4466554400aa';
    fs.writeFileSync(
      path.join(upgradeConfig.queueDir, 'processing', `${jobId}.json`),
      JSON.stringify({ id: jobId, state: 'running', image: IMAGE, step: 'pull' }),
      { mode: 0o640 }
    );

    expect(upgradeService.findActiveJob()).toMatchObject({ id: jobId, state: 'running' });
    expect(
      upgradeService.getOverview({ buildInfo: { version: '1.0.0' } }).upgrade.activeJob
    ).toMatchObject({ id: jobId, state: 'running' });
    expect(() =>
      upgradeService.createUpgradeRequest({ image: IMAGE, user: { userId: 'u5', username: 'a5' } })
    ).toThrow(expect.objectContaining({ code: 'UPGRADE_ALREADY_RUNNING' }));
  });

  test('processing 目录读不出来（EACCES）⇒ fail-closed：拒绝入队、不写请求文件、就绪给信号', () => {
    // 旧实现把 readdirSync 的 EACCES 折成 []，于是「读不到」与「没有进行中的任务」同形：
    // 升级进行中仍接受第二个请求，且日志/指标/readyz 三面无痕（审计报告 §1.1 实跑复现）。
    writeHeartbeat();
    const jobId = '550e8400-e29b-41d4-a716-4466554400bb';
    fs.writeFileSync(
      path.join(upgradeConfig.queueDir, 'processing', `${jobId}.json`),
      JSON.stringify({ id: jobId, state: 'running', image: IMAGE }),
      { mode: 0o640 }
    );

    const realReaddir = fs.readdirSync;
    const realAccess = fs.accessSync;
    const denied = (target) => String(target).endsWith('processing');
    const boom = (target) => {
      if (denied(target)) {
        throw Object.assign(new Error('EACCES: permission denied'), { code: 'EACCES' });
      }
    };
    fs.readdirSync = (target, ...rest) => {
      boom(target);
      return realReaddir(target, ...rest);
    };
    fs.accessSync = (target, ...rest) => {
      boom(target);
      return realAccess(target, ...rest);
    };
    try {
      // 就绪判据必须包含 processing：它此前从未被探测，而它读不到时并发闸会静默失效
      expect(upgradeService.getReadiness().codes).toContain('PROCESSING_DIR_UNREADABLE');
      expect(upgradeService.getReadiness().ready).toBe(false);

      expect(() => upgradeService.findActiveJob()).toThrow(
        expect.objectContaining({ name: 'QueueIoError' })
      );
      expect(() =>
        upgradeService.createUpgradeRequest({
          image: IMAGE,
          user: { userId: 'u6', username: 'a6' },
        })
      ).toThrow(expect.objectContaining({ code: 'UPGRADE_QUEUE_UNAVAILABLE' }));

      // 概览要说「队列读不出来」，不许渲染成「没有进行中的任务」
      const overview = upgradeService.getOverview({ buildInfo: { version: '1.0.0' } });
      expect(overview.upgrade.ready).toBe(false);
      expect(overview.upgrade.reasonCodes).toContain('QUEUE_IO_UNREADABLE');
      expect(overview.upgrade.reasons.join(' | ')).toContain('processing');
    } finally {
      fs.readdirSync = realReaddir;
      fs.accessSync = realAccess;
    }

    // 拒绝必须发生在写入之前：队列里不得留下半个请求
    expect(fs.readdirSync(upgradeConfig.requestsDir).filter((n) => n.endsWith('.json'))).toEqual(
      []
    );
  });

  test('状态文件读不出来（坏 JSON）⇒ 同样 fail-closed，且概览给可归因信号', () => {
    writeHeartbeat();
    fs.writeFileSync(
      path.join(upgradeConfig.statusDir, '550e8400-e29b-41d4-a716-4466554400cc.json'),
      '{ 这不是 JSON',
      { mode: 0o640 }
    );
    // 目录与心跳都正常：坏文件不该把就绪判据一起拉红（两类口径分明，便于运维定位）
    expect(upgradeService.getReadiness().ready).toBe(true);

    expect(() =>
      upgradeService.createUpgradeRequest({ image: IMAGE, user: { userId: 'u7', username: 'a7' } })
    ).toThrow(expect.objectContaining({ code: 'UPGRADE_QUEUE_UNAVAILABLE' }));

    const overview = upgradeService.getOverview({ buildInfo: { version: '1.0.0' } });
    expect(overview.upgrade.ready).toBe(false);
    expect(overview.upgrade.reasonCodes).toContain('QUEUE_IO_UNREADABLE');
    expect(overview.upgrade.activeJob).toBeNull();
    expect(fs.readdirSync(upgradeConfig.requestsDir).filter((n) => n.endsWith('.json'))).toEqual(
      []
    );
  });

  describe('离线升级（mode 与 bundles 透传）', () => {
    const writeHeartbeatWithBundles = (bundles) =>
      fs.writeFileSync(
        upgradeConfig.heartbeatFile,
        JSON.stringify({
          lastSeenAt: new Date().toISOString(),
          version: 'test',
          ready: true,
          bundles,
        }),
        { mode: 0o644 }
      );

    test("mode:'offline' 入队：落盘显式带 mode，签名按 offline 分型（5 段）且剥掉 mode 必红", () => {
      writeHeartbeat();
      const { job } = upgradeService.createUpgradeRequest({
        image: IMAGE,
        mode: 'offline',
        user: { userId: 'u8', username: 'a8' },
      });
      const file = path.join(upgradeConfig.requestsDir, `${job.id}.json`);
      const raw = JSON.parse(fs.readFileSync(file, 'utf8'));
      expect(raw.mode).toBe('offline');
      const verifyPayload = {
        id: raw.id,
        image: raw.image,
        requestedAt: raw.requestedAt,
        userId: raw.requestedBy.userId,
      };
      // 带 mode 验（5 段）通过；剥掉 mode 冒充 registry（4 段）必红——两条旁路都不存在
      expect(
        signature.verifyUpgradeRequest(
          process.env.HMAC_SECRET,
          { ...verifyPayload, mode: 'offline' },
          raw.signature
        )
      ).toBe(true);
      expect(
        signature.verifyUpgradeRequest(process.env.HMAC_SECRET, verifyPayload, raw.signature)
      ).toBe(false);
      // 任务视图带 mode（前端进度弹窗显示「来源」）
      expect(upgradeService.readJob(job.id).mode).toBe('offline');
    });

    test('mode 缺省入队：落盘 mode=registry，签名维持 4 段历史格式（滚动期旧代理也能验）', () => {
      writeHeartbeat();
      const { job } = upgradeService.createUpgradeRequest({
        image: IMAGE,
        user: { userId: 'u9', username: 'a9' },
      });
      const raw = JSON.parse(
        fs.readFileSync(path.join(upgradeConfig.requestsDir, `${job.id}.json`), 'utf8')
      );
      expect(raw.mode).toBe('registry');
      // 与历史格式逐字节相同的 4 段验签必须通过（旧版宿主脚本兼容性）
      expect(
        signature.verifyUpgradeRequest(
          process.env.HMAC_SECRET,
          {
            id: raw.id,
            image: raw.image,
            requestedAt: raw.requestedAt,
            userId: raw.requestedBy.userId,
          },
          raw.signature
        )
      ).toBe(true);
    });

    test('service 层 mode 兜底归一：非法值按 registry 处理（路由层 isIn 已先行 400）', () => {
      writeHeartbeat();
      const { job } = upgradeService.createUpgradeRequest({
        image: IMAGE,
        mode: 'evil',
        user: { userId: 'u10', username: 'a10' },
      });
      const raw = JSON.parse(
        fs.readFileSync(path.join(upgradeConfig.requestsDir, `${job.id}.json`), 'utf8')
      );
      expect(raw.mode).toBe('registry');
      expect(job.mode).toBe('registry');
    });

    test('心跳 bundles 原样透传；心跳坏 bundles / 无 bundles 折成空结构（不让坏心跳炸概览）', () => {
      writeHeartbeatWithBundles({
        available: [
          {
            dirName: 'v1.2.3',
            ref: IMAGE,
            digest: DIGEST,
            repository: 'ghcr.io/fsms-test/app',
            version: '1.2.3',
            buildId: 'ci-42',
            createdAt: '2026-11-01T00:00:00Z',
          },
        ],
        invalid: [{ dirName: 'broken', error: 'manifest 缺 sha256' }],
      });
      const overview = upgradeService.getOverview({ buildInfo: { version: '1.0.0' } });
      expect(overview.upgrade.bundles.available).toHaveLength(1);
      expect(overview.upgrade.bundles.available[0]).toMatchObject({
        dirName: 'v1.2.3',
        ref: IMAGE,
      });
      expect(overview.upgrade.bundles.invalid).toHaveLength(1);

      writeHeartbeatWithBundles({ available: 'not-an-array', invalid: 42 });
      const degraded = upgradeService.getOverview({ buildInfo: { version: '1.0.0' } });
      expect(degraded.upgrade.bundles).toEqual({ available: [], invalid: [] });

      writeHeartbeat();
      const plain = upgradeService.getOverview({ buildInfo: { version: '1.0.0' } });
      expect(plain.upgrade.bundles).toEqual({ available: [], invalid: [] });
      // 从未上报心跳（null）时同样给空结构，而不是 undefined
      fs.rmSync(upgradeConfig.heartbeatFile, { force: true });
      const noBeat = upgradeService.getOverview({ buildInfo: { version: '1.0.0' } });
      expect(noBeat.upgrade.bundles).toEqual({ available: [], invalid: [] });
    });

    test('心跳 intake（落位通道）原样透传；坏形状 / 缺字段折成空结构', () => {
      const writeBeat = (intake) =>
        fs.writeFileSync(
          upgradeConfig.heartbeatFile,
          JSON.stringify({
            lastSeenAt: new Date().toISOString(),
            version: 'test',
            ready: true,
            intake,
          }),
          { mode: 0o644 }
        );

      writeBeat({
        pending: ['v1.3.0.tar.gz', 'v1.3.1.tar.gz'],
        rejected: [
          { archive: 'bad.tar.gz', outcome: 'aborted_signature_failed', reason: '未签名' },
        ],
        landed: 'v1.2.3',
      });
      const overview = upgradeService.getOverview({ buildInfo: { version: '1.0.0' } });
      expect(overview.upgrade.intake).toEqual({
        pending: ['v1.3.0.tar.gz', 'v1.3.1.tar.gz'],
        rejected: [
          { archive: 'bad.tar.gz', outcome: 'aborted_signature_failed', reason: '未签名' },
        ],
        landed: 'v1.2.3',
      });

      // 坏形状：pending 非数组、rejected 混入非对象、landed 非字符串 —— 一律折成缺省
      writeBeat({ pending: 'nope', rejected: [null, 42, { archive: 'x.tar.gz' }], landed: 123 });
      const degraded = upgradeService.getOverview({ buildInfo: { version: '1.0.0' } });
      expect(degraded.upgrade.intake).toEqual({
        pending: [],
        rejected: [{ archive: 'x.tar.gz', outcome: '', reason: '' }],
        landed: '',
      });

      // 无 intake 字段（老代理心跳）/ 从未上报：都给空结构而不是 undefined
      writeHeartbeat();
      const plain = upgradeService.getOverview({ buildInfo: { version: '1.0.0' } });
      expect(plain.upgrade.intake).toEqual({ pending: [], rejected: [], landed: '' });
      fs.rmSync(upgradeConfig.heartbeatFile, { force: true });
      const noBeat = upgradeService.getOverview({ buildInfo: { version: '1.0.0' } });
      expect(noBeat.upgrade.intake).toEqual({ pending: [], rejected: [], landed: '' });
    });
  });
});
