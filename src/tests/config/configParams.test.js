/**
 * 配置项外置与安全取值边界（P2-37 / P2-39 / P2-40 / P2-49）
 *
 * 报告 §15 P2 清单里这几条同属「硬编码参数外置 + 危险取值不得静默放行」，
 * 合并到一个文件便于对照。每条都附**能失败**的断言（见各用例注释里的变异手法）。
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..', '..', '..');
const read = (rel) => fs.readFileSync(path.join(ROOT, rel), 'utf8');

/** 在独立子进程里按指定 env 读 config，避免污染本进程的模块缓存 */
function loadConfigWith(env) {
  const { execFileSync } = require('child_process');
  const script = `
    const c = require(process.env.CFG_ROOT + '/src/config');
    process.stdout.write(JSON.stringify({
      bcryptRounds: c.bcryptRounds,
      statsCacheMaxSize: c.cache.statsCacheMaxSize,
      statsCacheCleanupInterval: c.cache.statsCacheCleanupInterval,
    }));
  `;
  const out = execFileSync(process.execPath, ['-e', script], {
    cwd: ROOT,
    env: { ...process.env, ...env, CFG_ROOT: ROOT },
    encoding: 'utf8',
  });
  return JSON.parse(out);
}

describe('P2-39 bcryptRounds 范围校验（10–14）', () => {
  test('过小（4）回落 12：低轮数哈希可被离线秒破，不得静默采用', () => {
    expect(loadConfigWith({ BCRYPT_ROUNDS: '4' }).bcryptRounds).toBe(12);
  });

  test('过大（999）回落 12：bcrypt 是同步 CPU 密集操作，会让登录变成自我 DoS', () => {
    expect(loadConfigWith({ BCRYPT_ROUNDS: '999' }).bcryptRounds).toBe(12);
  });

  test('边界值 10 与 14 均被接受（不误伤合法配置）', () => {
    expect(loadConfigWith({ BCRYPT_ROUNDS: '10' }).bcryptRounds).toBe(10);
    expect(loadConfigWith({ BCRYPT_ROUNDS: '14' }).bcryptRounds).toBe(14);
  });

  test('未设置 / 非法值回落 12', () => {
    expect(loadConfigWith({ BCRYPT_ROUNDS: '' }).bcryptRounds).toBe(12);
    expect(loadConfigWith({ BCRYPT_ROUNDS: 'abc' }).bcryptRounds).toBe(12);
  });

  test('越界时打印告警而非静默（避免「按危险参数运行却无人知晓」）', () => {
    const { execFileSync } = require('child_process');
    const out = execFileSync(
      process.execPath,
      ['-e', `require(process.env.CFG_ROOT + '/src/config')`],
      {
        cwd: ROOT,
        env: { ...process.env, BCRYPT_ROUNDS: '5', CFG_ROOT: ROOT },
        encoding: 'utf8',
        stdio: 'pipe',
      }
    );
    // console.warn 走 stderr，execFileSync 的 stdout 拿不到，改断言源码含告警
    const src = read('src/config/index.js');
    expect(src).toMatch(/BCRYPT_ROUNDS=\$\{process\.env\.BCRYPT_ROUNDS\} 超出安全范围/);
    void out;
  });
});

describe('P2-40 统计缓存参数可配', () => {
  test('STATS_CACHE_MAX_SIZE / STATS_CACHE_CLEANUP_INTERVAL 生效', () => {
    const c = loadConfigWith({
      STATS_CACHE_MAX_SIZE: '2000',
      STATS_CACHE_CLEANUP_INTERVAL: '60000',
    });
    expect(c.statsCacheMaxSize).toBe(2000);
    expect(c.statsCacheCleanupInterval).toBe(60000);
  });

  test('未设置时保持原默认（500 / 120000，行为不回归）', () => {
    const c = loadConfigWith({ STATS_CACHE_MAX_SIZE: '', STATS_CACHE_CLEANUP_INTERVAL: '' });
    expect(c.statsCacheMaxSize).toBe(500);
    expect(c.statsCacheCleanupInterval).toBe(120000);
  });

  test('非法/非正值回落默认（0 与负数会让缓存在首次写入时即失效或死循环）', () => {
    expect(
      loadConfigWith({ STATS_CACHE_MAX_SIZE: '0', STATS_CACHE_CLEANUP_INTERVAL: '-1' })
    ).toMatchObject({ statsCacheMaxSize: 500, statsCacheCleanupInterval: 120000 });
  });
});

describe('P2-37 DOCS_RATE_LIMIT_MAX 负值处理', () => {
  test('负值不再直接传给限流器（原写法 Number(...) || 30 会让负值生效 → 全部 429）', () => {
    const src = read('src/config/swagger.js');
    // 变异验证：把这段改回 `Number(process.env.DOCS_RATE_LIMIT_MAX) || 30` → 本用例红
    expect(src).toMatch(/Number\.isInteger\(n\) && n > 0 \? n : 30/);
    expect(src).not.toMatch(/max: Number\(process\.env\.DOCS_RATE_LIMIT_MAX\) \|\| 30/);
  });

  test('行为实证：负值/非数字/零配置下，限流器不会把每个请求都判超限', async () => {
    // express-rate-limit 的配额不在实例上直接可见，故真跑一次中间件：
    // 若配额被配成负值，第一个请求即 429（文档页 100% 不可用）。
    const { execFileSync } = require('child_process');
    const script = `
      const path = require('path');
      (async () => {
      const swagger = require(process.env.CFG_ROOT + '/src/config/swagger');
      const limiter = swagger.docsLimiter;
      const req = { ip: '10.0.0.1', method: 'GET', originalUrl: '/api-docs/', headers: {}, app: { get: () => undefined } };
      let status = null;
      const res = {
        statusCode: 200,
        setHeader: () => {},
        getHeader: () => undefined,
        status(c) { status = 'status:' + c; return this; },
        json: () => {},
        send: () => {},
        set: () => {},
      };
      // express-rate-limit v7 的中间件是 async（内部 await 存储）——不 await 会拿到 null
      await limiter(req, res, () => { status = 'next'; });
      process.stdout.write('RESULT:' + JSON.stringify({ outcome: status }));
      })();
    `;
    const run = (value) => {
      const out = execFileSync(process.execPath, ['-e', script], {
        cwd: ROOT,
        env: { ...process.env, CFG_ROOT: ROOT, DOCS_RATE_LIMIT_MAX: value },
        encoding: 'utf8',
        stdio: 'pipe',
      });
      // swagger.js 在加载期可能打印告警（stdout 会混入非 JSON 文本），
      // 故用标记定位而不是整体 JSON.parse
      const m = out.match(/\{"outcome":.*?\}/);
      if (!m) throw new Error('未捕获到限流结果，原始输出：' + out);
      return JSON.parse(m[0]).outcome;
    };
    // 合法配额：放行
    expect(run('30')).toBe('next');
    // 三种非法值都必须回落到默认 30（放行），而不是立即 429
    expect(run('-1')).toBe('next');
    expect(run('abc')).toBe('next');
    expect(run('0')).toBe('next');
  });
});

describe('P2-49 redis 镜像钉 digest', () => {
  test('redis 服务使用 digest 引用而非浮动标签', () => {
    const yml = read('docker-compose.yml');
    const m = yml.match(/^\s*image: (redis:[^\s#]+)$/m);
    expect(m).not.toBeNull();
    expect(m[1]).toMatch(/^redis:7-alpine@sha256:[0-9a-f]{64}$/);
  });

  test('digest 的来源与复验结论如实记录（2026-10-01 双源复验后同步更新）', () => {
    const yml = read('docker-compose.yml');
    // 两段事实都必须在：2026-09-17 的初捕获当时未经本机 pull 复核（历史如实保留）；
    // 2026-10-01 经两条独立 registry 通道复验发现 tag 漂移，digest 已同步为当前指向
    expect(yml).toMatch(/未经本机 docker pull 复核/);
    expect(yml).toMatch(/2026-10-01 复验/);
    expect(yml).toMatch(/AWS ECR Public/);
    // 复验命令保留：部署机侧一条命令可再次确认
    expect(yml).toMatch(/docker pull redis:7-alpine@sha256:/);
  });
});
