/**
 * 共享缓存锁"降级为无锁语义"必须在默认日志级别下看得见
 *
 * 三处 `catch` 原先记的是 `logger.debug`：
 *   - `acquireLock`：Redis 命令抛错时返回的是**无锁句柄**——调用方以为自己持锁，
 *     跨实例互斥当场不成立（fail-open，全局可见的行为差异）；
 *   - `acquireLockBlocking`：返回 null，本该串行的段落不再串行；
 *   - `casSet`：返回 false——把"基础设施故障"伪装成"版本冲突"，运维按冲突排查会走错方向。
 * 默认 LOG_LEVEL 下 debug 根本不落盘 ⇒ 事故当天这些事实完全隐身，而同文件的 `noOpLock`
 * 早就为"配了 REDIS_URL 但链路不可用"给出 warn。分级判据必须一致：
 *   **未配置 Redis = 单实例设计语义 ⇒ debug（热路径不许刷日志）；
 *    已配置却拿不到结果 = 部署预期被打破 ⇒ warn。**
 *
 * 为什么走子进程而不是进程内 spy（本仓第二次撞上同一格，记死）：
 * jest 沙箱里 winston 的 Console transport 落到的是 `console._stdout`／
 * `this._consoleLog`（node_modules/winston/lib/winston/transports/console.js:70-90），
 * 而那两个都已被 jest 的 CustomConsole 接管 ⇒ `jest.spyOn(process.stdout,'write')`
 * 与 `console._stdout.write = …` **都抓不到任何一行**（实测：连直接
 * `logger.warn('SENTINEL')` 的探针例都是空）。要断言"真实告警发出去了"，
 * 只能在真 node 进程里取证——子进程的 stdout/stderr 是可信 sink。
 *
 * 反向前提同样重要：未配置 Redis 时**不许**出现 warn（否则就是把热路径刷成噪音，
 * 那会让真正的告警淹没在噪音里，等于没修）。
 */

const { spawnSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const REPO = path.join(__dirname, '..', '..');

const PROBE = `
const path = require('path');
const { createLockOperations } = require(path.join(process.env.ZZ_REPO, 'src', 'services', 'sharedCacheLocks'));
const failing = () => ({
  set: async () => { throw new Error('ZZBOOM redis down'); },
  eval: async () => { throw new Error('ZZBOOM redis down'); },
});
const ok = () => ({ set: async () => 'OK', eval: async () => 1 });
const mode = process.env.ZZ_MODE;
const ops = createLockOperations({
  getRedisClient: () => (mode === 'unconfigured' ? ok() : failing()),
  isRedisEnabled: () => mode !== 'unconfigured',
  isRedisConfigured: () => mode !== 'unconfigured',
});
const run = async () => {
  if (mode === 'acquire') {
    const h = await ops.acquireLock('zz:lock', 1000);
    // 打印"调用方以为自己持锁"这一事实：句柄非空且 release 可用 ⇒ fail-open 是真的
    console.log('ZZ_HANDLE=' + JSON.stringify(h !== null && typeof h.release === 'function'));
  } else if (mode === 'blocking') {
    console.log('ZZ_RESULT=' + JSON.stringify(await ops.acquireLockBlocking('zz:lock', 1000, 30)));
  } else if (mode === 'cas') {
    console.log('ZZ_RESULT=' + JSON.stringify(await ops.casSet('zz:key', 1, 2)));
  } else {
    const h = await ops.acquireLock('zz:lock', 1000);
    console.log('ZZ_HANDLE=' + JSON.stringify(h !== null));
  }
};
run().then(
  () => setTimeout(() => process.exit(0), 120),
  (e) => { console.log('ZZ_THREW=' + e.message); setTimeout(() => process.exit(0), 120); }
);
`;

const probePath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'zzlock-')), 'probe.cjs');
fs.writeFileSync(probePath, PROBE, 'utf8');

function drive(mode) {
  const r = spawnSync(process.execPath, [probePath], {
    encoding: 'utf8',
    env: { ...process.env, ZZ_REPO: REPO, ZZ_MODE: mode, NODE_ENV: 'test' },
    timeout: 30000,
  });
  // Console transport 带 colorize ⇒ 真实字节是 `ESC[33mwarnESC[39m`，
  // 字面量 `[warn]` 反而匹配不上（本仓在 prettier 输出上栽过同一枪）。先剥 ANSI。
  const raw = `${r.stdout || ''}\n${r.stderr || ''}`;
  // ESC 用 fromCharCode 构造：本仓 eslint 的 `no-control-regex` 是 error 级，
  // 正则字面量里出现 \x1B / \u001B 都会红。
  const ANSI = new RegExp(`${String.fromCharCode(27)}\\[[0-9;]*m`, 'g');
  return raw.replace(ANSI, '');
}

afterAll(() => {
  fs.rmSync(path.dirname(probePath), { recursive: true, force: true });
});

const warnLines = (out) => out.split('\n').filter((l) => l.includes('[warn]'));

describe('锁降级留痕：已配置 Redis 却失败 ⇒ 必须 warn（子进程取证）', () => {
  test('探针自检：logger 在真进程里确实会输出带级别标签的行（防"抓不到"被当成"没告警"）', () => {
    const out = drive('acquire');
    // 至少能抓到一行日志（含时间戳 + [level]），否则下面所有断言都没有意义
    expect(out).toMatch(/\[(warn|error|info|debug)\]/);
  });

  test('acquireLock 失败：调用方拿到"无锁句柄"（fail-open 事实成立），且留一条 warn', () => {
    const out = drive('acquire');
    expect(out).toMatch(/ZZ_HANDLE=true/);
    const hits = warnLines(out).filter((l) => /ZZBOOM redis down/.test(l));
    expect(hits.length).toBeGreaterThanOrEqual(1);
    expect(hits.join('\n')).toMatch(/无锁语义|跨实例互斥/);
  });

  test('acquireLockBlocking 失败：返回 null 并留 warn（不得继续静默）', () => {
    const out = drive('blocking');
    expect(out).toMatch(/ZZ_RESULT=null/);
    expect(warnLines(out).join('\n')).toMatch(/阻塞锁获取失败/);
  });

  test('casSet 失败：warn 里写明"不是版本冲突"（否则排查方向就是错的）', () => {
    const out = drive('cas');
    expect(out).toMatch(/ZZ_RESULT=false/);
    const hits = warnLines(out).join('\n');
    expect(hits).toMatch(/casSet 失败/);
    expect(hits).toMatch(/不是版本冲突/);
  });

  test('反向前提：未配置 Redis 时不得出现任何 warn（单实例热路径，debug 才是对的级别）', () => {
    const out = drive('unconfigured');
    expect(out).toMatch(/ZZ_HANDLE=true/);
    expect(warnLines(out)).toEqual([]);
  });

  test('反向前提的对照：这条判据不是"日志一律判红"——把上面任一行改掉级别就该红', () => {
    // 若有人把三处 warn 退回 debug，acquire/blocking/cas 三例全红；
    // 若有人把未配置那格也升级成 warn，第五例红。两向都有牙。
    const configured = warnLines(drive('acquire')).length;
    const unconfigured = warnLines(drive('unconfigured')).length;
    expect(configured).toBeGreaterThan(unconfigured);
  });
});
