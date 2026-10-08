/**
 * ──────────────────────────────────────────────────────────────────────────
 * 被测对象：services/statsCache.js 的 TTL 取值路径（配置默认 + 调用方传入两条）
 * 守护的不变式：任何一次写入的剩余寿命都不得越过陈旧窗口上界（3600 秒），
 *   且被夹时必须留痕；合法取值不得被夹坏。
 * 可证伪性（2026-10-03 实测，tools/ledger.js，台账 tools/ledger-statsCacheTtlCeiling.json）：
 *   ① 删配置侧夹取 ⇒ 红 #1 #2；② 上界放大到 1e9 ⇒ 红 #1 #2 #5；
 *   ③ 删调用方侧夹取 ⇒ 红 #5；④ 判据简写 `ttl > 0` ⇒ 全绿（预期活下来的那条，见 #7 注释）。
 *   四条预测与实测逐条一致，跑完 sha256 校验被测文件回到开始时逐字节相同。
 * ──────────────────────────────────────────────────────────────────────────
 *
 * 为什么"上界"不是防御式冗余：`STATS_CACHE_TTL` 只校验有限正数
 * （src/config/index.js 的 statsCacheTtl），配成一年也不会被拒；而 config 注释给长 TTL
 * 背书的理由是"写路径已有 invalidateByUserId 主动失效"。这个前提**按现网键形不成立**：
 *   · 缓存键 = `stats:{查看者id}:{范围摘要}`（controllers/userController.js:972）；
 *   · 失效只删 `stats:{被改用户id}:` 前缀（statsCache.js 的 invalidateByUserIdLocal）
 *     ⇒ 除了被改者本人，其他管理员的桶一条都删不掉；
 *   · 公开注册（services/authService.js 的 User.create）与角色改名
 *     （controllers/roleController.js，统计聚合里有 $lookup roles）根本不触达失效。
 * 于是"多久变新"实际只由 TTL 决定，TTL 没有上界就等于把派生统计变成无限期快照。
 *
 * 判据用**独立字面量 3600**（不是从被测模块导出 MAX_TTL_SECONDS 推导）：
 * 从被测码取期望值就是同义反复——把上界放大到 1e9 后仍然全绿。
 * 同理，"剩余寿命 ≤ 3600s"是量出来的行为差，不是读源码里的数字。
 *
 * 每条用例都在**子进程**里跑：config 的取值发生在模块加载期（IIFE），本进程里改
 * process.env 再 resetModules 会让后面的用例继承脏缓存。子进程是仓内既有做法
 * （src/tests/config/configParams.test.js 的 loadConfigWith 同法），且这里连
 * logger/statsCache/sharedCache 都不用替身——被测的就是真实装配。
 */
const { execFileSync } = require('child_process');
const path = require('path');

const ROOT = path.join(__dirname, '..', '..', '..');

/** 真实装配下量一次写入的剩余寿命 */
const CHILD = `
  const probe = JSON.parse(process.env.FSMS_STATS_PROBE);
  if (probe.ttlEnv === null) delete process.env.STATS_CACHE_TTL;
  else process.env.STATS_CACHE_TTL = String(probe.ttlEnv);
  // 第三参必须按"种类"还原：JSON 会把 Infinity/NaN 静默写成 null，
  // 于是那两条用例会被当成"没传第三参"跑过——那是仪器自己造出来的假绿
  const kind = probe.callKind;
  const callTtl =
    kind === 'none' ? undefined :
    kind === 'inf' ? Infinity :
    kind === 'nan' ? NaN : Number(probe.callValue);
  const logger = require(process.env.CFG_ROOT + '/src/utils/logger');
  const warns = [];
  logger.warn = (msg) => { warns.push(String(msg)); };
  const statsCache = require(process.env.CFG_ROOT + '/src/services/statsCache');
  statsCache.set('stats:viewerA:fp', { total: 1 }, callTtl);
  const entry = statsCache._store.get('stats:viewerA:fp');
  process.stdout.write(JSON.stringify({
    finite: Number.isFinite(entry.expireAt),
    remainMs: Number.isFinite(entry.expireAt) ? entry.expireAt - Date.now() : null,
    warns,
  }));
`;

/**
 * @param {number|null} ttlEnv STATS_CACHE_TTL 的原始值（null=不设该环境变量）
 * @param {number|undefined} callTtl 调用方传给 set 的第三个参数
 */
function measure(ttlEnv, callTtl) {
  let callKind = 'value';
  if (callTtl === undefined) callKind = 'none';
  else if (callTtl === Infinity) callKind = 'inf';
  else if (Number.isNaN(callTtl)) callKind = 'nan';
  const out = execFileSync(process.execPath, ['-e', CHILD], {
    cwd: ROOT,
    encoding: 'utf8',
    env: {
      ...process.env,
      CFG_ROOT: ROOT,
      NODE_ENV: 'test',
      FSMS_STATS_PROBE: JSON.stringify({ ttlEnv, callKind, callValue: callTtl ?? 0 }),
    },
  });
  return JSON.parse(out.slice(out.indexOf('{')));
}

const HOUR_MS = 3600 * 1000; // 独立抄本：期望值不许从被测模块取

describe('statsCache 陈旧窗口上界', () => {
  test('配置成一年（31536000 秒）也只能缓存一小时', () => {
    const r = measure(31536000);
    expect(r.finite).toBe(true);
    expect(r.remainMs).toBeGreaterThan(0);
    expect(r.remainMs).toBeLessThanOrEqual(HOUR_MS);
  });

  test('被夹时必须留痕——否则运维以为自己配的一年生效了，实际是一小时', () => {
    const r = measure(31536000);
    expect(r.warns.length).toBe(1);
    expect(r.warns[0]).toContain('3600');
    expect(r.warns[0]).toContain('31536000');
  });

  test('反向对照：合法的 300 秒不得被夹（上界不许把好值改坏，也不许刷 warn）', () => {
    const r = measure(300);
    expect(r.remainMs).toBeGreaterThan(295_000);
    expect(r.remainMs).toBeLessThanOrEqual(300_000);
    expect(r.warns).toEqual([]);
  });

  test('边界：恰好 3600 秒不算越界', () => {
    const r = measure(3600);
    expect(r.warns).toEqual([]);
    expect(r.remainMs).toBeLessThanOrEqual(HOUR_MS);
  });

  test('调用方自己传大 TTL 也不能放大陈旧窗口（userController 之外的第二条写入路径）', () => {
    const r = measure(300, 999_999);
    expect(r.remainMs).toBeGreaterThan(0);
    expect(r.remainMs).toBeLessThanOrEqual(HOUR_MS);
    expect(r.warns.length).toBe(1);
    expect(r.warns[0]).toContain('调用方');
  });

  test('反向对照：审计风险摘要那种 10 秒短 TTL 不受牵连（不得被夹、不得 warn）', () => {
    const r = measure(300, 10);
    expect(r.remainMs).toBeGreaterThan(9_000);
    expect(r.remainMs).toBeLessThanOrEqual(10_000);
    expect(r.warns).toEqual([]);
  });

  test('Infinity / NaN / 0 / 负数一律回落配置默认，不得产生"永不过期"的条目', () => {
    // 这条是**契约钉**而不是可杀判据：现在有两道闸（`Number.isFinite(ttl)` 与上界夹取），
    // 单删任一道都仍然有限。变异实测证实这一点——`isfinite-to-gt0`（把判据简写成 `ttl > 0`）
    // 在这条门禁下活下来（8 条全绿），因为 Infinity 随后被夹到 3600。
    // 它要防的是"两道闸一起没"的那次重构，所以留着，但不计入台账的杀伐数。
    for (const bad of [Infinity, NaN, 0, -5]) {
      const r = measure(300, bad);
      expect({ bad: String(bad), finite: r.finite }).toEqual({ bad: String(bad), finite: true });
      expect(r.remainMs).toBeGreaterThan(0);
      expect(r.remainMs).toBeLessThanOrEqual(HOUR_MS);
    }
  });

  test('未设环境变量时用默认 300 秒（上界改动不得顺带改掉默认值口径）', () => {
    const r = measure(null);
    expect(r.remainMs).toBeGreaterThan(295_000);
    expect(r.remainMs).toBeLessThanOrEqual(300_000);
    expect(r.warns).toEqual([]);
  });
});
