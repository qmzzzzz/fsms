'use strict';

/**
 * （2026-09-19）：数值型环境变量的统一判据（负值是真值）
 *
 * 本仓已有 4 处独立修过同一类缺陷（swagger P2-37/P2-70、config P2-39、retention 钳制、
 * 本次改动 的 WAL 上限），但每次就地打补丁 ⇒ 仍有漏网。本次改动把判据收进
 * `utils/envNumber`，并先接两个最要命的点：
 *  - `AUDIT_CHAIN_LOCK_TIMEOUT_MS`（审计链锁超时）
 *  - `AUDIT_WAL_MAX_BYTES`（WAL 硬上限）
 * 其余三处（AUDIT_BUFFER_HARD_LIMIT / ALERT_RATE_LIMIT_MAX / AUDIT_MONITOR_INTERVAL_MS /
 * LOG_SHIPPING_*）在并行会话的 M 态文件里，补丁已交付协作技术文档。
 */

const { readPositiveNumberEnv } = require('../../src/utils/envNumber');

const NAME = 'TEST_NUMBER';

function withEnv(raw, fn) {
  const saved = process.env[NAME];
  if (raw === undefined) delete process.env[NAME];
  else process.env[NAME] = String(raw);
  const invalid = [];
  try {
    return { value: fn((name, value, fallback) => invalid.push([name, value, fallback])), invalid };
  } finally {
    if (saved === undefined) delete process.env[NAME];
    else process.env[NAME] = saved;
  }
}

describe('readPositiveNumberEnv 判据', () => {
  test.each([
    [undefined, 42],
    ['', 42],
    ['   ', 42],
    ['0', 42],
    ['-1', 42],
    ['-0.5', 42],
    ['abc', 42],
    ['Infinity', 42],
    ['-Infinity', 42],
    ['NaN', 42],
    ['7', 7],
    [' 12 ', 12],
    ['1.5', 1.5],
    ['1e3', 1000],
    ['0x10', 16],
  ])('%s ⇒ %s', (raw, expected) => {
    const r = withEnv(raw, (cb) => readPositiveNumberEnv(NAME, 42, { onInvalid: cb }));
    expect(r.value).toBe(expected);
  });

  test('integer 模式：非整数被拒（条目数/批次大小一类不接受 1.5）', () => {
    const r = withEnv('1.5', (cb) =>
      readPositiveNumberEnv(NAME, 10, { integer: true, onInvalid: cb })
    );
    expect(r.value).toBe(10);
    expect(r.invalid).toEqual([[NAME, '1.5', 10]]);
    const ok = withEnv('5', (cb) =>
      readPositiveNumberEnv(NAME, 10, { integer: true, onInvalid: cb })
    );
    expect(ok.value).toBe(5);
    expect(ok.invalid).toEqual([]);
  });

  test('未配置不告警，非法才告警（配置缺省是正常状态）', () => {
    const unset = withEnv(undefined, (cb) => readPositiveNumberEnv(NAME, 9, { onInvalid: cb }));
    expect(unset.value).toBe(9);
    expect(unset.invalid).toEqual([]);
    const bad = withEnv('-3000', (cb) => readPositiveNumberEnv(NAME, 9, { onInvalid: cb }));
    expect(bad.invalid).toHaveLength(1);
    expect(bad.invalid[0][1]).toBe('-3000');
  });

  test('负值确实会被原样采纳（证明 `Number(env) || 默认` 这个惯用法为什么会出事）', () => {
    withEnv('-1', () => {
      expect(Number(process.env[NAME]) || 15000).toBe(-1);
    });
  });
});

describe('审计链锁超时不再接受负值', () => {
  const TIMEOUT_NAME = 'AUDIT_CHAIN_LOCK_TIMEOUT_MS';
  const saved = process.env[TIMEOUT_NAME];

  afterEach(() => {
    if (saved === undefined) delete process.env[TIMEOUT_NAME];
    else process.env[TIMEOUT_NAME] = saved;
  });

  function freshChain() {
    jest.resetModules();
    return require('../../src/utils/auditChain');
  }

  test('负值 ⇒ 回落 15s 默认，临界区正常执行（旧行为：每次都立即判定超时）', async () => {
    process.env[TIMEOUT_NAME] = '-1';
    // 顺序很关键：resetModules 之后先拿"本代" logger 实例装好 spy，再 require auditChain——
    // 同一代注册表里 auditChain 要到的就是被 spy 过的那个对象。
    // 反过来（先 spy 顶层 require 到的旧实例、再 resetModules）会完全听不到加载期告警：
    // CHAIN_LOCK_TIMEOUT_MS 是在模块加载期读的，那一声 error 早于任何用例代码。
    jest.resetModules();
    const freshLogger = require('../../src/utils/logger');
    const errSpy = jest.spyOn(freshLogger, 'error').mockImplementation(() => {});
    let value;
    try {
      const chain = require('../../src/utils/auditChain');
      value = await chain.withChainLock(async () => 'ok');
      const logged = errSpy.mock.calls.map((c) => c.join(' ')).join('\n');
      expect(logged).toContain(TIMEOUT_NAME);
      expect(logged).toContain('非法');
    } finally {
      errSpy.mockRestore();
    }
    expect(value).toBe('ok');
  });

  test('合法小值仍被原样采用（80ms 超时确实生效，没有偷偷设最小值）', async () => {
    process.env[TIMEOUT_NAME] = '80';
    const chain = freshChain();
    const started = Date.now();
    await expect(
      chain.withChainLock(
        () =>
          new Promise((r) => {
            const t = setTimeout(r, 1500);
            if (t.unref) t.unref();
          })
      )
    ).rejects.toThrow(/持有超时/);
    const elapsed = Date.now() - started;
    expect(elapsed).toBeLessThan(1200);
  });

  test('未配置时用 15s 默认，且不产生任何告警', async () => {
    delete process.env[TIMEOUT_NAME];
    jest.resetModules();
    const freshLogger = require('../../src/utils/logger');
    const errSpy = jest.spyOn(freshLogger, 'error').mockImplementation(() => {});
    try {
      const chain = require('../../src/utils/auditChain');
      expect(await chain.withChainLock(async () => 1)).toBe(1);
      expect(errSpy.mock.calls.filter((c) => String(c[0]).includes(TIMEOUT_NAME))).toHaveLength(0);
    } finally {
      errSpy.mockRestore();
    }
  });
});
