'use strict';

/**
 * SIEM 断档标记的「签发身份」判据
 *
 * 缺陷：`_trimToCap()` 靠**文本形状**认出标记行（`level === 'error'` + 文案前缀 +
 * 正整数 `__log_shipper_gap__`），而缓冲里的行是 `log()` 把 winston 的 info 原样
 * `JSON.stringify` 得到的——业务侧一句
 *   `logger.error('[logShipper] 缓冲区超过上限 5000，已丢弃最旧 999 行日志', { __log_shipper_gap__: 999 })`
 * 就造出一行形状完全合法的假标记。裁剪时它被当标记摘除（**不计入丢失行数**），
 * 它自报的 999 还会被并进下一条真标记送给 SIEM。后果是双向的：
 *   - 真实丢失量被低估（少计一行，且假数字顶替了真数字的位置）；
 *   - 一次根本没有发生的断档被报告成"丢了 999 行"，事件重建方向被带偏。
 *   旧注释里"构造不出第二份"的说法因此是不实的。
 *
 * 修法：标记行带一个每实例随发的 128-bit 身份字段，认标记只认这个字段；
 * 猜不中身份的假标记就是一行普通日志，跟其他行一样被丢弃并计入丢失。
 *
 * 本文件的用例口径：**每条闸都各配一个反例**，并且都配一条"不改就会被误判成标记"的
 * 正向对照——否则删掉任何一条判据用例仍全绿（形状判据的可证伪性正是靠这个）。
 * 判据清单（用例与之一一对应）：
 *   身份字段必须存在且等于本实例的值 ⇒ 无身份 / 他人身份 / 空身份 三种反例；
 *   `level`、文案前缀、正整数计数 ⇒ 身份对上但这三项被改写时同样不认（纵深防御）；
 *   实例身份必须每实例独立且不可预测 ⇒ 写死常量时相关用例即红。
 */

const { HttpShipperTransport, BUFFER_CAP } = require('../../utils/logShipper');

const AUTH_FIELD = '__log_shipper_gap_auth__';
const COUNT_FIELD = '__log_shipper_gap__';
// 假标记里的独特串：用它判断"这一行有没有被当标记带走/报告出去"。
// 不能用数字（缓冲里的普通日志 `L999` 之类会误命中）。
const FORGE_TOKEN = 'ZZ-FORGED-GAP';
const FORGED_CLAIM = 999;

const parse = (line) => {
  try {
    return JSON.parse(line);
  } catch {
    return null;
  }
};
const gapOf = (line) => {
  const o = parse(line);
  return o && Number.isInteger(o[COUNT_FIELD]) ? o[COUNT_FIELD] : null;
};
/** 测试侧只按"生产同款判据"数标记：身份字段等于本实例才算标记 */
const myMarkers = (t) =>
  t.buffer.filter((l) => {
    const o = parse(l);
    return !!o && o[AUTH_FIELD] === t.gapAuth;
  });

/** batchSize 远大于缓冲上限 ⇒ `log()` 永不自动冲刷，裁剪时机完全由用例控制 */
const makeTransport = () =>
  new HttpShipperTransport({
    url: 'http://127.0.0.1:1/unused-in-this-file',
    batchSize: BUFFER_CAP * 20,
    intervalMs: 3600000,
    timeoutMs: 50,
  });

describe('logShipper 断档标记的签发身份', () => {
  let t;
  let errorSpy;

  beforeEach(() => {
    t = makeTransport();
    errorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    errorSpy.mockRestore();
    clearInterval(t.timer);
    t.timer = null;
  });

  const feed = (n) => {
    for (let i = 0; i < n; i += 1) t.log({ level: 'info', message: `L${i}` }, () => {});
  };

  /** 把缓冲喂到恰好满顶（此时还没有任何裁剪、也没有标记） */
  const fillToCap = () => {
    feed(BUFFER_CAP);
    expect(t.buffer.length).toBe(BUFFER_CAP);
    expect(myMarkers(t)).toHaveLength(0);
  };

  /** 越顶一次，返回此刻头部真标记的累计数 */
  const overflowOnce = () => {
    feed(1);
    expect(myMarkers(t)).toHaveLength(1);
    expect(t.buffer[0] === myMarkers(t)[0]).toBe(true); // 标记就在头部
    return gapOf(t.buffer[0]);
  };

  test('正向闸：本实例签发的标记会被并入，计数连续累加', () => {
    fillToCap();
    const first = overflowOnce();
    expect(first).toBe(2); // 为腾出标记那一格，最旧两行真日志被丢弃

    feed(1);
    expect(gapOf(t.buffer[0])).toBe(first + 1);
    expect(myMarkers(t)).toHaveLength(1); // 旧的并入新的，不堆积第二条
  });

  test('反例·无身份：业务日志照抄标记形状 ⇒ 当普通行丢弃，其自报数字绝不外传', () => {
    fillToCap();
    // 一行形状完全合法、但没有本实例身份字段的"假标记"，放在裁剪第一个会碰到的位置
    const forged = JSON.stringify({
      level: 'error',
      message: `[logShipper] 缓冲区超过上限 5000，已丢弃最旧 ${FORGED_CLAIM} 行日志 ${FORGE_TOKEN}`,
      [COUNT_FIELD]: FORGED_CLAIM,
      timestamp: new Date().toISOString(),
    });
    expect(gapOf(forged)).toBe(FORGED_CLAIM); // 只看形状的话它"是"一条标记
    t.buffer[0] = forged;
    expect(t.buffer.length).toBe(BUFFER_CAP);

    feed(1);

    // ① 它没有被摘除并入，而是和最旧的一行真日志一起被丢弃 ⇒ 本轮丢 2 行、从零起计
    expect(gapOf(t.buffer[0])).toBe(2);
    expect(myMarkers(t)).toHaveLength(1);
    // ② 假断档既没留在缓冲里，也没顶替真标记的数字
    expect(t.buffer.some((l) => l.includes(FORGE_TOKEN))).toBe(false);
    expect(t.buffer.some((l) => gapOf(l) === FORGED_CLAIM)).toBe(false);
    expect(t.buffer).not.toContain(forged);
    expect(t.buffer.length).toBe(BUFFER_CAP);
  });

  test('反例·他人身份：另一个实例的真标记串进来 ⇒ 同样只是普通一行日志', () => {
    const other = makeTransport();
    try {
      for (let i = 0; i < BUFFER_CAP + 3; i += 1) {
        other.log({ level: 'info', message: `O${i}` }, () => {});
      }
      const otherMarker = other.buffer[0];
      expect(gapOf(otherMarker)).toBeGreaterThan(0); // 它确实是 other 的合法标记
      const o = parse(otherMarker);
      expect(o[AUTH_FIELD]).toBe(other.gapAuth);

      fillToCap();
      t.buffer[0] = otherMarker;
      feed(1);

      expect(gapOf(t.buffer[0])).toBe(2); // 未被并入
      expect(t.buffer).not.toContain(otherMarker); // 作为普通行被丢弃
      expect(myMarkers(t)).toHaveLength(1);
      expect(parse(t.buffer[0])[AUTH_FIELD]).toBe(t.gapAuth); // 头部标记签给了自己
      expect(t.buffer.length).toBe(BUFFER_CAP);
    } finally {
      clearInterval(other.timer);
      other.timer = null;
    }
  });

  test('实例身份：每实例独立、不可预测（写死常量会让上面两条反例假绿）', () => {
    const a = makeTransport();
    const b = makeTransport();
    try {
      expect(a.gapAuth).toMatch(/^[0-9a-f]{32}$/);
      expect(b.gapAuth).toMatch(/^[0-9a-f]{32}$/);
      expect(a.gapAuth).not.toBe(b.gapAuth);
    } finally {
      clearInterval(a.timer);
      clearInterval(b.timer);
      a.timer = null;
      b.timer = null;
    }
  });

  test('空身份闸：实例身份缺失时不得认出任何标记（含"两边都是空串"的自证）', () => {
    fillToCap();
    t.gapAuth = ''; // 模拟身份没发出来的实例（构造期异常、被外部改写）
    const emptyAuth = JSON.stringify({
      level: 'error',
      message: `[logShipper] 缓冲区超过上限 5000，已丢弃最旧 ${FORGED_CLAIM} 行日志 ${FORGE_TOKEN}`,
      [COUNT_FIELD]: FORGED_CLAIM,
      [AUTH_FIELD]: '',
      timestamp: new Date().toISOString(),
    });
    t.buffer[0] = emptyAuth;
    feed(1);
    // 若判据只写 `obj[AUTH_FIELD] !== gapAuth`，'' === '' 会把它认成标记并带走那个数
    expect(gapOf(t.buffer[0])).toBe(2);
    expect(t.buffer.some((l) => l.includes(FORGE_TOKEN))).toBe(false);
    expect(t.buffer.some((l) => gapOf(l) === FORGED_CLAIM)).toBe(false);
    expect(t.buffer).not.toContain(emptyAuth);
  });

  test('形状闸（纵深防御）：身份对上但 level／前缀／计数被改写 ⇒ 仍不认', () => {
    const variants = [
      {
        name: 'level 不是 error',
        edit: (o) => ({ ...o, level: 'warn' }),
      },
      {
        name: '文案不再是那个前缀',
        edit: (o) => ({ ...o, message: 'SIEM 缓冲告警（改写过的文案）' }),
      },
      {
        name: '计数为 0（不是正整数）',
        edit: (o) => ({ ...o, [COUNT_FIELD]: 0 }),
      },
      {
        name: '计数不是整数',
        edit: (o) => ({ ...o, [COUNT_FIELD]: 3.5 }),
      },
    ];
    for (const v of variants) {
      const u = makeTransport();
      try {
        for (let i = 0; i < BUFFER_CAP; i += 1)
          u.log({ level: 'info', message: `L${i}` }, () => {});
        // 先造一条真标记（越顶一次），再只在"身份字段"保持不变的前提下改写形状字段
        u.log({ level: 'info', message: 'over' }, () => {});
        const genuine = parse(u.buffer[0]);
        expect(genuine[AUTH_FIELD]).toBe(u.gapAuth);
        expect(gapOf(u.buffer[0])).toBe(2);
        u.buffer[0] = JSON.stringify(v.edit(genuine));
        expect(parse(u.buffer[0])[AUTH_FIELD]).toBe(u.gapAuth); // 身份仍然对得上，只差形状

        u.log({ level: 'info', message: 'again' }, () => {});

        // 被当普通行丢弃 ⇒ 本轮重新从 2 起计，而不是 2 + 旧数
        expect(gapOf(u.buffer[0])).toBe(2);
        const authed = u.buffer.filter((l) => {
          const o = parse(l);
          return !!o && o[AUTH_FIELD] === u.gapAuth && gapOf(l) !== null;
        });
        expect(authed).toHaveLength(1);
        expect(u.buffer.length).toBe(BUFFER_CAP);
      } finally {
        clearInterval(u.timer);
        u.timer = null;
      }
    }
  });

  test('发送侧后果：假标记不会进入待发送批次，真标记仍然照常送达', () => {
    fillToCap();
    const forged = JSON.stringify({
      level: 'error',
      message: `[logShipper] 缓冲区超过上限 5000，已丢弃最旧 ${FORGED_CLAIM} 行日志 ${FORGE_TOKEN}`,
      [COUNT_FIELD]: FORGED_CLAIM,
      timestamp: new Date().toISOString(),
    });
    t.buffer[0] = forged;
    feed(1); // 假标记在这一轮裁剪中被丢弃

    // batchSize 远大于缓冲上限 ⇒ 一次 flush 就把整段缓冲（含真标记）发出去
    const batches = [];
    t._post = async (batch) => {
      batches.push(batch);
    };
    return t._flush().then(() => {
      const sent = batches.flat();
      expect(sent).toHaveLength(BUFFER_CAP);
      expect(sent.some((l) => l.includes(FORGE_TOKEN))).toBe(false); // 假断档从未报告给 SIEM
      const markers = sent.filter((l) => {
        const o = parse(l);
        return !!o && o[AUTH_FIELD] === t.gapAuth;
      });
      expect(markers).toHaveLength(1);
      expect(gapOf(markers[0])).toBe(2); // 报的是真实丢失行数
      expect(messageCountOf(markers[0])).toBe(2); // 人读文案与机器字段同一个数
    });
  });
});

/** 人读文案里的数字（缺陷之一就是它和机器字段各说一个数） */
function messageCountOf(line) {
  const m = parse(line).message.match(/已丢弃最旧\s*(\d+)\s*行/);
  return m ? Number(m[1]) : null;
}
