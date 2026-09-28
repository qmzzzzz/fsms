'use strict';

/**
 * 日志转发缓冲超限时的「断档标记」记账
 *
 * 缺陷（用真实入口 `log()` 逐行喂出来，不手搓 buffer）：
 *   `_trimToCap()` 每被触发一次就把上一轮的标记**当成一行日志丢掉**并 `unshift` 一条新标记，
 *   而本轮计数 `_droppedCount` 在函数末尾归零 ⇒ 标记之间互相吞噬，计数永不能跨事件累计。
 *   稳态（缓冲已满、每来一行都超限一行）下的实测后果：
 *     喂进 2×BUFFER_CAP 行时真实丢失 5001 行，缓冲里那条标记自报 **2** 行
 *     （人读文案还另报 1 行）。SIEM 侧把"少五千行"读成"少了两行"。
 *
 * 修法口径（本文件钉的就是这三条不变量）：
 *   ① 标记是**累加器**而不是易碎品：头部若有尚未送达的标记，先摘出来、把它已报的数并入新标记，
 *      且它本身**不计入**"丢弃的日志行数"；
 *   ② 标记只在**随成功批次送达 SIEM 之后**才归零；发送失败整批 unshift 回头部时计数必须保留；
 *   ③ 人读的 `message` 数字与机器读的 `__log_shipper_gap__` 字段必须一致。
 *
 * 边界（不放宽任何一侧）：缓冲长度仍必须 ≤ BUFFER_CAP（内存保护是这条标记存在的理由本身），
 * 缓冲里同时最多只能有 1 条标记（否则下游会把一次连续断档读成多次）。
 *
 * 判据算法：真实丢失 = 本段喂入行数 −（仍在缓冲的真日志行 + 本段已成功送达的真日志行）。
 * "本段"由 `rebase()` 划界——一次成功送达就是一个新段的起点。
 */

const { HttpShipperTransport, BUFFER_CAP } = require('../../utils/logShipper');

const gapOf = (line) => {
  try {
    const o = JSON.parse(line);
    return Number.isInteger(o.__log_shipper_gap__) ? o.__log_shipper_gap__ : null;
  } catch {
    return null;
  }
};
const markerLines = (t) => t.buffer.filter((l) => gapOf(l) !== null);
const headMarker = (t) => {
  expect(markerLines(t)).toHaveLength(1);
  expect(gapOf(t.buffer[0])).toEqual(expect.any(Number));
  return t.buffer[0];
};
/** 人读文案里的数字（缺陷之一就是它和机器字段各说一个数） */
const messageCount = (line) => {
  const m = JSON.parse(line).message.match(/已丢弃最旧\s*(\d+)\s*行/);
  return m ? Number(m[1]) : null;
};

/** batchSize 远大于缓冲上限 ⇒ `log()` 永不自动冲刷，发送时机完全由用例控制 */
const makeTransport = () =>
  new HttpShipperTransport({
    url: 'http://127.0.0.1:1/unused-in-this-file',
    batchSize: BUFFER_CAP * 20,
    intervalMs: 3600000,
    timeoutMs: 50,
  });

describe('logShipper 断档标记的记账不变量', () => {
  let t;
  let fed;
  let shippedReal;
  let epoch;
  let errorSpy;

  beforeEach(() => {
    t = makeTransport();
    fed = 0;
    shippedReal = 0;
    epoch = { fed: 0, shipped: 0 };
    errorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    errorSpy.mockRestore();
    clearInterval(t.timer); // 不发网络、不排空：本文件只测记账
    t.timer = null;
  });

  /** 走真实入口逐行喂 */
  const feed = (n) => {
    for (let i = 0; i < n; i += 1) {
      fed += 1;
      t.log({ level: 'info', message: `L${fed}` }, () => {});
    }
  };
  const liveRealLines = () => t.buffer.filter((l) => gapOf(l) === null).length;
  /** 本段真实丢失行数（不依赖任何算术假设） */
  const lostNow = () => fed - epoch.fed - liveRealLines() - (shippedReal - epoch.shipped);
  const rebase = () => {
    epoch = { fed, shipped: shippedReal };
  };

  /** 成功/失败两种发送端：失败路径不计数（整批会 unshift 回缓冲） */
  const shipOnceSucceed = () => {
    const batches = [];
    t._post = async (batch) => {
      batches.push(batch);
      shippedReal += batch.filter((l) => gapOf(l) === null).length;
    };
    return batches;
  };
  const shipAlwaysFail = () => {
    t._post = async () => {
      throw new Error('siem down');
    };
  };

  test('前提：未超限时不留标记、不丢行（否则差值判据全是空的）', () => {
    feed(BUFFER_CAP);
    expect(t.buffer.length).toBe(BUFFER_CAP);
    expect(markerLines(t)).toHaveLength(0);
    expect(lostNow()).toBe(0);
    expect(liveRealLines()).toBe(BUFFER_CAP);
    // 缓冲里确实还是最初那批行，没被悄悄裁掉
    expect(JSON.parse(t.buffer[0]).message).toBe('L1');
    expect(JSON.parse(t.buffer[BUFFER_CAP - 1]).message).toBe(`L${BUFFER_CAP}`);
  });

  test('前提：成功送达的行不得被算成丢失（否则"累计"判据会假绿）', async () => {
    feed(BUFFER_CAP);
    const batches = shipOnceSucceed();
    await t._flush();
    expect(batches).toHaveLength(1);
    expect(batches[0]).toHaveLength(BUFFER_CAP);
    expect(t.buffer.length).toBe(0);
    expect(lostNow()).toBe(0);
    expect(liveRealLines()).toBe(0);
  });

  test('刚越过上限：机器字段与人读文案必须是同一个数，且等于真实丢失行数', () => {
    feed(BUFFER_CAP + 10);

    const head = headMarker(t);
    const lost = lostNow();
    expect(lost).toBeGreaterThan(0);
    expect(gapOf(head)).toBe(lost);
    expect(messageCount(head)).toBe(lost);
    expect(t.buffer.length).toBeLessThanOrEqual(BUFFER_CAP);
  });

  test('稳态持续溢出（标记从未送达）：计数必须累计，不得停在个位数', () => {
    feed(BUFFER_CAP * 2);

    const head = headMarker(t);
    const lost = lostNow();
    // 1 万行喂进 5000 格缓冲：真实丢失必须是一千行量级以上
    expect(lost).toBeGreaterThan(BUFFER_CAP);
    expect(gapOf(head)).toBe(lost);
    expect(messageCount(head)).toBe(lost);
    expect(markerLines(t)).toHaveLength(1); // 标记不得堆积成第二条
  });

  test('标记随成功批次送达后才归零：下一段断档从零重新计（防"永远累加"式修法）', async () => {
    feed(BUFFER_CAP + 10);
    const firstLost = lostNow();
    expect(firstLost).toBeGreaterThan(0);
    expect(gapOf(headMarker(t))).toBe(firstLost);

    const batches = shipOnceSucceed();
    await t._flush();
    expect(batches).toHaveLength(1);
    expect(batches[0].some((l) => gapOf(l) !== null)).toBe(true); // 标记确实被送出去了
    expect(t.buffer.length).toBe(0);
    rebase(); // 已报告过的这一段到此为止

    feed(BUFFER_CAP + 3);
    const secondLost = lostNow();
    expect(secondLost).toBeGreaterThan(0);
    expect(secondLost).toBeLessThan(BUFFER_CAP + 3);
    expect(gapOf(headMarker(t))).toBe(secondLost); // 不得把已报告过的一段再报一次
  });

  test('发送失败整批回头部：计数不得被冲掉（否则断档事实永久消失）', async () => {
    feed(BUFFER_CAP + 10);
    const firstLost = lostNow();

    shipAlwaysFail();
    await t._flush(); // 失败 ⇒ 整批 unshift 回，标记应回到头部

    expect(gapOf(t.buffer[0])).toEqual(expect.any(Number));
    expect(lostNow()).toBe(firstLost); // 失败路径本身不额外丢行
    expect(t.buffer.length).toBeLessThanOrEqual(BUFFER_CAP);

    feed(5);
    expect(lostNow()).toBe(firstLost + 5);
    expect(gapOf(headMarker(t))).toBe(firstLost + 5);
  });

  test('不变量：任意时刻缓冲长度 ≤ BUFFER_CAP，且标记至多一条、计数恒等于真实丢失', () => {
    for (let round = 0; round < 6; round += 1) {
      feed(1 + round * 7);
      expect(t.buffer.length).toBeLessThanOrEqual(BUFFER_CAP);
      expect(markerLines(t).length).toBeLessThanOrEqual(1);
    }
    feed(BUFFER_CAP * 2);
    expect(t.buffer.length).toBeLessThanOrEqual(BUFFER_CAP);
    expect(lostNow()).toBeGreaterThan(0);
    expect(gapOf(headMarker(t))).toBe(lostNow());
  });
});
