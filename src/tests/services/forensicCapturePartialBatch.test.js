'use strict';

/**
 * G-6（r21-c 门禁缺口）：取证落库「批内部分成功」的清单锚定判据
 *
 * 守的是什么：**已经进库的记录必须出现在取证清单里**。
 * 清单（forensic-manifest）是取证链对外的核心承诺——「这条记录存在过」。
 * 记录进库但没进清单 ⇒ 事后复核会把它判成「库里多出来的野记录」或干脆看不见，
 * 而这种悬空态**没有任何重试路径能补上**（回填只回填没入库的）。
 *
 * 为什么要单独一个文件：现有用例（forensicCaptureHardening.test.js:137「落库失败时回填与计数都在告警之前完成」）
 * 的桩是 `insertMany` **整批抛错、一条也没进库**。它证明的是「全失败不丢批」，
 * **恰恰没有覆盖「部分成功」**——那种情况下回填集合是空的，而漏掉的是**已成功那部分**的清单锚定。
 * 实跑证据（缺陷在场时现有用例仍绿）：`npx jest src/tests/services/forensicCaptureHardening.test.js` → `Tests: 14 passed`。
 *
 * 缺陷为什么可达（不是纯理论）：记录带**确定性 `_id`**（`forensicCaptureCodec.js` 的 `deterministicId`：
 * recordHash 前 24 位即 _id）。WAL 里「已落库但还没裁」的行在下次启动重放时必然撞 `_id`（E11000）；
 * 而 `insertMany(..., { ordered: false, throwOnValidationError: true })` 在批内部分失败时**仍然整批 reject**。
 *
 * 本文件的三条腿：
 *   ① 全成功批量 ⇒ 清单必须收到全部 hash（**反向对照**：缺陷不在时该绿，也是「夹具/桩没坏」的自证）；
 *   ② 整批抛错 ⇒ 清单不得被调用、且这批必须回填（现有语义的 flusher 级复述，防止 ① 变成「什么都记」）；
 *   ③ **批内一条撞 _id、另一条新记录 ⇒ 新记录必须进清单**（H-3 本体，当前为 `test.failing`）。
 *
 * 关于 `test.failing`（本仓惯例，见 `mfaLifecycleTotpClaim.test.js:153-159`）：
 * H-3 的修复已单独派单，本文件的 ③ 先以「已知缺陷」记账——**CI 保持绿，但缺陷已被判据看住**；
 * 修复落地后 ③ 会**转红**，提醒把 `.failing` 摘掉变成常规回归门禁。
 * 我没有把 ③ 写成普通红用例，因为那会把整仓 CI 变红、掩盖别的泳道的真红；
 * 也没有把它写成「恒绿」的宽断言——那正是这条缺口本来的样子。
 *
 * ③ 摘掉 `.failing` 后的**真实失败原文**（团队口径：`.failing` 的失败原因必须被钉死，
 * 否则它会把夹具自己坏掉也一并吸收成「缺陷已记账」）：
 *
 *   ● G-6 落库清单锚定 › ③ 批内一条撞 _id、另一条新记录 ⇒ 新记录必须进清单
 *     expect(received).toContain(expected) // indexOf
 *     Expected value: "a7db5ea3cd5e235abf6dee7d4fdc0f22142ae464cf333ea391b434dfca7f5e41"
 *     Received array: []                 ← appendBatch 一次都没被调用
 *   Tests:       1 failed, 2 passed, 3 total
 *
 * 注意同一用例内「B 确实进库了」（`countDocuments({ip:'203.0.113.25'})` = 1）是**绿**的——
 * 这一格是 H-3（批内部分成功）与「整批都没进库」的分水岭；没有它，上面那句「Received array: []」
 * 既可能是「部分成功的清单漏锚」，也可能是「整批根本没进库」，两种缺陷分不开。
 */

process.env.FORENSIC_CAPTURE_ENABLED = 'true';
process.env.FORENSIC_WAL_PATH = '';

// 清单写入用替身：本文件的判据是「appendBatch 收到了哪些 hash」，不是「清单文件内容」（那有 forensicManifest.test.js 管）。
// 用替身还有一个好处：不会在仓库 logs/ 下产生真实清单文件。
jest.mock('../../services/forensicManifest', () => ({
  appendBatch: jest.fn(async () => ({ written: true, entry: {} })),
  readManifest: jest.fn(async () => ({ entries: [] })),
  MANIFEST_DIR: '/tmp/not-used',
}));

const mongoose = require('mongoose');

const manifest = require('../../services/forensicManifest');
const { createFlusher } = require('../../services/forensicCaptureFlush');
const { buildRecord } = require('../../services/forensicCapture');
const payload = require('../../services/forensicCapturePayload');
const { deterministicId } = require('../../services/forensicCaptureCodec');
const RealModel = jest.requireActual('../../models/ForensicCapture');

/** 直接构造 flusher：本文件测的是**落库阶段**的语义，不经过编排层的预算/采样 */
const makeHarness = () => {
  const state = { flushing: false, buffer: [], dropped: 0, writeFailures: 0, lastError: null };
  const flush = createFlusher({
    state,
    noteError: (err) => {
      state.lastError = String((err && err.message) || err);
    },
    warnRateLimited: () => {},
    errText: (err) => String((err && err.message) || err),
    bufferHardLimit: 64,
  });
  return { state, flush };
};

const recordFor = (ip, seq) => {
  const response = payload.buildResponsePart({
    status: 200,
    headers: { 'content-type': 'application/json' },
    contentType: 'application/json',
    body: '{"ok":1}',
    complete: true,
  });
  const req = {
    method: 'POST',
    originalUrl: '/api/probe?ok=1',
    path: '/api/probe',
    query: {},
    params: {},
    httpVersion: '1.1',
    headers: {},
    get: () => undefined,
  };
  const doc = buildRecord({ req, ip, trigger: null, response });
  doc.seq = seq;
  doc.__walSeq = seq;
  doc.recordHash = payload.recordHashOf(doc);
  doc._id = deterministicId(doc.recordHash);
  return doc;
};

beforeAll(async () => {
  if (mongoose.connection.readyState === 0) await mongoose.connect(process.env.MONGODB_URI);
});
afterAll(async () => {
  if (mongoose.connection.readyState !== 0) await mongoose.connection.close();
});

beforeEach(async () => {
  await RealModel.deleteMany({});
  manifest.appendBatch.mockClear();
});

describe('G-6 落库清单锚定：已进库的记录必须进清单', () => {
  test('① 全成功批量：清单必须收到这一批的全部 recordHash（反向对照，缺陷不在时该绿）', async () => {
    const { state, flush } = makeHarness();
    const a = recordFor('203.0.113.21', 'G6-1');
    const b = recordFor('203.0.113.22', 'G6-2');
    state.buffer.push(a, b);

    await flush();

    // 先证明夹具真的落库了（否则下面「清单收到了」可能只是空批的自证）
    expect(await RealModel.countDocuments({})).toBe(2);
    expect(manifest.appendBatch).toHaveBeenCalledTimes(1);
    const sent = manifest.appendBatch.mock.calls[0][0];
    expect(sent.recordHashes.slice().sort()).toEqual([a.recordHash, b.recordHash].sort());
  });

  test('② 整批落库失败：清单不得被调用、这批必须回到缓冲待重试（否则 ① 会退化成「什么都记」）', async () => {
    const { state, flush } = makeHarness();
    // 真模型上打一次「整批 reject」：这是 hardening.test.js:137 覆盖过的语义，这里复述一遍，
    // 目的是给 ① 做反向对照——若 flusher 变成「不管成没成都记清单」，① 仍绿而 ② 会红。
    const spy = jest.spyOn(RealModel, 'insertMany').mockRejectedValueOnce(new Error('db down'));
    const a = recordFor('203.0.113.23', 'G6-3');
    state.buffer.push(a);

    await flush();
    spy.mockRestore();

    expect(await RealModel.countDocuments({})).toBe(0);
    expect(manifest.appendBatch).not.toHaveBeenCalled();
    // 回填：这条必须回到缓冲待重试（不是被丢掉）
    expect(state.buffer.length).toBe(1);
    expect(state.writeFailures).toBe(1);
  });

  test.failing(
    '③ 批内一条撞 _id、另一条新记录 ⇒ 新记录必须进清单（H-3：当前一条都不记，修复后本用例转红）',
    async () => {
      // 现场：WAL 里「已落库但还没裁」的 A 与一条新记录 B 同批重放
      const a = recordFor('203.0.113.24', 'G6-4');
      const b = recordFor('203.0.113.25', 'G6-5');
      await RealModel.insertMany([a], { ordered: false, throwOnValidationError: true });

      const { state, flush } = makeHarness();
      state.buffer.push(a, b); // A 撞 _id，B 是新记录
      await flush();

      // 关键事实一：B 确实进库了（E11000 不阻止同批其它文档）
      expect(await RealModel.countDocuments({ ip: '203.0.113.25' })).toBe(1);
      // 关键事实二：它必须同时出现在清单里。缺陷在场时 appendBatch 一次都不会被调用，
      // 因为 insertMany 整批 reject ⇒ 跳过 appendBatch；而回填集合又是空的（两条都已在库）。
      const sent = manifest.appendBatch.mock.calls.flatMap((c) => c[0].recordHashes);
      expect(sent).toContain(b.recordHash);
    }
  );
});
