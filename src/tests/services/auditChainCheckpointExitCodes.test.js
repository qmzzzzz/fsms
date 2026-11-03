/**
 * 检查点核验的 degraded 档语义与脚本退出码形态（A4）。
 *
 * 服务层：新鲜度臂（checkpoint_stale）归 degraded——ok 仍按 errors 判（degraded 不判红），
 * 但脚本侧据此退 3（0=ok / 1=errors / 2=判据不可用 / 3=degraded），不再 exit 0。
 * 脚本侧用源码读断言钉退出码形态（起 mongoose + 真库跑一遍脚本对单测不划算，
 * 且退出码形态是"源码里写死的字面量"这一事实）。
 */

'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const {
  DEFAULT_FRESHNESS_MS,
  freshnessBudgetMs,
} = require('../../services/auditCheckpointFreshness');
const { createCheckpoint, verifyCheckpoints } = require('../../services/auditChainCheckpoint');

const SECRET = 'checkpoint-exit-test-secret';
const ID1 = '000000000000000000000010';
const ID2 = '000000000000000000000020';

/** 与 auditChainCheckpoint.test.js 同形态的假模型（只实现本模块实际调用的面）。 */
function fakeModel(docs) {
  const state = docs.map((doc) => ({ ...doc }));
  const model = {
    state,
    findOne: jest.fn((query) => {
      let result = null;
      if (query && typeof query.hash === 'string') {
        result = state.find((doc) => doc.hash === query.hash) || null;
      } else if (query && query._id !== undefined) {
        result = state.find((doc) => String(doc._id) === String(query._id)) || null;
      }
      const chain = { sort: () => chain, lean: async () => (result ? { ...result } : null) };
      return chain;
    }),
    find: jest.fn((query) => {
      let rows = state.slice();
      if (query && query.hash && query.hash.$in) {
        rows = rows.filter((doc) => query.hash.$in.includes(doc.hash));
      }
      const api = {
        sort: () => api,
        limit: () => api,
        lean: async () => rows.map((doc) => ({ ...doc })),
      };
      return api;
    }),
    countDocuments: jest.fn(async (query) => {
      if (query && query.hash && query.hash.$ne === null) {
        return state.filter((doc) => doc.hash != null).length;
      }
      return state.length;
    }),
  };
  return model;
}

const hashedDocs = () => [
  { _id: ID1, hash: 'hash-1', hmac: 'hmac-1', prevHash: null },
  { _id: ID2, hash: 'hash-2', hmac: 'hmac-2', prevHash: 'hash-1' },
];

describe('检查点新鲜度臂（degraded 档）', () => {
  let dir;
  let envBackup;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-checkpoint-exit-'));
    envBackup = process.env.CHECKPOINT_FRESHNESS_MS;
    delete process.env.CHECKPOINT_FRESHNESS_MS;
  });

  afterEach(() => {
    if (envBackup === undefined) delete process.env.CHECKPOINT_FRESHNESS_MS;
    else process.env.CHECKPOINT_FRESHNESS_MS = envBackup;
    fs.rmSync(dir, { recursive: true, force: true });
  });

  const filePath = () => path.join(dir, 'checkpoints.jsonl');

  test('新鲜度预算：默认 26h，env 置 0=显式关闭，非法值回退默认', () => {
    expect(DEFAULT_FRESHNESS_MS).toBe(26 * 60 * 60 * 1000);
    expect(freshnessBudgetMs()).toBe(DEFAULT_FRESHNESS_MS);
    process.env.CHECKPOINT_FRESHNESS_MS = '3600000';
    expect(freshnessBudgetMs()).toBe(3600000);
    process.env.CHECKPOINT_FRESHNESS_MS = '0';
    expect(freshnessBudgetMs()).toBe(0);
    process.env.CHECKPOINT_FRESHNESS_MS = '-5';
    expect(freshnessBudgetMs()).toBe(DEFAULT_FRESHNESS_MS);
    process.env.CHECKPOINT_FRESHNESS_MS = 'garbage';
    expect(freshnessBudgetMs()).toBe(DEFAULT_FRESHNESS_MS);
  });

  test('签名全有效但最近检查点超预算 ⇒ ok 仍为 true，degraded 带 checkpoint_stale', async () => {
    const model = fakeModel(hashedDocs());
    const file = filePath();
    const createdAt = new Date('2026-10-01T00:00:00.000Z');
    await createCheckpoint({ model, filePath: file, secret: SECRET, now: createdAt });
    const result = await verifyCheckpoints({
      model,
      filePath: file,
      secret: SECRET,
      now: new Date(createdAt.getTime() + DEFAULT_FRESHNESS_MS + 60000),
    });
    expect(result.ok).toBe(true);
    expect(result.errors).toEqual([]);
    expect(result.degraded).toHaveLength(1);
    expect(result.degraded[0]).toMatchObject({ type: 'checkpoint_stale' });
  });

  test('预算内 ⇒ 无 degraded 键（安静系统不得凭空多说话）', async () => {
    const model = fakeModel(hashedDocs());
    const file = filePath();
    const createdAt = new Date('2026-10-01T00:00:00.000Z');
    await createCheckpoint({ model, filePath: file, secret: SECRET, now: createdAt });
    const result = await verifyCheckpoints({
      model,
      filePath: file,
      secret: SECRET,
      now: new Date(createdAt.getTime() + DEFAULT_FRESHNESS_MS - 60000),
    });
    expect(result.ok).toBe(true);
    expect(result.degraded).toBeUndefined();
  });

  test('env 置 0 显式关闭新鲜度（首次部署未排 cron 的豁免口）⇒ 超龄也不 degraded', async () => {
    process.env.CHECKPOINT_FRESHNESS_MS = '0';
    const model = fakeModel(hashedDocs());
    const file = filePath();
    const createdAt = new Date('2020-01-01T00:00:00.000Z');
    await createCheckpoint({ model, filePath: file, secret: SECRET, now: createdAt });
    const result = await verifyCheckpoints({
      model,
      filePath: file,
      secret: SECRET,
      now: new Date('2026-11-01T00:00:00.000Z'),
    });
    expect(result.ok).toBe(true);
    expect(result.degraded).toBeUndefined();
  });

  test('边界：无任何检查点走 no_checkpoints 判红臂，不得因新鲜度重复报 degraded', async () => {
    const model = fakeModel(hashedDocs());
    const result = await verifyCheckpoints({
      model,
      filePath: filePath(), // 文件不存在 ⇒ entries 为空
      secret: SECRET,
    });
    expect(result.ok).toBe(false);
    expect(result.errors).toEqual([expect.objectContaining({ type: 'no_checkpoints' })]);
    expect(result.degraded).toBeUndefined();
  });

  test('degraded 不与判红混档：errors 非空时 ok=false，degraded 仍并列可见', async () => {
    const model = fakeModel(hashedDocs());
    const file = filePath();
    const createdAt = new Date('2020-01-01T00:00:00.000Z');
    await createCheckpoint({ model, filePath: file, secret: SECRET, now: createdAt });
    // 篡改头部 hash ⇒ head_hash_mismatch 判红；同时检查点早已超龄 ⇒ 两条并存
    const doc = JSON.parse(fs.readFileSync(file, 'utf8').trim());
    doc.headHash = 'tampered';
    doc.signature = undefined;
    fs.writeFileSync(file, `${JSON.stringify(doc)}\n`);
    const result = await verifyCheckpoints({
      model,
      filePath: file,
      secret: SECRET,
      now: new Date('2026-11-01T00:00:00.000Z'),
    });
    expect(result.ok).toBe(false);
    expect(result.errors).toEqual([expect.objectContaining({ type: 'signature_invalid' })]);
    // 签名坏的那行不参与后续比对（含新鲜度），新鲜度看的是最后一个有效检查点 ⇒ 此处无
    expect(result.degraded).toBeUndefined();
  });
});

describe('audit-chain-checkpoint 脚本退出码形态（源码读断言）', () => {
  const scriptPath = path.resolve(
    __dirname,
    '..',
    '..',
    '..',
    'scripts',
    'audit-chain-checkpoint.js'
  );

  test('degraded ⇒ stderr 打 VERDICT: DEGRADED 并 return 3；0/1/2 档注释与实现同在', () => {
    const src = fs.readFileSync(scriptPath, 'utf8');
    expect(src).toMatch(/VERDICT: DEGRADED — /);
    expect(src).toMatch(/return 3;/);
    expect(src).toMatch(/3 = degraded/);
    expect(src).toMatch(/2 = 判据不可用/);
    // 判红优先于降级：errors 先检查
    expect(src.indexOf('!result.ok')).toBeGreaterThan(-1);
    expect(src.indexOf('result.degraded')).toBeGreaterThan(src.indexOf('!result.ok'));
    // PASS 文案不再声称"计数一致"（recordCount 仅创建估算、不参与判红）
    expect(src).not.toMatch(/链头与计数一致/);
    expect(src).toMatch(/recordCount 仅创建时的/);
  });

  test('--file 相对路径按仓库根解析（脚本内不再引用 process.cwd）', () => {
    const src = fs.readFileSync(scriptPath, 'utf8');
    expect(src).toMatch(/const REPO_ROOT = path\.resolve\(__dirname, '\.\.'\)/);
    expect(src).not.toMatch(/process\.cwd\(/);
  });

  test('新鲜度 env 名与默认值口径在脚本注释与判据模块一致', () => {
    const src = fs.readFileSync(scriptPath, 'utf8');
    expect(src).toMatch(/CHECKPOINT_FRESHNESS_MS/);
    const freshness = fs.readFileSync(
      path.resolve(__dirname, '..', '..', 'services', 'auditCheckpointFreshness.js'),
      'utf8'
    );
    expect(freshness).toMatch(/CHECKPOINT_FRESHNESS_MS/);
    expect(DEFAULT_FRESHNESS_MS).toBe(26 * 60 * 60 * 1000); // 2×13h cron 间隔上限
  });
});
