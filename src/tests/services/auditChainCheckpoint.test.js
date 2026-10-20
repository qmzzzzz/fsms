/**
 * 审计链签名检查点：创建 / 读取 / 核验的检出能力
 *
 * 这些用例逐条对应模块头注释承诺的检出面：签名被改、链头被换、锚点前插入
 * （计数变化）、尾部截断（含整体删空），以及无密钥时拒绝造锚点。所用的假模型
 * 只实现本模块实际调用的 findOne().sort().lean() 与 countDocuments()，
 * 不把「Mongo 行为」当作被测对象。
 */

'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const config = require('../../config');
const {
  CHECKPOINT_VERSION,
  createCheckpoint,
  readCheckpoints,
  signCheckpoint,
  verifyCheckpoints,
} = require('../../services/auditChainCheckpoint');

const SECRET = 'checkpoint-test-secret';
const ID1 = '000000000000000000000010';
const ID_BRANCH = '000000000000000000000015';
const ID2 = '000000000000000000000020';
const ID3 = '000000000000000000000030';

/**
 * 假 AuditLog：docs 按 _id 升序存放，findOne 支持两种查询——
 * 取最新哈希记录（createCheckpoint）与按 _id 取头（verifyCheckpoints）。
 */
function fakeModel(docs) {
  const state = docs.map((doc) => ({ ...doc }));
  const resultOf = (query) => {
    if (query.hash && query.hash.$ne === null) {
      const hashed = state.filter((doc) => doc.hash != null);
      return hashed.length ? { ...hashed[hashed.length - 1] } : null;
    }
    if (query._id !== undefined) {
      const hit = state.find((doc) => String(doc._id) === String(query._id));
      return hit ? { ...hit } : null;
    }
    return null;
  };
  const model = {
    state,
    findOne: jest.fn((query) => {
      const result = resultOf(query);
      const chain = { sort: () => chain, lean: async () => result };
      return chain;
    }),
    countDocuments: jest.fn(async (query) => {
      if (query && query._id && query._id.$lte !== undefined) {
        return state.filter((doc) => String(doc._id) <= String(query._id.$lte)).length;
      }
      return state.length;
    }),
  };
  return model;
}

const hashedDocs = () => [
  { _id: ID1, hash: 'hash-1', hmac: 'hmac-1' },
  { _id: ID2, hash: 'hash-2', hmac: 'hmac-2' },
];

describe('auditChainCheckpoint', () => {
  let dir;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-checkpoint-'));
  });

  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  const filePath = () => path.join(dir, 'nested', 'checkpoints.jsonl');

  test('创建检查点会固化为签名记录，并可原样通过核验', async () => {
    const model = fakeModel(hashedDocs());
    const now = new Date('2026-10-20T00:00:00.000Z');

    const { record, filePath: written } = await createCheckpoint({
      model,
      filePath: filePath(),
      secret: SECRET,
      now,
    });

    expect(written).toBe(filePath());
    expect(record).toMatchObject({
      version: CHECKPOINT_VERSION,
      createdAt: now.toISOString(),
      headId: ID2,
      headHash: 'hash-2',
      headHmac: 'hmac-2',
      recordCount: 2,
    });
    expect(record.signature).toMatch(/^[0-9a-f]{64}$/);
    expect(record.signature).toBe(signCheckpoint(record, SECRET));

    const entries = readCheckpoints(filePath());
    expect(entries).toHaveLength(1);
    expect(entries[0].record).toEqual(record);

    await expect(
      verifyCheckpoints({ model, filePath: filePath(), secret: SECRET })
    ).resolves.toEqual({
      ok: true,
      checked: 1,
      errors: [],
    });
  });

  test('锚点之后追加正常记录不算篡改（链尾晚于检查点）', async () => {
    const model = fakeModel(hashedDocs());
    await createCheckpoint({ model, filePath: filePath(), secret: SECRET });
    model.state.push({ _id: ID3, hash: 'hash-3', hmac: 'hmac-3' });

    const result = await verifyCheckpoints({ model, filePath: filePath(), secret: SECRET });
    expect(result).toEqual({ ok: true, checked: 1, errors: [] });
  });

  test('空库检查点（headId=null）可以创建并通过核验', async () => {
    const model = fakeModel([]);
    const { record } = await createCheckpoint({ model, filePath: filePath(), secret: SECRET });
    expect(record).toMatchObject({ headId: null, headHash: null, recordCount: 0 });

    const result = await verifyCheckpoints({ model, filePath: filePath(), secret: SECRET });
    expect(result.ok).toBe(true);
  });

  test('检查点文件被改写 ⇒ signature_invalid', async () => {
    const model = fakeModel(hashedDocs());
    await createCheckpoint({ model, filePath: filePath(), secret: SECRET });

    const line = JSON.parse(fs.readFileSync(filePath(), 'utf8').trim());
    line.recordCount = 1; // 把锚点计数改小，试图掩盖插入
    fs.writeFileSync(filePath(), `${JSON.stringify(line)}\n`);

    const result = await verifyCheckpoints({ model, filePath: filePath(), secret: SECRET });
    expect(result.ok).toBe(false);
    expect(result.errors).toEqual([
      expect.objectContaining({ line: 1, type: 'signature_invalid' }),
    ]);
  });

  test('锚点之前插入分支记录 ⇒ count_mismatch', async () => {
    const model = fakeModel(hashedDocs());
    await createCheckpoint({ model, filePath: filePath(), secret: SECRET });

    // prevHash 指向链内已有 hash 的分支记录：链内校验会放过，计数不会
    model.state.splice(1, 0, { _id: ID_BRANCH, hash: 'branch', hmac: 'branch' });

    const result = await verifyCheckpoints({ model, filePath: filePath(), secret: SECRET });
    expect(result.ok).toBe(false);
    expect(result.errors).toEqual([expect.objectContaining({ type: 'count_mismatch' })]);
  });

  test('检查点头部被替换 ⇒ head_hash_mismatch / head_hmac_mismatch', async () => {
    const model = fakeModel(hashedDocs());
    await createCheckpoint({ model, filePath: filePath(), secret: SECRET });

    Object.assign(model.state[1], { hash: 'rewritten', hmac: 'rewritten' });

    const result = await verifyCheckpoints({ model, filePath: filePath(), secret: SECRET });
    expect(result.ok).toBe(false);
    expect(result.errors.map((e) => e.type)).toEqual(
      expect.arrayContaining(['head_hash_mismatch', 'head_hmac_mismatch'])
    );
  });

  test('把链截断到锚点之前 ⇒ head_missing + count_mismatch + tail_rolled_back', async () => {
    const model = fakeModel(hashedDocs());
    await createCheckpoint({ model, filePath: filePath(), secret: SECRET });

    model.state.splice(1, 1); // 删掉锚点那条，链尾退回到锚点之前

    const result = await verifyCheckpoints({ model, filePath: filePath(), secret: SECRET });
    expect(result.ok).toBe(false);
    expect(result.errors.map((e) => e.type)).toEqual(
      expect.arrayContaining(['head_missing', 'count_mismatch', 'tail_rolled_back'])
    );
  });

  test('整表哈希记录被删空 ⇒ tail_rolled_back（不能因 tail 为空而跳过）', async () => {
    const model = fakeModel(hashedDocs());
    await createCheckpoint({ model, filePath: filePath(), secret: SECRET });

    model.state.length = 0;

    const result = await verifyCheckpoints({ model, filePath: filePath(), secret: SECRET });
    expect(result.ok).toBe(false);
    expect(result.errors).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ type: 'head_missing' }),
        expect.objectContaining({ type: 'tail_rolled_back' }),
      ])
    );
  });

  test('检查点时间/头部 _id 倒退 ⇒ order_violation', async () => {
    const model = fakeModel(hashedDocs());
    const file = filePath();
    await createCheckpoint({
      model,
      filePath: file,
      secret: SECRET,
      now: new Date('2026-10-20T12:00:00.000Z'),
    });
    const second = {
      version: CHECKPOINT_VERSION,
      createdAt: '2026-10-20T11:00:00.000Z',
      headId: ID1,
      headHash: 'hash-1',
      headHmac: 'hmac-1',
      recordCount: 1,
    };
    second.signature = signCheckpoint(second, SECRET);
    fs.appendFileSync(file, `${JSON.stringify(second)}\n`);

    const result = await verifyCheckpoints({ model, filePath: file, secret: SECRET });
    expect(result.ok).toBe(false);
    expect(result.errors.filter((e) => e.type === 'order_violation')).toHaveLength(2);
  });

  test('无 HMAC_SECRET 时拒绝创建检查点', async () => {
    const original = config.hmacSecret;
    config.hmacSecret = '';
    try {
      await expect(
        createCheckpoint({ model: fakeModel(hashedDocs()), filePath: filePath(), secret: '' })
      ).rejects.toMatchObject({ code: 'AUDIT_CHECKPOINT_HMAC_REQUIRED' });
      expect(fs.existsSync(filePath())).toBe(false);
    } finally {
      config.hmacSecret = original;
    }
  });

  test('无 HMAC_SECRET 时核验判 hmac_not_configured，不得当作通过', async () => {
    const original = config.hmacSecret;
    config.hmacSecret = '';
    try {
      const result = await verifyCheckpoints({
        model: fakeModel([]),
        filePath: filePath(),
        secret: '',
      });
      expect(result).toEqual({
        ok: false,
        checked: 0,
        errors: [expect.objectContaining({ type: 'hmac_not_configured' })],
      });
    } finally {
      config.hmacSecret = original;
    }
  });

  test('没有检查点文件 ⇒ no_checkpoints（不是静默通过）', async () => {
    const result = await verifyCheckpoints({
      model: fakeModel(hashedDocs()),
      filePath: filePath(),
      secret: SECRET,
    });
    expect(result).toEqual({
      ok: false,
      checked: 0,
      errors: [expect.objectContaining({ type: 'no_checkpoints' })],
    });
  });

  test('坏行不会被跳过 ⇒ file_unreadable', async () => {
    fs.mkdirSync(path.dirname(filePath()), { recursive: true });
    fs.writeFileSync(filePath(), '{not json}\n');

    const result = await verifyCheckpoints({
      model: fakeModel(hashedDocs()),
      filePath: filePath(),
      secret: SECRET,
    });
    expect(result).toEqual({
      ok: false,
      checked: 0,
      errors: [expect.objectContaining({ type: 'file_unreadable' })],
    });
  });

  test('不支持的版本 ⇒ version_unsupported', async () => {
    const file = filePath();
    fs.mkdirSync(path.dirname(file), { recursive: true });
    const record = {
      version: 999,
      createdAt: new Date().toISOString(),
      headId: null,
      headHash: null,
      headHmac: null,
      recordCount: 0,
    };
    record.signature = signCheckpoint(record, SECRET);
    fs.writeFileSync(file, `${JSON.stringify(record)}\n`);

    const result = await verifyCheckpoints({
      model: fakeModel([]),
      filePath: file,
      secret: SECRET,
    });
    expect(result.ok).toBe(false);
    expect(result.errors).toEqual([expect.objectContaining({ type: 'version_unsupported' })]);
  });
});

describe('audit-chain-checkpoint CLI 参数', () => {
  const { parseArgs, resolveCheckpointFile } = require('../../../scripts/audit-chain-checkpoint');

  test('create / verify 与 --file=路径', () => {
    expect(parseArgs(['create'])).toEqual({ command: 'create', filePath: undefined });
    expect(parseArgs(['verify', '--file=logs/x.jsonl'])).toEqual({
      command: 'verify',
      filePath: 'logs/x.jsonl',
    });
    expect(resolveCheckpointFile('logs/x.jsonl')).toBe(path.resolve(process.cwd(), 'logs/x.jsonl'));
  });

  test('缺子命令、未知子命令、未知参数一律报错（含试图用命令行传密钥）', () => {
    expect(() => parseArgs([])).toThrow(/缺少子命令/);
    expect(() => parseArgs(['createe'])).toThrow(/未知子命令/);
    expect(() => parseArgs(['create', '--secret=x'])).toThrow(/无法识别的参数/);
    expect(() => parseArgs(['create', '--file='])).toThrow(/无法识别的参数/);
    expect(() => parseArgs(['verify', 'extra'])).toThrow(/无法识别的参数/);
  });
});
