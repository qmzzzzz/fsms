/**
 * D1 的现场：_id 序 ≠ 追加序（真实 auditBuffer.push 预分配路径，非手工造文档）
 *
 * 为什么必须用真路径而不是手工造 doc：F-143 之后 `_id` 在 **push 时**就分配并写进 WAL 行
 * （src/services/auditBuffer.js assignDocId），于是"先 push、后落库"的批次天然带着更小的
 * _id 排在链的更后面。手工造 doc 只能证明"这种形状会红"，证明不了"这种形状是诚实产生的"。
 *
 * 本文件复现的诚实时序（WAL 重放，跨重启的常规路径）：
 *   t0  push(A)          ⇒ A._id 最小，WAL 有行，未落库
 *   t1  进程重启         ⇒ 缓冲丢失（__resetForTest），WAL 行仍在
 *   t2  push(B) push(C)  ⇒ 落库并串链 B → C，_id 都比 A 大
 *   t3  WAL 重放 A       ⇒ A 连到 C 之后成为**真链尾**，但 _id 仍是三者最小
 * 结果：_id 升序是 A,B,C，追加序是 B,C,A。任何"取最大 _id 当链尾"的判据都会把 C 当尾。
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const mongoose = require('mongoose');

// 必须在 require auditBuffer 之前设：WAL 路径在模块加载期读 env
const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'probe-d1-real-'));
process.env.AUDIT_WAL_PATH = path.join(tmpDir, 'd1.wal');

const auditBuffer = require('../../services/auditBuffer');
const wal = require('../../services/auditBufferWal');
const AuditLog = require('../../models/AuditLog');
const {
  createCheckpoint,
  verifyCheckpoints,
  signCheckpoint,
  CHECKPOINT_VERSION,
} = require('../../services/auditChainCheckpoint');

const SECRET = 'd1-real-tail-secret';
const TAG = 'zd1tail';

const doc = (n) => ({
  action: 'device_export',
  category: 'system',
  username: `${TAG}_${n}`,
  ip: '10.1.2.3',
  method: 'GET',
  path: '/api/devices/export',
  success: true,
  riskLevel: 'low',
});

const byId = (a, b) => String(a._id).localeCompare(String(b._id));

describe('审计链检查点 × _id 乱序的诚实库（真实 push 预分配）', () => {
  let dir;

  beforeAll(async () => {
    mongoose.set('strictQuery', false);
    if (mongoose.connection.readyState === 0) await mongoose.connect(process.env.MONGODB_URI);
    auditBuffer.stop();
    auditBuffer.start();
    auditBuffer.stop();
    // 只重新开启 WAL 写入口（start() 会带定时器；这里要的是"push 即落行"这一半）：
    // 关定时器后 walEnabled=false，push 就不会写行，WAL 重放这条真实路径也就造不出来。
    wal.startup(process.env.AUDIT_WAL_PATH);
  });

  beforeEach(async () => {
    auditBuffer.__resetForTest();
    await cleanup();
    try {
      fs.writeFileSync(auditBuffer.getWalPath(), '');
    } catch (_) {
      /* 文件尚不存在 */
    }
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'd1-checkpoint-'));
  });

  afterEach(async () => {
    await cleanup();
    fs.rmSync(dir, { recursive: true, force: true });
  });

  afterAll(async () => {
    auditBuffer.stop();
    auditBuffer.__resetForTest();
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch (_) {
      /* 尽力清理 */
    }
    if (mongoose.connection.readyState !== 0) await mongoose.connection.close();
  });

  async function cleanup() {
    try {
      await AuditLog.deleteMany({ username: new RegExp(`^${TAG}_`) }, { bypassAppendOnly: true });
    } catch (_) {
      /* 库未连接时忽略 */
    }
  }

  /** 真实 push 造出 _id 乱序的诚实库，返回 { tail, maxIdDoc } */
  async function buildDisorderedHonestChain() {
    auditBuffer.push(doc('late1')); // t0：_id 在这里就被定下（最小两个），WAL 行落盘，不 flush
    auditBuffer.push(doc('late2'));
    await wal.drain(); // 行是异步 appendFile：不等它排空，读文件会读不到（实测空串）
    const walLines = fs.readFileSync(auditBuffer.getWalPath(), 'utf8').split('\n');
    const lateLine = walLines.find((line) => line.includes(`${TAG}_late1`));
    const lateLine2 = walLines.find((line) => line.includes(`${TAG}_late2`));
    expect(lateLine).toBeTruthy();
    expect(lateLine2).toBeTruthy();
    auditBuffer.__resetForTest(); // t1：模拟重启，内存缓冲丢失，WAL 行留下

    auditBuffer.push(doc('b'));
    auditBuffer.push(doc('c'));
    await auditBuffer.flush(); // t2：B → C 串链落库

    auditBuffer.push(JSON.parse(lateLine), true); // t3：WAL 重放，沿用原 _id
    await auditBuffer.flush();

    const rows = await AuditLog.find({ username: new RegExp(`^${TAG}_`) }).lean();
    expect(rows).toHaveLength(3);
    const parentHashes = new Set(rows.map((r) => r.prevHash).filter(Boolean));
    const tails = rows.filter((r) => !parentHashes.has(r.hash));
    expect(tails).toHaveLength(1); // 链自洽：只有一个没有子记录的尾
    const maxId = rows.slice().sort(byId).at(-1);
    return { rows, tail: tails[0], maxId, lateLine2 };
  }

  test('createCheckpoint 必须钉住真链尾：_id 最小的那条才是尾', async () => {
    const { tail, maxId } = await buildDisorderedHonestChain();
    // 前提自证：这个库确实是 _id 乱序的诚实库（尾不是最大 _id）
    expect(String(tail._id)).not.toBe(String(maxId._id));

    const { record } = await createCheckpoint({
      model: AuditLog,
      filePath: path.join(dir, 'cp.jsonl'),
      secret: SECRET,
    });
    expect(record.headId).toBe(String(tail._id));
    expect(record.headHash).toBe(tail.hash);
  });

  test('诚实乱序库核验必须全绿（旧判据在这里会误报）', async () => {
    await buildDisorderedHonestChain();
    const file = path.join(dir, 'cp.jsonl');
    await createCheckpoint({ model: AuditLog, filePath: file, secret: SECRET });
    const result = await verifyCheckpoints({ model: AuditLog, filePath: file, secret: SECRET });
    expect(result.ok).toBe(true);
    expect(result.errors).toEqual([]);
    expect(result.checked).toBe(1);
  });

  test('检查点之后诚实追加（_id 更小）⇒ 不得误报 count_mismatch', async () => {
    // TTL 裁剪与迟到批写（push 预分配）会同时动「计数」：把计数当篡改判据，
    // 在诚实库上必误报。这里让检查点之后真的再落一条 _id 更小的记录。
    const { lateLine2 } = await buildDisorderedHonestChain();
    const file = path.join(dir, 'cp.jsonl');
    await createCheckpoint({ model: AuditLog, filePath: file, secret: SECRET });

    auditBuffer.push(JSON.parse(lateLine2), true); // 真尾部续链，_id 比锚点小
    await auditBuffer.flush();

    const result = await verifyCheckpoints({ model: AuditLog, filePath: file, secret: SECRET });
    expect(result.ok).toBe(true);
    expect(result.errors).toEqual([]);
  });

  test('检查点钉的是真链尾（_id 最小）⇒ 旧判据会假红 tail_rolled_back，这里必须绿', async () => {
    // 升级/双端不一致的现场：checkpoint 的 headId 是**真链尾**（_id 最小那条），
    // 而库里 _id 最大的那条仍在链中间。只按 _id 取尾的核验会把它当"当前链尾"，
    // 于是 String(tail._id) > String(headId) 之外的比较把诚实库判成回滚。
    const { tail } = await buildDisorderedHonestChain();
    const file = path.join(dir, 'cp.jsonl');
    const record = {
      version: CHECKPOINT_VERSION,
      createdAt: new Date().toISOString(),
      headId: String(tail._id),
      headHash: tail.hash,
      headHmac: tail.hmac || null,
      recordCount: 3,
    };
    record.signature = signCheckpoint(record, SECRET);
    fs.writeFileSync(file, `${JSON.stringify(record)}\n`);

    const result = await verifyCheckpoints({ model: AuditLog, filePath: file, secret: SECRET });
    expect(result.errors.map((e) => e.type)).not.toContain('tail_rolled_back');
    expect(result.ok).toBe(true);
  });

  test('反向：真的删掉真链尾 ⇒ tail_rolled_back（判据不只会在诚实库上误报）', async () => {
    const { tail } = await buildDisorderedHonestChain();
    const file = path.join(dir, 'cp.jsonl');
    await createCheckpoint({ model: AuditLog, filePath: file, secret: SECRET });

    await AuditLog.deleteOne({ _id: tail._id }, { bypassAppendOnly: true });

    const result = await verifyCheckpoints({ model: AuditLog, filePath: file, secret: SECRET });
    expect(result.ok).toBe(false);
    expect(result.errors.map((e) => e.type)).toEqual(
      expect.arrayContaining(['head_missing', 'tail_rolled_back'])
    );
  });
});
