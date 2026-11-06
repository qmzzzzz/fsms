/**
 * 取证捕获保留期与启动对账（P2）：TTL 声明 → 物理索引 → 改档/失配处置
 *
 * 被测对象：services/initData/indexes.js 的 reconcileBusinessTtlIndexes（对 ForensicCapture 的自动覆盖，
 * P2 不编辑该文件）+ constants/businessRetention.js 的 resolveTtlIndexPlan。
 *
 * 为什么单开一个库：对账判据是"物理索引与声明不符时修正"，必须能控制集合的初始物理态；
 * 与其它用例共用库时会互相看到对方 autoIndex 建出来的索引，判据变成"看谁先跑"。
 */

const mongoose = require('mongoose');

const DB_NAME = 'zzb_fc_ttl';
const ENV_KEY = 'BUSINESS_RETENTION_DAYS_FORENSIC_CAPTURE';
const THIRTY_DAYS_SECONDS = 30 * 24 * 60 * 60;

describe('ForensicCapture 启动对账（自动覆盖，无需编辑 indexes.js）', () => {
  let ForensicCapture;
  let reconcileBusinessTtlIndexes;

  beforeAll(async () => {
    process.env[ENV_KEY] = '30';
    const base = process.env.MONGODB_URI;
    const [head, query] = base.split('?');
    const uri = head.replace(/\/[^/]*$/, '/' + DB_NAME) + (query ? '?' + query : '');
    await mongoose.connect(uri);
    // 先设 env 再 require：schema 的 TTL 决策在模型加载期固化
    ForensicCapture = require('../../models/ForensicCapture');
    ({ reconcileBusinessTtlIndexes } = require('../../services/initData'));
  });

  afterAll(async () => {
    delete process.env[ENV_KEY];
    // 先等后台建索引落定再拆库：否则 index 事件在用例队列之后才触发，回调里 require logger 会撞上
    // "Jest environment torn down"（实测噪音），摘监听是第二道保险
    await ForensicCapture.init().catch(() => {});
    ForensicCapture.removeAllListeners('index');
    await mongoose.connection
      .collection(ForensicCapture.collection.collectionName)
      .drop()
      .catch(() => {});
    await mongoose.connection.close().catch(() => {});
  });

  const collName = () => ForensicCapture.collection.collectionName;
  const physicalTtl = async () => {
    const idx = await mongoose.connection.collection(collName()).indexes();
    return idx.find((i) => i.name === 'ttl_createdAt');
  };

  test('声明 30 且开关在场：启动对账建出 ttl_createdAt（物理态与声明一致）', async () => {
    await mongoose.connection
      .collection(collName())
      .drop()
      .catch(() => {});
    const summary = await reconcileBusinessTtlIndexes();
    const created = summary.created.find((c) => c.model === 'ForensicCapture');
    expect(created).toMatchObject({
      index: 'ttl_createdAt',
      expireAfterSeconds: THIRTY_DAYS_SECONDS,
    });
    expect(await physicalTtl()).toMatchObject({ expireAfterSeconds: THIRTY_DAYS_SECONDS });
  });

  test('二次对账幂等：已一致的索引不再动（不得反复 collMod）', async () => {
    // 自含前置（--randomize 打乱文件内用例顺序，「上一条建出的索引」不再可靠）：
    // 先落好「声明 30 + 空集合 ⇒ 建索引」的前置态，再验幂等。
    await mongoose.connection
      .collection(collName())
      .drop()
      .catch(() => {});
    process.env[ENV_KEY] = '30';
    await reconcileBusinessTtlIndexes();
    const summary = await reconcileBusinessTtlIndexes();
    expect(summary.created.find((c) => c.model === 'ForensicCapture')).toBeUndefined();
    expect(summary.aligned.find((c) => c.model === 'ForensicCapture')).toBeUndefined();
    expect(await physicalTtl()).toMatchObject({ expireAfterSeconds: THIRTY_DAYS_SECONDS });
  });

  test('开关越界（7 天，低于取证下限 30）⇒ 不建不删，标 orphaned 交人工（TTL 删除不可逆）', async () => {
    // 自含前置：先在声明 30 下把物理索引建出来（orphaned 的分类前提是「物理索引在场
    // 而声明不可执行」），再切 7 天验「不建不删、标 orphaned」。
    await mongoose.connection
      .collection(collName())
      .drop()
      .catch(() => {});
    process.env[ENV_KEY] = '30';
    await reconcileBusinessTtlIndexes();
    expect(await physicalTtl()).toBeTruthy();
    process.env[ENV_KEY] = '7';
    const summary = await reconcileBusinessTtlIndexes();
    const orphan = summary.orphaned.find((o) => o.model === 'ForensicCapture');
    expect(orphan).toMatchObject({
      index: 'ttl_createdAt',
      expireAfterSeconds: THIRTY_DAYS_SECONDS,
    });
    // 物理索引仍原样存在：开关失效不等于允许自动删索引
    expect(await physicalTtl()).toMatchObject({ expireAfterSeconds: THIRTY_DAYS_SECONDS });
    process.env[ENV_KEY] = '30';
  });
});
