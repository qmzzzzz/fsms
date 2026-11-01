/**
 * reconcileBusinessTtlIndexes 的边缘分支：indexes() 非 26 错误、NamespaceNotFound
 * 静默跳过、物理索引缺 expireAfterSeconds 时的「（未设置）」对齐日志。
 * 此前这些臂从未被计数（branches 91.3% < 95%）。刻意用独立数据库，不 require
 * 业务模型之外的初始化，避免 autoIndex 抢先把 TTL 索引建出来。
 */
const mongoose = require('mongoose');
const { reconcileBusinessTtlIndexes } = require('../../services/initData');
const logger = require('../../utils/logger');

const DB_NAME = 'zzb_bttl_edges';

const ENV_KEYS = [
  'BUSINESS_RETENTION_DAYS_FIRE_ALARM',
  'BUSINESS_RETENTION_DAYS_INSPECTION',
  'BUSINESS_RETENTION_DAYS_FIRE_DEVICE',
];

describe('业务集合 TTL 对账的边缘分支', () => {
  const saved = {};
  beforeAll(async () => {
    for (const k of ENV_KEYS) saved[k] = process.env[k];
    const base = process.env.MONGODB_URI;
    const [head, query] = base.split('?');
    const uri = head.replace(/\/[^/]*$/, '/' + DB_NAME) + (query ? '?' + query : '');
    await mongoose.connect(uri);
    require('../../models/FireAlarm');
    require('../../models/FireDevice');
    require('../../models/Inspection');
  });

  afterEach(() => {
    jest.restoreAllMocks();
    for (const k of ENV_KEYS) delete process.env[k];
  });

  afterAll(async () => {
    for (const name of ['firealarms', 'inspections', 'firedevices']) {
      await mongoose.connection
        .collection(name)
        .drop()
        .catch(() => {});
    }
    for (const k of ENV_KEYS) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
    await mongoose.connection.close().catch(() => {});
  });

  const alarmCollName = () => mongoose.model('FireAlarm').collection.collectionName;

  test('indexes() 抛非 NamespaceNotFound 错误：记 skipped 并告警，不抛出', async () => {
    const orig = mongoose.connection.collection.bind(mongoose.connection);
    const spy = jest.spyOn(mongoose.connection, 'collection').mockImplementation((name) => {
      if (name === alarmCollName()) {
        return {
          collectionName: name,
          indexes: async () => {
            const e = new Error('模拟权限不足');
            e.code = 13;
            throw e;
          },
        };
      }
      return orig(name);
    });
    const summary = await reconcileBusinessTtlIndexes();
    spy.mockRestore();
    expect(
      summary.skipped.some((s) => s.model === 'FireAlarm' && /模拟权限不足/.test(s.reason))
    ).toBe(true);
  });

  test('indexes() 抛 NamespaceNotFound：视为索引不存在，静默进入下一步', async () => {
    const orig = mongoose.connection.collection.bind(mongoose.connection);
    const spy = jest.spyOn(mongoose.connection, 'collection').mockImplementation((name) => {
      if (name === alarmCollName()) {
        return {
          collectionName: name,
          indexes: async () => {
            const e = new Error('ns does not exist');
            e.codeName = 'NamespaceNotFound';
            e.code = 26;
            throw e;
          },
        };
      }
      return orig(name);
    });
    const summary = await reconcileBusinessTtlIndexes();
    spy.mockRestore();
    expect(summary.skipped.some((s) => s.model === 'FireAlarm')).toBe(false);
  });

  test('物理索引存在但没带 expireAfterSeconds：对齐日志记「（未设置）」并发 collMod', async () => {
    process.env.BUSINESS_RETENTION_DAYS_FIRE_ALARM = '180';
    const name = alarmCollName();
    await mongoose.connection.db.createCollection(name).catch((e) => {
      if (e.codeName === 'NamespaceExists' || e.code === 48) return;
      throw e;
    });
    const coll = mongoose.connection.collection(name);
    const existing = (await coll.indexes()).find((i) => i.name === 'ttl_occurredAt');
    if (existing) await coll.dropIndex('ttl_occurredAt');
    await coll.createIndex({ occurredAt: 1 }, { name: 'ttl_occurredAt' });
    const commandSpy = jest.spyOn(mongoose.connection.db, 'command').mockResolvedValue({ ok: 1 });
    const warnSpy = jest.spyOn(logger, 'warn').mockImplementation(() => {});
    const summary = await reconcileBusinessTtlIndexes();
    expect(
      summary.aligned.some((a) => a.model === 'FireAlarm' && a.index === 'ttl_occurredAt')
    ).toBe(true);
    expect(warnSpy).toHaveBeenCalled();
    const text = warnSpy.mock.calls.map((c) => c.join(' ')).join('\n');
    expect(text).toContain('（未设置）');
    expect(commandSpy).toHaveBeenCalled();
  });
});
