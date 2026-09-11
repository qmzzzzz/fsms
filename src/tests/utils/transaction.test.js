/**
 * withTransaction 拓扑感知事务封装（第二轮审计 F-6 / B-1 基础设施）
 *
 * 测试环境为 mongodb-memory-server standalone（拓扑类型 Single），覆盖
 * 「确定性降级」路径：不开 session、fn 收到 null、告警一次、写入真实落库。
 * 副本集事务路径无法在单机内存库验证，由部署检查兜底（生产副本集上
 * topology.description.type 为 ReplicaSetWithPrimary，走 session 事务分支）。
 */

const mongoose = require('mongoose');
const { withTransaction, _resetForTests } = require('../../utils/transaction');

describe('withTransaction（拓扑感知事务封装）', () => {
  let User;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  beforeEach(() => {
    _resetForTests();
  });

  test('standalone 拓扑：fn 收到 null session，结果返回且写入真实落库', async () => {
    const startSession = jest.spyOn(mongoose, 'startSession');
    const marker = `txn_probe_${Date.now()}`;
    try {
      const result = await withTransaction(async (session) => {
        expect(session).toBeNull();
        const doc = {
          username: marker,
          email: `${marker}@test.local`,
          password: 'Txn1#probe2026x',
        };
        // mongoose 的 create(doc, {}) 会把空 options 误解析为第二个文档：
        // 无 session 时只传文档本体
        if (session) await User.create([doc], { session });
        else await User.create(doc);
        return 'done';
      });
      expect(result).toBe('done');
      // 降级路径根本不应创建 session
      expect(startSession).not.toHaveBeenCalled();
    } finally {
      startSession.mockRestore();
    }

    const found = await User.findOne({ username: marker });
    expect(found).toBeTruthy();
    await User.deleteOne({ _id: found._id });
  });

  test('降级告警只发一次（避免刷日志），_resetForTests 后可再次告警', async () => {
    const logger = require('../../utils/logger');
    const warnSpy = jest.spyOn(logger, 'warn').mockImplementation(() => {});
    try {
      await withTransaction(async () => {});
      await withTransaction(async () => {});
      expect(warnSpy).toHaveBeenCalledTimes(1);
      expect(warnSpy.mock.calls[0][0]).toContain('降级为顺序写');

      _resetForTests();
      await withTransaction(async () => {});
      expect(warnSpy).toHaveBeenCalledTimes(2);
    } finally {
      warnSpy.mockRestore();
    }
  });

  test('业务错误原样上抛，不被降级逻辑吞掉', async () => {
    const boom = new Error('业务失败');
    await expect(
      withTransaction(async () => {
        throw boom;
      })
    ).rejects.toBe(boom);
  });
});
