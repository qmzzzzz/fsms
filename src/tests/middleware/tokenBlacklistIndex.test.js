/**
 * P1-1 回归：refresh 轮换不得因遗留唯一索引被误判为「重放」
 *
 * 背景（实测事故）：tokenblacklists 集合残留旧 schema 的 `token_1` 唯一索引
 * （旧版本存明文 token，改为 tokenHash 后索引未删）。新文档一律不含 token 字段，
 * 于是 token=null 在唯一索引上从第二条起必然 E11000。consumeToken 原先把任意
 * E11000 都当作「同一 refresh token 被二次使用」，于是每次刷新都触发
 * invalidateUserTokens → tokenVersion 递增 + 写 passwordChangedAt，
 * 用户会话被永久吊销并收到「密码已修改」的误导提示。
 *
 * 本套件用纯 mock 断言两道防线，避免在共享的内存数据库上真造遗留索引
 * （那会让并行执行的其它套件的黑名单写入随机失败）：
 * 1. consumeToken/blacklistToken 按 err.keyPattern 区分 E11000 来源
 * 2. reconcileTokenBlacklistIndexes 只删「单键 token」索引，不误伤其它索引
 */

const mongoose = require('mongoose');

jest.mock('../../models/TokenBlacklist', () => ({
  create: jest.fn(),
  findOneAndUpdate: jest.fn(),
  findOne: jest.fn(),
}));

jest.mock('../../utils/logger', () => ({
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
  debug: jest.fn(),
}));

const TokenBlacklistModel = require('../../models/TokenBlacklist');
const logger = require('../../utils/logger');
const { consumeToken, blacklistToken } = require('../../middleware/tokenBlacklist');

/** 构造 Mongo 唯一键冲突错误 */
const dupKeyError = (keyPattern, indexName) => {
  const err = new Error(
    `E11000 duplicate key error collection: test.tokenblacklists index: ${indexName}`
  );
  err.code = 11000;
  if (keyPattern) err.keyPattern = keyPattern;
  err.index = indexName;
  return err;
};

const futureExpSec = () => Math.floor(Date.now() / 1000) + 3600;

describe('P1-1 refresh 轮换：E11000 来源区分', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('consumeToken', () => {
    test('插入成功即取得令牌所有权（返回 true）', async () => {
      TokenBlacklistModel.create.mockResolvedValueOnce({});
      await expect(consumeToken('rt-fresh', futureExpSec())).resolves.toBe(true);

      // 落库的是哈希而非明文，且标记 reason=rotate 以区分登出
      const doc = TokenBlacklistModel.create.mock.calls[0][0];
      expect(doc.tokenHash).toMatch(/^[a-f0-9]{64}$/);
      expect(doc.tokenHash).not.toContain('rt-fresh');
      expect(doc.reason).toBe('rotate');
    });

    test('tokenHash 冲突判定为真实重放（返回 false）', async () => {
      TokenBlacklistModel.create.mockRejectedValueOnce(
        dupKeyError({ tokenHash: 1 }, 'tokenHash_1')
      );
      await expect(consumeToken('rt-replayed', futureExpSec())).resolves.toBe(false);
    });

    test('遗留 token_1 冲突抛 BLACKLIST_INDEX_CONFLICT，绝不降级为重放', async () => {
      TokenBlacklistModel.create.mockRejectedValueOnce(dupKeyError({ token: 1 }, 'token_1'));

      // 关键断言：必须抛错。若返回 false，调用方会走重放处置吊销全部会话
      await expect(consumeToken('rt-legacy-index', futureExpSec())).rejects.toMatchObject({
        code: 'BLACKLIST_INDEX_CONFLICT',
      });

      // 运维可观测性：错误日志须指向修复脚本
      const msg = logger.error.mock.calls.map((c) => c[0]).join('\n');
      expect(msg).toContain('token_1');
      expect(msg).toContain('fix-token-blacklist-index');
    });

    test('keyPattern 缺失的 E11000 同样按基础设施异常抛错（不猜测来源）', async () => {
      const err = dupKeyError(null, 'unknown_1');
      TokenBlacklistModel.create.mockRejectedValueOnce(err);
      await expect(consumeToken('rt-nokeypattern', futureExpSec())).rejects.toMatchObject({
        code: 'BLACKLIST_INDEX_CONFLICT',
      });
    });

    test('非 E11000 的持久化失败向上抛出（fail-closed，拒绝轮换）', async () => {
      TokenBlacklistModel.create.mockRejectedValueOnce(new Error('connection reset'));
      await expect(consumeToken('rt-dberr', futureExpSec())).rejects.toThrow('connection reset');
    });
  });

  describe('blacklistToken', () => {
    test('tokenHash 冲突视为已在黑名单，静默返回且不记 error', async () => {
      TokenBlacklistModel.findOneAndUpdate.mockRejectedValueOnce(
        dupKeyError({ tokenHash: 1 }, 'tokenHash_1')
      );
      await expect(blacklistToken('at-dup', futureExpSec())).resolves.toBeUndefined();
      expect(logger.error).not.toHaveBeenCalled();
    });

    test('非 tokenHash 冲突须抛错（P2-26 fail-closed：登出未生效不得报成功）', async () => {
      TokenBlacklistModel.findOneAndUpdate.mockRejectedValueOnce(
        dupKeyError({ token: 1 }, 'token_1')
      );
      await expect(blacklistToken('at-legacy', futureExpSec())).rejects.toMatchObject({
        code: 'BLACKLIST_INDEX_CONFLICT',
      });
      expect(logger.error).toHaveBeenCalled();
      expect(logger.error.mock.calls[0][0]).toContain('fix-token-blacklist-index');
    });

    test('普通持久化失败同样 fail-closed（与 consumeToken 契约一致）', async () => {
      TokenBlacklistModel.findOneAndUpdate.mockRejectedValueOnce(new Error('connection reset'));
      await expect(blacklistToken('at-dberr', futureExpSec())).rejects.toMatchObject({
        code: 'BLACKLIST_PERSIST_FAILED',
      });
    });

    test('已过期令牌无需写库（提前返回）', async () => {
      await blacklistToken('at-expired', Math.floor(Date.now() / 1000) - 10);
      expect(TokenBlacklistModel.findOneAndUpdate).not.toHaveBeenCalled();
    });
  });
});

describe('P1-1 启动期对账：reconcileTokenBlacklistIndexes', () => {
  let reconcileTokenBlacklistIndexes;
  let collectionSpy;

  beforeAll(() => {
    ({ reconcileTokenBlacklistIndexes } = require('../../services/initData'));
  });

  beforeEach(() => {
    jest.clearAllMocks();
  });

  afterEach(() => {
    if (collectionSpy) collectionSpy.mockRestore();
    collectionSpy = null;
  });

  /** 用假集合替换 mongoose.connection.collection，避免污染共享内存库 */
  const stubCollection = (indexes, dropImpl) => {
    const dropped = [];
    const fake = {
      indexes: jest.fn().mockResolvedValue(indexes),
      dropIndex: jest.fn(async (name) => {
        if (dropImpl) return dropImpl(name);
        dropped.push(name);
      }),
    };
    collectionSpy = jest.spyOn(mongoose.connection, 'collection').mockReturnValue(fake);
    return { fake, dropped };
  };

  test('删除单键 token 索引，保留 tokenHash/TTL/复合索引', async () => {
    const { dropped } = stubCollection([
      { name: '_id_', key: { _id: 1 } },
      { name: 'tokenHash_1', key: { tokenHash: 1 }, unique: true },
      { name: 'expiresAt_1', key: { expiresAt: 1 }, expireAfterSeconds: 0 },
      { name: 'token_1', key: { token: 1 }, unique: true },
      // 复合索引含 token 但不是遗留单键索引，不得误删
      { name: 'token_1_userId_1', key: { token: 1, userId: 1 } },
    ]);

    await reconcileTokenBlacklistIndexes();
    expect(dropped).toEqual(['token_1']);
  });

  test('无遗留索引时不做任何删除（幂等，重复启动安全）', async () => {
    const { fake } = stubCollection([
      { name: '_id_', key: { _id: 1 } },
      { name: 'tokenHash_1', key: { tokenHash: 1 }, unique: true },
    ]);

    await reconcileTokenBlacklistIndexes();
    expect(fake.dropIndex).not.toHaveBeenCalled();
  });

  test('集合不存在（全新部署）静默跳过，不阻断启动', async () => {
    const nsErr = new Error('ns does not exist: test.tokenblacklists');
    nsErr.codeName = 'NamespaceNotFound';
    collectionSpy = jest.spyOn(mongoose.connection, 'collection').mockReturnValue({
      indexes: jest.fn().mockRejectedValue(nsErr),
      dropIndex: jest.fn(),
    });

    await expect(reconcileTokenBlacklistIndexes()).resolves.toBeUndefined();
    expect(logger.warn).not.toHaveBeenCalled();
  });

  test('删除失败只告警不抛错（启动不因索引对账中断）', async () => {
    stubCollection([{ name: 'token_1', key: { token: 1 }, unique: true }], () => {
      throw new Error('not authorized to dropIndex');
    });

    await expect(reconcileTokenBlacklistIndexes()).resolves.toBeUndefined();
    expect(logger.warn).toHaveBeenCalled();
  });
});
