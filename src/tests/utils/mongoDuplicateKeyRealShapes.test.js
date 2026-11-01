'use strict';

/**
 * 唯一键冲突谓词对**真实 mongoose 形态**的覆盖（不是合成对象）
 *
 * 合成形状容易把判据写成"我以为的形态"。本用例直接打 mongodb-memory-server，
 * 让驱动自己产生错误对象，再断言谓词结果。
 */

const mongoose = require('mongoose');
const { isDuplicateKeyError } = require('../../utils/mongoDuplicateKey');

describe('唯一键冲突谓词对真实驱动形态的覆盖', () => {
  let M;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    const schema = new mongoose.Schema(
      { key: { type: String, unique: true }, count: { type: Number } },
      { collection: 'dupkeyRealCases' }
    );
    M = mongoose.model('DupKeyRealCase', schema);
    await M.deleteMany({});
    // autoIndex 是后台异步建索引：不等它，重复插入不会报错（err 为 null，用例变成假绿/假红）
    await M.syncIndexes();
  });

  beforeEach(async () => {
    await M.deleteMany({});
    await M.create({ key: 'k1' });
  });

  afterAll(async () => {
    await M.deleteMany({}).catch(() => {});
    if (mongoose.connection.readyState !== 0) await mongoose.connection.close();
  });

  test('纯重复批（ordered:false）必须被识别为唯一键冲突', async () => {
    let err = null;
    try {
      await M.insertMany([{ key: 'k1' }], { ordered: false });
    } catch (e) {
      err = e;
    }
    expect(err).toBeTruthy();
    expect(isDuplicateKeyError(err)).toBe(true);
  });

  test('混合批（校验失败 + 重复）必须被识别为唯一键冲突', async () => {
    let err = null;
    try {
      await M.insertMany([{ key: null }, { key: 'k1' }], { ordered: false });
    } catch (e) {
      err = e;
    }
    expect(err).toBeTruthy();
    expect(isDuplicateKeyError(err)).toBe(true);
  });

  test('collection 直写（原生驱动）必须被识别', async () => {
    let err = null;
    try {
      await M.collection.insertMany([{ key: null }, { key: 'k1' }], { ordered: false });
    } catch (e) {
      err = e;
    }
    expect(err).toBeTruthy();
    expect(isDuplicateKeyError(err)).toBe(true);
  });

  test('反向对照：纯校验失败（无重复）不得被当成唯一键冲突', async () => {
    // 校验失败（ValidationError，非 11000）：谓词不得把它当成重复键。
    // 注：insertMany 不做 cast（实测 err=null），必须用 create 才会抛 ValidationError。
    let err = null;
    try {
      await M.create({ key: 'k2', count: 'not-a-number' });
    } catch (e) {
      err = e;
    }
    expect(err).toBeTruthy();
    expect(isDuplicateKeyError(err)).toBe(false);
  });
});
