'use strict';

/**
 * 唯一键冲突谓词的**逐条码臂**（合成形状，防回归）
 *
 * 诚实标注：本文件用的是**构造出来的**错误对象，不是驱动真实产物。
 * 真实产物的实测见 mongoDuplicateKeyRealShapes.test.js —— mongoose 8.24.1 下
 * Model.insertMany 的混合批恒为 top.code=11000（writeErrors[].err.code 也是 11000），
 * 即**顶层判据本来就能识别**；本文件钉的是 writeErrors 里逐条码的两条臂，
 * 用于换驱动/降版本时仍不退化。
 */

const { isDuplicateKeyError } = require('../../utils/mongoDuplicateKey');

describe('唯一键冲突谓词覆盖 mongoose 批量形态', () => {
  const mongooseBatch = () => {
    const err = new Error('E11000 batch');
    err.code = 121;
    err.writeErrors = [
      { index: 0, err: { code: 121, errmsg: 'validation failed' } },
      { index: 1, err: { code: 11000, errmsg: 'duplicate key' } },
    ];
    return err;
  };

  const driverBatch = () => {
    const err = new Error('E11000 driver');
    err.code = 11000;
    err.writeErrors = [{ index: 1, code: 11000 }];
    return err;
  };

  test('mongoose 批量：逐条码在 writeErrors[].err.code（混合批里 11000 非首位）', () => {
    expect(isDuplicateKeyError(mongooseBatch())).toBe(true);
  });

  test('原生驱动批量：逐条码在 writeErrors[].code（既有形态不得回退）', () => {
    expect(isDuplicateKeyError(driverBatch())).toBe(true);
  });

  test('Model.bulkWrite 批量：逐条码同样在 writeErrors[].code', () => {
    const err = new Error('E11000 bulkWrite');
    err.code = 65;
    err.writeErrors = [{ index: 0, code: 11000 }];
    expect(isDuplicateKeyError(err)).toBe(true);
  });

  test('单文档写：顶层 code===11000', () => {
    expect(isDuplicateKeyError({ code: 11000 })).toBe(true);
  });

  test('反向对照：非重复键错误不得被当成重复（判据不是恒真）', () => {
    expect(isDuplicateKeyError({ code: 121 })).toBe(false);
    expect(isDuplicateKeyError(null)).toBe(false);
    expect(isDuplicateKeyError(new Error('boom'))).toBe(false);
  });
});
