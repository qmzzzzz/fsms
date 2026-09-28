'use strict';

/**
 * 夹具：构造"服务端按内容逐条拒绝"的批量写错误形状
 *
 * 为什么需要它（F-96）：`auditBuffer` 的毒批判据从"全局连败计数"改成
 * "能从错误里 positively 认出内容级失败"之后，未知形状的错误一律**保守按基础设施问题处理**
 * （不删审计）——因为误判成"毒文档"的代价是把合法审计从 WAL 移除并永久丢失，
 * 而误判成基础设施的代价只是重试不收敛。
 * 所以"测毒批隔离"的用例不能再用 `new Error('永久失败')` 这种无形状错误：
 * 那测的其实是"未知错误也不许删审计"（另一条判据，已有专门用例）。
 *
 * 形状以**真库实跑**为准，不是手编的：F-183 前这里写的是 `name='BulkWriteError'`，
 * 而驱动实际抛出的类名是 `MongoBulkWriteError`（同仓 `permissionService.js:164` 也踩过同一个坑），
 * 顶层还多一条"第一条 writeError 的 code 回显"。三处形状断言现在都被
 * `tests/utils/mongoFailureAttribution.test.js` 的"真库形状"用例和
 * `tests/auditBufferZombieDuplicate.test.js:144-168` 钉在真实驱动上，
 * 驱动升级改了形状会先红在那里。
 *
 * @param {number} count 被拒条目数（决定 writeErrors 长度）
 * @param {number} code 服务端错误码，默认 121 = DocumentValidationFailure
 */
function contentLevelWriteError(count = 1, code = 121) {
  const err = new Error(`MongoBulkWriteError: ${count} write error(s)`);
  err.name = 'MongoBulkWriteError';
  err.writeErrors = Array.from({ length: count }, (_, index) => ({
    index,
    // 实测：服务端码嵌在 .err 下，条目自身只有 {index, err}
    err: { index, code, errmsg: 'Document failed validation', op: { _id: `fake-${index}` } },
  }));
  if (count > 0) err.code = code; // 实测：驱动只回显第一条的码（顶层判定顺序相关的根因）
  return err;
}

module.exports = { contentLevelWriteError };
