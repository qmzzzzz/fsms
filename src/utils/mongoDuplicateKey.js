/** 顶层 code、writeErrors[].code 与 writeErrors[].err.code 三处都认：实测 mongoose 8.24.1 批量恒为顶层 11000，后两处属防御（换驱动/降版本时才会用到） */
const isDuplicateKeyError = (e) =>
  Boolean(
    e &&
    (e.code === 11000 ||
      (e.writeErrors || []).some((w) => w && (w.code === 11000 || w.err?.code === 11000)))
  );

module.exports = { isDuplicateKeyError };
