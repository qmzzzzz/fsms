/**
 * P2-03：verifyExport 对**畸形包**的失败契约。
 *
 * 守的是什么：缺 `records`（或 records 不是数组）的包此前会走到
 * `sha256(canonicalJson(undefined))` —— canonicalJson(undefined) 返回 undefined，
 * sha256 对 undefined 抛 TypeError。校验方拿到的是"校验器崩了"而不是"包不合法"，
 * 两种失败在告警/审计里完全不同形。修复后必须按该函数既有失败契约
 * `{ ok: false, reason }` 点名返回，且**先于**任何哈希计算。
 */
const { buildExport, verifyExport, secretOf } = require('../../services/forensicExport');

const SECRET = 'test-export-secret-'.padEnd(32, 'x');

describe('P2-03 verifyExport 畸形包守卫', () => {
  const withSecret = (fn) => {
    const prev = process.env.FORENSIC_EXPORT_SECRET;
    process.env.FORENSIC_EXPORT_SECRET = SECRET;
    try {
      return fn();
    } finally {
      if (prev === undefined) delete process.env.FORENSIC_EXPORT_SECRET;
      else process.env.FORENSIC_EXPORT_SECRET = prev;
    }
  };

  test('正向对照：合法包 verify 通过（夹具自证）', () => {
    withSecret(() => {
      const { ok, pkg } = buildExport({ records: [{ a: 1 }] });
      expect(ok).toBe(true);
      expect(verifyExport({ pkg })).toMatchObject({ ok: true, count: 1 });
    });
  });

  test.each([
    [
      '缺 records 键',
      (pkg) => {
        const { records: _omit, ...rest } = pkg;
        return rest;
      },
    ],
    ['records 为 undefined', (pkg) => ({ ...pkg, records: undefined })],
    ['records 为对象', (pkg) => ({ ...pkg, records: { 0: {} } })],
    ['records 为字符串', (pkg) => ({ ...pkg, records: '[]' })],
    ['records 为 null', (pkg) => ({ ...pkg, records: null })],
  ])('畸形包（%s）⇒ ok:false / bad_records，且不得抛 TypeError', (_label, mutate) => {
    withSecret(() => {
      const { pkg } = buildExport({ records: [{ a: 1 }] });
      let threw = null;
      let verdict = null;
      try {
        verdict = verifyExport({ pkg: mutate(pkg) });
      } catch (e) {
        threw = e;
      }
      expect(threw).toBeNull();
      expect(verdict).toEqual({ ok: false, reason: 'bad_records' });
    });
  });

  test('/pkg 本身缺省仍按 bad_pkg（不与 bad_records 混淆）', () => {
    withSecret(() => {
      expect(verifyExport({})).toEqual({ ok: false, reason: 'bad_pkg' });
    });
  });

  test('未配密钥时仍先按 no_secret 拒绝（顺序契约不变）', () => {
    const prev = process.env.FORENSIC_EXPORT_SECRET;
    delete process.env.FORENSIC_EXPORT_SECRET;
    try {
      expect(secretOf()).toBe('');
      expect(verifyExport({ pkg: { alg: 'HMAC-SHA256', v: 1 } })).toEqual({
        ok: false,
        reason: 'no_secret',
      });
    } finally {
      if (prev === undefined) delete process.env.FORENSIC_EXPORT_SECRET;
      else process.env.FORENSIC_EXPORT_SECRET = prev;
    }
  });

  // 审计 2026-11-17 P3：签名材料必须绑定导出归属（operator）。
  // 旧材料只签 version/exportedAt/count/digest/manifestRef，持包者把 operator
  // 改成任何人签名仍通过——导出归属成了可无痕改写的字段。
  test('改写 operator ⇒ signature_mismatch（导出归属参与签名，不得无痕易主）', () => {
    withSecret(() => {
      const { pkg } = buildExport({ records: [{ a: 1 }], operator: 'alice' });
      expect(pkg.operator).toBe('alice');
      const reowned = { ...pkg, operator: 'mallory' };
      expect(verifyExport({ pkg: reowned })).toEqual({ ok: false, reason: 'signature_mismatch' });
      // 原归属仍必须验签通过（上面的判红不是把合法包也拦下的恒红）
      expect(verifyExport({ pkg })).toMatchObject({ ok: true, count: 1 });
    });
  });
});
