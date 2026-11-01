/**
 * privilegeGrantValidation 的**边界**单元用例（C-08 拆出的校验模块）。
 *
 * 服务层测试只钉了「999 小时越界」「目录外权限码」两条，属于"越界即拒"的粗判；
 * 真正决定行为的是**边界两侧**：MIN=1 / MAX=168 是闭区间，超一位就拒；
 * 20 是权限码条数上限（20 收、21 拒）；保留通配不可授；停用码与不存在码必须
 * 在提示里点名。这些分支一旦改口径（例如把 > 写成 >=），服务层用例不会红——
 * 因为它压根没走到边界值上。
 */
jest.mock('../../models/Permission', () => ({ find: jest.fn() }));

const Permission = require('../../models/Permission');
const {
  clampDurationHours,
  normalizeCodes,
  assertCodesGrantable,
} = require('../../services/privilegeGrantValidation');
const {
  MIN_GRANT_HOURS,
  MAX_GRANT_HOURS,
  MAX_GRANT_CODES,
} = require('../../constants/privilegeGrant');
const { RESERVED_WILDCARD_PERMISSION } = require('../../utils/superAdmin');

/** Permission.find(...).select(...).lean() 的替身：按给定"库里存在的码"作答 */
const withCatalog = (codes) => {
  Permission.find.mockReturnValue({
    select: () => ({
      lean: async () => codes.map((code) => ({ code })),
    }),
  });
};

describe('clampDurationHours：有效期为闭区间整数小时', () => {
  test('两端点恰好落在界内：MIN 与 MAX 都放行', () => {
    expect(clampDurationHours(MIN_GRANT_HOURS)).toBe(MIN_GRANT_HOURS);
    expect(clampDurationHours(MAX_GRANT_HOURS)).toBe(MAX_GRANT_HOURS);
  });

  test('端点外一位即拒：0 与 MAX+1（用常量推导，改口径必红）', () => {
    expect(MIN_GRANT_HOURS).toBeGreaterThan(0); // 0 小时=永久，不该是"临时授权"的合法输入
    for (const bad of [MIN_GRANT_HOURS - 1, MAX_GRANT_HOURS + 1]) {
      expect(() => clampDurationHours(bad)).toThrow(
        expect.objectContaining({ code: 'PRIVILEGE_DURATION_INVALID' })
      );
    }
  });

  test('非数值与非有限值一律拒（undefined/null/NaN/Infinity/任意字符串）', () => {
    for (const bad of [undefined, null, NaN, Infinity, -Infinity, 'x', '', {}]) {
      expect(() => clampDurationHours(bad)).toThrow(
        expect.objectContaining({ code: 'PRIVILEGE_DURATION_INVALID' })
      );
    }
  });

  test('数字字符串按数值处理；小数在界内向下/向上取整到整数小时', () => {
    expect(clampDurationHours('2')).toBe(2);
    expect(clampDurationHours(' 3 ')).toBe(3);
    expect(clampDurationHours(MIN_GRANT_HOURS + 0.2)).toBe(MIN_GRANT_HOURS);
    expect(clampDurationHours(MAX_GRANT_HOURS - 0.4)).toBe(MAX_GRANT_HOURS); // 界内小数只在落库前取整
  });
});

describe('normalizeCodes：去重/去空白/条数上下界', () => {
  test('空输入与非数组一律按 0 项处理并拒（含字符串、null、对象）', () => {
    for (const bad of [undefined, null, 'a:b', 42, {}]) {
      expect(() => normalizeCodes(bad)).toThrow(
        expect.objectContaining({ code: 'PRIVILEGE_GRANT_INVALID' })
      );
    }
    expect(() => normalizeCodes([])).toThrow(
      expect.objectContaining({ code: 'PRIVILEGE_GRANT_INVALID' })
    );
    expect(() => normalizeCodes(['', '   '])).toThrow(
      expect.objectContaining({ code: 'PRIVILEGE_GRANT_INVALID' })
    );
  });

  test('恰好 MAX_GRANT_CODES 项放行，多一项即拒（上限不离散地写在两处）', () => {
    const max = Array.from({ length: MAX_GRANT_CODES }, (_, i) => 'zzb:mod:c' + i);
    expect(normalizeCodes(max)).toHaveLength(MAX_GRANT_CODES);
    const over = [...max, 'zzb:mod:extra'];
    expect(() => normalizeCodes(over)).toThrow(
      expect.objectContaining({ code: 'PRIVILEGE_GRANT_INVALID' })
    );
  });

  test('去重与去空白：重复项折叠成一项，空白项被丢弃后仍按有效项计数', () => {
    expect(normalizeCodes([' a:b ', 'a:b', 'c:d'])).toEqual(['a:b', 'c:d']);
    // 20 个"看似 21 项"的列表：1 项空白 + 1 项重复 ⇒ 有效项 20，必须放行
    const padded = [
      '',
      ...Array.from({ length: MAX_GRANT_CODES }, (_, i) => 'zzb:m:c' + i),
      'zzb:m:c0',
    ]; // 21 项里 1 空白 + 1 重复 ⇒ 有效项恰好 20
    expect(normalizeCodes(padded)).toHaveLength(MAX_GRANT_CODES);
  });
});

describe('assertCodesGrantable：保留码与目录态', () => {
  afterEach(() => Permission.find.mockReset());

  test('保留通配不可经临时授权通道申请（与其他授予路径同口径）', async () => {
    await expect(assertCodesGrantable([RESERVED_WILDCARD_PERMISSION])).rejects.toMatchObject({
      code: 'PRIVILEGE_CODE_INVALID',
    });
    expect(Permission.find).not.toHaveBeenCalled(); // 保留码在查库前就被拦下
  });

  test('目录里没有 / 已停用的码必须在提示里点名（一次列全，不是只报第一个）', async () => {
    withCatalog(['zzb:m:ok']); // 'zzb:m:off' 已停用 ⇒ 查询结果里不含它
    const err = await assertCodesGrantable(['zzb:m:ok', 'zzb:m:off', 'zzb:m:gone']).catch((e) => e);
    expect(err).toBeDefined();
    expect(err.code).toBe('PRIVILEGE_CODE_INVALID');
    expect(err.message).toContain('zzb:m:off'); // 两个缺失项都要点名，不能只报第一个
    expect(err.message).toContain('zzb:m:gone');
    expect(err.message).not.toContain('zzb:m:ok');
    await expect(assertCodesGrantable(['zzb:m:off'])).rejects.toMatchObject({
      code: 'PRIVILEGE_CODE_INVALID',
    });
  });

  test('全部可授予时静默通过（不留痕、不改写输入）', async () => {
    withCatalog(['zzb:m:a', 'zzb:m:b']);
    await expect(assertCodesGrantable(['zzb:m:a', 'zzb:m:b'])).resolves.toBeUndefined();
  });
});
