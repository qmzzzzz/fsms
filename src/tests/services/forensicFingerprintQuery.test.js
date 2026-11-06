/**
 * 取证溯源的指纹判据（services/forensicTrace.conditionOf）。
 *
 * 背景：前端输入框一直写「指纹片段，如 ab12cd」，后端原本是严格等值——
 * 按提示输入片段必然 0 条，运维读到的结论却是「这个设备没痕迹」。
 * 这一组用例钉三件事：完整值仍等值、片段走锚定前缀、输入大小写与空白不影响命中。
 */
const { conditionOf, actorPools } = require('../../services/forensicTrace');

const FINGERPRINT = 'a1b2c3d4e5f60718293a4b5c6d7e8f90';

describe('取证溯源的指纹判据', () => {
  test('完整 32 位：等值匹配（继续吃 fingerprint+createdAt 索引）', () => {
    expect(conditionOf({ fingerprint: FINGERPRINT }).fingerprint).toBe(FINGERPRINT);
  });

  test('完整值大写粘贴：转小写后仍能命中，不静默漏', () => {
    expect(conditionOf({ fingerprint: FINGERPRINT.toUpperCase() }).fingerprint).toBe(FINGERPRINT);
  });

  test('片段：锚定前缀匹配，而不是子串扫全表', () => {
    expect(conditionOf({ fingerprint: ' A1B2C3D4 ' }).fingerprint).toEqual({ $regex: '^a1b2c3d4' });
  });

  test('用户输入里的正则元字符被转义（不能当成模式执行）', () => {
    expect(conditionOf({ fingerprint: 'a.b*c' }).fingerprint).toEqual({ $regex: '^a\\.b\\*c' });
  });

  test('纯空白指纹等于没给判据：返回 null，不退化成全表扫描', () => {
    expect(conditionOf({ fingerprint: '   ' })).toBeNull();
  });

  test('与时间区间组合时两者同时生效', () => {
    const cond = conditionOf({ fingerprint: 'abcd1234', since: '2026-11-01T00:00:00Z' });
    expect(cond.fingerprint).toEqual({ $regex: '^abcd1234' });
    expect(cond.createdAt.$gte).toBeInstanceOf(Date);
  });
});
describe('设备键判据（取证专用，不含地址）', () => {
  test('完整设备键走等值，片段走锚定前缀', () => {
    const full = 'a1b2'.repeat(8);
    expect(conditionOf({ deviceKey: full.toUpperCase() }).deviceKey).toBe(full);
    expect(conditionOf({ deviceKey: 'A1B2' }).deviceKey).toEqual({ $regex: '^a1b2' });
  });

  test('只给设备键也算判据，且不往 fingerprint 上凑条件', () => {
    const cond = conditionOf({ deviceKey: 'abcd1234' });
    expect(cond.fingerprint).toBeUndefined();
    expect(cond.deviceKey).toEqual({ $regex: '^abcd1234' });
  });

  test('actorPools 只给设备键也聚合：同一设备跨网段能被看见', async () => {
    const seen = [];
    const model = {
      aggregate: (pipeline) => {
        seen.push(pipeline);
        return Promise.resolve([{ _id: '1.2.3', hits: 2, ips: ['1.2.3.4', '1.2.3.9'] }]);
      },
    };
    const r = await actorPools({ model, deviceKey: 'abcd1234', until: new Date() });
    expect(r.ok).toBe(true);
    expect(seen[0][0].$match.deviceKey).toEqual({ $regex: '^abcd1234' });
    expect(seen[0][0].$match.fingerprint).toBeUndefined();
  });

  test('既无指纹也无设备键：拒绝聚合，不拿全表当结果', async () => {
    const model = {
      aggregate: () => {
        throw new Error('不该聚合');
      },
    };
    const r = await actorPools({ model });
    expect(r.ok).toBe(false);
    expect(r.pools).toEqual([]);
  });
});
