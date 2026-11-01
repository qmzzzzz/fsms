/**
 * U1 回归：EMAIL_RE 的 O(n²) + 嵌套字符串无长度闸
 *
 * 两个缺陷叠在一条链上：正则本身是二次方（首捕获组与后续字符类完全重叠，
 * 对「一长串同字符 + 无 @」的输入，每个起点都把整段吃完再失败），且
 * maskLogInfo 只对顶层 message/字段截断，嵌套对象里的字符串不限长。
 * 判据只钉「线性」与「形状不变」，不钉绝对毫秒数：同一用例内跑两档尺寸比耗时，
 * 二次方会是 ~16 倍，线性在 8 倍以内——这样换机器不会假红。
 */

'use strict';

const { maskPiiText, maskLogInfo } = require('../../utils/logPiiMask');

/** 取三次运行的最小值：单次计时会被 GC/调度噪声放大 */
const fastestMs = (fn, runs = 3) => {
  let best = Infinity;
  for (let i = 0; i < runs; i += 1) {
    const t0 = process.hrtime.bigint();
    fn();
    const ms = Number(process.hrtime.bigint() - t0) / 1e6;
    if (ms < best) best = ms;
  }
  return best;
};

describe('U1 EMAIL_RE 必须线性（不是二次方）', () => {
  test('n=16384 与 n=65536 的耗时比 < 8（二次方约 16 倍）', () => {
    const small = fastestMs(() => maskPiiText('1'.repeat(16384)));
    const large = fastestMs(() => maskPiiText('1'.repeat(65536)));
    // 分母设下限：修好后两档都是亚毫秒级，比值会被计时噪声主导
    const ratio = large / Math.max(small, 0.05);
    expect(ratio).toBeLessThan(8);
  });

  test('等价改写：掩码输出逐字不变', () => {
    expect(maskPiiText('a@b.co')).toBe('a***@b.co');
    expect(maskPiiText('zhangsan@corp.com')).toBe('z***@corp.com');
    expect(maskPiiText('用户 zhangsan@corp.example.com 登录失败')).toBe(
      '用户 z***@corp.example.com 登录失败'
    );
    expect(maskPiiText('a.b@x.io')).toBe('a***@x.io');
  });

  test('等价改写：不误伤（无 @ 的长串与普通文本原样返回）', () => {
    const digits = '1'.repeat(64);
    expect(maskPiiText(digits)).toBe(digits);
    expect(maskPiiText('route=/api/reports/export status=200')).toBe(
      'route=/api/reports/export status=200'
    );
  });
});

describe('U1 嵌套字符串必须有与顶层一致的长度闸', () => {
  test('嵌套对象里的超长字符串被截到 1024（原先不限长）', () => {
    const info = { message: 'x', payload: { blob: '1'.repeat(20000), keep: 'ok' } };
    maskLogInfo(info);
    expect(info.payload.blob.length).toBeLessThanOrEqual(1024);
    expect(info.payload.keep).toBe('ok');
  });

  test('数组元素同样受限（数组不是豁免）', () => {
    const info = { message: 'x', items: ['2'.repeat(20000)] };
    maskLogInfo(info);
    expect(info.items[0].length).toBeLessThanOrEqual(1024);
  });

  test('截断后掩码仍然生效（闸不能把 PII 放过去）', () => {
    const info = { message: 'x', contact: { email: 'zhangsan@corp.com' } };
    maskLogInfo(info);
    expect(info.contact.email).toBe('z***@corp.com');
  });

  test('放大器已封顶：64KB 嵌套串的掩码耗时 < 100ms（截断前实测 2.8s）', () => {
    const info = { message: 'x', payload: { blob: '1'.repeat(65536) } };
    const ms = fastestMs(() => maskLogInfo(info), 1);
    expect(ms).toBeLessThan(100);
  });
});
