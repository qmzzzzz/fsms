/**
 * CORS 来源白名单单一配置源（审计 2026-11-15）
 *
 * 修前形态：CORS_ORIGIN 解析 + 本地开发兜底清单在 app.js 与
 * services/websocketService/index.js 各抄一份（3001/5173 就是两侧分别加出来的）；
 * 且 `https://host:443`、大写 host 这类"浏览器永远不会发送"的书写形态被原样放进
 * 白名单——启动全绿，但真实请求 Origin 永远匹配不上，所有写操作静默 403。
 *
 * 本文件钉三件事：
 *   1. parseCorsOriginList：逗号切分 + 空项剔除（`", "` ⇒ []，回落方向由调用方定）；
 *   2. devCorsFallback：与 utils/constants.DEV_CORS_ORIGINS 单源同值；
 *   3. normalizeCorsOrigin：小写 host、去默认端口（https:443 / http:80），
 *      非默认端口保留；带路径/userinfo 的形态**原样返回**（归一化不得把路径级
 *      配置放大成全域放行）。
 */

const {
  parseCorsOriginList,
  devCorsFallback,
  normalizeCorsOrigin,
  DEV_CORS_ORIGINS,
} = require('../../config/corsOrigins');
const { DEV_CORS_ORIGINS: SINGLE_SOURCE } = require('../../utils/constants');

describe('parseCorsOriginList', () => {
  test('逗号切分 + trim + 空项剔除', () => {
    expect(parseCorsOriginList('https://a.example.com, https://b.example.com')).toEqual([
      'https://a.example.com',
      'https://b.example.com',
    ]);
  });

  test('全空项得到空数组（回落方向由调用方决定）', () => {
    expect(parseCorsOriginList(', ')).toEqual([]);
    expect(parseCorsOriginList('')).toEqual([]);
    expect(parseCorsOriginList(undefined)).toEqual([]);
  });
});

describe('devCorsFallback 与 constants 单源', () => {
  test('兜底清单与 DEV_CORS_ORIGINS 同源同值，且互不影响（防御性拷贝）', () => {
    expect(devCorsFallback()).toEqual(SINGLE_SOURCE);
    expect(DEV_CORS_ORIGINS).toBe(SINGLE_SOURCE);
    const snapshot = devCorsFallback();
    snapshot.push('https://mutated.example.com');
    expect(devCorsFallback()).toEqual(SINGLE_SOURCE); // 改动拷贝不得污染单源
  });
});

describe('normalizeCorsOrigin（浏览器永远不会发送的形态）', () => {
  test('https 默认端口 443 被省略；http 默认端口 80 被省略', () => {
    expect(normalizeCorsOrigin('https://admin.example.com:443')).toBe('https://admin.example.com');
    expect(normalizeCorsOrigin('http://admin.example.com:80')).toBe('http://admin.example.com');
  });

  test('大写 host 归一为小写（浏览器 Origin 恒为小写）', () => {
    expect(normalizeCorsOrigin('https://ADMIN.Example.COM')).toBe('https://admin.example.com');
  });

  test('非默认端口保留（8443 不能被吞掉）', () => {
    expect(normalizeCorsOrigin('https://api.example.com:8443')).toBe(
      'https://api.example.com:8443'
    );
  });

  test('规范形态是恒等变换（兜底清单里的本地源不受影响）', () => {
    for (const origin of SINGLE_SOURCE) {
      expect(normalizeCorsOrigin(origin)).toBe(origin);
    }
  });

  test('带路径/查询/userinfo 的形态原样返回：归一化不得放大白名单', () => {
    expect(normalizeCorsOrigin('https://admin.example.com/app')).toBe(
      'https://admin.example.com/app'
    );
    expect(normalizeCorsOrigin('https://user:pw@admin.example.com')).toBe(
      'https://user:pw@admin.example.com'
    );
    expect(normalizeCorsOrigin('not-a-url')).toBe('not-a-url');
  });
});
