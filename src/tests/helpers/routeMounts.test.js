/**
 * 挂载前缀解析器的自证（第 17 轮 F-06）
 *
 * 为什么单独测它：本工具被两个审计对账闸共用，而它的失败模式恰好都是**静默的**——
 * 前缀算错时闸门不会报"我算错了"，只会报"这条 action 不在白名单里"或"这条白名单条目永不产生"，
 * 把一次解析失误伪装成两个互相矛盾的业务缺陷。所以"解析失败必须抛"这条判据本身要有牙：
 * 上面两个闸门在真实仓库里永远走不到抛错分支（每个路由文件都挂得上），
 * 只靠它们测不到这里，必须在这里用合成输入打。
 */
const { readMounts, readNestedMounts, makePrefixOf } = require('../helpers/routeMounts');

describe('routeMounts：前缀解析失败必须显式失败', () => {
  test('真实仓库能解析出顶层与嵌套两类挂载（防空转：解析器塌缩成空表时这里先红）', () => {
    const mounts = readMounts();
    const nested = readNestedMounts();
    expect(mounts.securityRoutes).toBe('/api/security');
    expect(mounts.authRoutes).toBe('/api/auth');
    // 嵌套挂载至少有一条：securityRoutes 把 forensicRoutes 挂在 /forensic 下
    expect(nested.forensicRoutes).toEqual([{ parent: 'securityRoutes', sub: '/forensic' }]);
    const prefixOf = makePrefixOf(mounts, nested);
    expect(prefixOf('securityRoutes')).toBe('/api/security');
    // 拼出来的前缀必须是"父 + 子"，不是"子"也不是"父"——两者都会让派生 action 少一层/多一层
    expect(prefixOf('forensicRoutes')).toBe('/api/security/forensic');
  });

  test('未知路由名必须抛，不得返回 undefined（否则调用方会把它当作"该文件没有路由"跳过）', () => {
    const prefixOf = makePrefixOf({ aRoutes: '/api/a' }, {});
    expect(() => prefixOf('noSuchRoutes')).toThrow(/找不到前缀/);
    // 反向：抛出来的信息要能定位，不能只是一句"解析失败"
    expect(() => prefixOf('noSuchRoutes')).toThrow(/noSuchRoutes/);
  });

  test('父路由自己没有顶层前缀时必须抛（否则会静默丢一层，派生出一半的路径）', () => {
    const prefixOf = makePrefixOf({}, { childRoutes: [{ parent: 'orphanRoutes', sub: '/x' }] });
    expect(() => prefixOf('childRoutes')).toThrow(/父路由 orphanRoutes/);
  });

  test('同一子路由被多处嵌套挂载时必须抛（本工具只表达单一前缀，取第一个就是编造）', () => {
    const prefixOf = makePrefixOf(
      { aRoutes: '/api/a', bRoutes: '/api/b' },
      {
        sharedRoutes: [
          { parent: 'aRoutes', sub: '/s' },
          { parent: 'bRoutes', sub: '/s' },
        ],
      }
    );
    expect(() => prefixOf('sharedRoutes')).toThrow(/多处嵌套挂载/);
  });

  test('拼接不会留下双斜杠或尾斜杠（派生 action 会按段切分，双斜杠会切出空段）', () => {
    const prefixOf = makePrefixOf(
      { aRoutes: '/api/a/' },
      { cRoutes: [{ parent: 'aRoutes', sub: '/c' }] }
    );
    expect(prefixOf('aRoutes')).toBe('/api/a/');
    expect(prefixOf('cRoutes')).toBe('/api/a/c');
    expect(prefixOf('cRoutes')).not.toMatch(/\/\//);
  });
});
