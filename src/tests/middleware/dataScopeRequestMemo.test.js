/**
 * E7：数据范围判定的按请求记忆化。
 *
 * 钉三件事：① 同 req 的并发/后续调用共享同一次查询与同一个结果对象；
 * ② 不同 req 各查各的（键在 req 上，结构上不可能跨请求）；
 * ③ 失败不留缓存——被拒的 promise 不得变成同请求后续调用的永久答案。
 * 裸 getDataScope（服务层形态）行为不在本文件范围内（它没有 req 可挂）。
 */

const mockUserFindById = jest.fn();
jest.mock('../../models/User', () => ({
  findById: (...args) => mockUserFindById(...args),
}));

const { getDataScopeForRequest, REQUEST_SCOPE_KEY } = require('../../middleware/dataScope');

/** 假 User.findById 返回值：populate 链后给出 roles 文档 */
const userWith = (roles) => ({ populate: () => Promise.resolve({ roles }) });

beforeEach(() => {
  mockUserFindById.mockReset();
});

describe('dataScope 按请求记忆化（E7）', () => {
  test('同 req 双次调用只查一次，且拿到同一个结果对象', async () => {
    mockUserFindById.mockReturnValue(userWith([{ level: 10 }]));
    const req = {};
    const [a, b] = await Promise.all([
      getDataScopeForRequest(req, 'u1'),
      getDataScopeForRequest(req, 'u1'),
    ]);
    expect(mockUserFindById).toHaveBeenCalledTimes(1);
    expect(a).toEqual({ type: 'all' });
    expect(b).toBe(a); // 同一个缓存对象：不是"查两次再比结果"

    // 第二次（前一次已 resolve 之后）同样不再查
    const c = await getDataScopeForRequest(req, 'u1');
    expect(mockUserFindById).toHaveBeenCalledTimes(1);
    expect(c).toBe(a);
    // 载体确实挂在 req 上（随请求对象丢弃，天然不跨请求）
    expect(typeof REQUEST_SCOPE_KEY).toBe('symbol');
    expect(req[REQUEST_SCOPE_KEY]).toBeDefined();
  });

  test('不同 req 各查一次（绝不跨请求共享）', async () => {
    mockUserFindById.mockReturnValue(userWith([{ level: 10 }]));
    const reqA = {};
    const reqB = {};
    const [a, b] = await Promise.all([
      getDataScopeForRequest(reqA, 'u1'),
      getDataScopeForRequest(reqB, 'u1'),
    ]);
    expect(mockUserFindById).toHaveBeenCalledTimes(2);
    expect(a).toEqual({ type: 'all' });
    expect(b).toEqual({ type: 'all' });
    expect(b).not.toBe(a);
  });

  test('失败不留缓存：第一次被拒后，同 req 的下一次调用重试而不是共享 rejection', async () => {
    mockUserFindById
      .mockReturnValueOnce({ populate: () => Promise.reject(new Error('db down')) })
      .mockReturnValueOnce(userWith([]));
    const req = {};
    await expect(getDataScopeForRequest(req, 'u1')).rejects.toThrow('db down');
    // 键已被清除 ⇒ 第二次重新发起查询并成功
    const second = await getDataScopeForRequest(req, 'u1');
    expect(second).toEqual({ type: 'none' });
    expect(mockUserFindById).toHaveBeenCalledTimes(2);
  });

  test('无 req（服务层形态）等价裸 getDataScope：直查、不挂任何键', async () => {
    mockUserFindById.mockReturnValue(userWith([{ level: 4 }]));
    const scope = await getDataScopeForRequest(null, 'u1');
    expect(scope).toEqual({ type: 'self', userId: 'u1' });
    expect(mockUserFindById).toHaveBeenCalledTimes(1);
  });
});
