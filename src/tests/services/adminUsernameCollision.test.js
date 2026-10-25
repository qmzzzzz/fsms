/**
 * 并发首次启动的同名管理员冲突
 *
 * 「判重 → 创建」之间另一实例可能已经建好同名账户，User.create 抛 username
 * 唯一键冲突。复用赢家即可，但**不得**继续落盘本实例的口令——它与赢家账户的
 * 实际口令不同，写下去等于给运维一份永远登录不上的凭据，还会覆盖赢家写的那份。
 */

jest.mock('../../models/User', () => ({
  findByUsername: jest.fn(),
  create: jest.fn(),
}));
jest.mock('../../models/Role', () => ({ findOne: jest.fn() }));
jest.mock('../../services/initialPasswordFile', () => ({ filePath: jest.fn() }));

const User = require('../../models/User');
const Role = require('../../models/Role');
const initialPasswordFile = require('../../services/initialPasswordFile');
const { createDefaultAdmin } = require('../../services/initData/adminAccount');

const winner = { _id: 'winner-id', username: 'admin', roles: [] };
const duplicate = (key) =>
  Object.assign(new Error('E11000 duplicate key error'), {
    code: 11000,
    keyPattern: { [key]: 1 },
  });

describe('默认管理员的并发首启冲突', () => {
  const ENV_KEY = 'ADMIN_INITIAL_PASSWORD';
  let previous;

  beforeAll(() => {
    previous = process.env[ENV_KEY];
    process.env[ENV_KEY] = 'Aa1!admin-initial-password-for-test';
  });

  afterAll(() => {
    if (previous === undefined) delete process.env[ENV_KEY];
    else process.env[ENV_KEY] = previous;
  });

  beforeEach(() => {
    jest.clearAllMocks();
    Role.findOne.mockResolvedValue({ _id: 'role-id', code: 'SUPER_ADMIN', isBuiltIn: true });
  });

  test('username 冲突 ⇒ 复用赢家账户，且不覆盖初始口令文件', async () => {
    User.findByUsername.mockResolvedValueOnce(null).mockResolvedValueOnce(winner);
    User.create.mockRejectedValueOnce(duplicate('username'));

    const admin = await createDefaultAdmin();

    expect(admin).toBe(winner);
    expect(User.create).toHaveBeenCalledTimes(1);
    expect(initialPasswordFile.filePath).not.toHaveBeenCalled();
  });

  test('username 冲突且读不到赢家 ⇒ 原错误上抛，不得当作已创建', async () => {
    User.findByUsername.mockResolvedValue(null);
    User.create.mockRejectedValueOnce(duplicate('username'));

    await expect(createDefaultAdmin()).rejects.toMatchObject({ code: 11000 });
    expect(initialPasswordFile.filePath).not.toHaveBeenCalled();
  });

  test('email 冲突降级后备邮箱；后备重建再撞 username ⇒ 复用赢家', async () => {
    User.findByUsername.mockResolvedValueOnce(null).mockResolvedValueOnce(winner);
    User.create
      .mockRejectedValueOnce(duplicate('emailKey'))
      .mockRejectedValueOnce(duplicate('username'));

    const admin = await createDefaultAdmin();

    expect(admin).toBe(winner);
    expect(User.create).toHaveBeenCalledTimes(2);
    expect(initialPasswordFile.filePath).not.toHaveBeenCalled();
  });
});
