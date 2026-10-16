/**
 * User 模型测试
 */

describe('User Model', () => {
  let User;

  beforeAll(() => {
    User = require('../../models/User');
  });

  describe('Schema Validation', () => {
    test('should require username', () => {
      const user = new User({ password: 'Test@1234567' });
      const error = user.validateSync();
      expect(error).toBeDefined();
      expect(error.errors.username).toBeDefined();
    });

    test('should require password', () => {
      const user = new User({ username: 'test' });
      const error = user.validateSync();
      expect(error).toBeDefined();
      expect(error.errors.password).toBeDefined();
    });

    /**
     * 【2026-10-16 A3：本用例为什么必须走 async validate() 而不是 validateSync()】
     * A3 给 `User.email` 上了 at-rest 加密，同时把邮箱**格式校验**从 schema 的
     * `match` 前移到 `pre('validate')` 钩子的**明文阶段**——因为 validate 阶段看到的
     * 已是密文，正则会把每一行都判非法（详见 src/models/User.js 的 PII_ENCRYPTED_FIELDS 注释）。
     * 而 Mongoose 的 `validateSync()` **不执行 pre('validate') 钩子**（本机实测：
     * `validateSync()` 只报 username、不报 email；`await validate()` 与 `await save()`
     * 都报「请输入有效的邮箱地址」）。生产写入路径是 `save()`，行为未退化——
     * 变的只是"哪条 API 能看见这条判据"。
     */
    test('should validate email format', async () => {
      const user = new User({
        username: 'testuser',
        password: 'Test@1234567',
        email: 'invalid-email',
      });
      let error;
      try {
        await user.validate();
      } catch (e) {
        error = e;
      }
      expect(error).toBeDefined();
      expect(error.errors.email).toBeDefined();
      expect(error.errors.email.message).toBe('请输入有效的邮箱地址');
    });

    test('should accept valid user data', async () => {
      const user = new User({
        username: 'testuser',
        password: 'Test@1234567',
        email: 'test@example.com',
      });
      // 走 async validate()：这条会真的穿过 pre('validate') 钩子（加密 + 写检索键），
      // 所以它同时是"合法值不被误拒"与"加密路径本身不炸"的证据。
      await expect(user.validate()).resolves.toBeUndefined();
    });

    test('should have default status as active', () => {
      const user = new User({
        username: 'testuser',
        password: 'Test@1234567',
      });
      expect(user.status).toBe('active');
    });
  });

  describe('Schema Fields', () => {
    test('should have required fields defined', () => {
      const user = new User();
      expect(user.schema.path('username')).toBeDefined();
      expect(user.schema.path('password')).toBeDefined();
      expect(user.schema.path('email')).toBeDefined();
      expect(user.schema.path('status')).toBeDefined();
    });
  });
});
