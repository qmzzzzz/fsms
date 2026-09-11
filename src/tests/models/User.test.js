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

    test('should validate email format', () => {
      const user = new User({
        username: 'testuser',
        password: 'Test@1234567',
        email: 'invalid-email',
      });
      const error = user.validateSync();
      expect(error).toBeDefined();
      expect(error.errors.email).toBeDefined();
    });

    test('should accept valid user data', () => {
      const user = new User({
        username: 'testuser',
        password: 'Test@1234567',
        email: 'test@example.com',
      });
      const error = user.validateSync();
      expect(error).toBeUndefined();
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
