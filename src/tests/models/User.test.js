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
      // 断言到 kind 而不只是"有错"：username 同时有 minlength / match 两条判据，
      // 只判 errors.username 存在的话，把 required 摘掉后它仍可能因 match 报错而绿。
      expect(error.errors.username).toBeDefined();
      expect(error.errors.username.kind).toBe('required');
      expect(error.errors.username.message).toBe('用户名不能为空');
    });

    test('should require password', () => {
      const user = new User({ username: 'test' });
      const error = user.validateSync();
      expect(error).toBeDefined();
      expect(error.errors.password).toBeDefined();
      expect(error.errors.password.kind).toBe('required');
      expect(error.errors.password.message).toBe('密码不能为空');
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
    /**
     * 【2026-10-24 加强】原用例只做 `schema.path('x')).toBeDefined()`——它证明的
     * 是"字段存在"，而字段存在恰恰是**最不可能回归**的一环。真正会悄悄坏掉的是
     * 字段上的**约束与选项**：`select: false` 一旦被删，登录/用户列表接口就会
     * 开始返回 bcrypt 哈希与 MFA 密钥；`enum` 一旦被手抄一份，就会与 USER_STATUS
     * 分叉。所以下面按"选项值"断言，而不是按"字段存在"断言。
     */
    test('凭证级字段一律 select:false（删掉任意一个即 API 开始回吐哈希/密钥）', () => {
      // 清单来源：src/models/User.js 里 11 处 select: false（审计二-2 加了 passwordRetiredHash）。
      // 这不是"再抄一份常量"，
      // 而是**故意把清单钉在测试里**——新增凭证字段却忘了 select:false 时，
      // 本用例不会自动覆盖它，但下方"总数"断言会提示清单需要同步（见第二条）。
      const credentialFields = [
        'password',
        'passwordHistory',
        'passwordRetiredHash',
        'emailKey',
        'emailGrams',
        'phoneKey',
        'mfaSecret',
        'mfaLastCounter',
        'mfaRecoveryCodes',
        'mfaFailCount',
        'mfaLockUntil',
      ];
      const missing = credentialFields.filter(
        (f) => User.schema.path(f)?.options?.select !== false
      );
      expect(missing).toEqual([]);
    });

    test('select:false 的字段总数与清单一致（新增凭证字段必须同步本清单）', () => {
      const actual = Object.keys(User.schema.paths).filter(
        (p) => User.schema.path(p)?.options?.select === false
      );
      expect(actual.sort()).toEqual(
        [
          'emailGrams',
          'emailKey',
          'mfaFailCount',
          'mfaLastCounter',
          'mfaLockUntil',
          'mfaRecoveryCodes',
          'mfaSecret',
          'password',
          'passwordHistory',
          'passwordRetiredHash',
          'phoneKey',
        ].sort()
      );
    });

    test('username 的约束完整（必填/长度/字符集），且拒绝西里尔同形字', async () => {
      const opts = User.schema.path('username').options;
      expect(opts.required).toBeTruthy();
      expect(opts.minlength).toEqual([3, '用户名至少 3 个字符']);
      expect(opts.maxlength).toEqual([30, '用户名最多 30 个字符']);
      expect(opts.trim).toBe(true);
      // 字符集约束的**实际效果**：`аdmin`（首字符是西里尔 'а' U+0430）在
      // USERNAME_COLLATION 下与 admin 不等价，只有模型层这条正则能拦住它。
      // 只断言 opts.match 存在是不够的——正则写错（比如忘了锚点）同样存在。
      const cyrillic = new User({ username: '\u0430dmin', password: 'Test@1234567' });
      expect(cyrillic.validateSync().errors.username.message).toBe(
        '用户名只能包含字母、数字和下划线'
      );
      const latin = new User({ username: 'admin', password: 'Test@1234567' });
      expect(latin.validateSync().errors.username).toBeUndefined();
    });

    test('password 的长度约束覆盖字符数与 bcrypt 72 字节硬边界', () => {
      const opts = User.schema.path('password').options;
      expect(opts.required).toBeTruthy();
      expect(opts.minlength).toEqual([12, '密码至少 12 个字符']);
      expect(opts.maxlength).toEqual([72, '密码最多 72 个字符']);
      // 72 个汉字 = 216 字节：字符数上限拦不住它，只有 validate 里那条字节级
      // 校验器能拦。少了它，超出 72 字节的后缀会被 bcrypt 静默丢弃（等价口令）。
      const long = new User({ username: 'testuser', password: '密'.repeat(72) });
      const err = long.validateSync();
      expect(err.errors.password.message).toBe(
        '密码过长（超过 bcrypt 72 字节硬边界，超出部分会被静默丢弃）'
      );
      // 反向：72 字节以内的中文口令必须放行，否则上面的断言可能只是"恒报错"
      const ok = new User({ username: 'testuser', password: '密'.repeat(24) });
      expect(ok.validateSync().errors.password).toBeUndefined();
    });

    test('status 的 enum 与 utils/constants 的 USER_STATUS 同源（不是手抄的一份）', () => {
      const { USER_STATUS } = require('../../utils/constants');
      const opts = User.schema.path('status').options;
      expect(opts.enum).toEqual(Object.values(USER_STATUS));
      expect(opts.default).toBe('active');
      // 可证伪：给枚举加一档而忘了同步时，本条会红（这正是它要防的分叉）
      expect(opts.enum).toContain(USER_STATUS.LOCKED);
    });

    test('关键索引在位：username 大小写不敏感唯一、emailKey 唯一', () => {
      const indexes = User.schema.indexes();
      const byName = (n) => indexes.find(([, o]) => o && o.name === n);
      const usernameIdx = byName('username_ci');
      expect(usernameIdx).toBeTruthy();
      expect(usernameIdx[1].unique).toBe(true);
      // collation 是"Admin 与 admin 视为同一账号"的唯一保证；退回默认 collation
      // 不会报错，只会让仿冒账号重新可建。
      expect(usernameIdx[1].collation).toEqual({ locale: 'en', strength: 2 });
      expect(byName('emailKey_1')[1].unique).toBe(true);
    });
  });
});
