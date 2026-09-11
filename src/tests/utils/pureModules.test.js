/**
 * 纯函数与缓存模块覆盖（冲 100% 第二批）
 *
 * 目标模块此前缺口：encryption.js 52.9%（DataMasking 全量未测）、
 * captchaService 58.7%、userPermissionService 50%、statsCache 71.6%。
 * 全部为无 DB 依赖或最小 DB 依赖的可确定性路径。
 */

describe('encryption.js 缺口覆盖：DataMasking / HMACSigner / HashUtils / AESCipher', () => {
  const {
    DataMasking,
    HMACSigner,
    HashUtils,
    AESCipher,
    aesCipher,
    hmacSigner,
  } = require('../../utils/encryption');

  describe('DataMasking', () => {
    test('maskPhone：11 位打中间四位；非 11 位保留首尾', () => {
      expect(DataMasking.maskPhone('13812345678')).toBe('138****5678');
      expect(DataMasking.maskPhone('12345')).toBe('12***45'.replace('***', '***'));
      expect(DataMasking.maskPhone('')).toBe('');
      expect(DataMasking.maskPhone(null)).toBe('');
    });

    test('maskEmail：本地部分按长度打码；无 @ 原样返回', () => {
      expect(DataMasking.maskEmail('ab@example.com')).toBe('a****@example.com');
      expect(DataMasking.maskEmail('abcdef@example.com')).toMatch(/^a\*{4}f@example\.com$/);
      expect(DataMasking.maskEmail('not-an-email')).toBe('not-an-email');
      expect(DataMasking.maskEmail('')).toBe('');
      expect(DataMasking.maskEmail(null)).toBe('');
    });

    test('maskIdCard：≥14 位保留前后段；短号保留首尾', () => {
      expect(DataMasking.maskIdCard('110101199003077758')).toBe('110101********7758');
      expect(DataMasking.maskIdCard('1234567')).toBe('1234***67');
      expect(DataMasking.maskIdCard('')).toBe('');
      expect(DataMasking.maskIdCard(null)).toBe('');
    });

    test('maskName：单字/两字/多字', () => {
      expect(DataMasking.maskName('张')).toBe('*');
      expect(DataMasking.maskName('张三')).toBe('张*');
      expect(DataMasking.maskName('诸葛亮')).toBe('诸*亮');
      expect(DataMasking.maskName('')).toBe('');
      expect(DataMasking.maskName(null)).toBe('');
    });

    test('maskIP：IPv4 / IPv4-mapped IPv6 / 压缩与完整 IPv6 / 非法输入', () => {
      expect(DataMasking.maskIP('192.168.1.100')).toBe('192.168.*.*');
      // IPv4-mapped IPv6 按内嵌 IPv4 语义脱敏（P3-27）
      expect(DataMasking.maskIP('::ffff:192.168.1.100')).toBe('192.168.*.*');
      // 压缩 IPv6：展开后保留前 3 组原文（组内文本不做归一化），缺省组补 0
      expect(DataMasking.maskIP('2001:db8::1')).toBe('2001:db8:0:****');
      // 完整 8 组 IPv6
      expect(DataMasking.maskIP('2001:0db8:0000:0000:0000:0000:0000:0001')).toBe(
        '2001:0db8:0000:****'
      );
      // 非法 IPv6：整体打码，不猜测
      expect(DataMasking.maskIP('2001:db8:::junk')).toBe('****');
      expect(DataMasking.maskIP('')).toBe('');
      expect(DataMasking.maskIP(null)).toBe('');
      // 多个 ::：非法
      expect(DataMasking.maskIP('1::2::3')).toBe('****');
      // 末尾内嵌 IPv4 的 IPv6
      expect(DataMasking.maskIP('2001:db8::192.168.0.1')).toMatch(/^2001:db8/);
      // 非法 IPv4 尾段（>255）：mapped 前缀剥掉后按点分四段处理，兜底打码而非整体作废
      expect(DataMasking.maskIP('::ffff:999.999.999.999')).toBe('999.999.*.*');
      // 非 IP 形态（无 ':' 且非四段数字）：原样返回，不做猜测式打码
      expect(DataMasking.maskIP('abc.def')).toBe('abc.def');
    });

    test('_expandIPv6：组数超限 / 非法字符返回 null', () => {
      expect(DataMasking._expandIPv6('1:2:3:4:5:6:7:8:9')).toBeNull();
      expect(DataMasking._expandIPv6('zzzz::1')).toBeNull();
    });
  });

  describe('HMACSigner', () => {
    const signer = new HMACSigner('test-hmac-secret-1234');
    test('sign/verify 正常往返', () => {
      const sig = signer.sign('payload');
      expect(sig).toMatch(/^[0-9a-f]{64}$/);
      expect(signer.verify('payload', sig)).toBe(true);
    });

    test('verify：篡改/错 payload/非 hex/空值/长度不符 一律 false', () => {
      const sig = signer.sign('payload');
      expect(signer.verify('other', sig)).toBe(false);
      expect(signer.verify('payload', `${sig.slice(0, -2)}00`)).toBe(false);
      expect(signer.verify('payload', 'not-hex!')).toBe(false);
      expect(signer.verify('payload', '')).toBe(false);
      expect(signer.verify('payload', null)).toBe(false);
      expect(signer.verify('payload', 123)).toBe(false);
      // 长度不同的合法 hex
      expect(signer.verify('payload', 'abcd')).toBe(false);
    });

    test('实例独立性：不同密钥签名不互通', () => {
      const other = new HMACSigner('another-secret-key');
      expect(other.verify('payload', signer.sign('payload'))).toBe(false);
    });
  });

  describe('HashUtils', () => {
    test('sha256/sha512 带盐与不带盐', () => {
      expect(HashUtils.sha256('data')).toMatch(/^[0-9a-f]{64}$/);
      expect(HashUtils.sha256('data', 'salt')).not.toBe(HashUtils.sha256('data'));
      expect(HashUtils.sha512('data')).toMatch(/^[0-9a-f]{128}$/);
    });

    test('pbkdf2（默认 100000 次迭代）派生密钥可复现且盐敏感', async () => {
      const k1 = await HashUtils.pbkdf2('pwd', 'salt-a');
      const k2 = await HashUtils.pbkdf2('pwd', 'salt-a');
      const k3 = await HashUtils.pbkdf2('pwd', 'salt-b');
      expect(k1).toBe(k2);
      expect(k1).not.toBe(k3);
      expect(k1).toMatch(/^[0-9a-f]{64}$/);
    });

    test('generateSalt 长度符合 2×bytes；randomString 输出不超过指定长度', () => {
      expect(HashUtils.generateSalt(16)).toMatch(/^[0-9a-f]{32}$/);
      // base64 去除非字母数字字符后可能略短于请求长度
      const s = HashUtils.randomString(32);
      expect(s.length).toBeGreaterThan(0);
      expect(s.length).toBeLessThanOrEqual(32);
    });
  });

  describe('AESCipher', () => {
    test('GCM 加解密往返；密文不可预测（随机 IV）', () => {
      const cipher = new AESCipher('unit-test-aes-key-0123456789abcdef');
      const ct1 = cipher.encrypt('秘密内容');
      const ct2 = cipher.encrypt('秘密内容');
      expect(ct1).toMatch(/^gcm:/);
      expect(ct1).not.toBe(ct2);
      expect(cipher.decrypt(ct1)).toBe('秘密内容');
    });

    test('GCM 密文被篡改 → final() 认证失败抛错', () => {
      const cipher = new AESCipher('unit-test-aes-key-0123456789abcdef');
      const ct = cipher.encrypt('tamper-me');
      const parts = ct.split(':');
      const flipped = parts[3].slice(0, -2) + (parts[3].endsWith('AA') ? 'BB' : 'AA');
      expect(() => cipher.decrypt(`gcm:${parts[1]}:${parts[2]}:${flipped}`)).toThrow();
    });

    test('格式校验：空串/坏格式/坏 GCM 段数拒绝', () => {
      const cipher = new AESCipher('unit-test-aes-key-0123456789abcdef');
      expect(() => cipher.decrypt('')).toThrow('密文为空');
      expect(() => cipher.decrypt(123)).toThrow();
      expect(() => cipher.decrypt('notgcm:a:b')).toThrow();
    });

    test('默认实例可用（环境已注入 AES_SECRET_KEY）', () => {
      const ct = aesCipher.encrypt('shared');
      expect(aesCipher.decrypt(ct)).toBe('shared');
    });

    test('hmacSigner 默认实例可用', () => {
      expect(hmacSigner.verify('x', hmacSigner.sign('x'))).toBe(true);
    });
  });
});

describe('captchaService 缺口覆盖', () => {
  // generate 不返回答案文本（{captchaId, svg}）：mock svg-captcha 固定答案，
  // 使 happy path / 一次性消费 / 大小写不敏感 可测（与既有 captcha 套件同口径）
  let captchaService;

  beforeAll(() => {
    jest.doMock('svg-captcha', () => ({
      create: jest.fn(() => ({ data: '<svg>mock</svg>', text: 'ABCD' })),
    }));
    captchaService = require('../../services/captchaService');
  });

  afterAll(() => {
    jest.dontMock('svg-captcha');
    jest.resetModules();
  });

  test('generate 返回 captchaId + svg', async () => {
    const cap = await captchaService.generate();
    expect(cap.captchaId).toBeTruthy();
    expect(cap.svg).toContain('<svg');
  });

  test('verify：正确通过、一次性消费（无论成败都删除）', async () => {
    const cap = await captchaService.generate();
    expect(await captchaService.verify(cap.captchaId, 'ABCD')).toBe(true);
    // 一次性：同一 id 二次校验失败
    expect(await captchaService.verify(cap.captchaId, 'ABCD')).toBe(false);
  });

  test('verify：错误答案 / 不存在 id / 空入参拒绝', async () => {
    const cap = await captchaService.generate();
    expect(await captchaService.verify(cap.captchaId, 'XXXX')).toBe(false);
    expect(await captchaService.verify('nonexistent-id', 'ABCD')).toBe(false);
    expect(await captchaService.verify('', '')).toBe(false);
    expect(await captchaService.verify(null, null)).toBe(false);
  });

  test('verify 大小写不敏感', async () => {
    const cap = await captchaService.generate();
    expect(await captchaService.verify(cap.captchaId, 'abcd')).toBe(true);
  });
});

describe('userPermissionService 缺口覆盖', () => {
  let mongoose;
  let User;
  let Role;
  let Permission;
  let svc;
  let testUserId;

  beforeAll(async () => {
    mongoose = require('mongoose');
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    Role = require('../../models/Role');
    Permission = require('../../models/Permission');
    svc = require('../../services/userPermissionService');

    const { randomPassword } = require('../helpers/buildLoginEnvelope');
    const stamp = `ups${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);
    const permA = await Permission.create({
      name: 'UPS读',
      code: `ups${stamp}:read`,
      type: 'api',
      module: 'ups',
    });
    // 模块通配：hasPermission 的 `${mod}:*` 分支依赖用户实际持有该通配码
    const permWild = await Permission.create({
      name: 'UPS通配',
      code: `ups${stamp}:*`,
      type: 'api',
      module: 'ups',
    });
    const role = await Role.create({
      name: 'UPS角色',
      code: `UPS_${stamp}`,
      level: 5,
      permissions: [permA._id, permWild._id],
    });
    const user = await User.create({
      username: `upsuser${stamp}`,
      email: `ups${stamp}@example.com`,
      password: randomPassword(),
      roles: [role._id],
    });
    testUserId = String(user._id);
  });

  afterAll(async () => {
    svc.stopCleanup();
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  test('getPermissions：未命中查库聚合，返回角色权限码', async () => {
    const perms = await svc.getPermissions(testUserId);
    expect(perms.length).toBeGreaterThan(0);
    expect(perms.some((p) => p.startsWith('ups'))).toBe(true);
  });

  test('getPermissions：命中缓存（两次结果一致）', async () => {
    const first = await svc.getPermissions(testUserId);
    const second = await svc.getPermissions(testUserId);
    expect(second).toEqual(first);
  });

  test('invalidatePermissionCache(userId)：仅失效该用户', async () => {
    svc.invalidatePermissionCache(testUserId);
    const perms = await svc.getPermissions(testUserId);
    expect(Array.isArray(perms)).toBe(true);
  });

  test('invalidatePermissionCache()：全局失效', async () => {
    svc.invalidatePermissionCache();
    const perms = await svc.getPermissions(testUserId);
    expect(perms.length).toBeGreaterThan(0);
  });

  test('getPermissions：不存在的用户返回空数组（负缓存）', async () => {
    const perms = await svc.getPermissions('000000000000000000000000');
    expect(perms).toEqual([]);
  });

  test('hasPermission：精确 / 模块通配 / 未持有', async () => {
    const perms = await svc.getPermissions(testUserId);
    const owned = perms[0];
    const [module] = owned.split(':');
    expect(await svc.hasPermission(testUserId, owned)).toBe(true);
    expect(await svc.hasPermission(testUserId, `${module}:anything`)).toBe(true);
    expect(await svc.hasPermission(testUserId, 'nonexistent:perm')).toBe(false);
  });
});

describe('statsCache 缺口覆盖', () => {
  const statsCache = require('../../services/statsCache');

  afterAll(() => {
    statsCache.stopCleanup();
  });

  test('get/set 往返返回 {hit, data} 信封', () => {
    statsCache.set('sc:k1', { v: 1 });
    expect(statsCache.get('sc:k1')).toEqual({ hit: true, data: { v: 1 } });
  });

  test('TTL（秒）过期后 {hit:false}', async () => {
    statsCache.set('sc:ttl', { v: 2 }, 1);
    expect(statsCache.get('sc:ttl').hit).toBe(true);
    await new Promise((r) => setTimeout(r, 1100));
    expect(statsCache.get('sc:ttl')).toEqual({ hit: false });
  });

  test('del 删除单条', () => {
    statsCache.set('sc:del', { v: 3 });
    statsCache.del('sc:del');
    expect(statsCache.get('sc:del').hit).toBe(false);
  });

  test('invalidateByUserId 按前缀 stats:{userId}: 清除', () => {
    statsCache.set('stats:uid-x:a', { v: 1 });
    statsCache.set('stats:uid-x:b', { v: 2 });
    statsCache.set('stats:uid-y:a', { v: 3 });
    statsCache.invalidateByUserId('uid-x');
    expect(statsCache.get('stats:uid-x:a').hit).toBe(false);
    expect(statsCache.get('stats:uid-x:b').hit).toBe(false);
    expect(statsCache.get('stats:uid-y:a').hit).toBe(true);
  });

  test('容量上限：越界触发清扫，最旧被清、最新保留', () => {
    for (let i = 0; i < 520; i++) {
      statsCache.set(`sc:bulk:${i}`, { i }, 60);
    }
    // 清扫按 lastAccess 最旧优先：最早写入的 bulk:0 被清，最新的 bulk:519 保留
    expect(statsCache.get('sc:bulk:0').hit).toBe(false);
    expect(statsCache.get('sc:bulk:519').hit).toBe(true);
  });
});
