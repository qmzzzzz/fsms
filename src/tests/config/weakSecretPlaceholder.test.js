/**
 * P0-4：弱密钥校验的占位符/低熵判定
 *
 * 背景：审计发现 .env.example 的 JWT 占位符（'<替换为 openssl rand -base64 48 的输出>'，
 * 33 字符）能通过生产校验——旧实现只有「黑名单 + 长度 < 32」两重判定，长度足够
 * 就放行。照抄模板起生产 = JWT 密钥公开可知 = 可离线伪造任意用户（含超管）令牌。
 *
 * 本文件锁定两件事，且**都以 .env.example / generate-secrets.js 的真实产物为准**：
 *   1. 模板里的每一个密钥占位符必须判弱（改回可用的占位符 = 校验形同虚设）；
 *   2. scripts/generate-secrets.js 实际生成形式的高熵密钥必须判强
 *      （否则修完 P0-4 会让标准生成流程反而起不来）。
 *
 * 与 src/tests/config/validate.test.js 的分工：那个文件用固定字面量夹具覆盖
 * validateConfig 的整体编排；本文件只管 isWeakSecret 的判定边界，
 * 且刻意从 .env.example 读真实占位符，避免「改了模板忘了改测试」。
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const { isWeakSecret } = require('../../config/validate');

/**
 * 解析 .env.example，返回「变量名 -> 取值」。
 * 同时接受生效行（`NAME=value`）与注释行（`# NAME=value`）——
 * 模板里可选变量以注释形式给出，被 isWeakSecret 校验的四个密钥都在生效行。
 */
const parseEnvExample = () => {
  const file = path.join(__dirname, '../../../.env.example');
  const out = {};
  for (const raw of fs.readFileSync(file, 'utf8').split(/\r?\n/)) {
    const m = raw.match(/^\s*#?\s*([A-Z][A-Z0-9_]*)\s*=(.*)$/);
    if (!m) continue;
    out[m[1]] = m[2].trim();
  }
  return out;
};

const ENV_EXAMPLE = parseEnvExample();

// 被 collectSecretErrors 逐个送进 isWeakSecret 的四个变量（validate.js）。
// 若日后新增受校验的密钥变量，此清单必须同步——否则新变量没有占位符回归保护。
const GUARDED_SECRET_VARS = ['JWT_SECRET', 'JWT_REFRESH_SECRET', 'AES_SECRET_KEY', 'HMAC_SECRET'];

describe('P0-4：.env.example 的密钥占位符必须判弱', () => {
  test('四个受校验变量都在 .env.example 中有取值（否则本文件的覆盖是假的）', () => {
    for (const name of GUARDED_SECRET_VARS) {
      // 只断 toBeDefined() 时，`JWT_SECRET=`（空值）也算过：isWeakSecret('') 返回 true，
      // 下面的「判弱」用例照样绿——但那已经不是在验占位符形态，只是空值碰巧判弱。
      // 断非空 + 实测统一取值 <CHANGE_ME>（下方另有专门用例锁定该字符串）。
      expect(ENV_EXAMPLE[name]).toBeTruthy();
      expect(ENV_EXAMPLE[name]).toBe('<CHANGE_ME>');
    }
  });

  test.each(GUARDED_SECRET_VARS)('%s 的 .env.example 取值判弱', (name) => {
    expect(isWeakSecret(ENV_EXAMPLE[name])).toBe(true);
  });

  test('占位符必须是显式 <CHANGE_ME> 形态，而不是「看起来像命令输出」的说明文字', () => {
    // 关键回归点：旧占位符 '<替换为 openssl rand -base64 48 的输出>' 长 33 字符，
    // 长度足以骗过旧校验；改为 <CHANGE_ME> 后既短又命中黑名单，双重拦截。
    expect(ENV_EXAMPLE.JWT_SECRET).toBe('<CHANGE_ME>');
    expect(ENV_EXAMPLE.JWT_REFRESH_SECRET).toBe('<CHANGE_ME>');
  });
});

describe('P0-4：判据覆盖（占位符形态 / 低熵 / 循环拼接）', () => {
  test.each([
    ['旧模板占位符（33 字符，曾通过校验）', '<替换为 openssl rand -base64 48 的输出>'],
    ['<CHANGE_ME>', '<CHANGE_ME>'],
    ['change-me-in-production 短语', 'change-me-in-production-please-rotate-now'],
    ['changeme 重复拼接', 'changemechangemechangemechangeme'],
    ['your- 前缀示例值', 'your-super-secret-jwt-key-goes-right-here'],
    ['xxx 占位', 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'],
    ['全同字符', 'a'.repeat(40)],
    ['循环拼接（口令重复）', 'passwordpasswordpasswordpassword'],
    ['全数字', '1234567890123456789012345678901234'],
    ['长度不足', 'short-secret'],
    ['空串', ''],
    ['黑名单值', 'default-secret-change-in-production'],
  ])('%s → 判弱', (_label, value) => {
    expect(isWeakSecret(value)).toBe(true);
  });
});

describe('P0-4：高熵密钥必须判强（防「修完反而起不来」）', () => {
  // 样本取自 scripts/generate-secrets.js 的实际生成方式：
  //   jwt/refresh = randomBytes(48).toString('base64')  → 64 字符
  //   aes/hmac    = randomBytes(32).toString('hex')     → 64 字符
  //   admin 初始口令 = randomBytes(24).toString('base64') → 32 字符
  // 与 .env.example 注释给出的 `openssl rand -hex 16`（32 字符）——
  // 这是本函数必须放行的最弱合法形式，阈值 2.0 bit/char 就是按它定的。
  const generators = [
    ['randomBytes(48).base64（JWT 默认）', () => crypto.randomBytes(48).toString('base64')],
    ['randomBytes(32).hex（AES/HMAC 默认）', () => crypto.randomBytes(32).toString('hex')],
    ['randomBytes(24).base64（初始口令）', () => crypto.randomBytes(24).toString('base64')],
    ['randomBytes(16).hex（openssl rand -hex 16）', () => crypto.randomBytes(16).toString('hex')],
  ];

  test.each(generators)('%s → 判强（每类 200 次采样，防单次偶然）', (_label, gen) => {
    for (let i = 0; i < 200; i += 1) {
      expect(isWeakSecret(gen())).toBe(false);
    }
  });

  test('既有测试夹具（纯小写英文短语）必须仍判强——P0-4 的已知取舍', () => {
    // 这些字面量在 src/tests/config/validate.test.js 里被当作「合法强密钥」，
    // 且该文件不在本次改动写集内。它们的香农熵（3.71~3.91）与真实密钥区间重叠，
    // 因此 isWeakSecret 刻意**不**按「英文短语」一刀切——详见其函数注释的
    // 「取舍与残余风险」。此处把该取舍固化为测试：若日后有人加了「纯小写判弱」
    // 规则，这里会立刻变红，提醒他同时评估既有夹具。
    expect(isWeakSecret('strong-random-jwt-secret-that-is-long-enough')).toBe(false);
    expect(isWeakSecret('strong-random-refresh-secret-long-enough')).toBe(false);
    expect(isWeakSecret('test-aes-key-with-32-chars-minimum!!')).toBe(false);
    expect(isWeakSecret('strong-random-hmac-secret-that-is-long-enough')).toBe(false);
  });
});

describe('P0-4：validateConfig 端到端——占位符必须拦住生产启动', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    jest.resetModules();
    process.env = { ...originalEnv };
  });

  afterAll(() => {
    process.env = originalEnv;
  });

  test('生产环境使用 .env.example 的 JWT 占位符 → 致命错误且文案指向 JWT_SECRET', () => {
    process.env.NODE_ENV = 'production';
    process.env.JWT_SECRET = '<CHANGE_ME>';
    process.env.JWT_REFRESH_SECRET = 'strong-random-refresh-secret-long-enough';
    process.env.AES_SECRET_KEY = 'test-aes-key-with-32-chars-minimum!!';
    process.env.HMAC_SECRET = 'strong-random-hmac-secret-that-is-long-enough';
    process.env.MONGODB_URI = 'mongodb://prod-server:27017/db';
    process.env.CORS_ORIGIN = 'https://example.com';
    process.env.ENABLE_HTTPS = 'true';
    process.env.ALLOWED_HOSTS = 'api.example.com';
    process.env.REDIS_URL = 'redis://redis.example.com:6379';
    process.env.TRUST_PROXY_HOPS = '1';

    const { validateConfig } = require('../../config/validate');
    const logger = require('../../utils/logger');
    const messages = [];
    const mockError = jest
      .spyOn(logger, 'error')
      .mockImplementation((m) => messages.push(String(m)));
    jest.spyOn(logger, 'warn').mockImplementation(() => {});
    const mockExit = jest.spyOn(process, 'exit').mockImplementation(() => {
      throw new Error('process.exit called');
    });

    expect(() => validateConfig()).toThrow('process.exit called');
    expect(messages.join('\n')).toContain('JWT_SECRET');

    mockError.mockRestore();
    mockExit.mockRestore();
  });
});
