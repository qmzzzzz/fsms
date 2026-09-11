/**
 * MFA TOTP 种子的静态加密存储（P2-15）
 *
 * 问题：mfaSecret 原先以明文入库，仅靠 `select: false` 从查询结果中隐藏。
 * 对照同一文档里的其它凭证——password 走 bcrypt、mfaRecoveryCodes 存
 * SHA-256 摘要——只有 TOTP 种子是可直接使用的明文。数据库一旦泄露
 * （备份外泄、只读账号被拿下、日志误采集），攻击者可为任意账户离线生成
 * 有效的 6 位码，两步验证整体失效；而 password 泄露还需爆破。
 *
 * 与恢复码的区别：恢复码可以存单向摘要（校验时只需比对），
 * 但 TOTP 校验必须拿到种子本身重算 HOTP，因此只能选可逆加密。
 * 复用 encryption.js 的 AES-256-GCM（认证加密，密文被篡改会解密失败）。
 *
 * 迁移策略：密文带 `enc:v1:` 前缀。读取时无前缀即视为存量明文并原样返回，
 * 使升级后既有用户的 MFA 继续可用；下一次 enroll/enable 会自动写成密文。
 * 这样不需要停机迁移脚本，也不会把任何人锁在门外。
 *
 * 残余风险（必须明示）：AES_SECRET_KEY 与数据库同时泄露时保护失效。
 * 真正的解法是把密钥放进 KMS/HSM，此处只把「一次泄露」提升为「两处泄露」。
 */

const logger = require('./logger');

const ENC_PREFIX = 'enc:v1:';

/**
 * 惰性获取 AES 实例
 *
 * 不在模块加载时构造：AESCipher 构造函数在缺少 AES_SECRET_KEY 时会抛错，
 * 模块级构造会让整个 User 模型链在配置缺失时无法加载。
 */
let _cipher = null;
const getCipher = () => {
  if (!_cipher) {
    const { aesCipher } = require('./encryption');
    _cipher = aesCipher;
  }
  return _cipher;
};

/**
 * 判断是否为本模块产出的密文
 * @param {unknown} value
 * @returns {boolean}
 */
const isEncryptedMfaSecret = (value) => typeof value === 'string' && value.startsWith(ENC_PREFIX);

/**
 * 加密 TOTP 种子（写库前调用）
 *
 * 空值原样返回：'' 是「未配置 MFA」的正常状态，不应被加密成一段密文，
 * 否则 `if (!user.mfaSecret)` 之类的判空逻辑会全部失效。
 * @param {string} plain Base32 种子
 * @returns {string} 密文（enc:v1: 前缀）或原空值
 */
const encryptMfaSecret = (plain) => {
  if (typeof plain !== 'string' || plain.length === 0) return plain;
  if (isEncryptedMfaSecret(plain)) return plain; // 幂等：已加密不重复加密
  try {
    return ENC_PREFIX + getCipher().encrypt(plain);
  } catch (err) {
    // fail-closed：宁可让本次开启 MFA 失败，也不把明文种子写进数据库
    logger.error(`MFA 种子加密失败，拒绝以明文落库：${err.message}`);
    throw new Error('MFA_SECRET_ENCRYPT_FAILED');
  }
};

/**
 * 解密 TOTP 种子（校验前调用）
 *
 * 无前缀 → 存量明文，原样返回（迁移期兼容）。
 * 解密失败 → 返回空串而非抛错：调用方一律走「验证码错误」分支，
 * 既不泄露内部状态，也不会把 500 暴露给攻击者。
 * @param {string} stored 数据库中的值
 * @returns {string} Base32 种子；无法还原时返回 ''
 */
const decryptMfaSecret = (stored) => {
  if (typeof stored !== 'string' || stored.length === 0) return '';
  if (!isEncryptedMfaSecret(stored)) return stored;
  try {
    return getCipher().decrypt(stored.slice(ENC_PREFIX.length));
  } catch (err) {
    logger.error(`MFA 种子解密失败（密钥轮换或数据损坏？）：${err.message}`);
    return '';
  }
};

module.exports = {
  ENC_PREFIX,
  isEncryptedMfaSecret,
  encryptMfaSecret,
  decryptMfaSecret,
};
