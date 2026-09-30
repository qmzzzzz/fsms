/**
 * PII 字段加密（P1-②，2026-09-30）——at-rest 加密的单一事实来源
 *
 * 审计缺口核查（deliverables/安全缺口核查-2026-09-30.md P1-②）指出：
 * realName/phone 以明文入库，且 utils/encryption.js 的消费点全部是密钥/MFA
 * secret，没有一处用于业务 PII —— 一旦库文件或备份泄露，PII 即刻可用
 * （个保法第 51 条要求加密/去标识化）。
 *
 * 加密范围（2026-09-30 决策修订）：**当前只覆盖 phone**。realName 暂保持明文——
 * 姓名片段模糊检索是用户列表的日常能力，正则对密文不成立，加密它等于砍掉该
 * 能力；转入加密需先给姓名检索另立方案（独立检索索引/搜索引擎），届时随迁移
 * 脚本一起走。
 *
 * 设计：
 *   - phone 走 **随机 IV 的 AES-256-GCM**，密文格式带版本前缀
 *     `enc.v1.<iv>.<ct|tag>`，供轮换脚本按版本识别与重加密；
 *   - 精确检索不靠"确定性加密密文"（那会把相等模式直接泄漏在密文列里），
 *     而是独立的 **HMAC 检索键**（User.phoneKey，schema 上 select:false + 索引）：
 *     相等性只在一个键控字段上成立，密文列本身不可链接；
 *   - **存量明文透传**：decryptPii 对不带版本前缀的值原样返回——旧数据行在
 *     迁移脚本（scripts/migrate-pii-encryption.js）跑完之前照常可读，
 *     迁移与业务发布互不阻塞；
 *   - 密钥从 AES_SECRET_KEY 派生（HKDF 式域分离标签），不引入第二把业务密钥；
 *     轮换 AES_SECRET_KEY 时按 scripts/secret-rotation.md 流程，PII 列由
 *     migrate-pii-encryption.js --rotate 重加密。
 *
 * 已知边界（如实记录）：
 *   - 检索键只支持**精确匹配**（phone 本就无模糊检索需求）；
 *   - 检索键的相等性 = 归一化（trim + lowercase）后的相等性，与邮箱口径一致。
 */

const crypto = require('crypto');

const VERSION_PREFIX = 'enc.v1.';

/** 由主密钥派生子密钥：域分离标签保证「同一把主密钥、不同用途」互不混用 */
const deriveKey = (purpose) =>
  crypto
    .createHash('sha256')
    .update(`${process.env.AES_SECRET_KEY || ''}:${purpose}`, 'utf8')
    .digest();

/** 加解密都用当前版本密钥；缺失时直接抛错（fail-closed），绝不静默退化为明文写入 */
const currentAesKey = () => {
  const key = deriveKey('pii:aes:v1');
  if (!process.env.AES_SECRET_KEY) {
    throw new Error('PII 加密不可用：AES_SECRET_KEY 未设置（拒绝以明文写入 PII 字段）');
  }
  return key;
};

/**
 * 加密一个 PII 值（随机 IV AES-256-GCM）。
 * 空值/已加密值原样返回（幂等：pre-validate 钩子可能重复进入）。
 * @param {string|undefined|null} value 明文
 * @returns {string|undefined|null} `enc.v1.<iv>.<ct|tag>` 密文
 */
const encryptPii = (value) => {
  if (value === undefined || value === null) return value;
  if (typeof value !== 'string') return value;
  if (value === '' || value.startsWith(VERSION_PREFIX)) return value;
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', currentAesKey(), iv);
  const ct = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${VERSION_PREFIX}${iv.toString('base64')}.${Buffer.concat([ct, tag]).toString('base64')}`;
};

/**
 * 解密一个 PII 值。**存量明文透传**：不带版本前缀的值原样返回，
 * 使迁移前的旧数据行照常可读（读路径永远不需要先跑迁移脚本）。
 * 密文解密失败（密钥错误/数据被改）直接抛错——GCM 的认证标签就是为此存在的，
 * 吞掉它等于把"数据被篡改"静默降级成"读出乱码"。
 * @param {string|undefined|null} value 密文或存量明文
 * @returns {string|undefined|null} 明文
 */
const decryptPii = (value) => {
  if (value === undefined || value === null) return value;
  if (typeof value !== 'string' || !value.startsWith(VERSION_PREFIX)) return value;
  const [ivB64, dataB64] = value.slice(VERSION_PREFIX.length).split('.');
  if (!ivB64 || !dataB64) {
    throw new Error('PII 密文形态非法：缺少 IV 或数据段');
  }
  const iv = Buffer.from(ivB64, 'base64');
  const data = Buffer.from(dataB64, 'base64');
  const tag = data.subarray(data.length - 16);
  const ct = data.subarray(0, data.length - 16);
  const decipher = crypto.createDecipheriv('aes-256-gcm', currentAesKey(), iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8');
};

/**
 * 精确检索键：HMAC-SHA256（归一化后），hex 定长。
 * 归一化口径与 normalizeEmailKey 一致（trim + lowercase）——中文姓名不受影响，
 * 拉丁字母姓名大小写归一，避免"张三/张三 "两个键。
 * @param {string|undefined|null} value 明文（调用方传解密后的值）
 * @returns {string} 64 位 hex；空值返回空串（不产生可命中空串的键）
 */
const piiSearchKey = (value) => {
  if (typeof value !== 'string' || value.trim() === '') return '';
  const hmacKey = deriveKey('pii:hmac:v1');
  return crypto
    .createHmac('sha256', hmacKey)
    .update(value.trim().toLowerCase(), 'utf8')
    .digest('hex');
};

module.exports = { encryptPii, decryptPii, piiSearchKey, VERSION_PREFIX };
