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

/**
 * 主密钥取值判据（fail-closed，加密侧与检索键侧共用这唯一一个口子）。
 *
 * 为什么要拦 `'undefined'` / `'null'` 这类**字面量**，而不只是拦空值：
 * `process.env.X = undefined` 被 Node 强转成字符串 `"undefined"`（实测，v18/v22/v24 同），
 * 于是「非空即通过」的写法在这三种现场全部恒真通过——
 *   ① 运维在 `.env` 里写了 `AES_SECRET_KEY=undefined`（dotenv 给出的就是这四个字符）；
 *   ② 轮换脚本 `process.env.AES_SECRET_KEY = process.env.PII_ROTATION_CURRENT_KEY`
 *      而后者从未被设置（见 scripts/migrate-pii-encryption.js 的 decryptWith）；
 *   ③ CI/容器少传一个变量，模板把变量名展开成了字面量。
 * 后果不是报错而是**静默降级**：全部 PII 落到 `sha256("undefined:pii:aes:v1")` 这把
 * 任何读得到源码的人都能算出的密钥上，且轮换脚本照样打印「✅ 完成」。
 * 密钥缺失必须响，绝不允许拿一个可推导常量去加密。
 */
const DEGENERATE_KEY_LITERALS = new Set(['undefined', 'null', 'nan', '']);
const requireMasterSecret = () => {
  const raw = process.env.AES_SECRET_KEY;
  if (typeof raw !== 'string' || DEGENERATE_KEY_LITERALS.has(raw.trim().toLowerCase())) {
    throw new Error(
      'PII 加密不可用：AES_SECRET_KEY 未设置为有效值' +
        '（空/未设置/字面量 undefined|null|nan 一律拒绝，宁可不写也不落到可推导常量密钥上）'
    );
  }
  return raw;
};

/** 由主密钥派生子密钥：域分离标签保证「同一把主密钥、不同用途」互不混用 */
const deriveKey = (purpose) =>
  crypto.createHash('sha256').update(`${requireMasterSecret()}:${purpose}`, 'utf8').digest();

/** 加解密都用当前版本密钥；密钥不可用时由 masterSecret 抛错（fail-closed），绝不静默退化为明文写入 */
const currentAesKey = () => deriveKey('pii:aes:v1');

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
 * 使迁移前的旧数据行照常可读（读路径不需要先跑迁移脚本）。
 * 这句契约的边界写清楚，原先的「永远」是越界的：**透传认的是"没有版本前缀"，
 * 不认密钥**。存量**明文**确实永远可读；存量**旧钥密文**在 AES_SECRET_KEY 换过之后
 * 必抛（实测 `Unsupported state or unable to authenticate data`，GCM 认证标签的作用），
 * 那正是 `migrate-pii-encryption.js --rotate` 存在的理由——它跑完之后这条才重新成立。
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
 *
 * ⚠️ 空值返回的是**空串本身**，而空串是一个查得到的键：`find({ phoneKey: '' })`
 * 会命中所有无手机号的行。原先这句注释写作「空值不产生键」，是把它说成了
 * 已规避的风险——实际形态是 `User.phoneKey` 的 default `''`（`pre('validate')`
 * 钩子在明文为空时也写 `''`），且索引非唯一，所以今天没有任何错误提示。
 * 判据因此落在调用侧：**必须先确认明文非空再算键**，不要把用户输入直接喂进来。
 * （全仓目前无按 phoneKey 的查询点，这条是给第一个写它的人的。）
 *
 * @param {string|undefined|null} value 明文（调用方传解密后的值）
 * @returns {string} 64 位 hex；空值/纯空白返回空串
 */
const piiSearchKey = (value) => {
  if (typeof value !== 'string' || value.trim() === '') return '';
  const hmacKey = deriveKey('pii:hmac:v1');
  return crypto
    .createHmac('sha256', hmacKey)
    .update(value.trim().toLowerCase(), 'utf8')
    .digest('hex');
};

module.exports = {
  encryptPii,
  decryptPii,
  piiSearchKey,
  requireMasterSecret,
  VERSION_PREFIX,
};
