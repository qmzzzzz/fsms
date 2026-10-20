/**
 * PII 字段加密——at-rest 加密的单一事实来源
 *
 * 审计缺口：
 * realName/phone 以明文入库，且 utils/encryption.js 的消费点全部是密钥/MFA
 * secret，没有一处用于业务 PII —— 一旦库文件或备份泄露，PII 即刻可用
 * （个保法第 51 条要求加密/去标识化）。
 *
 * 加密范围（2026-10-16 扩到 email）：覆盖 `User.phone`、`User.email`、
 * `FireAlarm.reporter.phone`。realName 仍保持明文——姓名片段模糊检索是用户列表的
 * 日常能力，正则对密文不成立，加密它等于砍掉该能力；转入加密需先给姓名检索另立
 * 方案（与 email 的做法同族，见下方 piiSubstringKeys）。
 *
 * 设计：
 *   - phone 走 **随机 IV 的 AES-256-GCM**，密文格式带版本前缀，供轮换脚本按版本
 *     识别与重加密：`enc.v1.<iv>.<ct|tag>`（无行绑定）→ `enc.v2.<iv>.<ct|tag>`
 *     （AAD 绑定 <subjectId>:<field>，见下）；
 *   - **v2 AAD 行绑定**（2026-10-01 审计）：同一把派生钥下 v1 密文可以跨行搬运——
 *     持 DB 写权限者把受害者的 enc.v1 串复制到自己那行，读侧 getter 就会解出
 *     受害者的手机号明文，一次 DB 写权限兑换任意用户 PII（正是威胁模型自认的
 *     「持 DB 写权限的内部人」位面）。v2 把 `pii:v2:<subjectId>:<field>` 作为
 *     GCM 的 AAD 灌进认证标签：换行、换字段、缺上下文，解密一律认证失败。
 *     v1 读侧兼容保留（存量行迁移前照常可读），migrate-pii-encryption.js 会把
 *     v1 行升级为 v2；**写侧一律产 v2**；
 *   - IV 长度（12 字节）与数据段下限（≥16 字节认证标签）在形态层前置校验，
 *     不再让 `subarray` 负索引静默变形后才在 GCM 原生报错里迷失；
 *   - 精确检索不靠"确定性加密密文"（那会把相等模式直接泄漏在密文列里），
 *     而是独立的 **HMAC 检索键**（User.phoneKey，schema 上 select:false + 索引）：
 *     相等性只在一个键控字段上成立，密文列本身不可链接；
 *   - **存量明文透传**：decryptPii 对不带版本前缀的值原样返回——旧数据行在
 *     迁移脚本（scripts/migrate-pii-encryption.js）跑完之前照常可读，
 *     迁移与业务发布互不阻塞；
 *   - 密钥从 AES_SECRET_KEY 派生（HKDF 式域分离标签），不引入第二把业务密钥；
 *     v1/v2 使用不同的派生标签（pii:aes:v1 / pii:aes:v2），版本间密钥互不混用；
 *     轮换 AES_SECRET_KEY 时按 scripts/secret-rotation.md 流程，PII 列由
 *     migrate-pii-encryption.js --rotate 重加密。
 *
 * 已知边界（如实记录）：
 *   - 精确检索键（piiSearchKey）只支持**整串相等**；子串检索另有一套 n-gram 盲索引
 *     （piiSubstringKeys），它给的是**候选超集**而非精确子串，边界见该函数注释；
 *   - 检索键的相等性 = 归一化（trim + lowercase）后的相等性，与邮箱口径一致。
 */

const crypto = require('crypto');

const VERSION_PREFIX = 'enc.v1.';
const VERSION_PREFIX_V2 = 'enc.v2.';

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

/**
 * v2 的 AAD 绑定上下文判据：{ subjectId, field } 均须为非空字符串。
 * 单独成函数是因为 encrypt 与 decrypt 两侧共用同一构造（AAD 不一致 = 解密必失败），
 * 也让「缺上下文」的报错在形态层就说清楚，而不是落进 GCM 原生认证错误里。
 */
const buildAad = (aadContext) => {
  const subjectId = aadContext && aadContext.subjectId;
  const field = aadContext && aadContext.field;
  if (
    typeof subjectId !== 'string' ||
    subjectId === '' ||
    typeof field !== 'string' ||
    field === ''
  ) {
    throw new Error(
      'PII v2 密文需要 AAD 绑定上下文：{ subjectId, field } 均须为非空字符串' +
        '（v2 把行身份灌进 GCM 认证标签，缺上下文的解密请求无法被满足）'
    );
  }
  return `pii:v2:${subjectId}:${field}`;
};

/**
 * 加密一个 PII 值（随机 IV AES-256-GCM）。
 * 传 aadContext（{ subjectId, field }）时产出 **v2**（AAD 行绑定）——写侧一律走这条；
 * 不传时产出 v1（旧格式，仅为让旧调用方/旧测试继续可用——存量行升级由迁移脚本负责）。
 * 空值/已加密值原样返回（幂等：pre-validate 钩子可能重复进入）。
 * @param {string|undefined|null} value 明文
 * @param {{subjectId: string, field: string}|null} [aadContext] v2 行绑定上下文
 * @returns {string|undefined|null} `enc.v2.<iv>.<ct|tag>`（v2）或 `enc.v1.<iv>.<ct|tag>`
 */
const encryptPii = (value, aadContext = null) => {
  if (value === undefined || value === null) return value;
  if (typeof value !== 'string') return value;
  if (value === '' || value.startsWith(VERSION_PREFIX) || value.startsWith(VERSION_PREFIX_V2)) {
    return value;
  }
  const isV2 = aadContext !== null;
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(
    'aes-256-gcm',
    deriveKey(isV2 ? 'pii:aes:v2' : 'pii:aes:v1'),
    iv
  );
  if (isV2) cipher.setAAD(Buffer.from(buildAad(aadContext), 'utf8'));
  const ct = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  const prefix = isV2 ? VERSION_PREFIX_V2 : VERSION_PREFIX;
  return `${prefix}${iv.toString('base64')}.${Buffer.concat([ct, tag]).toString('base64')}`;
};

/**
 * 解密一个 PII 值。**存量明文透传**：不带版本前缀的值原样返回，
 * 使迁移前的旧数据行照常可读（读路径不需要先跑迁移脚本）。
 * 这句契约的边界写清楚，原先的「永远」是越界的：**透传认的是"没有版本前缀"，
 * 不认密钥**。存量**明文**确实永远可读；存量**旧钥密文**在 AES_SECRET_KEY 换过之后
 * 必抛（实测 `Unsupported state or unable to authenticate data`，GCM 认证标签的作用），
 * 那正是 `migrate-pii-encryption.js --rotate` 存在的理由——它跑完之后这条才重新成立。
 *
 * 版本分派：v2（enc.v2.）**必须**带与加密时一致的 aadContext——行身份灌在认证标签里，
 * 换行/换字段/缺上下文都表现为 GCM 认证失败（这正是"密文跨行搬运"被拦下的形态）；
 * v1（enc.v1.）读侧兼容保留，不需要上下文（getter 统一传也不受影响）。
 * 密文解密失败（密钥错误/数据被改/AAD 不符）直接抛错——GCM 的认证标签就是为此存在的，
 * 吞掉它等于把"数据被篡改"静默降级成"读出乱码"。
 *
 * 形态前置校验的次序是刻意的：**主密钥判据最先**（密钥不可用必须最先响，fail-closed），
 * 之后才是 IV 长度 / 数据段下限——原先 data 不足 16 字节时 `subarray` 负索引静默变形
 * （整段当 tag、空 ct），要到 setAuthTag/final 才以 GCM 原生报错浮现，错误类型与
 * "形态非法"这一档混在一起。
 * @param {string|undefined|null} value 密文或存量明文
 * @param {{subjectId: string, field: string}|null} [aadContext] v2 行绑定上下文
 * @returns {string|undefined|null} 明文
 */
const decryptPii = (value, aadContext = null) => {
  if (value === undefined || value === null) return value;
  if (typeof value !== 'string') return value;
  let prefix;
  let keyPurpose;
  let aad = null;
  if (value.startsWith(VERSION_PREFIX_V2)) {
    prefix = VERSION_PREFIX_V2;
    keyPurpose = 'pii:aes:v2';
    aad = Buffer.from(buildAad(aadContext), 'utf8');
  } else if (value.startsWith(VERSION_PREFIX)) {
    prefix = VERSION_PREFIX;
    keyPurpose = 'pii:aes:v1';
  } else {
    return value; // 存量明文透传
  }
  // 主密钥判据最先：密钥不可用时无论密文形态如何都最先响（与加密侧同一口径）
  const key = deriveKey(keyPurpose);
  const [ivB64, dataB64] = value.slice(prefix.length).split('.');
  if (!ivB64 || !dataB64) {
    throw new Error('PII 密文形态非法：缺少 IV 或数据段');
  }
  const iv = Buffer.from(ivB64, 'base64');
  const data = Buffer.from(dataB64, 'base64');
  if (iv.length !== 12) {
    throw new Error('PII 密文形态非法：IV 段必须为 12 字节');
  }
  if (data.length < 16) {
    throw new Error('PII 密文形态非法：数据段不足以容纳 16 字节认证标签');
  }
  const tag = data.subarray(data.length - 16);
  const ct = data.subarray(0, data.length - 16);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  if (aad) decipher.setAAD(aad);
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

/** 子串盲索引的 n-gram 长度（3 = 拉丁邮箱地址上「能搜到片段」与索引体积的折中） */
const SUBSTRING_GRAM_SIZE = 3;

/**
 * 子串盲索引：把归一化后的明文切成**重叠 n-gram**，逐个 HMAC。
 *
 * 存在的唯一理由：`User.email` 加密后，用户管理的「按邮箱片段搜索」
 * （`userService.buildListQuery` 的 `{ email: new RegExp(...) }`）会对密文恒不命中、
 * **静默失效**（不报错、不告警、只是搜不到）。精确检索键（piiSearchKey）救不了它——
 * 那个键只支持「整串相等」。要在密文列上保住**子串**语义，只能让每行预先登记
 * 它包含的全部片段指纹，查询侧把搜索串也切成同样粒度再求交集。
 *
 * 与 piiSearchKey 的两点刻意差异：
 *   ① 派生标签不同（`pii:ngram:v1` vs `pii:hmac:v1`）——域分离，两个键族互不可推导；
 *   ② **不 trim 成空串键**：长度不足 n 的输入返回空数组（而不是像 piiSearchKey 那样
 *      返回 `''`）。原因在调用侧：查询要用 `{ emailGrams: { $all: [...] } }`，
 *      而 `$all: []` 在 MongoDB 里**匹配全部文档**——返回空串键会让「搜 2 个字符」
 *      退化成「返回所有用户」。调用方必须把空数组当作「该分支不参与 $or」。
 *
 * 已知边界（如实记录，不是待办）：
 *   - **候选超集**：n-gram 是无位置信息的，`abc` 与 `bcd` 同时命中的行未必包含连续的
 *     `abcd`（`abcXbcd` 也会命中）。搜索串越长，多余候选的比例越低。要精确子串只能
 *     解密后在内存里二次过滤，而过滤发生在分页之前 —— 代价是把候选集整表读进进程，
 *     与 at-rest 加密的初衷相反。本仓接受"略宽的候选集"，不为此把明文拉回内存。
 *   - **体积随明文线性增长**：gram 数量 = 归一化长度 − n + 1，去重后更少。
 *     `User.email` 的明文期长度上限 254（`models/User.js` 钩子里的 maxlength）
 *     把上界钉在 252 个 gram；典型邮箱（≤ 40 字符）约 20~40 个。
 *   - **相等模式可见**：同一片段在不同行产生同一个 gram，持库者可看到"哪些行共享同一片段"
 *     的频率分布（拿不到明文，除非同时持有密钥）。这是所有盲索引的固有代价，
 *     换取的是"不必为了搜索而放弃加密"。
 *
 * @param {string|undefined|null} value 明文（调用方传解密后的值）
 * @param {number} [gramSize] 片段长度，默认 SUBSTRING_GRAM_SIZE
 * @returns {string[]} 去重并排序的 64 位 hex 片段键；长度不足或非字符串时返回 `[]`
 */
const piiSubstringKeys = (value, gramSize = SUBSTRING_GRAM_SIZE) => {
  if (typeof value !== 'string') return [];
  const normalized = value.trim().toLowerCase();
  if (normalized.length < gramSize) return [];
  const hmacKey = deriveKey('pii:ngram:v1');
  const keys = new Set();
  for (let i = 0; i + gramSize <= normalized.length; i += 1) {
    keys.add(
      crypto
        .createHmac('sha256', hmacKey)
        .update(normalized.slice(i, i + gramSize), 'utf8')
        .digest('hex')
    );
  }
  return [...keys].sort();
};

module.exports = {
  encryptPii,
  decryptPii,
  piiSearchKey,
  piiSubstringKeys,
  SUBSTRING_GRAM_SIZE,
  requireMasterSecret,
  VERSION_PREFIX,
  VERSION_PREFIX_V2,
};
