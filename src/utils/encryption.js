/**
 * 加密工具模块
 * 提供多种加密算法支持
 */

const crypto = require('crypto');
const config = require('../config');
const logger = require('./logger');

// HashUtils.randomString 的字符表：62 个字符，配丢弃式采样（256 不能被 62 整除，
// 取模会引入偏差，所以表外的字节直接丢弃）
const RANDOM_STRING_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

// GCM 密文的字段规范。唯一权威是本模块的写入侧（encrypt 的产出形状），
// 读取侧的校验正则由这几个常量生成，避免「写入改了、校验忘了改」的漂移。
const GCM_IV_LENGTH_BYTES = 12; // AES-GCM 标准 96-bit nonce
const GCM_AUTH_TAG_LENGTH_BYTES = 16; // getAuthTag() 的标签长度
const hexOfLength = (bytes) => new RegExp(`^[0-9a-f]{${bytes * 2}}$`);
const GCM_IV_HEX = hexOfLength(GCM_IV_LENGTH_BYTES);
const GCM_TAG_HEX = hexOfLength(GCM_AUTH_TAG_LENGTH_BYTES);
// 标准 base64（toString('base64') 的产出形式）：4 字符一组，'=' 只允许作末尾填充。
// 空密文合法——明文为空时 GCM 密文本就是 0 字节。
const GCM_CIPHER_B64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

// HMAC 签名串的规范形式：小写十六进制，长度 = 摘要字节数 × 2。
// 从算法推导而不是写死 64——换算法时校验侧自动跟上，不会出现「产出 64 位、校验按别的长度」的漂移。
// dummy key 只用于问出摘要长度，不触碰实例密钥。
const hmacHexShapeOf = (algorithm) =>
  new RegExp(`^[0-9a-f]{${crypto.createHmac(algorithm, 'shape-probe').digest().length * 2}}$`);

/**
 * AES 加密解密工具类
 * 用于敏感数据的加密存储
 */
class AESCipher {
  constructor(secretKey = null) {
    // 使用 aes-256-gcm 认证加密，防止密文篡改和填充预言机攻击
    this.algorithm = 'aes-256-gcm';
    const effectiveKey = secretKey || process.env.AES_SECRET_KEY || config.aesSecret;
    if (!effectiveKey) {
      // 仅自动化测试允许回退默认密钥（测试套件会显式设置环境变量，此为兜底）
      if (process.env.NODE_ENV !== 'test') {
        throw new Error(
          '缺少 AES_SECRET_KEY：请配置至少 32 字符的强随机密钥（openssl rand -hex 32），禁止使用源码内默认密钥'
        );
      }
      logger.warn('AES 加密正在使用测试环境默认密钥（仅限 NODE_ENV=test）');
    }
    this.secret = effectiveKey || 'default-aes-key-change-in-production';
    // 确保密钥长度为 32 字节（256 位）
    this.key = crypto.createHash('sha256').update(String(this.secret)).digest();
    this.ivLength = GCM_IV_LENGTH_BYTES; // AES-GCM 推荐 96-bit (12 字节) IV
  }

  /**
   * AES-256-GCM 加密（认证加密，防篡改）
   * @param {string} text - 明文
   * @returns {string} - 格式: gcm:ivHex:authTagHex:base64Ciphertext
   */
  encrypt(text) {
    const iv = crypto.randomBytes(this.ivLength);
    const cipher = crypto.createCipheriv(this.algorithm, Buffer.from(this.key), iv);

    let encrypted = cipher.update(text, 'utf8', 'base64');
    encrypted += cipher.final('base64');

    // GCM 认证标签（16 字节），用于验证密文完整性
    const authTag = cipher.getAuthTag();

    // gcm: 前缀标识新格式，解密时自动识别
    return 'gcm:' + iv.toString('hex') + ':' + authTag.toString('hex') + ':' + encrypted;
  }

  /**
   * AES 解密
   * - 新格式 (gcm: 前缀): 使用 AES-256-GCM 解密并验证完整性
   * - 旧格式 (无前缀): AES-256-CBC 遗留路径，**默认关闭**（见下）
   *
   * P3-27：CBC 无认证，保留可用的解密入口即保留填充预言机面——
   * 攻击者若能反复投喂密文并观察「填充错误 vs 其他错误」的差异，
   * 即可在不知密钥的情况下逐字节解密。
   *
   * 现状核查：全仓 aesCipher 的唯一消费者是 utils/mfaSecret.js，
   * 它写入时一律带 `enc:v1:` 前缀且内部走 GCM——即**不存在**存量 CBC 密文。
   * 因此把 CBC 解密改为需显式开启（ALLOW_LEGACY_CBC_DECRYPT=true）：
   * 默认拒绝，从代码路径上消除该攻击面；确有历史数据需迁移时临时开启，
   * 迁移完成后移除本方法。
   *
   * @param {string} encryptedText - 密文
   * @returns {string} - 解密后的明文
   */
  decrypt(encryptedText) {
    if (typeof encryptedText !== 'string' || encryptedText.length === 0) {
      throw new Error('密文为空');
    }
    if (encryptedText.startsWith('gcm:')) {
      return this._decryptGCM(encryptedText.slice(4));
    }
    // 向后兼容旧 CBC 格式（默认禁用）
    if (process.env.ALLOW_LEGACY_CBC_DECRYPT !== 'true') {
      throw new Error(
        '拒绝解密无认证的 CBC 遗留密文（填充预言机风险）。' +
          '确需迁移存量数据时设置 ALLOW_LEGACY_CBC_DECRYPT=true，迁移完成后请立即关闭'
      );
    }
    return this._decryptCBC(encryptedText);
  }

  /**
   * 解析并解密 GCM 密文
   *
   * F-181：三段先按 encrypt() 的产出规范校验，再交给密码学调用。
   * 实测（Node v24.15.0）不加校验时有两类后果：
   *   1) 接受集严格大于产出集——大写十六进制、十六进制段尾随非法字符
   *      （`iv:…zz`，Buffer 会截断到坏字符前）、base64 段里插入非法字符
   *      （解码会跳过），**全都照常解出明文**。也就是同一段明文可以由
   *      多个互不相同的密文字符串表示，而 encrypt() 永远产不出那些串；
   *      任何按密文字符串做的比对（改动检测、去重、取证）都会漏掉它们。
   *   2) 截断的 tag（4/8/12 字节被 setAuthTag 接受，DEP0182）与错误长度的 IV
   *      只靠 OpenSSL 在 final() 才失败——今天确实是失败关闭（实测无一条解出
   *      明文），但「认证强度由标签长度决定」这件事被交给了运行时行为而不是本模块。
   * 校验放在密码学调用之前，非规范输入不进入 GCM 路径。
   */
  _decryptGCM(payload) {
    const parts = payload.split(':');
    if (parts.length !== 3) {
      throw new Error('无效的 GCM 密文格式');
    }

    const [ivHex, tagHex, encrypted] = parts;
    if (!GCM_IV_HEX.test(ivHex)) {
      throw new Error(
        `无效的 GCM 密文格式：iv 段必须是 ${GCM_IV_LENGTH_BYTES * 2} 位小写十六进制（当前 ${ivHex.length} 字符）`
      );
    }
    if (!GCM_TAG_HEX.test(tagHex)) {
      throw new Error(
        `无效的 GCM 密文格式：tag 段必须是 ${GCM_AUTH_TAG_LENGTH_BYTES * 2} 位小写十六进制（当前 ${tagHex.length} 字符）`
      );
    }
    if (!GCM_CIPHER_B64.test(encrypted)) {
      throw new Error(
        `无效的 GCM 密文格式：密文段必须是标准 base64（当前 ${encrypted.length} 字符）`
      );
    }

    const iv = Buffer.from(ivHex, 'hex');
    const authTag = Buffer.from(tagHex, 'hex');

    // authTagLength 显式传入：不依赖 SDK 默认值与标签长度恰好一致
    const decipher = crypto.createDecipheriv(this.algorithm, Buffer.from(this.key), iv, {
      authTagLength: authTag.length,
    });
    decipher.setAuthTag(authTag);

    let decrypted = decipher.update(encrypted, 'base64', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
  }

  // @deprecated CBC 格式无认证，存在填充预言机攻击风险。待存量数据迁移完成后移除此方法。
  _decryptCBC(encryptedText) {
    const parts = encryptedText.split(':');
    if (parts.length !== 2) {
      throw new Error('无效的 CBC 密文格式');
    }

    const iv = Buffer.from(parts[0], 'hex');
    const encrypted = parts[1];

    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(this.key), iv);
    let decrypted = decipher.update(encrypted, 'base64', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
  }
}

/**
 * HMAC 签名工具
 * 用于数据完整性验证和请求签名
 */
class HMACSigner {
  constructor(secretKey = null) {
    this.algorithm = 'sha256';
    // 放在任何 return 分支之前：两条退出路径都要带上它，否则 verify 会读到 undefined
    this.signatureShape = hmacHexShapeOf(this.algorithm);
    const effectiveKey = secretKey || process.env.HMAC_SECRET || config.hmacSecret;
    if (!effectiveKey) {
      // 生产/开发一律拒绝启动，避免签名退化为可预测值
      if (process.env.NODE_ENV !== 'test') {
        throw new Error(
          '缺少 HMAC_SECRET：请配置至少 16 字符的强随机密钥（openssl rand -hex 16），禁止使用源码内默认密钥'
        );
      }
      // G11：测试环境兜底改为进程内随机值，不再使用源码内硬编码常量。
      // 硬编码常量的问题在于它是「可被搜索到的确定值」——一旦某条路径绕过
      // 上面的环境判断（如误置 NODE_ENV=test 上线），攻击者可直接用已知密钥
      // 伪造签名；随机值则使该退化路径不可利用。
      // 每个实例独立随机不影响测试：签名与验证在同一实例内完成。
      this.secret = crypto.randomBytes(32).toString('hex');
      logger.warn('HMAC 签名使用进程内随机临时密钥（仅限 NODE_ENV=test，跨进程签名不互通）');
      return;
    }
    this.secret = effectiveKey;
  }

  /**
   * 生成 HMAC 签名
   * @param {string} data - 要签名的数据
   * @returns {string} - hex 格式的签名
   */
  sign(data) {
    return crypto.createHmac(this.algorithm, this.secret).update(data).digest('hex');
  }

  /**
   * 验证 HMAC 签名
   * @param {string} data - 原始数据
   * @param {string} signature - 待验证的签名（必须是 sign() 的产出形式：小写十六进制）
   * @returns {boolean} - 签名是否有效（任何输入不合形状都是 false，不抛异常）
   */
  verify(data, signature) {
    // 先守卫、后计算：原先 this.sign(data) 排在守卫之前，非字符串 data 会让
    // ERR_INVALID_ARG_TYPE 从这个标着 @returns {boolean} 的判定方法里抛给调用方。
    // 形状必须是"等于产出集"而不是"hex 解得开"：Buffer.from(x,'hex') 大小写不敏感、
    // 且截断到第一个坏字符，所以改前 sig.toUpperCase() 与 sig+'zz' 都判等成立。
    if (typeof signature !== 'string' || !this.signatureShape.test(signature)) {
      return false;
    }

    let expectedSignature;
    try {
      expectedSignature = this.sign(data);
    } catch {
      // data 不是 update() 接受的类型：判定为"未通过"，不把异常当成调用方的错误处理负担
      return false;
    }

    // 两侧都是定长小写十六进制（上面已校验），timingSafeEqual 不可能因长度不等抛错
    return crypto.timingSafeEqual(
      Buffer.from(signature, 'hex'),
      Buffer.from(expectedSignature, 'hex')
    );
  }
}

/**
 * 哈希工具类
 * 提供 SHA256、SHA512 等哈希算法
 */
class HashUtils {
  /**
   * SHA256 哈希
   * @param {string} data - 输入数据
   * @param {string} salt - 可选盐值
   * @returns {string} - hex 格式的哈希值
   */
  static sha256(data, salt = '') {
    return crypto
      .createHash('sha256')
      .update(salt + data)
      .digest('hex');
  }

  /**
   * SHA512 哈希
   * @param {string} data - 输入数据
   * @param {string} salt - 可选盐值
   * @returns {string} - hex 格式的哈希值
   */
  static sha512(data, salt = '') {
    return crypto
      .createHash('sha512')
      .update(salt + data)
      .digest('hex');
  }

  /**
   * PBKDF2 密钥派生
   * @param {string} password - 密码
   * @param {string} salt - 盐值
   * @param {number} iterations - 迭代次数
   * @param {number} keylen - 密钥长度
   * @returns {string} - hex 格式的派生密钥
   */
  static pbkdf2(password, salt, iterations = 100000, keylen = 32) {
    return new Promise((resolve, reject) => {
      crypto.pbkdf2(password, salt, iterations, keylen, 'sha256', (err, derivedKey) => {
        if (err) return reject(err);
        resolve(derivedKey.toString('hex'));
      });
    });
  }

  /**
   * 生成随机盐值
   * @param {number} length - 盐值长度（字节）
   * @returns {string} - hex 格式的盐值
   */
  static generateSalt(length = 16) {
    return crypto.randomBytes(length).toString('hex');
  }

  /**
   * 生成安全随机字符串（字母+数字，长度**恰好**等于 length）
   *
   * 原实现取 `randomBytes(n*3/4).toString('base64')` 再删掉非字母数字字符，
   * 于是 `+` `/` `=` 被删掉的那些字符不会补回来——实测 500 次调用里
   * 63% 的 `randomString(32)` 返回不足 32 位（观察到最短 27 位），16 位档 43% 偏短。
   * 调用方按"长度=熵"来理解这个函数（重置码/nonce/临时口令），
   * 静默变短就是熵被悄悄扣掉，且下游任何按长度做的校验会莫名失败。
   * 现改为在 62 字符表上做丢弃式采样：不做取模（避免模偏差），
   * 落在表外的字节直接扔掉再取下一批。
   *
   * @param {number} length - 字符串长度（正整数）
   * @returns {string} - 恰好 length 位的随机串
   */
  static randomString(length = 32) {
    const chars = [];
    while (chars.length < length) {
      const bytes = crypto.randomBytes((length - chars.length) * 2);
      for (const byte of bytes) {
        if (byte < RANDOM_STRING_ALPHABET.length) chars.push(RANDOM_STRING_ALPHABET[byte]);
        if (chars.length === length) break;
      }
    }
    return chars.join('');
  }
}

/**
 * 敏感数据脱敏工具
 */
class DataMasking {
  /**
   * 手机号脱敏
   * @param {string} phone - 手机号
   * @returns {string} - 脱敏后的手机号
   */
  static maskPhone(phone) {
    if (!phone) return '';
    const str = String(phone);
    // 四条正则一律**全串锚定**：非锚定的 `replace` 只改写命中的那一段，
    // 尾部会整段留下（实测 20 位以上纯数字串会漏出后 12 位明文）。
    // 锚定后"形状不认识"就落到兜底，兜底保证整串被打码。
    if (str.length === 11) {
      const masked = str.replace(/^(\d{3})\d{4}(\d{4})$/, '$1****$2');
      if (masked !== str) return masked;
    }
    const generic = str.replace(/^(\d{2})\d+(\d{2})$/, '$1***$2');
    // `replace` 未命中时返回的是**原串**。原实现在这里把"认不出的形态"
    // 当成"不需要脱敏"，4 位以内的短号会整串出现在响应/日志里。
    return generic === str ? '****' : generic;
  }

  /**
   * 邮箱脱敏
   * @param {string} email - 邮箱地址
   */
  static maskEmail(email) {
    if (!email) return '';
    const str = String(email);
    const at = str.indexOf('@');
    // 无 @ 或本地部分为空：非邮箱形态，原样返回（避免产出 "undefined*@d" 这类脏数据）
    if (at <= 0) return str;
    const local = str.slice(0, at);
    const domain = str.slice(at + 1);

    const maskedLocal =
      local.length <= 2
        ? `${local[0]}****`
        : `${local[0]}${'*'.repeat(Math.min(local.length - 2, 4))}${local.slice(-1)}`;

    return `${maskedLocal}@${domain}`;
  }

  /**
   * 身份证号脱敏
   * @param {string} idCard - 身份证号
   * @returns {string} - 脱敏后的身份证号
   */
  static maskIdCard(idCard) {
    if (!idCard) return '';
    const str = String(idCard);
    if (str.length >= 14) {
      const masked = str.replace(/^(\d{6})\d{8}(\w{4})$/, '$1********$2');
      if (masked !== str) return masked;
      // 上面那条正则要 6+8+4=18 位才命中，而**老式 15 位身份证确实存在**
      // （1999 年前签发），16/17 位也可能来自录入残缺。原实现在这些形态下
      // 整串原样返回 ⇒ 证件号明文进入响应/日志/导出。
      return DataMasking._maskMiddle(str, 6, 4);
    }
    const short = str.replace(/^(\d{4})\d+(\w{2})$/, '$1***$2');
    return short === str ? '****' : short;
  }

  /**
   * 兜底打码：保留头 head 位与尾 tail 位，中间全部替换为等长星号。
   * 供各 mask* 在"正则没认出来"时使用——认不出不等于可以不脱敏。
   * 长度不足以同时保留头尾时整串打码（绝不返回原串）。
   * @param {string} str 已 String 化的输入
   * @param {number} head 保留的头部字符数
   * @param {number} tail 保留的尾部字符数
   * @returns {string} 与原串等长的脱敏结果
   */
  static _maskMiddle(str, head, tail) {
    if (str.length <= head + tail) return '*'.repeat(str.length);
    return `${str.slice(0, head)}${'*'.repeat(str.length - head - tail)}${str.slice(-tail)}`;
  }

  /**
   * 姓名脱敏
   * @param {string} name - 姓名
   * @returns {string} - 脱敏后的姓名
   */
  static maskName(name) {
    if (!name) return '';
    const str = String(name);
    if (str.length === 1) {
      return '*';
    } else if (str.length === 2) {
      return str[0] + '*';
    } else {
      return str[0] + '*'.repeat(str.length - 2) + str.slice(-1);
    }
  }

  /**
   * IP 地址脱敏
   *
   * P3-27 IPv6 修正：不能对压缩写法「过滤空组后取前 3 个」。
   * `2001:db8::1` 过滤空组得 ['2001','db8','1']，输出 `2001:db8:1:****`——
   * 把接口标识（::1）当成了网络前缀的第三组，脱敏结果与真实前缀不符，
   * 既误导排障（看起来是 2001:db8:1::/48 网段，实际是 2001:db8::/32），
   * 也让不同主机产生相同掩码串而无法区分。
   * 正确做法：先把 `::` 展开为完整 8 组，再保留前 3 组（约 /48 前缀）。
   *
   * @param {string} ip - IP 地址
   */
  static maskIP(ip) {
    if (!ip) return '';
    const str = String(ip).trim();

    // IPv4-mapped IPv6（::ffff:1.2.3.4）：按其内嵌的 IPv4 语义脱敏，
    // 否则会被 IPv6 分支处理成 `::ffff:1.2.3.4` 的前 3 组，丢失可读性
    const mappedMatch = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(str);
    if (mappedMatch) {
      return DataMasking.maskIP(mappedMatch[1]);
    }

    // IPv4：保留前两段
    const parts = str.split('.');
    if (parts.length === 4 && parts.every((p) => /^\d{1,3}$/.test(p))) {
      return `${parts[0]}.${parts[1]}.*.*`;
    }

    // IPv6：展开 :: 后保留前 3 组（约 /48），其余打码
    if (str.includes(':')) {
      const groups = DataMasking._expandIPv6(str);
      if (groups) {
        return `${groups.slice(0, 3).join(':')}:****`;
      }
      // 非法/无法解析的 IPv6：不做「猜测式」脱敏，整体打码更安全
      return '****';
    }

    // 其他形态兜底：隐去最后一个点分段
    return str.replace(/\.\d+$/, '.***');
  }

  /**
   * 把 IPv6 展开为完整的 8 组（小写、不补前导零）
   *
   * `::` 只能出现一次，展开时按缺失组数补 '0'。
   * 无法解析（组数超限、多个 `::`、含非法字符）时返回 null，
   * 由调用方决定兜底策略——不返回「部分正确」的结果。
   *
   * @param {string} ip
   * @returns {string[]|null} 8 组十六进制串
   */
  static _expandIPv6(ip) {
    const lower = String(ip).toLowerCase();
    // 末尾内嵌 IPv4（如 2001:db8::192.168.0.1）先转为两组十六进制
    const v4Tail = /:(\d{1,3}(?:\.\d{1,3}){3})$/.exec(lower);
    let work = lower;
    if (v4Tail) {
      const octets = v4Tail[1].split('.').map(Number);
      if (octets.some((o) => !Number.isInteger(o) || o < 0 || o > 255)) return null;
      const hi = ((octets[0] << 8) | octets[1]).toString(16);
      const lo = ((octets[2] << 8) | octets[3]).toString(16);
      work = `${lower.slice(0, v4Tail.index)}:${hi}:${lo}`;
    }

    const doubleColonCount = (work.match(/::/g) || []).length;
    if (doubleColonCount > 1) return null;

    let head;
    let tail;
    if (doubleColonCount === 1) {
      const [a, b] = work.split('::');
      head = a ? a.split(':') : [];
      tail = b ? b.split(':') : [];
    } else {
      head = work.split(':');
      tail = [];
    }

    const all = [...head, ...tail];
    if (all.some((g) => !/^[0-9a-f]{1,4}$/.test(g))) return null;

    const missing = 8 - all.length;
    if (doubleColonCount === 1) {
      if (missing < 0) return null;
      return [...head, ...Array(missing).fill('0'), ...tail];
    }
    return all.length === 8 ? all : null;
  }
}

// 导出实例
const aesCipher = new AESCipher();
const hmacSigner = new HMACSigner();

module.exports = {
  AESCipher,
  HMACSigner,
  HashUtils,
  DataMasking,
  aesCipher,
  hmacSigner,
  // GCM 密文字段的规范形式（见 _decryptGCM）。导出是为了让用例把
  // 「写入侧产出」与「读取侧接受」直接比对，而不是把正则再抄一遍到测试里——
  // 抄一份的话，生产侧放宽、测试侧不会跟着红。
  GCM_FIELD_SHAPES: { iv: GCM_IV_HEX, tag: GCM_TAG_HEX, cipher: GCM_CIPHER_B64 },
};
