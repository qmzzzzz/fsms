/**
 * 公共工具函数
 */

/**
 * HTML 实体转义，防止存储型 XSS
 * 文本字段入库前必须转义，避免未来 HTML 消费方直接执行脚本
 */
function escapeHtml(str) {
  if (typeof str !== 'string') return str;
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

/**
 * 头像字段白名单校验（统一入口，供个人资料/管理员更新用户复用）
 * 允许：http(s) URL、/ 开头的相对图片路径、data:image 数据 URI（不含 svg，防存储型脚本注入）
 *
 * P3-9：相对路径分支必须拒绝协议相对地址（//evil.com/x.png）。
 * 原字符类 [\w\-./] 包含 /，导致 //evil.com/x.png 整体命中"站内路径"，
 * 浏览器按当前协议解析后会向第三方域发起请求（头像 URL 可用于
 * 去匿名化追踪查看者 IP/时区）。(?!\/) 保证 / 后不再跟 /。
 * @param {string} avatar 待校验的头像值
 * @returns {boolean} 是否合法
 */
const isValidAvatar = (avatar) => {
  if (typeof avatar !== 'string' || avatar.length > 2048) return false;
  return (
    /^https?:\/\/\S+$/i.test(avatar) ||
    /^\/(?!\/)[\w\-./]*\.(png|jpe?g|gif|webp)$/i.test(avatar) ||
    /^data:image\/(png|jpe?g|gif|webp);base64,[A-Za-z0-9+/]+=*$/i.test(avatar)
  );
};

/**
 * 转义正则表达式中的特殊字符，防止 ReDoS 和无效 regex
 * @param {string} str 需要转义的字符串
 * @returns {string} 转义后的字符串
 */
const escapeRegExp = (str) => String(str).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/**
 * 枚举白名单校验
 * value 为 undefined/null/空串时返回 null（表示未传参，允许）；
 * 不在 allowedValues 中时抛出携带 status=400 与明确错误信息的异常；
 * 合法时原值返回
 * @param {string|undefined|null} value 待校验参数值
 * @param {string[]} allowedValues 合法枚举值数组
 * @param {string} fieldName 参数名（用于错误消息）
 * @returns {string|null}
 */
const validateEnum = (value, allowedValues, fieldName) => {
  if (value === undefined || value === null || value === '') return null;
  if (!Array.isArray(allowedValues) || allowedValues.length === 0) {
    throw new Error(`参数 ${fieldName} 未配置合法枚举值`);
  }
  if (!allowedValues.includes(value)) {
    const err = new Error(`参数 ${fieldName} 必须为 ${allowedValues.join('/')} 之一`);
    err.status = 400;
    throw err;
  }
  return value;
};

/**
 * 校验并规范化分页参数
 * @param {any} page 页码
 * @param {any} limit 每页数量
 * @param {number} [maxLimit=500] 每页最大数量（不同接口可自定义上限）
 * @returns {{ page: number, limit: number }}
 */
const normalizePagination = (page, limit, maxLimit = 500) => {
  let p = parseInt(page, 10);
  let l = parseInt(limit, 10);
  if (Number.isNaN(p) || p < 1) p = 1;
  if (Number.isNaN(l) || l < 1) l = 10;
  if (l > maxLimit) l = maxLimit;
  // 限制 page 上限，防止 skip 巨大偏移量导致性能问题
  if (p > 10000) p = 10000;
  return { page: p, limit: l };
};

/**
 * 密码策略常量（P3-29）
 *
 * PASSWORD_SPECIAL_REGEX 覆盖全部 ASCII 可打印标点，四段区间依次为：
 *   ! - /   (0x21-0x2F)   : - @  (0x3A-0x40)
 *   [ - `   (0x5B-0x60)   { - ~  (0x7B-0x7E)
 * 原实现仅列举 `!@#$%^&*(),.?":{}|<>`，把 - _ = + [ ] ; ' \ ~ ` 等
 * 常见符号排除在外，导致 `Str0ng-Pass_2026` 这类强口令被判为「缺少特殊字符」。
 *
 * PASSWORD_MAX_BYTES = 72：bcrypt 只取前 72 字节，超出部分被静默丢弃
 * （`<72字节前缀>+任意后缀` 与原口令等价通过校验）。同时纯 JS bcryptjs
 * 对超长输入存在 CPU 放大，故长度必须在进入哈希前收口。
 * 按字节而非字符计：中文口令单字符 3 字节，64 字符可达 192 字节。
 */
const PASSWORD_SPECIAL_REGEX = /[!-/:-@[-`{-~]/;
const PASSWORD_MAX_BYTES = 72;
const PASSWORD_MAX_LENGTH = 64;

/**
 * 密码强度规则（企业级统一策略）
 * 至少 12 位，且包含大写字母、小写字母、数字、特殊字符
 * （L-1，2026-09-02：按 OWASP/NIST 建议自 8 位提升至 12 位；存量用户不受影响——
 * 本校验仅在设置/修改密码时触发，登录比对不走此函数）
 */
const PASSWORD_RULES = [
  { regex: /.{12,}/, message: '密码长度至少 12 位' },
  { regex: /[A-Z]/, message: '密码必须包含大写字母' },
  { regex: /[a-z]/, message: '密码必须包含小写字母' },
  { regex: /[0-9]/, message: '密码必须包含数字' },
  { regex: PASSWORD_SPECIAL_REGEX, message: '密码必须包含特殊字符' },
];

/**
 * 常见泄露/弱口令黑名单（G8）
 *
 * 设计取舍：不接入 HaveIBeenPwned 等在线 API——那会把用户密码哈希前缀
 * 发往第三方，且给注册/改密链路引入外部依赖与延迟。改为内置「已通过复杂度
 * 规则但仍属高频撞库口令」的本地清单：这类口令恰好满足大小写+数字+符号，
 * 复杂度校验拦不住，却位于所有撞库字典的前列。
 *
 * 比对时归一化（小写 + 去除重复末尾数字/符号），覆盖 Admin@123 / admin@1234
 * 这类同源变体。清单保持精简可维护，不追求覆盖全部字典。
 */
const BREACHED_PASSWORDS = new Set([
  'admin@123',
  'admin@1234',
  'admin@12345',
  'admin123',
  'password@123',
  'passw0rd!',
  'p@ssw0rd',
  'p@ssword',
  'qwer1234!',
  'qwerty@123',
  'abc@1234',
  'abcd1234!',
  'test@123',
  'root@123',
  'user@123',
  'welcome@123',
  'changeme@1',
  'letmein@123',
  'iloveyou@1',
  'monkey@123',
  'dragon@123',
  'master@123',
  'sunshine@1',
  'football@1',
  'baseball@1',
  '1qaz@wsx',
  '1q2w3e4r!',
  'zaq1@wsx',
  'qazwsx@123',
  'aa123456!',
  'a1234567!',
  '12345678a!',
  'huawei@123',
  'xiaomi@123',
  'china@123',
  'fire@123',
  'fire@1234',
  'xf@123456',
  'admin@qwe',
  'admin@asd',
]);

/**
 * 归一化口令用于黑名单比对：小写化 + 收敛末尾连续数字为单一形态
 * 例：Admin@1234 → admin@123（与 admin@123 同源，一并拦截）
 */
const normalizePasswordForBreachCheck = (pwd) => {
  const lower = String(pwd).toLowerCase();
  // 末尾 4 位以上连续数字截断为 3 位，抹平 123/1234/12345 的差异
  return lower.replace(/(\d{3})\d+$/, '$1');
};

/**
 * 判断口令是否命中泄露/弱口令黑名单
 * @param {string} password 待检查口令
 * @returns {boolean}
 */
const isBreachedPassword = (password) => {
  if (!password || typeof password !== 'string') return false;
  const lower = password.toLowerCase();
  if (BREACHED_PASSWORDS.has(lower)) return true;
  return BREACHED_PASSWORDS.has(normalizePasswordForBreachCheck(password));
};

/**
 * 校验密码强度
 * @param {string} password 待校验密码
 * @returns {string|null} 不满足时返回错误消息，满足返回 null
 */
const validatePasswordStrength = (password) => {
  if (!password || typeof password !== 'string') return '密码不能为空';
  // P3-29：长度上限必须在复杂度规则之前判定——正则遍历超长串本身就是开销，
  // 且 bcrypt 的 72 字节截断会让「超长口令」的后缀失效（等价口令绕过）
  if (password.length > PASSWORD_MAX_LENGTH) {
    return `密码长度不能超过 ${PASSWORD_MAX_LENGTH} 个字符`;
  }
  if (Buffer.byteLength(password, 'utf8') > PASSWORD_MAX_BYTES) {
    return `密码过长（UTF-8 编码后不能超过 ${PASSWORD_MAX_BYTES} 字节）`;
  }
  for (const rule of PASSWORD_RULES) {
    if (!rule.regex.test(password)) return rule.message;
  }
  // G8：复杂度达标后再查泄露口令黑名单——Admin@123 这类口令满足全部
  // 复杂度规则却位于撞库字典首位，仅靠字符类型校验无法拦截
  if (isBreachedPassword(password)) {
    return '该密码属于常见泄露口令，请更换为不易猜测的密码';
  }
  return null;
};

/**
 * 校验并规范化排序参数
 * 防止 NoSQL 注入或无效排序条件
 * @param {string} sortInput 输入的排序字符串，如 "-createdAt" 或 "username"
 * @param {Object} options 选项
 * @param {string[]} options.allowedFields 允许排序的字段列表（所有字段都被移除前缀后检查）
 * @param {string} options.defaultSort 默认排序条件
 * @returns {string} 安全的排序条件
 */
const validateSort = (sortInput, options = {}) => {
  const { allowedFields = [], defaultSort = '-createdAt' } = options;
  if (!sortInput || typeof sortInput !== 'string') return defaultSort;

  // 解析排序字段和方向
  let field = sortInput;
  let direction = 1;
  if (field.startsWith('-')) {
    direction = -1;
    field = field.slice(1);
  } else if (field.startsWith('+')) {
    field = field.slice(1);
  }

  // 检查字段名是否允许
  if (allowedFields.length > 0 && !allowedFields.includes(field)) {
    return defaultSort;
  }

  // 防止操作符注入（确保不包含 $ 或 .）
  if (field.includes('$') || field.includes('.')) {
    return defaultSort;
  }

  return direction === -1 ? `-${field}` : field;
};

/**
 * 解析日期字符串为本地时区的查询边界
 * date-only 字符串（如 '2026-08-21'）被 new Date() 按 UTC 零点解析（GMT+8 为当天 08:00），
 * 会漏掉边界时段的数据；此处手工构造本地时间，避免日期范围查询边界偏移
 * @param {string} dateStr 日期字符串
 * @param {'start'|'end'} boundary 边界类型：start → 本地当天 00:00:00.000，end → 本地当天 23:59:59.999
 * @returns {Date} 本地时间 Date
 */
const parseDateBoundary = (dateStr, boundary) => {
  if (typeof dateStr === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(dateStr)) {
    const [y, m, d] = dateStr.split('-').map(Number);
    return boundary === 'end'
      ? new Date(y, m - 1, d, 23, 59, 59, 999)
      : new Date(y, m - 1, d, 0, 0, 0, 0);
  }
  return new Date(dateStr);
};

/**
 * 构造日期范围查询过滤器（报表/导出统一口径，七维终评「日期过滤样板 4 处重复」）
 *
 * 入参须先经 isValidDateParam 校验；本函数只负责把通过校验的入参
 * 翻译为 {$gte,$lte} 形态，空值对应边界省略。
 * @param {string|undefined} startDate 起始日期（date-only 或完整时间串）
 * @param {string|undefined} endDate 结束日期（同上，含当天末尾语义）
 * @returns {Object} Mongo 范围条件对象（可能为空对象）
 */
const buildDateRangeFilter = (startDate, endDate) => {
  const dateFilter = {};
  if (startDate) dateFilter.$gte = parseDateBoundary(startDate, 'start');
  if (endDate) dateFilter.$lte = parseDateBoundary(endDate, 'end');
  return dateFilter;
};

/**
 * 清除字符串中的控制字符（换行/回车/制表/NUL 等），防止日志注入与下游渲染污染
 * @param {any} value 待清洗值
 * @param {number} [maxLength=1024] 最大保留长度，超长截断
 * @returns {any} 非字符串原样返回；字符串返回清洗后的值
 */
const stripControlChars = (value, maxLength = 1024) => {
  if (typeof value !== 'string') return value;
  // C0/C1 控制字符 + DEL + Unicode 行终止符（\u2028/\u2029）与双向控制符（\u202A-\u202E），
  // 后者同样可注入日志伪造多行输出或篡改终端显示方向。
  // P3-29 补：\u2066-\u2069 是 Unicode 6.3 新增的双向隔离符（LRI/RLI/FSI/PDI），
  // 与 \u202A-\u202E 同属 Bidi 控制类，可实现 Trojan Source 式的显示顺序篡改，
  // 原区间上界停在 \u202E 恰好漏掉这四个码点
  // eslint-disable-next-line no-control-regex
  const controlCharPattern = /[\u0000-\u001F\u007F\u0080-\u009F\u2028-\u202E\u2066-\u2069]/g;
  const cleaned = value.replace(controlCharPattern, ' ').trim();
  return cleaned.length > maxLength ? cleaned.slice(0, maxLength) : cleaned;
};

/**
 * 递归清洗对象中所有字符串值的控制字符（用于审计 params/query 等结构化字段）
 * @param {any} value 待清洗值
 * @param {number} [depth=0] 当前递归深度（内部使用）
 * @returns {any} 清洗后的同构值
 */
const stripControlCharsDeep = (value, depth = 0) => {
  if (depth > 6) return value;
  if (typeof value === 'string') return stripControlChars(value);
  if (Array.isArray(value)) return value.map((v) => stripControlCharsDeep(v, depth + 1));
  if (value && typeof value === 'object') {
    const cleaned = {};
    for (const [k, v] of Object.entries(value)) {
      cleaned[stripControlChars(k, 128)] = stripControlCharsDeep(v, depth + 1);
    }
    return cleaned;
  }
  return value;
};

/**
 * 访问日志中需要打码的 query 参数名（小写、子串匹配）
 * P3-32：morgan combined 会把完整 URL（含 query string）写入访问日志。
 * 审计日志的 body 有 SENSITIVE_KEYS 脱敏，query 却只做了控制字符清洗——
 * 一旦有接口以 query 传令牌/口令（导出下载链接、找回密码链接、第三方回调），
 * 明文就长期留存在 combined-*.log 里，且该文件的读取权限通常宽于审计库。
 */
const SENSITIVE_QUERY_KEYS = Object.freeze([
  'password',
  'passwd',
  'pwd',
  'token',
  'access_token',
  'refresh_token',
  'secret',
  'apikey',
  'api_key',
  'code',
  'signature',
  'sign',
  'mfa',
  'otp',
  'captcha',
  'authorization',
  'session',
]);

/**
 * 对 URL 的 query string 做敏感值打码，保留键名与结构便于排障
 *
 * 保留键名而非整段丢弃：运维需要知道「调用方带了哪些参数」来定位问题，
 * 只是不需要知道值。无法解析的 URL 原样返回（不猜测结构）。
 * @param {string} url 原始 URL（可为相对路径）
 * @returns {string} 敏感值替换为 *** 后的 URL
 */
const redactUrlQuery = (url) => {
  if (typeof url !== 'string' || !url.includes('?')) return url;
  const idx = url.indexOf('?');
  const pathPart = url.slice(0, idx);
  const queryPart = url.slice(idx + 1);
  const redacted = queryPart
    .split('&')
    .map((pair) => {
      const eq = pair.indexOf('=');
      if (eq === -1) return pair;
      const key = pair.slice(0, eq);
      const lower = key.toLowerCase();
      return SENSITIVE_QUERY_KEYS.some((s) => lower.includes(s)) ? `${key}=***` : pair;
    })
    .join('&');
  return `${pathPart}?${redacted}`;
};

/**
 * 电子表格公式注入防护（OWASP Formula Injection）
 * 以 = + - @ 或 Tab/CR 开头的单元格文本在 Excel/WPS/CSV 消费方可能被当作公式执行，
 * 统一前置单引号使其强制作为文本处理
 * @param {any} value 单元格值
 * @returns {any} 非字符串原样返回；危险前缀字符串返回加固后的值
 */
const sanitizeSpreadsheetCell = (value) => {
  if (typeof value !== 'string' || value.length === 0) return value;
  return /^[=+\-@\t\r]/.test(value) ? `'${value}` : value;
};

module.exports = {
  escapeRegExp,
  normalizePagination,
  parseDateBoundary,
  buildDateRangeFilter,
  stripControlChars,
  stripControlCharsDeep,
  redactUrlQuery,
  SENSITIVE_QUERY_KEYS,
  sanitizeSpreadsheetCell,
  validateSort,
  validateEnum,
  validatePasswordStrength,
  isBreachedPassword,
  escapeHtml,
  isValidAvatar,
  PASSWORD_RULES,
  PASSWORD_SPECIAL_REGEX,
  PASSWORD_MAX_BYTES,
  PASSWORD_MAX_LENGTH,
  BREACHED_PASSWORDS,
};
