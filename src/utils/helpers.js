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
  const MAX_PAGE = 10000;
  if (p > MAX_PAGE) p = MAX_PAGE;
  // 评价报告 #13：深分页的真实代价是偏移量 (p-1)*l——page 上限 10000 配
  // maxLimit 500 时 skip 可达 5e6，MongoDB 需扫描丢弃全部前序文档。
  // 按偏移量二次收敛：默认参数下最深可翻到约 10 万条（高量级列表应走游标分页）。
  const MAX_SKIP_OFFSET = 100000;
  const maxPageByOffset = Math.floor(MAX_SKIP_OFFSET / l) + 1;
  if (p > maxPageByOffset) p = maxPageByOffset;
  return { page: p, limit: l };
};

/**
 * 请求体 id 列表的归一入口：逐项转字符串 + 大小写规范化 + 去重 + 保序。
 *
 * 为什么"去重"属于正确性而不是洁癖：本仓判断"请求的 id 里有不存在的"用的唯一口径是
 * `查到的文档数 !== 请求的 id 数`，而 `$in` 天生只回**去重后**的文档 ⇒ 请求里重复一个 id
 * 就会被算成"有一个 id 不存在"，一次本来合法的写操作回 400。归一必须在比较**之前**，
 * 并且归一后的那份还要参与后续写入——否则重复项会被原样存进数组字段里。
 *
 * 为什么"大小写"是同一条判据的另一维（不是风格问题）：
 *  - 路由格式闸 `isMongoId` **放得过大写十六进制**：validator 的 isMongoId 委托
 *    isHexadecimal，其正则 `/^(0x|0h)?[0-9A-F]+$/i` 带 `i`（实测 `isMongoId('67ED…D5') === true`）。
 *  - 而库里读回来的 id **恒为小写**：bson 的 ObjectId.prototype.toString → toHexString 用
 *    `byteToHex` 查表（表项是 `n.toString(16).padStart(2,'0')`），没有大写分支。
 *  - `$in` 里两者却指向**同一个文档**（Mongoose 按 12 字节解析，大小写无关）。
 * 于是 `["67ED…","67ed…"]` 在归一前是 2 个不同字符串、查到 1 份文档 ⇒ 一次合法的写操作被
 * 判成"有 id 不存在"；更要命的是身份自检：`requestedIds.includes(String(req.user.userId))`
 * 拿小写的操作者 id 去比大写的那一份，**"不许删除自己"的闸被换个字母大小写绕过**
 * （userController.js 批量删除）。Mongoose 的 cast 会把落库值归回小写，所以这条只影响
 * "比较与集合语义"，不影响存储形态——也正因为如此，光看数据库看不出问题。
 * 只规范化 24 位十六进制：非该形状的值（口令、编码、原始 12 字节串）原样保留，
 * 否则这个"id 归一入口"会顺手改掉它不该改的字段。
 *
 * 只做归一，不校验格式：格式非法与"不存在"在各接口是两条不同的错误文案。
 *
 * 两个导出都要：`uniqueIdStrings` 管"数组比对/落库"，`canonicalIdString` 管
 * "单个请求值 vs 库里读出来的值"这类比较（permissionService 的父级存在性判定）。
 * 只导出前者的话，单值比较点只能继续手写 `String(...)`——那正是大小写绕过待的地方。
 * @param {any} list 请求体里的原始数组（可能不是数组）
 * @returns {string[]} 去重保序的 id 字符串数组（24 位十六进制项已转小写）
 */
const ID_HEX_24 = /^[0-9a-fA-F]{24}$/;

const canonicalIdString = (item) => {
  const text = String(item);
  return ID_HEX_24.test(text) ? text.toLowerCase() : text;
};

const uniqueIdStrings = (list) =>
  Array.isArray(list) ? [...new Set(list.map(canonicalIdString))] : [];

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
 * 弱口令词干表（G8）本体在 constants/breachedPasswords.js：
 * 一百余条词干是策略数据而非工具函数，放这里会让本文件整体越过体积预算。
 * 判定逻辑（归一化 + 比对）仍在本文件，见 isBreachedPassword。
 */
const { BREACHED_PASSWORD_STEMS } = require('../constants/breachedPasswords');

/**
 * 归一化口令用于黑名单比对：小写化 → 去掉**所有**非字母数字 → 去掉**末尾连续数字**，
 * 得到「词干」。**只有口令侧需要归一化**——表里存的本来就是词干（见该文件头），
 * 两侧口径因此不可能再漂移（2026-10-09 前正是两侧口径不一致，导致 40 条里 24 条永不命中）。
 * 例：Admin@123456 → admin；P@ssw0rd1234! → pssw0rd；Fire@2026Safe! → fire2026safe
 */
const normalizePasswordForBreachCheck = (pwd) =>
  String(pwd)
    .toLowerCase()
    .replace(/[^a-z0-9]/g, '')
    .replace(/\d+$/, '');

/**
 * 判断口令是否命中泄露/弱口令词干表
 * @param {string} password 待检查口令
 * @returns {boolean}
 */
const isBreachedPassword = (password) => {
  if (!password || typeof password !== 'string') return false;
  // 去掉所有非字母数字（含空白）后再比对，方向只会更严：把 "admin@123 "、
  // " admin@123" 这类加空格的变体也纳入拦截，不会放过任何真实口令。
  // 旧实现只做 toLowerCase + 去空白，导致 userRoutes 未对 password .trim() 时，
  // "Admin@123456 " 既不在字面量集合、又能破坏末尾数字归一化正则（$ 锚定被空格挡住）→ 绕过。
  const stem = normalizePasswordForBreachCheck(password);
  return stem.length > 0 && BREACHED_PASSWORD_STEMS.has(stem);
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
 * 解析日期字符串为查询边界（评价报告 #12：统一到业务时区口径）
 *
 * date-only 字符串（如 '2026-08-21'）被 new Date() 按 UTC 零点解析（GMT+8 为当天 08:00），
 * 会漏掉边界时段的数据。原实现用服务器本地时区手工构造——在 UTC 容器下与
 * constants/timezone 的东八区业务口径相差 8 小时（跨日漏数）。
 * 现收敛为单一事实来源：date-only 一律走 businessDayBounds（业务时区，
 * 默认 Asia/Shanghai，可用 TZ_BUSINESS 覆盖）；完整时间串仍透传 new Date()。
 * @param {string} dateStr 日期字符串
 * @param {'start'|'end'} boundary 边界类型：start → 业务时区当天 00:00:00.000，end → 23:59:59.999
 * @returns {Date} 业务时区口径的 UTC 瞬间
 */
const DATE_ONLY_LOOSE = /^(\d{4})-(\d{1,2})-(\d{1,2})$/;
/**
 * 零填充日期 + 时间后缀（`T` 或空格分隔，V8 两种都接受）。
 * 这类串不会进上面的 date-only 分支，也就绕过了 `businessDayBounds` 里的
 * `clampToRealCalendarDay`，直接落到 `new Date()` 的**前滚**语义：
 * 实测 `2026-04-31T10:00` → 5 月 1 日 10:00、`2026-06-31T10:00` → 7 月 1 日、
 * `2027-02-29T12:00` → 3 月 1 日。同一意图写成 date-only 是"回夹到四月底"，
 * 写成带时间就成了"四月报表含五月"，所以这里补同一道回夹，**只动日期部分、
 * 时间原样保留**（对合法日期是恒等变换，因此不会把 23:59 这类终态时刻挪走）。
 */
const DATE_PREFIX_WITH_TIME = /^(\d{4})-(\d{2})-(\d{2})([T ].*)$/;
/**
 * @param {string} dateStr 日期参数
 * @param {'start'|'end'} boundary
 * @param {string} [timeZone] IANA 时区；缺省 = 业务时区（既有口径不变）。
 *                            报表接口把浏览器的 resolvedOptions().timeZone 传进来，
 *                            使「今日」按浏览器所在时区的本地自然日计算。
 */
const parseDateBoundary = (dateStr, boundary, timeZone) => {
  if (typeof dateStr === 'string') {
    const parts = DATE_ONLY_LOOSE.exec(dateStr.trim());
    const [, yy, mm, dd] = parts || [];
    // 上下界一起判：把 0 月塞进 businessDayBounds 会在 Intl 格式化处抛 RangeError，
    // 于是"该 400 的坏参数"变成 500；越界值一律留给 new Date() 判成无效，由上游拒掉。
    if (mm >= 1 && mm <= 12 && dd >= 1 && dd <= 31) {
      const { zonedDayBounds, BUSINESS_TIMEZONE } = require('../constants/timezone');
      // 必须补齐零再转发：非零填充串会被 businessDayBounds 静默换成"今天"
      const pad = (v) => String(v).padStart(2, '0');
      const bounds = zonedDayBounds(timeZone || BUSINESS_TIMEZONE, `${yy}-${pad(mm)}-${pad(dd)}`);
      return boundary === 'end' ? bounds.end : bounds.start;
    }
    const timed = DATE_PREFIX_WITH_TIME.exec(dateStr.trim());
    if (timed) {
      const [, ty, tm, td, rest] = timed;
      // 沿用 date-only 分支同一道越界闸门：日序 > 31（如 2026-12-32）留给 new Date()
      // 判成 Invalid Date ⇒ 上游 400。刻意不在这里回夹：那会把一个"响亮拒绝"
      // 悄悄换成"可用窗口"，属对外契约变更，且与 date-only 的既有结论不一致。
      if (tm >= 1 && tm <= 12 && td >= 1 && td <= 31) {
        const { clampToRealCalendarDay } = require('../constants/timezone');
        const padded = `${ty}-${tm}-${td}`;
        const clamped = clampToRealCalendarDay(padded);
        if (clamped !== padded) return new Date(`${clamped}${rest}`);
      }
    }
  }
  return new Date(dateStr);
};

/**
 * 报表/导出日期参数合法性校验（与 buildDateRangeFilter 配套的统一口径）
 *
 * 空值（undefined / null / ''）视为未传、放行；其余值必须是**字符串**且能被 Date 解析。
 *
 * 为什么不是只判 `!isNaN(new Date(v))`：那条判据对非字符串全部放行——
 * 实测 `null / false / 0 / 20260801 / '123'` 曾一律返回 true，而 `'123'` 经
 * `new Date('123')` 变成**公元 0122 年**的有效时刻，于是"参数写错了"退化成
 * "一个窄得离谱却看起来正常"的结果集（200 + 空表）。本仓对这一格有既定判例：
 * 静默翻译的筛选参数是一类缺陷，不是风格问题。
 * 纯数字串单独挡：它是这类误用的最常见形态（把日期写成 20260801 或被 URL 猜成数字）。
 * 注意 `2026-04-31` 这类"不存在的日历日"仍放行——那是 by-design：入口三道判据
 * （isISO8601 非 strict / new Date 前滚 / 本函数）都拦不住它，收口在
 * `constants/timezone.clampToRealCalendarDay`（见 businessDayBoundsIllegalCalendarDay 用例；
 * 带时间后缀的同一写法由 parseDateBoundary 的 DATE_PREFIX_WITH_TIME 分支收口，
 * 见 zzqB_illegalCalendarDayWithTime 用例）。
 * @param {string|undefined|null} value 待校验的日期参数
 * @returns {boolean} 合法（含未传）返回 true
 */
const isValidDateParam = (value) => {
  if (value === undefined || value === null || value === '') return true;
  if (typeof value !== 'string') return false;
  if (/^\d+$/.test(value.trim())) return false;
  return !Number.isNaN(new Date(value).getTime());
};

/**
 * 构造日期范围查询过滤器（报表/导出统一口径，七维终评「日期过滤样板 4 处重复」）
 *
 * 入参须先经 isValidDateParam 校验；本函数只负责把通过校验的入参
 * 翻译为 {$gte,$lte} 形态，空值对应边界省略。
 * 调用形态：buildDateRangeFilter(startDate, endDate, timeZone)
 * @param {string|undefined} startDate 起始日期（date-only 或完整时间串）
 * @param {string|undefined} endDate 结束日期（同上，含当天末尾语义）
 * @param {string} [timeZone] date-only 入参按哪个 IANA 时区展开成当天首尾（缺省业务时区）。
 *   带时间且无偏移的串不吃这个参数：它原样交给 `new Date()`，落点由**宿主**时区决定，
 *   且 end 与 start 同值——已登记为欠账 A，判据见 src/tests/utils/dateBoundaryTzWiring.test.js。
 * @returns {Object} Mongo 范围条件对象（可能为空对象）
 */
const buildDateRangeFilter = (startDate, endDate, timeZone) => {
  const dateFilter = {};
  if (startDate) dateFilter.$gte = parseDateBoundary(startDate, 'start', timeZone);
  if (endDate) dateFilter.$lte = parseDateBoundary(endDate, 'end', timeZone);
  return dateFilter;
};

/**
 * 孤立代理项（未配对的 UTF-16 码元）：高代理项后面不跟低代理项，或低代理项前面不是高代理项。
 * 必须用前后瞻配对判定，不能用裸区间 `[\uD800-\uDFFF]` —— 那会把合法的 emoji 整个删掉。
 * 两个分支各只匹配**一个**码元，替换成 U+FFFD 后长度不变。
 */
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/g;

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
  const cleaned = value.replace(controlCharPattern, ' ').trim().slice(0, maxLength);
  // 孤立代理项必须在这里归一，且必须在截断**之后**：
  // `.length`/`.slice` 按 UTF-16 码元计数，奇数边界会把一个代理对劈成两半，
  // 留下的那半个码元在 UTF-8 里不存在 ⇒ BSON 落盘时驱动把它改写成 U+FFFD。
  // 而审计哈希是在序列化**之前**用内存文档算的（models/auditLogHooks.js），校验器却是
  // 拿读回来的文档重算（services/auditChainVerify.js）⇒ 「内存值 ≠ 落盘值」直接等价于
  // 一条没人碰过的记录永久报 hash_mismatch，与真实篡改同形（未认证者一条 user-agent 即可投毒）。
  // 换成 U+FFFD 而不是删掉：这正是存储层本来会做的动作，改完内存值与落盘值逐字符相同，
  // 长度语义（≤ maxLength）也不变；成对的代理对两个臂都不匹配，合法 emoji 一个都不丢。
  return cleaned.replace(LONE_SURROGATE, '\uFFFD');
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
      const ck = stripControlChars(k, 128);
      // 用 defineProperty 落键：直接 `cleaned[ck] = ...` 在 ck === '__proto__' 时
      // 触发原型 setter（把值挂成 cleaned 的原型而非自身键），导致审计副本与实际
      // 请求体不一致。defineProperty 把 '__proto__' 存为普通自身可枚举属性。
      Object.defineProperty(cleaned, ck, {
        value: stripControlCharsDeep(v, depth + 1),
        enumerable: true,
        writable: true,
        configurable: true,
      });
    }
    return cleaned;
  }
  return value;
};

/**
 * 访问日志中需要打码的 query 参数名（小写、按整键/下划线边界匹配）
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

// 短键（code / sign）不能做 includes 子串匹配，否则会误伤
// postcode/zipcode（都含 'code'）——合法业务参数被脱敏成 ***。
// 因此这一路按下划线边界判：精确相等，或以 _ 为边界的组合词
// （access_code / user_password / auth_token 命中；postcode / zipcode 放行）。
// 代价：按下划线判抓不到无分隔的拼接键（refreshtoken）与 camelCase（refreshToken），
// 所以它单独用不完备，必须与下面的子串名单取并集（见 isCredentialQueryKey）。
const matchesSensitiveQueryKey = (lower) =>
  SENSITIVE_QUERY_KEYS.some(
    (s) =>
      lower === s ||
      lower.endsWith(`_${s}`) ||
      lower.startsWith(`${s}_`) ||
      lower.includes(`_${s}_`)
  );

/**
 * 子串匹配名单（拼接键与 camelCase 只有子串抓得住）
 *
 * 审计 body 的脱敏走这一路：body 里凭据常以 currentPassword / refreshToken /
 * mfaCode 之类形态出现，没有下划线可依据边界。
 * 这里同时是审计与访问日志两条链路的共同事实来源（auditLogSanitizer 直接引用本数组）。
 *
 * 名单口径不止"凭据"：`phone` 也在列，且理由与凭据同类——AuditLog 是 append-only、
 * 会被定期导出 CSV 的集合，`security:audit` 持有者能从 GET /api/security/alerts
 * 与 /audit-logs 直接读出 body。此前 PUT /api/users/:id、POST /api/alarms/report
 * 这些写路径把**手机号明文**留在了 body 里，等于绕开仓里专为手机号建的合规通道
 * （POST /api/security/view-sensitive：二次验证 + view_sensitive_data 留痕）
 * 开了一个无需验证、无需 system:read、也不留任何痕迹的旁路。
 * 键名判定对嵌套同样生效，故 `reporter.phone`、`workPhone`、`phoneNumber` 一起收。
 * 不误伤的边界仍成立：`postcode` / `zipcode` 不含 "phone" 这个子串。
 */
const SENSITIVE_KEY_SUBSTRINGS = Object.freeze([
  'password',
  'currentpassword',
  'newpassword',
  'mfacode',
  'token',
  'refreshtoken',
  'secret',
  'apikey',
  'phone',
]);

/**
 * body 名单：子串匹配（比对前把键名压成纯字母数字）
 *
 * 为什么必须先压平：两条审计链路对"清洗"与"脱敏"的先后顺序不同
 * （writeStatics 先清洗后脱敏、security 中间件先脱敏后清洗），所以判定侧会
 * 看到两种噪声形态——清洗之前键里是原始控制字符 `pass\0word`，清洗之后
 * stripControlChars 把控制字符**换成空格**且只 trim 首尾，同一键变成 `pass word`。
 * 两种形态下 "password" 这个子串都是断的 ⇒ 名单命中不了 ⇒ 明文口令写进
 * append-only 并定期导出 CSV 的审计集合（本轮实测两处在压平前均原样保留值）。
 * 落在名单词首尾的噪声早已被 trim 掉，漏网的只有"插在中间"这一种形态。
 *
 * 用「删掉所有非字母数字」而不是「枚举空白+控制字符」：一类覆盖两种已知形态，
 * 且不必为控制字符正则加 no-control-regex 豁免；对业务键的误伤面没有变大——
 * 本名单里没有裸 code / otp 这类短词（它们归 SENSITIVE_QUERY_KEYS 那侧按下划线
 * 边界判），所以 `zip code` ⇒ `zipcode`、`postcode` ⇒ `postcode` 仍都不命中。
 */
const matchesSensitiveBodyKey = (lower) =>
  SENSITIVE_KEY_SUBSTRINGS.some((s) => lower.replace(/[^0-9a-z]/gi, '').includes(s));

/**
 * 「这个键的值算凭据」的唯一判定：边界名单 ∪ 子串名单
 *
 * 两份名单盲区方向相反（边界判漏 camelCase，子串判漏裸键 code/otp/authorization），
 * 任一单独使用都会留洞。审计 query/params 与访问日志 URL 打码必须用同一个函数：
 * 此前 URL 那侧只用了一半，于是 ?accessToken=xxx 明文进 combined 日志、
 * 同一条请求的审计副本里却是 ***，两边互相"证明"对方没问题。
 */
const isCredentialQueryKey = (key) => {
  const lower = String(key).toLowerCase();
  return matchesSensitiveQueryKey(lower) || matchesSensitiveBodyKey(lower);
};

/**
 * query 键名解码：判定「算不算凭据」之前必须先还原线上形态
 *
 * qs 解析查询串时会先 decode，所以 `?%74oken=<JWT>` 在业务侧就是 `?token=<JWT>`；
 * 而打码侧原本拿原始键名去匹配 ⇒ 一个百分号编码就绕开脱敏，
 * 同一请求的审计副本是 ***、访问日志与 404 响应体却是明文（两边互相"证明"没问题）。
 * 解码失败（非法百分号序列）回退原文：宁可多打一层码，不可因畸形输入放弃判定。
 */
const decodeQueryKey = (key) => {
  try {
    return decodeURIComponent(String(key).replace(/\+/g, ' '));
  } catch (_) {
    return String(key);
  }
};

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
      return isCredentialQueryKey(decodeQueryKey(key)) ? `${key}=***` : pair;
    })
    .join('&');
  return `${pathPart}?${redacted}`;
};

/**
 * 路径前缀判定：与路由同尺
 *
 * Express 默认 `case sensitive routing = false`，所以 /API/users 会真实命中
 * /api/users 的处理器；任何用字符串前缀比较来"按路径决定放行/记账/豁免"的判据
 * 都必须先归一大小写，否则改一个字母大小写就能换一套行为。
 * 审计侧的后果与落库字段处理见 utils/auditMeta.js 的同名注释。
 *
 * @param {string} fullPath 待判定的路径
 * @param {string} prefix 配置的前缀（自身也归一，防止配置写成 /API 时永不匹配）
 * @returns {boolean} 相等或为其子路径
 */
const matchesPathPrefix = (fullPath, prefix) => {
  const p = String(prefix || '').toLowerCase();
  if (!p) return false;
  const f = String(fullPath || '').toLowerCase();
  return f === p || f.startsWith(`${p}/`);
};

/** 列表版前缀判定（excludePaths / auditGetExcludePaths / RESERVED_PREFIXES / skipPaths 共用） */
const matchesAnyPathPrefix = (prefixes, fullPath) =>
  (prefixes || []).some((prefix) => matchesPathPrefix(fullPath, prefix));

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
  canonicalIdString,
  uniqueIdStrings,
  parseDateBoundary,
  isValidDateParam,
  buildDateRangeFilter,
  stripControlChars,
  stripControlCharsDeep,
  redactUrlQuery,
  SENSITIVE_QUERY_KEYS,
  matchesSensitiveQueryKey,
  SENSITIVE_KEY_SUBSTRINGS,
  matchesSensitiveBodyKey,
  isCredentialQueryKey,
  decodeQueryKey,
  matchesPathPrefix,
  matchesAnyPathPrefix,
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
  BREACHED_PASSWORD_STEMS,
  normalizePasswordForBreachCheck,
};
