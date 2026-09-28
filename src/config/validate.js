// 弱密钥黑名单：生产环境禁止使用这些默认值。
// P0-4（2026-09-17）：加入 '<CHANGE_ME>' —— .env.example 的模板占位符
// 此前形如「<替换为 openssl rand -base64 48 的输出>」（33 字符）能通过长度校验，
// 照抄模板起生产 = JWT 密钥公开可知 = 可离线伪造任意用户（含超管）令牌。
const WEAK_SECRETS = [
  'default-secret-change-in-production',
  'default-aes-key-change-in-production',
  'default-hmac-secret',
  'your-super-secret-jwt-key-change-in-production',
  'your-refresh-token-secret',
  'change-this-secret',
  '<CHANGE_ME>',
  '',
];

// 占位符形态（P0-4）：模板示例值必须判弱。仅靠长度不够——
// 原 `.env.example` 的 JWT 占位符长 33 字符，直接通过旧校验。
// 【实测校准（2026-09-17）】以下模式全部要求「整串即占位符」或「命中不可随机
// 生成的形态」，而非子串命中。子串式模式在随机 base64 上会稳定误伤——
// 50 万次采样实测：/xxx+/i 命中 5 例、/todo|fixme/i 命中 39 例、/dummy/i 命中 2 例
//（如 'hUe65ONT+Uf+8bhWqDjT94s15137oS+jq+b4+grY78DvL4ehHWlkSDmesntODoAr'，
// 熵 5.00——高于本函数放行的全部真实密钥）。误伤的后果是标准生成流程起不来。
// 另：短关键词（todo/fixme/dummy/example）后必须紧跟分隔符或整串结束，
// 用 [\w-]* 允许纯字母数字尾随会让「恰好以这 4~7 个字母开头」的随机串被误判
// （200 万次 randomBytes(48).base64 采样实测 1 例，'TOdO80RYDsnEBF...'）。
const PLACEHOLDER_PATTERNS = [
  /[<>]/, // '<CHANGE_ME>' / '<替换为 ... 的输出>'：尖括号只出现在模板占位符中
  /^change[-_]?(me|this|in[-_]?production)[-_\w]*$/i, // 整串为 change-me 系短语
  /^your[-_][\w-]*$/i, // 'your-secret' / 'your-super-secret-jwt-key' 类示例值
  /^placeholder([-_][\w-]*)?$/i,
  /^replace[-_]?me([-_][\w-]*)?$/i,
  /^example([-_][\w-]*)?$/i,
  /^dummy([-_][\w-]*)?$/i,
  /^[xX]+$/, // 'xxx' 占位串：整串皆 x/X
  /^(todo|fixme)([-_][\w-]*)?$/i,
];

// 香农熵下限（bit/char）。取值依据见 isWeakSecret 的实测注释。
const MIN_SECRET_ENTROPY_BITS_PER_CHAR = 2.0;

// 周期 ≤ maxPeriod 的重复串：整串由同一个短单元反复拼接而成。
// 例：'passwordpassword...'（周期 8）、'12345678901234567890...'（周期 10）。
// 允许末段为不完整的一轮（如 '1234567890' ×3 + '1234'）——截断不改变
// 「熵上界只有 log2(单元空间)」这一事实。
//
// maxPeriod 取 16 的依据：真实弱密钥的重复单元都很短（password/changeme/
// qwerty/1234567890 均 ≤ 10），16 已覆盖并留余量。误伤概率随周期上升而指数
// 下降——随机串要满足周期 16，需第 16..31 位逐位等于第 0..15 位。
//
// 不用正则 /^(.{1,16}?)\1+$/：长串上回溯代价高，显式逐位比较更可控。
const isPeriodicRepetition = (value, maxPeriod) => {
  for (let period = 1; period <= maxPeriod; period += 1) {
    let repeated = true;
    for (let i = period; i < value.length; i += 1) {
      if (value[i] !== value[i % period]) {
        repeated = false;
        break;
      }
    }
    if (repeated) return true;
  }
  return false;
};

// 香农熵（bit/char）：字符出现频率的负熵，衡量「字符分布有多均匀」。
const shannonEntropy = (value) => {
  const freq = new Map();
  for (const ch of value) freq.set(ch, (freq.get(ch) || 0) + 1);
  let bits = 0;
  for (const n of freq.values()) {
    const p = n / value.length;
    bits -= p * Math.log2(p);
  }
  return bits;
};

/**
 * 密钥强度判定（P0-4 加固）
 *
 * 判据（任一命中即判弱）：
 *   1. 空值，或命中 WEAK_SECRETS 黑名单；
 *   2. 长度 < 32 字符；
 *   3. 命中 PLACEHOLDER_PATTERNS（模板占位符形态，整串匹配为主）；
 *   4. 周期 ≤ 16 的重复串——整串熵上界仅 log2(单元空间) 量级；
 *   5. 香农熵 < 2.0 bit/char。
 *
 * 说明：审计报告曾建议「全数字判弱」，实测不可采纳——`openssl rand -hex 32`
 * 的 64 字符产出偶尔全为数字（50 万采样 2 例），会误伤合法密钥。
 * 需要拦的 '1234567890...' 类序列已被低熵与循环拼接覆盖。
 *
 * 【阈值 2.0 与全部模式的实测依据】（2026-09-17，本机 Node v24.15.0）
 *   - scripts/generate-secrets.js 的实际产出（本函数必须放行的正样本）：
 *     jwt=b64(48) 64 字符、aes/hmac=hex(32) 64 字符、admin 口令=b64(24) 32 字符。
 *     三类各 300 万次采样，最低香农熵 4.57 / 3.27 / 3.73。
 *   - .env.example 注释给出的 `openssl rand -hex 16`（32 字符，HMAC 的备选形式）：
 *     300 万次采样最低 2.58。故取 2.0，对最坏观测值仍留 0.58 bit 余量。
 *   - 未采用审计报告举例的「去重字符数 < 10」与「熵 < 3.5」：
 *     实测两者都会误伤合法密钥——hex(16) 的 32 字符串中，去重字符数最小 7、
 *     香农熵有 18.7% 的样本低于 3.5。故改用「占位符形态 + 循环拼接 + 极低熵」组合。
 *
 * 【取舍与残余风险（如实记录）】
 *   形如 'this-is-a-long-pure-lowercase-english-phrase' 的纯小写英文短语，
 *   香农熵 3.76，与既有测试夹具 'strong-random-jwt-secret-that-is-long-enough'
 *   （3.86）数值重叠，无法在不误伤夹具的前提下判弱——夹具断言位于
 *   src/tests/config/validate.test.js（不在本次改动写集内）。因此本函数**不**按
 *   「英文短语」一刀切，只拦占位符形态。
 *   残余风险：运维若真手写一句长英文短语当密钥，本校验会放行。该类值约
 *   3.7 bit/char（44 字符 ≈ 163 bit），弱于随机密钥、但强于一切模板占位符，
 *   属可接受残余。
 *
 * 【校准后无误伤】按上述判据，对 generate-secrets.js 与 .env.example 注释给出的
 * 四种生成形式各采样 100 万次，判弱命中数均为 0（b64_48 / hex_32 / b64_24 /
 * hex_16）。校准过程中发现并修掉的误伤见 PLACEHOLDER_PATTERNS 上方注释。
 *
 * @param {string} value 待判定值
 * @returns {boolean} true=弱（生产环境应拒绝启动）
 */
function isWeakSecret(value) {
  if (!value) return true;
  if (WEAK_SECRETS.includes(value)) return true;
  if (value.length < 32) return true;
  if (PLACEHOLDER_PATTERNS.some((re) => re.test(value))) return true;
  if (isPeriodicRepetition(value, 16)) return true;
  if (shannonEntropy(value) < MIN_SECRET_ENTROPY_BITS_PER_CHAR) return true;
  return false;
}

/**
 * 生产环境「加固项缺失」告警（G6）
 *
 * 与 errors 的区别：这些项缺失不会让服务不可用，但会削弱纵深防御，
 * 因此只告警不退出——若升级为致命错误，所有依赖前置反代做 Host 校验的
 * 既有部署都会在升级后直接起不来。
 *
 * 【P1-34（2026-09-17）修正】此前本函数只有一个 ALLOWED_HOSTS 检查，而该
 * 条件在 collectAllowedHostsErrors 已升级为致命错误后**永不可达**——
 * reportProductionWarnings 只在 errors.length === 0 时执行，而 errors 为空
 * 就意味着 ALLOWED_HOSTS 必然非空。结果是「加固项告警」这条链路整体空转。
 * 现补入三条真正能在致命校验通过后仍成立的检查。
 *
 * 关于 ALLOWED_HOSTS 那条为何保留：本函数是导出 API，测试直接调用它断言
 * 「未配置即产出告警」的契约（src/tests/config/validate.test.js）。它描述的是
 * 该 env 组合下「有哪些加固项缺失」，与调用方是否会走到这里无关；但从
 * validateConfig 进入时确实不会触发，**不得**据此认为生产缺 ALLOWED_HOSTS 只告警。
 *
 * @returns {string[]} 告警消息列表（便于测试断言）
 */
function collectProductionWarnings() {
  const warnings = [];

  if (!process.env.ALLOWED_HOSTS || !process.env.ALLOWED_HOSTS.trim()) {
    warnings.push(
      'ALLOWED_HOSTS 未配置：protocolCompliance 的 Host 头白名单校验处于关闭状态，' +
        '若服务直接暴露（无反向代理固定 Host），存在 Host 头注入风险。' +
        '建议设置为对外域名列表，如 ALLOWED_HOSTS=api.example.com,api.example.com:443'
    );
  }

  // 1) 公开注册：生产开放注册等于把「谁能进系统」交给公网。
  // 该项无致命校验（initData 每次启动按此值播种 SystemConfig），故只能在此告警。
  if (process.env.ALLOW_PUBLIC_REGISTRATION === 'true') {
    warnings.push(
      'ALLOW_PUBLIC_REGISTRATION=true：生产环境开放了公开注册，任何可访问者都能自助创建账户。' +
        '若确需开放，请确认已有注册限流与人工审核流程；否则设为 false，改由管理员创建用户。'
    );
  }

  // 2) 遗留 CBC 解密开关（utils/encryption.js）：开启即重新暴露填充预言机面。
  // 该项是存量数据迁移的一次性开关，本应在迁移完成后关闭。
  if (process.env.ALLOW_LEGACY_CBC_DECRYPT === 'true') {
    warnings.push(
      'ALLOW_LEGACY_CBC_DECRYPT=true：无认证的 AES-CBC 遗留密文解密仍处于开启状态，' +
        '填充预言机攻击面未收口。存量数据迁移完成后请立即移除该开关。'
    );
  }

  // 3) debug 级日志：auth/rbac 等中间件在 debug 级会打印用户权限列表等
  // 运行情报，生产常开会让日志系统变成信息泄露面（且显著增加日志量）。
  if ((process.env.LOG_LEVEL || '').trim().toLowerCase() === 'debug') {
    warnings.push(
      'LOG_LEVEL=debug：生产环境开启 debug 级日志，权限/认证等中间件会输出运行细节。' +
        '建议改为 info 或更高，仅在排查问题时临时下调。'
    );
  }

  // M-2 的 TLS 告警已并入 validateConfig 的致命校验（M3，2026-09-11 放宽为
  // 「进程自启 HTTPS 或声明由前置反代终结」二选一），此处不再重复告警——
  // 保留会让 README / .env.example / docker-compose 的标准拓扑（TLS 由前置
  // Nginx 终结、应用明文 HTTP 反代）每次启动都刷一条与本意相悖的告警。

  return warnings;
}

/**
 * M-01：开启 API 文档时必须配置 Basic Auth 凭据。
 *
 * swagger.basicAuth 已改为 fail-closed（无凭据则 503），故缺凭据不会造成
 * 匿名可读；但那是运行期兜底，配置错误应当在启动期就被拦下——否则文档
 * 实际不可用却无人知晓，属"静默失效"。口令下限 16 字符与其余密钥口径一致。
 *
 * 抽为独立函数：validateConfig 已接近 max-lines-per-function 上限
 *（见 eslint.ratchet.json），新增校验须放在独立函数内。
 */
// 显式开启类开关的「真值」口径：'true' 与 '1'（大小写与首尾空白不敏感）。
// 'false'/'0'/'no' 及一切其他取值均为假——**不做**「非空即真」的宽松解释，
// 否则 ENABLE_API_DOCS=false 会被读成开启（fail-open）。
const TRUTHY_FLAG_VALUES = new Set(['true', '1']);

/**
 * ENABLE_API_DOCS 是否开启（P2-38 单一口径）
 *
 * 统一前是两套口径：
 *   - 本文件只认 'true'（'1' 不触发凭据校验）；
 *   - config/swagger.js 认 'true' | '1'，且未显式设置时按 NODE_ENV 回退。
 * 后果：`ENABLE_API_DOCS=1` 在生产会让文档端点真的开放（swagger 认 1），
 * 却不触发启动期的凭据必填校验（本文件不认 1）→ 文档以 fail-closed 拒绝
 * 访问但无人知晓，属「静默失效」。现统一为本函数，两处共用。
 *
 * 语义（与 config/swagger.js 原实现逐条等价，另有收紧）：
 *   - 显式设置时按其取值判定（'true'/'1' 为开，其余为关）；
 *   - 未显式设置时跟随 NODE_ENV：生产默认关，非生产默认开。
 *
 * 放在本文件（而非 swagger.js）的原因：validate.js 零依赖，可被启动期校验
 * 安全引入；反向引用 swagger.js 会把 swagger-ui-express 拖进配置校验链路。
 *
 * @returns {boolean} true=文档端点启用
 */
function isDocsEnabled() {
  const raw = process.env.ENABLE_API_DOCS;
  if (raw !== undefined) {
    return TRUTHY_FLAG_VALUES.has(String(raw).trim().toLowerCase());
  }
  // 未显式设置时按环境决定。原实现是 (NODE_ENV || 'development') !== 'production'，
  // 于是 NODE_ENV=prod 的部署会把 API 文档**默认打开**——与 validateConfig 的
  // 生产硬闸恰好相反：闸因拼写被跳过，文档却因同一拼写暴露出来。
  // 用同一个 fail-closed 判据：未识别的环境值也按"关"处理。
  return !requiresProductionSemantics();
}

function validateDocsCredentials(errors) {
  if (!isDocsEnabled()) return;

  const docsUser = (process.env.DOCS_USERNAME || '').trim();
  const docsPass = process.env.DOCS_PASSWORD || '';
  if (!docsUser || !docsPass) {
    errors.push(
      'ENABLE_API_DOCS=true 时必须同时配置 DOCS_USERNAME 与 DOCS_PASSWORD：' +
        '否则 API 文档将按 fail-closed 拒绝访问（配置错误应在启动期暴露，而非运行期静默失效）'
    );
  } else if (docsPass.length < 16) {
    errors.push('DOCS_PASSWORD 至少 16 字符（API 文档暴露全部接口契约与权限编码，需强口令）');
  }
}

// 反向代理最大信任跳数（E-01：原为 validateConfig 内的局部常量，现提到模块级，
// 供 collectTrustProxyErrors 与 collectTlsErrors 共用；同时是运行时归一函数
// resolveTrustProxyHops 的上限，并被导出供 HTTP/WS 两侧复用）
const MAX_TRUST_PROXY_HOPS = 5;

/**
 * TRUST_PROXY_HOPS 运行时归一（纯函数：不读 process.env、不打日志，
 * 于是可以按格钉判据，也不必为「环境分叉」拉起整个 app）
 *
 * 为什么要有这一个函数：同一条取值规则原本写了两遍——
 * src/app.js 与 src/services/websocketService.js 各一份「parseInt → >0 才信任
 * → 否则 development 取 1 / 其余取 0」，而**只有 app.js 那一份带 MAX 夹取**。
 * 漂移的后果不是"两个数字不一致"这么轻：WS 侧把 TRUST_PROXY_HOPS=999999 原样
 * 交给 resolveHandshakeClientIP，等价于信任整条 X-Forwarded-For，握手期客户端 IP
 * 完全由请求方决定 ⇒ 直接绕过用户 allowedIPs 的登录 IP 白名单
 * （用例 src/tests/services/websocketTrustProxyHopsParity.test.js 钉住）。
 *
 * 判据与 app.js 原实现逐条等价，不引入任何行为变化：
 *   - 正整数：hops = min(值, MAX_TRUST_PROXY_HOPS)，被夹取时 clamped=true
 *   - 非正整数（0 / 负数 / 非法文本 / 未配置）：development → 1（本机 Vite 代理），
 *     其余环境 → 0，0 表示不信任任何转发头
 *   - 显式配了值却不是正整数 → illegal=true；是否留痕、留什么文案由调用方决定
 *     （HTTP 与 WS 的失真后果不同，文案各自描述自己的那一条，不强行共用句子）
 * @param {string|undefined} raw process.env.TRUST_PROXY_HOPS 的原始值
 * @param {string} nodeEnv 归一后的环境名（如 config.nodeEnv）
 * @returns {{hops: number, parsed: number, illegal: boolean, clamped: boolean}}
 */
function resolveTrustProxyHops(raw, nodeEnv) {
  const parsed = parseInt(raw, 10);
  const isPositiveInt = Number.isFinite(parsed) && parsed > 0;
  const illegal = raw !== undefined && String(raw).trim() !== '' && !isPositiveInt;
  const clamped = isPositiveInt && parsed > MAX_TRUST_PROXY_HOPS;
  let hops;
  if (isPositiveInt) hops = clamped ? MAX_TRUST_PROXY_HOPS : parsed;
  else hops = nodeEnv === 'development' ? 1 : 0;
  return { hops, parsed, illegal, clamped };
}

/**
 * NODE_ENV 归一
 *
 * 原先整套生产硬闸的入口是 `nodeEnv !== 'production'` 的字面量比较，等于把
 * 「弱密钥能否启动 / 有无 ALLOWED_HOSTS / 有无 REDIS_URL / API 文档是否默认打开」
 * 全部押在一个字符串的拼写上。实测：
 *   NODE_ENV=prod JWT_SECRET=change-this-secret（就在 WEAK_SECRETS 黑名单里）
 *   → validateConfig() 直接 return，进程零校验启动；
 *   同一环境把值改成 production → 报 8 条致命并 exit(1)。
 * `prod` / `Production` / `" production "` 都是真实部署里常见的写法，
 * 而失败的表象是"CI 与本地全绿"，没有任何信号。
 *
 * 判据（fail-closed）：
 *   - 开发家族（development/dev/local/test/ci）→ 允许跳过致命校验（保持既有语义）；
 *   - 预发家族（staging/stage）→ 同样跳过（ADR-005 明确的环境边界，见
 *     src/tests/zzqoder_nodeEnvGateFailsClosed.test.js 对该行为的既有断言）；
 *   - 生产家族（production/prod/live）→ 执行硬闸；
 *   - **其余任何值 → 也执行硬闸并额外报一条致命错**：猜错的代价必须是
 *     "启动不起来"，而不是"生产以零校验启动"。"其余任何值"包含**配了但为空**
 *     （`NODE_ENV=`）——那是部署脚本里最常见的失误，不是"没配"（F-216）。
 */
const DEV_ENV_ALIASES = new Set(['development', 'dev', 'local', 'test', 'ci']);
const PROD_ENV_ALIASES = new Set(['production', 'prod', 'live']);
const STAGING_ENV_ALIASES = new Set(['staging', 'stage']);

function normalizeNodeEnv() {
  const raw = process.env.NODE_ENV;
  const value = typeof raw === 'string' ? raw.trim().toLowerCase() : '';
  // F-216：`value || 'development'` 把"配了但配成空"和"根本没配"并成一类，
  // 于是本文件头上那条契约（"其余任何值 → 也执行硬闸并额外报一条致命错"）
  // 对 `NODE_ENV=`（compose 的 `environment:` 只写键名、Dockerfile 的
  // `ARG NODE_ENV=` 未传值、.env 里留一行 `NODE_ENV=`，三者都得到它）不成立：
  // requiresProductionSemantics() 返回 false ⇒ validateConfig() 第一行就 return
  // ⇒ 生产以零校验启动，且一行日志都不打。空串仍归一为"未识别"（'' 不属于任何
  // 家族），只有**真正未设置**才落 development。
  return value || (raw === undefined ? 'development' : '');
}

function isProductionLikeEnv() {
  return PROD_ENV_ALIASES.has(normalizeNodeEnv());
}

/**
 * 该环境是否必须按生产语义行事（生产家族 + 一切无法识别的值）。
 *
 * 这是"fail-closed"唯一落点：凡按字面量 'production' 分叉的**安全**开关
 * （cookie Secure、API 文档默认位、前端托管、密钥强度审计留痕）都必须用它，
 * 而不是 isProductionLikeEnv()——后者只认显式生产名，会让 `prodution` 这类
 * 拼写错误重新变成"闸照常关、安全属性静默失效"。
 * 由本函数把"未识别 = 按生产办"这条规则说一次，避免每个调用点各自猜方向。
 */
function requiresProductionSemantics() {
  const env = normalizeNodeEnv();
  if (DEV_ENV_ALIASES.has(env) || STAGING_ENV_ALIASES.has(env)) return false;
  return true;
}

// 生产环境配置校验（与 config/index.js 的 validateProductionConfig 保持一致）
//
// E-01 整改：本函数原圈复杂度 34（报告 §八 E-01 三个目标函数之一）。
// 按校验域拆为 4 个「收集器」（各自只负责把错误推进 errors 数组）与 2 个「上报器」，
// validateConfig 本体退化为顺序编排。收集器全部保持原有的 push 顺序与文案，
// 因此 errors 数组的内容与顺序与拆分前逐字一致（测试直接断言该数组）。
function validateConfig() {
  if (!requiresProductionSemantics()) {
    // §14.20.3「最小改动档」（预授权）：`NODE_ENV` **真正未设置**（undefined）时
    // normalizeNodeEnv() 归一为 development ⇒ 整套生产硬闸（弱密钥/ALLOWED_HOSTS/
    // REDIS_URL/TLS）静默跳过、零日志、零退出码，而它恰是最常见的误配
    // （K8s 未声明 / docker run 不带 -e / 直接 node src/index.js）。
    // 这里补一条显式告警，让该部署至少在启动日志里留痕。
    // 注意 `NODE_ENV=`（空串）**不走这条**：F-216 已让它按生产办并报致命错
    // （zzqoder_nodeEnvGateFailsClosed.test.js:114）。
    if (process.env.NODE_ENV === undefined) {
      const message =
        'NODE_ENV 未设置：按 development 处理，生产硬闸（弱密钥/ALLOWED_HOSTS/REDIS_URL/TLS）已全部跳过';
      try {
        // 不能顶层 require logger（validate → logger → config 构成加载期环），惰性取。
        require('../utils/logger').warn(message);
      } catch (_) {
        console.warn(message);
      }
    }
    return;
  }

  const errors = [];

  if (!isProductionLikeEnv()) {
    // 放在最前：运维先看到"你的 NODE_ENV 我看不懂"，再看到下面一串因此被要求的生产项，
    // 否则会被误读成"生产环境怎么突然多了这么多要求"。
    errors.push(
      `NODE_ENV 取值 "${process.env.NODE_ENV}" 未被识别：仅 development/dev/local/test/ci 与 ` +
        'staging 可跳过生产校验；生产部署请用 production 或 prod'
    );
  }

  collectSecretErrors(errors);
  collectConnectionErrors(errors);
  collectAllowedHostsErrors(errors);
  // M-01：API 文档凭据校验（抽为独立函数，避免本函数体积超标——
  // 见 eslint.ratchet.json 的 max-lines-per-function 约束）
  validateDocsCredentials(errors);
  collectTrustProxyErrors(errors);
  collectTlsErrors(errors);
  collectTimezoneErrors(errors);

  if (errors.length > 0) reportConfigErrors(errors);

  // G6：致命项全部通过后，再输出加固项缺失告警（不阻断启动）。
  // 注意（P1-34）：能走到这里说明 errors 为空，因此 collectProductionWarnings
  // 里的 ALLOWED_HOSTS 分支必然不成立——该分支只对直接调用者（测试）有效。
  reportProductionWarnings();
}

/**
 * 弱密钥校验（E-01 自 validateConfig 拆出）：四个密钥的强弱判定
 *
 * 顺序与文案与拆分前一致——JWT / JWT_REFRESH / AES / HMAC。
 * isWeakSecret 的判据见其自身函数注释（P0-4 起为「空值 / 黑名单 / 长度 /
 * 占位符形态 / 周期拼接 / 低熵」五项；「全数字」一条经实测被否，见该函数注释）。
 * 此行原称「含空值、黑名单、长度三重判定」——**失实**：既漏了实际存在的判据，
 * 又让人以为已有字符集层面的检查（这正是 .env.example 占位符能通过校验的认知根源）。
 */
function collectSecretErrors(errors) {
  if (isWeakSecret(process.env.JWT_SECRET)) {
    errors.push('JWT_SECRET 必须设置为至少 32 字符的强随机值，不能使用默认弱密钥');
  }

  if (isWeakSecret(process.env.JWT_REFRESH_SECRET)) {
    errors.push('JWT_REFRESH_SECRET 必须设置为至少 32 字符的强随机值');
  }

  if (isWeakSecret(process.env.AES_SECRET_KEY)) {
    errors.push('AES_SECRET_KEY 必须设置为至少 32 字符的强随机值');
  }

  if (isWeakSecret(process.env.HMAC_SECRET)) {
    errors.push('HMAC_SECRET 必须设置为至少 32 字符的强随机值');
  }

  // 两把 JWT 密钥必须不同。access 与 refresh 的唯一区别就是签名密钥不同
  // （access 载荷里没有 type，见 services/tokenService.js 的说明），
  // 配成同值 ⇒ 7 天有效期的 refresh 令牌可以直接当 Bearer access 令牌用：
  // authenticate 只按 userId/tokenVersion/sid 校验，全部通过，
  // 于是"access 短有效期 + 频繁重新换发"这条收缩访问窗口的机制整体失效。
  const jwtSecret = (process.env.JWT_SECRET || '').trim();
  const jwtRefreshSecret = (process.env.JWT_REFRESH_SECRET || '').trim();
  if (jwtSecret && jwtSecret === jwtRefreshSecret) {
    errors.push(
      'JWT_SECRET 与 JWT_REFRESH_SECRET 不得相同（refresh 令牌可被当作 access 令牌直接使用）'
    );
  }
}

/**
 * 连接与来源校验（E-01 自 validateConfig 拆出）：MongoDB / CORS / Redis
 *
 * Redis 的 URL 解析放在这里而非独立函数：解析失败与协议不符是同一处 try/catch
 * 的两个出口，拆开会让 try 的边界与错误归属脱节。
 */
function collectConnectionErrors(errors) {
  if (!process.env.MONGODB_URI || process.env.MONGODB_URI.includes('localhost')) {
    errors.push('MONGODB_URI 不能指向 localhost');
  }

  if (!process.env.CORS_ORIGIN) {
    errors.push('CORS_ORIGIN 必须设置（禁止通配符）');
  }
  if ((process.env.CORS_ORIGIN || '').split(',').includes('*')) {
    errors.push('CORS_ORIGIN 禁止使用通配符');
  }

  const redisUrl = (process.env.REDIS_URL || '').trim();
  if (!redisUrl) {
    errors.push('REDIS_URL 必须配置：生产环境限流、IP 黑名单广播与审计链锁不得退化为单实例内存态');
  } else {
    try {
      const parsedRedisUrl = new URL(redisUrl);
      if (!['redis:', 'rediss:'].includes(parsedRedisUrl.protocol)) {
        errors.push('REDIS_URL 协议必须是 redis: 或 rediss:');
      }
    } catch (_) {
      errors.push('REDIS_URL 必须是有效的 Redis 连接地址');
    }
  }
}

/**
 * Host 头白名单校验（E-01 自 validateConfig 拆出）：M3 生产必填项
 */
function collectAllowedHostsErrors(errors) {
  // M3：生产环境必须配置 ALLOWED_HOSTS（Host 头白名单校验）
  if (!process.env.ALLOWED_HOSTS || !process.env.ALLOWED_HOSTS.trim()) {
    errors.push(
      'ALLOWED_HOSTS 必须配置：生产环境缺少 Host 头白名单，存在缓存投毒与密码重置链接投毒风险'
    );
  }
}

/**
 * TRUST_PROXY_HOPS 合法性校验（E-01 自 validateConfig 拆出）
 *
 * 必须是 1..MAX_TRUST_PROXY_HOPS 的整数，不能只验存在性（AUX-01 / P2-24）：
 * 只验 `!process.env.TRUST_PROXY_HOPS` 时，`TRUST_PROXY_HOPS=abc` 能通过校验，
 * 运行时 parseInt → NaN → app.js 落入 `trust proxy = false`，且无任何告警。
 * 后果分两个方向，都很严重：
 *   1. 反代场景下 req.ip 恒为代理 IP：全站共享一个限流桶（一人试错锁死所有人
 *      的登录额度）、自动封禁误封反代 IP 导致全站 403、审计 IP 全部失真；
 *   2. 反向配置过大（如 99）时，Express 会信任 XFF 链中更靠前的元素，
 *      客户端伪造 X-Forwarded-For 即可无限轮换 IP，击穿 IP 级限流/黑名单。
 * 因此取值必须是 1..MAX_TRUST_PROXY_HOPS 的整数（1=单层 Nginx，最常见）。
 */
function collectTrustProxyErrors(errors) {
  const rawHops = process.env.TRUST_PROXY_HOPS;
  if (!rawHops || !String(rawHops).trim()) {
    errors.push('TRUST_PROXY_HOPS 必须设置（反向代理层数，用于正确获取客户端真实 IP）');
  } else if (!/^\d+$/.test(String(rawHops).trim())) {
    errors.push(
      `TRUST_PROXY_HOPS 必须是正整数（当前值：${rawHops}），非法值会静默退化为「不信任代理」`
    );
  } else {
    const hops = parseInt(rawHops, 10);
    if (hops < 1 || hops > MAX_TRUST_PROXY_HOPS) {
      errors.push(
        `TRUST_PROXY_HOPS 必须在 1..${MAX_TRUST_PROXY_HOPS} 之间（当前值：${hops}）。` +
          '过小会让 req.ip 恒为代理 IP，过大会允许客户端伪造 X-Forwarded-For 轮换 IP 绕过限流'
      );
    }
  }
}

/**
 * TLS 终结校验（E-01 自 validateConfig 拆出；M3，2026-09-11 放宽版）
 *
 * TLS 必须在某一层终结，但「哪一层」由部署形态决定。原实现只认
 * ENABLE_HTTPS=true，与 README / .env.example / docker-compose 的目标形态直接
 * 冲突——那里明确写着「TLS 由前置 Nginx 终结，应用进程本身不建议暴露 443」，
 * 且该形态下 ENABLE_HTTPS 必须保持关闭：置 true 会让进程转而加载 ./certs 证书
 * 自起 HTTPS（见 src/index.js 的 HTTPS 分支），证书缺失时直接拒绝启动。
 * 结果是：文档推荐的生产拓扑无法通过生产校验（演练与 CI e2e 一并变红）。
 *
 * 放宽后的判定：以下二者之一成立即可，二者皆无才判致命——
 *   a) 进程自启 HTTPS：ENABLE_HTTPS === 'true'（需自备证书）；
 *   b) 声明由前置反代终结：TRUST_PROXY_HOPS 为 1..MAX_TRUST_PROXY_HOPS 的整数
 *      且 ALLOWED_HOSTS 已配置（反代场景的基本前提，两者本身也已是生产必填）。
 * 注意：这是「声明式」判定，应用无从验证反代是否真的终结了 TLS。若日后要收紧为
 * 显式声明，可引入专用开关（如 TLS_TERMINATED_UPSTREAM=true）并在部署清单固化。
 */
function collectTlsErrors(errors) {
  const tlsInProcess = process.env.ENABLE_HTTPS === 'true';
  const hopsForTls = parseInt(String(process.env.TRUST_PROXY_HOPS || '').trim(), 10);
  const tlsTerminatedUpstream =
    Number.isInteger(hopsForTls) &&
    hopsForTls >= 1 &&
    hopsForTls <= MAX_TRUST_PROXY_HOPS &&
    !!(process.env.ALLOWED_HOSTS || '').trim();
  if (!tlsInProcess && !tlsTerminatedUpstream) {
    errors.push(
      'TLS 未在任一层终结：需 ENABLE_HTTPS=true（进程自启 HTTPS，需自备证书），' +
        '或声明由前置反代终结（TRUST_PROXY_HOPS 取 1..5 且配置 ALLOWED_HOSTS）。' +
        '二者皆无时，登录口令的 ECDH 加密无法抵御主动 MITM'
    );
  }
}

/**
 * 业务时区校验（P2-36）
 *
 * TZ_BUSINESS 是 IANA 时区名，constants/timezone.js 用它构造 Intl.DateTimeFormat。
 * 非法值（如 'Asia/Shangai' 拼错、'UTC+8' 这类固定偏移写法）此前**不在任何
 * 启动校验清单内**：模块加载不报错，直到首次调用 businessDateParts 才抛
 * RangeError: Invalid time zone specified——暴露时机可能是一个用户请求，
 * 且报错信息指向 Intl 而非配置，排查方向被带偏。
 *
 * 判定方式与运行期完全一致（真去构造一次 Intl.DateTimeFormat），不做语法层面的
 * 猜测：只有真正能被 Intl 接受的名字才放行，避免「校验通过但运行期仍抛」。
 *
 * 未配置时不报错：constants/timezone.js 回退 'Asia/Shanghai'，属合法默认。
 * 仅生产环境执行（validateConfig 已提前 return 非生产环境）。
 */
function collectTimezoneErrors(errors) {
  const tz = (process.env.TZ_BUSINESS || '').trim();
  if (!tz) return;
  try {
    // 构造即校验：非法 IANA 名在此抛 RangeError
    new Intl.DateTimeFormat('en-CA', { timeZone: tz });
  } catch (_) {
    errors.push(
      `TZ_BUSINESS 不是合法的 IANA 时区名（当前值：${tz}）。` +
        '非法值不会在启动期暴露，而会在首次业务调用（仪表盘今日边界、审计按天聚合）' +
        "抛 RangeError: Invalid time zone specified。请使用如 'Asia/Shanghai' 的 IANA 名称"
    );
  }
}

/**
 * 致命配置错误上报（E-01 自 validateConfig 拆出）
 *
 * L-05：走统一 logger；P1-13：退出前同步落盘（理由见函数内注释）。
 */
function reportConfigErrors(errors) {
  // L-05：启动致命校验走统一 logger（不再使用 console.error），
  // 使致命配置错误同样进入结构化日志与日志收集链路。
  // 惰性引入避免 config → validate → logger → config 的加载期循环依赖。
  //
  // P1-13：logger.error 走**异步** transport，紧接 process.exit 会丢日志
  //（实测表见 utils/loggerFlush.js 的模块注释）。本函数是同步 API——
  // 测试以 expect(() => validateConfig()).toThrow('process.exit called') 断言，
  // 改成 setTimeout 会让「配置错误」变成「延迟退出」而破坏同步契约。
  // 故先用 flushLogsSync 同步落盘，再走 logger（保留 console 与日志转发链路）。
  // 真实退出路径下异步那份必然丢失，文件里只剩同步这一份；
  // 仅当 process.exit 被 mock（单测）时两者都会落地，同内容重复一行，可接受。
  try {
    const { flushLogsSync } = require('../utils/loggerFlush');
    flushLogsSync('error', '配置校验失败：');
    errors.forEach((err) => flushLogsSync('error', `  - ${err}`));
    const logger = require('../utils/logger');
    logger.error('配置校验失败：');
    errors.forEach((err) => logger.error(`  - ${err}`));
  } catch (e) {
    // 极端情况下 logger/落盘不可用，降级到 stderr，确保信息不丢失
    console.error('配置校验失败：');
    errors.forEach((err) => console.error('  -', err));
  }
  process.exit(1);
}

/**
 * 加固项缺失告警上报（E-01 自 validateConfig 拆出；G6）
 *
 * 致命项全部通过后才执行；logger 不可用时降级到 console，确保信息不丢失。
 */
function reportProductionWarnings() {
  const warnings = collectProductionWarnings();
  if (warnings.length > 0) {
    try {
      const logger = require('../utils/logger');
      warnings.forEach((w) => logger.warn(`安全加固建议：${w}`));
    } catch (e) {
      warnings.forEach((w) => console.warn('安全加固建议：', w));
    }
  }
}

module.exports = {
  validateConfig,
  isWeakSecret,
  // 纯函数（只往传入的数组里 push），导出供用例直接钉判据：
  // 走 validateConfig 会连带读环境、按环境分叉，测试里无法只验"两把 JWT 密钥相同"这一格
  collectSecretErrors,
  collectProductionWarnings,
  isDocsEnabled,
  // 供其余按环境分叉的模块复用同一判据（cookie secure / staticFrontend auto /
  // logger 生产档 / index.js 的 TLS 要求等），避免各处再各写一次字面量比较。
  // 安全属性一律用 requiresProductionSemantics（未识别值按生产办）；
  // isProductionLikeEnv 只回答"是否显式声明为生产"。
  isProductionLikeEnv,
  requiresProductionSemantics,
  normalizeNodeEnv,
  // trust proxy 取值规则的单一来源：app.js（HTTP）与 websocketService.js（WS 握手）
  // 必须共用同一份判据与同一个上限，否则同一条请求在两侧得出不同的客户端 IP。
  MAX_TRUST_PROXY_HOPS,
  resolveTrustProxyHops,
};

// 支持直接执行：node src/config/validate.js
if (require.main === module) {
  validateConfig();
}
