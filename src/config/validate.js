// F-01（2026-10-16 独立审计，P1）：可信代理网段的解析判据在 config/trustedProxies.js，
// 本文件只把它的结论接到启动闸上。依赖方向 config → utils（trustedProxies 依赖
// utils/ipUtils 的 CIDR 原语），与 config/swagger.js 同向，不构成环。
const trustedProxies = require('./trustedProxies');
// 部署凭据强度 / CORS 来源 / 告警 webhook 配置三组启动闸（2026-10-24 审计），
// 判据与取值理由见该文件头注释；独立成模块以避开本文件的体积棘轮。
const deploymentGuards = require('./deploymentCredentialGuards');

// 弱密钥黑名单：生产环境禁止使用这些默认值。
// 加入 '<CHANGE_ME>' —— .env.example 的模板占位符
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

// 占位符形态：模板示例值必须判弱。仅靠长度不够——
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
// 遗留 CBC 解密开关的告警判据（含"为何不阻断启动"的取舍说明）在独立模块：
// 本文件行数贴着 max-lines 棘轮上限，新增判据须放到独立文件——同 metricsAuditDrops 的惯例。
// immutable 档位（改配置需配套数据迁移）的判据同在独立模块，理由相同。
const { cbcAndInvariantWarnings } = require('./legacyCbcGuard');
// 登录密文轨 strict 未开的告警（含「为何不阻断启动」的取舍说明）同样在独立模块：
// LOGIN_ENCRYPT_STRICT 关死明文口令轨的前提是浏览器有 WebCrypto，而纯 HTTP
// 内网形态拿不到——致命闸会拦死一种合法部署，故只做 loud warning + 计数。
const { loginEncryptWarnings } = require('./loginEncryptGuard');

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
 * 密钥强度判定（加固）
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
 * 【修正】此前本函数只有一个 ALLOWED_HOSTS 检查，而该
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
  // 【2026-09-30 加固】从"一条日志"升级为可观测的安全告警（同时计 incSecurityAlert），
  // 并**刻意不阻断启动**。判据与取舍说明集中在 config/legacyCbcGuard.js（本文件的行数
  // 已贴着 max-lines 棘轮上限，新增判据须放到独立模块——同 metricsAuditDrops 的惯例）。
  for (const w of cbcAndInvariantWarnings()) warnings.push(w);

  // 3) debug 级日志：auth/rbac 等中间件在 debug 级会打印用户权限列表等
  // 运行情报，生产常开会让日志系统变成信息泄露面（且显著增加日志量）。
  if ((process.env.LOG_LEVEL || '').trim().toLowerCase() === 'debug') {
    warnings.push(
      'LOG_LEVEL=debug：生产环境开启 debug 级日志，权限/认证等中间件会输出运行细节。' +
        '建议改为 info 或更高，仅在排查问题时临时下调。'
    );
  }
  // 4) 登录密文轨 strict 未开（config/loginEncryptGuard.js）：明文口令字段仍可上行。
  // 与 2) 同型的「告警 + 计数、不阻断启动」——判据与取舍说明集中在独立模块。
  for (const w of loginEncryptWarnings()) warnings.push(w);

  // TLS 告警已并入 validateConfig 的致命校验（M3，2026-09-11 放宽为
  // 「进程自启 HTTPS 或声明由前置反代终结」二选一），此处不再重复告警——
  // 保留会让 README / .env.example / docker-compose 的标准拓扑（TLS 由前置
  // Nginx 终结、应用明文 HTTP 反代）每次启动都刷一条与本意相悖的告警。

  return warnings;
}

/**
 * 开启 API 文档时必须配置 Basic Auth 凭据。
 *
 * swagger.basicAuth 已改为 fail-closed（无凭据则 503），故缺凭据不会造成
 * 匿名可读；但那是运行期兜底，配置错误应当在启动期就被拦下——否则文档
 * 实际不可用却无人知晓，属"静默失效"。口令下限 32 字符，与其余密钥（HMAC / AES / JWT 均 ≥32）同口径；此处是唯一口径，以本函数下方的 `docsPass.length < 32` 为准。
 *
 * 抽为独立函数：validateConfig 已接近 max-lines-per-function 上限
 *（见 eslint.ratchet.json），新增校验须放在独立函数内。
 */
// 显式开启类开关的「真值」口径：'true' 与 '1'（大小写与首尾空白不敏感）。
// 'false'/'0'/'no' 及一切其他取值均为假——**不做**「非空即真」的宽松解释，
// 否则 ENABLE_API_DOCS=false 会被读成开启（fail-open）。
const TRUTHY_FLAG_VALUES = new Set(['true', '1']);

/**
 * ENABLE_API_DOCS 是否开启（单一口径）
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
  // 未显式设置时跟随硬闸判据（staging 默认同生产，只有显式宽松才默认开）：原实现用
  // 字面量比较，NODE_ENV=prod 的部署里"闸被跳过、文档却打开"——同一条判据才不会再分叉。
  return !requiresProductionHardening();
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
  } else if (docsPass.length < 32 || isWeakSecret(docsPass)) {
    errors.push(
      'DOCS_PASSWORD 必须是至少 32 字符的强随机值（API 文档暴露全部接口契约与权限编码，需强口令）'
    );
  }
}

// 反向代理最大信任跳数（原为 validateConfig 内的局部常量，现提到模块级，
// 供 collectTrustProxyErrors 与 collectTlsErrors 共用；同时是运行时归一函数
// resolveTrustProxyHops 的上限，并被导出供 HTTP/WS 两侧复用）
const MAX_TRUST_PROXY_HOPS = 5;

/**
 * TRUST_PROXY_HOPS 运行时归一（纯函数：不读 process.env、不打日志，
 * 于是可以按格钉判据，也不必为「环境分叉」拉起整个 app）
 *
 * 为什么要有这一个函数：同一条取值规则原本写了两遍——
 * src/app.js 与 src/services/websocketService/handshake.js 各一份「parseInt → >0 才信任
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

// A-1（2026-10-26）：NODE_ENV 归一与"生产语义"判定已抽到 config/envSemantics.js
// （零 require 的叶子模块），此处只做 re-export，对外契约不变。
// 抽出的理由写在那个文件头上：logger.js 曾为取一个判据把整张配置图拉进自己的
// 加载链，并在依赖图上形成 logger ↔ config 的环。
const {
  normalizeNodeEnv,
  isProductionLikeEnv,
  isStagingLikeEnv,
  stagingLeniencyAcknowledged,
  requiresProductionSemantics,
  requiresProductionHardening,
} = require('./envSemantics');

// 生产环境配置校验（与 config/index.js 的 validateProductionConfig 保持一致）
//
// 按校验域拆为「收集器」+「上报器」，validateConfig 本体只做顺序编排。errors 的内容与
// 顺序由测试直接断言锁定：收集器的 push 顺序与文案属于对外契约，新增项须同步更新期望。
function validateConfig() {
  // NODE_ENV 是环境声明，不是"跳过校验"的开关：staging 默认与生产同判，只有显式
  // FSMS_ALLOW_STAGING_LENIENT=true 才放宽（后果由 reportStagingLeniency 逐条打印）。
  if (process.env.NODE_ENV === undefined) {
    reportConfigErrors([
      'NODE_ENV 必须显式设置（development/dev/local/test/ci/staging 或 production/prod/live），' +
        '未设置时拒绝启动，避免以开发语义跳过生产安全校验',
    ]);
    return;
  }
  if (!requiresProductionHardening()) {
    // 2026-10-24 审计：声明了生产语义却落在开发家族 ⇒ 拒绝启动（判据在 guards 模块）。
    // requiresProductionSemantics 只管诊断口径（日志格式/采样率/前端托管），不再决定本闸。
    const envMismatch = deploymentGuards.productionSemanticsMismatch();
    if (envMismatch) {
      reportConfigErrors([envMismatch]);
      return;
    }
    reportStagingLeniency();
    return;
  }

  const errors = [];

  if (!isProductionLikeEnv() && !isStagingLikeEnv()) {
    // 放在最前：运维先看到"你的 NODE_ENV 我看不懂"，再看到下面一串因此被要求的生产项，
    // 否则会被误读成"生产环境怎么突然多了这么多要求"。staging 是已知环境（默认走硬闸），
    // 不在这条"未识别"文案里。
    errors.push(
      `NODE_ENV 取值 "${process.env.NODE_ENV}" 未被识别：仅 development/dev/local/test/ci 可跳过` +
        '生产校验；staging/stage 默认与 production 同判（放宽须显式 FSMS_ALLOW_STAGING_LENIENT=true）；' +
        '生产部署请用 production 或 prod'
    );
  }

  collectSecretErrors(errors);
  // P2-3 判据在 config/jwtRotation.js（validate.js 体积棘轮贴着上限）；
  // 启动期只调一次，惰性 require 与 config/index.js 的委托写法同型
  require('./jwtRotation').collectJwtRotationErrors(errors);
  // 运维凭据强度（Redis / metrics / 告警 webhook / 日志外发）与 webhook 配置完整性：
  // 原先只有"有没有"的判据，弱口令与占位符在启动期不可区分。
  deploymentGuards.collectRuntimeCredentialGuards(errors);
  collectConnectionErrors(errors);
  collectAllowedHostsErrors(errors);
  // API 文档凭据校验（抽为独立函数，避免本函数体积超标——
  // 见 eslint.ratchet.json 的 max-lines-per-function 约束）
  validateDocsCredentials(errors);
  collectTrustProxyErrors(errors);
  // F-01：生产启用 TRUST_PROXY_HOPS 时必须显式配置 TRUSTED_PROXY_CIDRS，禁止把
  // 「对端属私网/回环」当成代理身份；但**配了就必须配得对**——空项、解析不出、
  // 全域网段（0.0.0.0/0、::/0，等于宣布整个互联网都是可信代理）三类非法值，
  // 逐条判据与理由见 config/trustedProxies.js。非生产环境仍保留兼容回退，便于本地
  // 开发直接调用 createApp；生产入口在这里硬失败，避免安全边界只靠日志提醒。
  const rawTrustedProxyCidrs = process.env[trustedProxies.ENV_KEY];
  errors.push(...trustedProxies.parseTrustedProxyCidrs(rawTrustedProxyCidrs).errors);
  collectTlsErrors(errors);
  collectTimezoneErrors(errors);

  if (errors.length > 0) reportConfigErrors(errors);

  // G6：致命项全部通过后，再输出加固项缺失告警（不阻断启动）。
  // 注意：能走到这里说明 errors 为空，因此 collectProductionWarnings
  // 里的 ALLOWED_HOSTS 分支必然不成立——该分支只对直接调用者（测试）有效。
  reportProductionWarnings();
}

/**
 * 弱密钥校验（自 validateConfig 拆出）：四个密钥的强弱判定
 *
 * 顺序与文案固定为 JWT / JWT_REFRESH / AES / HMAC。
 * isWeakSecret 的判据见其自身函数注释（即「空值 / 黑名单 / 长度 /
 * 占位符形态 / 周期拼接 / 低熵」五项；「全数字」一条经实测被否，见该函数注释）。
 * 此行原称「含空值、黑名单、长度三重判定」——**失实**：既漏了实际存在的判据，
 * 又让人以为已有字符集层面的检查（这正是 .env.example 占位符能通过校验的认知根源）。
 */
// 配了密钥集后，legacy 单密钥不再是必填项：留空 = 「拒绝一切无 kid 令牌」，这正是轮换收尾
// （删掉旧钥）唯一能真正关掉旧钥的开关。反过来强制必填，旧钥泄露后永远无法吊销。
const hasKidSet = (name) => (process.env[name] || '').trim().length > 0;

function collectSecretErrors(errors) {
  if (!hasKidSet('JWT_SECRETS') && isWeakSecret(process.env.JWT_SECRET)) {
    errors.push('JWT_SECRET 必须设置为至少 32 字符的强随机值，不能使用默认弱密钥');
  }

  if (!hasKidSet('JWT_REFRESH_SECRETS') && isWeakSecret(process.env.JWT_REFRESH_SECRET)) {
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
 * 连接与来源校验（自 validateConfig 拆出）：MongoDB / CORS / Redis
 *
 * Redis 的 URL 解析放在这里而非独立函数：解析失败与协议不符是同一处 try/catch
 * 的两个出口，拆开会让 try 的边界与错误归属脱节。
 * 传输加密断言收口在 config/transportSecurity.js：非回环主机的
 * Mongo/Redis 不得明文过网，豁免走显式旗标（compose 的同宿主形态即豁免使用者）。
 */
function collectConnectionErrors(errors) {
  // Mongo/Redis 的 host 侧判据（含既有的 localhost 拒绝）收口在 transportSecurity
  require('./transportSecurity').collectTransportErrors(errors);

  // CORS 来源逐项解析：缺项 / 通配符 / 非完整来源 / 生产 http 来源
  deploymentGuards.collectCorsOriginErrors(errors);

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
 * Host 头白名单校验（自 validateConfig 拆出）：M3 生产必填项
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
 * TRUST_PROXY_HOPS 合法性校验（自 validateConfig 拆出）
 *
 * 必须是 1..MAX_TRUST_PROXY_HOPS 的整数，不能只验存在性：
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
  let validHops = false;
  if (!rawHops || !String(rawHops).trim()) {
    errors.push('TRUST_PROXY_HOPS 必须设置（反向代理层数，用于正确获取客户端真实 IP）');
  } else if (!/^\d+$/.test(String(rawHops).trim())) {
    errors.push(
      `TRUST_PROXY_HOPS 必须是正整数（当前值：${rawHops}），非法值会导致生产启动失败（fail-closed）`
    );
  } else {
    const hops = parseInt(rawHops, 10);
    if (hops < 1 || hops > MAX_TRUST_PROXY_HOPS) {
      errors.push(
        `TRUST_PROXY_HOPS 必须在 1..${MAX_TRUST_PROXY_HOPS} 之间（当前值：${hops}）。` +
          '过小会让 req.ip 恒为代理 IP，过大会允许客户端伪造 X-Forwarded-For 轮换 IP 绕过限流'
      );
    } else {
      validHops = true;
    }
  }

  // 一旦生产启用了 trust proxy，必须同时声明真实代理网段；仅按私网/回环
  // 判断对端身份会允许同一容器网络内的其他服务伪造 X-Forwarded-For。
  if (requiresProductionHardening() && validHops) {
    const trusted = trustedProxies.parseTrustedProxyCidrs(process.env[trustedProxies.ENV_KEY]);
    if (!trusted.configured) {
      errors.push(
        'TRUSTED_PROXY_CIDRS 必须配置：生产启用 TRUST_PROXY_HOPS 时，必须显式声明可信反向代理网段，' +
          '禁止按私网/回环地址回退信任'
      );
    }
  }
}

/**
 * TLS 终结校验（自 validateConfig 拆出；M3，2026-09-11 放宽版）
 *
 * TLS 必须在某一层终结，但「哪一层」由部署形态决定。原实现只认 ENABLE_HTTPS=true，与
 * README / .env.example / docker-compose 的「TLS 由前置 Nginx 终结」直接冲突：该形态下
 * ENABLE_HTTPS 必须保持关闭（置 true 会加载 ./certs 自起 HTTPS，证书缺失即拒启动），
 * 于是文档推荐的生产拓扑反而过不了生产校验（演练与 CI e2e 一并变红）。
 * 放宽后的判定（2026-10-24 收紧为显式声明）：以下二者之一成立即可——
 *   a) 进程自启 HTTPS：ENABLE_HTTPS === 'true'（需自备证书）；
 *   b) 部署方显式声明：TLS_TERMINATED_UPSTREAM === 'true'。
 * 「反代场景」不能用 TRUST_PROXY_HOPS 合法 + ALLOWED_HOSTS 非空来推断：这两项
 * 本身已是生产必填，用它们推断等于让 TLS 判据恒真（审计 P2，2026-10-24）。
 * 注意：这是「声明式」判定，应用无从验证反代是否真的终结了 TLS；但显式声明
 * 至少把"这份部署声称自己终结了 TLS"变成一条可审计的配置事实，而不是隐式推断。
 */
function collectTlsErrors(errors) {
  const tlsInProcess = process.env.ENABLE_HTTPS === 'true';
  // 2026-10-24 审计：原判据从 TRUST_PROXY_HOPS + ALLOWED_HOSTS 推断上游终结 TLS，
  // 而这两项在别处已必填 ⇒ 判据恒真、明文反代照样启动。现改为部署方显式声明。
  const tlsTerminatedUpstream = process.env.TLS_TERMINATED_UPSTREAM === 'true';
  if (!tlsInProcess && !tlsTerminatedUpstream) {
    errors.push(
      'TLS 终结层未声明：需 ENABLE_HTTPS=true（进程自启 HTTPS，需自备证书），' +
        '或 TLS_TERMINATED_UPSTREAM=true（声明由前置反代终结 TLS）。' +
        'TRUST_PROXY_HOPS 与 ALLOWED_HOSTS 已另有必填校验，不能再拿它们推断 TLS——' +
        '否则只提供明文 HTTP 的反代部署也会通过启动闸，口令的 ECDH 交换可被主动 MITM'
    );
  }
}

/**
 * 业务时区校验
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
 * 致命配置错误上报（自 validateConfig 拆出）
 *
 * L-05：走统一 logger；退出前同步落盘（理由见函数内注释）。
 */
function reportConfigErrors(errors) {
  // L-05：启动致命校验走统一 logger（不再使用 console.error），
  // 使致命配置错误同样进入结构化日志与日志收集链路。
  // 惰性引入避免 config → validate → logger → config 的加载期循环依赖。
  //
  // logger.error 走**异步** transport，紧接 process.exit 会丢日志
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
 * 加固项缺失告警上报（自 validateConfig 拆出；G6）
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
  isStagingLikeEnv,
  stagingLeniencyAcknowledged,
  requiresProductionSemantics,
  requiresProductionHardening,
  normalizeNodeEnv,
  // trust proxy 取值规则的单一来源：app.js（HTTP）与 websocketService/handshake.js（WS 握手）
  // 必须共用同一份判据与同一个上限，否则同一条请求在两侧得出不同的客户端 IP。
  MAX_TRUST_PROXY_HOPS,
  resolveTrustProxyHops,
};

// 预发宽松（显式声明）时跳过的硬闸清单：只用于启动日志，判据以 validateConfig 的调用顺序为准
const STAGING_SKIPPED_GATES = [
  '弱密钥 / JWT 轮换',
  '运维凭据与 webhook',
  'CORS 来源',
  'Mongo/Redis 传输与认证',
  'ALLOWED_HOSTS',
  '文档凭据',
  'TRUST_PROXY_HOPS 与 TRUSTED_PROXY_CIDRS',
  'TLS 终结',
  'TZ_BUSINESS',
];

/**
 * 预发宽松启动的显式登记：放宽不能是静默的——跳过了哪些硬闸、同时生效了哪些放宽项，
 * 必须在启动日志里逐条可见，否则与"一个变量把整张生产校验表关掉"没有区别。
 * 只对 staging + 显式 ack 发声；开发家族本地跑不打印（那是设计内的默认口径）。
 */
function reportStagingLeniency() {
  if (!isStagingLikeEnv() || !stagingLeniencyAcknowledged()) return;
  const lines = [
    '预发宽松启动已显式声明（FSMS_ALLOW_STAGING_LENIENT=true），以下生产硬闸本次全部跳过：',
    `  ${STAGING_SKIPPED_GATES.join(' / ')}`,
    `同时生效的放宽项：/api-docs 默认${isDocsEnabled() ? '开启' : '关闭'}（ENABLE_API_DOCS 未显式设置时为开）；`,
    '会话 cookie 无 Secure 位（COOKIE_SECURE 未显式 true）；限流参数越界不拒绝启动。',
    '生产部署请勿设置该开关：staging 默认与 production 同判据（硬闸全部执行）。',
  ];
  try {
    const logger = require('../utils/logger');
    lines.forEach((line) => logger.warn(line));
  } catch (e) {
    lines.forEach((line) => console.warn(line));
  }
}

// 支持直接执行：node src/config/validate.js（= `npm run validate`）
//
// 这一支是**独立进程入口**，不经过 src/config/index.js:11，于是没人替它把 <NAME>_FILE
// 回填进 process.env——而容器里密钥**只**以文件挂载（见 ./secrets.js）。
// 不回填时 collectSecretErrors 读到 undefined，报出四条「JWT/REFRESH/AES/HMAC 必须设置
// 为至少 32 字符的强随机值」的**假错**（实测退出码 1），而 deployment/secret-rotation.md:384
// 正是拿这一步的退出码当"轮换后配置自洽"的证据——*_FILE 部署下那条轮换流程做不到收尾。
// 为什么不在文件顶部 hydrate（本轮真的先写成顶部方案，被自己的测试打回来了）：
// 本文件同时是**库**（app.js / index.js / staticFrontend.js / websocketService/handshake.js 都 require 它）
// 和**入口**，而这两种身份对 require 期的副作用要求相反。顶部写法在 require 期就覆写
// process.env：src/tests/setup.js 给每个 worker 预置了四把 `*_FILE` 临时副本，于是
// 「先设 env、后 require」的用例被回填悄悄改回测试密钥，实测连带打红 5 个配置套件
// （validate / startupGuards / weakSecretPlaceholder / transportTlsAssertion / immutableConfigGuard）。
// 库不该在 require 期动全局环境；index.js 能那么做是因为它本身就是应用入口。
// 代价是"hydrate 早于首次读取"在本文件不再由源码位置保证（读取都在函数体内），
// 改由下面两条判据钉住：① 回填必须在本支里、② 且必须早于 validateConfig() 调用。
// 见 src/tests/config/scriptSecretHydration.test.js。
if (require.main === module) {
  require('./secrets').hydrateSecretsFromFiles();
  validateConfig();
}
