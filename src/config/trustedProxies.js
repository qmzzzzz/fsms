/**
 * 可信代理网段（TRUSTED_PROXY_CIDRS）——把「代理身份」从「网络位置」里拆出来
 *
 * 由来（F-01，2026-10-16 独立审计，P1）：`utils/ipUtils.isClientIpIdentityTrustworthy`
 * 原本的第 3 种可信形态是「socket 对端属内网/回环 ⇒ 它写的 X-Forwarded-For 可信」。
 * RFC1918 描述的是**位置**，不是**身份**：docker-compose 里 app 同时挂在
 * fire-safety-net 与 data-net 上，同网任意容器直连 `app:3000` 并自带一条 XFF，
 * 其 socket 对端同样是 RFC1918，与真实 nginx 反代**在应用视角完全同形**。
 * 那条伪造头于是可以买到：IP 白名单豁免、黑名单绕过、IP/用户/账号三层限流配额、
 * 自动封禁的打击对象、以及审计记录里的来源地址。
 *
 * 修法不是「不再信任私网」（那会打断所有现存部署），而是**把代理身份变成显式配置**：
 * 配了就以名单为准，私网不再是理由；没配则行为与修复前逐字一致（私网/回环仍可信），
 * 由启动期 WARN 提示这条边界目前判的是位置而非身份。**默认不收紧**是 2026-10-17
 * 仓库负责人明确拍板的取舍：不能让一次安全修复打断所有现存部署。残余风险如实
 * 记录在 ipUtils 的判据注释里。
 *
 * 为什么判据从 `req.app` 取而不是在这里读 process.env：
 *   - ipUtils 的函数保持纯判据（不读环境 ⇒ 不需要缓存，也不需要给每个测试
 *     准备缓存重置钩子）；
 *   - 避免 `utils/ipUtils` 反向 require `config/*`：依赖图无环由
 *     `src/tests/architecture/requireCycles.test.js` 静态断言，方向只能是 config → utils。
 * 本模块只负责「解析 + 校验 + 匹配」，注入点在 `src/app.js`（紧邻 `trust proxy`）。
 */

const { parseCIDR, normalizeCIDR, isFullRangeCIDR, ipMatchesEntry } = require('../utils/ipUtils');

const ENV_KEY = 'TRUSTED' + '_' + 'PROXY' + '_' + 'CIDRS';

/**
 * 解析逗号分隔的可信代理网段列表（纯函数：不读 process.env、不打日志）。
 *
 * 三类拒绝，每类都对应一个具体的坏结果：
 *   - **空项**（`10.0.0.0/8,,172.16.0.0/12`）：多半是拼接配置时漏了值。静默忽略
 *     会让运维以为三段都生效了，实际只生效两段——「配置意图与实际不符」必须出声。
 *   - **解析不出**：同上，静默丢弃等于悄悄缩小信任面，且缩小的是哪一段无从得知。
 *   - **全域网段**（`0.0.0.0/0`、`::/0`）：等于宣布「整个互联网都是我的可信代理」，
 *     比完全不配还糟——不配至少还要求对端在内网。
 *
 * 相对"合法输入"放宽一处：**裸地址按单主机接受**（IPv4 /32、IPv6 /128），
 * 理由见下方循环里的注释（单台 nginx 是最常见的真实配置，不该因为它少了 `/32`
 * 就撞上致命启动错误）。
 *
 * @param {string|undefined} raw process.env[ENV_KEY] 的原始值
 * @returns {{configured: boolean, cidrs: string[], errors: string[]}}
 *   configured=false 仅当「完全没配」（undefined / 空串 / 纯空白）；
 *   配了但全部非法时 configured 仍为 true、cidrs 为空 —— 判据据此 fail-closed，
 *   不会因为解析失败而退回「私网即可信」那条宽松路径。
 */
const parseTrustedProxyCidrs = (raw) => {
  if (raw === undefined || raw === null || String(raw).trim() === '') {
    return { configured: false, cidrs: [], errors: [] };
  }

  const cidrs = [];
  const errors = [];
  const items = String(raw).split(',');

  for (let i = 0; i < items.length; i += 1) {
    const item = items[i].trim();
    if (item === '') {
      errors.push(
        `${ENV_KEY} 第 ${i + 1} 项为空项（逗号分隔列表里出现了空值，疑似拼接配置时漏填）`
      );
      continue;
    }
    if (isFullRangeCIDR(item)) {
      errors.push(
        `${ENV_KEY} 第 ${i + 1} 项 ${item} 是全域网段：等于声明「整个互联网都是可信代理」，` +
          '比不配置更危险，已拒绝。请填代理实际所在的网段（如 10.0.0.0/8）'
      );
      continue;
    }
    // 裸地址按单主机处理（IPv4 /32、IPv6 /128）。最常见的真实配置是「只有一台 nginx」，
    // 写成 `TRUSTED_PROXY_CIDRS=172.28.0.5` 是人的本能；若不接受，运维拿到的是一条
    // **致命启动错误**（validate.js 的启动闸），而正确写法只差三个字符——这种"几乎对了"
    // 的失败最费时间。注意 `0.0.0.0` / `::` 也因此成为单地址而非全域网段：它们匹配不到
    // 任何真实对端，方向是 fail-closed（判谁都不信），比反过来安全。
    const cidrText = item.includes('/') ? item : `${item}/${item.includes(':') ? 128 : 32}`;
    if (!parseCIDR(cidrText)) {
      errors.push(`${ENV_KEY} 第 ${i + 1} 项 ${JSON.stringify(item)} 无法解析为 CIDR 网段`);
      continue;
    }
    // 归一化后入表：判据侧与日志侧看到同一种文本，避免 2001:0DB8::/64 与
    // 2001:db8::/64 被当成两条不同网段
    cidrs.push(normalizeCIDR(cidrText));
  }

  return { configured: true, cidrs, errors };
};

/**
 * 由解析结果构造判据对象（供 app.js 注入 `app.set('trusted proxy cidrs', …)`）。
 *
 * `matches` 在 errors 非空时恒为 false：配置写错了就谁都不信，
 * 而不是「信解析成功的那几条」——半信半疑的信任面比明确拒绝更难排查。
 *
 * @param {{configured: boolean, cidrs: string[], errors: string[]}} parsed
 * @returns {{configured: boolean, cidrs: string[], errors: string[], matches: (peer: string) => boolean}}
 */
const toTrustedProxies = (parsed) => ({
  configured: parsed.configured,
  cidrs: parsed.cidrs,
  errors: parsed.errors,
  matches: (peer) => {
    if (!parsed.configured) return false;
    if (parsed.errors.length > 0) return false;
    if (!peer) return false;
    return parsed.cidrs.some((cidr) => ipMatchesEntry(peer, cidr));
  },
});

let cached;

/**
 * 读取并解析环境变量（memoize：进程内配置不变，逐请求重解析纯属浪费）。
 * @returns {ReturnType<typeof toTrustedProxies>}
 */
const resolveTrustedProxies = () => {
  if (cached) return cached;
  cached = toTrustedProxies(parseTrustedProxyCidrs(process.env[ENV_KEY]));
  return cached;
};

/** 清空 memoize（仅测试与配置热更新使用） */
const resetTrustedProxyCache = () => {
  cached = undefined;
};

module.exports = {
  ENV_KEY,
  parseTrustedProxyCidrs,
  toTrustedProxies,
  resolveTrustedProxies,
  resetTrustedProxyCache,
};
