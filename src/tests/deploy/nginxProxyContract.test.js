/**
 * 反代参考配置（deployment/nginx.conf.example）契约测试
 *
 * 为什么需要这一层：supertest 直连 Express app，e2e 冒烟也是 `node src/index.js`
 * 起真实服务，两条路径都**不经过 nginx**。于是「应用侧要求 Host 白名单，而反代
 * 没转发 Host」这类断链在 CI 上永远看不见，只有真实部署后 WebSocket/上报/抓取
 * 全量 400 才暴露——2026-09-19 实测：本文件 5 个 proxy 块中只有 /api/ 转发了 Host，
 * 且 security.txt 根本没被反代。本测试把这类配置漂移变成红灯：静态解析 nginx
 * 与后端根路径路由表，比对两者的契约。
 *
 * 四条断言：
 *  1. 每个 proxy_pass 块完整声明 Host / X-Real-IP / X-Forwarded-For / X-Forwarded-Proto
 *     —— proxy_set_header 在嵌套块中是**整体替换**而非继承，漏一条等于该块没有，
 *     而 Host 缺失时 nginx 默认发 `Host: $proxy_host`（= proxy_pass 目标地址），
 *     必被 protocolCompliance 的 ALLOWED_HOSTS 精确比对拒为 400 HOST_HEADER_INVALID；
 *  2. 后端挂在**根路径**的公开端点必须被某个 proxy 块接管，否则会被 location / 的
 *     try_files 退化成 200 的 SPA index.html（security.txt 正是这种静默失效）；
 *  3. 80→443 跳转不得使用 $host —— $host 取自请求 Host 头，任何解析到本机的域名
 *     都会命中 :80 的默认 server 并被 301 到攻击者指定的主机（开放重定向）。
 *  4. 每个 server 块都要 `server_tokens off`（版本外泄 + 与本仓 app.disable('x-powered-by')
 *     同口径）。写它的原因是上面那条"两条路径都不经过 nginx"的盲区，而不是这一行本身多高危。
 *
 * finding #6/#10 合同（2026-10-01，第二个 describe）：
 *  5. 静态直出路径（location / 与 /assets/）各自下发**同一份**静态 CSP 且含
 *     script-src 'self' 等硬底线；CSP 只允许出现在这两块——server 级与反代块叠加
 *     nginx 侧 CSP 会与后端 nonce CSP 取交集，把后端放行的内联样式全部拦掉。
 *  6. http 级边缘闸：limit_req_zone、超时族（client_header/body_timeout、
 *     send/keepalive_timeout）与 client_max_body_size 1m（与后端 express.json
 *     limit '1mb' 显式对齐）必须在首个 server 块之前声明；limit_req 只落在
 *     /api 两条入口（nodelay + 429），socket.io 长连接语义刻意豁免；每个反代块
 *     另须显式钉住 proxy_connect/send_timeout（socket.io 的 send 60s 是心跳余量）。
 *  7. 443 兜底块：default_server + ssl_reject_handshake + return 444 + server_tokens，
 *     且不带 root/proxy_pass（任意未匹配 SNI 不再拿到整套 SPA）；:80 仍只有一个
 *     监听者（其「唯一声明即默认」的前提不被破坏）。
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..', '..', '..');
const read = (rel) => fs.readFileSync(path.join(ROOT, rel), 'utf8');

/**
 * 注释安全的「代码视图」：把每行 `#` 之后的内容替换成等长空格（掩码而非删除）。
 *
 * 为什么必须是掩码：nginx 忽略注释里的 `{`/`}`，而 parseLocations 靠花括号配平切块。
 * 实测本文件注释中含 2 个花括号——若直接删注释再配平，块边界会整体错位（试算时
 * 7 个 proxy 块全变 0）。等长替换保证原索引几何不变，同时让所有指令级正则
 * （proxy_pass / proxy_set_header / return 301）不再被注释文本喂出假绿。
 *
 * 已知前提：本文件不存在「引号内的 #」（否则会被误掩）。由下方「掩码前提自证」用例钉住。
 */
const codeView = (text) =>
  text
    .split(/\r?\n/)
    .map((line) => {
      const i = line.indexOf('#');
      return i < 0 ? line : line.slice(0, i) + ' '.repeat(line.length - i);
    })
    .join('\n');

/** 与 /api/ 块同口径的四条头：少任一条都会让该通道在应用侧失真或被拒 */
const REQUIRED_PROXY_HEADERS = ['host', 'x-real-ip', 'x-forwarded-for', 'x-forwarded-proto'];

/** 不要求反代的根路径端点，附理由（出现新条目必须在此登记理由，否则测试红） */
const NON_PROXIED = {
  '/': 'SPA 静态入口：由 nginx 的 root + try_files 直接服务，不进后端',
  '/readyz': '就绪探针：容器/编排健康检查直连 3000，刻意不对公网暴露',
  '/api-docs': 'Swagger UI：生产默认关闭（ENABLE_API_DOCS 门禁），反代等于对外常开文档',
  '/api-docs.json': '同上，OpenAPI 文档体',
};

/** `location` 声明及其花括号配平的块体（入参必须是 codeView() 的输出） */
const parseLocations = (text) => {
  const out = [];
  const re = /^[ \t]*location[ \t]+([^{\n]+)[ \t]*\{/gm;
  let m;
  while ((m = re.exec(text)) !== null) {
    let i = m.index + m[0].length;
    let depth = 1;
    while (i < text.length && depth > 0) {
      if (text[i] === '{') depth += 1;
      else if (text[i] === '}') depth -= 1;
      i += 1;
    }
    out.push({ head: m[1].trim(), body: text.slice(m.index + m[0].length, i - 1) });
  }
  return out.map((loc) => {
    const parts = loc.head.split(/\s+/);
    const modifier = ['=', '~', '~*', '^~'].includes(parts[0]) ? parts[0] : '';
    const pattern = modifier ? parts.slice(1).join(' ') : parts[0];
    const headers = new Set();
    for (const line of loc.body.split(/\r?\n/)) {
      const h = /^[ \t]*proxy_set_header[ \t]+(\S+)/.exec(line);
      if (h) headers.add(h[1].toLowerCase());
    }
    return {
      head: loc.head,
      modifier,
      pattern,
      // 块体（代码视图切片）：finding #6/#10 的 CSP / limit_req 合同直接在块体上
      // 做指令级断言。早期版本没有这个字段，各用例只能各自重解析——统一暴露避免漂移。
      body: loc.body,
      headers,
      proxied: /proxy_pass\s/.test(loc.body),
    };
  });
};

/**
 * nginx 的 location 匹配优先级：`=` 精确 → 最长前缀（`^~` 命中即终止）→
 * 按出现顺序的 regex → 回落到最长前缀。
 * 简化实现，但覆盖了本文件用到的全部形态。
 */
const matchLocation = (p, locations) => {
  const exact = locations.find((l) => l.modifier === '=' && l.pattern === p);
  if (exact) return exact;
  let prefix = null;
  for (const l of locations) {
    if ((l.modifier === '' || l.modifier === '^~') && p.startsWith(l.pattern)) {
      if (!prefix || l.pattern.length > prefix.pattern.length) prefix = l;
    }
  }
  if (prefix && prefix.modifier === '^~') return prefix;
  for (const l of locations) {
    if ((l.modifier === '~' || l.modifier === '~*') && new RegExp(l.pattern).test(p)) return l;
  }
  return prefix;
};

/**
 * server 块（花括号配平，含嵌套 location）。入参必须是 codeView() 的输出。
 * 与 parseLocations 同一套配平逻辑：nginx 忽略注释里的花括号，代码视图才等价。
 */
const parseServers = (text) => {
  const out = [];
  const re = /^[ \t]*server[ \t]*\{/gm;
  let m;
  while ((m = re.exec(text)) !== null) {
    let i = m.index + m[0].length;
    let depth = 1;
    while (i < text.length && depth > 0) {
      if (text[i] === '{') depth += 1;
      else if (text[i] === '}') depth -= 1;
      i += 1;
    }
    out.push({ body: text.slice(m.index + m[0].length, i - 1) });
  }
  return out;
};

/** 每个 server 块都必须关闭版本外泄；返回缺口所在块的序号（不是布尔，便于报缺） */
const findServerTokenGaps = (text) =>
  parseServers(text)
    .map((s, idx) => ({ idx, ok: /^[ \t]*server_tokens[ \t]+off[ \t]*;/m.test(s.body) }))
    .filter((s) => !s.ok)
    .map((s) => ({ server: s.idx, missing: ['server_tokens off'] }));

/** 从源码静态提取「挂在根路径」的后端端点（app.js 根级 + '/' 挂载的 wellKnownRoutes） */
const rootBackendPaths = () => {
  const mountedAtRoot = /app\.use\('\/',\s*wellKnownRoutes\)/.test(read('src/app.js'));
  if (!mountedAtRoot) {
    // 挂载点若改成非 '/'，下面对 wellKnownRoutes 的推导就不成立，必须同步本测试
    throw new Error("app.js 不再以 app.use('/', wellKnownRoutes) 挂载，请同步本测试的推导");
  }
  const appLevel = [...read('src/app.js').matchAll(/app\.(?:get|post|use)\('([^']+)'/g)].map(
    (m) => m[1].split('?')[0]
  );
  const wellKnown = [
    ...read('src/routes/wellKnownRoutes.js').matchAll(/router\.(?:get|post)\('([^']+)'/g),
  ].map((m) => m[1]);
  // 只跳过 `/api/` 下的挂载点（nginx 的 `location /api/` 前缀块覆盖它们）。
  // 注意不能写成 startsWith('/api')：那会把**不带斜杠**的 `/api` 一起放过，
  // 而前缀块恰好匹配不到它——这正是本测试要抓的那一类缺口（见 nginx 的 `= /api` 块）。
  return [...new Set([...appLevel, ...wellKnown])].filter((p) => !p.startsWith('/api/'));
};

/** 纯函数：返回配置文本中的 proxy 块缺头清单，供正向与负向（可证伪）用例共用 */
const findProxyHeaderGaps = (text) => {
  const gaps = [];
  for (const loc of parseLocations(text)) {
    if (!loc.proxied) continue;
    const missing = REQUIRED_PROXY_HEADERS.filter((h) => !loc.headers.has(h));
    if (missing.length > 0) gaps.push({ head: loc.head, missing });
  }
  return gaps;
};

/** 纯函数：给定 location 列表，返回「有后端路由却拿不到反代归属」的端点清单 */
const proxyOwnershipGaps = (locs) => {
  const gaps = [];
  for (const p of rootBackendPaths()) {
    if (p in NON_PROXIED) continue;
    const loc = matchLocation(p, locs);
    if (!loc || !loc.proxied) gaps.push(p);
  }
  return gaps;
};

describe('deployment/nginx.conf.example 反代契约', () => {
  const text = read('deployment/nginx.conf.example');
  const code = codeView(text);
  const locations = parseLocations(code);

  test('掩码前提自证：不存在「引号内的 #」，且掩码没有吃掉任何真实指令', () => {
    // codeView 取每行第一个 # 为注释起点。若某条真实指令的值里带 #（例如
    // add_header X "a#b"），它会被误掩，下面所有断言的口径就失效——所以钉死前提。
    expect(text).not.toMatch(/["'][^"\n]*#[^"\n]*["']/);
    // 掩码后必须仍能看到全部 7 个 proxy 块与那条 301，否则是「掩过头把断言喂空」
    expect((code.match(/proxy_pass\s/g) || []).length).toBeGreaterThanOrEqual(7);
    expect((code.match(/return\s+301\s/g) || []).length).toBe(1);
    // 原视图形成的 location 数与代码视图一致（注释里没有 location 声明）
    expect(parseLocations(text).length).toBe(locations.length);
  });

  test('解析器自检：确实读到了预期数量的 location 块', () => {
    // 解析器一旦失配（例如块头换行写法变了），下面的用例会「全绿因为列表为空」。
    // 这条断言把「解析成功」本身固定下来。
    expect(locations.length).toBeGreaterThanOrEqual(6);
    expect(locations.filter((l) => l.proxied).length).toBeGreaterThanOrEqual(5);
  });

  test('每个 proxy 块都完整声明四条转发头', () => {
    expect(findProxyHeaderGaps(code)).toEqual([]);
  });

  test('可证伪：抹掉 socket.io 的 Host 后，同一断言必须报出该缺口', () => {
    const broken = code.replace(
      /(location \/socket\.io\/ \{[\s\S]*?)proxy_set_header Host \$host;[^\S\n]*\r?\n/,
      '$1'
    );
    expect(broken).not.toBe(code); // 替身若没替换成功，本用例就是空跑
    expect(findProxyHeaderGaps(broken)).toEqual([{ head: '/socket.io/', missing: ['host'] }]);
  });

  test('可证伪：把真实 proxy_pass 改成注释，旧口径不报缺、代码视图必须报缺', () => {
    // B 的自查线索 1（"被断言的词只写进注释"）在本文件的实例：proxied 判定是
    // /proxy_pass\s/ 对整块文本做**非锚定**匹配，所以"删掉指令、留着同名注释"
    // 在旧实现下仍然全绿——即 security.txt/metrics 这类块真的丢了反代、退化成
    // SPA 200 HTML，门禁看不见。这里同时钉住"旧口径是假绿"和"新口径报缺"。
    const mutated = text.replace(/^([ \t]*)(proxy_pass\shttp:\/\/127\.0\.0\.1:3000;)/m, '$1# $2');
    expect(mutated).not.toBe(text); // 替身没替换成功 = 空跑
    // 旧口径（直接解析原视图）：看不见这条缺口——这条断言就是"假绿曾被证实"的记录
    expect(proxyOwnershipGaps(parseLocations(mutated))).toEqual([]);
    // 新口径（掩码后的代码视图）：该端点必须失去反代归属
    expect(proxyOwnershipGaps(parseLocations(codeView(mutated)))).toContain('/metrics');
  });

  test('后端根路径端点全部有反代归属（不被 SPA try_files 吞掉）', () => {
    expect(proxyOwnershipGaps(locations)).toEqual([]);
  });

  test('可证伪：删掉 security.txt 块后该端点必须落入 SPA 兜底并报缺', () => {
    const withoutSecurityTxt = locations.filter((l) => !/security\\\.txt/.test(l.head));
    const p = '/.well-known/security.txt';
    const loc = matchLocation(p, withoutSecurityTxt);
    expect(loc && loc.proxied).toBe(false);
    expect(loc.pattern).toBe('/'); // 落到 SPA 兜底：返回 200 HTML，静默失效
  });

  test('豁免反代的端点必须真实存在于路由表（防例外清单腐化）', () => {
    const existing = new Set(rootBackendPaths());
    for (const p of Object.keys(NON_PROXIED)) expect(existing.has(p)).toBe(true);
  });

  test('80→443 跳转目标为字面域名，不得使用请求可控的 $host', () => {
    // 在代码视图上匹配：本文件的注释里就写着 $host/$proxy_host（解释为什么不能用它），
    // 用原视图匹配等于让注释参与判定。
    const redirects = [...code.matchAll(/return\s+301\s+(\S+);/g)].map((m) => m[1]);
    expect(redirects.length).toBeGreaterThanOrEqual(1);
    for (const target of redirects) expect(target).not.toMatch(/\$host/);
    expect(redirects[0]).toContain('your-domain.example');
  });

  test('可证伪：把 return 301 改成注释后，代码视图必须看不见该指令', () => {
    const mutated = text.replace(/^([ \t]*)(return 301 \S+;)/m, '$1# $2');
    expect(mutated).not.toBe(text);
    const REDIRECT_RE = /return\s+301\s+(\S+);/g;
    // 旧口径：指令被注释掉后依然计数（真实配置里删了 301，门禁却仍绿）
    expect([...mutated.matchAll(REDIRECT_RE)].length).toBe(1);
    // 新口径：掩码后归零，上面的 >=1 断言会红
    expect([...codeView(mutated).matchAll(REDIRECT_RE)].length).toBe(0);
  });

  test('每个 server 块都关闭 server_tokens，且可证伪（注释版不算数）', () => {
    // 版本外泄本身是低危信息，这条闸的价值在**形状**：本文件是"生产参考配置"，
    // 部署方按它抄，抄漏一行就等于线上裸奔，而 supertest/e2e 两条路径都不经过 nginx
    // （见文件头）——漂移只有这里能看见。
    const servers = parseServers(code);
    // 解析器自检：本文件有 :80 跳转、:443 主入口、:443 兜底三个 server 块（finding #10
    // 加入兜底块后为 3）。列表为空时下面的断言会全绿，
    // 所以先把"确实解析到了"钉住（与 parseLocations 的自检同一条理由）。
    expect(servers.length).toBe(3);
    expect(findServerTokenGaps(code)).toEqual([]);

    // 可证伪：把**最后**一处真实指令改成注释形态，同一断言必须报出该缺口。
    // 这一条同时证明两件事：断言打的是代码视图（不是原文，否则注释里的同名文本会喂出假绿），
    // 以及缺口是按 server 块逐个报的（不是"全文出现过一次就放行"）。
    // 最后一处属于文件末尾的 :443 兜底块（序号 2）：它没有证书与内容，唯一的价值
    // 就是把「未匹配 SNI」挡死，server_tokens 在这里同样是默认身份的一部分。
    const last = text.lastIndexOf('server_tokens off;');
    expect(last).toBeGreaterThan(-1);
    const mutated =
      text.slice(0, last) + '# server_tokens off;' + text.slice(last + 'server_tokens off;'.length);
    expect(findServerTokenGaps(codeView(mutated))).toEqual([
      { server: 2, missing: ['server_tokens off'] },
    ]);
  });

  test('/api-docs 不在生产反代之内（文档默认关闭，反代等于对外常开）', () => {
    // 这是一条「有意如此」的断言：将来若决定开放文档，需显式改这里并配认证。
    const loc = matchLocation('/api-docs.json', locations);
    expect(loc.proxied).toBe(false);
  });
});

// ============================================================================
// finding #6（静态直出路径 CSP）与 finding #10（边缘资源闸 + 443 兜底）的合同。
// 背景与 #1-#4 同源：supertest/e2e 都不经过 nginx，而这两项整改全部只落在
// nginx 层——没有本组断言，它们在 CI 上同样是不可见的漂移。
// ============================================================================

const EXPECTED_STATIC_CSP = [
  "default-src 'self'",
  "script-src 'self'",
  // 'unsafe-inline' 与 fonts.googleapis.com 是**有证据的保留**：global.css 以 @import
  // 引入 Google Fonts；element-plus 组件运行时经 style 属性/注入做定位与主题。
  // 与 web-admin/vite.config.js buildSecurityHeaders 的生产 CSP 同源（已被前端验证）。
  "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
  "img-src 'self' data: blob:",
  "font-src 'self' data: https://fonts.gstatic.com",
  "connect-src 'self'",
  "object-src 'none'",
  "base-uri 'self'",
  "frame-ancestors 'none'",
  "form-action 'self'",
];

/** /api 两条入口（前缀 + 精确）都必须挂同一条边缘令牌桶 */
const LIMIT_REQ_LOCATIONS = [
  { modifier: '', pattern: '/api/' },
  { modifier: '=', pattern: '/api' },
];

/** 从直出块提取 CSP 指令值（按分号拆分为指令数组；缺失返回 null） */
const staticCspDirectives = (loc) => {
  if (!loc) return null;
  const m = /add_header[ \t]+Content-Security-Policy[ \t]+"([^"]+)"[ \t]+always;/.exec(loc.body);
  if (!m) return null;
  return m[1]
    .split(';')
    .map((s) => s.trim())
    .filter(Boolean);
};

/** 纯函数：两条直出路径的静态 CSP 缺口清单（入参原文，内部走代码视图） */
const findStaticCspGaps = (raw) => {
  const locs = parseLocations(codeView(raw));
  const root = staticCspDirectives(locs.find((l) => l.modifier === '' && l.pattern === '/'));
  const assets = staticCspDirectives(
    locs.find((l) => l.modifier === '' && l.pattern === '/assets/')
  );
  const gaps = [];
  if (!root) gaps.push('location / 缺静态 CSP');
  if (!assets) gaps.push('location /assets/ 缺静态 CSP');
  // 同一份策略的两份副本必须逐指令一致：只改一条 = 另一条静默漂移（与 L-09 三份
  // 安全头副本同一个道理，CSP 是其中最容易漏改的一条）
  if (root && assets && root.join(';') !== assets.join(';')) {
    gaps.push('location / 与 /assets/ 的静态 CSP 不一致');
  }
  for (const directive of EXPECTED_STATIC_CSP) {
    if (root && !root.includes(directive)) gaps.push(`location / 的 CSP 缺 ${directive}`);
    if (assets && !assets.includes(directive))
      gaps.push(`location /assets/ 的 CSP 缺 ${directive}`);
  }
  return gaps;
};

/** 纯函数：limit_req 闸的落点缺口（必须在 /api 两条入口，且不得出现在其他反代块） */
const findLimitReqGaps = (raw) => {
  const locs = parseLocations(codeView(raw));
  const gaps = [];
  for (const want of LIMIT_REQ_LOCATIONS) {
    const loc = locs.find((l) => l.modifier === want.modifier && l.pattern === want.pattern);
    if (!loc) {
      gaps.push(`${want.pattern} 块缺失`);
      continue;
    }
    if (!/limit_req\s+zone=\S+\s+burst=\d+\s+nodelay;/.test(loc.body)) {
      gaps.push(`${want.pattern} 缺 limit_req（nodelay）`);
    }
    if (!/limit_req_status\s+429;/.test(loc.body)) {
      gaps.push(`${want.pattern} 缺 limit_req_status 429`);
    }
  }
  for (const loc of locs) {
    if (!loc.proxied) continue;
    const isApiEntry = LIMIT_REQ_LOCATIONS.some(
      (w) => w.modifier === loc.modifier && w.pattern === loc.pattern
    );
    // 注意 limit_req\b 不匹配 limit_req_status（_ 是 word 字符，无边界）
    if (!isApiEntry && /limit_req\b/.test(loc.body)) gaps.push(`${loc.head} 意外携带 limit_req`);
  }
  return gaps;
};

/** 纯函数：反代块 connect/send 超时缺口（每个 proxy 块显式钉值、不依赖 nginx 默认；#10） */
const findProxyTimeoutGaps = (raw) => {
  const locs = parseLocations(codeView(raw));
  const gaps = [];
  for (const loc of locs) {
    if (!loc.proxied) continue;
    if (!/proxy_connect_timeout\s+\d+s;/.test(loc.body)) {
      gaps.push(`${loc.head} 缺 proxy_connect_timeout`);
    }
    if (!/proxy_send_timeout\s+\d+s;/.test(loc.body)) {
      gaps.push(`${loc.head} 缺 proxy_send_timeout`);
    }
  }
  return gaps;
};

/** 纯函数：http 级边缘闸（首个 server 块之前）的缺口清单 */
const findEdgeGateGaps = (raw) => {
  const code = codeView(raw);
  const firstServer = code.search(/^[ \t]*server[ \t]*\{/m);
  if (firstServer < 0) return ['未解析到任何 server 块'];
  const httpLevel = code.slice(0, firstServer);
  const required = [
    [/limit_req_zone\s+\$binary_remote_addr\s+zone=\S+:\d+m\s+rate=\d+r\/s;/, 'limit_req_zone'],
    [/client_header_timeout\s+\d+s;/, 'client_header_timeout（slowloris 防线）'],
    [/client_body_timeout\s+\d+s;/, 'client_body_timeout（slow-read 防线）'],
    [/send_timeout\s+\d+s;/, 'send_timeout'],
    [/keepalive_timeout\s+\d+s;/, 'keepalive_timeout'],
    // 与 src/app.js 的 express.json/urlencoded limit '1mb' 显式对齐，不是巧合一致
    [/client_max_body_size\s+1m;/, 'client_max_body_size 1m'],
  ];
  return required.filter(([re]) => !re.test(httpLevel)).map(([, name]) => name);
};

/** 纯函数：443 兜底块的缺口清单（存在性 + 五要素 + 不可服务内容） */
const findFallbackGaps = (raw) => {
  const fallback = parseServers(codeView(raw)).find((s) =>
    /listen\s+\[::\]:443\s+ssl\s+default_server;/.test(s.body)
  );
  if (!fallback) return ['443 default_server 兜底块缺失'];
  const required = [
    [/listen\s+443\s+ssl\s+default_server;/, 'listen 443 ssl default_server'],
    [/ssl_reject_handshake\s+on;/, 'ssl_reject_handshake on'],
    [/server_name\s+_;/, 'server_name _'],
    [/return\s+444;/, 'return 444'],
    [/server_tokens\s+off;/, 'server_tokens off'],
  ];
  const gaps = required
    .filter(([re]) => !re.test(fallback.body))
    .map(([, name]) => `兜底块缺 ${name}`);
  if (/\broot\s|\bproxy_pass\b/.test(fallback.body)) {
    gaps.push('兜底块携带了可服务内容（root/proxy_pass）');
  }
  return gaps;
};

describe('静态直出 CSP（finding #6）与边缘资源闸/443 兜底（finding #10）', () => {
  const text = read('deployment/nginx.conf.example');
  const code = codeView(text);
  const locations = parseLocations(code);

  test('前提自证：两条直出块、/api 两条入口与 socket.io 都被解析到（防空集假绿）', () => {
    // 与上面 describe 的解析器自检同一条理由：本组的所有断言都从
    // parseLocations/parseServers 出发，解析一旦失配就会「全绿因为列表为空」。
    expect(locations.find((l) => l.modifier === '' && l.pattern === '/')).toBeDefined();
    expect(locations.find((l) => l.modifier === '' && l.pattern === '/assets/')).toBeDefined();
    expect(locations.find((l) => l.modifier === '' && l.pattern === '/api/')).toBeDefined();
    expect(locations.find((l) => l.modifier === '=' && l.pattern === '/api')).toBeDefined();
    expect(locations.find((l) => l.pattern === '/socket.io/')).toBeDefined();
  });

  test('两条直出路径各自携带同一份静态 CSP，且含 script-src self 等硬底线（#6）', () => {
    expect(findStaticCspGaps(text)).toEqual([]);
  });

  test('CSP 只落在两条直出块：server 级与全部反代块不得叠加 nginx 侧 CSP（#6）', () => {
    // 反代路径由后端下发 nonce CSP（src/middleware/security.js）；静态策略一旦在
    // 同一响应上叠加，浏览器取交集就会把后端放行的内联样式全部拦掉——这是原注释
    // 警告的唯一真实场景，按路径分工后 server 级必须保持无 CSP。
    expect((code.match(/add_header\s+Content-Security-Policy/g) || []).length).toBe(2);
    for (const loc of locations) {
      if (loc.proxied) {
        expect(/add_header\s+Content-Security-Policy/.test(loc.body)).toBe(false);
      }
    }
  });

  test('可证伪：注释掉 location / 的 CSP 行后必须报缺，且总数减一', () => {
    // 第一处 CSP 行属于 location /（文件顺序在前）
    const mutated = text.replace(/^([ \t]*)(add_header[ \t]+Content-Security-Policy)/m, '$1# $2');
    expect(mutated).not.toBe(text);
    expect(findStaticCspGaps(mutated)).toContain('location / 缺静态 CSP');
    expect((codeView(mutated).match(/add_header\s+Content-Security-Policy/g) || []).length).toBe(1);
  });

  test('可证伪：把两条直出块的 CSP 改成不一致时必须报漂移', () => {
    const mutated = text.replace(
      /(location \/assets\/ \{[\s\S]*?add_header Content-Security-Policy ")[^"]+(")/,
      "$1default-src 'self'$2"
    );
    expect(mutated).not.toBe(text);
    expect(findStaticCspGaps(mutated)).toContain('location / 与 /assets/ 的静态 CSP 不一致');
  });

  test('http 级边缘闸齐全且位于首个 server 块之前（#10）', () => {
    expect(findEdgeGateGaps(text)).toEqual([]);
    // 后端对齐前提自证：client_max_body_size 1m 对齐的是这行 body parser 限额
    expect(read('src/app.js')).toMatch(/express\.json\(\{ limit: '1mb' \}\)/);
  });

  test('limit_req 只落在 /api 两条入口（nodelay + 429），socket.io 刻意豁免（#10）', () => {
    expect(findLimitReqGaps(text)).toEqual([]);
    const socket = locations.find((l) => l.pattern === '/socket.io/');
    expect(socket.proxied).toBe(true);
    expect(/limit_req\b/.test(socket.body)).toBe(false);
  });

  test('可证伪：注释掉 /api/ 的 limit_req 后必须报缺', () => {
    const mutated = text.replace(/^([ \t]*)(limit_req\s+zone=)/m, '$1# $2');
    expect(mutated).not.toBe(text);
    expect(findLimitReqGaps(mutated)).toContain('/api/ 缺 limit_req（nodelay）');
  });

  test('每个反代块都显式钉住 connect/send 超时，且可证伪（#10）', () => {
    // 「显式钉值」的口径与 /api/ 块注释一致：上游 nginx.conf 的静默变更不应改变
    // 本文件的边缘语义；socket.io 的 send 60s（心跳余量）与短请求块的 30s 都算数。
    expect(findProxyTimeoutGaps(text)).toEqual([]);
    // 可证伪：分别抹掉一处 connect（/api/）与一处 send（socket.io），缺口必须
    // 按块报出——「全文出现过一次就放行」的口径在这里不成立
    const noConnect = text.replace(
      /(location \/api\/ \{[\s\S]*?)proxy_connect_timeout 5s;[^\S\n]*\r?\n/,
      '$1'
    );
    expect(noConnect).not.toBe(text);
    expect(findProxyTimeoutGaps(noConnect)).toEqual(['/api/ 缺 proxy_connect_timeout']);
    const noSend = text.replace(
      /(location \/socket\.io\/ \{[\s\S]*?)proxy_send_timeout 60s;[^\S\n]*\r?\n/,
      '$1'
    );
    expect(noSend).not.toBe(text);
    expect(findProxyTimeoutGaps(noSend)).toEqual(['/socket.io/ 缺 proxy_send_timeout']);
  });

  test('443 兜底块契约：default_server + ssl_reject_handshake + 444，且不可服务（#10）', () => {
    expect(findFallbackGaps(text)).toEqual([]);
    // ssl_reject_handshake 全文仅此一处：主块必须用真证书正常握手，兜底块才谈得上
    // 「抢到默认身份后拒绝一切」
    expect((code.match(/ssl_reject_handshake/g) || []).length).toBe(1);
  });

  test('可证伪：注释掉 ssl_reject_handshake / return 444 后必须报缺', () => {
    const noHandshake = text.replace(/^([ \t]*)(ssl_reject_handshake\s+on;)/m, '$1# $2');
    expect(noHandshake).not.toBe(text);
    expect(findFallbackGaps(noHandshake)).toEqual(['兜底块缺 ssl_reject_handshake on']);
    const no444 = text.replace(/^([ \t]*)(return\s+444;)/m, '$1# $2');
    expect(no444).not.toBe(text);
    expect(findFallbackGaps(no444)).toEqual(['兜底块缺 return 444']);
  });

  test('default_server 唯一性：443 只有兜底块声明默认；:80 仍只有一个监听者（#10）', () => {
    const servers = parseServers(code);
    expect(servers.length).toBe(3); // :80 跳转、:443 主入口、:443 兜底
    const withDefault = servers.filter((s) =>
      /listen\s+\[::\]:443\s+ssl\s+default_server;/.test(s.body)
    );
    expect(withDefault.length).toBe(1);
    // :80 块注释「唯一声明该端口的块自动成为默认」的前提：全文只允许一对 :80 监听
    // （nginx 指令有缩进，正则必须容许前导空白，否则是恒 0 的假绿）
    expect((code.match(/^[ \t]*listen\s+80;/m) || []).length).toBe(1);
    expect((code.match(/^[ \t]*listen\s+\[::\]:80;/m) || []).length).toBe(1);
  });
});
