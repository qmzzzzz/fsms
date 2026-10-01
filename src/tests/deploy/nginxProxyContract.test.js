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
    // 解析器自检：本文件有 :80 与 :443 两个 server 块。列表为空时下面的断言会全绿，
    // 所以先把"确实解析到了"钉住（与 parseLocations 的自检同一条理由）。
    expect(servers.length).toBe(2);
    expect(findServerTokenGaps(code)).toEqual([]);

    // 可证伪：把**最后**一处真实指令改成注释形态，同一断言必须报出该缺口。
    // 这一条同时证明两件事：断言打的是代码视图（不是原文，否则注释里的同名文本会喂出假绿），
    // 以及缺口是按 server 块逐个报的（不是"全文出现过一次就放行"）。
    const last = text.lastIndexOf('server_tokens off;');
    expect(last).toBeGreaterThan(-1);
    const mutated =
      text.slice(0, last) + '# server_tokens off;' + text.slice(last + 'server_tokens off;'.length);
    expect(findServerTokenGaps(codeView(mutated))).toEqual([
      { server: 1, missing: ['server_tokens off'] },
    ]);
  });

  test('/api-docs 不在生产反代之内（文档默认关闭，反代等于对外常开）', () => {
    // 这是一条「有意如此」的断言：将来若决定开放文档，需显式改这里并配认证。
    const loc = matchLocation('/api-docs.json', locations);
    expect(loc.proxied).toBe(false);
  });
});
