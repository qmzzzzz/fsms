#!/usr/bin/env node
/**
 * 第三方镜像 digest 的**离线可复核**核验工具（零依赖，只用 node 内置 fetch/crypto）。
 *
 * 【它补的是哪一环】`scripts/capture-image-digests.sh` 是"在有 docker 守护进程的机器上
 * pull → inspect → 写回文件"的升级路径，它的前提是**这台机器能 pull**。而核验一个 digest
 * 其实不需要 pull：registry 的 manifest 端点返回的就是那堆内容寻址的字节，对它自算 sha256
 * 就等于该 manifest 的 digest。本仓库 2026-10-01 钉 node、2026-10-04 钉其余镜像用的都是
 * 这个口径（见下表 sources 列）。有了它，"部署机跑脚本"不再是唯一路径——CI、开发机、
 * 拿到一份可疑的 tag 想确认内容的人都能自己跑一遍。
 *
 * 【判据为什么是"多个独立来源一致 + 自算哈希"]单个来源说了不算：任何一个 registry（包括
 * pull-through 缓存）都可以被投毒或自己坏掉。三条判据同时成立才放行：
 *   ① 对**返回的原始字节**自算的 sha256 必须等于表里的期望值（不是抄 header）；
 *   ② 至少 `--min-sources`（默认 2）个来源给出**同一个**值；
 *   ③ 拿到的必须是 manifest **列表 / OCI index**（多架构），单层 manifest 的 digest 钉上去
 *      等于把自己锁死在一个 architecture 上。
 * 来源之间必须**运营主体不同**：`public.ecr.aws` 是 AWS 自己发布的 docker 官方镜像，
 * 另两个是 Docker Hub 的 pull-through 缓存（不同运营商）。缓存不会重打包，所以它服务的
 * 字节与 Hub 一致；把 ECR 与缓存混在一起才叫独立。
 *
 * 【为什么期望值写在代码里】digest 是外部落的事实，仓库内没有任何东西能复算出它——
 * 与 `src/tests/security/baseImageDigestPinned.test.js` 把 node 的 digest 写成字面量是
 * 同一个理由。升级时**两边都要改**（本表 + Dockerfile/compose/ci.yml），漏一边由
 * `src/tests/security/imageReferenceInventory.test.js` 判红。
 *
 * 用法：
 *   node scripts/verify-image-digests.js                 # 全表核验
 *   node scripts/verify-image-digests.js --only mongo:6.0.20
 *   node scripts/verify-image-digests.js --min-sources 3
 * 退出码：0 全部通过；1 有来源不一致/达不到下限；2 用法错、表本身错、或**命中 0 行**（空跑）。
 * 不打印任何 header 原文，也不回显外部响应体，只打印来源名、摘要值、index 条目数与字节数。
 */

'use strict';

const crypto = require('crypto');

const ACCEPT = [
  'application/vnd.oci.image.index.v1+json',
  'application/vnd.docker.distribution.manifest.list.v2+json',
].join(', ');

/** 匿名可读的来源表；`map(repo)` 返回 null 表示该来源不托管这个仓库（跳过而不是失败） */
const SOURCES = [
  {
    name: 'public.ecr.aws',
    // AWS 自己发布的 Docker Hub official 镜像面：路径是 `docker/library/<名>`（**不是** `docker/<名>`，
    // 后者实测 404）。只托管 official 库，第三方命名空间（prom/…、grafana/…）一律 404 ⇒ 归 null 跳过。
    map: (repo) => (repo.startsWith('library/') ? `docker/${repo}` : null),
  },
  {
    name: 'docker.m.daocloud.io',
    map: (repo) => repo,
  },
  {
    name: 'docker.1ms.run',
    map: (repo) => repo,
  },
];

/**
 * 期望表。captured/sources 是**取证现场**的描述，不是注释性装饰：删掉它们，下一个想复核的人
 * 就不知道该找谁、该要求几条腿。
 */
const EXPECTED = [
  {
    ref: 'node:22.14.0-alpine',
    repo: 'library/node',
    // manifest list（OCI index）摘要，含 amd64/arm/arm64/s390x 等
    digest: '9bef0ef1e268f60627da9ba7d7605e8831d5b56ad07487d24d1aa386336d1944',
    captured: '2026-10-01',
    sources:
      'public.ecr.aws + docker.m.daocloud.io（当日 Docker Hub 官方端点 DNS 污染不可达）；' +
      '2026-10-04 复跑补 docker.1ms.run，三源一致',
    sites: 'Dockerfile 的三处 FROM',
  },
  {
    ref: 'redis:7-alpine',
    repo: 'library/redis',
    digest: '858f009f9709ce576febc734aa78b8f6d624b82571f9ddb6bda4377c833b3499',
    captured: '2026-10-01',
    sources:
      'public.ecr.aws + docker.m.daocloud.io（旧值 ff02b58f 已被上游漂走，见 compose 的 redis 注释）；' +
      '2026-10-04 复跑补 docker.1ms.run，三源一致',
    sites: 'docker-compose.yml 的 redis',
  },
  {
    ref: 'mongo:6.0.20',
    repo: 'library/mongo',
    digest: 'eb5819129dee31a32982a940b6e32c9873fed05b5e938b65f802bb96dca8753d',
    captured: '2026-10-04',
    sources: 'public.ecr.aws + docker.m.daocloud.io + docker.1ms.run（三源一致，index 7 个条目）',
    sites: 'docker-compose.yml 的 mongo、.github/workflows/ci.yml 的 service 容器',
  },
  {
    ref: 'prom/prometheus:v2.53.0',
    repo: 'prom/prometheus',
    digest: '075b1ba2c4ebb04bc3a6ab86c06ec8d8099f8fda1c96ef6d104d9bb1def1d8bc',
    captured: '2026-10-04',
    sources: 'docker.m.daocloud.io + docker.1ms.run（ECR Public 不托管该命名空间：HTTP 404）',
    sites: 'docker-compose.yml 的 prometheus',
  },
  {
    ref: 'prom/alertmanager:v0.27.0',
    repo: 'prom/alertmanager',
    digest: 'e13b6ed5cb929eeaee733479dce55e10eb3bc2e9c4586c705a4e8da41e5eacf5',
    captured: '2026-10-04',
    sources: 'docker.m.daocloud.io + docker.1ms.run（同上）',
    sites: 'docker-compose.yml 的 alertmanager',
  },
  {
    ref: 'grafana/grafana:11.1.0',
    repo: 'grafana/grafana',
    digest: '079600c9517b678c10cda6006b4487d3174512fd4c6cface37df7822756ed7a5',
    captured: '2026-10-04',
    sources: 'docker.m.daocloud.io + docker.1ms.run（同上，index 3 个条目）',
    sites: 'docker-compose.yml 的 grafana',
  },
];

function parseArgs(argv) {
  const opts = { only: null, minSources: 2, timeoutMs: 20000 };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === '--only') {
      const v = argv[i + 1];
      if (!v) throw new Error('--only 后面要跟一个引用（逗号分隔也可）');
      opts.only = v
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean);
      i += 1;
    } else if (a === '--min-sources') {
      const v = Number(argv[i + 1]);
      if (!Number.isInteger(v) || v < 1) throw new Error('--min-sources 必须是 ≥1 的整数');
      opts.minSources = v;
      i += 1;
    } else if (a === '--timeout-ms') {
      const v = Number(argv[i + 1]);
      if (!Number.isInteger(v) || v < 1000) throw new Error('--timeout-ms 必须是 ≥1000 的整数');
      opts.timeoutMs = v;
      i += 1;
    } else {
      throw new Error(`未知参数 ${a}（支持 --only / --min-sources / --timeout-ms）`);
    }
  }
  return opts;
}

/**
 * 照着 401 的 Bearer 挑战取匿名 token；挑战里解析不出 realm 就**报错**，不静默直连
 * （旧注释写的是"当作公开端点直连"，代码从第一版起就是 throw：那种"降级"会让一个
 * 需要鉴权的端点用匿名身份返回 401，然后被归因成"这个来源没说话"）。
 * 参数名按 `i` 匹配：registry 生态里 `realm=` 与 `Realm=` 两种写法都实际存在
 * （Docker Hub 用小写，部分网关用首字母大写），只认一种会退化成
 * "HTTP 401 且响应里没有 Bearer 挑战"这种看起来像端点坏了的报错——运维的第一反应
 * 会是怀疑网络，而不是怀疑脚本。
 */
async function bearerFromChallenge(first, scope, timeoutMs) {
  const challenge = first.headers.get('www-authenticate') || '';
  const realm = (challenge.match(/realm="([^"]+)"/i) || [])[1];
  if (!realm) throw new Error(`HTTP ${first.status} 且响应里没有 Bearer 挑战`);
  const service = (challenge.match(/service="([^"]+)"/i) || [])[1] || '';
  const tokUrl = `${realm}?service=${encodeURIComponent(service)}&scope=${encodeURIComponent(scope)}`;
  const tr = await fetch(tokUrl, { signal: AbortSignal.timeout(timeoutMs) });
  if (!tr.ok) throw new Error(`token 端点 HTTP ${tr.status}`);
  const body = await tr.json();
  const tok = body.token || body.access_token;
  if (!tok) throw new Error('token 响应里没有 token 字段');
  return tok;
}

/** tag 取**最后一个**冒号之后：`reg.example.com:5000/x:1.2` 这类引用里前一个冒号是 registry 端口，不是 tag 分隔符。 */
function tagOf(ref) {
  return ref.slice(ref.lastIndexOf(':') + 1);
}

/**
 * 主流程的**纯**前置：解析参数 → 校验期望表自身 → 算出要核验哪些行。
 * 抽成纯函数的理由：这三步全是仓库内的静态判断，不联网就能判；留在 `main` 里就只能靠真
 * 跑一次网络来覆盖，于是"表本身写坏了"（2）与"某条 digest 漂了"（1）混成一锅。
 * `table` 形参默认取期望表，是为了让"表写坏了"这一档**能被夹具喂**：仓库里现在的表是好的，
 * 少了这个注入点，那条分支永远走不到，判据就等于装饰（`main` 同样接受 table）。
 * 返回 `{ok:true, opts, list}` 或 `{ok:false, code:2, message}`。
 */
function planRuns(argv, table = EXPECTED) {
  let opts;
  try {
    opts = parseArgs(argv);
  } catch (e) {
    return { ok: false, code: 2, message: `未知或非法参数：${e.message}` };
  }
  for (const e of table) {
    if (!/^[0-9a-f]{64}$/.test(e.digest)) {
      return {
        ok: false,
        code: 2,
        message: `期望表里 ${e.ref} 的 digest 不是 64 位小写十六进制（表本身写坏了）`,
      };
    }
  }
  if (opts.only) {
    const missing = opts.only.filter((r) => !table.some((e) => e.ref === r));
    if (missing.length) {
      return {
        ok: false,
        code: 2,
        message: `--only 里有引用不在期望表：${missing.join(', ')}（要加镜像请先在表里登记）`,
      };
    }
  }
  const list = table.filter((e) => !opts.only || opts.only.includes(e.ref));
  // 空列表必须是红。可达路径是真实存在的：`--only ,` 里 split/filter 之后是**空数组**，
  // 而空数组在 JS 里为真值，所以 `!opts.only` 那半永远不成立 ⇒ 六行全被排除。
  // 不拦就得到"==> 核验 0 个引用 … 全部通过"这种最坏的绿：写歪参数的人会以为全验过了。
  if (list.length === 0) {
    return {
      ok: false,
      code: 2,
      message: '命中 0 行期望表，没有可核验的引用（拒绝把空跑报成通过）',
    };
  }
  return { ok: true, opts, list };
}

/**
 * 取一个来源的 manifest 并**对它自算 sha256**。
 * 返回的 `digest` 永远来自本地哈希计算；`header` 只用于旁证（不一致时报出来，
 * 因为那意味着来源在发假 header 或我们的字节拼接有问题）。
 *
 * 【为什么是"一次请求，401 才重试"而不是"先探测再取"】公开端点占来源表的大多数，
 * 探测式写法会为每一个引用**把 manifest 下载两遍**（第一遍的响应体整批扔掉）。
 * 现在只下一次：拿到 200 就用，拿到非 200 才按挑战取 token 重试一次——重试的目标
 * 仍是同一个 URL，token 不会流向 realm 之外的地址。
 */
async function fetchOne(source, entry, timeoutMs) {
  const repo = source.map(entry.repo);
  if (repo === null) return { source: source.name, skipped: '该来源不托管这个仓库' };
  const url = `https://${source.name}/v2/${repo}/manifests/${entry.tag}`;
  const headers = { Accept: ACCEPT };
  const first = await fetch(url, { headers, signal: AbortSignal.timeout(timeoutMs) });
  let res = first;
  if (!first.ok) {
    const tok = await bearerFromChallenge(first, `repository:${repo}:pull`, timeoutMs);
    res = await fetch(url, {
      headers: { ...headers, Authorization: `Bearer ${tok}` },
      signal: AbortSignal.timeout(timeoutMs),
    });
  }
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const buf = Buffer.from(await res.arrayBuffer());
  // 非 JSON 响应（WAF 拦截页、透明代理的登录门户、截断的响应体）必须报错，但不能把响应体
  // 回显出来：本工具的契约是"外部响应体一律不回显"（文件头），而 JSON 解析异常默认会带上
  // 原文前若干字符——那正好是最可能被注入的一截内容。只报字节数与来源名。
  let json;
  try {
    json = JSON.parse(buf.toString('utf8'));
  } catch {
    throw new Error(`响应体不是 JSON（${buf.length} 字节，内容未回显）`);
  }
  return {
    source: source.name,
    digest: crypto.createHash('sha256').update(buf).digest('hex'),
    header: (res.headers.get('docker-content-digest') || '').replace(/^sha256:/, ''),
    mediaType: json.mediaType || res.headers.get('content-type') || '',
    entries: Array.isArray(json.manifests) ? json.manifests.length : 0,
    bytes: buf.length,
  };
}

/** 单个引用的核验结论：全 PASS 的判据三条都成立（见文件头） */
function judge(entry, got, minSources) {
  const ok = got.filter((g) => g.digest);
  const agreed = ok.filter((g) => g.digest === entry.digest);
  const isIndex = ok.every((g) => g.entries > 1);
  return {
    ref: entry.ref,
    expected: entry.digest,
    sources: got.map((g) => ({
      source: g.source,
      digest: g.digest || null,
      skipped: g.skipped || null,
      error: g.error || null,
      // 三态：相符 / 不符 / 来源根本没发这个 header。把"缺失"并进"相符"会让输出念出一句假话
      // （一个不发 Docker-Content-Digest 的中间缓存，与一个 header 和字节对不上的缓存，
      // 是完全不同的信号——后者才是要警觉的那种）。
      headerMatches: g.digest ? (g.header === '' ? null : g.header === g.digest) : null,
      entries: g.entries || 0,
      // 字节数也要过一道：`对返回字节自算 sha256` 这句取证话术的唯一实物证据就是它，
      // 打印出来才能让"某个来源只回了 41 字节的空 index"这种异常在输出里显形。
      bytes: g.bytes || 0,
    })),
    agreeCount: agreed.length,
    needCount: minSources,
    ok: agreed.length >= minSources && isIndex,
    reasons: [
      agreed.length >= minSources ? null : `一致来源 ${agreed.length} 个 < 下限 ${minSources} 个`,
      isIndex ? null : '拿到的不是 manifest 列表（钉单层摘要会锁死 architecture）',
      got.every((g) => !g.error) ? null : '有可达来源报错（见 sources 列）',
    ].filter(Boolean),
  };
}

async function verifyOne(entry, opts) {
  const got = [];
  for (const source of SOURCES) {
    try {
      got.push(await fetchOne(source, entry, opts.timeoutMs));
    } catch (e) {
      got.push({ source: source.name, error: String(e && e.message).slice(0, 120) });
    }
  }
  return judge(entry, got, opts.minSources);
}

/**
 * header 旁证的一句话。三态各写各的：把"来源没发 Docker-Content-Digest"说成"相符"是假话
 * ——ECR Public 实测就不发这个 header（2026-10-04），旧写法每次都在给它念一句"相符"。
 */
function headerNote(s) {
  // 认不出的一律落到"没有可说的"那一档：默认值必须是**不作断言**，而不是"相符"。
  if (s.headerMatches === true) return '（header 相符）';
  if (s.headerMatches === false) return '（header 与自算摘要不符）';
  return '（来源未发 Docker-Content-Digest）';
}

/**
 * 逐条打印核验结论。只打印来源名与摘要值，外部响应体一律不回显（见文件头）。
 * 单独成函数不是为了好看：`main` 的圈复杂度贴着棘轮上限（15），把输出面拆出去
 * 才能让"改判据"这件事继续待在小函数里。
 *
 * 【为什么是 应答/跳过/报错 三个数而不是"可用"】旧写法打印 `可用 = 非跳过的来源数`，
 * 而**硬报错**（HTTP 500、响应体不是 JSON）不是"跳过"，于是被算进了"可用"。读者看到
 * `一致来源 2/3（可用 3）`会以为第三个来源支持了结论，实际它一句话都没说——分母说谎
 * 与分子说谎在取证工具里是同一类缺陷。三个数分开之后，`应答` 才是 `agreeCount` 的分母，
 * 跳过与报错各自占用自己的名额。
 *
 * 【为什么逐条打印 index 条目数】期望表 `sources` 列里写着"index 7 个条目"这类取证描述，
 * 它是判据③（必须是 manifest 列表）的现场证据；不打印出来的话那句话就永远不可复核。
 */
function printVerdict(r) {
  const answered = r.sources.filter((s) => s.digest).length;
  const skipped = r.sources.filter((s) => s.skipped).length;
  const errored = r.sources.filter((s) => s.error).length;
  console.log(
    `${r.ok ? 'OK  ' : 'FAIL'} ${r.ref} @sha256:${r.expected.slice(0, 16)}… ` +
      `一致来源 ${r.agreeCount}/${answered}（跳过 ${skipped}，报错 ${errored}）`
  );
  for (const s of r.sources) {
    if (s.skipped) console.log(`       - ${s.source}: 跳过（${s.skipped}）`);
    else if (s.error) console.log(`       - ${s.source}: 报错：${s.error}`);
    else
      console.log(
        `       - ${s.source}: ${s.digest}${headerNote(s)}（index ${s.entries} 个条目，${s.bytes} 字节）`
      );
  }
  if (!r.ok) for (const why of r.reasons) console.log(`       ! ${why}`);
}

async function main(argv, table = EXPECTED) {
  const plan = planRuns(argv, table);
  if (!plan.ok) {
    console.error(`错误：${plan.message}`);
    return plan.code;
  }
  const { opts, list } = plan;
  console.log(`==> 核验 ${list.length} 个引用，要求至少 ${opts.minSources} 个来源一致`);
  let failed = 0;
  for (const entry of list) {
    // repo 必须用表里的 `entry.repo`（Hub 的仓库路径，official 镜像带 `library/` 前缀），
    // 不能从 `ref` 切——`mongo:6.0.20` 这个短名切出来是 `mongo`，
    // 而 ECR Public 上的路径是 `docker/mongo`：实测这样切会让第三个来源被当成"不托管"跳过，
    // 于是"三源一致"的取证口径悄悄退化成两源，而输出的措辞完全看不出来。
    // 这条踩坑的对账闸是 src/tests/security/imageReferenceInventory.test.js（判 repo 与 ref 互洽）。
    const r = await verifyOne({ ...entry, tag: tagOf(entry.ref) }, opts);
    printVerdict(r);
    if (!r.ok) failed += 1;
  }
  if (failed) {
    console.error(`错误：${failed}/${list.length} 个引用没通过（上面逐条给了原因）`);
    return 1;
  }
  console.log('全部通过：每个引用都有足够独立来源，且自算摘要与期望表一致。');
  return 0;
}

if (require.main === module) {
  main(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (e) => {
      console.error(`错误：核验过程抛出异常：${String(e && e.message).slice(0, 200)}`);
      process.exit(1);
    }
  );
}

module.exports = {
  EXPECTED,
  SOURCES,
  judge,
  parseArgs,
  planRuns,
  tagOf,
  verifyOne,
  fetchOne,
  headerNote,
  printVerdict,
  main,
};
