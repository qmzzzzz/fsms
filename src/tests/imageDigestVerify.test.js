/**
 * scripts/verify-image-digests.js 的判据行为（离线：fetch 用替身，不碰网络）
 *
 * 【这个脚本管的是什么】它是"钉版引用的事实来源"那一侧：表里每个 digest 都必须由
 * ①对 registry 返回的**原始字节**自算 sha256、②≥N 个运营主体不同的来源给同一个值、
 * ③拿到的是 manifest 列表（多架构 index）这三条同时成立才放行。这三条哪一条被写坏，
 * 产出的都是一份"看着钉得很实"的假安全清单——而且它不会在任何 pull/build 时报错，
 * 只会在上游投毒那天失去唯一防线。所以判据必须有用例，而不是靠脚本文件头的论证。
 *
 * 【为什么替身而不是真跑】真跑要联网，而本仓已实测 Docker Hub 官方端点在开发网络被
 * DNS 污染（CHANGELOG 2026-10-01/10-04 两段都记了）。把网络写进门禁的代价是"红了之后
 * 先怀疑网络"，那正是门禁最容易被人为绕开的形态。仓库内部对账由
 * `src/tests/security/imageReferenceInventory.test.js` 负责（不联网）；本文件只管判据逻辑。
 *
 * 【fetchOne 是本文件的重点】它是最容易"写对了但退化了"的一段：把 header 当结论、
 * 把 JSON 解析后的某个字段当摘要、把"来源不托管"和"来源报错"混成一类，都会让输出
 * 仍然像一次核验。替身故意让 header 与真实字节摘要**不相等**，断言取的是字节那条。
 *
 * 【判据分两半：逻辑用夹具，外壳用子进程】表内六行在仓库里是**全绿**的，所以"digest 不符"
 * "命中 0 行""registry 端口当 tag"这些分支在真实数据上永远不会显形——变异测试实测三条
 * 存活（M2/M3/M6）。对策是把判据写成可注入的纯函数（`planRuns(argv, table)`、`main(argv, table)`、
 * `tagOf`），用夹具喂；而 `process.exit(code)` 那一层外壳用 spawnSync 真跑脚本判退出码
 * （挑的都是触网之前就返回的路径，所以仍然是离线的）。表与文件之间的对账同理，见
 * `src/tests/security/imageReferenceInventory.test.js` 的 `reconcile` 夹具用例。
 */

'use strict';

const crypto = require('crypto');
const path = require('path');
const { spawnSync } = require('child_process');

const {
  EXPECTED,
  SOURCES,
  judge,
  parseArgs,
  planRuns,
  tagOf,
  fetchOne,
  verifyOne,
  headerNote,
  printVerdict,
  main,
} = require('../../scripts/verify-image-digests.js');

/** 造一个 manifest 列表体（2 个架构条目）；digest 由调用方按同一批字节自算，保证可核对 */
function indexBody(tag) {
  const json = JSON.stringify({
    schemaVersion: 2,
    mediaType: 'application/vnd.docker.distribution.manifest.list.v2+json',
    manifests: [
      { digest: `sha256:${'1'.repeat(64)}`, platform: { os: 'linux', architecture: 'amd64' } },
      { digest: `sha256:${'2'.repeat(64)}`, platform: { os: 'linux', architecture: 'arm64' } },
    ],
  });
  return { buf: Buffer.from(json, 'utf8'), tag };
}

/**
 * fetch 响应的鸭子类型替身：只提供 fetchOne 真正读取的那几面
 * （`ok` / `status` / `headers.get` / `arrayBuffer` / `json`）。
 * 不用 globalThis.Response：那是 undici 随 Node 带进来的，"这个环境里有没有它、
 * 它的 ok 怎么算"会跟着 Node 版本漂，不该决定本文件的结论。
 * 键一律小写存：真实 `Headers.get` 大小写不敏感，替身若按字面键查，实现里写成
 * `get('Docker-Content-Digest')` 就会"测试里过、线上拿到空串"。
 */
function resp(body, { status = 200, headers = {} } = {}) {
  const h = {};
  for (const [k, v] of Object.entries(headers)) h[String(k).toLowerCase()] = String(v);
  const buf = Buffer.isBuffer(body) ? body : Buffer.from(String(body), 'utf8');
  const get = (name) => {
    const key = String(name).toLowerCase();
    return Object.hasOwn(h, key) ? h[key] : null;
  };
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get },
    arrayBuffer: async () => buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength),
    json: async () => JSON.parse(buf.toString('utf8')),
  };
}

const okSource = (name) => ({
  source: name,
  digest: 'a'.repeat(64),
  entries: 3,
  header: 'a'.repeat(64),
});
const skippedSource = (name) => ({ source: name, skipped: '该来源不托管这个仓库' });
const erroredSource = (name) => ({ source: name, error: 'HTTP 404' });

describe('verify-image-digests.js 的判据行为', () => {
  test('judge：三条判据各自能单独把结论打回 false（不是"多数同意就过"）', () => {
    const entry = { ref: 'x/y:1.0', digest: 'a'.repeat(64) };
    // 自证正向腿：三条都成立时必须真的判过，否则下面的每条"因为缺 X 而红"毫无意义。
    const pass = judge(entry, [okSource('s1'), okSource('s2'), skippedSource('s3')], 2);
    expect({ ok: pass.ok, agree: pass.agreeCount, reasons: pass.reasons }).toMatchObject({
      ok: true,
      agree: 2,
      reasons: [],
    });

    // ① 一致来源不足：三个来源都答了，但只有 1 个与期望表相同。
    const fewAgree = judge(
      entry,
      [
        okSource('s1'),
        { source: 's2', digest: 'b'.repeat(64), entries: 3, header: 'b'.repeat(64) },
        { source: 's3', digest: 'c'.repeat(64), entries: 3, header: 'c'.repeat(64) },
      ],
      2
    );
    expect(fewAgree.ok).toBe(false);
    expect(fewAgree.reasons.join('\n')).toMatch(/一致来源 1 个 < 下限 2 个/);

    // ② 两个来源完全一致、但拿的是单层 manifest：钉上去等于锁死一个 architecture。
    const singleLayer = judge(
      entry,
      [
        { ...okSource('s1'), entries: 1 },
        { ...okSource('s2'), entries: 1 },
      ],
      2
    );
    expect(singleLayer.ok).toBe(false);
    expect(singleLayer.reasons.join('\n')).toMatch(/不是 manifest 列表/);

    // ③ 有可达来源报错：结论不能因为"另外两个刚好一致"就变成全绿。
    const errored = judge(entry, [okSource('s1'), okSource('s2'), erroredSource('s3')], 2);
    expect(errored.ok).toBe(true); // 一致来源够了
    expect(errored.reasons.join('\n')).toMatch(/有可达来源报错/);

    // skipped 不算"报错"也不算"一致"：ECR Public 对第三方命名空间就是这一类。
    const skipped = judge(entry, [okSource('s1'), skippedSource('s3')], 2);
    expect(skipped.ok).toBe(false);
    expect(skipped.reasons.join('\n')).not.toMatch(/有可达来源报错/);

    // headerMatches 是旁证位（不参与 ok），三种情况必须可区分：header 说真话 / 说假话 / 压根没发。
    // 把"没发"当成"相符"，输出就会对一个剥掉了 header 的中间缓存念出"header 相符"这种假话。
    const proof = judge(
      entry,
      [
        okSource('s1'),
        { ...okSource('s2'), header: 'e'.repeat(64) },
        { ...okSource('s3'), header: '' },
      ],
      2
    );
    expect(proof.sources.map((s) => s.headerMatches)).toEqual([true, false, null]);
    // skipped/error 两类没有摘要，旁证位必须是 null 而不是"true"（否则表格读起来像它们验过）。
    const mixed = judge(entry, [okSource('s1'), skippedSource('s2'), erroredSource('s3')], 1);
    expect(mixed.sources.map((s) => s.headerMatches)).toEqual([true, null, null]);
  });

  test('judge：min-sources 下限真的生效（把它调大，同一批数据必须变红）', () => {
    const entry = { ref: 'x/y:1.0', digest: 'a'.repeat(64) };
    const got = [okSource('s1'), okSource('s2'), skippedSource('s3')];
    expect(judge(entry, got, 2).ok).toBe(true);
    expect(judge(entry, got, 3).ok).toBe(false);
  });

  test('headerNote：三态各自成话，认不出的值默认"不作断言"而不是"相符"', () => {
    // 这一位是运维唯一会读的来源健康信号之一：ECR Public 实测不发 Docker-Content-Digest
    // （2026-10-04），把它念成"header 相符"就是脚本自己在造假。
    expect(headerNote({ headerMatches: true })).toBe('（header 相符）');
    expect(headerNote({ headerMatches: false })).toBe('（header 与自算摘要不符）');
    expect(headerNote({ headerMatches: null })).toBe('（来源未发 Docker-Content-Digest）');
    // undefined/缺字段也必须走"没话说"那一档：判据的默认值不能是"通过"。
    expect(headerNote({ headerMatches: undefined })).toBe('（来源未发 Docker-Content-Digest）');
    expect(headerNote({})).toBe('（来源未发 Docker-Content-Digest）');
  });

  test('fetchOne：摘要取自返回字节自算，header 说谎也不改结论', async () => {
    const { buf } = indexBody('1.0');
    const self = crypto.createHash('sha256').update(buf).digest('hex');
    const calls = [];
    const sentHeaders = [];
    const realFetch = global.fetch;
    global.fetch = async (url, init) => {
      calls.push(url);
      sentHeaders.push((init && init.headers) || {});
      return resp(buf, {
        status: 200,
        headers: {
          // header 故意与字节摘要不同：如果实现抄 header，下面的断言会拿到假摘要。
          'docker-content-digest': `sha256:${'f'.repeat(64)}`,
          'content-type': 'application/vnd.oci.image.index.v1+json',
        },
      });
    };
    try {
      const r = await fetchOne(
        { name: 'fake', map: (repo) => repo },
        { ref: 'prom/prometheus:v1', repo: 'prom/prometheus', tag: 'v1', digest: self },
        5000
      );
      expect(r.digest).toBe(self);
      // header 就是那个假值：`digest === self` 单看会被"header 恰好也等于 self"蒙过去，
      // 所以必须同时钉住 header 的原始值，证明两者是分开的两条信息。
      expect(r.header).toBe('f'.repeat(64));
      expect(r.digest).not.toBe(r.header);
      expect(r.entries).toBe(2);
      // mediaType 取的是**响应体里**的字段（body 才是内容寻址的那堆字节，header 只是传输层声明）。
      expect(r.mediaType).toBe('application/vnd.docker.distribution.manifest.list.v2+json');
      expect(r.bytes).toBe(buf.length);
      // URL 必须由 repo + tag 拼出来：路径写错（比如漏了 library/ 前缀）就是 404，
      // 而脚本会把 404 归成"这个来源没说话"，静默少一条腿。
      // Accept 必须同时带 OCI index 与 docker manifest list：只声明一种时 registry 会按
      // 单平台 manifest 回答，`entries` 变 0，判据③红——但那是"验不过"而不是"验的是什么"，
      // 所以这里钉 header 内容而不是只看结论。
      expect(calls).toEqual(['https://fake/v2/prom/prometheus/manifests/v1']);
      expect(sentHeaders[0].Accept).toBe(
        'application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json'
      );
      // 公开端点（200 直接可用）只请求一次、且绝不携带 Authorization：旧写法先探测再取，
      // 会把 manifest 下载两遍并对每个引用多打一次请求。
      expect(sentHeaders[0].Authorization).toBeUndefined();
    } finally {
      global.fetch = realFetch;
    }
  });

  test('fetchOne：单层 manifest 必须让 entries 归 0（判据③唯一的输入就是它）', async () => {
    // 真实场景：Accept 没被满足、或 registry 只发布了单架构变体时，返回体是一个
    // `manifest.v2`（有 layers、没有 manifests）。这个 digest 技术上"正确"，钉上去却
    // 把自己锁死在一个 architecture 上——所以这里必须是 0，而不是"字段缺失＝不管"。
    const buf = Buffer.from(
      JSON.stringify({
        schemaVersion: 2,
        mediaType: 'application/vnd.docker.distribution.manifest.v2+json',
        layers: [{ digest: `sha256:${'3'.repeat(64)}` }],
      }),
      'utf8'
    );
    const realFetch = global.fetch;
    global.fetch = async () => resp(buf, { status: 200 });
    let r;
    try {
      r = await fetchOne(
        { name: 'fake', map: (repo) => repo },
        { repo: 'library/x', tag: '1', ref: 'x:1' },
        5000
      );
    } finally {
      global.fetch = realFetch;
    }
    expect(r.entries).toBe(0);
    expect(r.digest).toBe(crypto.createHash('sha256').update(buf).digest('hex'));
    // 端到端一根：两个来源完全一致、摘要也等于期望值，但只要拿的是单层就判红。
    const entry = { ref: 'x:1', digest: r.digest };
    const v = judge(entry, [r, { ...r, source: 'other' }], 2);
    expect(v.ok).toBe(false);
    expect(v.agreeCount).toBe(2);
    expect(v.reasons.join('\n')).toMatch(/不是 manifest 列表/);
  });

  test('fetchOne：来源不托管 ⇒ skipped；HTTP 错误 ⇒ error。两者不得混成一类', async () => {
    const realFetch = global.fetch;
    // map() 返回 null 的分支不碰网络，直接给 skipped（ECR Public 对第三方命名空间就是这一类）。
    const none = { name: 'fake', map: () => null };
    expect(await fetchOne(none, { repo: 'prom/prometheus', tag: 'v1' }, 1000)).toMatchObject({
      source: 'fake',
      skipped: '该来源不托管这个仓库',
    });
    // 404 且响应里没有 Bearer 挑战 ⇒ 必须报错。写成"跳过"的话，一条坏掉的 registry 路径
    // （比如漏了 library/ 前缀）会长期只表现为"这条腿今天没说话"。
    global.fetch = async () => resp('', { status: 404 });
    try {
      await expect(
        fetchOne({ name: 'fake', map: (repo) => repo }, { repo: 'library/x', tag: '1' }, 1000)
      ).rejects.toThrow(/HTTP 404/);
    } finally {
      global.fetch = realFetch;
    }
    // ECR Public 的映射口径：official 库走 `docker/library/<名>`（写成 `docker/<名>` 实测 404），
    // 命名空间镜像一律不托管（写成"任何 repo 都映射"就等于去验别人仓库的摘要）。
    const ecr = SOURCES.find((s) => s.name === 'public.ecr.aws');
    expect(ecr.map('library/node')).toBe('docker/library/node');
    expect(ecr.map('prom/prometheus')).toBeNull();
  });

  test('匿名 Bearer 挑战被跟随，token 只用于该仓库的 pull scope', async () => {
    const { buf } = indexBody('7');
    const seen = [];
    const sentAuth = [];
    const realFetch = global.fetch;
    global.fetch = async (url, init) => {
      seen.push(url);
      sentAuth.push((init && init.headers && init.headers.Authorization) || null);
      if (url.startsWith('https://reg.example.com/token?')) {
        return resp(JSON.stringify({ access_token: 'tok-abc' }), { status: 200 });
      }
      if (sentAuth[sentAuth.length - 1]) {
        return resp(buf, { status: 200 });
      }
      return resp('', {
        status: 401,
        headers: {
          'www-authenticate':
            'Bearer realm="https://reg.example.com/token",service="registry.docker.io",scope="repository:library/node:pull"',
        },
      });
    };
    try {
      const r = await fetchOne(
        { name: 'reg.example.com', map: (repo) => repo },
        { repo: 'library/node', tag: '7', digest: 'a'.repeat(64), ref: 'node:7' },
        5000
      );
      expect(r.digest).toBe(crypto.createHash('sha256').update(buf).digest('hex'));
      // 顺序本身是判据：不带 token 直接重试（少一步）、或者拿 token 那次也带上了
      // Authorization（把凭据发给挑战解析前的 URL）都要红。
      expect(seen).toEqual([
        'https://reg.example.com/v2/library/node/manifests/7',
        'https://reg.example.com/token?service=registry.docker.io&scope=repository%3Alibrary%2Fnode%3Apull',
        'https://reg.example.com/v2/library/node/manifests/7',
      ]);
      expect(sentAuth).toEqual([null, null, 'Bearer tok-abc']);
      // 第二腿换一个替身：challenge 用小写 realm（Hub 的真实形态）但 token 响应把字段名
      // 换成 `token`。access_token 与 token 两个字段名都要认：registry 与 token 服务在这一项
      // 上从不统一，只认其中一个会让那条来源整年"报错"而被忽略。
      const seen2 = [];
      const sentAuth2 = [];
      global.fetch = async (url, init) => {
        const auth = (init && init.headers && init.headers.Authorization) || null;
        seen2.push(url);
        sentAuth2.push(auth);
        if (url.startsWith('https://reg.example.com/token?')) {
          // 取 token 这一步**不带** Authorization：带上了就等于把上一轮的凭据发给
          // 一个还没验过的新 URL，而这里正是那个 URL 由外部 header 决定的地方。
          return resp(JSON.stringify({ token: 'tok-xyz' }), { status: 200 });
        }
        if (auth) return resp(buf, { status: 200 });
        return resp('', {
          status: 401,
          headers: {
            'www-authenticate':
              'Bearer realm="https://reg.example.com/token",service="registry.docker.io",scope="repository:library/node:pull"',
          },
        });
      };
      const r2 = await fetchOne(
        { name: 'reg.example.com', map: (repo) => repo },
        { repo: 'library/node', tag: '7', digest: 'a'.repeat(64), ref: 'node:7' },
        5000
      );
      expect(r2.digest).toBe(crypto.createHash('sha256').update(buf).digest('hex'));
      expect(sentAuth2).toEqual([null, null, 'Bearer tok-xyz']);
    } finally {
      global.fetch = realFetch;
    }
  });

  test('挑战参数名大小写不敏感，但解析不出 realm 时绝不静默直连', async () => {
    const { buf } = indexBody('9');
    const realFetch = global.fetch;
    // 首字母大写的参数名（部分网关这么发）：只认小写时这一条来源会常年报
    // "响应里没有 Bearer 挑战"，看起来像端点坏了。
    global.fetch = async (url, init) => {
      if (url.startsWith('https://cap.example.com/token?')) {
        return resp(JSON.stringify({ token: 'tok-cap' }), { status: 200 });
      }
      return init && init.headers && init.headers.Authorization
        ? resp(buf, { status: 200 })
        : resp('', {
            status: 401,
            headers: {
              'www-authenticate':
                'Bearer Realm="https://cap.example.com/token",Service="registry.docker.io"',
            },
          });
    };
    try {
      const r = await fetchOne(
        { name: 'cap.example.com', map: (repo) => repo },
        { repo: 'library/node', tag: '9' },
        5000
      );
      expect(r.digest).toBe(crypto.createHash('sha256').update(buf).digest('hex'));
      // 没有 realm 的挑战（另一种鉴权方案）必须报错，而不是"当作公开端点直连"：
      // 静默直连的产物是一个需要鉴权的端点用匿名身份返回 401，最后被归成"这条腿没说话"。
      global.fetch = async () =>
        resp('', { status: 401, headers: { 'www-authenticate': 'Negotiate' } });
      await expect(
        fetchOne(
          { name: 'x.example.com', map: (repo) => repo },
          { repo: 'library/y', tag: '1' },
          1000
        )
      ).rejects.toThrow(/HTTP 401 且响应里没有 Bearer 挑战/);
      // token 端点自己非 200 ⇒ 报错，不能拿空 token 继续
      global.fetch = async (url) =>
        url.startsWith('https://x.example.com/token')
          ? resp('', { status: 500 })
          : resp('', {
              status: 401,
              headers: { 'www-authenticate': 'Bearer realm="https://x.example.com/token"' },
            });
      await expect(
        fetchOne(
          { name: 'x.example.com', map: (repo) => repo },
          { repo: 'library/y', tag: '1' },
          1000
        )
      ).rejects.toThrow(/token 端点 HTTP 500/);
    } finally {
      global.fetch = realFetch;
    }
  });

  test('parseArgs：参数面的每条边界（写坏一条就会把整表核验变成"什么都没验"）', () => {
    expect(parseArgs([])).toEqual({ only: null, minSources: 2, timeoutMs: 20000 });
    expect(parseArgs(['--only', 'mongo:6.0.20,redis:7-alpine']).only).toEqual([
      'mongo:6.0.20',
      'redis:7-alpine',
    ]);
    expect(parseArgs(['--min-sources', '3']).minSources).toBe(3);
    expect(parseArgs(['--timeout-ms', '5000']).timeoutMs).toBe(5000);
    // 每一条都必须抛：`--only` 拼错成静默不过滤会验全表；`--min-sources 0` 会让
    // "任何一个来源说什么都算"，判据直接归零。
    expect(() => parseArgs(['--only'])).toThrow(/--only/);
    expect(() => parseArgs(['--min-sources', '0'])).toThrow(/min-sources/);
    expect(() => parseArgs(['--min-sources', 'x'])).toThrow(/min-sources/);
    expect(() => parseArgs(['--min-sources', '1.5'])).toThrow(/min-sources/);
    expect(() => parseArgs(['--timeout-ms', '999'])).toThrow(/timeout-ms/);
    expect(() => parseArgs(['--aply'])).toThrow(/未知参数/);
  });

  test('来源表与期望表互洽：来源名唯一、每个 ref 的 repo 都能被至少两个来源映射', () => {
    const names = SOURCES.map((s) => s.name);
    expect(new Set(names).size).toBe(names.length);
    expect(names.length).toBeGreaterThanOrEqual(3);
    for (const e of EXPECTED) {
      const usable = SOURCES.filter((s) => s.map(e.repo) !== null);
      // 少于两个可用来源就没法满足默认 min-sources=2：这条判据把"表里加了一个所有来源都
      // 不托管的引用"变成结构错误，而不是每次跑都在输出里念"跳过"。
      // 带上 ref 是为了失败信息能指名是哪一条引用出问题。
      expect({ ref: e.ref, atLeast2: usable.length >= 2 }).toEqual({ ref: e.ref, atLeast2: true });
      // 映射后的路径必须仍带同一个仓库末段名：来源重写仓库名（Hub 的 official 前缀之外）
      // 就等于去验另一个仓库的 digest。
      for (const s of usable) {
        const mapped = s.map(e.repo);
        expect({ ref: e.ref, source: s.name, last: mapped.split('/').pop() }).toMatchObject({
          last: e.repo.split('/').pop(),
        });
      }
    }
  });

  test('judge：判据③对混合结果取"每个来源都是 index"而不是"至少一个"（顺序无关）', () => {
    // `every` 改成 `some` 是实测存活过的一条变异（M10）：两条腿一条拿到多架构 index、
    // 另一条只拿到单平台 manifest 时，"多架构已被独立来源共同证实"这句话其实不成立——
    // 而 ok 会变成 true。夹具必须两个方向都喂：断言顺序不影响结论。
    const entry = { ref: 'x/y:1.0', digest: 'a'.repeat(64) };
    const idx = okSource('s1'); // entries: 3
    const single = { ...okSource('s2'), entries: 0 };
    for (const got of [
      [idx, single],
      [single, idx],
    ]) {
      const v = judge(entry, got, 2);
      expect({ order: got.map((g) => g.entries).join('-'), ok: v.ok }).toEqual({
        order: got.map((g) => g.entries).join('-'),
        ok: false,
      });
      expect(v.reasons.join('\n')).toMatch(/不是 manifest 列表/);
      // 摘要一致这件事仍然成立：判据①与判据③混成一团的话，"两条腿都在说谎"和
      // "两条腿说真话但只有一条是多架构"就分不出来了。
      expect(v.agreeCount).toBe(2);
    }
  });

  test('tagOf：registry 端口不是 tag 分隔符（真实六行各只有一个冒号，判据只能靠夹具）', () => {
    // `lastIndexOf` 改成 `indexOf`（实测存活 M3）在 `mongo:6.0.20` 这类引用上毫无差别，
    // 所以这条判据的唯一来源就是带端口的夹具。
    expect(tagOf('reg.example.com:5000/team/app:1.2.3')).toBe('1.2.3');
    expect(tagOf('localhost:5000/x:latest')).toBe('latest');
    expect(tagOf('node:22.14.0-alpine')).toBe('22.14.0-alpine');
    // 正向对账：真实表里每一条切出来的 tag 必须既不含斜杠也不含冒号（否则 URL 拼接会跨段，
    // `/v2/<repo>/manifests/<tag>` 直接指到别的路径上去）。
    for (const e of EXPECTED) {
      const tag = tagOf(e.ref);
      // 真实六行都只有一个冒号，所以"最后一个"与"唯一的"两种切法必须给同一个结果——
      // 这条交叉判据的作用是让下次有人加**内网 registry（带端口）**的引用时先看一眼这里。
      expect(e.ref.split(':')).toHaveLength(2);
      expect(tag).toBe(e.ref.split(':')[1]);
      expect(tag.includes('/')).toBe(false);
      expect(tag.includes(':')).toBe(false);
    }
  });

  test('planRuns：命中 0 行与"表本身写坏"都必须是 2（空跑不得念成全部通过）', () => {
    const all = planRuns([]);
    expect(all.ok).toBe(true);
    expect(all.list).toHaveLength(EXPECTED.length);
    // 顺序来自**期望表**而不是 `--only` 的写法顺序：这条断言钉的是"过滤不改序"，
    // 否则下次有人按 --only 的顺序读输出会对不上表。
    expect(planRuns(['--only', 'mongo:6.0.20,redis:7-alpine']).list.map((e) => e.ref)).toEqual([
      'redis:7-alpine',
      'mongo:6.0.20',
    ]);
    // `--only ,`：split+filter 之后是**空数组**，而空数组在 JS 里为真值 ⇒ 六行全被排除。
    // 旧实现由此打印"==> 核验 0 个引用 … 全部通过"并退 0（实测存活 M2）。
    const empty = planRuns(['--only', ',']);
    expect(empty.ok).toBe(false);
    expect(empty.code).toBe(2);
    expect(empty.message).toMatch(/0 行/);
    expect(planRuns(['--only', 'nope:1']).code).toBe(2);
    expect(planRuns(['--nope']).code).toBe(2);
    // "表写坏了"这一档只能靠注入夹具判（仓库里的表现在是好的）：少一位 hex 必须在**触网之前**
    // 拦住——放到网络之后就会与"上游漂了"混成同一个 1，运维分不清该改表还是该重新取证。
    const broken = planRuns([], [{ ref: 'x:1', repo: 'library/x', digest: 'a'.repeat(63) }]);
    expect({ ok: broken.ok, code: broken.code, msg: broken.message }).toMatchObject({
      ok: false,
      code: 2,
      msg: expect.stringContaining('x:1'),
    });
  });

  test('main：0 / 1 / 2 三档退出码各自可达（fetch 全替身，不联网）', async () => {
    const { buf } = indexBody('1');
    const self = crypto.createHash('sha256').update(buf).digest('hex');
    const entry = {
      ref: 'prom/p:1',
      repo: 'prom/p',
      digest: self,
      captured: '2026-10-04',
      sources: 'x',
      sites: 'y',
    };
    const out = { log: [], error: [] };
    const real = { fetch: global.fetch, log: console.log, error: console.error };
    global.fetch = async () => resp(buf, { status: 200 });
    console.log = (...a) => out.log.push(a.join(' '));
    console.error = (...a) => out.error.push(a.join(' '));
    try {
      // 0：ECR 不托管该命名空间（跳过），两条缓存给同一个值且都是 index ⇒ 判据三条全立。
      expect(await main(['--only', 'prom/p:1'], [entry])).toBe(0);
      expect(out.log.join('\n')).toMatch(/全部通过/);
      // 1：内容寻址没变，但期望表指的是另一个值——"上游漂了/表被改坏"的形态。
      out.log.length = 0;
      expect(await main(['--only', 'prom/p:1'], [{ ...entry, digest: 'b'.repeat(64) }])).toBe(1);
      expect(out.log.join('\n')).toMatch(/FAIL prom\/p:1/);
      expect(out.log.join('\n')).not.toMatch(/全部通过/);
      // 2：前置就拦住，一次网络都不该发（替身换成"发了就抛"）。
      out.log.length = 0;
      global.fetch = async () => {
        throw new Error('不该触网');
      };
      expect(await main(['--only', ','], [entry])).toBe(2);
      expect(out.error.join('\n')).toMatch(/0 行/);
    } finally {
      global.fetch = real.fetch;
      console.log = real.log;
      console.error = real.error;
    }
  });

  test('CLI 外壳真的把返回值接到退出码（spawnSync 判 2 号路径，全程不触网）', () => {
    // `main` 的返回值判过了不等于 `process.exit(code)` 判过了：把那一句改成 `exit(0)` 时
    // 上面的用例全绿而 CI 全绿。挑三条都在触网之前返回的路径真跑一次脚本，
    // 让外壳也进判据（不联网、耗时约三次 node 启动）。
    const script = path.join(__dirname, '..', '..', 'scripts', 'verify-image-digests.js');
    const run = (args) => spawnSync(process.execPath, [script, ...args], { encoding: 'utf8' });
    expect(run(['--only', ',']).status).toBe(2);
    expect(run(['--min-sources', '0']).status).toBe(2);
    expect(run(['--aply']).status).toBe(2);
    const r = run(['--only', 'nope:1']);
    expect(r.status).toBe(2);
    expect(r.stderr).toMatch(/不在期望表/);
    // 三条都得有 stderr 文案：只判退出码的话，"任何异常都退 2"这种偷懒写法也能过。
    for (const args of [['--only', ','], ['--min-sources', '0'], ['--aply']]) {
      expect(run(args).stderr.length).toBeGreaterThan(0);
    }
  });

  test('替身 self-check：resp() 的 header 归一化两面都有判据（否则大小写用例是空转）', () => {
    // 上面那条"各种大小写都要读得到"依赖替身模拟了真实 Headers 的大小写不敏感。替身自己
    // 坏掉的话，那条用例就变成"实现恰好写对小写键"的巧合通过——所以存/取两面各钉一条直接断言：
    // 把 `h[String(k).toLowerCase()]` 或 `get` 里的归一化删掉任一半，本用例立刻红。
    const r = resp('{}', { status: 200, headers: { 'Docker-Content-Digest': 'sha256:abc' } });
    expect(r.headers.get('docker-content-digest')).toBe('sha256:abc'); // 存的那一面
    expect(r.headers.get('Docker-Content-Digest')).toBe('sha256:abc'); // 取的那一面
    expect(r.headers.get('DOCKER-CONTENT-DIGEST')).toBe('sha256:abc');
    // 缺失键必须是 null（不是 undefined、也不是空串）：实现用 `|| ''` 把"没发"归成空串，
    // 三态判据才分得开"没发"与"发了但和字节不符"。
    expect(r.headers.get('x-not-there')).toBeNull();
    // ok 的算法也钉住：替身若写成 `status === 200`，304/2xx 分支的判据就会跟着变。
    expect(resp('', { status: 404 }).ok).toBe(false);
    expect(resp('', { status: 201 }).ok).toBe(true);
  });

  test('fetchOne：Docker-Content-Digest 的各种大小写形态都要读得到', async () => {
    // 替身按小写存键（真实 Headers 是大小写不敏感的），所以这一条判的是**实现里的取值键**：
    // 写成 `get('Docker-Content-Digest')` 而替身不归一化时会拿到空串，headerMatches 一律
    // 退化成 null，输出就对着一个发过 header 的来源念"未发 Docker-Content-Digest"。
    const { buf } = indexBody('1');
    const self = crypto.createHash('sha256').update(buf).digest('hex');
    const realFetch = global.fetch;
    try {
      for (const key of [
        'docker-content-digest',
        'Docker-Content-Digest',
        'DOCKER-CONTENT-DIGEST',
      ]) {
        global.fetch = async () => resp(buf, { status: 200, headers: { [key]: `sha256:${self}` } });
        const r = await fetchOne(
          { name: 'fake', map: (repo) => repo },
          { repo: 'library/x', tag: '1' },
          1000
        );
        expect({ key, header: r.header }).toEqual({ key, header: self });
        expect(judge({ ref: 'x:1', digest: self }, [r], 1).sources[0].headerMatches).toBe(true);
      }
    } finally {
      global.fetch = realFetch;
    }
  });

  test('fetchOne：非 JSON 响应体报错但不回显内容（外部响应一律不进输出）', async () => {
    const body = '<html>WAF blocked - marker-KEEP-OUT-8f3c</html>';
    const bytes = Buffer.byteLength(body, 'utf8');
    const realFetch = global.fetch;
    global.fetch = async () =>
      resp(body, { status: 200, headers: { 'content-type': 'text/html' } });
    let message = '';
    try {
      const call = () =>
        fetchOne({ name: 'fake', map: (repo) => repo }, { repo: 'library/x', tag: '1' }, 1000);
      await expect(call()).rejects.toThrow(/不是 JSON/);
      message = await call().catch((e) => e.message);
    } finally {
      global.fetch = realFetch;
    }
    // JSON.parse 的原生异常文本会带上响应体前若干字符——那正是"外部内容进日志"的口子
    // （一个透明代理可以把任意文本放进 200 响应体里）。判据是**字节数可报、内容不可报**。
    expect(message).toContain(String(bytes));
    expect(message).toMatch(/未回显/);
    expect(message).not.toMatch(/KEEP-OUT/);
    expect(message).not.toMatch(/<html>/);
  });

  test('verifyOne + printVerdict：跳过/报错/应答三个数分开，报错不得占用分母', async () => {
    const { buf } = indexBody('1');
    const self = crypto.createHash('sha256').update(buf).digest('hex');
    const realFetch = global.fetch;
    global.fetch = async (url) =>
      url.includes('docker.1ms.run')
        ? resp('<html>nope</html>', { status: 200 })
        : resp(buf, { status: 200 });
    let r;
    try {
      r = await verifyOne(
        { ref: 'prom/p:1', repo: 'prom/p', tag: '1', digest: self },
        { minSources: 1, timeoutMs: 1000 }
      );
    } finally {
      global.fetch = realFetch;
    }
    const byName = Object.fromEntries(r.sources.map((s) => [s.source, s]));
    expect(byName['public.ecr.aws'].skipped).toBeTruthy(); // 命名空间镜像：ECR 不托管
    expect(byName['docker.m.daocloud.io'].digest).toBe(self);
    expect(byName['docker.1ms.run'].error).toMatch(/不是 JSON/);
    expect(byName['docker.1ms.run'].digest).toBeNull();
    // 下限设 1：一条腿应答且与期望一致 ⇒ 结论成立，但 reasons 仍要点名那条报错的腿。
    expect(r.ok).toBe(true);
    expect(r.agreeCount).toBe(1);
    expect(r.reasons.join('\n')).toMatch(/有可达来源报错/);
    const lines = [];
    const realLog = console.log;
    console.log = (...a) => lines.push(a.join(' '));
    try {
      printVerdict(r);
    } finally {
      console.log = realLog;
    }
    // 旧写法打印 `可用 = 非跳过的来源数`，把**硬报错**也算进去（实测存活 M13）：
    // 读者看到 `2/3（可用 3）` 会以为第三条腿支持了结论。
    expect(lines[0]).toContain('一致来源 1/1（跳过 1，报错 1）');
    // 标记列的宽度也钉住：`OK  `/`FAIL` 两档等宽是给人（和 grep）读的，退化成 `OK` 就会与
    // 上面的 FAIL 对不齐。
    expect(lines[0]).toMatch(/^OK {3}prom\/p:1/);
    expect(lines.join('\n')).toMatch(/docker\.1ms\.run: 报错：/);
    expect(lines.join('\n')).toMatch(/index 2 个条目/);
    expect(lines.join('\n')).not.toMatch(/可用/);
    // 打印面的字节数必须是**真实字节数**：judge 若不透传 `bytes`（实测存活 D5），
    // 输出会念 "0 字节"——那正是"对返回字节自算 sha256"这句话唯一的实物证据，念错等于没念。
    expect(lines.join('\n')).toContain(`${buf.length} 字节`);
    expect(lines.join('\n')).toMatch(/index 2 个条目/);
    expect(lines.join('\n')).not.toMatch(/undefined/);
  });
});
