/**
 * 两条托管路径的 sourcemap 纵深必须同口径
 *
 * `src/middleware/staticFrontend.js` 与 `deployment/nginx.conf.example` 是**二选一**的
 * 生产前端托管方案（两个文件头都这么写）。此前给 Express 侧补上了
 * "解码后路径 + 大小写归一 + GET/HEAD 都拦"的 `.map`/`.ts` 纵深拦截，
 * 但如果部署走 nginx（README/nginx 示例里的默认路径），那道拦截完全不参与：
 * `location / { try_files $uri $uri/ /index.html; }` 会让
 * `GET /assets/leak.js.map` 直接命中真实文件下发。
 * ⇒ 只在一条路径上设防等于没设防。
 *
 * 本用例把"两条路径同一份扩展名清单"钉成闸，判据从**生产代码**里读
 * `DENIED_STATIC_EXTS`，而不是在本文件里再抄一份清单（抄一份就是第二个漂移源）。
 *
 * 文本断言的既有教训（本仓三次因此吃过假绿）：
 *  ① 必须先剥掉注释再匹配——conf 的说明文字里就写着 `.map/.ts`，不剥会恒绿；
 *  ② 必须自带反向前提（把块删掉/少写一个扩展名/把 `~*` 写成 `~` 都要转红），
 *     否则"当前恰好有"和"判据真的有效"是两回事。
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..', '..', '..');
const read = (rel) => fs.readFileSync(path.join(ROOT, rel), 'utf8');

/** 剥掉行注释：nginx 用 #，JS 用 // 与块注释。保留行结构（换行不吞） */
function stripComments(text) {
  return text
    .replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, ' '))
    .replace(/(^|[^:])\/\/[^\n]*/g, '$1')
    .replace(/#[^\n]*/g, '');
}

/** Express 侧的真实清单（唯一事实来源） */
function expressDeniedExts() {
  const code = stripComments(read('src/middleware/staticFrontend.js'));
  const m = code.match(/DENIED_STATIC_EXTS\s*=\s*\[([^\]]*)\]/);
  if (!m) throw new Error('读不到 DENIED_STATIC_EXTS，Express 侧清单改名了 ⇒ 本闸需要跟着改');
  return [...m[1].matchAll(/'(\.[a-z0-9]+)'/g)].map((x) => x[1]);
}

/** nginx 里大小写不敏感的正则 location 块（返回其块体与捕获的扩展名） */
function nginxRegexBlocks(code) {
  return [...code.matchAll(/location\s+(~\*|~)\s+\\?\.\(?([a-z|]+)\)?\$\s*\{([\s\S]*?)\}/g)].map(
    (m) => ({ modifier: m[1], exts: m[2].split('|'), body: m[3] })
  );
}

describe('zzqoder nginx 托管路径的 sourcemap 纵深与 Express 侧同口径', () => {
  const code = stripComments(read('deployment/nginx.conf.example'));
  const exts = expressDeniedExts();

  test('取数有效：两侧都真的读到了内容（防解析坏掉后空集恒绿）', () => {
    expect(exts.length).toBeGreaterThanOrEqual(2);
    expect(code).toMatch(/location\s+\//);
    expect(nginxRegexBlocks(code).length).toBeGreaterThanOrEqual(1);
  });

  test('存在大小写不敏感（~*）的扩展名拦截块，且返回 404', () => {
    const block = nginxRegexBlocks(code).find((b) =>
      exts.every((e) => b.exts.includes(e.replace(/^\./, '')))
    );
    expect(block).toBeDefined();
    expect(block.modifier).toBe('~*'); // `~` 只挡小写，Windows/开发机上 leak.js.MAP 是同一文件
    expect(block.body).toMatch(/return\s+404\s*;/);
  });

  test('拦截的扩展名集合与 Express 侧完全一致（两侧不得各自增删）', () => {
    const nginxExts = new Set(nginxRegexBlocks(code).flatMap((b) => b.exts));
    const expected = new Set(exts.map((e) => e.replace(/^\./, '')));
    // 双向比较：nginx 少一项是缺口，多一项是误杀（例如哪天有人把 .js 也挡了）
    expect([...nginxExts].filter((e) => !expected.has(e))).toEqual([]);
    expect([...expected].filter((e) => !nginxExts.has(e))).toEqual([]);
  });

  test('拦截块不得顺手下发缓存/安全头以外的 add_header（404 用不到，且 add_header 是整体替换语义）', () => {
    const block = nginxRegexBlocks(code).find((b) => b.exts.includes('map'));
    expect(block.body).not.toMatch(/add_header/);
  });

  // ---- 反向前提：三种真实回退形态都必须被本闸抓到 ----
  test('反向前提①：删掉拦截块 → 判据必须转红', () => {
    const broken = code.replace(/location\s+~\*\s+\\\.\(map\|ts\)\$\s*\{[\s\S]*?\}/, '');
    expect(broken).not.toBe(code);
    expect(
      nginxRegexBlocks(broken).find((b) =>
        expressDeniedExts().every((e) => b.exts.includes(e.replace(/^\./, '')))
      )
    ).toBeUndefined();
  });

  test('反向前提②：只挡 .map 漏掉 .ts → 转红', () => {
    const broken = code.replace('location ~* \\.(map|ts)$ {', 'location ~* \\.map$ {');
    expect(broken).not.toBe(code);
    const blocks = nginxRegexBlocks(broken);
    expect(
      blocks.some((b) => expressDeniedExts().every((e) => b.exts.includes(e.replace(/^\./, ''))))
    ).toBe(false);
  });

  test('反向前提③：把 ~* 写成 ~（丢掉大小写不敏感） → 转红', () => {
    const broken = code.replace('location ~* \\.(map|ts)$ {', 'location ~ \\.(map|ts)$ {');
    expect(broken).not.toBe(code);
    const block = nginxRegexBlocks(broken).find((b) => b.exts.includes('map'));
    expect(block.modifier).not.toBe('~*');
  });

  test('注释里出现 .map/.ts 不足以让判据通过（防止哪天有人只加一句注释）', () => {
    const onlyComment =
      'server {\n    # 已拦截 .map/.ts 请求\n    location / { try_files $uri /index.html; }\n}\n';
    expect(stripComments(onlyComment)).not.toMatch(/\.map\|ts/);
    expect(nginxRegexBlocks(stripComments(onlyComment))).toEqual([]);
  });
});
