/**
 * 镜像引用面账（finding #7 的收口：把"钉版"从各文件各说各话变成一份可对账的清单）
 *
 * 【为什么需要这个文件】钉版这件事原本有三份互不相干的记录：
 *   - `Dockerfile` / `docker-compose.yml` / `.github/workflows/ci.yml` 里的真实指令行；
 *   - `scripts/capture-image-digests.sh` 顶部的两个常量（`NODE_TAG` / `MONGO_TAG`）；
 *   - `scripts/verify-image-digests.js` 里的期望表（digest 的取证记录）。
 * 三者只要有一个漂了，另外两个仍然绿灯：`baseImageDigestPinned` 只看 node 与 redis 两处，
 * `capture-image-digests.sh` 只管 node 与 mongo 两个镜像，compose 里 prometheus /
 * alertmanager / grafana 三条引用**从来没有任何闸看过一眼**。2026-10-04 补钉这几条的时候
 * 就撞上了这个形状：改 compose 不会碰任何闸，改表也不会碰任何闸——"钉全了"这个结论
 * 当时只能靠人肉 grep，而人肉 grep 正是这类"全覆盖式表述"最先失实的地方。
 *
 * 本文件把"全仓第三方镜像引用"抽成一份清单，然后按六条判据对账：
 *   ① 扫描面自证：文件清单与指令行**条数**必须精确。解析器退化（正则改错、注释规则变了）
 *      会让下面所有断言空转通过——先证明"确实扫到了这些行"。
 *   ② 形态：每条指向 registry 的引用都必须是 `name:tag@sha256:<64 位小写 hex>`，
 *      不允许裸 tag、夹空白、双 digest、无 tag 的纯 digest。
 *   ③ 双向对账：文件里的每条 `name:tag` 必须在期望表里且 digest 相等；表里每条 ref
 *      必须在至少一个文件里真的出现。两个方向都要——只查前者会让表里陈行"永久通过"，
 *      只查后者会让"表改了、文件没改"绿着上线。
 *   ④ 名号一致：同一个 `name:tag` 在不同文件里必须是同一个 digest（mongo 同时出现在
 *      compose 与 CI 的 service 容器；node 出现在 Dockerfile 三处）。CI 跑的数据库与生产
 *      跑的数据库不是同一批字节时，测试绿了也不代表生产。
 *   ⑤ repo 名号唯一：期望表里 `repo` 必须由 `ref` 唯一决定——official 短名（没有命名空间段）
 *      一律 `library/<名>`，第三方命名空间一律短名本身。判据⑥与 verify 脚本的来源映射都依赖
 *      这一条；写成"两种之一都接受"就放行了"官方镜像登记成裸短名"这种会让第三个来源静默跳过
 *      的写法（2026-10-04 的审计实测这条曾经存活）。
 *   ⑥ 取证列可被证伪：`sources` 里点名的来源必须都在来源表里、且声称用过的来源必须真的能答
 *      （ECR Public 对第三方命名空间给不出路径）；`sites` 里点名的文件必须与扫描面逐条对齐。
 *      这两列是"下一个复核人该找谁、该看哪几处"的现场记录，只判非空等于没判。
 *
 * 【判据自身也要有夹具】③⑤⑥对**当前数据**都只能判"全等"，真实仓库里六行全对，于是任何
 * 削弱比较的改动都不会显形。所以 `reconcile()`、`workflowFileNames()`、`parsePinned()`、
 * `refValueOf()` 都是纯函数并有各自的夹具用例（含 `.yaml` 这种本仓没有实例的后缀）。
 * 变异矩阵见 CHANGELOG 2026-10-04 供应链批 D：21 条 arm 全 CAUGHT，另 1 条是刻意的负对照
 * （把判据⑤退回"二选一"后，"第三方命名空间被加上 library/ 前缀"这条数据缺陷确实抓不到——
 * 那条 arm 用来证明严格版 `toBe` 是唯一能抓它的判据，而不是装饰）。
 *
 * 【例外清单为什么也要自证】`${APP_IMAGE:-fire-safety-app:local}`（compose）与
 * `${{ steps.meta.outputs.image }}@${{ steps.push.outputs.digest }}`（CI 的 SBOM 输入）
 * 都不是外部依赖：前者是本地构建产物，后者是 Actions 表达式。它们**必须**被剔除，
 * 但剔除本身要有条数判据——否则"以后有人新加一条带变量的引用"会和"解析器坏了"长得一模一样。
 *
 * 【为什么不联网核验】digest 的**事实来源**是 registry，核验它的是
 * `node scripts/verify-image-digests.js`（对返回字节自算 sha256 + 要求多个独立来源一致）。
 * 本闸只保证"仓库内部三方对齐"：它判绿不等于 digest 是真的，判红一定说明仓库自相矛盾。
 * 把两者混在一个用例里会得到一个更糟的东西——网络抖动时仓库对账也红了。
 */

'use strict';

const fs = require('fs');
const path = require('path');

const { EXPECTED, SOURCES } = require('../../../scripts/verify-image-digests.js');

const ROOT = path.resolve(__dirname, '../../..');

/**
 * 钉版形态的解析器（不用一条正则硬啃，理由见下面 negative 腿那条用例）。
 * 返回 `{ok:true, nameTag, digest}` 或 `{ok:false, why}`，`why` 会进断言失败信息。
 * 判据按 Docker 引用文法拆成四步：摘要分隔符恰好一个 ⇒ 摘要是 64 位小写十六进制
 * ⇒ 剩下的 `name:tag` 里 tag 必须在**最后一个斜杠之后**（`reg.example.com:5000/x:1.2`
 * 的前一个冒号是端口）⇒ 仓库段字符集合规。
 */
const REPO = /^[A-Za-z0-9][A-Za-z0-9._-]*(?::[0-9]+)?(?:\/[A-Za-z0-9][A-Za-z0-9._-]*)*$/;
const TAG = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

function parsePinned(value) {
  const parts = value.split('@sha256:');
  if (parts.length === 1) return { ok: false, why: '没有 digest（裸 tag）' };
  if (parts.length > 2) return { ok: false, why: '出现多个 @sha256:（双 digest 产物）' };
  const [nameTag, hex] = parts;
  if (!/^[0-9a-f]{64}$/.test(hex)) {
    return { ok: false, why: `/^[0-9a-f]{64}$/ 不通过（长度或大小写），实际值 "${hex}"` };
  }
  const slash = nameTag.lastIndexOf('/');
  const colon = nameTag.lastIndexOf(':');
  if (colon <= slash) return { ok: false, why: '没有可读 tag（纯 digest 或 tag 落在路径段里）' };
  const repo = nameTag.slice(0, colon);
  const tag = nameTag.slice(colon + 1);
  if (!REPO.test(repo)) return { ok: false, why: `仓库段 "${repo}" 不符合引用文法` };
  if (!TAG.test(tag)) return { ok: false, why: `tag "${tag}" 不符合引用文法` };
  return { ok: true, nameTag, digest: hex, repo, tag };
}

/** 变量展开 / Actions 表达式：不是外部依赖，不参与钉版判据 */
const isDynamic = (value) => value.includes('${');

/**
 * 取"指令行的值位置"上的引用：`FROM <值>` 与 `image: <值>`，整行注释返回 null。
 * 与 `capture-image-digests.sh` 的 probe_ref 同一套口径（先看指令词、再看紧跟其后的
 * 第一个字段），所以脚本说"这条已钉"与本闸说"这条已钉"是同一个判断。
 * 注释必须排除：Dockerfile 顶部与 compose 的 redis 段都放着完整的钉版示例文本。
 * 【为什么它是纯函数】真实文件里恰好没有 `# image: …` 这种行，所以"删掉注释排除"
 * 这种回归用真实文件测不出来（变异测试实测存活）。判据必须由夹具喂，不靠仓库内容配合。
 */
function refValueOf(raw) {
  const line = raw.trim();
  if (line === '' || line.startsWith('#')) return null;
  // FROM 指令 Docker 解析器大小写不敏感，YAML 的键**大小写敏感**：`IMAGE:` 是 Actions 的
  // env 键（ci.yml 里真有这一行），把它当 image 指令会把一条正常的工作流报成缺陷。
  if (/^from\s+\S+/i.test(line)) return line.split(/\s+/)[1];
  if (/^image:\s+\S/.test(line)) return line.replace(/^image:\s+/, '').trim();
  return null;
}

/**
 * 「够不着的提及」：行里出现了 `image:` 或 `FROM `，却没被取成引用值，且不是整行注释。
 * 这类写法（序列项 `- image:`、冒号后无空白、值为空的 `image:`）在本闸的判定能力之外——
 * 本闸对它们的态度必须是"红"，不能是"没看见"：否则把引用写成这些形态，就等于把钉版
 * 门禁整条绕开，而输出看起来全绿。`capture-image-digests.sh` 对同一族形态也是停手并报行号。
 * FROM 只认行首：Dockerfile 的指令一律顶行首，而 `- name: Extract notes from CHANGELOG`
 * 这种散文里的 "from" 不是引用（实测误报过一次，判据必须比"看起来更严"更准）。
 */
function unreachableOf(raw) {
  const line = raw.trim();
  if (line === '' || line.startsWith('#')) return null;
  if (refValueOf(raw) !== null) return null;
  // `image:` 作为**独立 token** 出现即可（前面不是单词字符），值在不在指令位上由
  // refValueOf 决定；序列项 `- image:`、折叠标量 `image: >-` 都属于"提到了镜像但取不到值"。
  // `image_tag:` / `imageUrl:` 这类前缀撞车靠这个字符类排除，否则会误报 deploy.yml 的输入名。
  if (/(^|[^A-Za-z0-9_.-])image:/.test(line)) return line;
  if (/^from(\s|$)/i.test(line)) return line;
  return null;
}

/**
 * 扫描面：Dockerfile 与 docker-compose.yml 写死（它们是这两条链路的固定两端），
 * `.github/workflows/` 按目录列举（新增 workflow 也能被扫到，而不是等下次想起来补）。
 * 文件缺失一律抛错：面账闸自己"扫不到东西"必须是红，不能是绿。
 */
/**
 * workflow 目录的文件名筛选（纯函数）。
 * `.yaml` 那一半在本仓库里**没有实例**——没有任何 `.yaml` 文件，所以真实扫描面证不了它没用：
 * 把它抽成纯函数才能用夹具喂 `draft.yaml`，证明"后缀判据没写漏"。否则将来有人把工作流命名
 * 成 `.yaml`，它会既不进扫描面也不报错，而"全仓引用都对账"这句话仍然是假的。
 */
function workflowFileNames(names) {
  return names.filter((f) => f.endsWith('.yml') || f.endsWith('.yaml')).sort();
}

function targetFiles() {
  const wf = workflowFileNames(fs.readdirSync(path.join(ROOT, '.github', 'workflows'))).map((f) =>
    path.posix.join('.github/workflows', f)
  );
  return ['Dockerfile', 'docker-compose.yml', ...wf];
}

function scanFiles() {
  return targetFiles().flatMap((file) => {
    const lines = fs.readFileSync(path.join(ROOT, file), 'utf8').split(/\r?\n/);
    return lines.map((raw, i) => ({ file, line: i + 1, raw }));
  });
}

const scanned = scanFiles();
const all = scanned
  .filter((r) => refValueOf(r.raw) !== null)
  .map((r) => {
    const value = refValueOf(r.raw);
    return { file: r.file, line: r.line, value, dynamic: isDynamic(value) };
  });
const unreachable = scanned
  .filter((r) => unreachableOf(r.raw) !== null)
  .map((r) => `${r.file}:${r.line} ${r.raw.trim()}`);
const registryRefs = all.filter((r) => !r.dynamic);
const dynamicRefs = all.filter((r) => r.dynamic);
/** 解析后的引用清单：解析失败的条目保留原值，让对账用例也能把它报出来（而不是先抛异常） */
const parsedRefs = registryRefs.map((r) => {
  const p = parsePinned(r.value);
  return { ...r, ...p, nameTag: p.nameTag || r.value, digest: p.digest || null };
});

/** `name:tag` → 它在哪些文件里出现（期望表 `sites` 列的对账基准） */
const filesByNameTag = new Map();
for (const r of parsedRefs) {
  if (!filesByNameTag.has(r.nameTag)) filesByNameTag.set(r.nameTag, new Set());
  filesByNameTag.get(r.nameTag).add(r.file);
}

/**
 * 双向对账的纯逻辑：`refs` 是文件里扫出来的 `{nameTag, digest}`，`table` 是期望表
 * `Map<ref, digest>`；返回三类缺陷（表里没有的 / digest 不符的 / 表里的陈行）。
 *
 * 【为什么抽成函数】真实仓库里六条引用与表**完全一致**，所以"digest 不符"这条判据在真实数据
 * 上永远是空数组——把它写成 `table.get(x) !== y` 之后改成 `长度不同才不符`，实测变异存活（M6）：
 * 没有夹具就没有判据。抽出纯函数后同一份逻辑既能对真实数据跑，也能被构造出来的"同长度、
 * 末位不同"的假 digest 打红。
 */
function reconcile(refs, table) {
  const label = (r) => `${r.file}:${r.line} ${r.nameTag}`;
  const orphans = refs.filter((r) => !table.has(r.nameTag)).map(label);
  const mismatched = refs
    .filter((r) => table.has(r.nameTag) && table.get(r.nameTag) !== r.digest)
    .map((r) => `${label(r)} 文件 ${r.digest} ≠ 表 ${table.get(r.nameTag)}`);
  const present = new Set(refs.map((r) => r.nameTag));
  const stale = [...table.keys()].filter((ref) => !present.has(ref));
  return { orphans, mismatched, stale, present };
}

describe('镜像引用面账（真实文件 ↔ 期望表 ↔ 脚本常量三方对齐）', () => {
  test('扫描面自证：文件清单与指令行条数一个都不能漂（解析器退化的地基判据）', () => {
    expect(targetFiles()).toEqual([
      'Dockerfile',
      'docker-compose.yml',
      '.github/workflows/ci.yml',
      '.github/workflows/codeql.yml',
      '.github/workflows/dependency-review.yml',
      '.github/workflows/deploy.yml',
      '.github/workflows/release.yml',
      '.github/workflows/scorecard.yml',
    ]);
    // 11 = Dockerfile 3 处 FROM + compose 6 条 image + ci.yml 2 条 image；其余 workflow 0 条。
    // 新增一个带镜像的 workflow 会同时改这里与下面的 byFile ⇒ 逼着改动的人把新引用登记进表。
    expect(all).toHaveLength(11);
    const byFile = {};
    for (const r of all) byFile[r.file] = (byFile[r.file] || 0) + 1;
    expect(byFile).toEqual({
      Dockerfile: 3,
      'docker-compose.yml': 6,
      '.github/workflows/ci.yml': 2,
    });
    // 例外清单的条数同样是判据：新增一条"带变量的引用"必须显式改这里。
    expect(dynamicRefs.map((r) => r.value)).toEqual([
      '${APP_IMAGE:-fire-safety-app:local}',
      '${{ steps.meta.outputs.image }}@${{ steps.push.outputs.digest }}',
    ]);
    expect(registryRefs).toHaveLength(9);
    // 引用面本身（哪个文件钉的是哪个 name:tag）：digest 由期望表那侧对账，这里只管"谁在哪"。
    expect(parsedRefs.map((r) => r.nameTag).sort()).toEqual([
      'grafana/grafana:11.1.0',
      'mongo:6.0.20',
      'mongo:6.0.20',
      'node:22.14.0-alpine',
      'node:22.14.0-alpine',
      'node:22.14.0-alpine',
      'prom/alertmanager:v0.27.0',
      'prom/prometheus:v2.53.0',
      'redis:7-alpine',
    ]);
    // 自证的反面（注释语料确实没被算进来）由下面那条独立用例判：这里不再写
    // `all.some(r => /<64 位 hex>|<捕获值>|/.test(r.value)) === false` 那种永真断言——
    // 扫描到的 value 全都过了解析器，里面**不可能**出现占位符文本，它红了也说明不了任何事。
    // 真实文件里不能有任何"提到了镜像却没落在可判定位置上"的行（判据本身见夹具那条用例）。
    expect(unreachable).toEqual([]);
  });

  test('否定语料自证：注释里的钉版文本既不算引用也不算"够不着"（注释排除有实物可判）', () => {
    const corpus = scanned.filter(
      (r) => r.raw.trim().startsWith('#') && r.raw.includes('@sha256:')
    );
    const byFile = {};
    for (const r of corpus) byFile[r.file] = (byFile[r.file] || 0) + 1;
    // 语料必须真实存在且条数精确：这条判据的有效性依赖仓库里放着这些"看着就是引用"的文本
    // （Dockerfile 顶部的 `docker pull` 抄写行、compose 的 mongo/redis 段、deploy.yml 的说明）。
    // 哪天有人把它们删光，本用例就退化成空转——所以条数本身也是判据，与扫描面自证同一个道理。
    expect(byFile).toEqual({
      Dockerfile: 3,
      'docker-compose.yml': 2,
      '.github/workflows/deploy.yml': 1,
    });
    expect(corpus.filter((r) => refValueOf(r.raw) !== null)).toEqual([]);
    expect(corpus.filter((r) => unreachableOf(r.raw) !== null)).toEqual([]);
    // compose 的 mongo 段里有一条**写成反引号包裹的 `image: mongo…<捕获值>`**：它取不到值
    // （不在指令位上），所以一旦 `unreachableOf` 的注释排除被删，它立刻进 unreachable 把
    // "全仓没有够不着的写法"打红。这条断言钉的是"仓库里确实存在这种形态"，否则上一条
    // 的 null 判定就没人看着——分类器夹具用例管的是逻辑，这条管的是实物。
    expect(corpus.filter((r) => /`image:/.test(r.raw))).toHaveLength(1);
  });

  test('行分类器 self-check：注释/非指令/指令三类各自归位（判据不靠仓库内容配合）', () => {
    const H = 'a'.repeat(64);
    const cases = [
      ['    image: mongo:6.0.20', 'mongo:6.0.20'],
      ['image: mongo:6.0.20', 'mongo:6.0.20'],
      [`FROM node:22.14.0-alpine@sha256:${H} AS builder`, `node:22.14.0-alpine@sha256:${H}`],
      ['  FROM   node:22.14.0-alpine', 'node:22.14.0-alpine'],
      ['  #   docker pull node:22.14.0-alpine@sha256:' + H, null],
      ['# image: mongo:6.0.20', null],
      ['#FROM node:22.14.0-alpine', null],
      ['    imageUrl: mongo:6.0.20', null],
      ['    IMAGE: mongo:6.0.20', null],
      ['    - image: mongo:6.0.20', null],
      ['    image:mongo:6.0.20', null],
      ['    image:', null],
      ['    from', null],
      ['    run: npm ci', null],
      ['', null],
    ];
    for (const [raw, want] of cases) {
      expect({ raw, got: refValueOf(raw) }).toEqual({ raw, got: want });
    }
    // 反向自证：分类器取不到、但确实提到了镜像的行必须被 unreachableOf 抓到。
    // 三条误报防线各自对应仓库里真实存在的一行——放宽任何一条都会把好工作流报成缺陷：
    // YAML 键大小写敏感（`IMAGE:` 是 env 键）、散文里的 "from"、非 image 指令的前缀撞车。
    for (const raw of [
      '    - image: mongo:6.0.20',
      '    image:mongo:6.0.20',
      '    image:',
      '    from',
    ]) {
      expect(unreachableOf(raw)).toBe(raw.trim());
    }
    for (const raw of [
      '# image: mongo:6.0.20',
      '    imageUrl: mongo:6.0.20',
      '    IMAGE: ${{ steps.meta.outputs.image }}',
      '  - name: Extract release notes from CHANGELOG',
      '    run: npm ci',
      '',
    ]) {
      expect(unreachableOf(raw)).toBeNull();
    }
  });

  test('解析器 self-check：五种"看着像但不是"的形态必须各自被拒（防正向断言空转）', () => {
    // 正向用例只证明"当前的 9 条都过"；如果解析器退化成一律放行，它自己永远发现不了。
    // 六条反例各只违反一项判据：裸 tag / 大写摘要 / 63 位摘要 / 双 digest / 无 tag 纯 digest /
    // 端口当 tag。最后一条是正向边界：带端口的私有 registry 引用必须**能**解析，
    // 否则将来加一台内网 registry 就会把闸改成"绕开它"而不是"修好它"。
    const rejects = [
      ['node:22.14.0-alpine', '裸 tag'],
      [`NODE:22@sha256:${'A'.repeat(64)}`, '大写摘要（且 tag 段大写）'],
      [`node:22@sha256:${'a'.repeat(63)}`, '63 位摘要'],
      [`node:22@sha256:${'a'.repeat(64)}@sha256:${'b'.repeat(64)}`, '双 digest'],
      [`docker.io/library/node@sha256:${'a'.repeat(64)}`, '没有可读 tag'],
      ['node:22@sha256:' + 'a'.repeat(64) + ' ', '尾部空白'],
    ];
    for (const [value, label] of rejects) {
      expect({ value, label, ok: parsePinned(value).ok }).toMatchObject({ ok: false });
      expect(parsePinned(value).why.length).toBeGreaterThan(0);
    }
    const portRef = `reg.example.com:5000/team/app:1.2.3@sha256:${'a'.repeat(64)}`;
    expect(parsePinned(portRef)).toMatchObject({
      ok: true,
      repo: 'reg.example.com:5000/team/app',
      tag: '1.2.3',
    });
  });

  test('每条 registry 引用都是 name:tag@sha256:<64 位小写 hex>，没有裸 tag 与畸形形态', () => {
    // 先证明集合非空：空数组上的"全部合规"与"一条都没扫到"看不出区别。
    expect(registryRefs.length).toBeGreaterThan(0);
    const bad = parsedRefs
      .filter((r) => !r.ok)
      .map((r) => `${r.file}:${r.line} ${r.value} —— ${r.why}`);
    expect(bad).toEqual([]);
  });

  test('双向对账：文件里的每条引用都在期望表里且 digest 相等，表里每条 ref 都真的在用', () => {
    const table = new Map(EXPECTED.map((e) => [e.ref, e.digest]));
    expect(table.size).toBe(EXPECTED.length); // ref 不能重复登记
    const { orphans, mismatched, stale, present } = reconcile(parsedRefs, table);
    expect(orphans).toEqual([]);
    expect(mismatched).toEqual([]);
    // 反向：表里的每一条都必须在某个文件里出现（陈行会让"全部通过"变成一句空话）。
    expect(stale).toEqual([]);
    expect(present.size).toBe(EXPECTED.length);
  });

  test('对账逻辑夹具自证：同长度、末位不同的 digest 必须被判不符（真实数据上这条永远为空）', () => {
    // 上一条用例对真实六行判的是"全等"，所以它对**判据本身**没有约束力：把
    // `table.get(x) !== r.digest` 改成 `String(table.get(x)).length !== r.digest.length`
    // 之类（实测变异 M6 存活）在真实数据上照样全绿。这里用一对"长度相同、只有一位不同"
    // 的 digest 直接判逻辑，让任何削弱值比较的改动立刻显形。
    const A = 'a'.repeat(64);
    const B = `${'a'.repeat(63)}b`;
    expect(B).toHaveLength(A.length);
    expect(B).not.toBe(A);
    const table = new Map([
      ['pinned:1', A],
      ['only-in-table:1', A],
    ]);
    const refs = [
      { file: 'docker-compose.yml', line: 1, nameTag: 'pinned:1', digest: B },
      { file: 'Dockerfile', line: 2, nameTag: 'not-in-table:1', digest: A },
    ];
    const r = reconcile(refs, table);
    expect(r.orphans).toEqual(['Dockerfile:2 not-in-table:1']);
    expect(r.mismatched).toHaveLength(1);
    expect(r.mismatched[0]).toContain('pinned:1');
    expect(r.stale).toEqual(['only-in-table:1']);
    // 三个集合必须是**互相独立**的判据：若实现把"表里陈行"并进 orphans，上面三条断言里
    // 至少一条会红——所以每条都在钉自己的那一半。
    expect(r.present).toEqual(new Set(['pinned:1', 'not-in-table:1']));
    // 正向腿：完全一致时必须三项全空，否则"空数组"这个判据没意义（夹具退化也会全绿）。
    const clean = reconcile(
      [{ file: 'x', line: 3, nameTag: 'pinned:1', digest: A }],
      new Map([['pinned:1', A]])
    );
    expect(clean).toMatchObject({ orphans: [], mismatched: [], stale: [] });
  });

  test('workflow 文件名筛选夹具自证：.yaml 与噪音后缀各自归位（本仓没有 .yaml 实例）', () => {
    // `.yaml` 这种"只有后缀"的名字会被当成 workflow 文件收进扫描面——这是**保守方向**
    // （多扫一个文件而不是漏扫一个），不去收紧它：收紧只会让"新后缀写法"变成静默漏网。
    // 大小写敏感的 `.YML` 同理不收：GitHub 只认 `.yml` 后缀的工作流，收进来只会让面账噪音化。
    expect(
      workflowFileNames([
        'ci.yml',
        'draft.yaml',
        'README.md',
        'yml',
        'ci.yml.bak',
        '.yaml',
        'x.YML',
      ])
    ).toEqual(['.yaml', 'ci.yml', 'draft.yaml']);
    // 空目录必须得到空数组而不是报错——真正的"扫不到东西"由 targetFiles() 读不存在的目录抛错兜。
    expect(workflowFileNames([])).toEqual([]);
    // 顺序自证：readdirSync 的顺序不保证，扫描面必须与它无关（否则新增 workflow 会让
    // 扫描面自证那条用例随机红）。
    const names = ['b.yml', 'a.yaml', 'c.yml'];
    expect(workflowFileNames(names)).toEqual(workflowFileNames([...names].reverse()));
  });

  test('同一个 name:tag 在不同文件上必须是同一个 digest（CI 与生产的库不能是两批字节）', () => {
    const groups = new Map();
    for (const r of parsedRefs) {
      if (!groups.has(r.nameTag)) groups.set(r.nameTag, new Map());
      groups
        .get(r.nameTag)
        .set(r.digest, [...(groups.get(r.nameTag).get(r.digest) || []), `${r.file}:${r.line}`]);
    }
    const multi = [...groups.entries()].filter(([, digests]) => digests.size > 1);
    expect(
      multi.map(([nameTag, digests]) => `${nameTag} → ${[...digests.keys()].join(' / ')}`)
    ).toEqual([]);
    // 名号一致这条判据本身也要有覆盖：mongo（compose + CI）与 node（Dockerfile 三处）
    // 都必须是"同一 digest 出现多次"，否则上面那条断言是在空转。
    const repeats = [...groups.entries()].filter(
      ([, digests]) => [...digests.values()].flat().length > 1
    );
    expect(repeats.map(([nameTag]) => nameTag).sort()).toEqual([
      'mongo:6.0.20',
      'node:22.14.0-alpine',
    ]);
  });

  test('期望表自身站得住：ref/repo/tag 互洽，digest 与取证字段形状合规', () => {
    expect(EXPECTED.length).toBe(6);
    for (const e of EXPECTED) {
      expect(e.digest).toMatch(/^[0-9a-f]{64}$/);
      expect(e.captured).toMatch(/^\d{4}-\d{2}-\d{2}$/);
      expect(parsePinned(`${e.ref}@sha256:${e.digest}`).ok).toBe(true);
      const shortName = e.ref.slice(0, e.ref.lastIndexOf(':'));
      // 仓库路径由 `ref` **唯一决定**：Docker Hub 的 official 镜像（短名里没有命名空间段）在
      // API 路径里必须写成 `library/<名>`，第三方命名空间就是短名本身。旧写法判的是
      // "短名 或 library/短名 二者之一"，于是把官方镜像登记成裸短名照样绿——而 `SOURCES` 里
      // ECR Public 的 map() 正是靠 `library/` 前缀判断"官方库才托管"，第三个来源会静默变成
      // "跳过"，输出念一句 `一致来源 2/2` 就把"三源一致"的取证口径退化成两源
      // （这条踩坑在 verify 脚本文件头记着，当时的闸却放行了它：变异 M9 实测存活）。
      const official = !shortName.includes('/');
      expect(e.repo).toBe(official ? `library/${shortName}` : shortName);
    }
  });

  test('取证列可被证伪：sources 说的来源真能答，sites 说的文件与扫描面逐条对齐', () => {
    // `sources` / `sites` 是"下一个想复核的人该找谁、该看哪几处"的现场记录。旧写法只判
    // 它们非空（变异 M7 存活：把任一条改成一句假话仍然全绿），所以这里给它们**可证伪**的判据。
    const names = SOURCES.map((s) => s.name);
    const ecr = SOURCES.find((s) => s.name === 'public.ecr.aws');
    expect(ecr).toBeTruthy();
    const KNOWN = ['Dockerfile', 'docker-compose.yml', '.github/workflows/ci.yml'];
    for (const e of EXPECTED) {
      // ① 来源名只能来自来源表：散文里出现一个表里没有的域名，等于给复核者指了一条不存在的腿
      //    （`grep` 不到的来源就是没核验过的来源）。判据是"散文里所有像主机名的 token 恰好
      //    等于被登记的来源名集合"，所以编造来源与拼错来源都会被抓住。
      const mentioned = names.filter((n) => e.sources.includes(n));
      const hostLike = e.sources.match(/[a-z][a-z0-9.-]*\.[a-z]{2,}/g) || [];
      expect({ ref: e.ref, got: hostLike.sort() }).toEqual({
        ref: e.ref,
        got: [...mentioned].sort(),
      });
      // ② 独立来源下限两条腿：不足两条就写不出"多个独立来源一致"（脚本默认 --min-sources 2）。
      expect(mentioned.length).toBeGreaterThanOrEqual(2);
      // ③ 声称用了 ECR Public ⇒ 表里的 repo 必须让 ECR 的 map() 给得出路径。
      //    反向不要求（official 镜像也可以选择不去 ECR 取证）。
      if (e.sources.includes('public.ecr.aws')) {
        expect({ ref: e.ref, mapped: ecr.map(e.repo) }).toEqual({
          ref: e.ref,
          mapped: `docker/${e.repo}`,
        });
      }
      // ④ sites 必须与扫描面逐文件对上：说了某个文件而那个文件里没有这条引用是假证词，
      //    漏说某个真实存在的文件则意味着"表改了、文件没改"这一族还没被登记。
      const files = [...filesByNameTag.get(e.ref)];
      expect(files.length).toBeGreaterThan(0);
      for (const f of files) expect(e.sites.includes(f)).toBe(true);
      for (const f of KNOWN) {
        if (!files.includes(f)) expect(e.sites.includes(f)).toBe(false);
      }
    }
    // ⑤ 表与扫描面的引用点总数也要对上：9 个引用点 = node 三处 FROM + mongo 两处（compose
    //    与 CI service）+ 其余四条各一处。漏登记任何一处重复，这条就会与②③同时显形。
    const occurrences = EXPECTED.map(
      (e) => parsedRefs.filter((r) => r.nameTag === e.ref).length
    ).sort();
    expect(occurrences).toEqual([1, 1, 1, 1, 2, 3]);
  });

  test('capture-image-digests.sh 的常量与期望表同源（脚本改得了的每一条都在表里）', () => {
    // 常量与表分叉的后果是"脚本按旧 tag 去刷新，把已钉的行改成一条表里不存在的引用"，
    // 而这条只有跑一次 --apply 才暴露；本用例把它提前到静态对账。
    const src = fs.readFileSync(path.join(ROOT, 'scripts', 'capture-image-digests.sh'), 'utf8');
    const consts = [...src.matchAll(/^(NODE_TAG|MONGO_TAG)="([^"]+)"/gm)].map((m) => m[2]);
    expect(consts).toEqual(['node:22.14.0-alpine', 'mongo:6.0.20']);
    for (const c of consts) {
      expect(EXPECTED.some((e) => e.ref === c)).toBe(true);
    }
    // 脚本只认这两个镜像 ⇒ 表里其余四条必须由**本闸或 verify 脚本**盯着，
    // 否则"全仓钉版"这句话就还是假象。这里把"谁负责哪几条"写成断言而不是散文。
    const scripted = new Set(consts);
    const outside = EXPECTED.map((e) => e.ref).filter((r) => !scripted.has(r));
    expect(outside.sort()).toEqual([
      'grafana/grafana:11.1.0',
      'prom/alertmanager:v0.27.0',
      'prom/prometheus:v2.53.0',
      'redis:7-alpine',
    ]);
  });

  test('baseImageDigestPinned 里的 node 字面量与本表一致（两道闸不能各钉一份事实）', () => {
    const gate = fs.readFileSync(
      path.join(ROOT, 'src', 'tests', 'security', 'baseImageDigestPinned.test.js'),
      'utf8'
    );
    const m = gate.match(/const PINNED_NODE_DIGEST = '([0-9a-f]{64})'/);
    expect(m).toBeTruthy();
    const node = EXPECTED.find((e) => e.ref === 'node:22.14.0-alpine');
    expect(node).toBeTruthy();
    expect(m[1]).toBe(node.digest);
    // redis 在那道闸里是按形态判的（只要求带 @sha256），这里补上值对账：
    // 它同样是"外部落的事实"，两处字面量分叉就等于两处都能绿。
    const redis = EXPECTED.find((e) => e.ref === 'redis:7-alpine');
    const composeRedis = parsedRefs.find((r) => r.nameTag === 'redis:7-alpine');
    expect(composeRedis.digest).toBe(redis.digest);
  });
});
