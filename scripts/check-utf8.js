// 扫描仓库源码中非 UTF-8 文件（CI 门禁：`npm run check:utf8`，步骤名 "Check source encoding"）
//
// 退出码：0 = 全部是合法 UTF-8；1 = 发现非 UTF-8 文件，**或扫描集为空/缩水**
// （根目录缺位、根目录存在但没有贡献任何文件，同样判 1，见下面 missingRoots/emptyRoots）。
// 「扫了 0 个文件」不能算通过，见下面 files.length === 0 那段。
//
// 扫描范围此前只有 web-admin：而本文件自己的注释举的反例（scripts/deploy.js 里
// 有一处 GBK↔UTF-8 互错解码留下的字符）恰好不在 web-admin 里 —— 门禁的动机案例
// 落在门禁的盲区里，说明范围定错了。后端源码/脚本/迁移/部署配置同样是中文注释的
// 重灾区，一个 mojibake 字符进仓库后只能靠人眼发现，且会一路传到日志与文档。
// （反面教训：这条注释最初直接抄写了那个错字符本身，于是本工具立刻把**自己**
// 判成 MOJIBAKE_FILES —— 描述一个编码缺陷时不要把它的内容复制进源码。）
const fs = require('fs');
const path = require('path');

const REPO = path.join(__dirname, '..');

const roots = [
  path.join(REPO, 'web-admin'),
  path.join(REPO, 'src'),
  path.join(REPO, 'scripts'),
  path.join(REPO, 'migrations'),
  path.join(REPO, 'e2e'),
  path.join(REPO, 'deployment'),
  // `deliverables/` 于 2026-09-28 从版本库移除（内部留档目录，见 CONTRIBUTING.md §9），
  // 因此不再作为扫描根：本脚本对「根缺位」判红的纪律（见文件头）意味着——留着这一条
  // 会让**任何新克隆**的 `npm run check:utf8` 直接失败。覆盖面一致性判据
  // （gateSelfTest.test.js「format:check 管的每一条都必须在编码门禁的扫描集里」）
  // 是包含关系，两处同时移除后仍然成立。
  path.join(REPO, '.github'),
  // `npm run format:check` 的参数表里第一个目录就是 docs，而这份扫描根没有它：
  // 同一批文件被格式门禁管着、却不被编码门禁管着。ADR/架构文档里进一个错编码字符，
  // 只有人眼能发现——而本文件开头举的动机案例（scripts/deploy.js 那一处互错解码）
  // 正是「门禁的动机落在门禁的盲区里」这一族。两个门禁的覆盖面必须一致，
  // 判据与用例：`src/tests/security/gateSelfTest.test.js` 的覆盖面一致性那条。
  path.join(REPO, 'docs'),
];

// 仓库根的一级文件：此前 roots 全是目录，这些文件一个都不扫（CHANGELOG.md、
// docker-compose.yml、package.json、eslint.config.js……而 format:check 恰好管其中六条）。
// 清单取自 `git ls-files -- . | grep -v /`（2026-09-26 实测 25 条），与目录共用下面同一套
// 「缺位即红」判据：改名或删掉一条会当场红，不会静默缩小扫描面。
//
// 刻意不写成「扫仓库根目录下所有文件」：那会把 .env、本机日志、未提交的大二进制一起拖进
// 门禁。写本批探针时就在错误的目录层级上撞到一个 4 GB 文件，readFileSync 直接抛
// ERR_FS_FILE_TOO_LARGE —— 无界枚举的失败形态就是这个，不是假想。
const rootFiles = [
  '.dockerignore',
  '.editorconfig',
  '.env.example',
  '.gitattributes',
  '.gitignore',
  '.gitleaksignore',
  '.prettierignore',
  '.prettierrc',
  'CHANGELOG.md',
  'CONTRIBUTING.md',
  'Dockerfile',
  'LICENSE',
  'README.md',
  'SECURITY.md',
  'dev-backend.cmd',
  'dev-vite.cmd',
  'docker-compose.yml',
  'eslint.config.js',
  'eslint.ratchet.json',
  'jest.config.js',
  'migrate-mongo-config.js',
  'package-lock.json',
  'package.json',
  'playwright.config.js',
  'start.bat',
].map((name) => path.join(REPO, name));
const skip = new Set(['node_modules', 'dist', '.git', 'coverage']);

// 常见二进制扩展名：内容本就不是文本，UTF-8 校验必然误报，直接跳过
const binaryExts = new Set([
  '.png',
  '.jpg',
  '.jpeg',
  '.gif',
  '.ico',
  '.webp',
  '.bmp',
  '.woff',
  '.woff2',
  '.ttf',
  '.eot',
  '.otf',
  '.pdf',
  '.zip',
  '.gz',
  '.bz2',
  '.xz',
  '.7z',
  '.rar',
  '.mp3',
  '.mp4',
  '.webm',
  '.avi',
  '.mov',
  '.wav',
]);

function walk(dir, out) {
  for (const name of fs.readdirSync(dir)) {
    if (skip.has(name)) continue;
    const full = path.join(dir, name);
    const st = fs.statSync(full);
    if (st.isDirectory()) walk(full, out);
    else out.push(full);
  }
}

// 乱码特征：合法 UTF-8 **但内容已被某个环节错编码**的痕迹。
// UTF-8 解码判不出来（它们本身就是有效字节序列），只靠 fatal:true 会全绿放过。
// 2026-09-19 全仓实测（658 个文本文件）命中 1 处并已修：scripts/deploy.js 的「一处 GBK↔UTF-8 互错解码留下的字符」→「拦下」。
// 这些模式都是无歧义的 corruption 指纹（不是正常用字），所以不必留豁免清单。
const MOJIBAKE_PATTERNS = [
  ['U+FFFD 替换字符（解码失败的残留）', /\uFFFD/],
  ['GBK/UTF-8 互错解码的经典串', /锟|斤拷|烫烫|屯屯/],
  ['latin1 双重编码（Ã/â€/ï¼ 等）', /Ã©|Ã¨|Ã¤|Ã¶|â€|ï¼|ã€/],
  ['罕见误读字', /抦|鎏|馊|鹆/],
];

/**
 * 收集扫描集，并顺手兑现两条恒真式要求。
 * 返回文件清单；扫描面本身不可信时返回 null（此刻失败原因已经打到 stderr）。
 */
function collectScanSet() {
  const files = [];
  // 扫描集「缩水」与扫描集「为空」是同一个洞的两端。原实现对不存在的 root 只往
  // stderr 打一行 [跳过] 就 continue，退出码仍是 0 —— 于是把根目录改名/移走，
  // 门禁照样打印 ALL_FILES_ARE_UTF8（扫描 12 个文件），看起来像验过了。
  // 判据不用"总数必须 ≥ N"这种会腐烂的魔法数字，而是两条恒真式要求：
  //   1) 每个扫描根必须存在：清单与仓库结构脱节时要让人当场知道，
  //      要么补回目录/文件，要么显式改这份清单（改清单是一次看得见的决定）；
  //   2) 每个扫描根目录必须至少贡献一个文件：存在但被搬空（或只剩 node_modules/dist 这类
  //      skip 目录）的目录同样在静默缩小扫描面，existsSync 判不出来。
  // 目录与单个文件走**同一条**判据（两份实现就是将来漏改一份的那个族）；
  // 单文件天然贡献自己这一条，所以 emptyRoots 对它不成立——存在性那条照样成立。
  const missingRoots = [];
  const emptyRoots = [];
  for (const r of [...roots, ...rootFiles]) {
    if (!fs.existsSync(r)) {
      missingRoots.push(r);
      continue;
    }
    const before = files.length;
    if (fs.statSync(r).isDirectory()) walk(r, files);
    else files.push(r);
    if (files.length === before) emptyRoots.push(r);
  }

  if (missingRoots.length > 0 || emptyRoots.length > 0) {
    if (missingRoots.length > 0) {
      console.error('UTF8_CHECK_ROOTS_MISSING：' + missingRoots.join(', '));
    }
    if (emptyRoots.length > 0) console.error('UTF8_CHECK_ROOTS_EMPTY：' + emptyRoots.join(', '));
    console.error('扫描根（目录/根文件）缺位或为空＝扫描面在静默缩水，不能判为通过');
    return null;
  }

  // 空扫描集**不是**通过：扫描根被改名/移走时上面的循环只留一条 [跳过] 警告，
  // 而 bad 仍是空 ⇒ 旧写法会打印 ALL_FILES_ARE_UTF8 并 exit 0——
  // 门禁红了没有意义，但"扫了 0 个文件还报绿"更糟（它看起来像验过了）。
  // 保留作聚合兜底：上面两条是逐项判据，而"整份清单被改成空数组"两者都不触发。
  if (files.length === 0) {
    console.error(
      'EMPTY_SCAN_SET：' +
        [...roots, ...rootFiles].join(', ') +
        '（没有任何文件被检查，不能判为通过）'
    );
    return null;
  }

  return files;
}

/** 逐文件解码，返回两类问题：非 UTF-8 字节 / 编码合法但内容是错编码残留 */
function findEncodingProblems(files) {
  const bad = [];
  const garbled = [];
  for (const f of files) {
    if (binaryExts.has(path.extname(f).toLowerCase())) continue;
    // 本文件自外：MOJIBAKE_PATTERNS 就是由"它要检出的那些字符"组成的，
    // 不排除的话把 scripts/ 纳入扫描会让门禁恒红，而原因并不是仓库里有乱码。
    // 这是唯一一处例外，性质是"自指"，不是给某个目录开的豁免口。
    if (path.resolve(f) === __filename) continue;
    const buf = fs.readFileSync(f);
    let text;
    try {
      text = new TextDecoder('utf-8', { fatal: true }).decode(buf);
    } catch {
      bad.push(f);
      continue;
    }
    const hit = MOJIBAKE_PATTERNS.find(([, re]) => re.test(text));
    if (hit) garbled.push(`${f} ← ${hit[0]}`);
  }
  return { bad, garbled };
}

function main() {
  // 扫描集本身不可信时不进逐文件检查：那时"没发现问题"只意味着"没看"
  const files = collectScanSet();
  if (!files) process.exit(1);

  const { bad, garbled } = findEncodingProblems(files);

  if (bad.length === 0 && garbled.length === 0) {
    console.log(`ALL_FILES_ARE_UTF8（扫描 ${files.length} 个文件，含乱码指纹检查）`);
    process.exit(0);
  }
  if (bad.length > 0) {
    console.log('NON_UTF8_FILES:');
    for (const f of bad) console.log(f);
  }
  if (garbled.length > 0) {
    console.log('MOJIBAKE_FILES（编码合法但内容是错编码残留）:');
    for (const g of garbled) console.log(g);
  }
  process.exit(1);
}

// 交出扫描集本身，而不是让消费方再抄一份清单。
// 这条不是"顺手加的导出"：`src/tests/security/gateSelfTest.test.js` 的夹具此前**硬写了
// 8 个根目录名**，脚本加一条根就得同时记得改测试——那是与本仓"五份到期口径"同族的
// 第二份真源。本批把 docs/ 与 25 条根文件加进来时，正是那份硬写清单会静默失效的形状
// （测试仍按旧夹具生成 ⇒ 对照用例红，或者更糟：新根从来没被自证扫到过）。
// 被 require 时只声明、不跑门禁、不 process.exit（否则 jest 进程会被门禁的 exit 0 打死）。
module.exports = { roots, rootFiles };

if (require.main === module) main();
