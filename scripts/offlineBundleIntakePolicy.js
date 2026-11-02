/**
 * 离线包落位判据（scripts/offlineBundleIntake.js 的纯逻辑层）
 *
 * 分层理由与 offlineBundlePolicy.js / hotUpgradePolicy.js 相同：这里每一条判据都要能在
 * 毫秒级被直接断言（这个归档该不该被解开、条目名安不安全、传输到底完没完），而「执行」
 *（调系统 tar、rename 落位）只能靠临时目录与子进程观测。
 *
 * 本模块只做一件事的判据：**把单个 .tar.gz 变成 bundles 下的一个包目录**。它与
 * offlineBundlePolicy 的分工是「搬运形态 vs 包内容」——归档里装的是什么、payload 与
 * manifest 是否对得上，仍由后者与 scripts/importOfflineBundle.js 判（落位时以
 * `importOfflineBundle.js --dry-run` 复用同一套判据，不重复实现）。
 *
 * 为什么可以做「解包」这件事（ADR-019 §9 原写「刻意不自做解包」）：
 *   原决策防的是**自写 tar 解析器**（在 JS 里手撸 512 字节头、PAX 扩展头、GNU longname
 *   ——那才是新开的路径穿越面）。本模块的做法是**调系统 tar 且只解点名的条目**：
 *   ① `tar -tzf` 先列条目并逐条过 assertSafeRelativePath（与包内路径同一条判据）；
 *   ② 解包分步进行，每一步只给一个显式条目名（`--` 之后），从不「整包全解再检查」；
 *   ③ 解包后对每个落点 lstat 复核「普通文件 + 非符号链接」（不解析 `tar -tv` 文本——
 *      那是在解析一个会随 locale/实现变化的输出格式）；
 *   ④ `--no-same-owner --no-same-permissions` 剥掉归档里的 uid/gid 与 setuid 位。
 *   路径穿越面因此不是「被检查掉了」，而是**根本不存在**：没有任何一步会跟随归档里
 *   声明的目录结构去创建子目录。
 *
 * 本模块零副作用：不读 process.env、不碰文件系统、不打印、不退出。
 *
 * 每一条判据对应的失败形态（都是「落位报成功、装进去的是别的东西」）：
 *   · 只解自己点名的条目 ⇒ 归档里藏着 `../../etc/cron.d/x` 也无处可落；
 *   · 条目数封顶 ⇒ 一个声明 10 万条目的 tar 不能把落位变成一次磁盘耗尽；
 *   · 静默期 + 双读数 ⇒ scp 传到一半就被当成完整包解包（解出一个截断的 tar.gz 会
 *     以解包错误收场，而不是「文件还没传完」）；
 *   · 外层签名覆盖归档摘要 ⇒ 归档被整体替换（含其中 manifest 与 payload）可被检测。
 */

'use strict';

const path = require('path');

/** 落位只接受这一种归档形态；判据只认它，别的一律拒绝（不做「尽力而为」的解包） */
const ARCHIVE_SUFFIX = '.tar.gz';

/** 外层签名文件后缀（与归档同名 + 此后缀） */
const ARCHIVE_SIG_SUFFIX = '.tar.gz.sig';

/**
 * 归档条目数上限。
 *
 * 存在的理由同 payload 上限：正常包只有 manifest.json / manifest.sig / SHA256SUMS /
 * 一个 payload，加起来个位数。声明式条目数（`tar -tzf` 只读头，不解压）没有上限时，
 * 一个畸形归档可以把「列条目」这一步变成一次超长输出读——现场表现是「落位卡住」。
 */
const MAX_ENTRIES = 32;

/** 单个归档体积上限（默认 8 GiB，与 offlineBundlePolicy.DEFAULT_MAX_PAYLOAD_BYTES 同量级） */
const DEFAULT_MAX_ARCHIVE_BYTES = 8 * 1024 * 1024 * 1024;

/** 传输静默期：mtime 距今不足该秒数一律视为「可能还在写」 */
const DEFAULT_SETTLE_SECONDS = 60;

/** sha256 十六进制（小写）——与 offlineBundlePolicy 的 digest 同口径 */
const SHA256_HEX_RE = /^[0-9a-f]{64}$/;

/** 包内必须存在的四个条目（与目录形态一致）；payload 名由 manifest 声明，不写死 */
const REQUIRED_ENTRIES = ['manifest.json', 'manifest.sig', 'SHA256SUMS'];

/**
 * 把 `tar -tzf` 的输出切成条目名数组。
 *
 * **保留目录条目的形态**（末尾 `/` 留着）：解包时必须区分文件与目录（见 fileEntriesOnly
 * 的注释），而安全判据与条目数统计对两者一视同仁。
 *
 * 三件事必须在这里做完，不能留给下游：
 *   · 剥掉行尾 `\r`（Windows 上生成的归档可能带）；
 *   · **跳过空行**——`tar` 输出末尾有一个换行，split 会多出一个空串；把它当条目会让
 *     下游拼出包根路径；
 *   · 含 ` -> ` 的行一律拒绝：`tar` 对硬链接/符号链接以 `name link -> target` 形式打印，
 *     而落位只该有普通文件——链接指向的可以是包外任意位置。
 *
 * @param {string} listing `tar -tzf` 的 stdout
 * @returns {string[]} 条目名（目录条目保留末尾 `/`）
 */
function parseArchiveListing(listing) {
  if (typeof listing !== 'string') {
    throw new Error('归档条目列表不是字符串：无法判定这个归档里有什么');
  }
  const entries = [];
  for (const line of listing.split('\n')) {
    const raw = line.replace(/\r$/, '');
    if (raw.trim() === '') continue; // 末尾换行与空白行不是条目
    if (raw.includes(' -> ')) {
      throw new Error(
        `归档里包含链接条目（${raw}）：落位只接受普通文件——链接指向的可以是包外任意位置`
      );
    }
    entries.push(raw);
  }
  if (entries.length === 0) {
    throw new Error('归档条目列表为空：这个 .tar.gz 里没有任何文件');
  }
  return entries;
}

/** 目录条目：末尾带 `/`（tar 的既有约定） */
const isDirectoryEntry = (entry) => typeof entry === 'string' && entry.endsWith('/');

/** 去掉目录标记，得到用于路径判据的规范名（`payload/` → `payload`） */
function normalizeEntry(entry) {
  const text = String(entry ?? '');
  return isDirectoryEntry(text) ? text.replace(/\/+$/, '') : text;
}

/**
 * 从条目列表里挑出**要解的文件条目**，丢弃目录条目。
 *
 * 为什么必须区分（实测，GNU tar 1.35）：`tar -czf x.tar.gz -C dir payload` 会同时产出
 * `payload/`（目录）与 `payload/fsms-app.tar`（文件）两条。把两者一起交给
 * `-xzf ... -- payload payload/fsms-app.tar` 会以
 * `tar: payload/fsms-app.tar: Not found in archive` 失败——同一路径既声明为目录又声明为
 * 成员时解析冲突。目录会随文件条目的父路径隐式创建，不需要显式解。
 *
 * 目录条目仍参与安全判据与条目数统计（它们也是归档的一部分）。
 */
function fileEntriesOnly(entries) {
  if (!Array.isArray(entries)) throw new Error('条目列表不是数组：无法判定要解什么');
  return entries.filter((entry) => !isDirectoryEntry(entry)).map(normalizeEntry);
}

/** 解析命令行（与其它脚本同口径：未知参数报错而不是忽略） */

/**
 * 条目数封顶。报错里带上限，便于运维判断该调上限还是分包。
 */
function assertEntryCountWithinCap(entries, cap = MAX_ENTRIES) {
  if (!Array.isArray(entries)) {
    throw new Error('归档条目不是数组：无法判定这个归档里有什么');
  }
  if (entries.length > cap) {
    throw new Error(
      `归档条目数超过上限：${entries.length} > ${cap}\n` +
        '  正常离线包只有 manifest.json / manifest.sig / SHA256SUMS / 一个 payload。' +
        '条目数超限通常意味着这不是本链路的包。'
    );
  }
  return true;
}

/**
 * 归档体积上限（读取前判，把畸形声明挡在算摘要之前）。
 */
function assertArchiveSizeWithinCap(bytes, cap = DEFAULT_MAX_ARCHIVE_BYTES) {
  if (!Number.isInteger(bytes) || bytes <= 0) {
    throw new Error(`归档字节数不是正整数，收到：${JSON.stringify(bytes)}`);
  }
  if (bytes > cap) {
    throw new Error(
      `归档超过体积上限：${bytes} > ${cap} 字节\n` +
        '  确需更大的包请显式调上限；上限用于把「畸形归档」挡在算摘要与解包之前。'
    );
  }
  return true;
}

/**
 * 归档必须包含的条目都在（名字逐字相等，不做大小写/前缀匹配）。
 * payload 条目不在 REQUIRED_ENTRIES 里——它的名字由 manifest 声明，parseBundleManifest 后才知道。
 *
 * 比对前先归一（`manifest.json/` 这类带目录标记的形态也能命中）：要求条目必须在，
 * 但「它被标成目录」不该让判据误报缺失——那是另一个问题（解包时会被 fileEntriesOnly 过滤）。
 */
function assertRequiredEntriesPresent(entries, required = REQUIRED_ENTRIES) {
  const set = new Set(entries.map(normalizeEntry));
  const missing = required.filter((name) => !set.has(name));
  if (missing.length > 0) {
    throw new Error(
      `归档缺少必需条目：${missing.join(' / ')}\n` +
        '  这四个条目是导入器判据的全部输入；缺任何一个都不该继续解包。'
    );
  }
  return true;
}

/**
 * 把摘要 hex 变成签名载荷。
 *
 * 为什么签「摘要的文本」而不是「归档字节」：Ed25519 是 one-shot 签名（`crypto.sign(null, buf)`
 * 要求完整 Buffer 在内存），8 GiB 归档整包签名必 OOM——而 OOM 在现场的表现是「构建进程被杀」，
 * 不是「包太大」。签 64 字节摘要 + 搬运两端各自流式算摘要，等价地覆盖了整包：
 *   `签名 → 摘要文本 → 归档字节`。
 *
 * 用 hex 文本而不是原始 32 字节：与 `sha256sum` 的输出口径一致，运维能手抄核对。
 */
function digestPayloadOf(digestHex) {
  if (typeof digestHex !== 'string' || !SHA256_HEX_RE.test(digestHex.trim().toLowerCase())) {
    throw new Error(
      `归档摘要形态非法（需要 64 位小写十六进制）：${JSON.stringify(digestHex)}\n` +
        '  摘要不是为了「好看」——它是外层签名唯一覆盖的对象。'
    );
  }
  return Buffer.from(digestHex.trim().toLowerCase(), 'utf8');
}

/**
 * 传输是否已经结束（静默期 + 双读数）。
 *
 * 为什么不是「运维先写 .part 再改名」：scp 的最自然用法就是直写目标名，
 * 不能要求运维为了配合判据改变肌肉记忆。故用**时间**（mtime 距今 ≥ settleSec）
 * 与**稳定性**（两次读数 size 一致）双条件——前者挡「正在被写」，后者挡
 * 「已暂停但尚未续传」（scp 中断后 resume 的场景）。
 *
 * 纯函数：调用方负责取两次读数（中间自行 sleep），这里只判。
 *
 * @param {{ sizeA: number, sizeB: number, mtimeMs: number, now: number, settleSec: number }} input
 * @returns {{ settled: boolean, reason: string }} reason 供心跳与留痕展示
 */
function isSettled({ sizeA, sizeB, mtimeMs, now, settleSec }) {
  if (!Number.isInteger(sizeA) || !Number.isInteger(sizeB)) {
    return { settled: false, reason: '文件尺寸读不出来（可能已被移走）' };
  }
  if (sizeA <= 0) {
    return { settled: false, reason: '文件为 0 字节（传输尚未开始或已失败）' };
  }
  if (sizeA !== sizeB) {
    return { settled: false, reason: '两次读数尺寸不一致（仍在传输中）' };
  }
  if (!Number.isFinite(mtimeMs)) {
    return { settled: false, reason: 'mtime 读不出来' };
  }
  const ageSec = Math.floor((now - mtimeMs) / 1000);
  if (ageSec < settleSec) {
    return {
      settled: false,
      reason: `最后写入距今 ${ageSec}s，不足静默期（${settleSec}s）`,
    };
  }
  return { settled: true, reason: '' };
}

/**
 * 路径与名字的形态收口（纯函数；调用方在**构造任何 argv 之前**用它的返回值）。
 *
 * 两条约束缺一不可：
 *   · 不得为空、不得以 `-` 开头——否则目标程序会把值当选项解释（GNU tar 尤甚：
 *     `-tzf -` 里的 `-` 是 stdin）；这是「命令选项注入」在数据层的唯一防线；
 *   · 给了 allowRoot 时，规范化后的落点必须真的在 allowRoot 之内——`path.join` 不做
 *     边界，`..` 段或绝对路径都能爬出去。
 *
 * 返回**规范化后的值**并要求调用方使用返回值：校验与使用是同一个值，
 * 不存在「校验了一个字符串、用了另一个」的窗口。
 *
 * 只做形态判据，不碰文件系统（path 是纯字符串处理）——故本模块保持零副作用。
 */
function resolveWithinRoot(candidate, allowRoot, what) {
  const text = String(candidate ?? '');
  if (text === '') throw new Error(`${what}为空：拒绝继续`);
  if (text.startsWith('-')) {
    throw new Error(`${what}以 - 开头（会被目标程序当成选项）：${JSON.stringify(text)}`);
  }
  const resolved = path.resolve(text);
  if (!allowRoot) return resolved;
  const root = path.resolve(allowRoot);
  if (resolved !== root && !resolved.startsWith(root + path.sep)) {
    throw new Error(`${what}落在允许的根之外：${resolved}\n  允许的根：${root}`);
  }
  return resolved;
}

/**
 * 落位目录名必须是「一个名字」：不含分隔符/控制字符、不是 `.`/`..`、不以 `-` 开头。
 * 归档名来自 readdir（单个文件名），但它会被拼进 bundles 根，必须在拼之前就确定形状。
 */
function assertPlainDirName(name) {
  const text = String(name ?? '');
  if (text === '' || text === '.' || text === '..') {
    throw new Error(`落位目录名非法：${JSON.stringify(name)}`);
  }
  if (/[\\/\0]/.test(text) || text.startsWith('-')) {
    throw new Error(`落位目录名含分隔符/控制字符或以 - 开头：${JSON.stringify(name)}`);
  }
  return text;
}

/**
 * 从条目列表里挑出**文件条目**（用于解包），丢弃目录条目。
 *
 /** 解析命令行（与其它脚本同口径：未知参数报错而不是忽略） */
const FLAGS = ['inbox', 'bundle-root', 'pubkey-file', 'allowlist', 'apply', 'dry-run', 'help'];

function parseArgs(argv = []) {
  const opts = {
    apply: false,
    dryRun: false,
    help: false,
    inbox: '',
    bundleRoot: '',
    pubkeyFile: '',
    allowlist: '',
  };
  for (let i = 0; i < argv.length; i += 1) {
    const raw = argv[i];
    if (!raw.startsWith('--')) throw new Error(`无法识别的参数：${raw}`);
    const [name, inlineValue] = raw.slice(2).split('=');
    if (!FLAGS.includes(name)) {
      throw new Error(`未知参数：--${name}（可用：${FLAGS.map((f) => `--${f}`).join(', ')}）`);
    }
    const takeValue = () => {
      if (inlineValue !== undefined) return inlineValue;
      const next = argv[i + 1];
      if (next === undefined || next.startsWith('--')) {
        throw new Error(`--${name} 需要一个值`);
      }
      i += 1;
      return next;
    };
    if (name === 'apply') opts.apply = true;
    else if (name === 'dry-run') opts.dryRun = true;
    else if (name === 'help') opts.help = true;
    else if (name === 'inbox') opts.inbox = takeValue();
    else if (name === 'bundle-root') opts.bundleRoot = takeValue();
    else if (name === 'pubkey-file') opts.pubkeyFile = takeValue();
    else if (name === 'allowlist') opts.allowlist = takeValue();
  }
  return opts;
}

module.exports = {
  ARCHIVE_SUFFIX,
  ARCHIVE_SIG_SUFFIX,
  MAX_ENTRIES,
  DEFAULT_MAX_ARCHIVE_BYTES,
  DEFAULT_SETTLE_SECONDS,
  REQUIRED_ENTRIES,
  FLAGS,
  parseArchiveListing,
  isDirectoryEntry,
  normalizeEntry,
  fileEntriesOnly,
  assertEntryCountWithinCap,
  assertArchiveSizeWithinCap,
  assertRequiredEntriesPresent,
  digestPayloadOf,
  resolveWithinRoot,
  assertPlainDirName,
  isSettled,
  parseArgs,
};
