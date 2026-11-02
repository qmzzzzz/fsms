#!/usr/bin/env node
/**
 * 离线包落位（宿主侧）：把 inbox 里的单个 .tar.gz 变成 bundles 下的一个包目录
 *
 * 为什么需要这一层：ADR-019 定的传包形态是**目录**（四个条目），但运维搬运用的是
 * scp/U 盘——多文件多目录最容易漏一个（漏 manifest.sig 的包看起来完全正常，
 * 直到导入时被判 fail-closed 拒绝）。同族系统（a033/LANSEC）传的是单个 tar.gz，
 * 本层把 fsms 的搬运形态对齐到「一个文件」，同时**不放松任何既有判据**。
 *
 * 信任链（三层，逐层收窄）：
 *   ① 外层 `pkg.tar.gz.sig` → 归档 sha256 的 hex 文本（本层新增；签的是 64 字节摘要，
 *      不是 8 GiB 归档本身——Ed25519 one-shot 要求整包在内存，整包签必 OOM）；
 *   ② 归档内 `manifest.sig` → manifest.json 原始字节（ADR-019 既有）；
 *   ③ manifest 内 `images[].sha256` → payload 逐字节（ADR-019 既有）。
 *
 * 落位步骤（顺序不可调换）：
 *   1. 静默期 + 双读数：确认 scp 已经写完（不能要求运维先写 .part 再改名——那是改变
 *      他的肌肉记忆去配合判据）；
 *   2. 外层验签：配了公钥就必须过（fail-closed，与 ADR-019 ② 同口径）；
 *   3. 列条目 → 逐条过 assertSafeRelativePath → 条目数封顶 → 必需条目齐全；
 *   4. 解包到 `bundles/.staging-<uuid>/`，**只解名单里的条目**（从不整包全解）；
 *   5. 落点 lstat 复核（普通文件 + 非符号链接）+ 递归收紧权限；不解析 `tar -tv` 文本；
 *   6. 复用 `importOfflineBundle.js` 的**演练模式**跑全部既有判据（验签/白名单/逐字节
 *      比对），通过才 rename 到最终目录名——**零新增判据**，判据只有一份实现。
 *
 * 命令面的分工：子进程调用收在 scripts/offlineBundleIntakeExec.js（argv 逐项构造，
 * 成员名排到 `--` 之后，file 全部字面量或 process.execPath），本模块只负责取数、
 * 状态机与文件系统动作，不自己拼 argv。
 *
 * 刻意不做的事：
 *   · 不「装完即重启服务」（LANSEC 是 install.sh 一步装完）：落位只让包出现在应用侧
 *     下拉里，升不升仍由唯一超管在应用内点按钮决定（ADR-019 §9 第一条：不做自动升级，
 *     自动升级 + 迁移 = 半夜静默炸库）；
 *   · 不从归档里解出任何**未点名**的条目：路径穿越面不是「被检查掉了」，而是根本不存在
 *     ——没有任何一步会跟随归档声明的目录结构去创建子目录；
 *   · 不做覆盖：最终目录已存在即拒绝（与 build-offline-bundle.sh 的「拒绝覆盖产物」同纪律）。
 *
 * 用法：
 *   node scripts/offlineBundleIntake.js --inbox /var/lib/fsms/upgrade/inbox
 *   node scripts/offlineBundleIntake.js --inbox <dir> --bundle-root <bundles> --pubkey-file <pub> --apply
 */

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ROOT = path.resolve(__dirname, '..');
const policy = require('./offlineBundleIntakePolicy');
const bundlePolicy = require('./offlineBundlePolicy');
const { verifyManifestBytes } = require('./offlineBundleSignature');
const { sha256File } = require('./importOfflineBundle');
const intakeExec = require('./offlineBundleIntakeExec');
const { buildImportBundleInvocation } = require('./deployCommands');

/**
 * 列归档条目（只读头，不解压）。archive 已过 resolveWithinRoot。
 */
function listEntries(archive) {
  const out = intakeExec.listArchiveEntries(archive);
  return policy.parseArchiveListing(out);
}

/**
 * 只解名单里的条目到 staging。成员名已由调用方逐条过 assertSafeRelativePath；
 * 执行层还会在 `--` 之后排布它们（选项终止符之后不再有选项解释）。
 *
 * **分两段解**（这是「只解点名条目」的实现方式，不是可选的优化）：
 *   第一段：只解 `manifest.json` —— 它是"点名"的唯一来源（payload 的**真实名字**
 *           写在 manifest 里，不是由我们猜的）；
 *   第二段：解 manifest 声明的那个 payload + manifest.sig + SHA256SUMS。
 * 因此归档里任何**未被 manifest 点名**的条目（多余文件、探针文件、别的版本的 payload）
 * 都没有落点——"路径穿越面不存在"这句话是靠这个结构成立的，不是靠事后扫描。
 *
 * 目录条目（`payload/`）不参与解包：它们会随文件条目的父路径隐式创建，且与文件条目
 * 混传会让 GNU tar 报 `Not found in archive`（实测，tar 1.35）。
 */
function extractNamedMembers(archive, stagingDir, members) {
  fs.mkdirSync(stagingDir, { recursive: true, mode: DIR_MODE });
  if (members.length === 0) throw new Error('解包成员列表为空：拒绝继续');
  intakeExec.extractArchiveMembers(archive, stagingDir, members);
  const landed = [];
  for (const member of members) {
    // 先与 stagingDir 拼成绝对路径再校验（成员名是包内相对路径，直接交给
    // resolveWithinRoot 会按 cwd 解析——见落位段的同类修正）
    const full = policy.resolveWithinRoot(
      path.join(stagingDir, member),
      stagingDir,
      `条目落点（${member}）`
    );
    let st;
    try {
      st = fs.lstatSync(full);
    } catch (err) {
      throw new Error(`条目未落到磁盘：${member}（${err.message}）`);
    }
    if (st.isSymbolicLink()) {
      throw new Error(`条目落成了符号链接（拒绝继续）：${member}——链接指向的可以是包外任意位置`);
    }
    if (!st.isFile()) {
      throw new Error(`条目不是普通文件：${member}`);
    }
    landed.push({ member, full, size: st.size });
  }
  return landed;
}

/**
 * 外层验签：归档 sha256 的 hex 文本 ↔ .sig。
 * 公钥未配置时放行并明示 unchecked（与 ADR-019 ② 的 fail-open 口径一致：
 * 是否把「未验签」定为拒绝是部署的显式选择，运行时不替没分发过密钥的环境兜底）。
 *
 * **返回结果对象，绝不退出进程**：本函数会被宿主代理在 runOnce 里调用，而代理是长驻
 * 调度单元——一个库函数调 process.exit 会把整个代理连同它的心跳一起带走（那会让应用侧
 * 看到「代理离线」，而真正原因只是某个包没签名）。退出只发生在 main()（CLI 形态）。
 *
 * @returns {{ ok: true, state: 'verified'|'unchecked' } | { ok: false, reason: string }}
 */
function verifyArchiveSignature(archivePath, pubkeyFile) {
  if (!pubkeyFile) return { ok: true, state: 'unchecked' };
  let pem;
  try {
    pem = fs.readFileSync(pubkeyFile, 'utf8');
  } catch (err) {
    return {
      ok: false,
      reason: `验签公钥不可读（--pubkey-file / OFFLINE_BUNDLE_VERIFY_PUBKEY）：${err.code || err.message}`,
    };
  }
  const sigPath = signaturePathOf(archivePath);
  let sigBytes;
  try {
    sigBytes = fs.readFileSync(sigPath);
  } catch (err) {
    if (err.code === 'ENOENT') {
      return {
        ok: false,
        reason:
          `本机已配置验签公钥，但归档旁没有 ${path.basename(sigPath)}（未签名包）：按 fail-closed 拒绝。\n` +
          '  请用 scripts/build-offline-bundle.sh --archive <路径> --sign-key <私钥.pem> 重新构建并搬运。',
      };
    }
    return { ok: false, reason: `外层签名不可读：${err.message}` };
  }
  const digest = sha256File(archivePath);
  // 复用 offlineBundleSignature 的验签：它只要求 Buffer，不关心内容是 manifest 还是摘要文本
  const result = verifyManifestBytes(policy.digestPayloadOf(digest), sigBytes, pem);
  if (!result.ok) {
    return {
      ok: false,
      reason: `归档外层签名验证失败：${result.reason}\n  本次 sha256：${digest}`,
    };
  }
  log(`外层签名验证通过（${path.basename(sigPath)} ↔ ${digest.slice(0, 12)}…）`);
  return { ok: true, state: 'verified' };
}

const log = (msg) => process.stdout.write(`[offline-intake] ${msg}\n`);
const warn = (msg) => process.stderr.write(`[offline-intake] 警告：${msg}\n`);

/**
 * CLI 形态的失败出口（**只允许 main() 与顶层 catch 使用**）。
 *
 * 库函数一律返回结果对象而不是退出进程：本模块的 `intakeOne` 会被宿主代理在 runOnce
 * 里调用，而代理是长驻调度单元——库函数里一个 process.exit 会把整个代理连同心跳一起
 * 带走，应用侧看到的是「代理离线」，真实原因却只是某个包没签名（实测踩中，见 ADR-020）。
 */
const fail = (msg, code = 1) => {
  process.stderr.write(`[offline-intake] 中止：${msg}\n`);
  process.exit(code);
};

/** 落位创建的临时目录名前缀（点开头：scanBundles 跳过点开头条目，不会把它当成一个包） */
const STAGING_PREFIX = '.staging-';

/** manifest 的条目名（「点名」的唯一来源，两段解包都用到） */
const MANIFEST_ENTRY = 'manifest.json';

/** 落位目录/文件的权限：目录 0750、文件 0640（root:root，与 status/processing 同档） */
const DIR_MODE = 0o750;
const FILE_MODE = 0o640;

/**
 * 递归收紧权限位。
 *
 * 为什么不用 tar 的 `--no-same-owner --no-same-permissions`：那两个选项是「请求 tar
 * 别照搬」，而归档里到底带没带 setuid 位、属主是谁，要看**落盘后的实际状态**。
 * 解包后逐条 lstat + chmod 是自证式的：判据作用在我们能观测的对象上。
 * 权限收紧失败必须中止——「权限没收到位」不该被静默接受（同 app-entrypoint 的口径）。
 */
function hardenTree(rootDir) {
  const stack = [rootDir];
  while (stack.length > 0) {
    const dir = stack.pop();
    fs.chmodSync(dir, DIR_MODE);
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      const st = fs.lstatSync(full);
      if (st.isSymbolicLink()) {
        throw new Error(`解包产物里出现符号链接（拒绝继续）：${entry.name}`);
      }
      if (st.isDirectory()) {
        stack.push(full);
      } else if (st.isFile()) {
        fs.chmodSync(full, FILE_MODE);
      } else {
        throw new Error(`解包产物里出现非普通文件（拒绝继续）：${entry.name}`);
      }
    }
  }
}

/** 目录里「可能可以落位」的归档候选（点开头跳过、只认 .tar.gz 后缀） */
function listInboxCandidates(inboxDir) {
  let names;
  try {
    names = fs.readdirSync(inboxDir);
  } catch (err) {
    if (err.code === 'ENOENT') return []; // 未启用落位通道的正常形态
    throw new Error(`inbox 目录不可读：${err.code || 'io'}`);
  }
  return names
    .filter((n) => !n.startsWith('.') && n.endsWith(policy.ARCHIVE_SUFFIX))
    .sort()
    .map((n) => path.join(inboxDir, policy.assertPlainDirName(n)));
}

/**
 * 静默期 + 双读数：确认 scp 已经写完。
 * 两次读之间 wait 一下，让「仍在增长的文件」自证——只判 mtime 时，一个暂停后 resume 的
 * scp 会在静默期里蒙混过关。
 */
function readStability(file, settleSec) {
  let statA;
  try {
    statA = fs.statSync(file);
  } catch {
    return { settled: false, reason: '文件读不出来（可能已被移走）', size: 0 };
  }
  // 静默期没到就不必做第二轮读数（省一次等待，也让 pending 的展示更及时）
  const ageSec = Math.floor((Date.now() - statA.mtimeMs) / 1000);
  if (ageSec < settleSec) {
    return {
      settled: false,
      reason: `最后写入距今 ${ageSec}s，不足静默期（${settleSec}s）`,
      size: statA.size,
    };
  }
  const sizeA = statA.size;
  // 同步等待 1s：本脚本是「一轮一次」的批处理进程（代理侧同理）。
  // 用 Atomics.wait 而不是忙等或 sleep 子进程——它是唯一既不占 CPU 也不起进程的同步等待。
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 1000);
  let statB;
  try {
    statB = fs.statSync(file);
  } catch {
    return { settled: false, reason: '第二轮读数时文件消失', size: sizeA };
  }
  const verdict = policy.isSettled({
    sizeA,
    sizeB: statB.size,
    mtimeMs: statB.mtimeMs,
    now: Date.now(),
    settleSec,
  });
  return { ...verdict, size: statB.size };
}

/** 外层签名的路径：归档名 + .sig（`pkg.tar.gz` → `pkg.tar.gz.sig`） */
const signaturePathOf = (archivePath) => `${archivePath}${'.sig'}`;

/**
 * 从环境读静默期（与 hotUpgradeQueue.loadConfig 的同一变量、同一区间）。
 *
 * CLI 与代理必须同口径：代理按配置的静默期判「传完了没有」，而运维手动跑 CLI 兜底时
 * 若用另一个默认值，会出现「代理说没好、CLI 说好了」这种无法解释的分歧。
 * 区间取 5..3600：小于 5 秒等于不设防（大文件必然被判成还在传），大于 1 小时运维会等死。
 */
function readSettleSecFromEnv(env = process.env) {
  const raw = Number.parseInt(String(env.OFFLINE_BUNDLE_SETTLE_SECONDS ?? ''), 10);
  if (!Number.isInteger(raw) || raw < 5 || raw > 3600) return policy.DEFAULT_SETTLE_SECONDS;
  return raw;
}

/** 留痕：与 importOfflineBundle.js / hotUpgrade.js 同口径，logs/ 下 0600 */
function recordState(state) {
  const dir = path.join(ROOT, 'logs');
  try {
    fs.mkdirSync(dir, { recursive: true });
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    const file = path.join(dir, `offline-intake-${stamp}.json`);
    fs.writeFileSync(file, JSON.stringify(state, null, 2), { encoding: 'utf8', mode: 0o600 });
    log(`状态记录：${file}`);
  } catch (err) {
    warn(`状态记录写入失败（${err.message}）`);
  }
}

function printHelp() {
  process.stdout.write(
    [
      '离线包落位：把 inbox 里的 .tar.gz 解包、校验、落到 bundles。默认只演练。',
      '',
      '  --inbox <dir>              待落位归档所在目录（代理侧 OFFLINE_BUNDLE_INBOX）',
      '  --bundle-root <dir>        落位目标根（代理侧 OFFLINE_BUNDLE_DIR）',
      '  --pubkey-file <file>       Ed25519 验签公钥（PEM）；也可用 OFFLINE_BUNDLE_VERIFY_PUBKEY',
      '  --allowlist <prefixes>     交给既有导入器判据的仓库前缀（逗号分隔；空白名单 = 全拒）',
      '  --apply                    真正落位（缺省为演练）',
      '  --help                     本帮助',
      '',
    ].join('\n')
  );
}

/** 解析参数。用法错误必须在**产生任何副作用之前**以退出码 2 拒绝 */
function parseOrExit(argv) {
  try {
    return policy.parseArgs(argv);
  } catch (err) {
    process.stderr.write(`[offline-intake] 用法错误：${err.message}\n`);
    process.exit(2);
  }
}

/**
 * 跑既有导入器的全部判据（演练模式：校验通过即 0，绝不碰 docker）。
 *
 * 单独成函数的两条理由：① 它是「零新增判据」这条设计约束的落点——判据只有一份实现
 * （在 importOfflineBundle 里），这里只是把它跑起来；② 它的错误文案与别的步骤不同
 * （要带导入器的输出尾巴，那是运维判断「包哪里不对」的唯一线索）。
 */
function verifyWithImporter({ stagingDir, bundlesRoot, allowlist, pubkeyFile }) {
  let invocation;
  try {
    invocation = buildImportBundleInvocation({
      bundleDir: stagingDir,
      bundleRoot: bundlesRoot,
      allowlist: String(allowlist)
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean),
      dryRun: true,
      pubkeyFile,
    });
  } catch (err) {
    return { ok: false, reason: `导入器参数构造失败：${err.message}` };
  }
  try {
    // args[0] 是脚本路径（构造器已钉），其余是它自己的选项
    intakeExec.runImporter(invocation.args);
    return { ok: true };
  } catch (err) {
    const detail = (err.stdout || err.stderr || err.message || '').trim().slice(-800);
    return {
      ok: false,
      reason: `既有导入器判据未通过（未改动本机 docker，staging 已清理）：\n${detail}`,
    };
  }
}

/**
 * 解包并校验到 staging（intakeOne 的第 4~5 步）。
 *
 * 单独成函数是为了让 intakeOne 只留编排骨架（复杂度棘轮：编排函数的圈复杂度会随
 * 步骤数线性上升，而每个步骤内部的判据与错误文案才是要写清的东西）。
 *
 * @returns {{ ok: true, stagingDir, finalDir, landed, manifest } | { ok: false, outcome, reason }}
 */
function extractAndVerify({
  archive,
  bundlesRoot,
  dirName,
  entries,
  allowlist,
  pubkeyFile,
  step,
  cleanup,
}) {
  const finalDir = policy.resolveWithinRoot(
    path.join(bundlesRoot, dirName),
    bundlesRoot,
    '落位目标目录'
  );
  if (fs.existsSync(finalDir)) {
    return {
      ok: false,
      outcome: 'aborted_target_exists',
      reason: `落位目标已存在（拒绝覆盖）：${dirName}——请先人工确认旧包是否还需要保留`,
    };
  }
  // staging 名称：点开头（扫描层跳过它，不会把半成品当成一个包）+ 随机 uuid（并发安全）
  const stagingDir = policy.resolveWithinRoot(
    path.join(bundlesRoot, `${STAGING_PREFIX}${crypto.randomUUID()}`),
    bundlesRoot,
    'staging 目录'
  );

  // 4a. 第一段解包：只解 manifest.json —— 它是「点名」的唯一来源。
  //     在此之前我们不知道 payload 的真实名字（它在 manifest 里声明），
  //     所以这一段必须先做，且只做这一件事。
  step('extract-manifest');
  let manifest;
  try {
    extractNamedMembers(archive, stagingDir, [MANIFEST_ENTRY]);
    const manifestPath = policy.resolveWithinRoot(
      path.join(stagingDir, MANIFEST_ENTRY),
      stagingDir,
      'manifest 落点'
    );
    manifest = bundlePolicy.parseBundleManifest(
      JSON.parse(fs.readFileSync(manifestPath).toString('utf8'))
    );
  } catch (err) {
    cleanup(stagingDir);
    return {
      ok: false,
      outcome: 'aborted_extract_failed',
      reason: `第一段解包（manifest）失败：${err.message}`,
    };
  }

  // 4b. 第二段解包：manifest 声明的 payload + 固定两件（manifest.sig / SHA256SUMS）。
  //     **这两段是「只解点名条目」的实现**：归档里任何没被 manifest 点名的条目
  //     （多余文件、别的版本的 payload、探针）都没有落点。
  const set = new Set(entries.map(policy.normalizeEntry));
  const missingDeclared = manifest.images.map((img) => img.file).filter((f) => !set.has(f));
  if (missingDeclared.length > 0) {
    cleanup(stagingDir);
    return {
      ok: false,
      outcome: 'aborted_archive_invalid',
      reason:
        `manifest 声明的 payload 不在归档里：${missingDeclared.join(' / ')}\n` +
        '  归档与 manifest 不是同一批产物（缺文件或指向了别处）。',
    };
  }
  const namedMembers = [
    MANIFEST_ENTRY,
    ...manifest.images.map((img) => img.file),
    ...policy.REQUIRED_ENTRIES.filter((n) => n !== MANIFEST_ENTRY),
  ];
  const fileMembers = [...new Set(namedMembers)];
  step('extract-to-staging', `${fileMembers.length} 个点名条目`);
  let landed;
  try {
    // 第二段会重新解一次 manifest.json（幂等：同名文件覆盖为相同内容），
    // 但换来的是「一次调用解完、且成员列表完全由 manifest 事实决定」这个可复核的结构。
    landed = extractNamedMembers(archive, stagingDir, fileMembers);
    hardenTree(stagingDir);
  } catch (err) {
    cleanup(stagingDir);
    return { ok: false, outcome: 'aborted_extract_failed', reason: err.message };
  }

  // 5. 复用既有导入器的全部判据（演练模式：校验通过即 0，绝不碰 docker）
  step('verify-with-importer');
  const verified = verifyWithImporter({ stagingDir, bundlesRoot, allowlist, pubkeyFile });
  if (!verified.ok) {
    cleanup(stagingDir);
    return { ok: false, outcome: 'aborted_verify_failed', reason: verified.reason };
  }
  return { ok: true, stagingDir, finalDir, landed, manifest };
}

function intakeOne({
  archivePath,
  bundleRoot,
  pubkeyFile,
  allowlist = '',
  apply = false,
  settleSec = policy.DEFAULT_SETTLE_SECONDS,
}) {
  // 路径收口失败也必须变成结果对象而不是抛出：代理侧调用时异常会冒到 runOnce，
  // 让一个坏归档名把整轮代理成异常收尾（心跳与后续请求都受影响）。
  let archive;
  let bundlesRoot;
  let archiveName;
  let dirName;
  try {
    // 所有路径在校验点收成规范化值，后续只用这些值（校验与使用同源，不存在二次拼接）
    archive = policy.resolveWithinRoot(archivePath, null, '归档路径');
    bundlesRoot = policy.resolveWithinRoot(bundleRoot, null, '落位目标根');
    archiveName = policy.assertPlainDirName(path.basename(archive));
    dirName = policy.assertPlainDirName(archiveName.slice(0, -policy.ARCHIVE_SUFFIX.length));
  } catch (err) {
    return {
      ok: false,
      outcome: 'aborted_archive_invalid',
      reason: `归档路径/落位目标形态非法：${err.message}`,
      dirName: '',
      archive: path.basename(String(archivePath ?? '')),
    };
  }
  const state = {
    archive: archiveName,
    dirName,
    startedAt: new Date().toISOString(),
    steps: [],
  };
  const step = (name, detail = '') => {
    state.steps.push({ name, detail, at: new Date().toISOString() });
    log(`▶ ${name}${detail ? `：${detail}` : ''}`);
  };
  const stagingCleanup = (dir) => fs.rmSync(dir, { recursive: true, force: true });

  const finish = (outcome, reason = '') => {
    state.outcome = outcome;
    state.reason = reason;
    state.finishedAt = new Date().toISOString();
    recordState(state);
    return { ok: outcome === 'success', outcome, reason, dirName, archive: archiveName };
  };

  // 0. 体积上限（在算摘要与解包之前；畸形声明不该换来一次超长读）
  let st;
  try {
    st = fs.statSync(archive);
    policy.assertArchiveSizeWithinCap(st.size);
  } catch (err) {
    return finish('aborted_archive_invalid', `归档不可读或超限：${err.message}`);
  }

  // 1. 静默期 + 双读数
  step('settle-check', `${st.size} 字节`);
  const stability = readStability(archive, settleSec);
  if (!stability.settled) return finish('not_settled', stability.reason);

  // 2. 外层验签（结果对象：库函数不退出进程，见 verifyArchiveSignature 注释）
  step('verify-archive-signature');
  const signature = verifyArchiveSignature(archive, pubkeyFile);
  if (!signature.ok) return finish('aborted_signature_failed', signature.reason);
  state.signature = signature.state;

  // 3. 列条目 + 逐条判据 + 必需条目
  step('list-entries');
  let entries;
  try {
    entries = listEntries(archive);
    policy.assertEntryCountWithinCap(entries);
    // 目录条目与文件条目都要过路径安全判据（它们都是归档的一部分）
    for (const entry of entries) bundlePolicy.assertSafeRelativePath(policy.normalizeEntry(entry));
    policy.assertRequiredEntriesPresent(entries);
  } catch (err) {
    return finish('aborted_archive_invalid', err.message);
  }

  if (!apply) {
    log(`演练模式：归档 ${entries.length} 个条目全部通过判据，未做任何改动。`);
    state.entries = entries;
    return finish('dry_run');
  }

  // 4-5. 解包（两段，只解点名条目）+ 复用导入器判据
  const attempt = extractAndVerify({
    archive,
    bundlesRoot,
    dirName,
    entries,
    allowlist,
    pubkeyFile,
    step,
    cleanup: stagingCleanup,
  });
  if (!attempt.ok) return finish(attempt.outcome, attempt.reason);
  state.staging = path.basename(attempt.stagingDir);
  state.landed = attempt.landed.map((l) => ({ member: l.member, size: l.size }));

  // 6. 原子落位：同目录 rename（staging 与最终目录同在 bundleRoot 下，同文件系统）
  step('promote', dirName);
  try {
    fs.renameSync(attempt.stagingDir, attempt.finalDir);
  } catch (err) {
    stagingCleanup(attempt.stagingDir);
    return finish('aborted_promote_failed', `落位 rename 失败：${err.message}`);
  }
  state.finalDir = dirName;
  return finish('success');
}

/**
 * 从 CLI 选项 + 环境变量收口出本次要用的参数（路径一律规范化）。
 * 用法错误返回 { error }，调用方映射成退出码 2。
 */
function resolveCliContext(opts, env = process.env) {
  try {
    const inbox = String(opts.inbox || env.OFFLINE_BUNDLE_INBOX || '').trim();
    if (!inbox) throw new Error('缺少 --inbox（待落位归档目录）');
    return {
      inboxDir: policy.resolveWithinRoot(inbox, null, 'inbox 目录'),
      bundleRoot: policy.resolveWithinRoot(
        String(opts.bundleRoot || env.OFFLINE_BUNDLE_DIR || '').trim(),
        null,
        '落位目标根（--bundle-root / OFFLINE_BUNDLE_DIR）'
      ),
      pubkeyFile: String(opts.pubkeyFile || env.OFFLINE_BUNDLE_VERIFY_PUBKEY || '').trim(),
      allowlist: String(
        opts.allowlist || env.OFFLINE_BUNDLE_ALLOWLIST || env.HOT_UPGRADE_REGISTRY_ALLOWLIST || ''
      ).trim(),
      // 静默期与代理侧同口径：从 env 读，缺省走判据层的 DEFAULT_SETTLE_SECONDS
      settleSec: readSettleSecFromEnv(env),
    };
  } catch (err) {
    return { error: err.message };
  }
}

/** 把落位结果映射成退出码（CLI 语义；代理侧不用这条路径） */
function exitCodeFor(result, opts) {
  if (result.ok) {
    log(`落位完成：${result.dirName}`);
    return 0;
  }
  if (result.outcome === 'dry_run') {
    log('演练模式：未做任何改动。确认无误后加 --apply 执行。');
    return opts.dryRun ? 0 : 2;
  }
  if (result.outcome === 'not_settled') {
    log(`暂不落位：${result.reason}`);
    return 0; // 未就绪不是错误：下一轮再看
  }
  process.stderr.write(`[offline-intake] 落位失败（${result.outcome}）：${result.reason}\n`);
  return 1;
}

function main() {
  const opts = parseOrExit(process.argv.slice(2));
  if (opts.help) {
    printHelp();
    return 0;
  }
  const ctx = resolveCliContext(opts);
  if (ctx.error) {
    process.stderr.write(`[offline-intake] 用法错误：${ctx.error}\n`);
    return 2;
  }

  let candidates;
  try {
    candidates = listInboxCandidates(ctx.inboxDir);
  } catch (err) {
    fail(err.message);
  }
  if (candidates.length === 0) {
    log(`inbox 里没有可落位的归档：${ctx.inboxDir}`);
    return opts.apply ? 0 : 2;
  }

  // 每轮最多落一个：落位耗时（GB 级摘要 + 解包）不该让一轮无限长，
  // 也让「哪个包失败了」在留痕里始终可归因到具体归档名。
  const target = candidates[0];
  log(
    `待落位归档：${path.basename(target)}` +
      (candidates.length > 1 ? `（另有 ${candidates.length - 1} 个排队）` : '')
  );
  const result = intakeOne({
    // 再收一道：candidates 来自 listInboxCandidates（已过 assertPlainDirName 且拼自
    // inboxDir），这里显式钉回 inbox 之内——校验与使用同源，不依赖上游的不变量。
    archivePath: policy.resolveWithinRoot(target, ctx.inboxDir, '待落位归档'),
    bundleRoot: ctx.bundleRoot,
    pubkeyFile: ctx.pubkeyFile,
    allowlist: ctx.allowlist,
    apply: opts.apply,
    settleSec: ctx.settleSec,
  });
  return exitCodeFor(result, opts);
}

if (require.main === module) {
  try {
    process.exit(main());
  } catch (err) {
    fail(err && err.message ? err.message : String(err));
  }
}

module.exports = {
  main,
  intakeOne,
  listInboxCandidates,
  readStability,
  listEntries,
  extractNamedMembers,
  hardenTree,
  verifyArchiveSignature,
  signaturePathOf,
  STAGING_PREFIX,
  DIR_MODE,
  FILE_MODE,
};
