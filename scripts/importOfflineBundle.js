#!/usr/bin/env node
/**
 * 离线包导入（air-gap 侧执行）
 *
 * 与在线升级的分工：在线路径的真相由 registry 给出（digest 来自 registry 的 manifest），
 * 离线路径没有 registry，包里的一切都是**自称**。因此本脚本每一步都在做同一件事——
 * 把「自称」与「实际」对上：
 *   · manifest 自称的字节数   ↔ 磁盘上的实际字节数；
 *   · manifest 自称的 sha256  ↔ 本脚本自己算出来的 sha256；
 *   · manifest 自称的 digest  ↔ docker load 之后 docker 认的 RepoDigests。
 * 三条任缺一条，「导入成功」就只是一句口号：包里的镜像可以既不是那个版本、
 * 也不是那个大小，而审计里记的仍是 manifest 上写的那一行。
 *
 * 默认演练：不加 --apply 只打印计划并以 2 退出（与 scripts/hotUpgrade.js 同语义）。
 *
 * 刻意不做的事：
 *   · 不接受 .tar，只接受**已解压的目录**——自己实现安全解包，等于在升级链路上
 *     再开一条路径穿越面，而这一步没有任何不可替代性（ADR-019 引入签名时保留了这条）；
 *   · 不切流：本脚本只负责「把镜像装进本地 docker 并证明它是哪一版」，
 *     换不换、什么时候换，仍由 scripts/hotUpgrade.js 的蓝绿七步决定；
 *   · 不接受 tag：离线包不是 tag 的逃生通道（判据在 scripts/offlineBundlePolicy.js）。
 *
 * 签名（ADR-019）：manifest.json 的原始字节由构建机 Ed25519 私钥签名（manifest.sig）。
 * 本脚本 fail-closed：配置了验签公钥（--pubkey-file / OFFLINE_BUNDLE_VERIFY_PUBKEY）时，
 * 未签名或验签失败的包一律拒绝；未配置公钥时放行，但 stdout 与留痕都会明示
 * signature: 'unchecked'——是否把「未验签」定为拒绝，是部署的显式选择。
 *
 * 用法：
 *   node scripts/importOfflineBundle.js --bundle /var/lib/fsms/upgrade/bundles/v1.2.3
 *   node scripts/importOfflineBundle.js --bundle <dir> --pubkey-file /etc/fsms/secrets/offline_bundle.pub --apply
 */

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');
const policy = require('./offlineBundlePolicy');
const { SIG_FILE, verifyManifestBytes } = require('./offlineBundleSignature');

const ROOT = path.resolve(__dirname, '..');

const log = (msg) => process.stdout.write(`[offline-import] ${msg}\n`);

/** 已产生副作用之后的失败：留痕交给调用方，这里只负责说清停在哪一步、现场是什么 */
const fail = (msg, code = 1) => {
  process.stderr.write(`[offline-import] 中止：${msg}\n`);
  process.exit(code);
};

/** 子进程一律显式传数组参数：manifest 里的字符串永远不经过 shell 求值 */
function runInherit(file, args) {
  execFileSync(file, args, { cwd: ROOT, stdio: 'inherit' });
}

/** 需要读输出的调用（docker image inspect）；管道捕获，不继承 stdio */
function runCapture(file, args) {
  return execFileSync(file, args, {
    cwd: ROOT,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
}

/**
 * 流式算 sha256。
 *
 * 不用 readFileSync：升级包动辄上 GB，一次性读进内存会把「校验摘要」这一步
 * 变成一次 OOM——而 OOM 在现场的表现是「导入进程被杀」，不是「这个包不合法」。
 */
function sha256File(file) {
  const hash = crypto.createHash('sha256');
  const fd = fs.openSync(file, 'r');
  try {
    const buf = Buffer.allocUnsafe(1024 * 1024);
    for (;;) {
      const n = fs.readSync(fd, buf, 0, buf.length, null);
      if (n <= 0) break;
      hash.update(buf.subarray(0, n));
    }
  } finally {
    fs.closeSync(fd);
  }
  return hash.digest('hex');
}

/**
 * 把 manifest 里的相对路径钉回包内，并拒绝符号链接。
 *
 * 这是判据层 assertSafeRelativePath 之外的**第二道**：路径字符串安全不代表落点安全——
 * 包内一个 `payload/app.tar -> /root/.ssh/authorized_keys` 的软链，字符串层面完全合法，
 * 而按它去读/去算摘要的对象已经是包外文件了。升级链路里没有「软链 payload」这种正当需求。
 */
function resolvePayload(bundleDir, relFile) {
  const full = path.resolve(bundleDir, relFile);
  const base = path.resolve(bundleDir);
  // 这里一律 throw 而不是直接退出：调用方要把「尚未改动本机 docker」拼在报错前面，
  // 那是运维判断「能不能改完包直接重试」的唯一依据，提前 exit 会把它吃掉。
  if (full !== base && !full.startsWith(base + path.sep)) {
    throw new Error(`payload 解析后的落点落在包外（拒绝继续）：${relFile}`);
  }
  let st;
  try {
    st = fs.lstatSync(full);
  } catch (err) {
    throw new Error(`payload 文件不存在：${relFile}（${err.message}）`);
  }
  if (st.isSymbolicLink()) {
    throw new Error(`payload 是符号链接（拒绝继续）：${relFile}——链接指向的可以是包外任意文件`);
  }
  if (!st.isFile()) {
    throw new Error(`payload 不是普通文件：${relFile}`);
  }
  return { full, size: st.size };
}

/** 读件、算摘要、逐条比对。任何一条不符都在**碰 docker 之前**中止 */
function verifyImage(bundleDir, img, maxPayloadBytes) {
  const { full, size } = resolvePayload(bundleDir, img.file);
  policy.assertWithinCap(size, maxPayloadBytes, `payload ${img.file}`);
  policy.assertSizeEqual(img.bytes, size, `payload ${img.file}`);
  const actual = sha256File(full);
  policy.assertDigestEqual(img.sha256, actual, `payload ${img.file}`);
  log(`校验通过：${img.file}（${size} 字节，sha256 ${actual.slice(0, 12)}…）`);
  return full;
}

/**
 * load 之后核对「docker 认的版本」就是 manifest 声明的那个 digest。
 *
 * 必须查 RepoDigests 而不是只看 load 退出码：load 的退出码只说明 tar 结构被接受了，
 * 完全可能装进来一个**另一个版本**的镜像（包里被换过 payload 时就是这样）。
 * 而 RepoDigests 里的 sha256 是镜像 manifest 的内容摘要——内容寻址，改一个字节就变，
 * 它是这条链上唯一不能自称的东西。
 */
function assertLoadedDigest(img) {
  let repoDigests;
  try {
    const out = runCapture('docker', [
      'image',
      'inspect',
      '--format',
      '{{json .RepoDigests}}',
      img.ref,
    ]);
    repoDigests = JSON.parse(out.trim() || '[]');
  } catch (err) {
    fail(
      `docker 里找不到镜像 ${img.ref}（load 之后的核对失败）。\n` +
        '  最常见的原因：这个包是用 tag（如 repo:v1.2.3）导出的，而不是用 digest 导出的——\n' +
        '  tag 导出无法在目标机上还原出 RepoDigests，于是「装进来的到底是哪一版」无法证明。\n' +
        '  请用 scripts/build-offline-bundle.sh 重新构建（它会 pull 指定 digest 后再 save）。\n' +
        `  原始错误：${err.message}`
    );
  }
  if (!Array.isArray(repoDigests) || !repoDigests.includes(img.ref)) {
    fail(
      `镜像 ${img.ref} 的 RepoDigests 不含该 digest：\n  实际：${JSON.stringify(repoDigests)}\n` +
        '  说明本地同名镜像不是包里声明的那一版，拒绝当成导入成功。'
    );
  }
  log(`版本核对通过：${img.ref}`);
}

function printHelp() {
  process.stdout.write(
    [
      '离线包导入。默认只演练，加 --apply 才真正 docker load。',
      '',
      '  --bundle <dir>              已解压的离线包目录（含 manifest.json 与 payload/）',
      '  --bundle-root <dir>         只允许包目录位于该根目录之下（代理调用时用）',
      '  --pubkey-file <file>             Ed25519 验签公钥（PEM）；也可用 OFFLINE_BUNDLE_VERIFY_PUBKEY。',
      '                              配置后未签名/验签失败的包一律拒绝（fail-closed）；不配则跳过',
      '                              验签并在留痕里明示 signature=unchecked',
      '  --allowlist <prefixes>      逗号分隔的仓库前缀；也可用 OFFLINE_BUNDLE_ALLOWLIST',
      '                              或 HOT_UPGRADE_REGISTRY_ALLOWLIST。空白名单 = 全拒',
      '  --max-payload-bytes <n>     单个 payload 大小上限，默认 8 GiB',
      '  --apply                     真正执行（缺省为演练）',
      '  --help                      本帮助',
      '',
    ].join('\n')
  );
}

/** 解析参数。用法错误必须在**产生任何副作用之前**以退出码 2 拒绝，且 stdout 一个字节都不留 */
function parseOrExit(argv) {
  try {
    return policy.parseArgs(argv);
  } catch (err) {
    process.stderr.write(`[offline-import] 用法错误：${err.message}\n`);
    process.exit(2);
  }
}

function resolveBundleDir(input, bundleRoot) {
  const dir = path.resolve(input);
  if (bundleRoot) {
    const base = path.resolve(bundleRoot);
    if (dir !== base && !dir.startsWith(base + path.sep)) {
      fail(`离线包目录不在允许的根目录之下：${input}\n  允许的根：${bundleRoot}`);
    }
  }
  let st;
  try {
    st = fs.statSync(dir);
  } catch (err) {
    fail(`离线包目录不存在：${input}（${err.message}）`);
  }
  if (!st.isDirectory()) {
    fail(
      `离线包必须是已解压的目录，而不是文件：${input}\n` +
        '  本导入器不自己解包——在升级链路上再实现一次安全解包，等于再开一条路径穿越面。\n' +
        '  请先解压，再对解压出来的目录执行导入。'
    );
  }
  const manifestPath = path.join(dir, 'manifest.json');
  if (!fs.existsSync(manifestPath)) {
    fail(`离线包里没有 manifest.json：${path.join(input, 'manifest.json')}`);
  }
  return dir;
}

function readManifestBytes(bundleDir) {
  const manifestPath = path.join(bundleDir, 'manifest.json');
  try {
    // 按 Buffer 读：签名是对原始字节做的，过一遍 utf8 字符串再编码回来可能不是同一批字节
    return fs.readFileSync(manifestPath);
  } catch (err) {
    fail(`manifest.json 不可读：${err.message}`);
  }
}

function parseManifestBytes(bytes) {
  let raw;
  try {
    raw = JSON.parse(bytes.toString('utf8'));
  } catch (err) {
    fail(`manifest.json 不是合法 JSON：${err.message}`);
  }
  return policy.parseBundleManifest(raw);
}

/**
 * 验签（fail-closed：公钥已配置时，未签名 = 拒绝）。
 *
 * 排在 manifest 结构解析**之前**：签名是对字节做的，与 JSON 语义无关——一个被改过
 * 字节但碰巧还能解析的 manifest，没有理由先享受判据层的服务再被拦下。
 * 三个失败面分开说清：公钥读不了（本机配置问题）、sig 不存在（包未签名）、
 * 字节不符（包被篡改或公钥配错）——运维的处置动作完全不同。
 */
function verifyBundleSignature(bundleDir, manifestBytes, pubkeyFile) {
  let pem;
  try {
    pem = fs.readFileSync(pubkeyFile, 'utf8');
  } catch (err) {
    fail(
      `验签公钥不可读（--pubkey-file / OFFLINE_BUNDLE_VERIFY_PUBKEY 指向的文件）：${err.code || err.message}`
    );
  }
  const sigPath = path.join(bundleDir, SIG_FILE);
  let sigBytes;
  try {
    sigBytes = fs.readFileSync(sigPath);
  } catch (err) {
    if (err.code === 'ENOENT') {
      fail(
        '本机已配置验签公钥，但包里没有 manifest.sig（未签名包）：按 fail-closed 拒绝。\n' +
          '  请用 scripts/build-offline-bundle.sh --sign-key <私钥.pem> 重新构建并搬运；\n' +
          '  或经人工确认本机确实要接受未签名包后，再移除公钥配置。'
      );
    }
    fail(`manifest.sig 不可读：${err.message}`);
  }
  const result = verifyManifestBytes(manifestBytes, sigBytes, pem);
  if (!result.ok) {
    fail(`离线包签名验证失败：${result.reason}`);
  }
  log(`签名验证通过（${SIG_FILE} ↔ manifest.json 原始字节）`);
}

/** 留痕：与 scripts/hotUpgrade.js 同口径，写 logs/ 下 0600 的本地记录 */
function recordState(state) {
  const dir = path.join(ROOT, 'logs');
  try {
    fs.mkdirSync(dir, { recursive: true });
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    const file = path.join(dir, `offline-import-${stamp}.json`);
    fs.writeFileSync(file, JSON.stringify(state, null, 2), { encoding: 'utf8', mode: 0o600 });
    log(`状态记录：${file}`);
  } catch (err) {
    process.stderr.write(`[offline-import] 警告：状态记录写入失败（${err.message}）\n`);
  }
}

/**
 * 把「阶段失败 → 留痕 → 退出」收成一处。
 *
 * 三个阶段用的是同一套动作，差别只在 outcome 名与那句现场描述——而那句描述**不能合并**：
 * 「尚未改动本机 docker」与「镜像已写入本地 docker」对运维是两种不同的处境（前者可以改完包
 * 直接重试，后者必须先确认本地镜像状态）。合并成一句会把这条区别抹掉。
 */
function runPhase(state, outcome, failureMessage, fn) {
  try {
    fn();
  } catch (err) {
    recordState({ ...state, outcome, reason: err.message });
    fail(`${failureMessage}：${err.message}`);
  }
}

function main() {
  const opts = parseOrExit(process.argv.slice(2));
  if (opts.help) {
    printHelp();
    return 0;
  }
  if (!opts.bundle) {
    process.stderr.write('[offline-import] 用法错误：缺少 --bundle（离线包目录）\n');
    return 2;
  }

  const allowlist = policy.splitAllowlist(
    opts.allowlist ||
      process.env.OFFLINE_BUNDLE_ALLOWLIST ||
      process.env.HOT_UPGRADE_REGISTRY_ALLOWLIST
  );
  const bundleDir = resolveBundleDir(opts.bundle, opts.bundleRoot);
  const pubkeyFile = String(
    opts.pubkeyFile || process.env.OFFLINE_BUNDLE_VERIFY_PUBKEY || ''
  ).trim();
  const manifestBytes = readManifestBytes(bundleDir);
  let signatureState = 'unchecked';
  if (pubkeyFile) {
    verifyBundleSignature(bundleDir, manifestBytes, pubkeyFile);
    signatureState = 'verified';
  } else {
    log(
      '未配置验签公钥（--pubkey-file / OFFLINE_BUNDLE_VERIFY_PUBKEY）：本次导入不校验签名，' +
        '包完整性仅由「搬运通道 + 逐字节比对 + load 后 RepoDigests 复核」保证'
    );
  }
  const manifest = parseManifestBytes(manifestBytes);

  // 白名单判据在**读盘之前**跑：这个包该不该被接受，与它有多大、装在哪无关
  for (const img of manifest.images) policy.assertBundleImageAllowed(img, allowlist);

  log(`离线包：${bundleDir}`);
  log(`  版本：${manifest.version}${manifest.buildId ? `（构建号 ${manifest.buildId}）` : ''}`);
  for (const img of manifest.images) log(`  镜像：${img.role} → ${img.ref}`);

  if (!opts.apply) {
    log('演练模式：未做任何改动（未 docker load、未 docker tag）。确认无误后加 --apply 执行。');
    return opts.dryRun ? 0 : 2;
  }

  const state = {
    bundle: bundleDir,
    version: manifest.version,
    buildId: manifest.buildId,
    signature: signatureState,
    startedAt: new Date().toISOString(),
    images: manifest.images.map((i) => ({ role: i.role, ref: i.ref })),
    steps: [],
  };
  const step = (name, detail = '') => {
    state.steps.push({ name, detail, at: new Date().toISOString() });
    log(`▶ ${name}${detail ? `：${detail}` : ''}`);
  };

  // 1. 全部摘要先校验完，再碰 docker。
  //    顺序很重要：先 load 后校验的话，一个损坏的包会在被拒绝之前就把半个镜像写进本地
  //    docker（占盘、并且和「上一版」抢同一个 repo 名），失败现场的清理成本远高于先校验。
  step('verify', `${manifest.images.length} 个 payload`);
  const payloads = [];
  runPhase(state, 'aborted_verify_failed', '离线包校验失败（尚未改动本机 docker）', () => {
    for (const img of manifest.images) {
      payloads.push({ img, full: verifyImage(bundleDir, img, opts.maxPayloadBytes) });
    }
  });

  // 2. load
  runPhase(state, 'aborted_load_failed', 'docker load 失败', () => {
    for (const { img, full } of payloads) {
      step('load', `${img.role} ← ${img.file}`);
      runInherit('docker', ['load', '-i', full]);
    }
  });

  // 3. 核对「装进来的就是 manifest 声明的那个 digest」。
  // 这一步失败时 docker 已经被改动过，故现场描述与前面两步相反（见 runPhase 注释）。
  step('verify-digest');
  runPhase(state, 'aborted_digest_mismatch', '镜像已导入本地 docker，但版本核对失败', () => {
    for (const { img } of payloads) assertLoadedDigest(img);
  });

  state.outcome = 'success';
  state.finishedAt = new Date().toISOString();
  recordState(state);
  log('导入完成。下一步：node scripts/hotUpgrade.js --image <ref> --offline --apply');
  return 0;
}

if (require.main === module) {
  try {
    process.exit(main());
  } catch (err) {
    fail(err && err.message ? err.message : String(err));
  }
}

module.exports = { main, sha256File };
