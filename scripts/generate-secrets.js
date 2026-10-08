#!/usr/bin/env node

/**
 * 全套密钥一次性生成器（R-1）
 *
 * 轮换手册（deployment/secret-rotation.md）的配套工具：把散落的
 * `openssl rand` 步骤收敛为一条命令，杜绝「手抄错一位」「忘了某个密钥」
 * 这类低级但致命的失误。
 *
 * 用法：
 *   node scripts/generate-secrets.js                    # 仅打印到 stdout（默认不落盘）
 *   node scripts/generate-secrets.js --out ./secrets-new   # 写入目录（不覆盖已有文件）
 *   node scripts/generate-secrets.js --out ./secrets-new --force  # 覆盖
 *   node scripts/generate-secrets.js --env-snippet      # 额外输出 .env 形式片段
 *
 * 安全约定：
 *   - 生成结果只写向 --out 指定目录或 stdout，从不回显到日志文件；
 *   - 参数严格校验（退出码 2 = 用法错误）：未知参数与缺值的 --out 在**生成任何密钥之前**
 *     即被拒绝，因此不存在"手误打成 --output 结果把全套密钥打印到了 stdout/CI 日志"这条路；
 *   - --out 目标如果落在一个 git 工作树里且**没有**被忽略规则覆盖 ⇒ 拒绝执行（退出码 1）。
 *     判据是 `git check-ignore` 自己给的，不是本脚本手写的模式匹配；轮换手册用的
 *     ./secrets-new 与下线后的 ./secrets-old 都已在 .gitignore/.dockerignore 在列。
 *     判不了（目标不在仓库里 / 机器没装 git）时只说明"没判成"，不拦——拦下一条轮换路径
 *     换来的安全性是负的；
 *   - 目录里已经躺着密钥文件时不再"缺哪个补哪个"：那会产出混合代次的一套，
 *     而 `mongodb_uri` 里拼的就是 `mongo_root_password`，两代混在一起应用连不上库。
 *     要么 --force 重做整套，要么换一个空目录；
 *   - 文件一律 0600，目录 0700（非 Windows 平台）。
 */

'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const USAGE = '用法: node scripts/generate-secrets.js [--out <dir> [--force]] [--env-snippet]';
/** 本脚本接受的全部参数（--out 后面必须跟目录，其余是纯开关） */
const KNOWN_TOKENS = ['--out', '--force', '--env-snippet', '--help', '-h'];

/**
 * 拼错时给出可照抄的正确写法（返回**真实 token**，含连字符）。
 * 抹掉非字母字符后三种形状相同即认定：多/少连字符（--envsnippet）、
 * 前后缀（--output ⇄ --out）、相邻字符换位（--fource → --force）。
 */
const suggestFlag = (token) => {
  const shape = (s) => s.replace(/[^a-z]/gi, '').toLowerCase();
  const sorted = (s) => [...s].sort().join('');
  const s = shape(token);
  if (s.length < 2) return undefined;
  return KNOWN_TOKENS.find((f) => {
    const k = shape(f);
    return k === s || k.startsWith(s) || s.startsWith(k) || sorted(k) === sorted(s);
  });
};

/**
 * 参数解析（严格），且必须在生成任何密钥之前完成。
 *
 * 原实现是 `argv.includes(name)` 与 `argv.indexOf(name) + 1` 两套松判据，于是三条
 * 最常见的手误都会**静默降级成"打印到 stdout"**（`outDir` 取不到值即走 else 分支）：
 *   - `--output ./secrets`（多打两个字母）→ 不被认成 --out，全套密钥进终端历史/CI 日志，
 *     而操作者以为已经落成 0600 文件；
 *   - `--out` 打在末尾（忘了目录）→ 同上；
 *   - `--out --force` → 目录名被设成字面量「--force」，落盘落到一个垃圾目录里。
 * 三条共同的形状是「参数没生效，但看起来生效了」。同族规矩已在
 * scripts/deployPolicy.js（--dryrun 曾换来一次真发布）与 scripts/run-rollback-drill.js
 * （--backup-dir 缺值）立过：未知参数与缺值一律以退出码 2 拒绝，不猜。
 */
function parseCliArgs(tokens) {
  const parsed = { outDir: undefined, force: false, envSnippet: false, help: false };
  const errors = [];
  for (let i = 0; i < tokens.length; i += 1) {
    const token = tokens[i];
    if (token === '--help' || token === '-h') parsed.help = true;
    else if (token === '--force') parsed.force = true;
    else if (token === '--env-snippet') parsed.envSnippet = true;
    else if (token === '--out') {
      const value = tokens[i + 1];
      if (!value || value.startsWith('--')) {
        errors.push('--out 缺少目录参数（要打印到 stdout 请整体不带 --out，而不是让目录丢失）');
        break; // 值槽被开关形态的 token 占掉后，后面的边界已不可信，不再继续解析
      }
      parsed.outDir = value;
      i += 1;
    } else {
      const hint = suggestFlag(token);
      errors.push(
        `未知参数：「${token}」（本脚本只接受 ${KNOWN_TOKENS.join(' / ')}，` +
          `其中 --out 必须跟目录）${hint ? `；是否想写 ${hint}？` : ''}`
      );
    }
  }
  return { ...parsed, errors };
}

const cli = parseCliArgs(process.argv.slice(2));
if (cli.help) {
  console.log(USAGE);
  process.exit(0);
}
if (cli.errors.length > 0) {
  for (const e of cli.errors) console.error(`[generate-secrets] ${e}`);
  console.error(`[generate-secrets] ${USAGE}`);
  process.exit(2);
}
const { outDir, force, envSnippet } = cli;

// ================= 生成 =================
const b64 = (bytes) => crypto.randomBytes(bytes).toString('base64').replace(/\n/g, '');
const hex = (bytes) => crypto.randomBytes(bytes).toString('hex');

const { privateKey: ecdhPem } = crypto.generateKeyPairSync('ec', {
  namedCurve: 'prime256v1',
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  publicKeyEncoding: { type: 'spki', format: 'pem' },
});

const mongoRootUsername = 'firesafety';

const secrets = {
  jwt_secret: b64(48),
  jwt_refresh_secret: b64(48),
  aes_secret_key: hex(32),
  hmac_secret: hex(32),
  login_ecdh_private_key: ecdhPem,
  mongo_root_username: mongoRootUsername,
  mongo_root_password: b64(32),
  admin_initial_password: b64(24),
  // Grafana 初始管理员口令：docker-compose.yml 的 grafana 服务经
  // GF_SECURITY_ADMIN_PASSWORD__FILE 指向 ./secrets/grafana_admin_password。
  // 此前本脚本不产出该文件，而 compose 的 secrets 段声明了它——
  // 用本脚本生成的密钥目录直接 `docker compose up` 会因为缺文件而失败，
  // 运维只能从 compose 头注释里的 openssl 片段手抄补齐（正是本脚本要消灭的失误源）。
  grafana_admin_password: b64(32),
  // Redis 认证口令（2026-10-01 审计 finding）：redis 侧 --requirepass 与 app 侧
  // REDIS_PASSWORD_FILE 共用。b64(32) 即可——应用侧走 ioredis 的 password 选项，
  // 不进 URL userinfo，字符集不受 percent-encoding 约束
  redis_password: b64(32),
};

// mongodb_uri 依赖上面两项，拼接时必须用生成值而非占位符
secrets.mongodb_uri =
  `mongodb://${encodeURIComponent(secrets.mongo_root_username)}` +
  `:${encodeURIComponent(secrets.mongo_root_password)}` +
  '@mongo:27017/fire_safety_db?authSource=admin';

// ================= 自检：全部满足 config/validate.js 的强度门槛 =================
const strengthChecks = [
  ['jwt_secret', secrets.jwt_secret.length >= 32],
  ['jwt_refresh_secret', secrets.jwt_refresh_secret.length >= 32],
  ['aes_secret_key', secrets.aes_secret_key.length >= 32],
  ['hmac_secret', secrets.hmac_secret.length >= 32],
  ['admin_initial_password', secrets.admin_initial_password.length >= 16],
  ['grafana_admin_password', secrets.grafana_admin_password.length >= 16],
  ['redis_password', secrets.redis_password.length >= 16],
];
const weak = strengthChecks.filter(([, ok]) => !ok).map(([name]) => name);
if (weak.length > 0) {
  console.error(`生成结果未通过强度自检：${weak.join(', ')}（不应发生，请检查 crypto 模块）`);
  process.exit(1);
}

// ================= 输出 =================
const isPosix = process.platform !== 'win32';

if (outDir) {
  const dir = path.resolve(outDir);
  if (fs.existsSync(dir) && !fs.statSync(dir).isDirectory()) {
    console.error(`--out 目标不是目录：${dir}`);
    process.exit(1);
  }

  // ---- 前置检查 A：目标目录会不会把真密钥交给版本库 ----
  // 判据交给 **git 自己的解析器**，不手写 gitignore 匹配：手写规则与 git 的读法一旦不一致，
  // 失效方向恰好是"规则看起来覆盖到了、实际一个字节都没挡"（本仓在 URI 解析上反复交过学费，
  // 同族规矩见 scripts/mongoUri.sh 的头注释——判据按参考解析器怎么读来定）。
  // 退出码逐档实测（不是推断）：0=命中忽略规则；1=在仓库内但 git 不报"已忽略"；128=不在仓库里
  // （容器里没有 .git、目标目录在仓库外、机器上没装 git 都归这一档）。
  // 只有 1 才拒绝：128 是"判不了"，判不了不许拦下一条轮换/DR 路径，但要把没判成说出来。
  // rc=1 合并了**两**种形态（都实测，也因此拒绝话术两种都点名）：
  //   · 没有任何规则命中它 —— 正常要拦的那一类；
  //   · 规则命中了，但该文件**已经在 index 里**（先 `git add`、事后才补 .gitignore；
  //     git 对 index 里的路径一律不再报"已忽略"）。这一类更危险：密钥已经进了版本库。
  // 所以这里**刻意不加** `--no-index`：加上后第二种会变成 rc=0 而放行，等于允许把新一套
  // 真凭据写进一个"上一套已经躺在仓库里"的目录，而那次拒绝才是现场唯一的声音。
  // 探针取目录里的**密钥文件名**（而不是目录本身）：入库的从来是里面的文件，问 git 的
  // 就该是 `git add` 实际会带走的那个路径。需说明的是这一条**不是**分歧判据——实测
  // 三组形态（规则 `s/`、规则 `s/`+反向 `!s/jwt_secret`、文件已入 index）里目录名与
  // 文件名的命中结果**完全一致**，原先写在这里的"测目录名会假绿"是没有取证就下的结论，
  // 已删。留文件探针只因为它更贴近被问的对象。
  //
  // 问 git 时的 cwd 取"目标最近的、已存在的祖先目录"而不是调用方当前所在目录：
  // 判的是**这个目录落在哪个版本库里**，与运维在哪个路径下敲命令无关。两点实测支撑——
  //   · 目标目录常常还不存在（`--out ./secrets-new` 首次轮换），git 的 cwd 必须是一个真实目录；
  //   · 用调用方的 cwd 会把"仓库外的目标"一律判成 128 而放行，而 `--out ~/keys` 在家目录
  //     本身是个 dotfiles 仓库时，恰恰是必须拦的那一类（祖先目录才是这条判据的主语）。
  const ignoreProbe = path.join(dir, Object.keys(secrets)[0]);
  let probeCwd = dir;
  while (!fs.existsSync(probeCwd)) {
    const parent = path.dirname(probeCwd);
    if (parent === probeCwd) break; // 已到文件系统根，不存在更上的祖先
    probeCwd = parent;
  }
  let ignoreVerdict = 'unknown';
  try {
    execFileSync('git', ['check-ignore', '-v', '--', ignoreProbe], {
      cwd: probeCwd,
      stdio: ['ignore', 'pipe', 'ignore'],
    });
    ignoreVerdict = 'ignored';
  } catch (e) {
    if (e.status === 1) {
      ignoreVerdict = 'not_ignored'; // git 明确回答：在仓库里，但它不报"已忽略"（两种形态见上）
    } else {
      // 128（目标不在工作树内/压根不是仓库）与"git 没跑起来"（机器上没装 git、进程被信号杀死，
      // 这两档 e.status 是 undefined）都算判不了。判不了不许拦住一条轮换/DR 路径——
      // 容器里没有 .git 是常态，把它做成硬失败等于在最要紧的那天多一个跑不通的脚本。
      ignoreVerdict = 'unknown';
    }
  }
  if (ignoreVerdict === 'not_ignored') {
    console.error(`--out 目标在 git 仓库内，而 git 不认它是被忽略的：${dir}`);
    console.error('这套文件是真凭据，落在这里等于等着被 `git add` 带走（本仓库是公开仓库）。');
    console.error('两种形态都会走到这里（`git check-ignore -v` 对两者都回 rc=1）：');
    console.error('  1) 没有 .gitignore 规则命中 —— 出路：把该目录写进 .gitignore');
    console.error('     （推荐 `secrets-*/` 这类带内容的规则，并用');
    console.error(
      '     `git check-ignore -v <目录>/jwt_secret` 自证命中），或 --out 指到仓库之外；'
    );
    console.error('  2) 规则有了，但同名文件**已经在 index 里**（先 add 后补规则）—— 这种');
    console.error('     不是"改脚本"能救的：那份真凭据已经在版本库里，只能当作已泄露处理——');
    console.error('     按 deployment/secret-rotation.md 重新轮换一套，并把该文件');
    console.error('     `git rm --cached` 后重写仓库历史（公开仓库里它已被任何人取走过）。');
    process.exit(1);
  }
  if (ignoreVerdict === 'unknown') {
    console.log(`（未向 git 核对忽略状态：${dir} 不在可判定的 git 工作树内。`);
    console.log('  请自行确认这个目录不会被版本库收走。）');
  }

  // ---- 前置检查 B：目录里已有密钥时不再"缺哪个补哪个" ----
  // 原实现在写入循环里逐个 `已存在，跳过` ⇒ 一次中断后的重跑会产出一个**混合代次**目录：
  // 已存在的是上一代随机值，缺的那几个是这一代。多数密钥彼此独立，混着看不出问题，
  // 但 `mongodb_uri` 是把 `mongo_root_password` 拼进去生成的——上一代的密码 + 这一代的 URI
  // 会同时躺在这个目录里。mongo 初始化用的是 `mongo_root_password`，应用连的是 `mongodb_uri`，
  // 于是轮换"成功"结束、应用第一次连库就认证失败，而现场证据是两份都是刚生成的 0600 文件。
  // 现在要么整套覆盖（--force），要么不动（拒绝），不存在半新半旧这一档。
  // 写入中途挂掉（磁盘满/权限）时 writeFileSync 直接抛出、进程非零退出，留下的也是半个目录——
  // 不必在这里再判一次"产物齐不齐"：下一次运行会被本条拒绝，而给的出路（--force 重做整套）
  // 恰好把它拉回"一整套同代次"。判齐否的那几条分支本机造不出可复现的触发形态，
  // 留着只会是一条没人证过的代码。
  const alreadyThere = Object.keys(secrets).filter((name) => fs.existsSync(path.join(dir, name)));
  if (alreadyThere.length > 0 && !force) {
    console.error(`--out 目录里已经有 ${alreadyThere.length} 个密钥文件：${dir}`);
    console.error(`已有：${alreadyThere.join(', ')}`);
    console.error(
      '不再"缺哪个补哪个"：那样产出的目录里，`mongodb_uri` 可能与 `mongo_root_password`'
    );
    console.error('分属两代随机值（前者是后者拼进去的），应用会带着对不上的连接串启动。');
    console.error('两条出路：加 --force 重做**整套**（旧值全部覆盖），或换一个空目录。');
    process.exit(1);
  }

  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });

  for (const [name, value] of Object.entries(secrets)) {
    const file = path.join(dir, name);
    fs.writeFileSync(file, value, { mode: 0o600 });
    if (isPosix) {
      fs.chmodSync(file, 0o600);
      fs.chmodSync(dir, 0o700);
    }
    console.log(`已写入 ${file}（${Buffer.byteLength(value)} 字节）`);
  }

  // 【M-05 修复】Windows 上 mode/chmod 均不映射 NTFS ACL：writeFileSync 的 mode
  // 被忽略，chmodSync 只能粗粒度切换只读属性。因此上面的权限收紧在 Windows 上
  // 是空操作，而文件会继承父目录的宽松 ACL（实测默认含 BUILTIN\Users:(I)(RX)
  // 与 Authenticated Users:(I)(M)，即任何本地用户可读取并改写密钥文件）。
  //
  // 2026-09-16 第二轮：由「打印一条待执行命令」升级为**实际执行**（utils/filePermission）。
  // 只提示不执行，等于把安全语义降级为建议——实践中大多数人不做，密钥长期裸奔。
  // 本模块的意图本就明确（生成只自己可读的密钥载体），因此默认直接收紧，
  // 并**回读校验**：收紧失败或校验不通过则大声告警，绝不静默放过。
  const { hardenPath, verifyHardened } = require('../src/utils/filePermission');
  const hardened = hardenPath(dir, { isDir: true, log: (m) => console.log(m) });

  // 目录收紧后再对目录内已写入的密钥文件逐个收紧（icacls /T 覆盖递归，这里显式复核）
  const fileFailures = [];
  if (hardened.ok) {
    for (const [name] of Object.entries(secrets)) {
      const file = path.join(dir, name);
      if (!fs.existsSync(file)) continue;
      // 返回值必须收：旧写法把 hardenPath(file) 的结果整批丢掉，于是"11 个密钥文件里
      // 有 4 个没收紧"只能靠运维盯 stdout 里的 icacls 报错——而它一次都不出现时，
      // 没有任何东西能区分"全都收好了"和"一个都没试"。
      const one = hardenPath(file, { log: (m) => console.log(m) });
      if (!one.ok) fileFailures.push(`${name}：${one.detail}`);
    }
  }
  const check = hardened.ok
    ? verifyHardened(dir)
    : { tightened: false, evidence: `目录收紧未执行：${hardened.detail}` };

  if (check.tightened && fileFailures.length === 0) {
    console.log(`\n✅ 权限已收紧并复核通过：${dir}（${hardened.detail}）`);
    console.log(`   复核证据：${check.evidence}`);
  } else {
    // 【为什么必须非零退出】"生成只自己可读的密钥载体"是本脚本的契约而不是建议：旧写法
    // 把收紧失败/复核不通过打成 console.log（连 stderr 都不走）然后退 0，于是
    // `generate-secrets … && 下一步` 会在密钥对本机其他用户可读、可改的状态下继续推进，
    // 而调用方收到的信号是"成功"。这与本仓反复修的"报告里已见的缺口在出口处丢了，PASS 照打"
    // 同一条形状。
    // 产物保留不删：密钥内容是有效的，毁掉它只会把运维推向手搓随机值——那比 ACL 宽松更糟。
    console.error(`\n❌ 权限收紧或复核未通过：${dir}`);
    if (!check.tightened) console.error(`   目录：${check.evidence}`);
    for (const f of fileFailures) console.error(`   文件收紧失败：${f}`);
    console.error('   密钥文件已写出且内容有效；请按上面提示手动收紧后复核，再进下一步。');
    console.error('   本脚本以非零退出：没做到「仅属主可读」就不算生成成功。');
    process.exitCode = 1;
  }

  console.log('\n落地后请执行轮换手册中的迁移步骤（AES 先迁 mfaSecret、HMAC 重签），');
  console.log('再重启应用。见 deployment/secret-rotation.md。');
} else {
  console.log('# ===== 生成结果（stdout 会留在终端历史，复制后请及时清屏）=====\n');
  for (const [name, value] of Object.entries(secrets)) {
    if (name === 'login_ecdh_private_key') {
      console.log(`${name}（PEM，env 内换行需写成 \\n）:`);
      console.log(value);
    } else {
      console.log(`${name}=${value}`);
    }
  }
  console.log('\n提示：加 --out <dir> 可直接写入 secrets 文件（0600）。');
}

if (envSnippet) {
  // .env 形式（本地开发用）；生产请用 *_FILE 注入，不要把密钥留在 environment
  const pemOneLine = secrets.login_ecdh_private_key.replace(/\r?\n/g, '\\n');
  console.log('\n# ===== .env 片段（仅本地开发；生产用 secrets 文件 + *_FILE）=====');
  console.log(`JWT_SECRET=${secrets.jwt_secret}`);
  console.log(`JWT_REFRESH_SECRET=${secrets.jwt_refresh_secret}`);
  console.log(`AES_SECRET_KEY=${secrets.aes_secret_key}`);
  console.log(`HMAC_SECRET=${secrets.hmac_secret}`);
  console.log(`LOGIN_ECDH_PRIVATE_KEY=${pemOneLine}`);
  console.log(`ADMIN_INITIAL_PASSWORD=${secrets.admin_initial_password}`);
  console.log(`GRAFANA_ADMIN_PASSWORD=${secrets.grafana_admin_password}`);
}
