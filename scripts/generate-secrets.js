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
 *   - --out 目录建议与仓库隔离（./secrets/ 已在 .gitignore/.dockerignore 在列）；
 *   - 文件一律 0600，目录 0700（非 Windows 平台）。
 */

'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

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
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });

  for (const [name, value] of Object.entries(secrets)) {
    const file = path.join(dir, name);
    if (fs.existsSync(file) && !force) {
      console.error(`已存在，跳过（加 --force 覆盖）：${file}`);
      continue;
    }
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
  if (hardened.ok) {
    for (const [name] of Object.entries(secrets)) {
      const file = path.join(dir, name);
      if (fs.existsSync(file)) hardenPath(file, { log: (m) => console.log(m) });
    }
    const check = verifyHardened(dir);
    if (check.tightened) {
      console.log(`\n✅ 权限已收紧并复核通过：${dir}（${hardened.detail}）`);
      console.log(`   复核证据：${check.evidence}`);
    } else {
      console.log(`\n⚠️  权限复核未通过：${dir}`);
      console.log(`   ${check.evidence}`);
      console.log('   密钥可能对本机其他用户可读，请按上述提示手动收紧后复核。');
    }
  } else {
    console.log(`\n⚠️  权限收紧未成功：${dir}（${hardened.detail}）`);
    console.log('   密钥可能对本机其他用户可读/可改，请按上述提示手动执行后复核。');
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
