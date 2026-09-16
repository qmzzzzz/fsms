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
 *   - --out 目录建议与仓库隔离（./secrets/ 已在 .gitignore/.dockerignore 在列）；
 *   - 文件一律 0600，目录 0700（非 Windows 平台）。
 */

'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const argv = process.argv.slice(2);
const getFlag = (name) => argv.includes(name);
const getOpt = (name) => {
  const i = argv.indexOf(name);
  return i !== -1 ? argv[i + 1] : undefined;
};

if (getFlag('--help') || getFlag('-h')) {
  console.log('用法: node scripts/generate-secrets.js [--out <dir> [--force]] [--env-snippet]');
  process.exit(0);
}

const outDir = getOpt('--out');
const force = getFlag('--force');
const envSnippet = getFlag('--env-snippet');

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
  // 原实现在 Windows 上静默跳过——用户以为权限已收紧。现显式提示并给出可直接
  // 执行的 icacls 命令。对照：src/services/initData.js:765-772 早已对同一平台
  // 局限做了 best-effort + 告警，此处口径与之对齐。
  if (!isPosix) {
    console.log('');
    console.log('⚠️  注意：Windows 不支持 POSIX 权限位，上述 0600/0700 未生效。');
    console.log('   密钥文件当前继承父目录 ACL，可能对本机其他用户可读/可改。');
    console.log('   请手动收紧（仅当前用户 + Administrators + SYSTEM 可访问）：');
    console.log('');
    console.log(`     icacls "${dir}" /inheritance:r /grant:r "%USERNAME%:(OI)(CI)F"`);
    console.log('');
    console.log('   验证：icacls "' + dir + '"  应不再出现 BUILTIN\\Users 与 Authenticated Users');
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
}
