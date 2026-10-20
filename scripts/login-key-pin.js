#!/usr/bin/env node
/**
 * 计算登录 ECDH 静态私钥对应的公钥指纹（S-2）。
 *
 * 用途：把「前端构建期钉扎的公钥指纹」与「运行期实际加载的私钥」绑定到
 * 同一次构建。CI 在 docker build 前用本脚本从 LOGIN_ECDH_PRIVATE_KEY 算出
 * 64 位指纹，作为 VITE_LOGIN_PUBLIC_KEY_SHA256 构建参数传入；Dockerfile 同时
 * 把它写进运行环境的 LOGIN_PUBLIC_KEY_SHA256_PIN，应用启动时逐字比对
 * （src/utils/loginCipher.js 的 verifyBuildPin）。不一致即启动失败。
 *
 * 输入优先级：
 *   node scripts/login-key-pin.js <private-key.pem>   # 文件
 *   LOGIN_ECDH_PRIVATE_KEY=... node scripts/login-key-pin.js  # 环境变量（支持字面量 \n）
 *
 * 未提供输入时输出空行并以 0 退出：调用方（CI）据此表示「未配置静态私钥，
 * 不钉扎」，而不是让构建因为缺一个可选秘密而失败。
 * 提供了输入但解析失败则非零退出——静默产出空指纹会让钉扎形同虚设。
 */
'use strict';

const fs = require('fs');
const crypto = require('crypto');

// 支持 <NAME>_FILE 注入（与其它入口脚本同口径）；不依赖 node_modules
require('../src/config/secrets').hydrateSecretsFromFiles();

function readPem() {
  const file = process.argv[2];
  if (file) return fs.readFileSync(file, 'utf8');
  return (process.env.LOGIN_ECDH_PRIVATE_KEY || '').replace(/\\n/g, '\n');
}

function fingerprint(pem) {
  const privateKey = crypto.createPrivateKey(pem);
  if (privateKey.asymmetricKeyType !== 'ec') {
    throw new Error(`必须是 EC 私钥，实际为 ${privateKey.asymmetricKeyType}`);
  }
  const pub = crypto.createPublicKey(privateKey);
  const spkiDer = pub.export({ type: 'spki', format: 'der' });
  return crypto.createHash('sha256').update(spkiDer).digest('hex');
}

function main() {
  const pem = readPem().trim();
  if (!pem) {
    // 空输出：CI 捕获后 build-arg 为空，镜像不做钉扎（本地/未配置静态密钥的部署）
    return;
  }
  process.stdout.write(`${fingerprint(pem)}\n`);
}

try {
  main();
} catch (err) {
  console.error(`[login-key-pin] 无法解析 LOGIN_ECDH_PRIVATE_KEY：${err.message}`);
  process.exit(1);
}
