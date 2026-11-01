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
 * 未提供输入时：
 *   - 默认（本地/PR 构建）输出空行并以 0 退出——调用方据此表示「不钉扎」，
 *     不让可选路径因为缺一个秘密而失败；
 *   - 带 `--require`（或 REQUIRE_LOGIN_KEY_PIN=true）时**非零退出**。
 *     2026-10-31（审计一-6）：发布镜像的构建此前与本地同形——缺 secret 只打印一条
 *     `::warning::`，随后照常构建、推送、部署。失效形态是**静默的**：
 *     镜像里 LOGIN_PUBLIC_KEY_SHA256_PIN 为空 ⇒ 运行期 verifyBuildPin 直接跳过，
 *     前端包与运行私钥的绑定在这条路径上完全不存在，而 CI 是绿的、镜像可拉可跑。
 *     「生产构建必须钉扎」这条口径之前只写在注释里，没有任何一处会红。
 * 提供了输入但解析失败则非零退出——静默产出空指纹会让钉扎形同虚设。
 */
'use strict';

const fs = require('fs');
const crypto = require('crypto');

// 支持 <NAME>_FILE 注入（与其它入口脚本同口径）；不依赖 node_modules
require('../src/config/secrets').hydrateSecretsFromFiles();

/** 本脚本认的全部开关 */
const REQUIRE_FLAG = '--require';

/**
 * 参数解析：未知开关一律拒绝（与本仓 deployPolicy / run-rollback-drill 同规矩）。
 * 判据不能是「argv 里出现过就当真」：`--requre`（少一个 i）这种手误若被当成
 * 「没要强制」，得到的正是一次无声的未钉扎发布——本开关的全部价值就在这里。
 * 只允许一个位置参数（PEM 文件路径）；其余位置参数同样拒绝。
 * @returns {{error?: string, pemPath: string|null, require: boolean}}
 */
function parseArgs(argv) {
  const requirePin = argv.includes(REQUIRE_FLAG);
  const positional = [];
  for (const token of argv) {
    if (token === REQUIRE_FLAG) continue;
    if (token.startsWith('--')) {
      return {
        error: `未知参数：${token}（可用参数：${REQUIRE_FLAG}，或一个 PEM 文件路径）`,
        pemPath: null,
        require: requirePin,
      };
    }
    positional.push(token);
  }
  if (positional.length > 1) {
    return {
      error: `只接受一个 PEM 文件路径，收到 ${positional.length} 个位置参数`,
      pemPath: null,
      require: requirePin,
    };
  }
  return { pemPath: positional[0] || null, require: requirePin };
}

function readPem(pemPath) {
  if (pemPath) return fs.readFileSync(pemPath, 'utf8');
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
  const parsed = parseArgs(process.argv.slice(2));
  if (parsed.error) {
    console.error(`[login-key-pin] ${parsed.error}`);
    process.exit(2);
  }
  // 强制钉扎：开关或环境变量任一为真即生效（CI 的发布构建传开关，
  // 手工构建/编排侧可只用环境变量，两条入口口径一致）
  const requirePin = parsed.require || process.env.REQUIRE_LOGIN_KEY_PIN === 'true';
  const pem = readPem(parsed.pemPath).trim();
  if (!pem) {
    if (requirePin) {
      console.error(
        '[login-key-pin] 要求钉扎（--require / REQUIRE_LOGIN_KEY_PIN=true）但未提供 ' +
          'LOGIN_ECDH_PRIVATE_KEY：拒绝产出未钉扎的前端包与镜像。' +
          '配置该 secret（或去掉强制开关，明确接受不钉扎）后重试。'
      );
      process.exit(1);
    }
    // 空输出：调用方捕获后 build-arg 为空，镜像不做钉扎（本地/未配置静态密钥的部署）
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
