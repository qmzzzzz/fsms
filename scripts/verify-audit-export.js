#!/usr/bin/env node
/**
 * 审计日志 CSV 导出的离线校验脚本
 *
 * 用法:
 *   node scripts/verify-audit-export.js <audit-logs-export.csv> [--allow-no-signature]
 *
 * 环境变量:
 *   HMAC_SECRET（或 HMAC_SECRET_FILE）—— 与审计链 hmac、manifest 签名共用。
 *   未配置时只能校验字节自洽，不能证明清单出自服务端，退出码 2。
 *
 * 校验三件事:
 *   ① csvSha256 / csvBytes —— 对交付文件的字节复算（manifest 行不参与）；
 *   ② sha256 / chainRecords —— 从 CSV 的 hash 列复算链摘要，核对覆盖面；
 *   ③ manifest.signature —— HMAC-SHA256 覆盖 generatedAt、两个摘要与全部声明字段。
 *
 * 为什么必须验 ③：①② 都是无密钥摘要，任何拿到文件的人都能在改完记录后重算。
 * 只有 HMAC 能证明清单出自持有 HMAC_SECRET 的服务端；没有它，篡改者可以
 * 改 CSV、重算链哈希、再改 manifest 的两个摘要，①②照样全绿。
 *
 * 退出码（与 verify-audit-chain.js 同口径）:
 *   0 = 字节、链摘要与 HMAC 签名全部通过
 *   1 = 发现不一致（文件/清单被改动，或签名密钥不同）
 *   2 = 校验不完整，不得当作"文件是真的"：缺 manifest、未签名（未显式放行）、
 *       带签名但本机没有 HMAC_SECRET、签名算法/版本未知
 */

require('dotenv').config();
// 容器里密钥只以 <NAME>_FILE 挂载，必须在此回填（同 verify-audit-chain.js）
require('../src/config/secrets').hydrateSecretsFromFiles();

const crypto = require('crypto');
const fs = require('fs');
const {
  MANIFEST_LINE_PREFIX,
  MANIFEST_SIGNATURE_VERSION,
  manifestSigningPayload,
} = require('../src/services/auditExportService');
const { getHmacSecret } = require('../src/utils/auditChain');

// 外部字面量：表头是交付格式的一部分，校验端不能 import 被测常量来自证
const EXPECTED_HEADER =
  'timestamp,action,category,username,ip,path,statusCode,success,riskLevel,prevHash,hash';

const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest('hex');

const fail = (message) => {
  console.error(`✗ ${message}`);
  process.exit(1);
};

const incomplete = (message) => {
  console.error(`⚠ ${message}`);
  process.exit(2);
};

const usage = (message) => {
  if (message) console.error(`错误：${message}`);
  console.error(
    '用法：node scripts/verify-audit-export.js <audit-logs-export.csv> [--allow-no-signature]'
  );
  process.exit(2);
};

function parseArgs(argv) {
  const out = { file: null, allowNoSignature: false };
  for (const arg of argv) {
    if (arg === '--allow-no-signature') {
      out.allowNoSignature = true;
      continue;
    }
    if (arg.startsWith('-')) usage(`未知参数 ${arg}`);
    if (out.file) usage(`只接受一个 CSV 文件，多余的参数：${arg}`);
    out.file = arg;
  }
  if (!out.file) usage('缺少 CSV 文件路径');
  return out;
}

/** 把交付体拆成「CSV 字节」与「manifest 对象」；manifest 是文件最后一行的注释。 */
function splitExport(raw) {
  const marker = Buffer.from(`\n${MANIFEST_LINE_PREFIX}`, 'utf8');
  const at = raw.lastIndexOf(marker);
  if (at < 0) return null;
  const manifestStart = at + 1 + Buffer.byteLength(MANIFEST_LINE_PREFIX, 'utf8');
  let manifest;
  try {
    manifest = JSON.parse(raw.subarray(manifestStart).toString('utf8').trim());
  } catch (err) {
    incomplete(`manifest 行不是合法 JSON：${err.message}`);
  }
  // csvPart 含最后一条数据行的换行，不含 manifest 行（与导出端 feedCsv 口径一致）
  return { csvPart: raw.subarray(0, at + 1), manifest };
}

/** RFC 4180 解析（支持引号转义与字段内换行；CRLF 的 CR 不作为内容） */
function parseCsv(text) {
  const rows = [];
  let row = [];
  let field = '';
  let inQuotes = false;
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];
    if (inQuotes) {
      if (ch === '"' && text[i + 1] === '"') {
        field += '"';
        i += 1;
      } else if (ch === '"') {
        inQuotes = false;
      } else {
        field += ch;
      }
      continue;
    }
    if (ch === '"') inQuotes = true;
    else if (ch === ',') {
      row.push(field);
      field = '';
    } else if (ch === '\n') {
      row.push(field);
      rows.push(row);
      row = [];
      field = '';
    } else if (ch !== '\r') {
      field += ch;
    }
  }
  if (inQuotes) fail('CSV 引号未闭合，文件结构已损坏');
  if (field !== '' || row.length > 0) {
    row.push(field);
    rows.push(row);
  }
  return rows;
}

function verifyFileDigest(csvPart, manifest) {
  const actual = sha256(csvPart);
  if (actual !== manifest.csvSha256) {
    fail(`文件字节摘要不匹配（声明 ${manifest.csvSha256}，实算 ${actual}）——文件被改动或截断`);
  }
  if (csvPart.length !== manifest.csvBytes) {
    fail(`文件字节数不匹配（声明 ${manifest.csvBytes}，实际 ${csvPart.length}）`);
  }
}

function verifyChainDigest(csvPart, manifest) {
  const rows = parseCsv(csvPart.toString('utf8'));
  if (rows.length === 0 || rows[0].join(',') !== EXPECTED_HEADER) {
    fail('CSV 表头与交付格式不一致（可能是改列/改序/非本系统导出）');
  }
  const header = rows[0];
  const data = rows.slice(1);
  if (data.length !== manifest.recordCount) {
    fail(`记录数不匹配（manifest ${manifest.recordCount}，实际 ${data.length}）`);
  }
  const hashIndex = header.indexOf('hash');
  const hashes = data.map((cells) => {
    if (cells.length !== header.length) fail(`数据行列数不匹配（期望 ${header.length}）`);
    return cells[hashIndex];
  });
  const chained = hashes.filter(Boolean);
  if (chained.length !== manifest.chainRecords) {
    fail(`链覆盖条数不匹配（manifest ${manifest.chainRecords}，实际 ${chained.length}）`);
  }
  if (sha256(Buffer.from(chained.join(''), 'utf8')) !== manifest.sha256) {
    fail('链摘要不匹配——CSV 中的 hash 列与 manifest 声明不一致');
  }
}

function verifySignature(manifest, allowNoSignature) {
  const { signature, ...signed } = manifest;
  if (!signature) {
    if (allowNoSignature) {
      console.warn(
        '⚠ manifest 未签名（--allow-no-signature 已放行）：只能证明文件自洽，来源不可证明'
      );
      return;
    }
    incomplete(
      'manifest 未签名，无法证明文件出自服务端（旧版导出确需放行加 --allow-no-signature）'
    );
  }
  if (signature.version !== MANIFEST_SIGNATURE_VERSION || signature.algorithm !== 'hmac-sha256') {
    incomplete(`manifest 签名方案未知（version=${signature.version}，${signature.algorithm}）`);
  }
  const secret = getHmacSecret();
  if (!secret) {
    incomplete('manifest 带签名，但本机未配置 HMAC_SECRET，无法验证（拒绝当作已验过）');
  }
  const expected = crypto
    .createHmac('sha256', secret)
    .update(manifestSigningPayload(signed), 'utf8')
    .digest();
  const actual = Buffer.from(String(signature.value || ''), 'hex');
  if (actual.length !== expected.length || !crypto.timingSafeEqual(actual, expected)) {
    fail(`manifest 签名不匹配（keyId=${signature.keyId}）——文件/清单被改动，或签名密钥不同`);
  }
}

function verifyGeneratedAt(manifest) {
  const issuedAt = Date.parse(manifest.generatedAt);
  if (!Number.isFinite(issuedAt)) fail('manifest.generatedAt 不是合法时间');
  if (issuedAt - Date.now() > 5 * 60 * 1000) {
    fail('manifest.generatedAt 在未来超过 5 分钟——签发端时钟异常或清单被伪造');
  }
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  let raw;
  try {
    raw = fs.readFileSync(args.file);
  } catch (err) {
    usage(`无法读取 ${args.file}：${err.message}`);
  }

  const split = splitExport(raw);
  if (!split) incomplete('未找到 manifest 尾行（文件不是本系统导出，或尾行被删除）');
  const { csvPart, manifest } = split;

  verifyFileDigest(csvPart, manifest);
  verifyChainDigest(csvPart, manifest);
  verifyGeneratedAt(manifest);
  verifySignature(manifest, args.allowNoSignature);

  console.log(`✓ 校验通过：${args.file}`);
  console.log(
    `  记录 ${manifest.recordCount} 条（链上 ${manifest.chainRecords} 条），` +
      `文件 ${manifest.csvBytes} 字节，签发于 ${manifest.generatedAt}`
  );
  console.log(
    manifest.signature
      ? `  manifest HMAC 已验证（keyId=${manifest.signature.keyId}，版本 v${manifest.signature.version}）`
      : '  manifest 未签名（已显式放行）'
  );
  if (manifest.truncated) console.log('  注意：导出为截断结果，仅覆盖筛选范围的前若干条');
  if (manifest.chainCoverageIncomplete) console.log('  注意：并非所有导出记录都带有链 hash');
}

main();
