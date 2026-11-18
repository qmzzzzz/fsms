'use strict';

/**
 * 快照格式层（run-rollback-drill 的实现层，体积棘轮批拆出）：
 * 加密/解密流、EJSON 编解码与 NDJSON/数组两代明文解析。
 * 集合级操作（backupCollection/restoreCollection）留在演练脚本内——
 * 它们是直接操作集合的破坏性面，必须与护栏同文件（destructiveGuardOrder 门禁）。
 *
 * 文件格式（自带魔数，便于与旧明文快照区分）：
 *   "FSMSBK1\n" (8) | iv (12) | authTag (16) | AES-256-GCM 密文
 * 密文解开后是 gzip：新快照为 NDJSON（每行一个 EJSON 文档，流式逐条写出）；
 * 改造前的旧快照为整体 JSON 数组（回灌侧两代都认，见 createSnapshotDocStream）。
 * 密钥由 `AES_SECRET_KEY` 经 sha256 派生（与 `src/utils/encryption.js` 的
 * AESCipher 同一派生方式），因此运维只需要记住一把主密钥。
 *
 * **fail-closed**：缺主密钥时直接退出，绝不退回明文写出——
 * 「加密配置缺失就悄悄不加密」正是这条 P1 的成因。
 */

const crypto = require('crypto');
const mongoose = require('mongoose');
const { Transform } = require('stream');

// 文件型密钥水合必须先于 AES_SECRET_KEY 的首次读取（scriptSecretHydration 门禁）：
// 本模块被演练脚本 require，水合幂等，重复调用无害。
require('../src/config/secrets').hydrateSecretsFromFiles();

const BACKUP_MAGIC = Buffer.from('FSMSBK1\n', 'utf8');
const GCM_IV_LEN = 12;
const GCM_TAG_LEN = 16;

function backupKey() {
  // 惰性取 config：require 期不碰 config 的校验逻辑，缺密钥时只在真正写/读备份时暴露
  const secret = process.env.AES_SECRET_KEY || require('../src/config').aesSecret;
  if (!secret) {
    console.error(
      '错误：缺少 AES_SECRET_KEY，拒绝写出/读取 PII 快照。\n' +
        '  本脚本不再产出明文备份（gzip 不是加密）。请先配置 AES_SECRET_KEY（openssl rand -hex 32）。'
    );
    process.exit(2);
  }
  return crypto.createHash('sha256').update(String(secret)).digest();
}

/**
 * 快照密文字节流 → gzip 明文字节流（流式解密）。
 *
 * 文件头与整块加密版一致：`FSMSBK1\n` | iv(12) | authTag(16) | AES-256-GCM 密文。
 * 无魔数 = 改造前的**明文** gzip 快照：原样透传，并回调 onPlain 让调用方显式告警
 * （认不出魔数不等于可以静默当明文用）。GCM 的认证要到流末 final() 才完成——
 * 调用方必须先走完一遍校验流、再消费明文，否则被篡改的快照会先落库、后报错。
 */
function createSnapshotDecryptStream(onPlain) {
  let header = Buffer.alloc(0);
  let decipher = null;
  let plain = false;
  return new Transform({
    transform(chunk, _enc, cb) {
      try {
        if (plain) {
          this.push(chunk);
          return cb();
        }
        if (!decipher) {
          header = Buffer.concat([header, chunk]);
          if (header.length < BACKUP_MAGIC.length) return cb(); // 连魔数都还没读够
          if (!header.subarray(0, BACKUP_MAGIC.length).equals(BACKUP_MAGIC)) {
            plain = true;
            onPlain();
            this.push(header);
            header = null;
            return cb();
          }
          if (header.length < BACKUP_MAGIC.length + GCM_IV_LEN + GCM_TAG_LEN) return cb();
          const iv = header.subarray(BACKUP_MAGIC.length, BACKUP_MAGIC.length + GCM_IV_LEN);
          decipher = crypto.createDecipheriv('aes-256-gcm', backupKey(), iv, {
            authTagLength: GCM_TAG_LEN,
          });
          decipher.setAuthTag(
            header.subarray(
              BACKUP_MAGIC.length + GCM_IV_LEN,
              BACKUP_MAGIC.length + GCM_IV_LEN + GCM_TAG_LEN
            )
          );
          chunk = header.subarray(BACKUP_MAGIC.length + GCM_IV_LEN + GCM_TAG_LEN);
          header = null;
        }
        this.push(decipher.update(chunk));
        cb();
      } catch (e) {
        cb(e);
      }
    },
    flush(cb) {
      try {
        if (plain) return cb();
        // 头部都没凑齐就结束了：文件被截断，认证无从谈起
        if (!decipher) return cb(new Error('快照文件不完整：不足加密头长度'));
        // GCM 认证失败（密钥不对/密文被改）在这里抛出——不降级、不猜测，直接失败
        this.push(decipher.final());
        cb();
      } catch (e) {
        cb(e);
      }
    },
  });
}

/**
 * 快照 gzip 明文 → 逐条文档（objectMode）。明文两代格式：
 *   旧：整体一个 JSON 数组（整块序列化时代的产物）——探测到首字符 `[` 后整段
 *       缓冲再解析，与它当初的整块产出方式对称；新格式绝不走这条路。
 *   新：NDJSON，每行一个 EJSON 文档——流式逐行解析，内存里有界的只是一行。
 */
function createSnapshotDocStream() {
  let pending = '';
  let arrayText = null;
  return new Transform({
    objectMode: true,
    transform(chunk, _enc, cb) {
      try {
        const text = chunk.toString('utf8');
        if (arrayText !== null) {
          arrayText += text;
          return cb();
        }
        pending += text;
        if (pending.trimStart().startsWith('[')) {
          arrayText = pending;
          pending = '';
          return cb();
        }
        let newlineAt;
        while ((newlineAt = pending.indexOf('\n')) >= 0) {
          const line = pending.slice(0, newlineAt);
          pending = pending.slice(newlineAt + 1);
          if (line.trim()) this.push(fromSerializable(JSON.parse(line)));
        }
        cb();
      } catch (e) {
        cb(e);
      }
    },
    flush(cb) {
      try {
        if (arrayText !== null) {
          for (const doc of JSON.parse(arrayText)) this.push(fromSerializable(doc));
        } else if (pending.trim()) {
          this.push(fromSerializable(JSON.parse(pending)));
        }
        cb();
      } catch (e) {
        cb(e);
      }
    },
  });
}

// BSON 类型安全的快照编解码。驱动返回的文档里 _id/日期是原生 BSON 类型，
// 但 JSON.stringify 会把 ObjectId 退化成 24 位 hex 字符串、Date 退化成 ISO 字符串，
// 于是回灌端拿到 String `_id` 与 String `timestamp`：TTL 索引不再过期、
// `timestamp: { $gte: new Date() }` 之类查询恒空（异常/暴破计数静默 0）。
// ObjectId 用跨 bson 版本稳定的 `_bsontype` 标记识别，Date 用原生 instanceof。
function toSerializable(value) {
  if (value && typeof value === 'object' && value._bsontype === 'ObjectId') {
    return { $oid: value.toString() };
  }
  if (value instanceof Date) {
    return { $date: value.toISOString() };
  }
  if (Array.isArray(value)) return value.map(toSerializable);
  if (value && typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) out[k] = toSerializable(v);
    return out;
  }
  return value;
}

function fromSerializable(value) {
  if (value && typeof value === 'object' && typeof value.$oid === 'string') {
    return new mongoose.Types.ObjectId(value.$oid);
  }
  if (value && typeof value === 'object' && typeof value.$date === 'string') {
    return new Date(value.$date);
  }
  if (Array.isArray(value)) return value.map(fromSerializable);
  if (value && typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) out[k] = fromSerializable(v);
    return out;
  }
  return value;
}

module.exports = {
  BACKUP_MAGIC,
  GCM_IV_LEN,
  GCM_TAG_LEN,
  backupKey,
  createSnapshotDecryptStream,
  createSnapshotDocStream,
  toSerializable,
  fromSerializable,
};
