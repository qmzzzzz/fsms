#!/usr/bin/env node
/**
 * 数据级回滚演练（本地/隔离环境）
 *
 * 说明：
 * - 使用 Node 原生 zlib 生成 .ndjson.gz 快照，避免依赖 mongodump/mongorestore；
 * - 快照仍包含 BSON 兼容的 EJSON，ObjectId/Date 可无损还原；
 * - 默认只演练 DRILL/SHADOW 库。源库带 --apply-source 才允许清空回滚，
 *   避免误连生产库造成破坏。
 *
 * 评价报告 #21（破坏性脚本护栏）/
 * - 库名白名单（**fail-closed**）：--apply-source 只允许作用于显式列入
 *   ALLOWED_SOURCE_DB 白名单的库。**未设置白名单即拒绝执行**——原先未设置时
 *   等于不校验，与「默认安全、显式放开」相反，已修正；
 * - 目标库回显：执行前打印实际连接的数据库名，人工核对一眼可辨；
 * - 二次确认：--apply-source 需再传 --yes 才真正落斧（CI 里显式带 --yes）；
 * - **顺序纪律**：--yes 与白名单两条护栏都在 `mongoose.connect` **之前**
 *   求值，被拒绝的执行不向目标库发起任何 TCP/鉴权握手（与同族脚本同序）。
 */

require('dotenv').config();
// <NAME>_FILE 部署下必须在此回填，否则下面直读的 MONGODB_URI 是空串 ⇒ 演练开局即失败
// （不变量见 src/tests/config/scriptSecretHydration.test.js）。
require('../src/config/secrets').hydrateSecretsFromFiles();

const fs = require('fs/promises');
const fsSync = require('fs');
const path = require('path');
const zlib = require('zlib');
const crypto = require('crypto');
const mongoose = require('mongoose');
// 快照格式层拆到 rollbackSnapshot（体积棘轮批）：加解密流与 EJSON 编解码在彼处；
// 直接操作集合的 backupCollection/restoreCollection 留在本文件（与护栏同文件过门禁）。
const { pipeline } = require('stream/promises');
const { Readable, Transform, Writable } = require('stream');
const {
  BACKUP_MAGIC,
  GCM_IV_LEN,
  GCM_TAG_LEN,
  backupKey,
  createSnapshotDecryptStream,
  createSnapshotDocStream,
  toSerializable,
  fromSerializable,
} = require('./rollbackSnapshot');

// 破坏性操作护栏（fail-closed 库名白名单），与同族脚本共用同一份声明。
// dbNameFromUri / hostFromUri 供"护栏前移"用：库名/主机必须从 URI 解析，
// 不能取 connect 之后的 mongoose.connection.name（那正是"护栏晚于 connect"的来源）。
const { assertApplyAllowed, dbNameFromUri, hostFromUri } = require('./destructiveGuard');
const { hardenPath } = require('../src/utils/filePermission');

const COLLECTIONS = ['users', 'roles', 'permissions', 'auditlogs'];

// 快照加密/流式快照/回灌的实现整体在 ./rollbackSnapshot（体积棘轮批拆出）：
// 文件格式、加解密流、EJSON 编解码与两个集合级操作都在那里；本文件只保留
// 演练编排（参数解析、护栏、连接与报告）。

function parseArgs(argv) {
  const args = {
    applySource: false,
    confirmYes: false,
    backupDir: path.join('backups', 'rollback-drill'),
    errors: [],
  };
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (token === '--apply-source') {
      args.applySource = true;
      continue;
    }
    if (token === '--yes') {
      args.confirmYes = true;
      continue;
    }
    if (token === '--backup-dir') {
      const value = argv[index + 1];
      // 原实现取 argv[index + 1] 却不消耗它：`--backup-dir --apply-source`
      // 会把目录名设成字面量「--apply-source」（mkdir 造出一个垃圾目录），
      // 同时 applySource 仍被置真——一次输入同时踩中「设置没生效」和「意外落斧」。
      // 值缺失或以 -- 开头一律按未提供处理并报错，不猜。
      if (!value || value.startsWith('--')) {
        args.errors.push('--backup-dir 缺少目录参数');
        // 值槽被一个开关形态的 token 占掉之后，后面的 token 边界已经不可信：
        // `--backup-dir --apply-source` 里 --apply-source 到底是「目录名」还是
        // 「落斧开关」，只有操作者本人知道。此处停止解析、不再猜——
        // 继续往下读会让报告里出现 applySource: true，而这次调用本来就该整体作废。
        break;
      }
      args.backupDir = value;
      index += 1;
      continue;
    }
    args.errors.push(
      `未知参数：「${token}」（本脚本只接受 --apply-source / --yes / --backup-dir <目录>）`
    );
  }
  return args;
}

/** #21 / 源库白名单——生产库名必须显式列入才允许 --apply-source
 *
 * 【修复】原实现为 fail-open：
 *   `if (allowList.length > 0 && !allowList.includes(dbName))`
 * 未设置 ALLOWED_SOURCE_DB 时 allowList 为空 → 条件恒假 → **白名单形同不存在**，
 * 与函数注释承诺的「默认安全、显式放开」相反。现改用共享护栏（fail-closed）：
 * 未设置白名单即拒绝执行。
 */
function assertSourceDbAllowed(dbName, host) {
  return assertApplyAllowed({
    scriptName: 'run-rollback-drill.js',
    dbName,
    host,
    apply: true,
  });
}

/** 回灌单批大小：流式解析下内存里有界的只是一批 replaceOne 操作 */
const RESTORE_BATCH_DOCS = 1000;

async function backupCollection(collection, file) {
  // 审计 P2（2026-11-17）：原实现 `find({}).toArray()` 把整集合一次性载入内存，
  // 再经 JSON.stringify / gzipSync / AES 各复制一份，GB 级 users/auditlogs 的峰值
  // 内存约为集合体积的数倍，OOM 即演练中断。改为 cursor 逐条序列化 → 流式 gzip →
  // 流式 AES-256-GCM → 落盘：内存里有界的只是"一条文档 + 各段流缓冲"
  // （驱动游标单批拉取另受服务端 16MB 消息上限约束）。
  // 明文由「整体 JSON 数组」改为 NDJSON（每行一个 EJSON 文档），.ndjson.gz 后缀
  // 从此名副其实；restoreCollection 同步流式消费，并兼容旧数组快照。
  const iv = crypto.randomBytes(GCM_IV_LEN);
  const cipher = crypto.createCipheriv('aes-256-gcm', backupKey(), iv);
  const out = fsSync.createWriteStream(file, { mode: 0o600 });
  // 文件布局与整块加密版完全一致（magic | iv | authTag(16) | 密文），独立按格式
  // 校验的 ops-e2e journey 与旧快照都不受影响。流式加密的 authTag 要到 final()
  // 才产出：先写 16 字节占位，落盘完成后回填（见本函数末尾）。
  out.write(BACKUP_MAGIC);
  out.write(iv);
  out.write(Buffer.alloc(GCM_TAG_LEN));
  // 快照含 users / auditlogs 明文 PII：先 gzip（体积）再 AES-256-GCM（机密性 + 完整性）。
  // 顺序不能反——先加密再压缩几乎压不动。两步都在流上，顺序由管道表达。
  let count = 0;
  await pipeline(
    Readable.from(collection.find({})),
    new Transform({
      objectMode: true,
      transform(doc, _enc, cb) {
        count += 1;
        cb(null, JSON.stringify(toSerializable(doc)) + '\n');
      },
    }),
    zlib.createGzip(),
    cipher,
    // 末端落盘用 Writable 而不是无 yield 的 async generator（require-yield）：
    // 「只消费不产出」的阶段本就是 Writable 的语义。
    new Writable({
      async write(chunk, _enc, cb) {
        // 磁盘慢时不让上游无界堆积
        if (!out.write(chunk)) await new Promise((resolve) => out.once('drain', resolve));
        cb();
      },
      final(cb) {
        out.end();
        cb();
      },
    })
  );
  // 回填真实 authTag（覆盖占位）：管道结束时 cipher.final() 已执行，tag 可用
  const handle = await fs.open(file, 'r+');
  try {
    await handle.write(cipher.getAuthTag(), 0, GCM_TAG_LEN, BACKUP_MAGIC.length + GCM_IV_LEN);
  } finally {
    await handle.close();
  }
  // 文件必须是 0600（Windows 走 ACL 收紧）：mode 只在创建时生效，已有文件由 hardenPath 兜底。
  hardenPath(file, { isDir: false, log: (m) => console.warn(m) });
  return count;
}

async function restoreCollection(collection, file) {
  // 流式回灌，与流式快照对称。旧实现整文件读入 → 整段解密 → gunzipSync →
  // JSON.parse → 整表建 bulkWrite 操作数组，GB 级快照会把回灌段同样打爆——
  // 而回灌发生在 deleteMany **之后**，这里的 OOM 是真正丢数据的方向，不是演练中断。
  // 改为：流式解密 → gunzip → 逐条解析 → 每满 RESTORE_BATCH_DOCS 条 bulkWrite 一批。
  //
  // 「认证失败不落库」必须保留：GCM 的认证只在流末 final() 完成，若边解密边写库，
  // 被篡改的快照会先落库、后报错。因此两遍走——第一遍只解密+解压（吞掉明文，
  // 不写库）把认证跑完；第二遍在认证通过后才真正回灌。内存两遍都有界，
  // 代价只是多一次 CPU 解密/解压，对演练脚本可以接受。
  let plain = false;
  await pipeline(
    fsSync.createReadStream(file),
    createSnapshotDecryptStream(() => {
      plain = true;
    }),
    zlib.createGunzip(),
    // 只为把流走完：GCM 认证在解密流的 flush/final() 里完成。
    // 用 Writable 表达「只消费不产出」的吞流段（见 backupCollection）。
    new Writable({
      write(_chunk, _enc, cb) {
        cb();
      },
    })
  );
  // 无魔数 ⇒ 改造前留下的明文快照。仍允许回灌（否则存量备份直接作废），
  // 但必须显式告警：这类文件意味着 PII 曾经以明文落过盘，属于需要处置的遗留物。
  if (plain) {
    console.warn(
      `⚠ 快照「${path.basename(file)}」是改造前的**未加密**格式（无 FSMSBK1 魔数），` +
        '本次按明文回灌。回灌完成后请立即删除该文件并核查其历史副本。'
    );
  }

  let count = 0;
  let batch = [];
  const flushBatch = async () => {
    if (batch.length === 0) return;
    const ops = batch.map(({ _id, ...rest }) => ({
      replaceOne: { filter: { _id }, replacement: rest, upsert: true },
    }));
    await collection.bulkWrite(ops, { ordered: false });
    count += ops.length;
    batch = [];
  };
  await pipeline(
    fsSync.createReadStream(file),
    createSnapshotDecryptStream(() => {}),
    zlib.createGunzip(),
    createSnapshotDocStream(),
    // 逐条攒批的回灌段：同样是「只消费不产出」的 Writable 语义。
    new Writable({
      objectMode: true,
      async write(doc, _enc, cb) {
        batch.push(doc);
        if (batch.length >= RESTORE_BATCH_DOCS) await flushBatch();
        cb();
      },
    })
  );
  await flushBatch();
  return count;
}

/**
 * **顺序纪律**：--yes 与库名白名单两条护栏必须在**任何** TCP/鉴权握手之前求值。
 *
 * 原实现是「connect → 打印目标库 → 校验 --yes → 校验白名单」⇒ 一次"被拒绝的执行"
 * 仍然对目标库（可能就是生产库）完成了连接；库不可达时脚本卡在 30s serverSelection
 * 重试里，运维看到的是"脚本挂死"而不是"被 fail-closed 拦下"。
 * 同族脚本 fix-token-blacklist-index.js 早已是这个顺序（见 destructiveGuardOrder.test.js）。
 *
 * 抽成独立函数有两个理由：① 让"护栏先于连接"在源码顺序上一目了然（静态门禁判的就是这个顺序）；
 * ② 主 IIFE 的圈复杂度贴着 lint 上限，护栏分支不能再内联进去。
 * 库名/主机从 URI 解析——护栏前移后 connect 尚未发生，拿不到 connection.name。
 *
 * @returns {void} 通过则正常返回；不通过直接 process.exit(2)
 */
function assertDrillGuards({ applySource, confirmYes, uri }) {
  const targetDbName = dbNameFromUri(uri);
  const targetHost = hostFromUri(uri);

  // 快照模式同样要过白名单：它虽然不写库，但会把 users / auditlogs 全量导出到
  // 本地 gzip。默认 URI 指向生产时，一次"只看一眼"的演练就是一次 PII 落地。
  // 因此库名白名单（ALLOWED_SOURCE_DB）对两种模式都必需；--yes 只约束写路径。
  if (!assertSourceDbAllowed(targetDbName, targetHost)) {
    process.exit(2);
  }

  if (applySource && !confirmYes) {
    console.error(
      `错误：--apply-source 将对库「${targetDbName || '(未解析出库名)'}」执行 deleteMany + 回灌，` +
        `需再传 --yes 确认。如非预期请立即中断。`
    );
    process.exit(2);
  }
}

/** 连接后把 URI 解析值与实际连接库交叉核对（URI 写的是意图，connection.name 是事实） */
function warnIfDbNameMismatch(intended, actual) {
  if (intended && intended !== actual) {
    console.warn(`⚠ URI 解析出的库名「${intended}」与实际连接库「${actual}」不一致，请人工核对。`);
  }
}

if (require.main === module) {
  (async () => {
    const { applySource, confirmYes, backupDir, errors } = parseArgs(process.argv.slice(2));
    if (errors.length > 0) {
      console.error('参数不合法，拒绝执行（未做任何变更）：');
      for (const e of errors) console.error(`  ✗ ${e}`);
      process.exit(2);
    }
    const uri = process.env.MONGODB_URI;
    if (!uri) {
      console.error('错误：必须提供 MONGODB_URI');
      process.exit(2);
    }

    // 顺序纪律：护栏先于 connect（实现与理由见 assertDrillGuards 注释）。
    assertDrillGuards({ applySource, confirmYes, uri });

    await fs.mkdir(backupDir, { recursive: true, mode: 0o700 });
    hardenPath(backupDir, { isDir: true, log: (m) => console.warn(m) });
    console.warn(
      `快照目录「${backupDir}」已用 AES-256-GCM 加密（密钥派生自 AES_SECRET_KEY）；` +
        '仍请在演练结束后立即删除，勿拷贝到共享盘或提交到仓库——' +
        '加密只保护"文件离开本机"这一环，不保护本机上的密钥。'
    );
    await mongoose.connect(uri);
    const database = mongoose.connection.db;
    const dbName = mongoose.connection.name;
    // 连接后再回显**实际**库名，并与 URI 解析值交叉核对
    // （URI 写的是意图，connection.name 是事实；不一致就是配错了）。
    console.log(`>>> 目标数据库：${dbName}（--apply-source=${applySource}）`);
    warnIfDbNameMismatch(dbNameFromUri(uri), dbName);
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    // encrypted 进 manifest：回灌侧据此判断"该文件本应带魔数"，
    // 也让演练留档本身能回答"这次备份到底加没加密"。
    const manifest = { uri: dbName, timestamp, encrypted: true, collections: {} };

    for (const name of COLLECTIONS) {
      const source = database.collection(name);
      // 后缀保留 .ndjson.gz 是为了让既有清理脚本/文档仍能按老模式匹配，
      // 再追加 .enc 标明这是密文（不是能直接 gunzip 的 gzip）。
      const backupFile = path.join(backupDir, `${name}-${timestamp}.ndjson.gz.enc`);
      manifest.collections[name] = { file: path.basename(backupFile), documents: 0 };
      manifest.collections[name].documents = await backupCollection(source, backupFile);
    }

    const manifestFile = path.join(backupDir, `manifest-${timestamp}.json`);
    await fs.writeFile(manifestFile, JSON.stringify(manifest, null, 2), { mode: 0o600 });
    hardenPath(manifestFile, { isDir: false, log: (m) => console.warn(m) });

    if (applySource) {
      for (const name of COLLECTIONS) {
        const file = path.join(backupDir, manifest.collections[name].file);
        await database.collection(name).deleteMany({});
        await restoreCollection(database.collection(name), file);
        // 「回灌成了多少条」必须由库回答，不能沿用脚本自己的读数。
        // 原实现丢弃 restoreCollection 的返回值，manifest 里的 documents 是
        // **删除之前**的计数——于是：快照之后、清空之前写入的文档被静默销毁，
        // 报告上仍是「N 条已回滚」；bulkWrite 漏写、_id 冲突、集合被别的进程
        // 清空，全都印一个 exit 0。演练的全部意义就是「回滚这条路真走得通」，
        // 一个不自查的回滚演练比没有演练更糟。
        manifest.collections[name].restored = await database.collection(name).countDocuments({});
      }
      manifest.restoreVerified = COLLECTIONS.every(
        (name) => manifest.collections[name].restored === manifest.collections[name].documents
      );
      manifest.totalSnapshotDocuments = COLLECTIONS.reduce(
        (sum, name) => sum + manifest.collections[name].documents,
        0
      );
      // 空快照：0 === 0 会让上面的比对「验证通过」，但这次演练什么都没验。
      // 单独回显，避免演练记录里出现一条凭空的绿灯。
      if (manifest.restoreVerified && manifest.totalSnapshotDocuments === 0) {
        console.warn('⚠ 各集合快照均为 0 条：本次清空/回灌没有回滚任何数据，不构成回滚能力证明。');
      }
      // 验证结果补写回 manifest：它必须先于清空落盘（作为恢复抓手），
      // 再随结论更新一次，让落盘产物与 stdout 报告同口径。
      await fs.writeFile(manifestFile, JSON.stringify({ ...manifest, applySource }, null, 2), {
        mode: 0o600,
      });
      hardenPath(manifestFile, { isDir: false, log: (m) => console.warn(m) });
    }

    console.log(JSON.stringify({ ...manifest, applySource }, null, 2));
    await mongoose.connection.close();
    if (applySource && manifest.restoreVerified === false) {
      process.exit(1);
    }
  })().catch(async (error) => {
    console.error(`回滚演练失败：${error.message}`);
    if (mongoose.connection.readyState !== 0) await mongoose.connection.close();
    process.exit(1);
  });
}

// 同型：导出纯函数供单测（不触发破坏性 IIFE），锁定 ObjectId/Date 往返无损
// 与参数解析的严格性（未知参数/缺值必须报错，不能静默变成一次真落斧）。
module.exports = { toSerializable, fromSerializable, parseArgs };
