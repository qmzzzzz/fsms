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
 * 评价报告 #21（破坏性脚本护栏）/ M-08：
 * - 库名白名单（**fail-closed**）：--apply-source 只允许作用于显式列入
 *   ALLOWED_SOURCE_DB 白名单的库。**未设置白名单即拒绝执行**——原先未设置时
 *   等于不校验，与「默认安全、显式放开」相反，已修正；
 * - 目标库回显：执行前打印实际连接的数据库名，人工核对一眼可辨；
 * - 二次确认：--apply-source 需再传 --yes 才真正落斧（CI 里显式带 --yes）；
 * - **顺序纪律（M-08）**：--yes 与白名单两条护栏都在 `mongoose.connect` **之前**
 *   求值，被拒绝的执行不向目标库发起任何 TCP/鉴权握手（与同族脚本同序）。
 */

require('dotenv').config();

const fs = require('fs/promises');
const path = require('path');
const zlib = require('zlib');
const mongoose = require('mongoose');

// M-08：破坏性操作护栏（fail-closed 库名白名单），与同族脚本共用同一份声明。
// dbNameFromUri / hostFromUri 供"护栏前移"用：库名/主机必须从 URI 解析，
// 不能取 connect 之后的 mongoose.connection.name（那正是"护栏晚于 connect"的来源）。
const { assertApplyAllowed, dbNameFromUri, hostFromUri } = require('./destructiveGuard');

const COLLECTIONS = ['users', 'roles', 'permissions', 'auditlogs'];

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

/** #21 / M-08：源库白名单——生产库名必须显式列入才允许 --apply-source
 *
 * 【M-08 修复】原实现为 fail-open：
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

async function backupCollection(collection, file) {
  const docs = await collection.find({}).toArray();
  await fs.writeFile(file, zlib.gzipSync(JSON.stringify(docs.map(toSerializable))));
  return docs.length;
}

async function restoreCollection(collection, file) {
  const raw = await fs.readFile(file);
  const docs = JSON.parse(zlib.gunzipSync(raw).toString('utf8')).map(fromSerializable);
  if (docs.length === 0) return 0;
  const prepared = docs.map((doc) => {
    const { _id, ...rest } = doc;
    return { replaceOne: { filter: { _id }, replacement: rest, upsert: true } };
  });
  await collection.bulkWrite(prepared, { ordered: false });
  return docs.length;
}

/**
 * M-08 **顺序纪律**：--yes 与库名白名单两条护栏必须在**任何** TCP/鉴权握手之前求值。
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
  if (!applySource) return;

  const targetDbName = dbNameFromUri(uri);
  const targetHost = hostFromUri(uri);

  if (!confirmYes) {
    console.error(
      `错误：--apply-source 将对库「${targetDbName || '(未解析出库名)'}」执行 deleteMany + 回灌，` +
        `需再传 --yes 确认。如非预期请立即中断。`
    );
    process.exit(2);
  }
  if (!assertSourceDbAllowed(targetDbName, targetHost)) {
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

    // M-08 顺序纪律：护栏先于 connect（实现与理由见 assertDrillGuards 注释）。
    assertDrillGuards({ applySource, confirmYes, uri });

    await fs.mkdir(backupDir, { recursive: true });
    await mongoose.connect(uri);
    const database = mongoose.connection.db;
    const dbName = mongoose.connection.name;
    // 连接后再回显**实际**库名，并与 URI 解析值交叉核对
    // （URI 写的是意图，connection.name 是事实；不一致就是配错了）。
    console.log(`>>> 目标数据库：${dbName}（--apply-source=${applySource}）`);
    warnIfDbNameMismatch(dbNameFromUri(uri), dbName);
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const manifest = { uri: dbName, timestamp, collections: {} };

    for (const name of COLLECTIONS) {
      const source = database.collection(name);
      const backupFile = path.join(backupDir, `${name}-${timestamp}.ndjson.gz`);
      manifest.collections[name] = { file: path.basename(backupFile), documents: 0 };
      manifest.collections[name].documents = await backupCollection(source, backupFile);
    }

    const manifestFile = path.join(backupDir, `manifest-${timestamp}.json`);
    await fs.writeFile(manifestFile, JSON.stringify(manifest, null, 2));

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
      await fs.writeFile(manifestFile, JSON.stringify({ ...manifest, applySource }, null, 2));
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

// E-02 同型：导出纯函数供单测（不触发破坏性 IIFE），锁定 ObjectId/Date 往返无损
// 与参数解析的严格性（未知参数/缺值必须报错，不能静默变成一次真落斧）。
module.exports = { toSerializable, fromSerializable, parseArgs };
