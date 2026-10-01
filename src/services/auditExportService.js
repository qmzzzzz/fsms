const crypto = require('crypto');
const AuditLog = require('../models/AuditLog');
// 与列表查询共用同一份「按需挂 collation」语义：导出必须与列表同口径，
// 否则带 username 前缀条件时列表能搜到 `ADMIN`、导出却搜不到（默认 collation 下
// `ADMIN` 不落在 `[adm, adn)` 内）。这是正确性问题，不只是性能问题。
const { withCollation } = require('../utils/auditQuery');
const { sanitizeSpreadsheetCell } = require('../utils/helpers');

const EXPORT_HARD_LIMIT = 50000;
const MANIFEST_LINE_PREFIX = '#__MANIFEST__:';
// 表头与数据行必须来自同一份列清单。此前表头是一串字面量、行是另一份数组字面量，
// 两侧各自增删一列都不会报错，只会让导出 CSV 全体列错位——而这份文件是防篡改链的交付凭证。
const EXPORT_CSV_COLUMNS = [
  'timestamp',
  'action',
  'category',
  'username',
  'ip',
  'path',
  'statusCode',
  'success',
  'riskLevel',
  'prevHash',
  'hash',
];
const EXPORT_CSV_HEADER = EXPORT_CSV_COLUMNS.join(',');

const csvEscape = (value) => {
  if (value === null || value === undefined) return '';
  let text;
  if (value instanceof Date) {
    text = value.toISOString();
  } else if (typeof value === 'object') {
    text = JSON.stringify(value);
  } else {
    text = String(value);
  }
  text = sanitizeSpreadsheetCell(text);
  return /[",\n\r]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
};

const exportAuditColumns = (doc, timestamp) =>
  EXPORT_CSV_COLUMNS.map((column) =>
    column === 'timestamp' ? csvEscape(timestamp) : csvEscape(doc[column])
  );

const sendAuditExportHeaders = async (query, res, collation) => {
  const estimatedCount = await withCollation(AuditLog.countDocuments(query), collation);
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="audit-logs-export.csv"');
  res.setHeader('X-Audit-Manifest-Records', String(Math.min(estimatedCount, EXPORT_HARD_LIMIT)));
  if (estimatedCount > EXPORT_HARD_LIMIT) {
    res.setHeader('X-Audit-Truncated', 'true');
  }
};

const streamAuditExport = async (query, res, collation) => {
  // 截断必须由查询自身封顶，不能靠"回调里 close() 游标"。
  // 实测（src/tests/exportTruncationCap.test.js）：mongoose 8 的
  // `cursor.eachAsync(fn)` 里调用 `cursor.close()` **不会停止迭代**——
  // 全部文档照样进回调（它只是关掉游标，既不抛错也不短路）。
  // 于是原实现在命中 5 万条上限之后，仍会把筛选命中的**剩余全部记录**
  // 从 MongoDB 逐条取回、反序列化、再走一遍早退分支：
  // 一次"看起来被截断了"的导出，代价等于全量导出（而 countDocuments 已经先全量数过一遍）。
  // 多取一条（+1）当"是否真的还有后续"的探针 ⇒ truncated 判定精确，且最多多读一条。
  const cursor = withCollation(
    AuditLog.find(query)
      .sort({ _id: 1 })
      .limit(EXPORT_HARD_LIMIT + 1)
      // 排除清单取模型上那一份（-body -params -query -hmac，不含 -hash/-prevHash，
      // 所以下面的链摘要照样读得到 doc.hash）。此前这条腿全字段取回：一次上限导出
      // 会把 5 万条记录的 HMAC 与请求体读进进程，而 xlsx 那条腿早就在用清单了——
      // 两条腿各写一遍排除口径，就是"控制点随时会漂"。
      .select(AuditLog.RESPONSE_EXCLUDE)
      .lean(),
    collation
  ).cursor();
  const counters = { recordCount: 0, startTime: null, endTime: null, truncated: false };
  const hasher = crypto.createHash('sha256');
  // 两个摘要各管一件事，而 manifest 必须说清各自管的是什么：
  //   `sha256`    —— 被导出记录的**链哈希**（`hash` 字段）串联后的摘要，
  //                  证明"这些记录出自审计哈希链"；
  //   `csvSha256` —— **实际写出的 CSV 字节**的摘要，证明"交付的文件没被删改"。
  // 只有前者是不够的：改掉导出文件里任意一个单元格都不影响链摘要，
  // 所以它从来不是"文件未被删改"的凭证（这一点此前被注释说成了签名信息）。
  // 表头行由 controller 用同一个 `EXPORT_CSV_HEADER` 常量写出，故此处一并喂进摘要，
  // 让校验方能对"去掉本 manifest 行之后的整个文件"直接复算。
  let chainRecords = 0;
  let csvBytes = 0;
  const csvHasher = crypto.createHash('sha256');
  const feedCsv = (chunk) => {
    csvHasher.update(chunk, 'utf8');
    csvBytes += Buffer.byteLength(chunk, 'utf8');
  };
  feedCsv(`${EXPORT_CSV_HEADER}\n`);
  const EXPORT_ABORTED = '导出响应中途断开（客户端中断或连接被重置）';
  // 只等 `drain` 是不够的：客户端中断时 `write()` 返回 false 而 drain **永不再来**
  // （探针实测：中断前后 drains 计数一动不动），于是这个 Promise 永不 settle，
  // `eachAsync` 卡死在中间一行——路由既不返回也不抛错，controller 的 catch 出口
  // （logger.error + markResponseAbortedByError）根本走不到。
  //
  // 但"逐行挂监听器"本身也不够：单行约 200 B，远小于 HTTP 的 16 KB highWaterMark
  // ⇒ `write()` 几乎恒返回 true，逐行的 `close`/`error` 监听器在绝大多数行**根本没挂上**，
  // 而已经 settle 的 Promise 上的 `onWriteCb(err)` 是空操作。客户端在第 2 行走掉、
  // 后面 49998 行全部写进死 socket 时，导出照样报成功。
  // 所以断连要按**整个流**的尺度盯：全程一对监听器 + 每行开头查一次。
  let aborted = null;
  const onStreamAbort = (err) => {
    if (!aborted) aborted = err || new Error(EXPORT_ABORTED);
  };
  res.once('close', onStreamAbort);
  res.once('error', onStreamAbort);

  // 背压窗口内的信号（drain 永不到来时要靠这三个收口，见上）
  const writeLine = (line) =>
    new Promise((resolve, reject) => {
      if (aborted || res.destroyed) return reject(aborted || new Error(EXPORT_ABORTED));
      const armed = [];
      const settle = (fn, arg) => {
        // 本模块对 res 只要求 write/once（现有测试传的就是普通对象流），
        // 摘监听器时不能假设它还有 removeListener。不清理则 5 万行会攒一堆监听器。
        if (typeof res.removeListener === 'function') {
          for (const [event, handler] of armed) res.removeListener(event, handler);
          armed.length = 0;
        }
        fn(arg);
      };
      const onDrain = () => settle(resolve);
      const onAbort = (err) => settle(reject, err || new Error(EXPORT_ABORTED));
      const onWriteCb = (err) => {
        if (err) settle(reject, err);
      };
      if (res.write(line, onWriteCb)) return settle(resolve);
      res.once('drain', onDrain);
      armed.push(['drain', onDrain]);
      res.once('close', onAbort);
      armed.push(['close', onAbort]);
      res.once('error', onAbort);
      armed.push(['error', onAbort]);
    });

  try {
    await cursor.eachAsync(async (doc) => {
      if (counters.recordCount >= EXPORT_HARD_LIMIT) {
        // 只有第 LIMIT+1 条（探针）会走到这里；不再 close()，因为没有后续文档可关
        counters.truncated = true;
        return;
      }
      counters.recordCount += 1;
      const timestamp = doc.timestamp instanceof Date ? doc.timestamp : new Date(doc.timestamp);
      if (!counters.startTime || timestamp < counters.startTime) counters.startTime = timestamp;
      if (!counters.endTime || timestamp > counters.endTime) counters.endTime = timestamp;
      if (doc.hash) {
        hasher.update(doc.hash, 'utf8');
        chainRecords += 1;
      }
      const line = `${exportAuditColumns(doc, timestamp).join(',')}\n`;
      feedCsv(line);
      await writeLine(line);
    });
    // 末行 write() 返回 true 只代表字节进了内核缓冲，不代表送达；全部写完后再查一次，
    // 否则"整份文件其实没出去"会被记成一次正常导出（审计侧就再也看不出被中断过）。
    if (aborted) throw aborted;
  } finally {
    if (typeof res.removeListener === 'function') {
      res.removeListener('close', onStreamAbort);
      res.removeListener('error', onStreamAbort);
    }
    // mongoose 的 eachAsync 在回调 reject 时**不会**关游标
    // （lib/helpers/cursor/eachAsync.js 里一处 destroy/close 都没有）
    // ⇒ 中断那一档会把服务端游标留到 10 分钟空闲回收才关。
    if (typeof cursor.close === 'function') {
      try {
        await cursor.close();
      } catch {
        // 关游标失败不得盖掉真正的导出错误
      }
    }
  }

  return {
    ...counters,
    sha256: hasher.digest('hex'),
    chainRecords,
    csvSha256: csvHasher.digest('hex'),
    csvBytes,
  };
};

const buildAuditExportManifest = (counters) => {
  const manifest = {
    recordCount: counters.recordCount,
    startTime: counters.startTime ? counters.startTime.toISOString() : null,
    endTime: counters.endTime ? counters.endTime.toISOString() : null,
    generatedAt: new Date().toISOString(),
    sha256: counters.sha256,
    // 摘要口径必须写在文件里：读到 manifest 的人（取证/审计/合规）要知道该拿什么去复算。
    sha256Scope: '被导出记录的 hash 字段串联后的 sha256（证明记录出自哈希链，不含 CSV 字节）',
    csvSha256: counters.csvSha256,
    csvSha256Scope:
      '实际写出的 CSV 字节的 sha256：表头行 + 全部数据行，不含本 manifest 行；可直接对文件复算',
    csvBytes: counters.csvBytes,
    chainRecords: counters.chainRecords,
  };
  if (counters.truncated) {
    manifest.truncated = true;
    manifest.notice = `导出记录数已达硬上限 ${EXPORT_HARD_LIMIT} 条并截断，请缩小筛选范围后分批导出`;
  }
  // 有记录没有 hash（非链上写入/历史数据）时，链摘要覆盖的条数会少于导出条数。
  // 不点出来的话，"sha256 对得上"就会被当成"整份导出都在链上"——那是句谎话。
  // 顺序要紧：这条必须在截断之后**追加**，否则两个理由同时成立时会互相覆盖，
  // 只剩一条的 manifest 就是在抹掉另一条。
  if (counters.chainRecords < counters.recordCount) {
    manifest.chainCoverageIncomplete = true;
    const gap = `哈希链摘要只覆盖 ${counters.chainRecords}/${counters.recordCount} 条，其余记录无 hash 字段`;
    manifest.notice = manifest.notice ? `${manifest.notice}；${gap}` : gap;
  }
  return manifest;
};

module.exports = {
  buildAuditExportManifest,
  sendAuditExportHeaders,
  streamAuditExport,
  MANIFEST_LINE_PREFIX,
  EXPORT_CSV_HEADER,
  EXPORT_CSV_COLUMNS,
};
