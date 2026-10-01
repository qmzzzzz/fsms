const ExcelJS = require('exceljs');
const {
  EXPORT_LIMIT,
  EXPORT_MODEL_CONFIG,
  EXPORT_SHEET_NAMES,
  EXPORT_COLUMN_DEFS,
  EXPORT_ROW_TRANSFORMS,
  createSafeTransform,
} = require('./reportExportService');
// 「按需挂 collation」的判据只有一份（utils/auditQuery）：CSV 导出链早就用它，
// xlsx 这条链此前从未挂过——username 条件改成前缀形态后，不挂就会**漏**记录
// （默认二进制 collation 下 ADMIN 不落在 [adm, adn) 内），见 auditQuery.js:190-201。
const { withCollation } = require('../utils/auditQuery');
// 业务日口径只有一份（constants/timezone）：仪表盘「今日」、报表日期边界、告警的
// 非工作时间判定都读它，导出文件名没有理由例外。
const { businessDateParts } = require('../constants/timezone');

const streamExportRows = async (worksheet, config, query, safeTransform, collation = null) => {
  // 封顶必须落到查询上：多取一条当"是否真的还有后续"的探针，
  // 于是"恰好 EXPORT_LIMIT 行"不会被误报成截断（与审计 CSV 导出同一判据）。
  const probeLimit = EXPORT_LIMIT + 1;
  let written = 0;
  let truncated = false;
  // 命中过、却在两次查询之间消失的行数（被删除，或改得不再匹配筛选条件）。
  // 必须单独计数而不是悄悄跳过：跳过之后文件行数比命中数少，而 truncated 仍是
  // false——一份"没被截断"的合规材料其实缺了行，读的人无从得知。
  let rowsLost = 0;

  if (config.populate && config.populate.length > 0) {
    const idDocs = await withCollation(
      // 排序取 config.sort 原样，**不再补 `_id: 1`**：那份配置现在声明的是全序
      // （与列表接口同一个 `{key:-1,_id:-1}`，理由见 reportExportService.js 的
      // EXPORT_MODEL_CONFIG 注释）。这里再补一个反向的 `_id: 1`，等于让"取 id 的腿"
      // 和"列表"对并列行取不同先后 ⇒ 撞上限时边界那条记录两边不是同一条；
      // 且混合方向用不上 `{key:-1,_id:-1}` 索引，退化成 5001 条的阻塞内存排序。
      config.model.find(query).sort(config.sort).limit(probeLimit).select('_id'),
      collation
    ).lean();
    truncated = idDocs.length > EXPORT_LIMIT;
    const orderedIds = (truncated ? idDocs.slice(0, EXPORT_LIMIT) : idDocs).map((d) => d._id);

    const BATCH_SIZE = 200;
    const docById = new Map();
    for (let i = 0; i < orderedIds.length; i += BATCH_SIZE) {
      const idBatch = orderedIds.slice(i, i + BATCH_SIZE);
      const docs = await withCollation(
        config.model
          .find({ $and: [query, { _id: { $in: idBatch } }] })
          .populate(config.populate)
          .select(config.select),
        collation
      ).lean();
      for (const doc of docs) docById.set(String(doc._id), doc);
    }

    for (const id of orderedIds) {
      const doc = docById.get(String(id));
      if (!doc) {
        rowsLost += 1;
        continue;
      }
      worksheet.addRow(safeTransform(doc));
      written += 1;
    }
  } else {
    const cursor = withCollation(
      config.model.find(query).sort(config.sort).limit(probeLimit).select(config.select),
      collation
    ).cursor();
    for await (const doc of cursor) {
      if (written >= EXPORT_LIMIT) {
        // 探针那一条：只证明"后面还有"，不写进文件
        truncated = true;
        continue;
      }
      worksheet.addRow(safeTransform(doc));
      written += 1;
    }
  }

  return { written, truncated, rowsLost };
};

/**
 * 不完整必须**说出来**：xlsx 此前静默封顶 5000 行，导出一份"看起来完整"的合规材料
 * 其实少了后面全部记录——与"筛选参数被静默翻译"同一类缺陷（HTTP 200 + 窄得多的结果集）。
 * 双通道：响应头给程序化读取（与 CSV 的 X-Audit-Truncated 同形），表内脚注给
 * 拿到文件的人（Excel 打开时表头与数据之间不会错位，因为它追加在最后一行）。
 *
 * 头只回答"这个文件完整吗"，脚注才回答"缺的是哪一种"：撞上限与被抽走是两回事，
 * 混写成一句"仅包含前 N 行"会把后者说成前者——读者会以为后面还有记录，
 * 而实际是那些行已经不存在了（追查方向完全不同）。
 */
const TRUNCATION_HEADER = 'X-Export-Truncated';

/**
 * 「不完整」有三种成因，各有一条判据，且互不重复计账：
 *   - `truncated`：撞导出上限，后面还有记录（措辞必须是"仅包含前 N 行"）；
 *   - `rowsLost`：populate 分支两步取数之间被抽走的行（点得名，逐行计）；
 *   - `countDrift`：**游标分支**没有第二次查询可点名，一条流里被删除或改得不再匹配
 *     筛选条件的记录根本不会到达，游标正常结束、零异常零计数。这一格只能靠
 *     "计数时 total 条、实际写出 written 条"对账对出来 —— 差额先减去 rowsLost
 *     已点名的部分，避免同一批行被两套措辞各报一次（populate 分支两式同时成立）。
 */
const buildTruncationFooter = ({ total, written, truncated, rowsLost, countDrift }) => {
  const reasons = [];
  if (truncated) {
    // `truncated` 是**取数腿**亲眼看到的证据：它读到了第 EXPORT_LIMIT+1 条。
    // 而 total 来自更早的计数腿，两腿之间新增的行它一个都没数到。
    // 原措辞无条件写"命中总数 ${total}"，于是 total ≤ 上限时脚注自相矛盾——
    // 文件明明被截断，文案却说命中数正好等于文件里那份切片的行数，
    // 被截掉的那批在材料里不存在（计数腿 5000 条 + 计数后新增 1 条即触发）。
    // 计数腿缺位（total 非有限数）时退回下界表述，与原行为一致。
    const phrase = !Number.isFinite(total)
      ? `命中数 ≥ ${EXPORT_LIMIT + 1}`
      : total > EXPORT_LIMIT
        ? `命中总数 ${total}`
        : `取数时命中 ≥ ${EXPORT_LIMIT + 1}（计数腿只数到 ${total}，两腿之间有新增）`;
    reasons.push(`本文件仅包含前 ${EXPORT_LIMIT} 行（${phrase}）`);
  }
  if (rowsLost > 0) {
    reasons.push(`${rowsLost} 行在导出期间被删除或不再匹配筛选条件（实际写入 ${written} 行）`);
  }
  if (countDrift > 0) {
    reasons.push(
      `${countDrift} 行在计数之后被删除或不再匹配筛选条件` +
        `（实际写入 ${written} 行，计数时 ${total} 行）`
    );
  }
  return (
    `⚠ ${truncated ? '数据已截断' : '数据不完整'}：${reasons.join('；')}，` +
    '请缩小时间范围或增加筛选条件后重新导出。'
  );
};

/**
 * 把 workbook 写进响应流，并且**只对真正送完的导出报成功**。
 *
 * 为什么 `await workbook.xlsx.write(res)` 之后还不能算成功（两处实测）：
 *   ① 它等的是 **zip 自己**收工（exceljs/lib/xlsx/xlsx.js 里 `zip.pipe(stream)` 之后
 *      由 zip 的收尾事件 resolve），不是目的端收工；
 *   ② 探针实测：write() resolve 的那一刻，目的端**一个事件都还没发**——
 *      正常收尾时 `finish`/`close` 都在其后才到（此时 `destroyed=false`），
 *      而中途被 destroy 的那次同样是先 resolve、事件后到。
 * 所以"写完读一下 destroyed/writableFinished 状态"这种写法抓不到任何一次中断
 * （状态位在那一刻还没来得及翻），CSV 侧的判据是"全程挂监听器 + 写完再等一步"
 * （auditExportService.js:85-101、150-152），这里按同一形状补齐 xlsx 这半边：
 * 挂上终局事件后**等目的端自己表态**，再决定报成功还是报中断。
 *
 * 三个终局事件都要挂，少一个都会在这里永久等待：
 *   - `finish`：字节全部交给内核，正常收尾；
 *   - `close`：连接结束——**正常收尾时 Node 也会发**（finish 之后紧跟 close），
 *     所以必须先认 finish 再认 close，否则每一次成功导出都会被读成中断；
 *   - `error`：写过程中 socket 报错（EPIPE/重置）。
 * 顺带一提：`error` 监听器本身也是必要的——目的端报错时若无人监听，
 * Node 会把 'error' 作为未处理事件抛出（裸 Writable 探针里进程直接死；
 * http.ServerResponse 有自己的内部兜底，实测不会崩，但不能指望依赖带着这层兜底）。
 */
const RESPONSE_ABORTED = '导出响应中途断开（客户端中断或连接被重置）';

const writeWorkbookToResponse = async (res, workbook) => {
  let aborted = null;
  let finished = false;
  const settled = new Promise((resolve) => {
    res.once('finish', () => {
      finished = true;
      resolve();
    });
    const onAbort = (err) => {
      // finish 之后的 close 不是中断（见上方判据），这里必须先认 finished
      if (!finished) aborted = aborted || err || new Error(RESPONSE_ABORTED);
      resolve();
    };
    res.once('close', onAbort);
    res.once('error', onAbort);
  });

  await workbook.xlsx.write(res);
  // write() 只代表 zip 把字节交给了 StreamBuf：目的端还没表态就等它表态。
  //
  // 但"等它表态"有一个前置条件：终局事件必须还没发过。上面那对监听器只能收到
  // **挂上之后**才发生的事件——客户端在 write() 之前就已断开（半截下载被取消、
  // 反代超时）时 finish/close 早已发完，settled 永不 settle，这个 handler 就永久
  // 挂在 await 上：既不报成功也不报中断，response_aborted_after_headers 那条审计
  // 走不到，workbook 与 mongoose 游标随挂起的 async 栈常驻。
  // CSV 侧的同一判据是"先查 res.destroyed 再等"（auditExportService.js 的 writeLine
  // 预检），这里按同一形状补 xlsx 这半边——用状态位收口，而不是假设事件还在后面。
  // 顺序不能反：正常收尾后 Node 也会 destroy socket，先认 writableFinished 才把
  // "成功写完"读成"中途断开"这种反向误判不会发生。
  if (!finished && !aborted) {
    if (res.writableFinished) finished = true;
    else if (res.destroyed || res.writableEnded) aborted = new Error(RESPONSE_ABORTED);
    else await settled;
  }
  if (aborted) throw aborted;
};

const writeExportWorkbook = async (res, { type, query, total = null, collation = null }) => {
  const config = EXPORT_MODEL_CONFIG[type];
  const sheetName = EXPORT_SHEET_NAMES[type] || '数据导出';
  // 文件名里的日期必须是**业务日**：原先用 `new Date().toISOString().slice(0,10)`，那是第三个
  // 口径（裸 UTC）——既不是这次查询用的 `?tz=`（前端传浏览器时区，见 reportController
  // resolveQueryTimezone），也不是全仓声明的业务时区。后果：东八区 10-01 00:30 点导出的文件
  // 名字写着 09-30，而同一份文件的日期过滤边界与仪表盘的「今日」都算 10-01。
  // 导出的 xlsx 是会被归档的取证件，名字里的日子说错一天就够人怀疑整份件。
  const filename = `${sheetName}_${businessDateParts().dateStr}.xlsx`;
  res.setHeader(
    'Content-Type',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
  );
  res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(filename)}"`);

  const workbook = new ExcelJS.Workbook();
  const worksheet = workbook.addWorksheet(sheetName);
  worksheet.properties.defaultColWidth = 15;
  worksheet.columns = EXPORT_COLUMN_DEFS[type];

  const safeTransform = createSafeTransform(EXPORT_ROW_TRANSFORMS[type]);
  const { written, truncated, rowsLost } = await streamExportRows(
    worksheet,
    config,
    query,
    safeTransform,
    collation
  );
  // 三种不完整共用同一个头（头只表态"不保证完整"），由脚注区分成因。
  // 对账这一式必须在这里做而不能塞进 streamExportRows：游标分支"少行"的形态
  // 就是流正常结束，任何逐行判据都看不见它，只有计数侧知道本来该有几条。
  const countDrift =
    !truncated && Number.isFinite(total) ? Math.max(total - written - rowsLost, 0) : 0;
  if (truncated || rowsLost > 0 || countDrift > 0) {
    res.setHeader(TRUNCATION_HEADER, 'true');
    worksheet.addRow([buildTruncationFooter({ total, written, truncated, rowsLost, countDrift })]);
  }

  worksheet.getRow(1).eachCell((cell) => {
    cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF4472C4' } };
    cell.font = { bold: true, color: { argb: 'FFFFFFFF' } };
    cell.alignment = { vertical: 'middle', horizontal: 'center' };
    cell.border = { thin: true };
  });

  await writeWorkbookToResponse(res, workbook);
};

module.exports = { streamExportRows, writeExportWorkbook };
