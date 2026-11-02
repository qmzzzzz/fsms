/**
 * 文件/导出类端点的诱饵应答（P1c）：合成文件现场生成，一个真实文档都不碰。拿不到的文件按真实链**逐字**拒绝（码/文案/参数/状态码全同，由 ApiResponse 同一个口构造）；写方法（未脱敏导出）也一律拒绝。
 * 表名/列/文件名/响应头/表头样式逐一同 reportWorkbookService.writeExportWorkbook。
 * 有意不模拟：并发闸、数据范围、日期窗以外的筛选维度——边界表与理由见 docs/adr/ADR-013；日期窗已模拟（buildDateRangeFilter，窗口外为空 ⇒ 只留表头）。台账：src/tests/ci/honeypotDecoyLedger.test.js 的「文件/导出类端点」用例。
 */

const { createWorkbook } = require('../utils/xlsxWriter');
const ApiResponse = require('../utils/apiResponse');
const {
  buildDateRangeFilter,
  isValidDateParam,
  isDateRangeReversed,
  toEpochMs,
} = require('../utils/helpers');
const { BUSINESS_TIMEZONE, businessDateParts } = require('../constants/timezone');
const {
  DECOY_EXPORT_DATE_FIELDS,
  DECOY_EXPORT_ITEMS,
  FILE_ENDPOINTS,
} = require('../constants/honeypotDecoyFiles');
const {
  HONEYPOT_VERDICT,
  WRITE_METHODS,
  materializeRow,
  rowClockNow,
} = require('../constants/honeypotDecoy');
const { reauthPayload } = require('../constants/honeypotTicketGate');
const {
  EXPORT_MODEL_CONFIG,
  EXPORT_ROW_TRANSFORMS,
  PII_NAME_EXPORT_TYPES,
  createSafeTransform,
  getExportColumnDefs,
  getExportSheetName,
} = require('./reportExportService');

/** 支持的报表类型 = buildExportQuery 的 switch 分支集合（那边不认的 type 回 null ⇒ 400） */
const SUPPORTED_EXPORT_TYPES = Object.freeze(Object.keys(EXPORT_MODEL_CONFIG));

/** 与 Express 同口径：大小写不敏感，容忍**一个**尾斜杠（实测：'//' 与 %XX 拼写都不算同一条路由） */
const canonPath = (raw) => {
  const s = String(raw).toLowerCase();
  return s.length > 1 && s.endsWith('/') ? s.slice(0, -1) : s;
};
const matchEndpoint = (path) => {
  const canon = canonPath(path);
  return (
    FILE_ENDPOINTS.find((e) =>
      e.prefix ? canon === e.path || canon.startsWith(e.path + '/') : canon === e.path
    ) || null
  );
};

/** 时区参数：与 reportController.resolveQueryTimezone 同判据（空/非串 = 业务时区，非法 IANA 名回同一句 400） */
const resolveQueryTimezone = (raw) => {
  const tz = typeof raw === 'string' ? raw.trim() : '';
  if (!tz) return { tz: BUSINESS_TIMEZONE };
  try {
    new Intl.DateTimeFormat('en', { timeZone: tz });
    return { tz };
  } catch {
    return { refusal: { kind: 'plainError', message: '时区参数无效', statusCode: 400 } };
  }
};

/** 报表导出腿：校验顺序与 reportController.exportReport 一致——格式 → 时区 → 日期 → 审计权限 → 类型 */
const resolveReportExport = (query) => {
  const { type = 'alarms', format = 'xlsx', startDate, endDate, lang } = query;
  if (format !== 'xlsx') return { kind: 'formatUnsupported', format }; // 文案带 ${format} 占位符：由 sendFileResponse 按真实控制器的写法内联补 message
  const { tz, refusal } = resolveQueryTimezone(query.tz);
  if (refusal) return refusal;
  if (!isValidDateParam(startDate) || !isValidDateParam(endDate)) {
    return { kind: 'codeError', code: 'DATE_PARAM_INVALID' }; // 与 reportController 同一判据与同一优先级：参数形态先于区间反向
  }
  if (isDateRangeReversed(startDate, endDate)) {
    return { kind: 'codeError', code: 'DATE_RANGE_INVALID' };
  }
  if (type === 'audit') return { kind: 'codeError', code: 'AUDIT_EXPORT_REQUIRES_AUDIT_PERM' }; // 装扮里故意没有 security:audit：这条 403 正是"零权限会话"该看到的
  if (!SUPPORTED_EXPORT_TYPES.includes(type))
    return { kind: 'codeError', code: 'REPORT_TYPE_UNSUPPORTED' };
  return {
    kind: 'workbook',
    type,
    lang: String(lang || '')
      .toLowerCase()
      .startsWith('en')
      ? 'en'
      : 'zh', // 与控制器同一式：lang=en* 全英文，其余中文
    startDate,
    endDate,
    tz,
  };
};

/** 未脱敏导出腿：先逐字复用 requirePiiExportType 的类型闸，再回未脱敏权限（pii:export）的拒绝 */
const resolvePiiExport = (query) => {
  const raw = query.type;
  const type = typeof raw === 'string' && raw ? raw : 'alarms';
  if (!PII_NAME_EXPORT_TYPES.includes(type)) {
    return {
      kind: 'codeError',
      code: 'REPORT_TYPE_UNSUPPORTED',
      options: { message: `未脱敏导出仅支持 ${PII_NAME_EXPORT_TYPES.join(' / ')}` },
    };
  }
  return { kind: 'codeError', code: 'PERMISSION_DENIED' };
};

/**
 * 判定文件类端点该回什么；非文件类端点回 null（交回通用改道判定）
 *
 * verdict 与 write 是给留痕用的（honeypotWatch.recordHoneypotProbe）：拿到合成文件记 decoy，其余（含各类拒绝）记 deny；write 按**方法**判（POST 未脱敏导出 ⇒ critical）， 不按"是否被拒"判——只读探测被拒不代表对方在写。
 * @param {{method?: string, path?: string, query?: object}} [req]
 * @returns {null|object}
 */
const resolveFileResponse = ({ method = '', path = '', query = {} } = {}) => {
  const upper = String(method).toUpperCase();
  const endpoint = matchEndpoint(String(path));
  if (!endpoint || !endpoint.methods.includes(upper)) return null;
  let response;
  if (endpoint.id === 'reports-export') response = resolveReportExport(query);
  else if (endpoint.id === 'reports-export-pii') response = resolvePiiExport(query);
  else if (endpoint.id === 'audit-logs-export')
    response = reauthPayload(); // 审计导出真实链是「权限闸 → 二次验证闸」：呈现身份经 security:* 已过第一道，所以缺票的 401 才是它在这里看到的下一句（旧口径的 403 是归因错误，见 ADR-013 P2-2）。拒绝体与判定层共用同一份冻结对象，逐字相同
  else response = { kind: 'codeError', code: 'AVATAR_NOT_FOUND', options: { statusCode: 404 } }; // 头像一律"尚未设置"：真链在没有头像时回的就是这句 404
  return {
    ...response,
    verdict: response.kind === 'workbook' ? HONEYPOT_VERDICT.DECOY : HONEYPOT_VERDICT.DENY,
    write: WRITE_METHODS.includes(upper),
    head: upper === 'HEAD',
  };
};

/** 合成 xlsx：表名/列/文件名/响应头/表头样式与 reportWorkbookService.writeExportWorkbook 逐一相同 */
const sendDecoyWorkbook = async (res, { type, lang, head, startDate, endDate, tz }) => {
  const sheetName = getExportSheetName(type, lang);
  const filename = `${sheetName}_${businessDateParts().dateStr}.xlsx`;
  res.setHeader(
    'Content-Type',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
  );
  res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(filename)}"`);
  if (head) return res.end(); // HEAD 与真实一致：只回头（Node 本就不为 HEAD 带体）
  const workbook = createWorkbook({
    sheetName,
    columns: getExportColumnDefs(type, lang),
    defaultColWidth: 15, // 与真实链同一个写入器 + 同一份列定义 ⇒ 表头/列宽/样式由构造保证相同
  });
  const worksheet = workbook.sheet;
  const transform = createSafeTransform(EXPORT_ROW_TRANSFORMS[type], { maskPii: true, lang }); // maskPii 恒真：真实 GET 导出由 forceMaskPii 强制同档
  // 日期参数真的作用在合成行上，与真实查询同一个 buildDateRangeFilter（date-only 按 tz 展开整天）：
  // 窗口外为空就只留表头——这正是真实腿"筛完没命中"时给出的文件，比"任何时候都给同一批行"更难识破
  const window = buildDateRangeFilter(startDate, endDate, tz);
  const field = DECOY_EXPORT_DATE_FIELDS[type];
  const base = rowClockNow(); // 一次导出只取一个基准：同一份表里所有行共享它（别写成 .map(materializeRow)——两参化之后下标会被当成基准，行时间直接落到 1970）
  DECOY_EXPORT_ITEMS[type]
    .map((row) => materializeRow(row, base))
    .filter((row) => {
      const at = toEpochMs(row[field]); // 与全仓同一个毫秒口径（裸 Date.parse 是 dateParamGateSingleSource 的禁形）
      return (
        (!window.$gte || at >= window.$gte.getTime()) &&
        (!window.$lte || at <= window.$lte.getTime())
      );
    })
    .forEach((row) => worksheet.addRow(transform(row)));
  try {
    workbook.write(res);
  } catch {
    // 头已发出（客户端中途断流）⇒ 与真实链同结局：断流；头还没发 ⇒ 只能是生成期异常，
    // 补一句 500 把连接收掉——不然客户端会一直挂在这条请求上，比 500 更像异常
    if (!res.headersSent) {
      res.removeHeader('Content-Type');
      res.removeHeader('Content-Disposition');
      res.status(500).end();
    } else res.destroy();
  }
};

/** 发应答：拒绝走 ApiResponse 的两个口（与真实链同一个口），文件走合成 xlsx */
const sendFileResponse = async (res, response) => {
  if (response.kind === 'formatUnsupported') {
    // 与 reportController.exportReport 那条逐字同写：本码的默认文案带 ${format} 占位符，
    // 可读文案必须由调用点内联补上（码表里那份带占位符的文本不能直接发出去）
    return ApiResponse.codeError(res, 'EXPORT_FORMAT_UNSUPPORTED', {
      message: `不支持的导出格式: ${response.format}`,
      params: { format: response.format },
    });
  }
  if (response.kind === 'codeError') {
    return ApiResponse.codeError(res, response.code, response.options || {});
  }
  if (response.kind === 'plainError') {
    return ApiResponse.error(res, response.message, response.statusCode);
  }
  return sendDecoyWorkbook(res, response);
};

module.exports = { resolveFileResponse, sendFileResponse };
