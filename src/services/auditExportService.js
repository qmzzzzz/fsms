const crypto = require('crypto');
const AuditLog = require('../models/AuditLog');
const { sanitizeSpreadsheetCell } = require('../utils/helpers');

const EXPORT_HARD_LIMIT = 50000;
const MANIFEST_LINE_PREFIX = '#__MANIFEST__:';
const EXPORT_CSV_HEADER =
  'timestamp,action,category,username,ip,path,statusCode,success,riskLevel,prevHash,hash';

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
  [
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
  ].map((column) => (column === 'timestamp' ? csvEscape(timestamp) : csvEscape(doc[column])));

const sendAuditExportHeaders = async (query, res) => {
  const estimatedCount = await AuditLog.countDocuments(query);
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="audit-logs-export.csv"');
  res.setHeader('X-Audit-Manifest-Records', String(Math.min(estimatedCount, EXPORT_HARD_LIMIT)));
  if (estimatedCount > EXPORT_HARD_LIMIT) {
    res.setHeader('X-Audit-Truncated', 'true');
  }
};

const streamAuditExport = async (query, res) => {
  const cursor = AuditLog.find(query).sort({ _id: 1 }).lean().cursor();
  const counters = { recordCount: 0, startTime: null, endTime: null, truncated: false };
  const hasher = crypto.createHash('sha256');
  const writeLine = (line) =>
    new Promise((resolve) => {
      if (res.write(line)) return resolve();
      res.once('drain', resolve);
    });

  await cursor.eachAsync(async (doc) => {
    if (counters.recordCount >= EXPORT_HARD_LIMIT) {
      counters.truncated = true;
      cursor.close();
      return;
    }
    counters.recordCount += 1;
    const timestamp = doc.timestamp instanceof Date ? doc.timestamp : new Date(doc.timestamp);
    if (!counters.startTime || timestamp < counters.startTime) counters.startTime = timestamp;
    if (!counters.endTime || timestamp > counters.endTime) counters.endTime = timestamp;
    if (doc.hash) {
      hasher.update(doc.hash, 'utf8');
    }
    await writeLine(`${exportAuditColumns(doc, timestamp).join(',')}\n`);
  });

  return { ...counters, sha256: hasher.digest('hex') };
};

const buildAuditExportManifest = (counters) => {
  const manifest = {
    recordCount: counters.recordCount,
    startTime: counters.startTime ? counters.startTime.toISOString() : null,
    endTime: counters.endTime ? counters.endTime.toISOString() : null,
    generatedAt: new Date().toISOString(),
    sha256: counters.sha256,
  };
  if (counters.truncated) {
    manifest.truncated = true;
    manifest.notice = `导出记录数已达硬上限 ${EXPORT_HARD_LIMIT} 条并截断，请缩小筛选范围后分批导出`;
  }
  return manifest;
};

module.exports = {
  buildAuditExportManifest,
  sendAuditExportHeaders,
  streamAuditExport,
  MANIFEST_LINE_PREFIX,
  EXPORT_CSV_HEADER,
};
