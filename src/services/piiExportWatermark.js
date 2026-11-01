/**
 * 未脱敏导出的水印与追溯号（审计 A-8）：16 位 hex 随机号同时进文件名后缀、工作簿属性、表尾可见行与响应头 X-Export-Trace-Id，并与审计里那条 view_sensitive_data 同号——一份外流件能反查到导出人。只在未脱敏的姓名报表上生成；用途（purpose）随请求体记录、不强制。
 */
const crypto = require('crypto');
const { formatDateTime } = require('../utils/dateFormat');
const { clientIpForSecurityDecision } = require('../utils/ipUtils');
const { PII_NAME_EXPORT_TYPES } = require('./reportExportService');

const TRACE_HEADER = 'X-Export-Trace-Id';
const PURPOSE_MAX = 200;

/** 折白与截断：水印要进单元格与文件属性，换行/控制字符与超长文本都会破坏结构。 */
const normalizePurpose = (raw) => {
  if (typeof raw !== 'string') return '';
  const flat = raw.replace(/\s+/g, ' ').trim();
  return flat.length > PURPOSE_MAX ? flat.slice(0, PURPOSE_MAX) : flat;
};

const buildWatermarkText = ({ operator, at, ip, purpose, traceId, lang }) => {
  const sep = lang === 'en' ? ' | ' : '｜';
  const parts =
    lang === 'en'
      ? [
          'Unmasked export',
          'by ' + operator,
          at,
          'trace ' + traceId,
          ip ? 'IP ' + ip : '',
          purpose ? 'purpose: ' + purpose : '',
        ]
      : [
          '未脱敏导出',
          '导出人 ' + operator,
          at,
          '追溯号 ' + traceId,
          ip ? 'IP ' + ip : '',
          purpose ? '用途 ' + purpose : '',
        ];
  return parts.filter(Boolean).join(sep);
};

/**
 * 本次请求是否打水印：只有"未脱敏 + 携带真实姓名的报表"两条同时成立才生成。与 auditFullPiiExportIfAny 同一判据——打标而不留痕等于把文件钉在一个审计里不存在的追溯号上。
 */
const piiExportWatermarkFor = (req, { type, maskPii, lang } = {}) => {
  if (maskPii || !PII_NAME_EXPORT_TYPES.includes(type)) return null;
  const watermark = {
    traceId: crypto.randomBytes(8).toString('hex'),
    operator: req.user.username || String(req.user.userId),
    at: formatDateTime(new Date()),
    ip: clientIpForSecurityDecision(req) || '',
    purpose: normalizePurpose(req.body && req.body.purpose),
  };
  return { ...watermark, text: buildWatermarkText({ ...watermark, lang }) };
};

module.exports = { TRACE_HEADER, PURPOSE_MAX, normalizePurpose, piiExportWatermarkFor };
