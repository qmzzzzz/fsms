/**
 * 取证捕获记录模型（P2，2026-10-31）
 *
 * 字段名是跨 lane 冻结契约（任务书 §2.3），任何改名都要先报 lead。与 AuditLog 的
 * 分工：AuditLog 是"谁在何时做了什么"的操作台账（常态、低成本），本集合只在
 * forensicTrigger 标记的取证态下记录请求/响应全量（高成本、短保留）。
 *
 * 保留期走 constants/businessRetention.js 登记（declaredDays=30，用户 2026-10-31 书面确认）+ 环境变量
 * BUSINESS_RETENTION_DAYS_FORENSIC_CAPTURE 开关；未配置时不建 TTL（数据常留）。
 */

const mongoose = require('mongoose');
const logger = require('../utils/logger');
const { resolveTtlIndexPlan } = require('../constants/businessRetention');

const headerBag = { type: mongoose.Schema.Types.Mixed, default: undefined };
const bodyBag = { type: mongoose.Schema.Types.Mixed, default: undefined };

const forensicCaptureSchema = new mongoose.Schema(
  {
    createdAt: { type: Date, default: Date.now },
    ip: { type: String, maxlength: 64 },
    ipSegment: { type: String, maxlength: 64 },
    method: { type: String, maxlength: 16 },
    path: { type: String, maxlength: 512 },
    action: { type: String, maxlength: 128 },
    category: { type: String, maxlength: 32 },
    userId: { type: String, maxlength: 64 },
    username: { type: String, maxlength: 128 },
    sessionId: { type: String, maxlength: 128 },
    fingerprint: { type: String, maxlength: 128 },

    trigger: {
      reason: { type: String, maxlength: 128 },
      markedAt: { type: Date },
    },

    request: {
      headers: headerBag,
      body: bodyBag,
      // §2.2 要求 query/params 也走 sanitizeAuditQuery 留存；§2.3 的字段清单未列这两个键，
      // 属"清单漏写"的最小补齐（只增不改名），已在 work/forensic-p2-capture.md 报备 lead。
      query: bodyBag,
      params: bodyBag,
      bodyBytes: { type: Number, default: 0 },
      bodyTruncated: { type: Boolean, default: false },
      bodySha256: { type: String, maxlength: 64 },
    },

    response: {
      status: { type: Number },
      headers: headerBag,
      body: bodyBag,
      contentType: { type: String, maxlength: 256 },
      bodyBytes: { type: Number, default: 0 },
      bodyTruncated: { type: Boolean, default: false },
      bodySha256: { type: String, maxlength: 64 },
    },

    device: {
      ua: { type: String, maxlength: 512 },
      browser: { type: String, maxlength: 64 },
      os: { type: String, maxlength: 64 },
      deviceType: { type: String, maxlength: 32 },
      secChUa: { type: String, maxlength: 512 },
      acceptLanguage: { type: String, maxlength: 512 },
      acceptEncoding: { type: String, maxlength: 512 },
      httpVersion: { type: String, maxlength: 16 },
      tlsProtocol: { type: String, maxlength: 32 },
      tlsCipher: { type: String, maxlength: 128 },
    },

    location: {
      country: { type: String, maxlength: 64 },
      province: { type: String, maxlength: 64 },
      city: { type: String, maxlength: 64 },
      isp: { type: String, maxlength: 64 },
      text: { type: String, maxlength: 256 },
    },

    net: {
      reportedIp: { type: String, maxlength: 64 },
      socketPeer: { type: String, maxlength: 64 },
    },

    recordHash: { type: String, maxlength: 64 },
    // WAL 行序号：落库成功时按它精确裁剪 WAL，不参与 recordHash 之外的语义
    seq: { type: String, maxlength: 160 },
  },
  { strict: true, versionKey: false, minimize: false } // 默认 minimize 会删空对象 ⇒ recordHash 复核必报假篡改
);

forensicCaptureSchema.index({ createdAt: -1 });
forensicCaptureSchema.index({ ip: 1, createdAt: -1 });
forensicCaptureSchema.index({ ipSegment: 1, createdAt: -1 });
forensicCaptureSchema.index({ fingerprint: 1, createdAt: -1 });

// 业务保留期（§1.2）：30 天（用户书面确认），区间 [30,3650]；下限独立于审计链（全局 MIN 仍 90，下调会连 AuditLog 一起降）
const ttlPlan = resolveTtlIndexPlan('ForensicCapture');
if (ttlPlan.days !== null) {
  forensicCaptureSchema.index(
    { createdAt: 1 },
    { expireAfterSeconds: ttlPlan.days * 24 * 60 * 60, name: 'ttl_createdAt' }
  );
}

const ForensicCapture = mongoose.model('ForensicCapture', forensicCaptureSchema);

ForensicCapture.on('index', (err) => {
  // logger 在加载期绑定：teardown 后 require 回来是 undefined，会盖掉真正的索引错误
  if (err) {
    // TTL 改档不回收旧选项：由 initData/indexes.js 的启动对账落地（同 FireAlarm 口径）
    logger.error(
      `ForensicCapture 索引创建失败：物理索引与声明不一致时 mongoose 只报错不改选项（改档由 services/initData/indexes.js 的启动对账落地）：${err.message}`
    );
  }
});

module.exports = ForensicCapture;
