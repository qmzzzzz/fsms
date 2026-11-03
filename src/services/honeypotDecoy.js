'use strict';

const ApiResponse = require('../utils/apiResponse');
const { redactUrlQuery } = require('../utils/helpers'); // 404 文案与 app.js 兜底逐字相同、打码必须同源：抄一份正则就会在某次改动后分叉，而分叉就是「同一路径陷阱比真实多/少一个字段」这种一眼可查的指纹
const honeypotWatch = require('./honeypotWatch');
const honeypotDecoyFiles = require('./honeypotDecoyFiles');
const honeypotDecoySelf = require('./honeypotDecoySelf');
const honeypotDecoyAggregates = require('../constants/honeypotDecoyAggregates'); // 聚合读端点的同形合成体（批次 B）：零真实读，只从合成表与真实白名单派生
const honeypotDecoyMetrics = require('../constants/honeypotDecoyMetrics');
const { isHoneypotEnabled } = require('../constants/honeypotAccounts');
const { resolvePunishableIp } = require('../utils/ipUtils');
const {
  HONEYPOT_VERDICT,
  WRITE_METHODS,
  resolveDecoyPayload,
  resolveDecoyVerdict,
} = require('../constants/honeypotDecoy');

const requestPathOf = (req) => String((req && (req.originalUrl || req.url)) || '').split('?')[0]; // 以原始 URL 判路：不带查询串，避免用 query 伪造判定
const isHoneypotSession = (req) => !!(req && req.user && req.user.isHoneypot === true); // 判据只看身份上下文（authenticate 从库里读的 isHoneypot），token 载荷与请求头都不可信

const sendRouteNotFound = (req, res) =>
  // 404 启发式可缓存（RFC 9111）：蜜罐 404 与真实 404 同形，被中间层缓存会污染同 URL 的正常响应面（审计 2026-11-02 F-3；no-store 与 app.js 兜底 404 同口径）
  res
    .setHeader('Cache-Control', 'no-store')
    .status(404)
    .json({
      success: false,
      message: `接口不存在：${req.method} ${redactUrlQuery(req.originalUrl || req.url)}`, // 形状同 app.js 的兜底 404：同一句 message、同样**没有** errors 键——多给一个 errors 就等于自报家门
    });

const sendAggregate = (res, payload) => {
  if (payload.kind === 'codeError') return respondDecoy(res, payload); // 参数非法走通用出口的 codeError 分支：拒绝路径只留一个 ApiResponse.codeError 调用点（多一处就多一次口径分叉），且绝不回落成 404「资源不存在」——那是一次请求就能拿到的自证
  return payload.envelope === 'paginated'
    ? ApiResponse.paginated(res, payload.data, payload.pagination, payload.message) // 分页口径（含 page/totalPages 的 null 位与 hasMore）由聚合体按真实控制器逐字给出
    : ApiResponse.success(res, payload.data, payload.message);
};

const respondDecoy = (res, payload) => {
  if (!payload) return ApiResponse.notFound(res, '资源不存在');
  if (payload.kind === 'codeError') {
    return ApiResponse.codeError(res, payload.code, payload.options);
  }
  if (payload.kind === 'list') {
    return ApiResponse.paginated(res, payload.data, payload.pagination, payload.message); // 信封由列表判定层按真实控制器逐字给出（含 nextCursor 的 null 位）：这里再算一次分页就是第二个口径
  }
  return ApiResponse.success(res, payload.data);
};

const sendDataFace = (res, { method, path, query, user }) => {
  const aggregate = honeypotDecoyAggregates.resolveAggregatePayload({ method, path, query }); // 判序同 steer：聚合与指标都判在通用载荷之前——同前缀不同语义，先判的理由见 ADR-013
  if (aggregate) return sendAggregate(res, aggregate);
  const metrics = honeypotDecoyMetrics.resolveMetricsPayload({ method, path });
  if (metrics) return ApiResponse.success(res, metrics.data, metrics.message);
  return respondDecoy(res, resolveDecoyPayload({ method, path, user, query })); // query 必须进判定层：路由校验链拦下的非法查询在真实链是 400，合成面不读 query 就会回 200 合成列表 —— 一次请求即可分辨
};

const steer = async (req, res) => {
  if (!isHoneypotSession(req)) return false;
  if (!isHoneypotEnabled()) return false; // 开关关闭即不接管：老会话回落到常规 RBAC（零角色 ⇒ 403），但绝不因关开关而放行
  // F1：惩罚归因必须在入口对**活 req** 算一次（resolvePunishableIp 读 socket 对端与转发头的关系），不能传已解析的地址串——否则「该打谁」的裁定退化成「请求自称是谁」，伪造 XFF的探测会落到受害者 IP 名下。四个分支共用同一份裁定（同一请求不会改道两次）。
  const attribution = resolvePunishableIp(req);
  const method = String(req.method || 'GET').toUpperCase();
  const path = requestPathOf(req);
  const verdict = resolveDecoyVerdict({ method, path });
  const writeAttempt = WRITE_METHODS.includes(method) || verdict === HONEYPOT_VERDICT.DENY; // 告警口径按「是不是写方法」定而不按判决反推：否则 GET 打到不存在的路径会被记成 critical 写尝试，把真信号淹掉
  if (verdict === HONEYPOT_VERDICT.PASSTHROUGH) return false; // 会话自身的续期/登出放行：接管道只会把攻击者提前赶走，且这些端点不读业务数据
  if (verdict === HONEYPOT_VERDICT.NOT_FOUND) {
    await honeypotWatch.recordHoneypotProbe({
      username: req.user.username,
      method,
      path,
      verdict,
      writeAttempt,
      ip: req.ip,
      attribution,
    });
    sendRouteNotFound(req, res); // 本分支必须排在文件/本人面之前：那些是「前缀 + 任意尾串」判定，会把 /api/avatars 这类裸前缀也认成文件端点，回一句形状不同的 body
    return true;
  }
  const fileResponse = honeypotDecoyFiles.resolveFileResponse({
    method,
    path,
    query: req.query || {},
  }); // 文件类端点先判：合成文件/逐字拒绝都不经过通用改道（前缀表对 /api/avatars 只会回 403，而真实链是 404）
  if (fileResponse) {
    await honeypotWatch.recordHoneypotProbe({
      username: req.user.username,
      method,
      path,
      verdict: fileResponse.verdict,
      writeAttempt: fileResponse.write,
      ip: req.ip,
      attribution,
    });
    await honeypotDecoyFiles.sendFileResponse(res, fileResponse);
    return true;
  }
  const selfResponse = honeypotDecoySelf.resolveSelfResponse({
    method,
    path,
    query: req.query || {},
    session: honeypotDecoySelf.sessionContextOf(req),
  }); // 本人自助面（P2）：真实链按令牌里的 userId 回 200 的那七条读侧端点，陷阱回同形合成体
  if (selfResponse) {
    await honeypotWatch.recordHoneypotProbe({
      username: req.user.username,
      method,
      path,
      verdict: selfResponse.verdict,
      writeAttempt: selfResponse.write,
      ip: req.ip,
      attribution,
    });
    honeypotDecoySelf.sendSelfResponse(res, selfResponse);
    return true;
  }
  await honeypotWatch.recordHoneypotProbe({
    username: req.user.username,
    method,
    path,
    verdict,
    writeAttempt,
    ip: req.ip,
    attribution,
  });
  if (writeAttempt) {
    ApiResponse.codeError(res, 'PERMISSION_DENIED'); // 与真实 403 同一个响应构造器：错误体逐字相同，不给对方任何可指纹的差异
    return true;
  }
  sendDataFace(res, { method, path, query: req.query || {}, user: req.user });
  return true;
};

module.exports = { isHoneypotSession, steer };
