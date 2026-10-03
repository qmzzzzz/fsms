/**
 * 手写审计写入失败的统一处理器（P0-5 回归防护）
 *
 * 背景：P0-5 修复后 `res.locals.skipGlobalAudit` 在响应时刻读取、真正生效，
 * 「控制器手写 AuditLog.create」成为该类操作在审计库中的**唯一留痕**。
 * 修复前该标志恒失效，全局审计中间件总会补记一条，因此控制器侧
 * `.catch(() => {})` 静默吞错时仍有兜底记录；修复后同样的静默吞错会让
 * 整个操作**零留痕**（合规上不可接受，且无任何可观测信号）。
 *
 * 本模块提供统一的失败处理器：
 *   - 不改变业务语义：审计失败仍不阻断主流程（与原 `.catch(() => {})` 一致）；
 *   - 但不再静默：写 error 日志 + 计入 security_alerts_total{type=audit_write_failed}，
 *     使「审计链出现缺口」在日志与监控面同时可见。
 *
 * 与 models/auditLogWriteStatics.js 的 `record()` 是同一纪律的两个落点
 * （那边 level=medium 且 resolve null；这边调用方用的是 `AuditLog.create`，
 * 需自行兜底且 level=high——因为此处记录的是敏感操作/安全配置变更）。
 *
 * 本模块另有 `guardDetection`：同一条纪律在"安全检测函数导出边界"上的形态，
 * 与本文件的审计写入处理器并列，见该函数文档。
 */

const logger = require('./logger');

/**
 * 被 catch 的东西**不保证是 Error**：`Promise.reject()`（undefined）、
 * `throw 'boom'`（字符串）、driver 在缓冲超时里 reject 裸对象都见过。
 * 原先两处直接写 `${err.message}`，于是在"记账"这一步自己抛 TypeError——
 * 而这里是旁路可观测性代码，它一炸就正好毁掉本模块存在的理由：
 *   - `onAuditWriteFailure` 的返回值是登录路径上 `await` 的 `.catch()` 处理器，
 *     处理器抛错 = 一个新的 rejection = 客户端拿到 500 而不是 401；
 *   - `guardDetection` 的文档承诺"永不 reject"（见其 @returns），处理器抛错
 *     直接违背该契约，而调用方全是 `.catch(() => {})` ⇒ TypeError 又被吞掉，
 *     结果是"检测失效 + 零痕迹"，与不修时同形。
 * 取本仓库既有写法（index.js:441、loggerFlush.js:216 errText）。
 */
const errText = (err) => (err && err.message ? err.message : err);

/**
 * 生成 `.catch()` 处理器
 * @param {string} auditAction 便于检索的审计动作标识（非 AuditLog 的 action 枚举值）
 * @param {object} [req] 可选：用于取操作者用户名
 * @returns {(err: Error) => void}
 */
const onAuditWriteFailure = (auditAction, req) => (err) => {
  logger.error(`{审计写入失败}：${errText(err)}`, {
    auditAction,
    operator: req?.user?.username,
  });
  try {
    require('./metrics').incSecurityAlert('audit_write_failed', 'high');
  } catch (_) {
    /* 指标端不可用时仅保留日志 */
  }
};

/**
 * 生成「记账后重抛」的 `.catch()` 处理器。
 *
 * 与 `onAuditWriteFailure` 的差别只在**业务语义**，不在纪律：两者都做到「不静默」，
 * 但吞掉错误意味着「操作结果已经达成、只是留痕没写上」——这个前提并非处处成立。
 * 两处写入点不成立（本仓实测）：
 *   - `securityController.viewSensitiveData`：`skipGlobalAudit` 之后这条 create 是
 *     PII 查看的唯一留痕；吞掉错误后 `res.json` 照样把明文手机号/邮箱发出去，
 *     于是「读取了 PII 却没有任何记录」成为可能——比失败更糟的是**成功且无痕**。
 *   - `securityController.reportSuspiciousActivity`：返回体里的 `reportId` 取自这条
 *     create 的文档，吞掉后它是 `undefined`，而响应话术仍写「举报已提交」。
 * 这两处的正确形态是失败照旧外抛（客户端得到 500，不宣称成功、不外发数据），
 * 同时把原因记进日志与指标。`AuditLog.record` 不在此列——它自带 catch 并计入 medium 档。
 *
 * 档位由 `src/tests/controllers/skipGlobalAuditWriteFailure.test.js` 的登记表钉住：
 * 把一处重抛悄悄改成吞错（或反之）都会让那条用例转红。
 *
 * @param {string} auditAction 检索用的审计动作标识
 * @param {object} [req] 用于取操作者用户名
 * @returns {(err: Error) => never} 记账后原样重抛
 */
const onAuditWriteFailureRethrow = (auditAction, req) => (err) => {
  onAuditWriteFailure(auditAction, req)(err);
  throw err;
};

/**
 * 安全检测函数的统一"不外抛"外壳
 *
 * 与 `onAuditWriteFailure` 是同一条纪律的两个落点：**旁路可观测性代码不得改变业务语义，
 * 但绝不静默**。差别只在形状——审计写入是"调用方手里有个 Promise"，所以给的是 `.catch`
 * 工厂；检测函数是"模块导出一组 async 函数，调用方各自决定怎么处理 reject"，
 * 所以在导出边界上包一层。
 *
 * 为什么必须在边界上包，而不是指望调用方：本仓三个检测器的调用方**全部**是空 catch 形态
 * （`services/authService.js` 五处 `await checkBruteForce(...).catch(() => {})`、
 * `middleware/rbac.js` 一处 `void checkPermissionAbuse(...).catch(() => {})`）。
 * 检测器内部一旦有未捕获的抛错（最先撞上的就是入口那次"用来观测的计数查询"：
 * DB 瞬断、缓冲超时、CastError），异常就在空 catch 里蒸发 ⇒ 自动封禁与权限滥用告警
 * 在故障期整体失效，而日志一行痕迹都没有。已实测复现：把 `AuditLog.countDocuments`
 * 换成 rejected 后走一遍调用点形状，得到"被静默吞掉 + logger 零调用"。
 *
 * 语义保持不变：抛错时该轮就是不检测、不封禁（本来也是这个结果），
 * 变的只是这件事从此可观测。
 *
 * @param {string} label 检索用的检测器名，日志形态 `${label}失败（本轮不检测）: 原因`
 *                       （必须含"检测"，用例按这个族筛日志，防止把无关 error 当成通过）
 * @param {Function} detect 被包裹的检测函数
 * @returns {(...args: any[]) => Promise<void>} 与 detect 同签名、但永不 reject 的函数
 */
const guardDetection =
  (label, detect) =>
  async (...args) => {
    try {
      await detect(...args);
    } catch (err) {
      logger.error(`${label}失败（本轮不检测）: ${errText(err)}`);
      try {
        // 与 onAuditWriteFailure 同一条纪律的两个落点，两边都得"不静默"到同一档：
        // 只有日志的话，故障期检测器整体失效要人去翻日志才发现，而这一路失效的
        // 是自动封禁与权限滥用告警——监控面必须有对应的那一格。
        require('./metrics').incSecurityAlert('security_detection_failed', 'medium');
      } catch (_) {
        /* 指标端不可用时仅保留日志（这里绝不能再抛：见本函数 @returns 的"永不 reject"） */
      }
    }
  };

// `errText` 是本仓对"被 catch 的东西不保证是 Error"这**一条**纪律的唯一实现：
// services/auditBuffer.js 与 services/auditMonitor.js 原先各自抄了一份箭头
// （2026-10-03 收敛到这里，两份副本已删）。导出它而不是再留私有副本，是因为
// 复制品会各自漂移——观测代码里最坏的一种漂移是"记账时自己抛"。
module.exports = { onAuditWriteFailure, onAuditWriteFailureRethrow, guardDetection, errText };
