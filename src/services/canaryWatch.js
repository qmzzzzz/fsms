/**
 * 安全哨兵用户名（canary username）检测：幽灵名探测的审计、告警与启动期遮蔽对账
 *
 * 【检测的构造性保证】凭证失败命中名单**且**该用户名查无此人（登录流程必须走到
 * `!user` 分支才会调到这里）。真实存在的账户永远进不了这个分支，所以「名单里
 * 有真账号 ⇒ 误报」这条路径不存在；反过来，如果名单里的名字真的被某个账户占用
 * （遮蔽），该哨兵会**静默失效**——启动期 init() 的遮蔽对账就是为这件事而设，
 * 结果经 getStatus() 暴露给合规面板。
 *
 * 【审计与通知解耦】命中的审计行**无条件写**（写失败也走 errText 式告警日志，
 * 不静默）；网络/即时告警按「同一哨兵每业务日一次」频控：先问共用频控
 * shouldSendAlert、再问当日闸，顺序与 auditMonitor.js:178-193 同口径——
 * 被抑制时"退回的是哪一道闸"可归因。探测方拿名单重试不会把告警通道刷成噪音，
 * 但每一次尝试都留正式审计（append-only）。
 *
 * 【名单与检测分离】名单是什么、CANARY_USERNAMES 怎么解析在
 * constants/canaryAccounts.js；本文件只消费。recordGhostAttempt 是热路径
 * （每次登录失败调用一次）：非名单名在归一化 + 小数组 includes 后立即返回，
 * 零副作用。
 *
 * 【两种调用形态（有意为之，勿改）】
 *  - 审计 action 必须裸 `ALERT_TYPES.<KEY>`：tests/helpers/auditWriteSites.js 的
 *    resolveActionExpr 只认这一形态，模块前缀会被审计门禁判成 unresolved；
 *  - dispatchNotification 以 `securityAlert.<fn>` 命名空间调用：测试可直接
 *    spyOn(securityAlert, 'dispatchNotification') 拦截断言（auditMonitor.js 对
 *    sendNotification 同型）。入参 type/level 用 `securityAlert.ALERT_TYPES.<KEY>`
 *    形态——出站契约允许一个模块前缀，且实参不是裸标识符 ⇒ 不计入动态调用点
 *    （outboundAlertContract 前提自证里 dynamic 必须恒为 1）。
 */

const User = require('../models/User');
const AuditLog = require('../models/AuditLog');
const logger = require('../utils/logger');
const securityAlert = require('./securityAlert');
const { guardDetection, errText } = require('../utils/auditWriteFailure');
const { normalizeIP, ipAttributionRiskFactors, resolvePunishTarget } = require('../utils/ipUtils');
const { businessDateParts } = require('../constants/timezone');
const { parseCanaryUsernames, findCanaryMatch } = require('../constants/canaryAccounts');

const { ALERT_TYPES } = securityAlert;

/**
 * 当日已推送表：key = 命中的哨兵名（名单本身有界，Map 也随之有界），
 * value = 业务日期串（businessDateParts().dateStr，与 securityController
 * 今日统计同一时区口径）。逐日自然过期，无需清理逻辑。
 */
const notifiedDayByCanary = new Map();

/** 遮蔽对账结果：null = 尚未检查（含对账失败），Set = 已检查（空集=全部干净） */
let shadowedNames = null;

/** init 幂等缓存；__resetForTest 置回 null 以便测试改 env 后重跑 */
let initPromise = null;

/** 每次实时解析生效名单：不设缓存 ⇒ env 变更/测试重置无需失效逻辑，开销可忽略 */
const effectiveNames = () => parseCanaryUsernames(process.env.CANARY_USERNAMES).names;

/**
 * 大小写不敏感地判断是否是哨兵名。
 * @param {string} username
 * @returns {string|null} 命中的归一化哨兵名（稳定键），或 null
 */
const matchCanaryName = (username) => findCanaryMatch(username, effectiveNames());

/**
 * 记录一次幽灵名探测：审计必写 + 每日一次告警（见文件头「审计与通知解耦」）。
 * 调用方（login 的 `!user` 分支）应 fire-and-forget 调用并自带 catch——
 * 本函数经 guardDetection 包裹后永不 reject，但调用点保持防御性口径。
 *
 * @param {object} ctx
 * @param {string} ctx.username 登录请求提交的用户名（原样，审计 setter 会清洗）
 * @param {string} [ctx.ip] 客户端 IP（未归一化）
 * @param {object} [ctx.attribution] resolvePunishableIp 的裁定结果（可选）
 */
async function recordGhostAttempt({
  username,
  ip,
  userAgent,
  fingerprint,
  method,
  path,
  attribution,
} = {}) {
  const canary = matchCanaryName(username);
  if (canary === null) return; // 热路径绝大多数：不是名单名，立即返回

  // 口径（与 checkBruteForce 同）：审计/去重都记**归一化 IP**，
  // `::ffff:1.2.3.4` 与 `1.2.3.4` 不得成为两条记录
  const punishTarget = resolvePunishTarget(attribution, ip);
  const normalizedIp = normalizeIP(punishTarget) || punishTarget;

  // 审计无条件写——频控只约束网络告警，不允许遮挡"探过"这一事实
  try {
    await AuditLog.create({
      action: ALERT_TYPES.CANARY_USERNAME_ATTEMPT,
      category: 'auth',
      username,
      ip: normalizedIp,
      userAgent,
      fingerprint,
      method,
      path,
      success: false,
      riskLevel: 'critical',
      riskFactors: [
        'canary_username_attempt',
        'nonexistent_account_probe',
        ...ipAttributionRiskFactors(attribution && attribution.kind),
      ],
      reason: 'canary_username_probe',
      body: { canary },
    });
  } catch (err) {
    logger.error(`哨兵用户名审计写入失败（不影响登录响应）：${errText(err)}`, { canary });
  }

  const dayWindow = businessDateParts().dateStr;
  const allowedByThrottle = securityAlert.shouldSendAlert(`canary_username_${canary}_${dayWindow}`);
  if (!allowedByThrottle) return;
  if (notifiedDayByCanary.get(canary) === dayWindow) return;
  notifiedDayByCanary.set(canary, dayWindow); // 占位在推送前（同 auditMonitor 口径）

  securityAlert.dispatchNotification(
    securityAlert.ALERT_TYPES.CANARY_USERNAME_ATTEMPT,
    securityAlert.ALERT_LEVELS.CRITICAL,
    `检测到哨兵用户名探测：'${username}'（系统保留名，不应对应任何真实账户）`,
    { canary, ip: normalizedIp }
  );
}

/**
 * 启动期遮蔽对账：名单里的名字若真实占用（大小写不敏感口径），对应哨兵的
 * 登录面检测会静默失效，必须显式告警（fail-loud）。幂等；内部兜底，
 * **永不 reject**（对账失败按"未检查"处理，不影响名单匹配）。调用方
 * （src/index.js）仍可 .catch 兜一道，双保险。
 */
function init() {
  if (initPromise === null) {
    initPromise = (async () => {
      const { names, fromEnv, errors } = parseCanaryUsernames(process.env.CANARY_USERNAMES);
      for (const message of errors) logger.error(`哨兵用户名配置问题：${message}`);
      try {
        const occupied = await User.find({ username: { $in: names } })
          .collation(User.USERNAME_COLLATION)
          .select('username')
          .lean();
        if (occupied.length > 0) {
          shadowedNames = new Set(occupied.map((u) => u.username));
          logger.error(
            `安全哨兵名单存在遮蔽：${[...shadowedNames].join(', ')} 在用户集合中真实存在，` +
              '这些哨兵在登录路径不会触发（真实账户走不到「用户名不存在」分支）；' +
              '请移除/改名这些账户，或调整 CANARY_USERNAMES'
          );
        } else {
          shadowedNames = new Set();
          logger.info(
            `安全哨兵已生效：${names.length} 个幽灵用户名（来源：${
              fromEnv ? 'CANARY_USERNAMES' : '默认名单'
            }）`
          );
        }
      } catch (err) {
        // shadowedNames 保持 null（= 未检查），getStatus().checked 为 false：
        // 不把"查不了"渲染成"查过且干净"
        logger.error(`安全哨兵遮蔽对账失败（按未检查处理，不影响名单匹配）：${errText(err)}`);
      }
    })();
  }
  return initPromise;
}

/**
 * 合规面板用状态：只报规模与遮蔽情况，不回传完整名单（名单本身不算机密，
 * 但没有展示需求就不外扩暴露面）。
 */
function getStatus() {
  const { names, fromEnv, errors } = parseCanaryUsernames(process.env.CANARY_USERNAMES);
  return {
    count: names.length,
    fromEnv,
    checked: shadowedNames !== null,
    shadowed: shadowedNames === null ? null : [...shadowedNames],
    configErrors: errors,
  };
}

/** 测试专用：清空当日推送表与对账状态，使 init 可重跑（名单无缓存，无需清） */
function __resetForTest() {
  notifiedDayByCanary.clear();
  shadowedNames = null;
  initPromise = null;
}

module.exports = {
  matchCanaryName,
  recordGhostAttempt: guardDetection('哨兵用户名检测', recordGhostAttempt),
  init,
  getStatus,
  __resetForTest,
};
