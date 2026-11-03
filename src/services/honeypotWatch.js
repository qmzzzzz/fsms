const crypto = require('crypto'); // 生成诱饵账户那份「无人知晓」的真随机口令
const User = require('../models/User');
const AuditLog = require('../models/AuditLog');
const logger = require('../utils/logger');
const securityAlert = require('./securityAlert');
const { guardDetection, errText } = require('../utils/auditWriteFailure');
const { normalizeIP, ipAttributionRiskFactors, resolvePunishTarget } = require('../utils/ipUtils');
const { businessDateParts } = require('../constants/timezone');
const { parseCanaryUsernames } = require('../constants/canaryAccounts');
const {
  findNameOverlap,
  isHoneypotEnabled,
  isLurePassword,
  honeypotNameOf,
  parseHoneypotUsernames,
} = require('../constants/honeypotAccounts');
const { deriveHoneypotPersona } = require('../constants/honeypotPersonas');

const { ALERT_TYPES } = securityAlert; // 审计 action 必须裸 ALERT_TYPES.<KEY>：tests/helpers/auditWriteSites.js 的 resolveActionExpr 只认这一形态

const notifiedDayByHoneypot = new Map(); // 当日已推送表：key = 诱饵名（名单有界 ⇒ Map 有界），value = 业务日期串；逐日自然过期，无需清理
let lastStatus = { checked: false, enabled: false, provisioned: [], skipped: [], errors: [] }; // init 快照：checked=false 表示「未对账」，不把查不了渲染成查过且干净
let initPromise = null; // init 幂等缓存；__resetForTest 置回 null，使测试改 env 后可重跑

const isLureLogin = (user, password) =>
  user?.isHoneypot === true &&
  user.mfaEnabled !== true &&
  isHoneypotEnabled() &&
  isLurePassword(password); // 诱饵判定：账户带标志 + 未开 MFA（开了就走真实二段，不制造旁路）+ 总开关开 + 口令命中弱口令词干

const HONEYPOT_PLACEHOLDER_EMAIL_DOMAIN = 'honeypot.invalid'; // 保留 TLD（RFC 2606）：不可路由，且在导出/备份里一眼可辨
const OCCUPIED_NAME_ERROR = '诱饵名已被真实账户占用，拒绝接管（请改用其它诱饵名或先改名该账户）'; // 与超管名判据同批：绝不把真人账户打标成蜜罐

const statusOf = (checked, enabled, provisioned, skipped, errors) => {
  return { checked, enabled, provisioned, skipped, errors };
}; // 状态对象只有这一种形状：三处赋值共用构造器，避免同形状被 prettier 展成十几行、把 max-lines 顶穿

async function createHoneypotAccount(name, takenRealNames) {
  const existing = await User.findByUsername(name).select('_id username isHoneypot').lean();
  if (existing) {
    if (existing.isHoneypot === true) return { name, created: false, skipped: true };
    return { name, created: false, error: OCCUPIED_NAME_ERROR + '：' + name };
  }
  const persona = deriveHoneypotPersona(name, takenRealNames); // 画像按名字确定性派生：同名恒同画像（重跑幂等），且与已有诱饵不撞名——统一 realName 会让持库读权限者一眼认出整个蜜罐农场
  await User.create({
    username: name,
    email: name + '@' + HONEYPOT_PLACEHOLDER_EMAIL_DOMAIN, // 见域名常量的说明
    password: crypto.randomBytes(36).toString('base64url') + '!Aa1', // 真随机且无人知晓：诱饵口令判据不看它，它的作用只是「这一行看起来像真账户」
    realName: persona.realName,
    department: persona.department,
    roles: [], // 零权限：凭证被攻破时爆炸半径为空，攻击者只能拿到一个处处 403 的会话（其尝试本身即情报）
    status: 'active',
    isHoneypot: true,
  });
  return { name, created: true, realName: persona.realName };
}

async function provision() {
  if (!isHoneypotEnabled()) return { enabled: false, created: [], skipped: [], errors: [] };
  const { names, errors } = parseHoneypotUsernames();
  const created = [];
  const skipped = [];
  const failures = [...errors];
  const taken = (await User.find({ isHoneypot: true }).select('realName').lean())
    .map((d) => d.realName)
    .filter(Boolean); // 已有诱饵的画像参与去重：重跑与分批物化都不会撞出同名画像
  for (const name of names) {
    try {
      const outcome = await createHoneypotAccount(name, taken);
      if (outcome.created) {
        created.push(name);
        taken.push(outcome.realName);
      } else if (outcome.skipped) skipped.push(name);
      else failures.push(outcome.error);
    } catch (err) {
      failures.push('诱饵账户 ' + name + ' 创建失败（名字不合 schema 规则等）：' + errText(err));
    }
  }
  return { enabled: true, created, skipped, errors: failures };
}

async function runInit() {
  const canaryConfig = parseCanaryUsernames(process.env.CANARY_USERNAMES);
  const config = parseHoneypotUsernames();
  try {
    for (const message of config.errors) logger.error('蜜罐用户名配置问题：' + message);
    const overlap = findNameOverlap(config.names, canaryConfig.names);
    if (overlap.length > 0)
      logger.info('蜜罐名单与哨兵名单重叠（这些哨兵名已升级为蜜罐账户）：' + overlap.join(', '));
    if (config.dropped.length > 0)
      logger.info(`诱饵名单剔除超管名（生效名单永不含超管名）：${config.dropped.join(', ')}`);
    if (!isHoneypotEnabled()) {
      lastStatus = statusOf(true, false, [], [], config.errors);
      logger.info(
        '蜜罐账户未启用（HONEYPOT_ENABLED 未置真值）：不物化任何账户，登录路径也不会放行任何标志位账户'
      );
      return;
    }
    const result = await provision();
    for (const message of result.errors) logger.error('蜜罐账户问题：' + message);
    const mfaOnDecoy = await User.countDocuments({ isHoneypot: true, mfaEnabled: true }); // 诱饵判据要求账户未开 MFA：开了就静默失效，启动期必须 fail-loud
    if (mfaOnDecoy > 0)
      logger.error(`诱饵账户已开 MFA（${mfaOnDecoy} 个）：诱饵口令判据已静默失效`);
    lastStatus = statusOf(true, true, result.created, result.skipped, result.errors);
    logger.info(
      `蜜罐账户已就绪：新建 ${result.created.length} 个、沿用 ${result.skipped.length} 个`
    );
    logger.info('诱饵名单来源：' + (config.fromEnv ? 'HONEYPOT_USERNAMES' : '默认名单'));
  } catch (err) {
    lastStatus = statusOf(false, isHoneypotEnabled(), [], [], [errText(err)]);
    logger.error(
      '蜜罐账户初始化失败（按「未就绪」处理，不影响登录与其余启动流程）：' + errText(err)
    );
  }
}

function init() {
  if (initPromise === null) initPromise = runInit();
  return initPromise;
}

async function recordHoneypotLogin({
  username,
  ip,
  userAgent,
  fingerprint,
  method,
  path,
  attribution,
  credentialShape,
} = {}) {
  const honeypot = honeypotNameOf(username);
  const punishTarget = resolvePunishTarget(attribution, ip);
  const normalizedIp = normalizeIP(punishTarget) || punishTarget;
  try {
    await AuditLog.create({
      action: ALERT_TYPES.HONEYPOT_LOGIN,
      category: 'auth',
      username,
      ip: normalizedIp,
      userAgent,
      fingerprint,
      method,
      path,
      success: true,
      riskLevel: 'critical',
      riskFactors: [
        'honeypot_account_login',
        'deceptive_account_interaction',
        ...ipAttributionRiskFactors(attribution && attribution.kind),
      ],
      reason: 'honeypot_account_login',
      body: credentialShape ? { honeypot, credentialShape } : { honeypot },
    });
  } catch (err) {
    logger.error('蜜罐账户登录审计写入失败（不影响登录响应）：' + errText(err), { honeypot });
  }
  const honeypotMarkOptions = { reason: 'honeypot_login', source: 'honeypotWatch' }; // 取证标记（P1 钩子b）：记录之后才标记——蜜罐登录=攻击者已持会话
  try {
    require('./forensicTrigger').markForensicTarget(normalizedIp, honeypotMarkOptions);
  } catch (_) {} // 失败怎么办：mark 内部吞异常并计数（fail-visible），壳只兜 require 期异常——都不得改变记录/告警行为
  const dayWindow = businessDateParts().dateStr;
  if (!securityAlert.shouldSendAlert('honeypot_login_' + honeypot + '_' + dayWindow)) return;
  if (notifiedDayByHoneypot.get(honeypot) === dayWindow) return;
  notifiedDayByHoneypot.set(honeypot, dayWindow); // 占位在推送前（同 auditMonitor/canaryWatch 口径）
  securityAlert.dispatchNotification(
    securityAlert.ALERT_TYPES.HONEYPOT_LOGIN,
    securityAlert.ALERT_LEVELS.CRITICAL,
    "蜜罐账户 '" + username + "' 被成功登录（诱饵口令命中）：攻击者已获得一个零权限会话",
    { honeypot, ip: normalizedIp }
  );
}

async function recordHoneypotSocketProbe(username, socket) {
  // WS 侧留痕：推送通道的建立企图与 HTTP 探测同表（action 同值、风险等级 critical）
  const honeypot = honeypotNameOf(username);
  const {
    resolveHandshakeIPForSecurityDecision: wsSecIp,
    resolveTrustProxyHops: wsHops,
  } = require('./websocketService/handshake'); // 惰性：handshake.js 顶部反向依赖本模块（isHoneypotSocket），加载期互引会成环
  const hs = socket && socket.handshake;
  const ip = normalizeIP(hs ? wsSecIp(hs, wsHops()) : null) || null;
  try {
    await AuditLog.create({
      action: ALERT_TYPES.HONEYPOT_PROBE,
      category: 'security',
      username,
      ip,
      method: 'WS',
      path: 'ws://handshake',
      success: true,
      riskLevel: 'critical',
      riskFactors: ['honeypot_account_socket_attempt', 'deceptive_account_interaction'],
      reason: 'honeypot_account_probe',
      body: { honeypot, verdict: 'deny' },
    });
  } catch (err) {
    logger.error('蜜罐账户 WS 探测审计写入失败（不影响拒绝）：' + errText(err), { honeypot });
  }
  const dayWindow = businessDateParts().dateStr;
  const throttleKey = 'honeypot_socket_' + honeypot + '_' + dayWindow;
  if (!securityAlert.shouldSendAlert(throttleKey)) return;
  if (notifiedDayByHoneypot.get(throttleKey) === dayWindow) return;
  notifiedDayByHoneypot.set(throttleKey, dayWindow);
  securityAlert.dispatchNotification(
    securityAlert.ALERT_TYPES.HONEYPOT_PROBE,
    securityAlert.ALERT_LEVELS.CRITICAL,
    "蜜罐账户 '" + username + "' 试图建立 WebSocket 推送通道（已拒绝，未绑定身份）",
    { honeypot, method: 'WS', path: 'ws://handshake', ip }
  );
}

function isHoneypotSocket(freshUser, socket) {
  // 同步判据：握手链的 await 序列不许被审计 IO 改写（websocketAuthGhostConnection 的结构闸按位置钉住）
  if (!freshUser || freshUser.isHoneypot !== true) return false; // 只看 DB 标志、不看总开关：WS 一旦建通道就能订阅推送，关开关的正当代价不该是把诱饵放进推送面（fail-closed）
  try {
    socket.emit('auth-error', { message: '账户已被禁用或锁定' });
    socket.disconnect(true);
  } catch (err) {
    logger.warn('蜜罐会话拒绝断开失败：' + errText(err), { socketId: socket && socket.id });
  }
  recordHoneypotSocketProbe(freshUser.username, socket).catch(() => {}); // fire-and-forget：留痕失败绝不影响拒绝
  return true;
}

const { decorateLureSession } = require('./honeypotLurePresentation');

async function recordHoneypotProbe({
  username,
  method,
  path,
  verdict,
  writeAttempt,
  ip,
  attribution,
} = {}) {
  const honeypot = honeypotNameOf(username);
  // F1：惩罚/留痕目标按 resolvePunishableIp 的裁定取（punishIp）；PUBLIC_PEER_HEADER 下 punishIp 已是 socket 对端——伪造 XFF 的探测不再落到受害者 IP 名下
  const punishTarget = resolvePunishTarget(attribution, ip);
  const normalizedIp = normalizeIP(punishTarget) || punishTarget;
  try {
    await AuditLog.create({
      action: ALERT_TYPES.HONEYPOT_PROBE,
      category: 'security',
      username,
      ip: normalizedIp,
      method,
      path,
      success: true,
      riskLevel: writeAttempt ? 'critical' : 'high',
      riskFactors: [
        writeAttempt ? 'honeypot_account_write_attempt' : 'honeypot_account_probe',
        'deceptive_account_interaction',
        ...ipAttributionRiskFactors(attribution && attribution.kind),
      ],
      reason: 'honeypot_account_probe',
      body: { honeypot, verdict },
    });
  } catch (err) {
    logger.error('蜜罐账户探测审计写入失败（不影响响应）：' + errText(err), { honeypot, path });
  }
  const dayWindow = businessDateParts().dateStr;
  const throttleKey =
    (writeAttempt ? 'honeypot_write_' : 'honeypot_probe_') + honeypot + '_' + dayWindow;
  if (!securityAlert.shouldSendAlert(throttleKey)) return;
  if (notifiedDayByHoneypot.get(throttleKey) === dayWindow) return;
  notifiedDayByHoneypot.set(throttleKey, dayWindow); // 与登录告警共用同一张当日表（键含类别，互不挤占）
  const actionText = writeAttempt ? '尝试写入' : '读取';
  const alertText =
    "蜜罐账户 '" + username + "' 在陷阱会话中" + actionText + '：' + method + ' ' + path;
  const alertMeta = { honeypot, method, path, verdict, ip: normalizedIp };
  if (writeAttempt) {
    securityAlert.dispatchNotification(
      securityAlert.ALERT_TYPES.HONEYPOT_PROBE,
      securityAlert.ALERT_LEVELS.CRITICAL,
      alertText,
      alertMeta
    );
  } else {
    securityAlert.dispatchNotification(
      securityAlert.ALERT_TYPES.HONEYPOT_PROBE,
      securityAlert.ALERT_LEVELS.HIGH,
      alertText,
      alertMeta
    );
  }
}

function getStatus() {
  const { names, fromEnv, errors } = parseHoneypotUsernames();
  return {
    enabled: isHoneypotEnabled(),
    nameCount: names.length,
    fromEnv,
    checked: lastStatus.checked,
    provisioned: [...lastStatus.provisioned],
    skipped: [...lastStatus.skipped],
    configErrors: [...errors, ...lastStatus.errors],
  };
}

function __resetForTest() {
  notifiedDayByHoneypot.clear();
  lastStatus = { checked: false, enabled: false, provisioned: [], skipped: [], errors: [] };
  initPromise = null;
}

module.exports = {
  __resetForTest,
  decorateLureSession,
  isHoneypotSocket,
  getStatus,
  init,
  isLureLogin,
  recordHoneypotLogin: guardDetection('蜜罐账户检测', recordHoneypotLogin),
  recordHoneypotProbe: guardDetection('蜜罐账户探测', recordHoneypotProbe),
  recordHoneypotSocketProbe: guardDetection('蜜罐账户 WS 探测', recordHoneypotSocketProbe),
};
