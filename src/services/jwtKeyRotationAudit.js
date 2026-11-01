/**
 * JWT 签发密钥轮换的启动期留痕（P2-3）
 *
 * 为什么是「变化检测」而不是每次启动都记：每次写一条 `jwt_key_rotated` 会让该 action 的事件数
 * 等于重启次数，真正的轮换被淹没——事后无法回答「旧密钥是哪天停用的」。基线（上次启动生效的
 * kid）落在 SystemConfig，只有当前值与之不同才落审计；首次启动只登记基线（首次配置不是轮换）。
 *
 * 多副本并发启动：基线读取后用一次带旧值条件的 findOneAndUpdate 原子认领，只有把旧值改成新值的
 * 副本拿得到旧文档并记录；其余副本 filter 不再匹配（或 upsert 撞唯一索引 E11000）直接跳过。
 * 只记 kid、不记密钥本身（连指纹都不记）：审计集合 append-only 且会导出 CSV，任何可离线验证密钥
 * 的派生值都不该进去。直换 JWT_SECRET 的单钥轮换在这里不可观测（前后 kid 都是 null），
 * 见 deployment/secret-rotation.md。
 */

const jwtKeys = require('../utils/jwtKeys');
const SystemConfig = require('../models/SystemConfig');
const AuditLog = require('../models/AuditLog');

const MARKER_KEY = 'jwtSigningKeyIds';
const DESCRIPTION = 'JWT 当前签发 key id（P2-3 轮换留痕基线，勿手工修改）';

const label = (kid) => kid || 'single';

const parseMarker = (value) => {
  if (typeof value !== 'string') return null;
  try {
    const parsed = JSON.parse(value);
    if (!parsed || typeof parsed !== 'object') return null;
    return { access: parsed.access || null, refresh: parsed.refresh || null };
  } catch (_) {
    return null;
  }
};

/** 比较并更新基线；发生切换时写一条 `jwt_key_rotated` 审计。
 *  @returns {Promise<{before: object, after: object}|null>} 本次是否记录了轮换 */
async function recordJwtKeyRotation() {
  const current = jwtKeys.signingKids();
  const marker = JSON.stringify({ access: current.access, refresh: current.refresh });

  const stored = await SystemConfig.findOne({ key: MARKER_KEY }).lean();
  if (stored && stored.value === marker) return null;

  let claimed;
  try {
    if (!stored) {
      // 首次启动：登记基线。$setOnInsert 防止把并发启动的另一个副本刚写下的
      // 基线覆盖掉（那种情况下 filter 已命中，不会走到插入）
      await SystemConfig.findOneAndUpdate(
        { key: MARKER_KEY },
        { $setOnInsert: { value: marker, valueType: 'string', description: DESCRIPTION } },
        { upsert: true }
      );
      return null;
    }
    // 旧基线带条件认领：值已被别的副本改掉 ⇒ 本次不记（事件归认领者）
    claimed = await SystemConfig.findOneAndUpdate(
      typeof stored.value === 'string'
        ? { key: MARKER_KEY, value: stored.value }
        : { key: MARKER_KEY },
      { $set: { value: marker, valueType: 'string', description: DESCRIPTION } },
      { new: false }
    );
  } catch (err) {
    // 并发首次启动：另一方已插入基线；本副本按"无变化"处理
    if (err && err.code === 11000) return null;
    throw err;
  }
  if (!claimed) return null;

  const before = parseMarker(stored.value);
  const reason = before
    ? `JWT 签发密钥已切换：access ${label(before.access)} → ${label(current.access)}，` +
      `refresh ${label(before.refresh)} → ${label(current.refresh)}`
    : 'JWT 签发密钥已切换（旧基线不可解析，按当前配置重新登记）';

  // AuditLog.record 自带 catch（失败时记日志 + audit_write_failed 指标，resolve null）。
  // 它返回 null 时把基线退回旧值，让下次启动重试：宁可同一次轮换被记两遍，
  // 也不能让"密钥换过"这件事在审计里消失。退回本身失败说明库已不可用，
  // 不再掩盖——audit_write_failed 指标已在 record 内发出。
  const recorded = await AuditLog.record({
    action: 'jwt_key_rotated',
    category: 'system',
    username: 'system',
    ip: '127.0.0.1',
    success: true,
    riskLevel: 'medium',
    reason,
  });
  if (!recorded) {
    try {
      await SystemConfig.findOneAndUpdate(
        { key: MARKER_KEY, value: marker },
        { $set: { value: stored.value } },
        { new: false }
      );
    } catch (_) {
      /* 退回失败：等下次启动再比较；库恢复后基线仍是新值，事件会缺席一次 */
    }
    return null;
  }
  return { before, after: current };
}

module.exports = { recordJwtKeyRotation, MARKER_KEY };
