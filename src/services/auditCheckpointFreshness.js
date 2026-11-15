// 检查点新鲜度臂（A4）：最近检查点距 now 超过预算 ⇒ degraded（type=checkpoint_stale）。
// 独立成模块的原因是体积棘轮：auditChainCheckpoint.js 的代码行数正好顶在 300。语义要点：
// 预算默认 26h = 2×13h cron 间隔上限的 2 倍容差，env CHECKPOINT_FRESHNESS_MS 可覆盖、
// 置 0 显式关闭（首次部署未排 cron 的豁免口）、负数/非数字回退默认；归 degraded 不判红（停摆与"运维手动暂停"在数据上不可分），但必须可见。
const DEFAULT_FRESHNESS_MS = 26 * 60 * 60 * 1000; // 2 × 13h

// 新鲜度预算（毫秒）：0=显式关闭；env 未配置（含空串/纯空白）或非法时回退默认。
// 空串必须按「未配置」处理：Number('') = 0 会被旧判据误读成显式关闭，静默关掉新鲜度臂
// （审计 2026-11-14 H，口径同 utils/envNumber 的「未配置 ≠ 非法」）。
const freshnessBudgetMs = () => {
  const raw = process.env.CHECKPOINT_FRESHNESS_MS;
  if (raw === undefined || String(raw).trim() === '') return DEFAULT_FRESHNESS_MS;
  const parsed = Number(raw);
  if (!Number.isFinite(parsed) || parsed < 0) return DEFAULT_FRESHNESS_MS;
  return parsed;
};

// 就地记一条 checkpoint_stale；previous 为空（空集合走 no_checkpoints 判红臂，不重复报）/ 预算 0 / 时间不可解析 / 预算内 ⇒ 不动
const pushStaleIfAny = (degraded, previous, now, budget) => {
  if (!(budget > 0) || !previous) return;
  const lastAt = new Date(previous.record.createdAt).getTime();
  const nowMs = new Date(now ?? new Date()).getTime();
  if (!(Number.isFinite(lastAt) && Number.isFinite(nowMs)) || nowMs - lastAt <= budget) return;
  degraded.push({
    line: previous.line,
    type: 'checkpoint_stale',
    message: `最近检查点 ${previous.record.createdAt} 距今超过 ${Math.round(
      budget / 3600000
    )}h（CHECKPOINT_FRESHNESS_MS=${budget}）：create 未按预期刷新，该锚点之后的尾部删除不可检出`,
  });
};

module.exports = { DEFAULT_FRESHNESS_MS, freshnessBudgetMs, pushStaleIfAny };
