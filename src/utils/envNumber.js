/**
 * 数值型环境变量的统一解析。`Number(env.X) || 默认` 的坑（负值是真值、0 被 || 吞掉）多次
 * 单独修过但总有漏网，判据统一在这里：只有「有限正数」（需要整数时必须是整数）才被采纳，
 * 其余回落默认值，日志级别由调用方决定。刻意不做最小值钳制：既有测试要注入极小正数驱动
 * 超时与裁剪分支。完整论证见 docs/env-number.md。
 */

/**
 * 读取一个「必须为正数」的环境变量。
 * @param {string} name 环境变量名
 * @param {number} fallback 未配置或非法时的生效值
 * @param {{integer?: boolean, onInvalid?: (name: string, raw: string, fallback: number) => void}} [opts]
 *   integer=true 时还要求是整数（条目数、批次大小一类）；
 *   onInvalid 在"配置了但被判非法"时回调（告警归调用方，决定级别与措辞）
 * @returns {number} 生效值
 */
function readPositiveNumberEnv(name, fallback, opts = {}) {
  const { integer = false, onInvalid } = opts;
  const raw = process.env[name];
  if (raw === undefined || String(raw).trim() === '') return fallback;

  const parsed = Number(raw);
  const finitePositive = Number.isFinite(parsed) && parsed > 0;
  if (finitePositive && (!integer || Number.isInteger(parsed))) return parsed;

  if (typeof onInvalid === 'function') onInvalid(name, String(raw), fallback);
  return fallback;
}

/**
 * 读取一个「整数且限定区间」的环境变量：越界或非法一律回退 fallback（不钳到边界）。
 *
 * 与 readPositiveNumberEnv 的分工：那里刻意不做区间钳制（多份测试要注入 1/5/80 这类
 * 极小正数去驱动超时与裁剪分支），而批次大小一类参数需要硬区间。回退而不是“钳到边界”
 * 是因为越界配置本身就是错配，静默取边界会把错配藏起来；告警照旧归调用方（本模块不引 logger）。
 * @param {string} name
 * @param {number} fallback 未配置或非法时的生效值
 * @param {[number, number]} range 允许闭区间
 * @param {{onInvalid?: (name: string, raw: string, fallback: number) => void}} [opts]
 * @returns {number}
 */
function readClampedIntEnv(name, fallback, range, opts = {}) {
  const [min, max] = range;
  const raw = process.env[name];
  const parsed = Number(raw);
  const ok =
    raw !== undefined &&
    String(raw).trim() !== '' &&
    Number.isInteger(parsed) &&
    parsed >= min &&
    parsed <= max;
  if (ok) return parsed;
  if (typeof opts.onInvalid === 'function') {
    opts.onInvalid(name, raw === undefined ? '' : String(raw), fallback);
  }
  return fallback;
}

module.exports = { readPositiveNumberEnv, readClampedIntEnv };
