/**
 * 数值型环境变量的统一解析
 *
 * 为什么要有这个文件：本仓多处配置写成 `Number(process.env.X) || 默认值`。
 * 这个惯用法有两个方向都错的坑，且都已被单独修过（swagger 的 P2-37/P2-70、
 * config 的 P2-39、retention 的钳制），但每次都是就地打补丁，于是始终有漏网的：
 *  - **负值是真值**：`Number('-1') || 15000` 得到 `-1`，原样生效。
 *    落到审计链锁超时上 ⇒ 每次 `Promise.race` 立即超时 ⇒ 链尾永不推进、
 *    所有带哈希的审计降级为 legacy；落到缓冲硬上限上 ⇒ 每次 push 都"超限"丢最旧。
 *  - `0` 会被 `||` 悄悄换成默认值，运维写的"0（不限制）"没有任何反馈。
 *
 * 判据统一在这里：只有「有限正数」（需要整数时还必须是整数）才被采纳，
 * 其余一律回落默认值，并由**调用方**决定日志级别（本模块不依赖 logger，
 * 以便被 logger 自己使用而不形成加载期循环）。
 *
 * 刻意不做"最小值钳制"：多个既有测试要注入 1/5/80/150/200 这类极小正数来驱动
 * 超时与裁剪分支（见 src/tests/observability/auditBufferFlushAndWalGuards.test.js 等）。
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

module.exports = { readPositiveNumberEnv };
