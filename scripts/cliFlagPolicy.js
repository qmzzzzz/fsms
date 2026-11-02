/**
 * 破坏性脚本的「开关白名单」解析（2026-10-21）
 *
 * 本仓已有三处各自实现过同一件事（`deployPolicy.js`、`bundleBudgetPolicy.js`、
 * `generate-secrets.js` 各有一份 `suggestFlag`），第四处是 `migrate-pii-encryption.js`。
 * 抽出来的直接动因是后者：它把五个开关写成五个独立 `if`，未知参数一律当没看见，
 * 于是 `--keys-onl`（少一个字母）不报错 ⇒ `keysOnly` 保持 false ⇒ 脚本退化为
 * **默认全量模式**（加密列 + 回填检索键 + 升级 v1），而操作者以为只补键。
 * 一个字母的差距，方向从"只补键"变成"批量改写 PII 列"。
 *
 * 判据（与 deploy 的 `--dryrun` 同一口径）：
 *  - 白名单外的一切 token（含位置参数）都进 errors，由调用方在**产生副作用之前**拒绝；
 *  - 报错文案要能直接照抄修复，故给 closest 建议。
 *
 * 为什么建议用编辑距离而不是「抹平非字母后全等」：全等法对 `--dryrun`（多/少连字符）
 * 有效，但对 `--keys-onl`（少一个字母）永不命中——`keysonl` ≠ `keysonly`。
 * 而"少打一个字母"恰恰是这类脚本最常见也最危险的误输，所以这里按距离 ≤ 2 取最近项。
 */

'use strict';

const flagShape = (s) =>
  String(s)
    .replace(/[^a-z]/gi, '')
    .toLowerCase();

/** Levenshtein 距离（两行滚动数组；token 都是短字符串，不做优化） */
function editDistance(a, b) {
  const prev = Array.from({ length: b.length + 1 }, (_, j) => j);
  for (let i = 1; i <= a.length; i += 1) {
    let diag = prev[0];
    prev[0] = i;
    for (let j = 1; j <= b.length; j += 1) {
      const tmp = prev[j];
      prev[j] = Math.min(prev[j] + 1, prev[j - 1] + 1, diag + (a[i - 1] === b[j - 1] ? 0 : 1));
      diag = tmp;
    }
  }
  return prev[b.length];
}

/**
 * @param {string} token 用户输入的未知 token
 * @param {string[]} allowed 白名单
 * @param {number} [maxDistance=2] 超过这个距离就不给建议（避免对无相似项凭空猜测）
 * @returns {string|null}
 */
function suggestFlag(token, allowed, maxDistance = 2) {
  const t = flagShape(token);
  let best = null;
  let bestD = Infinity;
  for (const f of allowed) {
    const d = editDistance(t, flagShape(f));
    if (d < bestD) {
      bestD = d;
      best = f;
    }
  }
  return bestD <= maxDistance ? best : null;
}

/**
 * 解析开关：只认白名单，其余全部报错。
 *
 * @param {string[]} argv 参数列表（不含 node 与脚本路径）
 * @param {string[]} allowed 白名单（闭合集合，新增开关必须同步）
 * @param {object} [opts]
 * @param {string} [opts.usage] 报错时附带的用法提示（可省略）
 * @returns {{flags: Set<string>, errors: string[]}}
 */
function parseFlags(argv, allowed, { usage } = {}) {
  const flags = new Set();
  const errors = [];
  for (const token of argv) {
    if (allowed.includes(token)) {
      flags.add(token);
      continue;
    }
    const hint = suggestFlag(token, allowed);
    errors.push(
      `未知参数：「${token}」（本脚本只接受 ${allowed.join(' / ')}）` +
        (hint ? `；是否想写 ${hint}？` : '')
    );
  }
  if (errors.length && usage) errors.push(`用法：${usage}`);
  return { flags, errors };
}

/**
 * 未知参数 ⇒ 立刻拒绝（stderr 报错 + 退出码 2）。
 *
 * 为什么单独给一个"打印并退出"的入口，而不是让调用方自己判 errors：本仓已三处手写同一段
 * （`deployPolicy.js`、`lint-ratchet.js:47-55`、`commentDensity.js:68-75`），调用方再抄一遍
 * 就是又一份会各自漂移的口径。退出码沿用同一约定：
 *   2 = 用法错误（未知参数）  ← 与 1 = 存在缺失/有债 分开，但两者都非零、CI 一律拦。
 *
 * 只在**确认自己作为脚本执行**的分支里调用（`require.main === module` 之后，或该文件唯一的
 * main 路径）。本仓脚本多数被测试 require：模块顶层校验进程 argv 会让 jest 进程直接 exit 2
 * ——`lint-ratchet.js:43-46` 与 `commentDensity.js` 都为此把校验收进 main。
 *
 * @param {string[]} argv 参数列表（不含 node 与脚本路径）
 * @param {string[]} allowed 白名单
 * @param {object} [opts] 同 parseFlags（usage 等）
 * @returns {Set<string>} 命中的开关
 */
function assertKnownArgs(argv, allowed, opts) {
  const { flags, errors } = parseFlags(argv, allowed, opts);
  if (errors.length === 0) return flags;
  process.stderr.write(`${errors.join('\n')}\n`);
  process.exit(2);
}

module.exports = { parseFlags, assertKnownArgs, suggestFlag, editDistance, flagShape };
