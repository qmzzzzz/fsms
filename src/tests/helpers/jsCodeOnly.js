/**
 * 「只剩代码」视图（测试辅助）
 *
 * 为什么要抽出来：本仓已有四份逐字复制的实现（shutdownBudgetContract、
 * shutdownBudget 的兄弟套件、logShipperShutdownWiring、websocketAuthGhostConnection 等）。
 * 文本型闸门的语义全在这十几行里，复制一份就等于复制一份"到底什么算注释"的口径 ——
 * 任一处改坏，另一处仍然绿。新写的闸一律从这里取。
 * （既有四份暂不合并：其中一份是并行会话的文件，避免顺手改别人的在途测试。）
 *
 * 用途：任何"按源码文本判定"的闸门都必须跑在这个视图上，否则注释可以双向骗它：
 *  1) 骗绿 —— 在注释里补一个被要求的调用串，然后把真实调用删掉；
 *  2) 骗红 —— 在注释里写下本仓惯例要记录的反例（F-145 两向实测）。
 *
 * 已知边界（与既有四份一致，刻意不改）：行尾 `//` 屏蔽是纯文本级的，
 * 字符串字面量里的 `//`（如 `'https://x'`）同样会被抹掉。对"数某个调用串出现没有"
 * 这类判据无影响（调用串不含 `//`），但**不要**用它做涉及 URL 字面量的判定。
 *
 * @param {string} src JS 源码
 * @returns {string} 抹掉块注释（保行号）、整行注释与行尾注释后的视图
 */
function jsCodeOnly(src) {
  return String(src)
    .replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, ' '))
    .split('\n')
    .filter((l) => !/^\s*\/\//.test(l))
    .map((l) => l.replace(/\/\/[^\n]*/g, ' '))
    .join('\n');
}

module.exports = { jsCodeOnly };
