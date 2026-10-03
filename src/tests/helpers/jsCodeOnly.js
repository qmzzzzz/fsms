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
 * 行尾：入口先把 CRLF 归一成 LF。本仓 `core.autocrlf=true` 且 prettier 是
 * `endOfLine:"auto"`，Windows 工作区的源码是 CRLF 而 CI 是 LF；不归一的话每行尾部
 * 会挂一个 `\r`，于是 `/...$/m` 这类锚到行尾的判据只在其中一侧成立。
 *
 * @param {string} src JS 源码
 * @returns {string} 抹掉块注释、整行注释（**连行一起删**）与行尾注释后的 LF 视图
 */
function jsCodeOnly(src) {
  return view(src, false);
}

/**
 * 同一套"什么算注释"的口径，但**行号保持不变**：整行注释被抹成空行而不是删掉。
 *
 * 为什么要有第二个视图：`jsCodeOnly` 的块注释是保行号的（用空格替换），整行注释却是
 * 直接 filter 掉的——于是它的返回值行数一定 ≤ 源码行数，偏移量正好等于被删掉的注释行数。
 * 只做"某个串在不在"的判据不受影响（既有 8 个消费者全是这一类），但**任何要报告
 * `file:line` 的判据用它就会报错行号**：本仓第 15 轮写 stubReturnTypeParity 时，
 * 用 jsCodeOnly 扫桩站点，报出来的行号比真实行号小了 55（那 55 行是前面的注释），
 * 照着它给的红讯去改代码会改到别处。判据口径仍然只有一份（`view`），只是多一个视图。
 *
 * @param {string} src JS 源码
 * @returns {string} 行号与 src 一一对应的「只剩代码」LF 视图
 */
function jsCodeOnlyKeepingLines(src) {
  return view(src, true);
}

/** 唯一的注释屏蔽实现：keepLineNumbers=true 时整行注释抹成空行而非删除 */
function view(src, keepLineNumbers) {
  return String(src)
    .replace(/\r\n/g, '\n')
    .replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, ' '))
    .split('\n')
    .map((l) => {
      if (!/^\s*\/\//.test(l)) return l.replace(/\/\/[^\n]*/g, ' ');
      return keepLineNumbers ? '' : null;
    })
    .filter((l) => l !== null)
    .join('\n');
}

module.exports = { jsCodeOnly, jsCodeOnlyKeepingLines };
