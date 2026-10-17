/**
 * `.dockerignore` 的模式求值（测试用 helper，2026-10-17 从 secretCarriersIgnored.test.js 抽出）
 *
 * 为什么抽出来：F-10 要判"前端生成物目录是否进构建上下文"，F-09（密钥载体）判"密钥目录
 * 是否进构建上下文"，两者用的是**同一个** `.dockerignore` 语义。原先那段解析内联在
 * secretCarriersIgnored.test.js 里，第二个消费方只能复制一份——两份解析器漂移时，
 * 会出现"一个门禁判绿、另一个判红"这种最难查的分歧（本仓对"第二份真源"的一贯纪律）。
 *
 * 语义要点（与 docker 的实现对齐，都是踩过的坑）：
 *   - **按行序求值**，后面的模式覆盖前面的结论；`!` 反选必须能把前面忽略的放回来。
 *     写成"任一模式命中即忽略"会把 `!.env.example` 读成忽略。
 *   - 单 `*` **不跨目录分隔符**（docker 走 Go 的 filepath.Match），`**` 才跨。
 *   - 模式里没有 `/` 时 docker 会匹配任意层级，但本仓的规则都带路径或位于根级，
 *     所以这里只做"整串匹配"，并在调用方用完整相对路径断言——不复现那条兜底，
 *     避免自造第二套语义。
 */

/** 把一行 dockerignore 模式编译成 {negated, re} */
const compilePattern = (line) => {
  const trimmed = line.trim();
  if (trimmed === '' || trimmed.startsWith('#')) return null;
  const negated = trimmed.startsWith('!');
  const body = negated ? trimmed.slice(1) : trimmed;
  // 按 `**` 先切段（跨目录通配），段内再把单 `*` 换成"不跨 /"的通配。
  // 用切段而不是塞占位符：占位符要么用控制字符（eslint no-control-regex 直接报错），
  // 要么就可能撞进真实模式的字节里。
  const esc = (s) => s.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '[^/]*');
  return { negated, re: new RegExp(`^${body.split('**').map(esc).join('.*')}$`) };
};

/**
 * 解析 `.dockerignore` 全文，返回求值函数。
 * @param {string} text `.dockerignore` 内容
 * @returns {(name: string) => boolean} 给定相对路径是否被排除
 */
const makeDockerIgnored = (text) => {
  const patterns = text
    .split(/\r?\n/)
    .map(compilePattern)
    .filter(Boolean);
  return (name) => {
    let ignored = false;
    for (const p of patterns) {
      if (p.re.test(name)) ignored = !p.negated;
    }
    return ignored;
  };
};

module.exports = { compilePattern, makeDockerIgnored };
