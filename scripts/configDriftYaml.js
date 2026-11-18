'use strict';

/**
 * 仓内零依赖 YAML 子集解析器（config-drift-check.js 的解析底座）。
 *
 * 为什么自己写：js-yaml 是传递依赖，`npm ci --omit=dev` 的运行镜像里没有它，
 * 而漂移检测必须能在**只有生产依赖**的容器里解析 docker-compose.yml。
 *
 * 能力边界（支持）：
 *   · 单文档；块映射 / 块序列 / 流式集合（[...] {...}，可跨行）；
 *   · 块标量 `|` 与 `>`（含 chomping `-`）；行内注释（引号内的 # 不算）；
 *   · 标量类型口径对齐 js-yaml core（布尔/整数/浮点/null，其余一律字符串）；
 *   · `!override` / `!reset` 等标签——由调用方剥掉标签 token 后再进来（compose 特有）。
 * 不支持的形态一律**抛错**（fail-closed，由调用方按「配置面不可解析」拒绝），不静默给错账面：
 *   · 锚点/别名（&a / *a）、多文档（--- 分隔的后续文档）、复杂键（? 显式键）；
 *   · 序列内映射项（`- key: value`）；
 *   · **重复的映射键**：YAML 规范本身禁止，而漂移检测按「键 → 值」抽面，重复键若按
 *     「后者覆盖前者」静默处理，等于把其中一份配置移出账面（改前值而闸不红）。故改为
 *     报错并附键名与行号（2026-11-17 审计：先扫过现有 docker-compose.yml 确认无重复键，
 *     本改动不改变任何现存文件的解析结果）。
 */

const {
  parseScalar,
  stripInlineComment,
  hasKeyColon,
  splitKey,
  parseFlowFrom,
  isSkippable,
} = require('./configDriftYamlLex');

const splitIndent = (raw) => {
  const m = /^([ \t]*)(.*)$/.exec(raw);
  return { indent: m[1].length, text: m[2] };
};

function parseBlockScalar(lines, i, parentIndent, indicator) {
  // | 与 >（含 chomping）；内容缩进取首行，末尾空行剥掉
  const folded = indicator[0] === '>';
  const chomp = indicator.includes('-') ? 'strip' : 'clip';
  const raws = [];
  let baseIndent = -1;
  let j = i;
  while (j < lines.length) {
    if (lines[j].trim() === '') {
      raws.push('');
      j += 1;
      continue;
    }
    const { indent, text } = splitIndent(lines[j]);
    if (indent <= parentIndent) break;
    if (baseIndent === -1) baseIndent = indent;
    if (indent < baseIndent) break;
    raws.push(' '.repeat(indent - baseIndent) + text);
    j += 1;
  }
  while (raws.length > 0 && raws[raws.length - 1] === '') raws.pop();
  let value = raws.join(folded ? ' ' : '\n');
  if (chomp === 'clip' && value !== '') value += '\n';
  return { value, i: j };
}

const stripLeadingTag = (rest) => (rest[0] === '!' ? rest.replace(/^!\S+\s*/, '').trim() : rest); // !override / !reset 等标签：剥掉标签 token，余下才是值

function parseValue(lines, i, keyIndent, rawRest) {
  // 行内值 / 块标量 / 流式集合 / 更深缩进的嵌套节点
  const rest = stripLeadingTag(rawRest);
  if (rest === '') {
    let j = i;
    while (j < lines.length && isSkippable(lines[j])) j += 1;
    if (j >= lines.length) return { value: null, i: j };
    if (splitIndent(lines[j]).indent > keyIndent) return parseNode(lines, j);
    return { value: null, i };
  }
  const c = rest[0];
  if (c === '|' || c === '>') {
    return parseBlockScalar(lines, i, keyIndent, rest.split(/\s/, 1)[0]);
  }
  if (c === '[' || c === '{') return parseFlowFrom(lines, i, rest);
  return { value: parseScalar(stripInlineComment(rest)), i };
}

function parseBlockMap(lines, i) {
  const { indent } = splitIndent(lines[i]);
  const obj = {};
  let cursor = i;
  while (cursor < lines.length) {
    if (isSkippable(lines[cursor])) {
      cursor += 1;
      continue;
    }
    const { indent: ind, text } = splitIndent(lines[cursor]);
    if (ind < indent) break;
    if (ind > indent) throw new Error(`意外的缩进（第 ${cursor + 1} 行）：${text.slice(0, 60)}`);
    const keyLine = cursor; // 0 基行号（splitKey 的报错口径是 +1，这里保持一致）
    const { key, rest } = splitKey(text, cursor);
    cursor += 1;
    const parsed = parseValue(lines, cursor, indent, rest);
    // 重复键 fail-loud：静默覆盖会让「改掉被覆盖的那份」在漂移账面上不可见（见文件头）。
    if (Object.prototype.hasOwnProperty.call(obj, key)) {
      throw new Error(
        `重复的映射键「${key}」（第 ${keyLine + 1} 行起）：后者会静默覆盖前者，` +
          '漂移检测按「键 → 值」抽面，重复键等于把其中一份配置移出账面——请合并重复键后再解析'
      );
    }
    obj[key] = parsed.value;
    cursor = parsed.i;
  }
  return { value: obj, i: cursor };
}

function parseSeqItem(lines, cursor, indent, itemText) {
  // 序列项三态：块标量 / 流式集合 / 纯标量（映射项不支持，抛错）
  const c = itemText[0];
  if (c === '|' || c === '>') {
    const bs = parseBlockScalar(lines, cursor, indent, itemText.split(/\s/, 1)[0]);
    return { value: bs.value, i: bs.i };
  }
  if (c === '[' || c === '{') {
    const fl = parseFlowFrom(lines, cursor, itemText);
    return { value: fl.value, i: fl.i };
  }
  const item = stripInlineComment(itemText);
  if (hasKeyColon(item)) {
    throw new Error(`暂不支持的序列内映射项（第 ${cursor} 行）：${item.slice(0, 60)}`);
  }
  return { value: parseScalar(item), i: cursor };
}

function parseBlockSeq(lines, i) {
  const { indent } = splitIndent(lines[i]);
  const arr = [];
  let cursor = i;
  while (cursor < lines.length) {
    if (isSkippable(lines[cursor])) {
      cursor += 1;
      continue;
    }
    const { indent: ind, text } = splitIndent(lines[cursor]);
    if (ind < indent) break;
    if (ind > indent) throw new Error(`意外的缩进（第 ${cursor + 1} 行）：${text.slice(0, 60)}`);
    if (text !== '-' && !text.startsWith('- ')) break;
    const itemText = stripLeadingTag(text === '-' ? '' : text.slice(2).trim());
    cursor += 1;
    if (itemText === '') {
      let j = cursor;
      while (j < lines.length && isSkippable(lines[j])) j += 1;
      if (j < lines.length && splitIndent(lines[j]).indent > indent) {
        const nested = parseNode(lines, j);
        arr.push(nested.value);
        cursor = nested.i;
      } else {
        arr.push(null);
      }
      continue;
    }
    const parsed = parseSeqItem(lines, cursor, indent, itemText);
    arr.push(parsed.value);
    cursor = parsed.i;
  }
  return { value: arr, i: cursor };
}

function parseNode(lines, i) {
  const { text } = splitIndent(lines[i]);
  if (text.startsWith('[') || text.startsWith('{')) return parseFlowFrom(lines, i + 1, text);
  if (text === '-' || text.startsWith('- ')) return parseBlockSeq(lines, i);
  return parseBlockMap(lines, i);
}

function parse(text) {
  // 入口：只支持单文档；解析不了就抛（调用方按「配置面不可解析」拒绝）
  const lines = String(text).replace(/\r\n?/g, '\n').split('\n');
  let i = 0;
  while (i < lines.length && isSkippable(lines[i])) i += 1;
  if (i < lines.length && lines[i].trim() === '---') i += 1; // 跳过文档起始标记
  while (i < lines.length && isSkippable(lines[i])) i += 1;
  if (i >= lines.length) return null;
  return parseNode(lines, i).value;
}

module.exports = { parse };
