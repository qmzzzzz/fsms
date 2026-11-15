'use strict';

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
    const { key, rest } = splitKey(text, cursor);
    cursor += 1;
    const parsed = parseValue(lines, cursor, indent, rest);
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
