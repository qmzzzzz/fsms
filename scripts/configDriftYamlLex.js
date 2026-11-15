'use strict';

const NULL_WORDS = new Set(['~', 'null', 'Null', 'NULL']);
const TRUE_WORDS = new Set(['true', 'True', 'TRUE']);
const FALSE_WORDS = new Set(['false', 'False', 'FALSE']);

function unescapeDoubleChar(c) {
  const map = {
    n: '\n',
    t: '\t',
    r: '\r',
    0: '\0',
    '"': '"',
    '\\': '\\',
    '/': '/',
    b: '\b',
    f: '\f',
  };
  return c in map ? map[c] : c;
}

function readDoubleQuoted(inner) {
  // 内层已去掉两侧引号；处理 \n 这类转义
  let out = '';
  for (let i = 0; i < inner.length; i += 1) {
    if (inner[i] === '\\' && i + 1 < inner.length) {
      out += unescapeDoubleChar(inner[i + 1]);
      i += 1;
    } else {
      out += inner[i];
    }
  }
  return out;
}

function parseScalar(raw) {
  // 类型口径对齐 js-yaml core：布尔/整数/浮点/null，其余（含引号内）一律字符串
  const t = String(raw).trim();
  if (t === '') return null;
  if (t.length >= 2 && t[0] === "'" && t[t.length - 1] === "'") {
    return t.slice(1, -1).replace(/''/g, "'");
  }
  if (t.length >= 2 && t[0] === '"' && t[t.length - 1] === '"') {
    return readDoubleQuoted(t.slice(1, -1));
  }
  if (NULL_WORDS.has(t)) return null;
  if (TRUE_WORDS.has(t)) return true;
  if (FALSE_WORDS.has(t)) return false;
  if (/^[-+]?[0-9]+$/.test(t)) return parseInt(t, 10);
  if (
    /^[-+]?([0-9]+\.[0-9]*|\.[0-9]+|[0-9]+[eE][-+]?[0-9]+|[0-9]+\.[0-9]*[eE][-+]?[0-9]+)$/.test(t)
  ) {
    return parseFloat(t);
  }
  return t;
}

function stripInlineComment(text) {
  // `#` 前有空白（或行首）才算注释，且引号内的 # 不是注释
  let quote = null;
  for (let j = 0; j < text.length; j += 1) {
    const ch = text[j];
    if (quote) {
      if (quote === '"' && ch === '\\') {
        j += 1;
      } else if (ch === quote) {
        quote = null;
      }
      continue;
    }
    if (ch === "'" || ch === '"') {
      quote = ch;
      continue;
    }
    if (ch === '#' && (j === 0 || text[j - 1] === ' ' || text[j - 1] === '\t')) {
      return text.slice(0, j).trim();
    }
  }
  return text.trim();
}

function hasKeyColon(text) {
  // 序列项里出现未引号包裹的 `key:` 形态 ⇒ 是映射项（本解析器不支持，调用方抛错）
  let quote = null;
  for (let j = 0; j < text.length; j += 1) {
    const ch = text[j];
    if (quote) {
      if (quote === '"' && ch === '\\') {
        j += 1;
      } else if (ch === quote) {
        quote = null;
      }
      continue;
    }
    if (ch === "'" || ch === '"') {
      quote = ch;
      continue;
    }
    if (ch === ':' && (j + 1 === text.length || text[j + 1] === ' ' || text[j + 1] === '\t')) {
      return true;
    }
  }
  return false;
}

function splitKey(text, lineNo) {
  // 键的边界 = 第一个未引号包裹、且后跟空白/行尾的冒号
  let quote = null;
  for (let j = 0; j < text.length; j += 1) {
    const ch = text[j];
    if (quote) {
      if (quote === '"' && ch === '\\') {
        j += 1;
      } else if (ch === quote) {
        quote = null;
      }
      continue;
    }
    if (ch === "'" || ch === '"') {
      quote = ch;
      continue;
    }
    if (ch === ':' && (j + 1 === text.length || text[j + 1] === ' ' || text[j + 1] === '\t')) {
      return { key: parseScalar(text.slice(0, j).trim()), rest: text.slice(j + 1).trim() };
    }
  }
  throw new Error(`无法解析映射键（第 ${lineNo + 1} 行）：${text.slice(0, 80)}`);
}

function flowBalanced(text) {
  // 引号外的中括号/花括号全部闭合才算完整（引号内的括号不影响计数）
  let quote = null;
  const depth = { square: 0, curly: 0 };
  for (let j = 0; j < text.length; j += 1) {
    const ch = text[j];
    if (quote) {
      if (quote === '"' && ch === '\\') {
        j += 1;
      } else if (ch === quote) {
        quote = null;
      }
      continue;
    }
    if (ch === "'" || ch === '"') {
      quote = ch;
    } else if (ch === '[') {
      depth.square += 1;
    } else if (ch === ']') {
      depth.square -= 1;
    } else if (ch === '{') {
      depth.curly += 1;
    } else if (ch === '}') {
      depth.curly -= 1;
    }
  }
  return quote === null && depth.square === 0 && depth.curly === 0;
}

function flowSkipWs(p) {
  while (p.i < p.s.length && (p.s[p.i] === ' ' || p.s[p.i] === '\t')) p.i += 1;
}

function parseFlowValue(p) {
  flowSkipWs(p);
  const c = p.s[p.i];
  if (c === '[') return parseFlowSeq(p);
  if (c === '{') return parseFlowMap(p);
  return parseFlowScalar(p);
}

function parseFlowSeq(p) {
  p.i += 1;
  const arr = [];
  for (;;) {
    flowSkipWs(p);
    if (p.i >= p.s.length) throw new Error('流式序列未闭合');
    if (p.s[p.i] === ']') {
      p.i += 1;
      break;
    }
    arr.push(parseFlowValue(p));
    flowSkipWs(p);
    if (p.s[p.i] === ',') {
      p.i += 1;
    } else if (p.s[p.i] === ']') {
      p.i += 1;
      break;
    } else {
      throw new Error(`流式序列语法错误（位置 ${p.i}）：${p.s.slice(p.i, p.i + 40)}`);
    }
  }
  return arr;
}

function parseFlowMap(p) {
  p.i += 1;
  const obj = {};
  for (;;) {
    flowSkipWs(p);
    if (p.i >= p.s.length) throw new Error('流式映射未闭合');
    if (p.s[p.i] === '}') {
      p.i += 1;
      break;
    }
    const key = parseFlowScalar(p);
    flowSkipWs(p);
    if (p.s[p.i] !== ':') throw new Error(`流式映射缺少冒号（位置 ${p.i}）`);
    p.i += 1;
    obj[key] = parseFlowValue(p);
    flowSkipWs(p);
    if (p.s[p.i] === ',') {
      p.i += 1;
    } else if (p.s[p.i] === '}') {
      p.i += 1;
      break;
    } else {
      throw new Error(`流式映射语法错误（位置 ${p.i}）：${p.s.slice(p.i, p.i + 40)}`);
    }
  }
  return obj;
}

function parseFlowScalar(p) {
  flowSkipWs(p);
  const c = p.s[p.i];
  if (c === "'" || c === '"') {
    let out = '';
    p.i += 1;
    while (p.i < p.s.length) {
      const ch = p.s[p.i];
      if (c === '"' && ch === '\\') {
        out += unescapeDoubleChar(p.s[p.i + 1]);
        p.i += 2;
        continue;
      }
      if (ch === c) {
        if (c === "'" && p.s[p.i + 1] === "'") {
          out += "'";
          p.i += 2;
          continue;
        }
        p.i += 1;
        return out;
      }
      out += ch;
      p.i += 1;
    }
    throw new Error('流式标量的引号未闭合');
  }
  let end = p.i;
  while (end < p.s.length && !' \t,]}'.includes(p.s[end])) end += 1;
  const raw = p.s.slice(p.i, end);
  p.i = end;
  return parseScalar(raw);
}

function parseFlowFrom(lines, i, firstChunk) {
  // 从 firstChunk 起，续接后续行直到引号外括号配平，再整体解析
  let buf = firstChunk;
  let j = i;
  while (!flowBalanced(buf)) {
    if (j >= lines.length) throw new Error(`流式集合未闭合：${buf.slice(0, 80)}`);
    if (!isSkippable(lines[j])) buf += ` ${lines[j].trim()}`;
    j += 1;
  }
  const p = { s: buf, i: 0 };
  return { value: parseFlowValue(p), i: j };
}

function isSkippable(raw) {
  // 空行与纯注释行不参与结构
  const t = raw.trim();
  return t === '' || t.startsWith('#');
}

module.exports = {
  parseScalar,
  stripInlineComment,
  hasKeyColon,
  splitKey,
  parseFlowFrom,
  isSkippable,
};
