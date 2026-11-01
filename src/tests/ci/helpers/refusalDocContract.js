'use strict';

/**
 * 拒绝原因码 ↔ 对外文档的**端点级**对账（banRefusalEnumSingleSource #4 的判据本体）。
 *
 * 为什么独立成文件：旧 #4 只问「整份 openapi.json 里出现过这个码吗」——ip-list POST 的
 * 400 描述写成通用文案（"IP 已在白名单中"）时它照样绿，因为同一个码出现在无关端点的
 * 长描述里。判据必须落在「**这个**端点自己的描述」上（第 22 轮实测缺口，实测原文见
 * work/audit-round22-h4-refusal-reason.md §6）。独立成文件的第二个理由：变异自证脚本
 * 要**用同一份判据**在回退后的产物上复算，不能在看守用例里再抄一份判据（抄了就会漂移）。
 *
 * 端点清单不是手抄：清单以「源码里真的会 codeError(res, '<CODE>') 的文件」为锚，
 * 双向断言（每个产出文件都有对应端点条目 / 每个条目都锚在产出文件上）。
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '../../../..');
/** 两个对外拒绝码：仅这两个码带 errors.reason 契约 */
const REFUSAL_ERROR_CODES = ['FORENSIC_POOL_BAN_REFUSED', 'IP_SEGMENT_WRITE_REFUSED'];
const EMIT_RE = /codeError\(\s*res\s*,\s*'([A-Z_]+)'/g;

/** 产出方文件 → 该文件里拒绝码所服务的端点（同一文件可服务多个端点） */
const ENDPOINT_OF_FILE = {
  'src/controllers/ipListSegmentGuards.js': [{ method: 'post', path: '/api/security/ip-list' }],
  'src/controllers/forensicController.js': [
    { method: 'post', path: '/api/security/forensic/pool-ban/request' },
    { method: 'post', path: '/api/security/forensic/pool-ban/confirm' },
  ],
};

const walk = (dir) => {
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...walk(full));
    else if (entry.name.endsWith('.js')) out.push(full);
  }
  return out;
};

/** 源码里真的会产出这两个码的文件（相对仓根，正斜杠） */
const collectEmitFiles = () =>
  walk(path.join(ROOT, 'src/controllers'))
    .filter((file) => {
      const src = fs.readFileSync(file, 'utf8');
      EMIT_RE.lastIndex = 0;
      const codes = [...src.matchAll(EMIT_RE)].map((m) => m[1]);
      return codes.some((code) => REFUSAL_ERROR_CODES.includes(code));
    })
    .map((file) => path.relative(ROOT, file).split(path.sep).join('/'))
    .sort();

const endpoints = () =>
  Object.values(ENDPOINT_OF_FILE)
    .flat()
    .map((ep) => ({
      ...ep,
      file: Object.keys(ENDPOINT_OF_FILE).find((f) => ENDPOINT_OF_FILE[f].includes(ep)),
    }))
    .sort((a, b) => a.path.localeCompare(b.path));

/** 该端点「自己的描述」= 操作描述 + 它自己所有 4xx 描述（不含整份文档的其它端点） */
const endpointText = (spec, { method, path: p }) => {
  const op = spec && spec.paths && spec.paths[p] && spec.paths[p][method];
  if (!op) return null;
  const fourXx = Object.entries(op.responses || {}).filter(([code]) => /^4\d\d$/.test(code));
  return {
    op,
    fourXx,
    text: [op.description || '', ...fourXx.map(([, res]) => (res && res.description) || '')].join(
      '\n'
    ),
  };
};

/**
 * 判据主体：每个真的会抛拒绝码的端点，其自身描述必须写明 errors.reason（原因码字段名），
 * 否则第三方照文档实现分支时不知道该读哪个字段。
 * @returns {Array<{path: string, method: string, why: string}>} 违规清单（空=通过）
 */
const endpointDocViolations = (spec) => {
  const violations = [];
  for (const ep of endpoints()) {
    const found = endpointText(spec, ep);
    if (!found) {
      violations.push({ ...ep, why: '端点不在产物里（实现有、文档无）' });
      continue;
    }
    if (found.fourXx.length === 0) {
      violations.push({ ...ep, why: '没有任何 4xx 描述（拒绝路径未文档化）' });
      continue;
    }
    if (!/errors\.reason/.test(found.text))
      violations.push({ ...ep, why: '自身描述里没有 errors.reason' });
  }
  return violations;
};

/** 更严一档（供收紧用）：4xx 描述**本身**（不看操作描述）必须含 errors.reason */
const strictFourXxGaps = (spec) => {
  const gaps = [];
  for (const ep of endpoints()) {
    const found = endpointText(spec, ep);
    if (!found) continue;
    const text = found.fourXx.map(([, res]) => (res && res.description) || '').join('\n');
    if (!/errors\.reason/.test(text)) gaps.push(ep.method.toUpperCase() + ' ' + ep.path);
  }
  return gaps;
};

module.exports = {
  ROOT,
  REFUSAL_ERROR_CODES,
  ENDPOINT_OF_FILE,
  collectEmitFiles,
  endpoints,
  endpointDocViolations,
  strictFourXxGaps,
};
