#!/usr/bin/env node
/**
 * CHANGELOG 结构完整性门禁（P1-1，2026-11-14）
 *
 * 背景：CHANGELOG.md 曾发生整文件自我拼接式腐化——「未发布 + 1.0.0」单元被连续
 * 追加 4 次（10729 行），文件头标题以「句子中间嵌入」的残片形式出现在每条拼接缝上
 * （`  改成必需的 \` &&# 更新日志（CHANGELOG）`）。这类腐化没有任何构建/测试会红：
 * 文档坏了，仓库照常绿。本门禁把结构判据钉成红灯。
 *
 * 判据（对全文行做分析，CRLF/LF 无关）：
 *   1. 标题唯一：`# 更新日志（CHANGELOG）` 这条标题串在全文只出现 1 次——
 *      按**字符串出现次数**计数而不是只锚行首，因此「句子中间嵌入的标题残片」
 *      （腐化的标志性指纹）同样会红。
 *   2. `## [未发布]` 恰好 1 次。
 *   3. 每个 `## [...]` 节头按版本键唯一：`## [1.0.0] - 2026-08-29` 以 `[1.0.0]`
 *      为键；同键出现两次（不管日期写什么）即红——正是腐化里 1.0.0 出现 4 次的形态。
 *
 * 判据/执行分离：checkChangelogStructure(text) 是纯函数（吃文本、吐问题清单），
 * 可被 src/tests/docs/changelogStructureGate.test.js 直接钉住；main 只负责读文件
 * 与退出码。文件缺失/不可读按 fail-closed 处理（退出码 2，不得当通过）。
 *
 * 用法：
 *   node scripts/check-changelog-structure.js
 * 退出码：0 通过；1 结构违规；2 无法判定（文件缺失/不可读）。
 */

'use strict';

const fs = require('fs');
const path = require('path');

const CHANGELOG_TITLE = '# 更新日志（CHANGELOG）';
const UNRELEASED_KEY = '未发布';

/** 提取 `## [...]` 节头的版本键：`## [1.0.0] - 2026-08-29` → `1.0.0` */
function sectionKey(headerLine) {
  const m = /^## \[([^\]]+)\]/.exec(headerLine.trim());
  return m ? m[1] : null;
}

/** 收集 `## [` 节头行（1-based 行号 + 原文） */
function collectSectionHeaders(text) {
  const headers = [];
  text.split(/\r?\n/).forEach((line, i) => {
    if (/^## \[/.test(line)) headers.push({ line: i + 1, text: line });
  });
  return headers;
}

function countUnescapedPipes(line) {
  // GFM 表格里 `\|` 是字面量竖线：跳过转义对，只数未转义的列分隔符
  let count = 0;
  for (let i = 0; i < line.length; i += 1) {
    if (line[i] === '\\') {
      i += 1;
      continue;
    }
    if (line[i] === '|') count += 1;
  }
  return count;
}

function tableColumnIssues(text) {
  // 表格列数一致性（错位行曾漏检）：连续 `|` 行成表，首行为表头，列数不一致的行报行号
  const issues = [];
  const lines = String(text).split('\n');
  let headerPipes = 0;
  let tableStart = -1;
  const flush = (endIdx) => {
    for (let i = tableStart + 1; i <= endIdx; i += 1) {
      const pipes = countUnescapedPipes(lines[i]);
      if (pipes !== headerPipes) {
        issues.push(
          `表格第 ${i + 1} 行列数与表头不一致（${pipes - 1} 列，表头 ${headerPipes - 1} 列）`
        );
      }
    }
  };
  for (let i = 0; i < lines.length; i += 1) {
    const isRow = lines[i].trimStart().startsWith('|');
    if (isRow && headerPipes === 0) {
      tableStart = i;
      headerPipes = countUnescapedPipes(lines[i]);
    } else if (!isRow && headerPipes > 0) {
      flush(i - 1);
      headerPipes = 0;
    }
  }
  if (headerPipes > 0) flush(lines.length - 1);
  return issues;
}

/**
 * 结构判据（纯函数）。
 * @param {string} text CHANGELOG 全文（CRLF/LF 均可）
 * @returns {{ ok: boolean, issues: string[] }} issues 为空即通过
 */
function checkChangelogStructure(text) {
  const issues = [];
  const normalized = String(text).replace(/\r\n/g, '\n');

  // 判据 1：标题串全文恰 1 次（不锚行首 ⇒ 嵌入式残片也被抓）
  const titleCount = normalized.split(CHANGELOG_TITLE).length - 1;
  if (titleCount !== 1) {
    issues.push(`标题「${CHANGELOG_TITLE}」应恰好出现 1 次，实际 ${titleCount} 次`);
  }

  // 判据 2 + 3：`## [未发布]` 恰 1 次；节头按版本键唯一
  const headers = collectSectionHeaders(normalized);
  const byKey = new Map();
  for (const h of headers) {
    const key = sectionKey(h.text);
    if (key === null) continue;
    if (!byKey.has(key)) byKey.set(key, []);
    byKey.get(key).push(h);
  }
  for (const [key, hits] of byKey) {
    if (key === UNRELEASED_KEY && hits.length !== 1) {
      issues.push(
        `「## [未发布]」应恰好出现 1 次，实际 ${hits.length} 次（行 ${hits
          .map((h) => h.line)
          .join(', ')}）`
      );
    } else if (hits.length > 1) {
      issues.push(
        `节头 [${key}] 重复 ${hits.length} 次（行 ${hits.map((h) => h.line).join(', ')}）`
      );
    }
  }

  issues.push(...tableColumnIssues(normalized));

  return { ok: issues.length === 0, issues };
}

/** 读 CHANGELOG 并返回结构判定；读不到时 fail-closed（code 2） */
function checkFile(changelogPath = path.join(__dirname, '..', 'CHANGELOG.md')) {
  let text;
  try {
    text = fs.readFileSync(changelogPath, 'utf8');
  } catch (err) {
    return {
      ok: false,
      code: 2,
      issues: [`无法读取 ${changelogPath}：${err && err.message ? err.message : err}`],
    };
  }
  const result = checkChangelogStructure(text);
  return { ...result, code: result.ok ? 0 : 1 };
}

function main() {
  const result = checkFile();
  // 机器可读一行，便于 CI 日志留证
  console.log(
    JSON.stringify({
      check: 'changelog_structure',
      ok: result.ok,
      issues: result.issues,
    })
  );
  for (const issue of result.issues) console.error(issue);
  process.exit(result.code);
}

if (require.main === module) main();

module.exports = {
  CHANGELOG_TITLE,
  UNRELEASED_KEY,
  sectionKey,
  collectSectionHeaders,
  countUnescapedPipes,
  tableColumnIssues,
  checkChangelogStructure,
  checkFile,
};
