#!/usr/bin/env node
/**
 * 回滚演练结果自动留档（A8，2026-10-16）
 *
 * 缺口（A8 动作 1）：
 * 「恢复演练**定时化**（如每季度），结果**自动写入** deployment/rollback-drill-record.md」。
 *
 * 留档现状：`run-rollback-drill.js` 会产出 manifest JSON（含每个集合的快照条数、
 * 回灌后条数、`restoreVerified`），但那个 JSON 落在 `backups/rollback-drill/` 下，
 * **和留档文件没有任何关系**。于是每次演练完都要人肉把数字抄进 markdown 表格——
 * 而"人肉抄写"正是留档最容易断掉的一环：演练做了、manifest 在、留档里没有，
 * 下个季度读留档的人以为没练过（或者反过来，凭记忆补一条没有证据的记录）。
 *
 * 本脚本把这一步接上：读 manifest → 渲染成留档格式的 markdown 小节 → 追加到
 * `deployment/rollback-drill-record.md` 的「## 三、实际演练记录」段末。
 *
 * ⚠ **默认 dry-run**：不加 `--write` 只打印将写入的内容，不碰文件。
 * 留档文件是人工维护的（含模板段、示例段），追加位置算错会污染结构——
 * 与 `scripts/migrate-pii-encryption.js`、`scripts/destructiveGuard.js` 同一纪律：
 * 写生产/人工产物前先让人看一眼。
 *
 * **为什么这个开关叫 `--write` 而不是 `--apply`**：本仓的 `--apply` 是一个**有约定含义**的
 * 标志族（`assertApplyAllowed` 的库名白名单 + `CONFIRM_FLAG = '--yes'`，共 9 个脚本），
 * 语义是「对**数据库**做破坏性改写」。本脚本不碰数据库、只追加一个 markdown 文件，
 * 沿用 `--apply` 会让读者以为它需要 `ALLOWED_SOURCE_DB`，也会撞上
 * `src/tests/config/runbookApplyCommandContract.test.js` 的判据（手册里每个
 * `node scripts/X.js … --apply` 都必须与该脚本自身的护栏一致）。换一个名字，
 * 两类脚本就不会互相污染。
 *
 * 用法:
 *   node scripts/record-rollback-drill.js --manifest backups/rollback-drill/manifest-<ts>.json \
 *     [--operator <姓名/角色>] [--environment <描述>] [--note <补充>] [--write]
 *
 * 退出码:
 *   0 = 成功（dry-run 也算成功）
 *   1 = manifest 不可读 / 结构不合法 / 找不到锚点（**未写入**）
 *   2 = 参数不合法（未做任何事）
 */

const fs = require('fs');
const path = require('path');

const DEFAULT_RECORD_FILE = path.join('deployment', 'rollback-drill-record.md');
/** 留档文件里实际记录段的锚点（自动登记一律追加到它之后） */
const RECORD_ANCHOR = '## 三、实际演练记录';

// ============================ 参数解析 ============================
function parseArgs(argv) {
  const args = {
    manifest: null,
    recordFile: DEFAULT_RECORD_FILE,
    operator: '自动登记（未署名）',
    environment: null,
    note: null,
    write: false,
    errors: [],
  };
  const takeValue = (index, flag) => {
    const value = argv[index + 1];
    if (!value || value.startsWith('--')) {
      args.errors.push(`${flag} 缺少参数`);
      return null;
    }
    return value;
  };
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (
      token === '--manifest' ||
      token === '--record-file' ||
      token === '--operator' ||
      token === '--environment' ||
      token === '--note'
    ) {
      const value = takeValue(i, token);
      if (value === null) break;
      if (token === '--manifest') args.manifest = value;
      else if (token === '--record-file') args.recordFile = value;
      else if (token === '--operator') args.operator = value;
      else if (token === '--environment') args.environment = value;
      else args.note = value;
      i += 1;
      continue;
    }
    if (token === '--write') {
      args.write = true;
      continue;
    }
    args.errors.push(
      `未知参数：「${token}」（只接受 --manifest / --record-file / --operator / --environment / --note / --write）`
    );
  }
  return args;
}

// ============================ 渲染（纯函数） ============================
/** 已有的 `### 演练 #N` 最大序号；没有则 0（下一条从 #1 起） */
function maxDrillNumber(text) {
  const re = /^###\s*演练\s*#(\d+)/gm;
  let max = 0;
  let m;
  while ((m = re.exec(String(text == null ? '' : text))) !== null) {
    const n = Number(m[1]);
    if (Number.isFinite(n) && n > max) max = n;
  }
  return max;
}

/**
 * 校验 manifest 结构。**不合法即拒绝**，不做"缺字段就用默认值"的兜底——
 * 一份缺 `restoreVerified` 的 manifest 如果被渲染成留档，会在记录里留下一条
 * 看起来正常、实际什么都没证明的演练（与 run-rollback-drill.js 里那条
 * "空快照也算验证通过"的注释是同一个坑）。
 *
 * @returns {{ok: true} | {ok: false, reason: string}}
 */
function validateManifest(manifest) {
  if (!manifest || typeof manifest !== 'object') return { ok: false, reason: '不是对象' };
  if (typeof manifest.timestamp !== 'string' || manifest.timestamp === '') {
    return { ok: false, reason: '缺少 timestamp' };
  }
  if (!manifest.collections || typeof manifest.collections !== 'object') {
    return { ok: false, reason: '缺少 collections' };
  }
  if (manifest.applySource !== true) {
    return {
      ok: false,
      reason:
        'manifest 的 applySource 不为 true：本次只做了快照、没有清空并回灌，' +
        '不构成"回滚能力"证明，不应登记为一次数据级回滚演练',
    };
  }
  if (typeof manifest.restoreVerified !== 'boolean') {
    return { ok: false, reason: '缺少 restoreVerified（无法证明回灌与快照一致）' };
  }
  return { ok: true };
}

/**
 * 把 manifest 渲染成留档小节。
 *
 * @param {{manifest: object, sequence: number, operator: string,
 *   environment: string|null, note: string|null}} input
 * @returns {string}
 */
function renderDrillRecord({ manifest, sequence, operator, environment = null, note = null }) {
  const when = manifest.timestamp.replace(/T/, ' ').replace(/\..*$/, '');
  const date = when.slice(0, 10);
  const rows = Object.entries(manifest.collections).map(([name, c]) => {
    const snap = c.documents;
    const restored = c.restored;
    const same = restored === snap ? '☑ 一致' : '☐ **不一致**';
    return `| ${name} | ${snap} | ${restored} | ${same} |`;
  });

  const verdict = manifest.restoreVerified
    ? `回灌与快照逐集合一致（restoreVerified=true），总快照 ${manifest.totalSnapshotDocuments} 条。`
    : '**回灌与快照不一致（restoreVerified=false）——本次演练不合格，须查明原因后复练。**';

  const lines = [
    `### 演练 #${sequence}（${date}，自动登记）`,
    '',
    '| 项目     | 内容 |',
    '| -------- | ---- |',
    `| 演练日期 | ${when} |`,
    `| 执行人   | ${operator} |`,
    `| 环境     | ${environment || `库 ${manifest.uri}（由 run-rollback-drill.js 记录）`} |`,
    '| 演练范围 | ☐ 备份 ☐ 蓝绿切流 ☐ 应用层回滚 ☐ 迁移回滚 ☑ 数据级恢复 |',
    '',
    '**数据级回滚结果**（来源：`scripts/run-rollback-drill.js` 的 manifest，自动登记）：',
    '',
    '| 集合 | 快照条数 | 回灌后条数 | 结果 |',
    '| ---- | -------- | ---------- | ---- |',
    ...rows,
    '',
    `**结论**：${verdict}`,
  ];
  if (note) lines.push('', `**补充**：${note}`);
  lines.push('');

  return lines.join('\n');
}

/**
 * 把小节追加到「## 三、实际演练记录」段末（= 文件末尾，记录按时间正序）。
 *
 * 找不到锚点即拒绝：锚点不在说明文件结构已变，此时"追加到末尾"很可能把记录
 * 塞进"已知边界"之类的段落里，留档看上去还完整，实际已经错位。
 *
 * @returns {{ok: true, text: string} | {ok: false, reason: string}}
 */
function appendDrillRecord(text, section) {
  const idx = text.indexOf(RECORD_ANCHOR);
  if (idx === -1) {
    return { ok: false, reason: `留档文件里找不到锚点「${RECORD_ANCHOR}」` };
  }
  const trimmed = text.replace(/\s*$/, '');
  return { ok: true, text: `${trimmed}\n\n${section}` };
}

// ============================ 主流程 ============================
function main(argv = process.argv.slice(2)) {
  const args = parseArgs(argv);
  if (args.errors.length > 0) {
    console.error('参数不合法，拒绝执行（未做任何变更）：');
    for (const e of args.errors) console.error(`  ✗ ${e}`);
    process.exit(2);
  }
  if (!args.manifest) {
    console.error('错误：必须提供 --manifest（run-rollback-drill.js 产出的 manifest JSON）');
    process.exit(2);
  }

  let manifest;
  try {
    manifest = JSON.parse(fs.readFileSync(args.manifest, 'utf8'));
  } catch (err) {
    console.error(`错误：读不到或解析不了 manifest ${args.manifest}：${err.message}`);
    process.exit(1);
  }

  const valid = validateManifest(manifest);
  if (!valid.ok) {
    console.error(
      `错误：manifest 不合法（${valid.reason}），拒绝登记——留档里的每条记录都必须有证据。`
    );
    process.exit(1);
  }

  let text;
  try {
    text = fs.readFileSync(args.recordFile, 'utf8');
  } catch (err) {
    console.error(`错误：读不到留档文件 ${args.recordFile}：${err.message}`);
    process.exit(1);
  }

  const sequence = maxDrillNumber(text) + 1;
  const section = renderDrillRecord({
    manifest,
    sequence,
    operator: args.operator,
    environment: args.environment,
    note: args.note,
  });
  const appended = appendDrillRecord(text, section);
  if (!appended.ok) {
    console.error(`错误：${appended.reason}，拒绝写入（避免把记录塞进错误位置）。`);
    process.exit(1);
  }

  if (!args.write) {
    console.log('（dry-run：以下内容**未写入**，确认无误后加 --write 落盘）\n');
    console.log(section);
    console.log(`目标文件：${args.recordFile}`);
    return;
  }

  fs.writeFileSync(args.recordFile, appended.text, 'utf8');
  console.log(`已登记到 ${args.recordFile}（演练 #${sequence}）。`);
}

if (require.main === module) {
  main();
}

module.exports = {
  DEFAULT_RECORD_FILE,
  RECORD_ANCHOR,
  parseArgs,
  maxDrillNumber,
  validateManifest,
  renderDrillRecord,
  appendDrillRecord,
};
