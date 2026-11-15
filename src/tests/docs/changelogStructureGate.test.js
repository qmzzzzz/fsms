/**
 * CHANGELOG 结构门禁的判据测试（P1-1，2026-11-14）
 *
 * 背景：CHANGELOG.md 曾发生「未发布+1.0.0」单元 4 次自我拼接的腐化（10729 行），
 * 文件头标题以残片形式嵌进每条拼接缝的句子中间。这类腐化不惊动任何构建/测试，
 * 因此判据本身必须可证伪：本文件用**微型腐化夹具**逐条钉住 checkChangelogStructure
 * 的每条判据——判据恒绿（夹具腐化却判通过）等于没有门禁。
 *
 * 判据/执行分离：纯函数 checkChangelogStructure(text) 在 scripts/check-changelog-structure.js
 * 导出，这里只测判据；接线（package.json / ci.yml / 是否被工作流真实调用）由
 * src/tests/deploy/ciGateWiring.test.js 的登记清单负责，两边职责不重叠。
 *
 * 最后一条把**仓库真实 CHANGELOG.md** 也钉进来：重建后的结构状态本身是判据——
 * 再发生同类拼接腐化时，这条会最先红。
 */

const fs = require('fs');
const path = require('path');

const {
  CHANGELOG_TITLE,
  sectionKey,
  collectSectionHeaders,
  checkChangelogStructure,
  checkFile,
} = require('../../../scripts/check-changelog-structure.js');

const ROOT = path.join(__dirname, '..', '..', '..');

/** 健康最小夹具：标题 + 未发布 + 一个版本节 */
const HEALTHY = [
  '# 更新日志（CHANGELOG）',
  '',
  '## [未发布]',
  '',
  '### 修复：某条目',
  '',
  '## [1.0.0] - 2026-08-29',
  '',
  '### 新增',
  '',
  '- 初始功能',
  '',
].join('\r\n');

/** 腐化夹具：同一「未发布+1.0.0」单元拼 2 次，且标题残片嵌进第二条缝的句中 */
const CORRUPTED_TWICE = [
  '# 更新日志（CHANGELOG）',
  '',
  '## [未发布]',
  '',
  '- 条目 A',
  '',
  '## [1.0.0] - 2026-08-29',
  '',
  '- 初始功能',
  '',
  '# 更新日志（CHANGELOG）',
  '',
  '## [未发布]',
  '',
  '- 条目 A',
  '',
  '## [1.0.0] - 2026-08-29',
  '',
  '- 初始功能',
  '',
].join('\r\n');

describe('checkChangelogStructure：判据逐条可证伪', () => {
  test('前提自证：判据能区分健康夹具与腐化夹具（恒真的闸等于没有闸）', () => {
    expect(checkChangelogStructure(HEALTHY)).toEqual({ ok: true, issues: [] });
    const bad = checkChangelogStructure(CORRUPTED_TWICE);
    expect(bad.ok).toBe(false);
    expect(bad.issues.length).toBeGreaterThan(0);
  });

  test('判据 1：标题串全文恰 1 次——句中嵌入的残片（腐化指纹）也算数', () => {
    // 残片形态：句子中间粘上完整标题串（原腐化缝：`  改成必需的 \` &&# 更新日志（CHANGELOG）`）
    const embedded = [
      '# 更新日志（CHANGELOG）',
      '',
      '## [未发布]',
      '',
      '  改成必需的 ` &&# 更新日志（CHANGELOG）',
      '',
      '## [1.0.0] - 2026-08-29',
      '',
      '- 初始功能',
      '',
    ].join('\r\n');
    const bad = checkChangelogStructure(embedded);
    expect(bad.ok).toBe(false);
    expect(bad.issues.some((s) => s.includes('2 次'))).toBe(true);
    // 可证伪：只锚行首的写法抓不到残片——本判据按字符串计数，上面这条就是证明
    expect(embedded.split(CHANGELOG_TITLE).length - 1).toBe(2);
  });

  test('判据 2：「## [未发布]」恰 1 次，重复报行号', () => {
    const bad = checkChangelogStructure(CORRUPTED_TWICE);
    expect(bad.ok).toBe(false);
    expect(bad.issues.some((s) => s.includes('未发布') && s.includes('2 次'))).toBe(true);
  });

  test('判据 3：节头按版本键唯一——日期不同也躲不过（[1.0.0] 键重复）', () => {
    const sneaky = HEALTHY.replace(
      '## [1.0.0] - 2026-08-29',
      ['## [1.0.0] - 2026-08-29', '', '## [1.0.0] - 2099-01-01'].join('\r\n')
    );
    const bad = checkChangelogStructure(sneaky);
    expect(bad.ok).toBe(false);
    // 日期改成 2099 也不能骗过按版本键的唯一性判据
    expect(bad.issues.some((s) => s.includes('[1.0.0] 重复'))).toBe(true);
  });

  test('4 次拼接的完整腐化形态（真实事故形状）被一次性全判出', () => {
    // 真实事故：未发布+1.0.0 ×4，标题残片 ×4。判据必须同时报出标题与两个版本键的重复
    let text = CORRUPTED_TWICE;
    for (let i = 0; i < 2; i += 1)
      text += '\r\n' + CORRUPTED_TWICE.split('\r\n').slice(9).join('\r\n');
    const bad = checkChangelogStructure(text);
    expect(bad.ok).toBe(false);
    expect(bad.issues.some((s) => s.includes('未发布'))).toBe(true);
    expect(bad.issues.some((s) => s.includes('[1.0.0] 重复'))).toBe(true);
    expect(bad.issues.some((s) => s.includes(CHANGELOG_TITLE))).toBe(true);
  });

  test('sectionKey/collectSectionHeaders：解析形状与边界', () => {
    expect(sectionKey('## [1.0.0] - 2026-08-29')).toBe('1.0.0');
    expect(sectionKey('## [未发布]')).toBe('未发布');
    expect(sectionKey('## [未发布] ')).toBe('未发布'); // 行尾空白不影响
    expect(sectionKey('### [1.0.0] 不是节头')).toBeNull();
    expect(collectSectionHeaders(HEALTHY)).toHaveLength(2);
  });
});

describe('checkChangelogStructure：仓库真实 CHANGELOG 与 fail-closed', () => {
  test('仓库现有 CHANGELOG.md 结构通过（重建态被本条钉住，再腐化即红）', () => {
    const real = fs.readFileSync(path.join(ROOT, 'CHANGELOG.md'), 'utf8');
    expect(checkChangelogStructure(real)).toEqual({ ok: true, issues: [] });
  });

  test('文件缺失/不可读：fail-closed 返回码 2，不得当通过（判据可失败）', () => {
    const missing = path.join(ROOT, 'CHANGELOG.no-such-file.md');
    expect(fs.existsSync(missing)).toBe(false);
    const result = checkFile(missing);
    expect(result.ok).toBe(false);
    expect(result.code).toBe(2);
  });

  test('checkFile：仓库真实文件返回 code 0', () => {
    expect(checkFile()).toEqual({ ok: true, issues: [], code: 0 });
  });
});
