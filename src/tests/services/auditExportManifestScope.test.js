'use strict';

/**
 * F-105：审计导出的 manifest 必须说清"每个摘要覆盖什么"，并且那个说法要真能复算
 *
 * 缺陷（台账 §4.2 末条 `[报]` 的前半）：manifest 只有一个 `sha256`，
 * 而它是对**被导出记录的 `hash` 字段串联**求的摘要，跟实际写出的 CSV 字节毫无关系。
 * 代码里的注释却把它说成"让下载的文件自带签名信息"，测试注释更写成
 * 「这是"导出未被中途删改"的唯一凭证」（`auditExportService.test.js:72`）。
 * 这句话是错的，而且错得可证：把导出文件里任意一个单元格改掉（用户名、时间、路径），
 * 链摘要**一个字节都不会变**——因为它从没看过那些字节。
 * ⇒ 一份被改过的取证 CSV，manifest 照样"对得上"。这跟 F-101 那句"已清空"是同一类缺陷：
 * 不是没做，是**做的和说的不是一回事**。
 *
 * 修法与钉法（成对，缺一条另一条就会悄悄失效）：
 *  ① 新增 `csvSha256`：对**实际写出的字节**（表头行 + 全部数据行，不含 manifest 行本身）
 *    求摘要，用例直接对整个文件字节复算并比对——复算不上的签名不叫签名。
 *  ② 同时把旧摘要的**盲区**钉成断言：改掉一个单元格后 `csvSha256` 变了、
 *    `sha256` 却仍然"对得上"。这条是负向证据，写给下一个想只验 `sha256` 的人。
 *  ③ 有记录不带 `hash` 时，链摘要覆盖的条数 < 导出条数 ⇒ 必须自己说出来
 *    （`chainCoverageIncomplete` + notice 里的 `N/M`），否则"摘要对得上"会被读成
 *    "整份导出都在链上"。
 *  ④ 两条理由（截断 / 覆盖不全）同时成立时 notice 必须**都在**：
 *    实现里两段是先后赋值，顺序写反就会互相抹掉。
 */

const crypto = require('crypto');
const mongoose = require('mongoose');

const {
  streamAuditExport,
  buildAuditExportManifest,
  EXPORT_CSV_HEADER,
} = require('../../services/auditExportService');
const AuditLog = require('../../models/AuditLog');
const { TEST_CLIENT_IP } = require('../fixtures');

const USER = 'manifest_scope_user';
const sha256 = (text) => crypto.createHash('sha256').update(text, 'utf8').digest('hex');

function makeDoc(seq, hash) {
  return {
    action: 'login',
    category: 'auth',
    username: `${USER}_${seq}`,
    userId: new mongoose.Types.ObjectId(),
    ip: TEST_CLIENT_IP,
    result: 'success',
    riskLevel: 'low',
    timestamp: new Date(2026, 8, 21, 8, 0, seq),
    hash,
  };
}

/** 收集写出字节的响应桩：始终接受写入，不参与背压。 */
function captureRes() {
  const lines = [];
  return {
    lines,
    setHeader: () => {},
    write: (line) => {
      lines.push(line);
      return true;
    },
    once: () => {},
  };
}

describe('审计导出 manifest 的摘要口径（F-105）', () => {
  let docs;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) await mongoose.connect(process.env.MONGODB_URI);
    await AuditLog.deleteMany({ username: new RegExp(`^${USER}_`) }, { bypassAppendOnly: true });
    // 两条**都带** hash；第三条故意不带 ⇒ 供 ③ 使用
    await AuditLog.insertMany([
      makeDoc(1, 'a'.repeat(64)),
      makeDoc(2, 'b'.repeat(64)),
      makeDoc(3, undefined),
    ]);
    docs = await AuditLog.find({ username: new RegExp(`^${USER}_`) })
      .sort({ _id: 1 })
      .lean();
  });

  afterAll(async () => {
    await AuditLog.deleteMany({ username: new RegExp(`^${USER}_`) }, { bypassAppendOnly: true });
  });

  test('① csvSha256 能被外部对"整个文件字节"直接复算（否则它不是签名）', async () => {
    const res = captureRes();
    const counters = await streamAuditExport(
      { username: { $in: [`${USER}_1`, `${USER}_2`] } },
      res
    );
    const manifest = buildAuditExportManifest(counters);

    // 文件字节 = 表头行 + 数据行；manifest 行本身不参与（它就是被验对象之外的页脚）
    const fileBytes = `${EXPORT_CSV_HEADER}\n${res.lines.join('')}`;
    expect(manifest.csvSha256).toBe(sha256(fileBytes));
    expect(manifest.csvBytes).toBe(Buffer.byteLength(fileBytes, 'utf8'));
    // 口径必须随文件一起交付，取证的人才知道该拿什么去复算
    expect(manifest.csvSha256Scope).toContain('不含本 manifest 行');
    expect(manifest.sha256Scope).toContain('不含 CSV 字节');
  });

  test('② 负向证据：改一个单元格，csvSha256 立刻对不上，而链摘要 sha256 照样"对得上"', async () => {
    const res = captureRes();
    const counters = await streamAuditExport(
      { username: { $in: [`${USER}_1`, `${USER}_2`] } },
      res
    );
    const manifest = buildAuditExportManifest(counters);
    const fileBytes = `${EXPORT_CSV_HEADER}\n${res.lines.join('')}`;

    const tampered = fileBytes.replace(`${USER}_1`, 'x'.repeat(USER.length + 2));
    expect(tampered).not.toBe(fileBytes); // 篡改确实落到了字节上
    expect(sha256(tampered)).not.toBe(manifest.csvSha256);

    // 同一份被改过的文件，用链摘要去验却是"通过"——这正是旧口径不能当文件凭证的原因
    const storedHashes = docs.filter((d) => d.hash).map((d) => d.hash);
    expect(storedHashes).toHaveLength(2);
    expect(sha256(storedHashes.join(''))).toBe(manifest.sha256);
  });

  test('③ 有记录不带 hash：链摘要覆盖面必须自己承认（chainCoverageIncomplete + N/M）', () => {
    const manifest = buildAuditExportManifest({
      recordCount: 5,
      chainRecords: 3,
      truncated: false,
      sha256: 'deadbeef',
      csvSha256: 'cafebabe',
      csvBytes: 123,
    });
    expect(manifest.chainCoverageIncomplete).toBe(true);
    expect(manifest.notice).toContain('3/5');
    expect(manifest.notice).toContain('无 hash 字段');
  });

  test('④ 截断与覆盖不全同时成立：两条理由都得在 notice 里，后一段不得抹掉前一段', () => {
    const manifest = buildAuditExportManifest({
      recordCount: 50000,
      chainRecords: 49990,
      truncated: true,
      startTime: new Date(2026, 8, 1),
      endTime: new Date(2026, 8, 2),
      sha256: 'deadbeef',
      csvSha256: 'cafebabe',
      csvBytes: 1000000,
    });
    expect(manifest.truncated).toBe(true);
    expect(manifest.chainCoverageIncomplete).toBe(true);
    expect(manifest.notice).toContain('硬上限');
    expect(manifest.notice).toContain('49990/50000');
  });
});

// 收尾必须关连接：mongodb-memory-server 是所有套件共用的同一个 mongod，
// 不关的套件会让 jest worker 在 FORCE_EXIT_DELAY(500ms) 后被强杀
// （"A worker process has failed to exit gracefully"），强杀会吞掉该套件的输出。
// readyState 守卫是为了不关别人建立的连接；本条挂在根作用域，故在本套件所有
// describe 自己的 afterAll 之后才跑。这里就地 require('mongoose')：本仓有 3 个套件
// 只在 describe 体内 require，从根作用域引用那个名字会 ReferenceError。
afterAll(async () => {
  const mongoose = require('mongoose');
  if (mongoose.connection.readyState !== 0) await mongoose.connection.close();
});
