'use strict';

/**
 * F-106：清单摘要必须对"真实交付的那串字节"成立（端到端复算）
 *
 * 为什么单独一册：`csvSha256` 的声明是"可直接对下载文件复算"，而实际写出的字节
 * 由**两个文件**共同决定——表头行由 `auditController.js` 写、数据行由
 * `auditExportService.js` 写、manifest 尾行又由 controller 追加；
 * 可是服务层测试自己拼 rows，controller 层测试（`auditExportStreamFailure`）
 * 又把整个 export service 换成了替身。**没有任何一条用例把两端接起来**：
 * 谁改 controller 那三行 `res.write`（漏写表头、写两遍、把 footer 也算进摘要），
 * 全套件照样绿，而交付的文件从此对不上自己声明的摘要——
 * 这正是本仓反复出现的"绿但不设防"，而且这次骗的是完整性凭证本身。
 *
 * 顺带钉住一条更要紧的：导出**必须**走数据范围翻译。此前该步骤只在
 * "mock 掉 applyAuditDataScope"的用例里出现过，删掉 `auditController.js:38`
 * 那行不会有任何测试变红——而后果是跨部门/跨范围导出审计明细。
 *
 * res 用真的 `stream.Writable`：这样 `write()` 的返回值、`once('drain')`、
 * `removeListener`、监听器计数都是 Node 的真实实现，不是手写替身。
 */

const crypto = require('crypto');
const { Writable } = require('stream');

jest.mock('../../models/AuditLog', () => ({
  countDocuments: jest.fn(),
  find: jest.fn(),
}));

// 数据范围替身：返回一个**可识别**的收窄条件，用来断言它真的进了游标
jest.mock('../../services/auditQueryService', () => ({
  applyAuditDataScope: jest.fn(),
  queryAuditLogs: jest.fn(),
}));

jest.mock('../../services/securityAlert', () => ({
  checkBulkExport: jest.fn(async () => {}),
}));

const AuditLog = require('../../models/AuditLog');
const { applyAuditDataScope } = require('../../services/auditQueryService');
const { checkBulkExport } = require('../../services/securityAlert');
const auditController = require('../../controllers/auditController');
const { EXPORT_CSV_HEADER, MANIFEST_LINE_PREFIX } = require('../../services/auditExportService');

const SCOPED_QUERY = { username: { $in: ['scoped_only'] } };
const REQUESTER = { userId: '507f1f77bcf86cd799439011', username: 'tester' };

const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest('hex');

class SinkRes extends Writable {
  constructor() {
    super();
    this.chunks = [];
    this.headers = {};
    this.ended = false;
  }

  _write(chunk, _enc, cb) {
    this.chunks.push(Buffer.from(chunk, 'utf8'));
    cb();
  }

  setHeader(key, value) {
    this.headers[key] = String(value);
  }

  end(...args) {
    this.ended = true;
    // 断连用例里 res 已被 destroy：真 HTTP 响应在"头已发出"分支上由 controller
    // 自行收尾，此处只求替身不要额外抛一个 ERR_STREAM_DESTROYED 掩盖真正的断连
    if (this.destroyed) return this;
    return super.end(...args);
  }

  // 让"头未发出"那条 JSON 错误出口可用（缺了它会在 catch 里再抛 TypeError，
  // 用例虽然照绿，却是为错误的原因而绿）
  status(code) {
    this.statusCode = code;
    return this;
  }

  json(payload) {
    this.body = payload;
    return this;
  }

  body() {
    return Buffer.concat(this.chunks);
  }
}

const makeCursorChain = (rows) => {
  const close = jest.fn().mockResolvedValue(undefined);
  return {
    close,
    sort: jest.fn().mockReturnThis(),
    limit: jest.fn().mockReturnThis(),
    lean: jest.fn().mockReturnThis(),
    cursor: jest.fn(() => ({
      close,
      eachAsync: async (callback) => {
        for (const row of rows) await callback(row);
      },
    })),
  };
};

const row = (seq, hash) => ({
  timestamp: new Date(Date.UTC(2026, 8, 8, 0, seq, 0)),
  action: 'auth_login',
  category: 'auth',
  username: `u${seq}`,
  path: '/api/auth/login',
  statusCode: 200,
  success: true,
  riskLevel: 'low',
  prevHash: hash ? 'f'.repeat(64) : undefined,
  hash,
});

const runExport = async () => {
  const res = new SinkRes();
  const req = { query: {}, user: REQUESTER };
  const next = jest.fn();
  await auditController.exportAuditLogs(req, res, next);
  return { res, next };
};

/** 把交付体拆成「CSV 部分」与「manifest 尾行」——复算口径就按这条线分。 */
const splitBody = (body) => {
  const text = body.toString('utf8');
  const at = text.lastIndexOf(`\n${MANIFEST_LINE_PREFIX}`);
  expect(at).toBeGreaterThan(-1);
  return {
    csvPart: Buffer.from(text.slice(0, at + 1), 'utf8'),
    manifest: JSON.parse(text.slice(at + 1 + MANIFEST_LINE_PREFIX.length).trim()),
  };
};

beforeEach(() => {
  jest.clearAllMocks();
  // 契约是 `{ query }`：把收窄条件摊平到返回值顶层 = controller 解构出 undefined
  // = `AuditLog.find(undefined)` = 不加任何筛选地导出全库（下面 ② 就是为钉住它）
  applyAuditDataScope.mockImplementation(async (query) => ({
    query: { ...query, ...SCOPED_QUERY },
  }));
});

describe('审计导出：清单摘要与实际字节一致（端到端）', () => {
  test('对交付体去掉 manifest 尾行后复算，必须等于 manifest.csvSha256', async () => {
    const rows = [row(1, 'a'.repeat(64)), row(2, 'b'.repeat(64)), row(3, 'c'.repeat(64))];
    AuditLog.countDocuments.mockResolvedValueOnce(rows.length);
    const chain = makeCursorChain(rows);
    AuditLog.find.mockImplementationOnce(() => chain);

    const { res, next } = await runExport();

    expect(next).not.toHaveBeenCalled();
    expect(res.ended).toBe(true);
    expect(res.headers['Content-Type']).toBe('text/csv; charset=utf-8');

    const { csvPart, manifest } = splitBody(res.body());

    // ① 摘要与字节数都对得上 ⇒ "这个文件没被删改"第一次成为可复算的事实
    expect(sha256(csvPart)).toBe(manifest.csvSha256);
    expect(csvPart.length).toBe(manifest.csvBytes);
    // ② 表头只出现一次，且就是**字面量清单**本身（少写/多写都会让 ① 红）。
    //    这里刻意不 import EXPORT_CSV_HEADER 来断它自己：那份常量的列名/列序变了，
    //    必须在这条外部见证上显式改一次，导出凭证的口径才不会被人悄悄换掉。
    expect(csvPart.toString('utf8').split('\n')[0]).toBe(
      'timestamp,action,category,username,ip,path,statusCode,success,riskLevel,prevHash,hash'
    );
    expect(csvPart.toString('utf8').split(`${EXPORT_CSV_HEADER}\n`)).toHaveLength(2);
    // ③ 反向口径：footer **不在**被摘要的字节里（声明的就是这个范围）
    expect(sha256(res.body())).not.toBe(manifest.csvSha256);
    // ④ 摘要确实有牙：改一个字节就对不上
    const tampered = Buffer.from(csvPart);
    tampered[tampered.length - 5] = tampered[tampered.length - 5] ^ 0x01;
    expect(sha256(tampered)).not.toBe(manifest.csvSha256);

    expect(manifest.chainCoverageIncomplete).toBeUndefined();
    expect(res.headers['X-Audit-Manifest-Records']).toBe(String(rows.length));
    // 批量导出告警里的数量 = 实际行数（§4.3 报过 xlsx 侧两者不一致）
    expect(checkBulkExport).toHaveBeenCalledWith(
      REQUESTER.userId,
      REQUESTER.username,
      rows.length,
      'audit_logs_export'
    );
  });

  test('导出必须经过数据范围翻译，且收窄后的条件真的进了游标', async () => {
    const rows = [row(1, 'a'.repeat(64))];
    AuditLog.countDocuments.mockResolvedValueOnce(rows.length);
    const chain = makeCursorChain(rows);
    AuditLog.find.mockImplementationOnce(() => chain);

    await runExport();

    expect(applyAuditDataScope).toHaveBeenCalledTimes(1);
    expect(AuditLog.find).toHaveBeenCalledWith(expect.objectContaining(SCOPED_QUERY));
    // 截断探针仍是最多 +1 条，不能被收窄条件改掉
    expect(chain.limit).toHaveBeenCalledWith(50001);
  });

  test('有无 hash 字段的记录混在一起时，footer 要如实报出链覆盖缺口', async () => {
    const rows = [row(1, 'a'.repeat(64)), row(2, null), row(3, 'c'.repeat(64))];
    AuditLog.countDocuments.mockResolvedValueOnce(rows.length);
    AuditLog.find.mockImplementationOnce(() => makeCursorChain(rows));

    const { res } = await runExport();
    const { csvPart, manifest } = splitBody(res.body());

    // 字节侧依然完整可复算——缺口只影响"链凭证"那一半，不该污染文件摘要
    expect(sha256(csvPart)).toBe(manifest.csvSha256);
    expect(manifest.recordCount).toBe(3);
    expect(manifest.chainRecords).toBe(2);
    expect(manifest.chainCoverageIncomplete).toBe(true);
    expect(manifest.notice).toContain('2/3');
    // 链摘要照旧可复算，但它证明的只是"这 2 条出自哈希链"
    expect(manifest.sha256).toBe(sha256(Buffer.from(`${'a'.repeat(64)}${'c'.repeat(64)}`, 'utf8')));
  });

  test('服务端游标必须被关掉：正常收尾与中途断连两条路都要', async () => {
    // 实测依据：mongoose 的 eachAsync 在回调 reject 时**不会**关游标
    // （lib/helpers/cursor/eachAsync.js 里一处 destroy/close 都没有），
    // 所以不显式 close ⇒ 一次被中断的导出把服务端游标留到 10 分钟空闲回收才关。
    const rows = [row(1, 'a'.repeat(64)), row(2, 'b'.repeat(64))];

    AuditLog.countDocuments.mockResolvedValueOnce(rows.length);
    const okChain = makeCursorChain(rows);
    AuditLog.find.mockImplementationOnce(() => okChain);
    await runExport();
    expect(okChain.close).toHaveBeenCalledTimes(1);

    // 断连：表头刚写完连接就被重置 ⇒ 第一条数据行就该收手，而游标照样得关
    AuditLog.countDocuments.mockResolvedValueOnce(rows.length);
    const deadChain = makeCursorChain(rows);
    AuditLog.find.mockImplementationOnce(() => deadChain);
    const res = new SinkRes();
    // 真实 HTTP 响应由框架兜住 error 事件；这里必须自己挂一个，否则
    // destroy(err) 的 'error' 在 finally 摘掉本模块监听器之后成了 unhandled error
    res.on('error', () => {});
    const write = res.write.bind(res);
    res.write = (chunk, cb) => {
      const ret = write(chunk, cb);
      if (res.chunks.length === 1) res.destroy(new Error('ECONNRESET'));
      return ret;
    };
    await auditController.exportAuditLogs({ query: {}, user: REQUESTER }, res, jest.fn());

    expect(deadChain.close).toHaveBeenCalledTimes(1);
    // 只写出去一个表头：断连之后的数据行不得继续灌进死连接
    expect(res.chunks.length).toBe(1);
  });

  test('数据行里伪造一条 footer 骗不过复算：口径是"前 csvBytes 个字节"，不是"扫 MANIFEST 字样"', async () => {
    // 来由：子 agent 报的一条**待核实**观察——CSV 字段可含换行 ⇒ 数据行里能出现
    // 形如 `\n#__MANIFEST__:{...}` 的字节串，"逐行扫 MANIFEST 找 footer"的复算方会被骗。
    // 本用例把它测成结论（两条都要成立才叫核实过）：
    //   A 行扫描**确实**会命中伪造行 ⇒ 观察不是空穴来风；
    //   B 但伪造行不是合法 JSON ⇒ 真去解析它的工具拿到的是异常，不是一个能用的清单。
    //      成因是 CSV 的引号机制（字段含 `"` 必被整体加引号，值里的 `"` 又双写成 `""`，
    //      于是伪造 JSON 后面总跟着残渣），属于**结构性**性质。
    //   C 真正有牙的断言在最后一段：`csvBytes` 必须是**字节**数，因为"取前 N 个字节"
    //      是唯一不需要定位 footer 的复算配方，而它只按长度切。
    // 两发变异实测（各只跑一次，测完即撤）：
    //   MK（删 csvEscape 的 `""` 双写）⇒ 红的只有 `auditExportService.test.js`
    //     「escapes dates, objects, quotes…」，本用例仍绿——B 段靠的是后面那截残渣，
    //     所以 B 只是**性质刻画**，不是本用例的防线；双写早已有别处在守。
    //   ML（`csvBytes += chunk.length`，字符数冒充字节数）⇒ 10 套件 57 例里
    //     **只有本用例红**（其余用例的载荷全 ASCII，字符数==字节数看不出来）。
    //     ⇒ 本用例的独占价值 = 跨字节/字符边界的那条长度配方，中文审计记录正是它的现实场景。
    const FAKE_SHA = '0'.repeat(64);
    const forged = `见下\n${MANIFEST_LINE_PREFIX}{"recordCount":1,"csvSha256":"${FAKE_SHA}","csvBytes":1}`;
    const rows = [
      row(1, 'a'.repeat(64)),
      { ...row(2, 'b'.repeat(64)), path: forged },
      row(3, 'c'.repeat(64)),
    ];
    AuditLog.countDocuments.mockResolvedValueOnce(rows.length);
    AuditLog.find.mockImplementationOnce(() => makeCursorChain(rows));

    const { res } = await runExport();
    const body = res.body();
    const text = body.toString('utf8');

    // 前提自检：交付体里至少有两条 manifest 样式行，第一条在数据区。
    // 少了这两行，后面的断言等于什么都没证明。
    const firstAt = text.indexOf(`\n${MANIFEST_LINE_PREFIX}`);
    const lastAt = text.lastIndexOf(`\n${MANIFEST_LINE_PREFIX}`);
    expect(firstAt).toBeGreaterThan(-1);
    expect(firstAt).not.toBe(lastAt);

    // A：伪造行落在**行首**，逐行扫的复算工具第一眼看到的就是它
    const forgedLine = text.slice(firstAt + 1, text.indexOf('\n', firstAt + 2));
    expect(forgedLine.startsWith(MANIFEST_LINE_PREFIX)).toBe(true);
    // B：伪造 JSON 后面跟着本行剩余列 ⇒ 不是合法 JSON（结构所致，见上 MK 实测）
    expect(() => JSON.parse(forgedLine.slice(MANIFEST_LINE_PREFIX.length))).toThrow();

    const { manifest } = splitBody(body);
    expect(manifest.csvSha256).not.toBe(FAKE_SHA);
    expect(manifest.recordCount).toBe(rows.length);
    // C：唯一不需要"找 footer"的配方——按长度取前缀，行内伪造与它无关
    expect(sha256(body.subarray(0, manifest.csvBytes))).toBe(manifest.csvSha256);
    // 边界必须精确：csvBytes 之后恰好剩**一行** footer，后面再无字节
    const tail = body.subarray(manifest.csvBytes).toString('utf8');
    expect(tail.startsWith(MANIFEST_LINE_PREFIX)).toBe(true);
    expect(tail.trimEnd().split('\n')).toHaveLength(1);
  });
});
