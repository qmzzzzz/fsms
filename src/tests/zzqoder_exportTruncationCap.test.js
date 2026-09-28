'use strict';

/**
 * 审计导出的截断必须由查询封顶，"在 eachAsync 回调里 close() 游标"是无效的
 *
 * 本文件先记录一个**实测事实**，再钉住由它导出的不变量：
 *
 * ① mongoose 8 里 `cursor.eachAsync(fn)` 的回调中调用 `cursor.close()`
 *    **不会停止迭代**——6 条文档照样全部进回调，既不抛错也不短路。
 *    （对照组：不 close 时同样是 6 条。两条形差才是证据。）
 *    原 `streamAuditExport` 正是靠这个 close() 来"截断"，
 *    于是命中 5 万条上限之后，它仍会把筛选命中的剩余全部记录逐条取回、
 *    反序列化、再走一遍早退分支 ⇒ 一次"看起来被截断"的导出，代价等于全量导出。
 *    这条断言写成"6 条全部到达"而不是"应当停止"，因为它钉的是**依赖行为**：
 *    哪天 mongoose 改了语义让本条转红，我们立刻知道
 *    （届时 .limit 依然是对的，只是那层保险从"必需"变成"冗余"）。
 *
 * ② 因此导出的查询必须自带 `limit(EXPORT_HARD_LIMIT + 1)`：
 *    +1 是"是否真的还有后续"的探针 ⇒ truncated 判定精确，且最多比上限多读一条。
 */

const mongoose = require('mongoose');

describe('zzqoder 审计导出截断的封顶语义', () => {
  let AuditLog;
  let auditExportService;
  const marker = 'zzqoder_cursor_close';

  const insert = async (n) => {
    const docs = Array.from({ length: n }, () => ({
      action: marker,
      category: 'security',
      timestamp: new Date(),
      success: true,
      riskLevel: 'low',
    }));
    // collection 层写入：绕开哈希链钩子，本用例只关心游标/查询行为
    await AuditLog.collection.insertMany(docs);
  };

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    AuditLog = require('../models/AuditLog');
    auditExportService = require('../services/auditExportService');
  });

  beforeEach(async () => {
    await AuditLog.collection.deleteMany({ action: marker });
  });

  afterAll(async () => {
    await AuditLog.collection.deleteMany({ action: marker });
    if (mongoose.connection.readyState !== 0) await mongoose.connection.close();
  });

  describe('① 依赖行为：eachAsync 回调里的 close() 不截断迭代', () => {
    test('close() 之后 6 条仍然全部到达回调（这正是"靠 close 截断"无效的原因）', async () => {
      await insert(6);
      const cursor = AuditLog.find({ action: marker }).sort({ _id: 1 }).lean().cursor();
      const seen = [];
      await cursor.eachAsync((doc) => {
        seen.push(doc._id.toString());
        if (seen.length === 2) cursor.close();
      });
      expect(seen).toHaveLength(6);
    });

    test('对照：完全不 close 时也是 6 条（上一条的差异只可能来自 close）', async () => {
      await insert(6);
      const cursor = AuditLog.find({ action: marker }).sort({ _id: 1 }).lean().cursor();
      let count = 0;
      await cursor.eachAsync(() => {
        count += 1;
      });
      expect(count).toBe(6);
    });
  });

  describe('② 修复后的不变量：导出查询必须自带 limit', () => {
    const fakeRes = () => {
      const chunks = [];
      return {
        chunks,
        write: (line) => {
          chunks.push(line);
          return true;
        },
        once: () => {},
      };
    };

    test('streamAuditExport 构造的查询带 limit(上限+1)', async () => {
      await insert(3);
      let captured = null;
      const realFind = AuditLog.find.bind(AuditLog);
      const spy = jest.spyOn(AuditLog, 'find').mockImplementation((...args) => {
        captured = realFind(...args);
        return captured;
      });
      let counters;
      let res;
      try {
        res = fakeRes();
        counters = await auditExportService.streamAuditExport({ action: marker }, res);
      } finally {
        spy.mockRestore();
      }
      // 正常路径自证：3 条全部写出、未标记截断、摘要是 sha256 形状
      expect(counters.recordCount).toBe(3);
      expect(counters.truncated).toBe(false);
      expect(res.chunks).toHaveLength(3);
      expect(counters.sha256).toMatch(/^[0-9a-f]{64}$/);

      expect(captured).not.toBeNull();
      // EXPORT_HARD_LIMIT 未导出 ⇒ 用值本身把契约钉死：50000 条 + 1 条探针
      expect(captured.getOptions().limit).toBe(50001);
    });

    test('反向前提：limit 断言不是恒真（不设限时取到的是 undefined）', () => {
      const bare = AuditLog.find({ action: marker }).sort({ _id: 1 });
      expect(bare.getOptions().limit ?? null).toBeNull();
      expect(bare.limit(50001).getOptions().limit).toBe(50001);
    });

    test('manifest 在截断与否两种情形下都把话说清楚', () => {
      const base = { recordCount: 2, startTime: new Date(0), endTime: new Date(1), sha256: 'ab' };
      const normal = auditExportService.buildAuditExportManifest({ ...base, truncated: false });
      expect(normal.truncated).toBeUndefined();
      expect(normal.recordCount).toBe(2);
      const cut = auditExportService.buildAuditExportManifest({ ...base, truncated: true });
      expect(cut.truncated).toBe(true);
      // 截断告示里必须给出真实上限，否则运维无法判断"少了多少"
      expect(cut.notice).toContain('50000');
    });
  });
});
