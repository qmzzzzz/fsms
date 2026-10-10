/**
 * L-13 回归：审计查询失败必须被**操作级** try/catch 接管（而非穿透到全局处理器）
 *
 * 缺陷历史：原实现形如
 *   const fn = (req, res, ...) => { try { return (async () => { await ... })(); } catch (e) { 操作级日志 } };
 * 同步 try 拦不住 async IIFE 的 reject（async 函数体内 throw 只会变成 rejected promise），
 * 于是失败时操作级日志**永不执行**，错误穿透到 asyncHandler → 全局 errorHandler，
 * 日志退化为泛化的 UnhandledError，丢失「哪次操作失败」这一上下文。
 * 响应码仍是 500 —— 退化**完全静默**，没有任何既有测试会红。
 *
 * 锁定判据（区分修复前后）：
 *   - 修复后：错误在操作级被接管 → next **不被调用** + 操作级日志写出 + 500
 *   - 退回旧写法：错误穿透 → next 被调用（第一条断言即红）
 * 用 next 是否被调用作为判据，而不是只看响应码——两者在旧写法下都是 500。
 */
const path = require('path');

// 数据范围翻译与失败注入无关，固定为 all 以免依赖库内角色播种
// isDataScopeDenied / deniedDataScope 从真实模块取（#12 之后 auditScopeFilter 也要用
// 这两个导出）：不在测试里重抄判据，重抄就是第二处会漂移的实现。
jest.mock('../../middleware/rbac', () => {
  const actual = jest.requireActual('../../middleware/rbac');
  return {
    isDataScopeDenied: actual.isDataScopeDenied,
    deniedDataScope: actual.deniedDataScope,
    getDataScope: jest.fn(async () => ({ type: 'all' })),
  };
});

const MODULE = path.resolve(__dirname, '../../services/auditQueryService');

/** 极简 res 桩：记录状态码/响应体，支持 setHeader */
function makeRes() {
  const res = {
    statusCode: null,
    body: null,
    headers: {},
    setHeader(k, v) {
      res.headers[k] = v;
    },
    status(code) {
      res.statusCode = code;
      return res;
    },
    json(payload) {
      res.body = payload;
      return res;
    },
    send(payload) {
      res.body = payload;
      return res;
    },
  };
  return res;
}

describe('L-13 审计查询的操作级错误接管', () => {
  let mod;
  let AuditLog;
  let logger;
  let errorSpy;

  beforeAll(() => {
    AuditLog = require('../../models/AuditLog');
    logger = require('../../utils/logger');
    mod = require(MODULE);
  });

  beforeEach(() => {
    // 屏蔽噪音日志，同时用于断言「操作级日志确实被写出」
    errorSpy = jest.spyOn(logger, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  test('offset 分支：countDocuments reject → 操作级日志 + 500 + 不穿透到 next', async () => {
    const spy = jest.spyOn(AuditLog, 'countDocuments').mockRejectedValue(new Error('db-down'));
    const res = makeRes();
    const next = jest.fn();
    try {
      await mod.queryAuditLogs(
        { query: {}, user: { userId: '507f1f77bcf86cd799439011' } },
        res,
        next
      );
    } finally {
      spy.mockRestore();
    }

    const lines = errorSpy.mock.calls.map((c) => String(c[0])).join('\n');
    // (a) 操作级文案必须出现——退回同步 try/catch 时这行永不写出
    expect(lines).toContain('审计日志查询失败');
    expect(lines).toContain('db-down');
    // (b) 错误在本层被消化，不得穿透给全局处理器
    expect(next).not.toHaveBeenCalled();
    // (c) 客户端仍应得到明确的失败响应（不是静默成功）
    expect(res.statusCode).toBe(500);
    expect(res.body && res.body.success).toBe(false);
  });

  test('cursor 分支：底层 find 抛错 → 操作级日志 + 500 + 不穿透到 next', async () => {
    const { encodeCursor } = require('../../utils/cursorPagination');
    // 装配期即抛：无论是同步 throw 还是 rejected promise，都必须由本层 catch 接管
    const spy = jest.spyOn(AuditLog, 'find').mockImplementation(() => {
      throw new Error('cursor-boom');
    });
    const res = makeRes();
    const next = jest.fn();
    try {
      await mod.queryAuditLogs(
        {
          query: { cursor: encodeCursor({ v: new Date().toISOString(), id: 'a'.repeat(24) }) },
          user: { userId: '507f1f77bcf86cd799439011' },
        },
        res,
        next
      );
    } finally {
      spy.mockRestore();
    }

    const lines = errorSpy.mock.calls.map((c) => String(c[0])).join('\n');
    expect(lines).toContain('审计日志查询失败');
    expect(lines).toContain('cursor-boom');
    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(500);
  });
});
