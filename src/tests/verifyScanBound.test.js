/**
 * 在线审计链核验必须有扫描上限
 *
 * 核验循环对每条记录做 SHA-256 + 规范 JSON 序列化，是纯 CPU 工作；
 * 而文档又**必须整档参与重算**（canonicalPayload 取全部业务字段），
 * 所以不能靠投影来省内存。此前 `?limit=` 一路透传到服务层的 HARD_MAX_RECORDS
 * (200000)，等于让单个请求把事件循环占住数十秒 —— 白名单 IP 还免 strictLimiter。
 *
 * 收口方式：HTTP 面钳到 DEFAULT_MAX_RECORDS；服务层保留 HARD 上限给脚本用。
 *
 * 只替换 verifyAuditChain 一个边界即可确定性断言"实际传给服务层的 maxRecords"，
 * 这正是本次修复的全部行为。res 桩要带 locals（控制器会写 skipGlobalAudit），
 * 且必须连库（否则模型调用被 bufferCommands 压到超时，表现为无因失败）。
 */

const verifyModule = require('../services/auditChainVerify');
const AuditLog = require('../models/AuditLog');
const { verifyAuditChainIntegrity } = require('../controllers/auditController');
const { DEFAULT_MAX_RECORDS, HARD_MAX_RECORDS } = verifyModule;

const realVerify = verifyModule.verifyAuditChain;
const realRecord = AuditLog.record;

beforeAll(async () => {
  const mongoose = require('mongoose');
  if (mongoose.connection.readyState === 0) {
    await mongoose.connect(process.env.MONGODB_URI);
  }
});

afterAll(async () => {
  const mongoose = require('mongoose');
  if (mongoose.connection.readyState !== 0) {
    await mongoose.connection.close();
  }
  verifyModule.verifyAuditChain = realVerify;
  AuditLog.record = realRecord;
});

/** 跑一次核验，返回服务层实际收到的 maxRecords */
async function scanWith(query) {
  let seen = null;
  verifyModule.verifyAuditChain = async (_model, options) => {
    seen = options;
    return { total: 0, breaks: 0, byType: {}, samples: [], intact: true, hmacChecked: true };
  };
  AuditLog.record = async (entry) => entry;

  const req = {
    query,
    user: { userId: '000000000000000000000001', username: 'auditor', sessionId: null },
    ip: '203.0.113.1',
    method: 'GET',
    originalUrl: '/api/security/audit-logs/verify',
    get: () => 'probe-agent',
  };
  const res = {
    locals: {},
    _body: null,
    status() {
      return res;
    },
    json(body) {
      res._body = body;
      return res;
    },
  };
  let nextErr = null;
  try {
    await verifyAuditChainIntegrity(req, res, (e) => {
      nextErr = e;
    });
  } finally {
    verifyModule.verifyAuditChain = realVerify;
    AuditLog.record = realRecord;
  }
  return { seen, body: res._body, nextErr };
}

describe('在线核验的 limit 参数必须被钳制', () => {
  test('前提：两个上限确实不同（否则下面的钳制断言是空的）', () => {
    expect(HARD_MAX_RECORDS).toBeGreaterThan(DEFAULT_MAX_RECORDS);
  });

  test('探针有效：请求真的走到了服务层调用，且没有内部异常', async () => {
    const { seen, body, nextErr } = await scanWith({ limit: '500' });
    expect(nextErr).toBeNull();
    expect(seen).not.toBeNull();
    expect(body.success).toBe(true);
  });

  test('?limit=200000 不得原样透传，必须被钳到 DEFAULT_MAX_RECORDS', async () => {
    const { seen } = await scanWith({ limit: String(HARD_MAX_RECORDS) });
    expect(seen.maxRecords).toBe(DEFAULT_MAX_RECORDS);
    expect(seen.maxRecords).toBeLessThan(HARD_MAX_RECORDS);
  });

  test('?limit=9999999（超出 HARD 的恶意值）同样被钳住', async () => {
    const { seen } = await scanWith({ limit: '9999999' });
    expect(seen.maxRecords).toBe(DEFAULT_MAX_RECORDS);
  });

  test('反向保护：小 limit 原样生效（钳制不得变成一刀切）', async () => {
    const { seen } = await scanWith({ limit: '100' });
    expect(seen.maxRecords).toBe(100);
  });

  test('反向保护：不给 limit 时用 DEFAULT，且 from=earliest 方向参数不被吞掉', async () => {
    const { seen } = await scanWith({});
    expect(seen.maxRecords).toBe(DEFAULT_MAX_RECORDS);
    expect(seen.fromLatest).toBe(true);

    const earliest = await scanWith({ from: 'earliest' });
    expect(earliest.seen.fromLatest).toBe(false);
  });
});
