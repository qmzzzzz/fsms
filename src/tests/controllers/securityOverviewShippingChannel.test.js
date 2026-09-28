/**
 * F-215 ④：合规面板 shippingEnabled 的行为面闸（补 ③ 那两条文本闸看不到的东西）
 *
 * zzqA_logShippingUrlValidatedAtMount 的 ③ 只从**源码**断言面板读的是挂载态谓词。
 * 文本闸挡得住"改回 env 真值"，挡不住"读了对的谓词但接错了值"，也挡不住将来有人
 * 把字段改名/挪位而谓词调用留在别处。本文件把同一个不变式跑在**真实处理器**上：
 *
 *   面板答复必须等于 logger.isShippingEnabled() 的返回值，
 *   并且必须与 process.env.LOG_SHIPPING_URL 的真值**无关**。
 *
 * 两臂互为对照（负断言必须有活对照臂，本仓惯例）：
 *   env 配着非法值 + 谓词 false ⇒ 面板 false（修复前这里会是 true）
 *   env 完全没配 + 谓词 true  ⇒ 面板 true （反向：证明它不是恒 false 的占位）
 * 只给一臂的话，"永远返回 false"的实现也能过——那同样是撒谎，只是方向相反。
 */

const mockGetSecurityOverview = jest.fn();
jest.mock('../../services/securityAlert', () => ({
  getSecurityOverview: (...args) => mockGetSecurityOverview(...args),
}));

const mockGetStats = jest.fn(() => ({}));
jest.mock('../../services/auditBuffer', () => ({
  isWalEnabled: () => true,
  getStats: (...args) => mockGetStats(...args),
}));

jest.mock('../../services/auditMonitor', () => ({
  isRunning: () => true,
  getHealth: () => ({ runs: 1, failures: 0, consecutiveFailures: 0, skippedOverlaps: 0 }),
}));

jest.mock('../../utils/auditChain', () => ({
  getLatestHash: () => Promise.resolve('tail-hash'),
}));

// asyncHandler 直接返回原函数，便于裸调用
jest.mock('../../middleware/errorHandler', () => ({
  asyncHandler: (fn) => fn,
}));

const mockIsShippingEnabled = jest.fn(() => false);
jest.mock('../../utils/logger', () => ({
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
  debug: jest.fn(),
  http: jest.fn(),
  verbose: jest.fn(),
  silly: jest.fn(),
  child: jest.fn(() => ({
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
  })),
  transports: [],
  isShippingEnabled: () => mockIsShippingEnabled(),
}));

const { getSecurityOverview } = require('../../controllers/securityController');

const overviewShape = () => ({
  criticalAlerts: 0,
  highAlerts: 0,
  failedLogins: 0,
  unusualAccess: 0,
  riskScore: 0,
});

const makeCtx = () => {
  const res = {
    statusCode: null,
    payload: null,
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(data) {
      this.payload = data;
      return this;
    },
  };
  return { req: {}, res, next: jest.fn() };
};

const callOverview = async () => {
  mockGetSecurityOverview.mockResolvedValue(overviewShape());
  const { req, res, next } = makeCtx();
  await getSecurityOverview(req, res, next);
  expect(res.statusCode).toBe(200);
  // 对照臂的对照：compliance 整块没能算出来时会降级成 {error}，
  // 那时 shippingEnabled 是"不存在"而不是"false"，两臂都会失去意义。
  expect(res.payload.data.compliance.error).toBeUndefined();
  return res.payload.data.compliance;
};

describe('F-215 ④：面板的 shippingEnabled 跟随挂载态谓词、与 env 无关', () => {
  const savedEnv = process.env.LOG_SHIPPING_URL;
  afterEach(() => {
    jest.clearAllMocks();
    if (savedEnv === undefined) delete process.env.LOG_SHIPPING_URL;
    else process.env.LOG_SHIPPING_URL = savedEnv;
  });

  test('env 配着一个非法值 + 谓词 false ⇒ 面板 false（修复前这里报 true）', async () => {
    process.env.LOG_SHIPPING_URL = 'not-a-url';
    mockIsShippingEnabled.mockReturnValue(false);
    const compliance = await callOverview();
    expect(compliance.shippingEnabled).toBe(false);
    expect(mockIsShippingEnabled).toHaveBeenCalled();
  });

  test('env 根本没配 + 谓词 true ⇒ 面板 true（证明它不是恒 false 的占位）', async () => {
    delete process.env.LOG_SHIPPING_URL;
    mockIsShippingEnabled.mockReturnValue(true);
    const compliance = await callOverview();
    expect(compliance.shippingEnabled).toBe(true);
    expect(mockIsShippingEnabled).toHaveBeenCalled();
  });

  test('谓词缺席时降级为 false，而不是抛出去把整块 compliance 打成 {error}', async () => {
    // 这块的实现用了 `typeof logger.isShippingEnabled === 'function' ? … : false`。
    // 邻居字段（monitorHealth / walEnabled）同型兜底，代价口径也同：
    // 抛出去会连带留存天数/链尾哈希/丢失计数一起降级，一个字段不值那个价。
    jest.resetModules();
    jest.doMock('../../utils/logger', () => ({
      info: jest.fn(),
      warn: jest.fn(),
      error: jest.fn(),
      debug: jest.fn(),
      transports: [],
    }));
    const fresh = require('../../controllers/securityController');
    mockGetSecurityOverview.mockResolvedValue(overviewShape());
    const { req, res, next } = makeCtx();
    await fresh.getSecurityOverview(req, res, next);
    expect(res.payload.data.compliance.error).toBeUndefined();
    expect(res.payload.data.compliance.shippingEnabled).toBe(false);
  });
});
