/**
 * API 文档门禁——行为化测试
 *
 * 覆盖 config/swagger.js 的三条行为线（2026-09-05 覆盖率复核：
 * swagger.js 行覆盖 45%，为未覆盖行数第二高文件）：
 *   1. isDocsEnabled 开关判定（显式 env 优先，生产默认关 / 非生产默认开）；
 *   2. basicAuth 凭据校验（未配置则拒绝 503 / 恒定时间比较 / 各畸形头 401）；
 *   3. 启动期「开启但无凭据」一次性告警 + 文档模板渲染不变量。
 *
 * 凭据一律运行期随机组装（无字面量口令）；环境变量逐项保存/恢复，
 * NODE_ENV 篡改仅在 try/finally 内进行，避免向同 worker 后续文件泄漏。
 */
const crypto = require('crypto');

describe('API 文档门禁（swagger.js）', () => {
  const ORIG = {};
  const KEYS = ['ENABLE_API_DOCS', 'DOCS_USERNAME', 'DOCS_PASSWORD'];

  const setEnv = (key, value) => {
    if (!(key in ORIG)) ORIG[key] = process.env[key];
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  };

  const restoreEnv = () => {
    for (const key of KEYS) {
      if (ORIG[key] === undefined) delete process.env[key];
      else process.env[key] = ORIG[key];
    }
  };

  // 运行期组装 Basic Auth 凭据（无字面量口令）
  const DOCS_USER = 'du' + crypto.randomBytes(4).toString('hex');
  const DOCS_PASS = 'Aa1' + crypto.randomBytes(6).toString('hex') + '!';
  const b64 = (u, p) => Buffer.from(`${u}:${p}`).toString('base64');

  const mockRes = () => ({
    setHeader: jest.fn(),
    status: jest.fn().mockReturnThis(),
    json: jest.fn(),
  });

  beforeAll(() => {
    setEnv('DOCS_USERNAME', undefined);
    setEnv('DOCS_PASSWORD', undefined);
    setEnv('ENABLE_API_DOCS', undefined);
  });

  afterAll(restoreEnv);

  describe('isDocsEnabled 开关判定', () => {
    const load = () => require('../../config/swagger');

    test.each([
      ['true', true],
      ['TRUE', true],
      ['1', true],
      ['false', false],
      ['0', false],
      ['no', false],
    ])('显式 ENABLE_API_DOCS=%s → %s', (raw, expected) => {
      setEnv('ENABLE_API_DOCS', raw);
      expect(load().isDocsEnabled()).toBe(expected);
    });

    test('未显式设置时跟随 NODE_ENV（非生产默认开）', () => {
      setEnv('ENABLE_API_DOCS', undefined);
      expect(load().isDocsEnabled()).toBe(process.env.NODE_ENV !== 'production');
    });

    test('生产环境未显式开启 → 默认关闭', () => {
      const origNodeEnv = process.env.NODE_ENV;
      try {
        process.env.NODE_ENV = 'production';
        setEnv('ENABLE_API_DOCS', undefined);
        jest.resetModules();
        const fresh = require('../../config/swagger');
        expect(fresh.isDocsEnabled()).toBe(false);
      } finally {
        process.env.NODE_ENV = origNodeEnv;
        jest.resetModules();
      }
    });
  });

  describe('basicAuth 凭据校验', () => {
    let swagger;
    let next;

    beforeEach(() => {
      jest.resetModules();
      swagger = require('../../config/swagger');
      next = jest.fn();
    });

    // M-01：原先"未配凭据即放行"是 fail-open——文档已开启却无凭据时，
    // 攻击者无需凭据即可枚举全部端点与权限编码。现改为 fail-closed。
    test('未配置 DOCS_USERNAME/PASSWORD → 拒绝访问（503，fail-closed）', () => {
      setEnv('DOCS_USERNAME', undefined);
      setEnv('DOCS_PASSWORD', undefined);
      const res = mockRes();
      swagger.basicAuth({ headers: {} }, res, next);
      expect(next).not.toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(503);
      expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ success: false }));
    });

    test('有效凭据（恒定时间比较路径）→ 放行', () => {
      setEnv('DOCS_USERNAME', DOCS_USER);
      setEnv('DOCS_PASSWORD', DOCS_PASS);
      const res = mockRes();
      swagger.basicAuth(
        { headers: { authorization: `Basic ${b64(DOCS_USER, DOCS_PASS)}` } },
        res,
        next
      );
      expect(next).toHaveBeenCalledTimes(1);
    });

    test.each([
      ['缺少 Authorization 头', {}],
      ['非 Basic scheme', { authorization: `Bearer ${b64(DOCS_USER, DOCS_PASS)}` }],
      ['Basic 但无载荷', { authorization: 'Basic' }],
      [
        '解码后无冒号分隔',
        { authorization: `Basic ${Buffer.from('noseparator').toString('base64')}` },
      ],
      ['用户名错误', { authorization: `Basic ${b64('wronguser', DOCS_PASS)}` }],
      ['口令错误', { authorization: `Basic ${b64(DOCS_USER, 'wrongpass')}` }],
    ])('%s → 401 + WWW-Authenticate', (_name, headers) => {
      setEnv('DOCS_USERNAME', DOCS_USER);
      setEnv('DOCS_PASSWORD', DOCS_PASS);
      const res = mockRes();
      swagger.basicAuth({ headers }, res, next);
      expect(next).not.toHaveBeenCalled();
      expect(res.setHeader).toHaveBeenCalledWith('WWW-Authenticate', 'Basic realm="API Docs"');
      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({ success: false, message: '需要认证' })
      );
    });

    test('仅配置用户名缺口令 → 视为未配置，拒绝访问（fail-closed）', () => {
      setEnv('DOCS_USERNAME', DOCS_USER);
      setEnv('DOCS_PASSWORD', undefined);
      const res = mockRes();
      swagger.basicAuth({ headers: {} }, res, next);
      expect(next).not.toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(503);
    });
  });

  describe('启动期告警与模板渲染', () => {
    afterEach(() => {
      jest.resetModules();
    });

    test('开启文档但未配置凭据 → 模块加载期告警一次', () => {
      setEnv('ENABLE_API_DOCS', 'true');
      setEnv('DOCS_USERNAME', undefined);
      setEnv('DOCS_PASSWORD', undefined);
      jest.resetModules();
      const logger = require('../../utils/logger');
      const warnSpy = jest.spyOn(logger, 'warn').mockImplementation(() => {});
      require('../../config/swagger');
      expect(warnSpy).toHaveBeenCalledWith(
        expect.stringContaining('未设置 DOCS_USERNAME/DOCS_PASSWORD')
      );
      warnSpy.mockRestore();
    });

    test('renderDocsHtml 产出 swagger-ui 模板（CSP 兼容性不变量载体）', () => {
      const swagger = require('../../config/swagger');
      const html = swagger.renderDocsHtml();
      expect(typeof html).toBe('string');
      expect(html).toContain('swagger');
    });

    test('openapiSpec 含 /health 与登录端点（规格接线不变量）', () => {
      const { openapiSpec } = require('../../config/swagger');
      expect(Object.keys(openapiSpec.paths)).toEqual(
        expect.arrayContaining(['/health', '/api/auth/login'])
      );
    });
  });
});
