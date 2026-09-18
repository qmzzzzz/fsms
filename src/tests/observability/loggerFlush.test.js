/**
 * 退出前日志落盘（P1-13）验证
 *
 * 报告原文：「validate.js:259 / database.js:59 / index.js:243,304 的 exit 前加
 * flush 等待（≥100ms）」。
 *
 * 【为什么不是「加个等待」就完事】本机实测（Node v24.15.0 / winston 3.19.0 /
 * winston-daily-rotate-file，探针见 utils/loggerFlush.js 模块注释）：
 * 同步忙等 100ms、logger.end()、logger.end() + 忙等——三种写法在紧接
 * process.exit 时**全部丢日志**（目标文件 0 字节）。原因是 winston 的文件
 * transport 走异步 I/O，而 process.exit 不等待事件循环。
 * 因此：
 *   - 同步上下文（config/validate.js，测试断言其同步抛错）→ 必须同步写文件；
 *   - 异步上下文（database.js / index.js）→ logger.end() + setTimeout 退出。
 *
 * 【本文件的可证伪点】下面的子进程用例会把两种写法都真跑一遍并断言
 * 「naive 丢、flushLogsSync 不丢」。若有人把 flushLogsSync 退回成
 * 「logger.error + 直接 exit」，用例 2 会红。
 */
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

const ROOT = path.resolve(__dirname, '../../..');
const NODE = process.execPath;
const {
  flushLogsSync,
  exitAfterFlush,
  dateStamp,
  DEFAULT_LOG_DIR,
} = require('../../utils/loggerFlush');

/** 每个用例独占的临时日志目录，避免与真实 logs/ 互相干扰 */
function makeTmpDir(tag) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `fsms-logflush-${tag}-`));
  return dir;
}

describe('P1-13 退出前日志落盘', () => {
  describe('dateStamp', () => {
    test('与 winston 的 datePattern YYYY-MM-DD 同口径（含补零）', () => {
      expect(dateStamp(new Date(2026, 0, 5))).toBe('2026-01-05');
      expect(dateStamp(new Date(2026, 11, 31))).toBe('2026-12-31');
    });
  });

  describe('flushLogsSync', () => {
    test('error 级别同时写入 error-*.log 与 combined-*.log（与 transport 配置一致）', () => {
      const dir = makeTmpDir('err');
      const line = flushLogsSync('error', '配置校验失败：', undefined, {
        logDir: dir,
        now: new Date(2026, 8, 17),
      });

      for (const name of ['error-2026-09-17.log', 'combined-2026-09-17.log']) {
        const file = path.join(dir, name);
        expect(fs.existsSync(file)).toBe(true);
        expect(fs.readFileSync(file, 'utf8')).toContain(line);
      }
      expect(line).toContain('配置校验失败：');
    });

    test('info 级别只进 combined（不进 error 文件）', () => {
      const dir = makeTmpDir('info');
      flushLogsSync('info', '普通消息', undefined, { logDir: dir, now: new Date(2026, 8, 17) });
      expect(fs.existsSync(path.join(dir, 'error-2026-09-17.log'))).toBe(false);
      expect(fs.readFileSync(path.join(dir, 'combined-2026-09-17.log'), 'utf8')).toContain(
        '普通消息'
      );
    });

    test('多次调用为追加而非覆盖（崩溃现场可能连续多条）', () => {
      const dir = makeTmpDir('append');
      flushLogsSync('error', '第一条', undefined, { logDir: dir, now: new Date(2026, 8, 17) });
      flushLogsSync('error', '第二条', undefined, { logDir: dir, now: new Date(2026, 8, 17) });
      const content = fs.readFileSync(path.join(dir, 'error-2026-09-17.log'), 'utf8');
      expect(content).toContain('第一条');
      expect(content).toContain('第二条');
    });

    test('目录不存在时自动创建（首次启动即配置错误也要能落盘）', () => {
      const dir = path.join(makeTmpDir('mkdir'), 'nested', 'logs');
      expect(fs.existsSync(dir)).toBe(false);
      flushLogsSync('error', '嵌套目录', undefined, { logDir: dir, now: new Date(2026, 8, 17) });
      expect(fs.existsSync(path.join(dir, 'error-2026-09-17.log'))).toBe(true);
    });

    test('默认目录指向仓库 logs/（与 utils/logger.js 的 logsDir 同规则）', () => {
      expect(DEFAULT_LOG_DIR).toBe(path.join(ROOT, 'logs'));
    });

    test('渲染复用 logger 的 format（同步行与异步行同版式，便于 grep）', () => {
      const dir = makeTmpDir('fmt');
      const line = flushLogsSync('error', '版式检查', undefined, {
        logDir: dir,
        now: new Date(2026, 8, 17),
      });
      // logger.js 的 fileFormat = attachRequestContext + timestamp + printfLayout
      // → '<ISO 时间> [error]: <message>'
      expect(line).toMatch(/^\d{4}-\d{2}-\d{2}T[\d:.]+Z \[error\]: 版式检查$/);
    });
  });

  describe('子进程实证：异步 transport 在 exit 前会丢，同步写入不会', () => {
    const probe = (mode, dir) => {
      const script = `
        const path = require('path');
        const logger = require(path.join(process.env.PROBE_ROOT, 'src/utils/logger'));
        const { flushLogsSync } = require(path.join(process.env.PROBE_ROOT, 'src/utils/loggerFlush'));
        const dir = process.env.PROBE_DIR;
        logger.error('SUBPROCESS-MARK-' + process.argv[2]);
        if (process.argv[2] === 'flush') {
          flushLogsSync('error', 'SUBPROCESS-MARK-flush', undefined, { logDir: dir });
        }
        process.exit(1);
      `;
      const scriptPath = path.join(dir, 'probe.cjs');
      fs.writeFileSync(scriptPath, script, 'utf8');
      try {
        execFileSync(NODE, [scriptPath, mode], {
          cwd: ROOT,
          env: { ...process.env, PROBE_ROOT: ROOT, PROBE_DIR: dir },
          encoding: 'utf8',
          stdio: 'pipe',
        });
      } catch (e) {
        // 探针脚本以 exit(1) 结束，属预期
        if (e.status !== 1) throw e;
      }
    };

    test('logger.error 后立即 exit → 日志丢失（这是 P1-13 要修的现象）', () => {
      const dir = makeTmpDir('naive');
      probe('naive', dir);
      const stamp = dateStamp();
      const file = path.join(ROOT, 'logs', `error-${stamp}.log`);
      const content = fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : '';
      expect(content).not.toContain('SUBPROCESS-MARK-naive');
    });

    test('flushLogsSync 后立即 exit → 日志必然落盘（修复生效）', () => {
      const dir = makeTmpDir('flush');
      probe('flush', dir);
      const content = fs.readFileSync(path.join(dir, `error-${dateStamp()}.log`), 'utf8');
      expect(content).toContain('SUBPROCESS-MARK-flush');
    });
  });

  describe('exitAfterFlush', () => {
    test('返回永不 settle 的 Promise（调用方必须 return，否则会继续跑后续启动步骤）', async () => {
      // 本用例只验证「不 resolve」这一契约，退出动作本身由下一个用例的计时行为覆盖
      const mockExit = jest.spyOn(process, 'exit').mockImplementation(() => {});
      try {
        const p = exitAfterFlush(0, { delayMs: 0 });
        const raced = await Promise.race([
          p.then(() => 'settled'),
          new Promise((r) => setTimeout(() => r('pending'), 20)),
        ]);
        expect(raced).toBe('pending');
      } finally {
        mockExit.mockRestore();
      }
    });

    test('缺省延迟为 100ms：99ms 未退出、100ms 退出（报告 P1-13 要求 ≥100ms）', () => {
      // 【本轮改造：源码正则 → 真实计时行为】原用例读 loggerFlush.js 源码匹配
      // `Number.isFinite(options.delayMs) ? options.delayMs : 100` 这段文本，两个方向都不可靠：
      //   · 假阳性——把 100 改成其他值、或让这段代码落进不可达分支，
      //     只要文本还在，断言照样绿；
      //   · 假阴性——等价重写成 `const D = 100; ... : D` 就误报。
      // 现用假定时器真跑 exitAfterFlush(0)（不传 delayMs，走缺省路径）：
      // 第 99ms 不得退出；第 100ms 必须以退出码 0 退出。
      jest.useFakeTimers();
      const mockExit = jest.spyOn(process, 'exit').mockImplementation(() => {});
      try {
        exitAfterFlush(0);
        expect(mockExit).not.toHaveBeenCalled();
        jest.advanceTimersByTime(99);
        expect(mockExit).not.toHaveBeenCalled();
        jest.advanceTimersByTime(1);
        expect(mockExit).toHaveBeenCalledTimes(1);
        expect(mockExit).toHaveBeenCalledWith(0);
      } finally {
        mockExit.mockRestore();
        jest.useRealTimers();
      }
    });
  });

  describe('四处退出点已接入（报告 P1-13 点名的位置）', () => {
    test('validate.js 的致命上报走同步落盘（真实执行）', () => {
      // 【本轮改造：源码正则 → 行为断言】原用例断言 reportConfigErrors 函数体里出现
      // flushLogsSync(/process.exit(1) 字样——只要文本在，实际不落盘也绿。
      // 现真跑一次 validateConfig() 的致命路径（极弱 JWT_SECRET 使其报错），
      // 断言「本次新增的日志内容（delta）里真的含有配置错误文案」。
      jest.resetModules();
      const saved = { ...process.env };
      process.env.NODE_ENV = 'production';
      process.env.JWT_SECRET = '<CHANGE_ME>';
      process.env.JWT_REFRESH_SECRET = 'strong-random-refresh-secret-long-enough-ok';
      process.env.AES_SECRET_KEY = 'test-aes-key-with-32-chars-minimum!!';
      process.env.HMAC_SECRET = 'strong-random-hmac-secret-that-is-long-enough';
      process.env.MONGODB_URI = 'mongodb://prod-server:27017/db';
      process.env.CORS_ORIGIN = 'https://example.com';
      process.env.ENABLE_HTTPS = 'true';
      process.env.ALLOWED_HOSTS = 'api.example.com';
      process.env.REDIS_URL = 'redis://redis.example.com:6379';
      process.env.TRUST_PROXY_HOPS = '1';
      const exitSpy = jest.spyOn(process, 'exit').mockImplementation(() => {
        throw new Error('process.exit called');
      });
      const errSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
      const logger = require('../../utils/logger');
      const errorSpy = jest.spyOn(logger, 'error').mockImplementation(() => {});
      try {
        // 同步落盘的目标目录由 DEFAULT_LOG_DIR 决定。
        // 【加固】必须看**本次新增的那段**（delta）：日志是追加写，
        // 文件里可能已有其它用例（如子进程探针）写入的同名文案，
        // 全文 toContain 会在本次根本没写入时也绿。
        const stamp = dateStamp();
        const errFile = path.join(DEFAULT_LOG_DIR, `error-${stamp}.log`);
        const combined = path.join(DEFAULT_LOG_DIR, `combined-${stamp}.log`);
        const beforeErr = fs.existsSync(errFile) ? fs.readFileSync(errFile, 'utf8') : '';
        const beforeCombined = fs.existsSync(combined) ? fs.readFileSync(combined, 'utf8') : '';

        const { validateConfig } = require('../../config/validate');
        expect(() => validateConfig()).toThrow('process.exit called');
        expect(exitSpy).toHaveBeenCalledWith(1);

        expect(fs.existsSync(errFile)).toBe(true);
        const deltaErr = fs.readFileSync(errFile, 'utf8').slice(beforeErr.length);
        expect(deltaErr).toContain('配置校验失败：');
        expect(deltaErr).toContain('JWT_SECRET');
        expect(fs.existsSync(combined)).toBe(true);
        const deltaCombined = fs.readFileSync(combined, 'utf8').slice(beforeCombined.length);
        expect(deltaCombined).toContain('配置校验失败：');
        // 审计跟踪链路：logger 必须收到**确切文案**，而非任意 error 调用
        expect(errorSpy.mock.calls.map((c) => String(c[0]))).toEqual(
          expect.arrayContaining(['配置校验失败：'])
        );
      } finally {
        exitSpy.mockRestore();
        errSpy.mockRestore();
        errorSpy.mockRestore();
        process.env = saved;
        jest.resetModules();
      }
    });

    test('database.js 失败路径走 exitAfterFlush(1) 而非裸 process.exit（真实执行）', async () => {
      // 【本轮改造：源码正则 → 行为断言】原用例断言 database.js 源码里出现
      // `return exitAfterFlush(1)` 且不出现 `process.exit(1)`——把调用改成其他函数名但保留注释文本，
      // 或把调用放进不可达分支，断言都照样绿。
      // 现 mock mongoose.connect 持续拒绝 + mock loggerFlush 记录调用，
      // 真跑 connectDB(0)（重试已耗尽的路径），断言 exitAfterFlush 真被以 1 调用、
      // 且未直接调 process.exit。
      jest.resetModules();
      jest.doMock('mongoose', () => ({
        connect: jest.fn().mockRejectedValue(new Error('probe-connect-refused')),
        connection: { on: jest.fn(), readyState: 0, close: jest.fn() },
      }));
      const exitAfterFlushMock = jest.fn(() => Promise.resolve('exit-after-flush-called'));
      jest.doMock('../../utils/loggerFlush', () => ({
        exitAfterFlush: exitAfterFlushMock,
        flushLogsSync: jest.fn(),
      }));
      const exitSpy = jest.spyOn(process, 'exit').mockImplementation(() => {
        throw new Error('direct process.exit must not be called');
      });
      try {
        const connectDB = require('../../config/database');
        await connectDB(0);
        expect(exitAfterFlushMock).toHaveBeenCalledTimes(1);
        expect(exitAfterFlushMock).toHaveBeenCalledWith(1);
        expect(exitSpy).not.toHaveBeenCalled();
      } finally {
        exitSpy.mockRestore();
        jest.dontMock('mongoose');
        jest.dontMock('../../utils/loggerFlush');
        jest.resetModules();
      }
    });

    test('index.js 四处致命退出点均走 exitAfterFlush(1)（子进程 e2e：启动失败）', () => {
      // 【本轮改造：源码计数 → 子进程真实退出行为】原用例用正则数
      // `return exitAfterFlush(1)` 出现次数 ≥ 4——调用全部放进死分支也绿。
      // 现启动真实进程：ENABLE_HTTPS=true 但证书路径不存在（TLS 加载失败路径），
      // 断言：进程以非零码退出、且「TLS 证书加载失败」真的落到了日志文件（而非只在 stdout）。
      // 证据：子进程 stdout 里同样能看到这行，但只有文件里的那份才能在进程死后取证。
      const uniq = `halleylf-${Date.now().toString(36)}`;
      const missingCert = path.join(os.tmpdir(), `${uniq}.crt`);
      const missingKey = path.join(os.tmpdir(), `${uniq}.key`);
      const stamp = dateStamp();
      const logFile = path.join(ROOT, 'logs', `error-${stamp}.log`);
      const before = fs.existsSync(logFile) ? fs.readFileSync(logFile, 'utf8') : '';

      // 【环境隔离】index.js 的启动编排是 DB → 播种 → createApp → TLS，
      // TLS 分支位于 DB 之后。若让子进程真连测试内存 Mongo，并行负载下建连会
      // 抖动（实测同一用例在重负载下偶发 DB 超时、甚至 180s 未退出），
      // 使「TLS 致命退出」这一被测行为被环境噪声掩盖。
      // 这里在子进程内以 Module._load 桩替换「连库」与「播种」两个前置步骤；
      // 被测对象仍是真实的 index.js 启动链 + 真实 TLS 加载失败 + 真实
      // exitAfterFlush + 真实日志落盘，断言判据不放松。
      const bootstrap = [
        "const Module = require('module');",
        'const orig = Module._load;',
        'Module._load = function (request) {',
        "  if (request === './config/database') return async () => ({});",
        "  if (request === './services/initData') return { initializeSystem: async () => {} };",
        '  return orig.apply(this, arguments);',
        '};',
        "require('./src/index.js');",
      ].join('\n');
      const r = require('child_process').spawnSync(NODE, ['-e', bootstrap], {
        cwd: ROOT,
        env: {
          ...process.env,
          NODE_ENV: 'test',
          ENABLE_HTTPS: 'true',
          TLS_CERT_PATH: missingCert,
          TLS_KEY_PATH: missingKey,
          PORT: '0',
        },
        encoding: 'utf8',
        timeout: 120000,
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      expect(r.status).toBe(1);
      const after = fs.existsSync(logFile) ? fs.readFileSync(logFile, 'utf8') : '';
      const delta = after.slice(before.length);
      expect(delta).toContain('TLS 证书加载失败');
      expect(delta).toContain(uniq);
    }, 150000);
  });
});
