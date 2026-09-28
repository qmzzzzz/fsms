/**
 * 日志层"静默失效"类缺陷
 *
 * ① `level: process.env.LOG_LEVEL || 'info'` 不做任何校验。winston 的
 *    _isLevelEnabled 拿 `levels[sysLevel]` 做数值比较，于是
 *    `LOG_LEVEL="info "`（.env/compose 里极易写出的尾空格）或 `LOG_LEVEL=Error`
 *    → `levels['info '] === undefined` → `0 >= undefined` 为 false →
 *    **所有记录（含 error）静默不落盘**，进程照常启动、退出码 0、无任何告警。
 * ② 落盘边界不清洗：dev/test 走 printf，消息里的换行原样落盘 = 凭空多出一行
 *    伪造日志；且无长度上限时一个超大字段就是一行超大日志。
 * ③ printf 的 meta 序列化遇循环引用/BigInt 会让该条记录整条消失
 *    （异常抛在 transport 内，exitOnError:false 还把 transport 错误一起吞掉）。
 *
 * ②③ 打在 `logger.__test` 暴露的纯函数上，不测"写文件再读回来"：
 * 后者依赖 daily-rotate 的异步落盘时序与**本地时区**文件名（实测本机 UTC+8
 * 跨午夜时读写差一天，表现为"一条都没新增"的假失败）。断言不该建立在时序上。
 */

const originalEnv = { ...process.env };

const loadLogger = (logLevel) => {
  jest.resetModules();
  const saved = process.env.LOG_LEVEL;
  if (logLevel === undefined) delete process.env.LOG_LEVEL;
  else process.env.LOG_LEVEL = logLevel;
  try {
    return require('../utils/logger');
  } finally {
    if (saved === undefined) delete process.env.LOG_LEVEL;
    else process.env.LOG_LEVEL = saved;
  }
};

describe('logger：级别解析不得静默失效，落盘边界必须清洗', () => {
  beforeEach(() => {
    process.env = { ...originalEnv };
  });

  afterAll(() => {
    process.env = originalEnv;
  });

  describe('① LOG_LEVEL 归一 + 白名单', () => {
    test.each([
      ['合法小写', 'warn', 'warn'],
      ['尾空格（此前会让全部日志静默消失）', 'info ', 'info'],
      ['首空格', ' debug', 'debug'],
      ['大小写混写', 'Error', 'error'],
      ['全大写', 'SILLY', 'silly'],
    ])('%s → 实际生效级别为 %s', (_label, input, expected) => {
      expect(loadLogger(input).level).toBe(expected);
    });

    test('未设置时仍是 info（不改既有默认）', () => {
      expect(loadLogger(undefined).level).toBe('info');
    });

    test('无法识别的取值：按 info 运行，且诊断确实可见（子进程 stderr 实测）', () => {
      const { resolveLogLevel } = require('../utils/logger').__test;
      process.env.LOG_LEVEL = 'verbose-ish-typo';
      let resolved;
      try {
        resolved = resolveLogLevel();
      } finally {
        delete process.env.LOG_LEVEL;
      }
      expect(resolved).toBe('info');

      // 诊断本身用 console.error 发出。进程内断言不了它：jest 沙箱里
      // jest.spyOn(console,'error') 的 calls 恒为空（实测，且 console===global.console
      // 为真也抓不到），写进去只会得到一条永远为空的假守卫。
      // 改为真起子进程读 stderr——那才是运维实际看到的东西。
      const loggerPath = require.resolve('../utils/logger');
      const probeEnvValue = 'verbose-ish-subproc';
      const probe = require('child_process').spawnSync(
        process.execPath,
        ['-e', `require(${JSON.stringify(loggerPath)}).__test.resolveLogLevel();`],
        { encoding: 'utf8', env: { ...process.env, LOG_LEVEL: probeEnvValue } }
      );
      expect(probe.status).toBe(0);
      const reported = (probe.stderr || '')
        .split('\n')
        .filter((line) => line.includes('LOG_LEVEL'))
        .join('\n');
      // 必须点名被拒的取值，否则运维只看到"级别没生效"，查不到原因
      expect(reported).toContain(probeEnvValue);
    });

    test('取值有效性直接可判定：合法集来自 winston，而不是自造清单', () => {
      const winston = require('winston');
      const { resolveLogLevel } = require('../utils/logger').__test;
      for (const lvl of Object.keys(winston.config.npm.levels)) {
        process.env.LOG_LEVEL = lvl;
        try {
          expect(resolveLogLevel()).toBe(lvl);
        } finally {
          delete process.env.LOG_LEVEL;
        }
      }
    });

    test('反向保护：非法级别不得让 error 记录消失（这才是原缺陷的真实危害）', () => {
      const logger = loadLogger('info ');
      // 修复前这一句就是 false：整条链静默丢弃，连 error 也没有
      expect(logger.isLevelEnabled('error')).toBe(true);
      expect(logger.isLevelEnabled('warn')).toBe(true);
    });

    test('反向保护：合法的低级别仍按声明收窄（校验不得变成一律 info）', () => {
      expect(loadLogger('error').isLevelEnabled('warn')).toBe(false);
      expect(loadLogger('error').isLevelEnabled('error')).toBe(true);
    });
  });

  describe('② 落盘边界：消息清洗 + 限长（纯函数）', () => {
    const { sanitizeLogInfo } = require('../utils/logger').__test;

    test('消息里的换行被剥离，不会再拼出第二条日志行', () => {
      const out = sanitizeLogInfo({
        level: 'warn',
        message: '正常消息\n2026-01-01 [info]: ADMIN LOGIN OK',
      });
      expect(out.message.includes('\n')).toBe(false);
      expect(out.message).toContain('ADMIN LOGIN OK'); // 内容保留，只是不再成行
    });

    test('超长消息截到 8192、超长字段截到 1024（不得产出一行巨型日志）', () => {
      const out = sanitizeLogInfo({
        message: 'M'.repeat(200000),
        username: 'U'.repeat(200000),
      });
      expect(out.message.length).toBeLessThanOrEqual(8192);
      expect(out.username.length).toBeLessThanOrEqual(1024);
    });

    test('反向保护：level / timestamp / 普通消息原样保留（清洗不得变成破坏）', () => {
      const out = sanitizeLogInfo({
        level: 'info',
        message: 'hello',
        timestamp: '2026-01-01T00:00:00.000Z',
      });
      expect(out.level).toBe('info');
      expect(out.message).toBe('hello');
      expect(out.timestamp).toBe('2026-01-01T00:00:00.000Z');
    });

    test('反向保护：非字符串字段不被当字符串处理（Error 等须原样传递）', () => {
      const err = new Error('boom');
      const out = sanitizeLogInfo({ message: 'x', err });
      expect(out.err).toBe(err);
    });
  });

  describe('③ meta 序列化：循环引用/BigInt 不得让整条记录消失', () => {
    const { serializeMeta } = require('../utils/logger').__test;

    test('普通对象仍走 JSON（保持既有格式与效率）', () => {
      expect(serializeMeta({ a: 1, b: 'x' })).toBe('{"a":1,"b":"x"}');
    });

    test('循环引用降级为可读文本而不是抛错', () => {
      const circular = { name: 'circular' };
      circular.self = circular;
      let out;
      expect(() => {
        out = serializeMeta({ payload: circular });
      }).not.toThrow();
      expect(typeof out).toBe('string');
      expect(out.length).toBeGreaterThan(0);
      expect(out).toContain('circular');
    });

    test('BigInt 同样不得抛（JSON.stringify 对它直接 TypeError）', () => {
      expect(() => serializeMeta({ big: BigInt(1) })).not.toThrow();
    });
  });

  describe('④ 落盘格式的判据与「未识别即按生产办」同源', () => {
    const loadWithEnv = (nodeEnv) => {
      jest.resetModules();
      const saved = process.env.NODE_ENV;
      if (nodeEnv === undefined) delete process.env.NODE_ENV;
      else process.env.NODE_ENV = nodeEnv;
      try {
        return require('../utils/logger').__test;
      } finally {
        if (saved === undefined) delete process.env.NODE_ENV;
        else process.env.NODE_ENV = saved;
      }
    };

    // 取 transport 实际写出去的那一行文本，判它是不是 JSON 记录
    const emitted = (nodeEnv) => {
      const { fileFormat } = loadWithEnv(nodeEnv);
      const out = fileFormat.transform({
        level: 'info',
        message: '消息',
        requestId: 'probe-req',
      });
      return out[Symbol.for('message')];
    };

    // 期望值逐行写死：测试不得把生产侧的规则再实现一遍（那样实现改错两边一起绿）
    test.each([
      ['production', 'json', '显式生产名'],
      ['prod', 'json', '部署里最常见的简写'],
      ['live', 'json', '另一种生产写法'],
      ['prodution', 'json', '拼错：必须 fail-closed'],
      // 实测记录：未设置时 normalizeNodeEnv 归一为 development，所以走 printf 档。
      // "未设置 NODE_ENV 是否该按生产办"是策略问题（会影响所有本地开发），
      // 已作为待决项登记，不在这里悄悄改判据。
      [undefined, 'printf', '未设置：当前按 development 处理'],
      ['development', 'printf', '开发环境保持不变'],
      ['test', 'printf', '单测环境保持不变'],
      ['staging', 'printf', '预发按显式声明处理'],
    ])('NODE_ENV=%s → %s 档（%s）', (env, expected, _why) => {
      const line = emitted(env);
      if (expected === 'json') {
        expect(line.startsWith('{')).toBe(true);
        // 结构化字段必须在：logShipper/ELK 按字段解析，靠 grep 字符串是脆的
        expect(JSON.parse(line).requestId).toBe('probe-req');
      } else {
        expect(line.startsWith('{')).toBe(false);
        expect(line).toContain('[info]:');
        expect(line).toContain('消息');
      }
    });
  });
});
