/**
 * 环境语义的**消费方一致性**（F-04，2026-10-17）
 *
 * 缺陷形状（已回源复核）：`config/validate.js` 已实现环境归一与「未识别值按生产办」，
 * 但多个消费方仍各自比较原始字符串：
 *   - `middleware/sentry.js`：`process.env.NODE_ENV === 'production'` 决定采样率与 environment；
 *   - `services/securityAlertDelivery.js`：同款字面量决定"生产 webhook 未设 allowlist"告警；
 *   - `src/index.js`：`config.nodeEnv === 'production'` 决定启动提示；
 *   - `config/immutableConfigGuard.js`：同款字面量决定 PII 旧密钥残留告警。
 *
 * 后果（以 `NODE_ENV=prod` 为例）：生产硬闸全开（弱密钥/ALLOWED_HOSTS/REDIS_URL/TLS 都验），
 * 而 Sentry 采样率仍是 1.0、生产 webhook 告警不响、启动提示不出现——同一进程里
 * 「是否生产」有两个答案，且差异只会在配额被吃光或告警没送达时才暴露。
 *
 * 本套件钉三件事：
 *  ① 生产别名（production/prod/live）与未识别值的**行为完全一致**（消费方都按生产办）；
 *  ② 开发家族仍走开发分支（不得把本地开发也闸停）；
 *  ③ 静态闸：`src/` 下不得再出现按字面量比较生产环境的代码（注释除外）。
 */

const fs = require('fs');
const path = require('path');

const SRC_DIR = path.resolve(__dirname, '../..');

const withEnv = (env, fn) => {
  const saved = process.env.NODE_ENV;
  if (env === undefined) delete process.env.NODE_ENV;
  else process.env.NODE_ENV = env;
  try {
    return fn();
  } finally {
    if (saved === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = saved;
  }
};

describe('F-04 Sentry：生产别名与 production 行为一致', () => {
  const loadSentry = (env) => {
    let captured = null;
    jest.isolateModules(() => {
      jest.doMock('@sentry/node', () => ({
        init: (opts) => {
          captured = opts;
        },
        Integrations: { Http: function Http() {} },
        Handlers: {
          requestHandler: () => (q, s, n) => n(),
          tracingHandler: () => (q, s, n) => n(),
          errorHandler: () => (e, q, s, n) => n(),
        },
        captureException: () => {},
      }));
      const prevDsn = process.env.SENTRY_DSN;
      process.env.SENTRY_DSN = 'https://dummy@example.invalid/1';
      withEnv(env, () => {
        require('../../middleware/sentry').initSentry();
      });
      if (prevDsn === undefined) delete process.env.SENTRY_DSN;
      else process.env.SENTRY_DSN = prevDsn;
    });
    return captured;
  };

  test.each(['production', 'prod', 'live', 'Production', ' production '])(
    'NODE_ENV=%p ⇒ 生产采样率 0.1',
    (env) => {
      const opts = loadSentry(env);
      expect(opts.tracesSampleRate).toBe(0.1);
    }
  );

  test.each(['development', 'dev', 'test', 'ci', 'staging'])(
    'NODE_ENV=%p ⇒ 开发采样率 1.0（不误伤非生产环境）',
    (env) => {
      const opts = loadSentry(env);
      expect(opts.tracesSampleRate).toBe(1.0);
    }
  );

  test('environment 字段用归一值，大小写/空白不产生第二个 environment', () => {
    expect(loadSentry(' Production ').environment).toBe('production');
  });
});

describe('F-04 securityAlertDelivery：生产 webhook 告警不因别名而静默', () => {
  const loadWith = (env) => {
    const errors = [];
    jest.isolateModules(() => {
      jest.doMock('../../utils/logger', () => ({
        error: (m) => errors.push(m),
        warn: () => {},
        info: () => {},
        debug: () => {},
      }));
      jest.doMock('../../utils/metrics', () => ({ incSecurityAlert: () => {} }));
      const saved = {
        webhook: process.env.SECURITY_ALERT_WEBHOOK,
        allow: process.env.SECURITY_ALERT_WEBHOOK_ALLOWLIST,
      };
      process.env.SECURITY_ALERT_WEBHOOK = 'https://hooks.example.com/x';
      delete process.env.SECURITY_ALERT_WEBHOOK_ALLOWLIST;
      withEnv(env, () => {
        require('../../services/securityAlertDelivery');
      });
      if (saved.webhook === undefined) delete process.env.SECURITY_ALERT_WEBHOOK;
      else process.env.SECURITY_ALERT_WEBHOOK = saved.webhook;
      if (saved.allow !== undefined) process.env.SECURITY_ALERT_WEBHOOK_ALLOWLIST = saved.allow;
    });
    return errors;
  };

  test.each(['production', 'prod', 'live'])('NODE_ENV=%p ⇒ 告警必须响', (env) => {
    expect(loadWith(env).some((m) => m.includes('SECURITY_ALERT_WEBHOOK_ALLOWLIST'))).toBe(true);
  });

  test.each(['development', 'dev', 'test'])('NODE_ENV=%p ⇒ 不误报', (env) => {
    expect(loadWith(env)).toEqual([]);
  });
});

describe('F-04 静态闸：不得再按字面量比较生产环境', () => {
  const listJs = (dir, out = []) => {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      if (e.name === 'tests' || e.name === 'node_modules') continue;
      const full = path.join(dir, e.name);
      if (e.isDirectory()) listJs(full, out);
      else if (e.name.endsWith('.js')) out.push(full);
    }
    return out;
  };

  test('src/ 生产代码里不存在 `NODE_ENV === production` / `nodeEnv === production` 的判定', () => {
    const offenders = [];
    for (const file of listJs(SRC_DIR)) {
      const rel = path.relative(SRC_DIR, file).replace(/\\/g, '/');
      const lines = fs.readFileSync(file, 'utf8').split('\n');
      lines.forEach((line, i) => {
        // 注释行不算（本仓多处注释在解释历史写法，那些正是"为什么不能这么写"的证据）
        if (/^\s*(?:\/\/|\*|\/\*)/.test(line)) return;
        if (
          /process\.env\.NODE_ENV\s*===\s*['"]production['"]/.test(line) ||
          /config\.nodeEnv\s*===\s*['"]production['"]/.test(line)
        ) {
          offenders.push(`${rel}:${i + 1}`);
        }
      });
    }
    expect(offenders).toEqual([]);
  });
});
