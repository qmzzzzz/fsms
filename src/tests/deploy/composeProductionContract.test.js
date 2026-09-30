/**
 * docker-compose 的 production 环境变量契约（类断裂的回归防线）
 *
 * 背景：`src/config/validate.js` 在 NODE_ENV=production 下有一组**致命**必填项，
 * 少任何一项应用都起不来（process.exit(1)）。而 `docker-compose.yml` 是实际的
 * 部署入口——它此前从未提供 ALLOWED_HOSTS，于是 `docker compose up` 必然在启动期
 * 失败：这不是「配置不优雅」，是部署链断裂。
 *
 * 为什么不做「grep 变量名存在」式静态断言：那只能证明字符串出现过，证明不了
 * 「照这份 compose 起得来」。本文件把 compose 的 environment 段展开进
 * process.env，再调用**真实的 validateConfig()**，于是这些都会变红：
 *   - 新增致命必填项而忘记补 compose；
 *   - compose 里变量名写错、或值不满足强度判定（弱密钥 / localhost 库串 / 通配 CORS）；
 *   - `*_FILE` 秘密注入形态被改坏。
 *
 * 最后两条是自检：一条证明替身密钥本身够强（否则「能启动」是假绿），
 * 一条证明「抹掉必填项会被抓到」（否则第一条可能只是断言没生效）。
 */

const fs = require('fs');
const os = require('os');
const path = require('path');

// 致命校验的出口是 logger.error（L-05 起不再走 console）——记录下来供断言使用，
// 同时避免把「配置校验失败」真写进 logs/（配合下面 loggerFlush 的 mock）。
// 用 Proxy 而非具名方法：logger 的导出面很宽（error/warn/info/debug/child/...），
// 只列几个会在后续改动里抛 "not a function"。
const mockLogLines = [];
jest.mock(
  '../../utils/logger',
  () =>
    new Proxy(
      {},
      {
        get: (target, prop) => {
          if (prop === '__esModule') return false;
          if (prop === 'default') return undefined;
          return (...args) => {
            mockLogLines.push(
              args.map((a) => (typeof a === 'string' ? a : JSON.stringify(a))).join(' ')
            );
          };
        },
      }
    )
);
jest.mock('../../utils/loggerFlush', () => ({ flushLogsSync: () => {} }));

const COMPOSE = path.join(__dirname, '../../../docker-compose.yml');

/** 一个足够强、且不含占位符语义的替身密钥（第 3 条用例自证它不被判弱） */
const STRONG_DUMMY = 'Zq7!Wn4#Rt9$Yp2@Ks6&Lm8*Vc3^Bh5%Jf1Nx0Kd';

/** 取出 app 服务 environment 段的 KEY=VALUE（结束边界取 app 自己的 secrets: 段） */
function readAppEnvironment() {
  const text = fs.readFileSync(COMPOSE, 'utf8');
  const envAt = text.indexOf('\n    environment:');
  if (envAt < 0) throw new Error('docker-compose.yml 里找不到 app 的 environment 段');
  const endAt = text.indexOf('\n    secrets:', envAt);
  const block = text.slice(envAt, endAt < 0 ? text.length : endAt);

  const vars = {};
  for (const rawLine of block.split('\n')) {
    const line = rawLine.trim();
    if (!line.startsWith('- ')) continue;
    const eq = line.indexOf('=');
    if (eq < 0) continue;
    const key = line.slice(2, eq).trim();
    vars[key] = line.slice(eq + 1).trim();
  }
  return vars;
}

/**
 * 展开 compose 的插值语法为「部署方实际会拿到的值」：
 *   ${VAR:?提示} → 强制外部输入，用强随机替身（等价于运维确实给了值）
 *   ${VAR:-默认} → 未显式配置时的默认值
 *   /run/secrets/x → 落一个临时文件，让 *_FILE 注入路径真实可读
 */
function materialize(raw, tmpDir) {
  if (raw.startsWith('/run/secrets/')) {
    const file = path.join(tmpDir, path.basename(raw));
    // 每个 secret 写**不同**的替身值：compose 的四个 secret 是 generate-secrets.js
    // 分别生成的独立随机值。全部写成同一个 STRONG_DUMMY 会让
    // JWT_SECRET === JWT_REFRESH_SECRET，被"两把 JWT 密钥不得相同"这条判据按真实
    // 拓扑拒掉（那条判据是对的，错的是替身）。
    const name = path.basename(raw);
    fs.writeFileSync(file, `${STRONG_DUMMY}:${name}`, 'utf8');
    return file;
  }
  const interpolation = raw.match(/^\$\{([A-Z0-9_]+)(?::?[-?][^}]*)?\}$/);
  if (interpolation) {
    const def = raw.match(/:-([^}]*)\}/);
    // 未给默认值时按变量名单独造替身：多个 `${X:?}` 共用同一个值会互相"撞库"，
    // 让按值比较的判据（如两把 JWT 密钥不得相同）测到替身而不是被测拓扑
    return def ? def[1] : `${STRONG_DUMMY}:${interpolation[1]}`;
  }
  return raw;
}

/** 跑一次真实的 validateConfig，返回它以什么退出码终止 + 期间记下的日志 */
function runValidate() {
  mockLogLines.length = 0;
  jest.resetModules();
  const { validateConfig } = require('../../config/validate');
  const originalExit = process.exit;
  let exitedWith = null;
  process.exit = (code) => {
    exitedWith = code;
    throw new Error('__process_exit__');
  };
  try {
    validateConfig();
  } catch (e) {
    if (e.message !== '__process_exit__') throw e;
  } finally {
    process.exit = originalExit;
  }
  return { exitedWith, output: mockLogLines.join('\n') };
}

describe('docker-compose 生产环境变量契约', () => {
  // 本用例集触碰的变量：全部保存/还原，避免污染同 worker 的后续文件
  const ENV_KEYS = [
    'NODE_ENV',
    'TZ',
    'TZ_BUSINESS',
    'TRUST_PROXY_HOPS',
    'CORS_ORIGIN',
    'ALLOWED_HOSTS',
    'AUDIT_RETENTION_DAYS',
    'REDIS_URL',
    'ENABLE_HTTPS',
    'DOCS_ENABLED',
    'DOCS_USERNAME',
    'DOCS_PASSWORD',
    'LOGIN_ENCRYPT_STRICT',
    'MONGODB_URI',
    'MONGODB_TLS_EXEMPT',
    'REDIS_TLS_EXEMPT',
    'JWT_SECRET',
    'JWT_REFRESH_SECRET',
    'AES_SECRET_KEY',
    'HMAC_SECRET',
    'JWT_SECRET_FILE',
    'JWT_REFRESH_SECRET_FILE',
    'AES_SECRET_KEY_FILE',
    'HMAC_SECRET_FILE',
    'MONGODB_URI_FILE',
    'ADMIN_INITIAL_PASSWORD_FILE',
  ];
  const saved = {};
  let tmpDir;
  let composeVars;

  beforeAll(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'compose-env-'));
    composeVars = readAppEnvironment();
    for (const key of ENV_KEYS) saved[key] = process.env[key];

    for (const [key, raw] of Object.entries(composeVars)) {
      process.env[key] = materialize(raw, tmpDir);
    }
    // compose 的真实形态是 *_FILE：值由 config/secrets.js 从文件读出后注入同名变量。
    // 这里直接给出"文件已注入"的结果态，等价于容器内进程启动后看到的环境。
    const fileMap = {
      JWT_SECRET_FILE: 'JWT_SECRET',
      JWT_REFRESH_SECRET_FILE: 'JWT_REFRESH_SECRET',
      AES_SECRET_KEY_FILE: 'AES_SECRET_KEY',
      HMAC_SECRET_FILE: 'HMAC_SECRET',
      MONGODB_URI_FILE: 'MONGODB_URI',
    };
    for (const [fileVar, target] of Object.entries(fileMap)) {
      if (process.env[fileVar]) {
        process.env[target] = fs.readFileSync(process.env[fileVar], 'utf8').trim();
      }
    }
  });

  afterAll(() => {
    for (const key of ENV_KEYS) {
      if (saved[key] === undefined) delete process.env[key];
      else process.env[key] = saved[key];
    }
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch (_) {
      /* 临时目录清理失败不影响结论 */
    }
  });

  test('environment 段解析出预期变量集（防解析锚点失效导致整文件假绿）', () => {
    const keys = Object.keys(composeVars);
    expect(keys.length).toBeGreaterThanOrEqual(12);
    // 锚点自证：取到的确实是 app 服务那段，而不是 mongo/redis 的 environment
    expect(composeVars.NODE_ENV).toBe('production');
    expect(composeVars.JWT_SECRET_FILE).toBe('/run/secrets/jwt_secret');
    expect(composeVars.TRUST_PROXY_HOPS).toBe('${TRUST_PROXY_HOPS:-1}');
  });

  test('替身密钥自身不被判弱（否则「校验通过」是假绿）', () => {
    jest.resetModules();
    const { isWeakSecret } = require('../../config/validate');
    expect(isWeakSecret(STRONG_DUMMY)).toBe(false);
  });

  test('按 compose 给的环境变量，生产配置校验必须通过（服务起得来）', () => {
    const { exitedWith, output } = runValidate();
    expect(exitedWith).toBeNull();
    // 只否定"致命项"的名字，不否定告警文案（reportProductionWarnings 允许有内容）
    expect(output).not.toMatch(/ALLOWED_HOSTS|REDIS_URL|JWT_SECRET|AES_SECRET_KEY|HMAC_SECRET/);
  });

  test('负向自证：抹掉 ALLOWED_HOSTS 后同一流程必须致命退出', () => {
    const keep = process.env.ALLOWED_HOSTS;
    delete process.env.ALLOWED_HOSTS;
    try {
      const { exitedWith, output } = runValidate();
      expect(exitedWith).toBe(1);
      expect(output).toMatch(/ALLOWED_HOSTS/);
    } finally {
      process.env.ALLOWED_HOSTS = keep;
    }
  });

  test('ALLOWED_HOSTS 是强制显式项而非默认值（给默认等于把真实域名关在门外）', () => {
    expect(composeVars.ALLOWED_HOSTS).toMatch(/^\$\{ALLOWED_HOSTS:\?/);
  });

  /**
   * 纯函数：从一批「文档/配置」文本里抽出 `node|sh|bash scripts/<file> [--flag…]` 形式的命令引用，
   * 报告 ① 指向不存在的脚本、② 文档写了但该脚本源码里根本没有的开关。
   *
   * 只认「与 scripts/x.js 出现在同一条命令行上」的 --flag，避免把散文里的引号内容当成参数；
   * 代价是跨行续行（`\`）里的开关扫不到——这属于漏报而非误报，宁可漏也不给文档加假红。
   */
  const findScriptRefDrift = (entries, existsSync, readFileSync) => {
    const refs = [];
    const missingFiles = [];
    const unknownFlags = [];
    for (const { name, text } of entries) {
      for (const m of text.matchAll(
        /(?:node|sh|bash)[ \t]+((?:\.{2}[\\/])?scripts[\\/][\w.@-]+\.(?:js|sh))((?:[ \t]+--[\w-]+)*)/g
      )) {
        const target = m[1].replace(/\\/g, '/').replace(/^\.\.\//, '');
        const flags = (m[2] || '').match(/--[\w-]+/g) || [];
        refs.push({ from: name, target, flags });
        if (!existsSync(target)) {
          missingFiles.push({ from: name, target });
          continue; // 脚本都不存在，无从判开关
        }
        const src = readFileSync(target);
        for (const f of flags)
          if (!src.includes(f)) unknownFlags.push({ from: name, target, flag: f });
      }
    }
    return { refs, missingFiles, unknownFlags };
  };

  test('文档与部署入口里引用的 scripts/* 与其开关，必须与仓库实际一致', () => {
    // 实证过的两类腐化：
    //  ① docker-compose.yml 曾写「scripts/deploy.sh 会做 fail-fast 校验」，而仓库从来没有
    //     deploy.sh（2026-09-18 审计报告点名、长期无人改）——运维照抄就是 command not found；
    //  ② runbook 写着 `--apply` 而实现早已改名/加双开关，运维按文档敲就是"命令不识别"，
    //     更坏的情况是脚本把未知参数当没看见、静默不做那一步。
    // 本用例把「文档说的 = 代码做的」变成断言。它是**文本 vs 文本**的契约（判据对象就是文档），
    // 所以这里用文本扫描是对的工具，不属于"该测行为却去扫源码"的那种假绿。
    const root = path.join(__dirname, '../../..');
    const docFiles = [
      path.join(root, 'docker-compose.yml'),
      path.join(root, 'README.md'),
      path.join(root, 'CONTRIBUTING.md'),
      ...fs
        .readdirSync(path.join(root, '.github/workflows'))
        .map((f) => path.join(root, '.github/workflows', f)),
      ...fs
        .readdirSync(path.join(root, 'deployment'))
        .filter((f) => f.endsWith('.md'))
        .map((f) => path.join(root, 'deployment', f)),
    ];
    const entries = docFiles
      .filter((f) => fs.existsSync(f))
      .map((f) => ({
        name: path.relative(root, f).replace(/\\/g, '/'),
        text: fs.readFileSync(f, 'utf8'),
      }));

    const existsSync = (rel) => fs.existsSync(path.join(root, rel));
    const readFileSync = (rel) => fs.readFileSync(path.join(root, rel), 'utf8');
    const { refs, missingFiles, unknownFlags } = findScriptRefDrift(
      entries,
      existsSync,
      readFileSync
    );

    // 前提自证：真的扫到足量引用（扫空会让本用例恒绿）
    expect(refs.length).toBeGreaterThanOrEqual(15);
    expect(missingFiles).toEqual([]);
    expect(unknownFlags).toEqual([]);

    // 可证伪：判据必须能报错。喂一份"指向不存在的脚本 + 编造一个开关"的假文档，
    // 两类漂移都要被抓到（否则上面两个 toEqual([]) 等于没断言）。
    const fake = findScriptRefDrift(
      [{ name: 'FAKE.md', text: 'node scripts/zzq-ghost.js --apply --confirm-yes' }],
      (rel) => rel === 'scripts/zzq-real.js',
      () =>
        '/* 源码里没有 --confirm-yes 这个开关 */ const APPLY = process.argv.includes("--apply");'
    );
    expect(fake.missingFiles).toEqual([{ from: 'FAKE.md', target: 'scripts/zzq-ghost.js' }]);
    const fake2 = findScriptRefDrift(
      [{ name: 'FAKE.md', text: 'node scripts/zzq-real.js --apply --confirm-yes' }],
      (rel) => rel === 'scripts/zzq-real.js',
      () => 'const APPLY = process.argv.includes("--apply");'
    );
    expect(fake2.unknownFlags).toEqual([
      { from: 'FAKE.md', target: 'scripts/zzq-real.js', flag: '--confirm-yes' },
    ]);
    // 且它不误伤：散文里出现的 --flag（不在命令行上）不算引用
    expect(
      findScriptRefDrift(
        [{ name: 'X.md', text: '我们讨论过 --some-random-doc-word 这个概念' }],
        () => true,
        () => ''
      ).refs
    ).toEqual([]);
  });
});
