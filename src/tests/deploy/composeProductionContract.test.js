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
const crypto = require('crypto');
const os = require('os');
const path = require('path');

// 致命校验的出口是 logger.error（L-05 起不再走 console）——记录下来供断言使用，
// 同时避免把「配置校验失败」真写进 logs/（配合下面 loggerFlush 的 mock）。
// 用 Proxy 而非具名方法：logger 的导出面很宽（error/warn/info/debug/child/...），
// 只列几个会在后续改动里抛 "not a function"。
// 分级留痕：mock 合并了所有级别，而"致命校验失败"与"合法启动告警"必须能分开断言。
// 背景（2026-09-30）：下面的「校验必须通过」用例原本对**全量输出**做
//   not.toMatch(/...|HMAC_SECRET/)
// 注释写着"不否定告警文案"，实现却把告警文案也否定了——于是任何合法告警只要
// 点名了某个密钥（如 immutable 档位的 pepper 轮换告警要点名 HMAC_SECRET 才说得清）
// 就会被误判为"致命项泄漏"。实测：新增该告警后本用例变红，而服务其实起得来。
// 故按级别分桶，断言只针对 error 级（真正的致命项）。
const mockLogLines = [];
const mockErrors = [];
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
            const line = args.map((a) => (typeof a === 'string' ? a : JSON.stringify(a))).join(' ');
            mockLogLines.push(line);
            // error/fatal 是"起不来"的一档；warn（安全加固建议）是"起来了但要知道"
            if (prop === 'error' || prop === 'fatal') mockErrors.push(line);
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
  return readAppEnvironmentFrom(fs.readFileSync(COMPOSE, 'utf8'));
}

/**
 * 同上，但入参是 compose 文本。
 *
 * 存在理由不是复用：下面的可证伪用例要拿**改过的文本**复跑同一条判据
 * （删掉一行、改一个默认值语法），否则断言只能证明"当前文件长这样"，
 * 证明不了"判据真的会报错"。
 */
function readAppEnvironmentFrom(text) {
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
 * `${VAR:?}` 的替身值必须**形状正确**，不能一律用强随机串。
 *
 * 2026-10-24 审计后 CORS_ORIGIN / TRUSTED_PROXY_CIDRS 会真的被解析：
 * 用 `STRONG_DUMMY:VAR` 那种串喂进去，红的是"替身不像真实配置"，不是被测契约。
 * 这里给每个强制项一个该拓扑下**合法**的样例值（与 README/.env.example 同形）。
 */
const INTERPOLATION_SAMPLES = Object.freeze({
  CORS_ORIGIN: 'https://admin.example.com',
  ALLOWED_HOSTS: 'admin.example.com',
  TRUSTED_PROXY_CIDRS: '172.28.0.0/16',
});

/**
 * 展开 compose 的插值语法为「部署方实际会拿到的值」：
 *   ${VAR:?提示} → 强制外部输入，用形状正确的替身（等价于运维确实给了值）
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
    // login_ecdh_private_key 的替身必须是**真 PEM**：它的下游消费者
    // （loginCipher 的 createPrivateKey）按 EC 私钥解析，喂 STRONG_DUMMY
    // 那种随机串会让「装配完整」与「密钥可用」脱节——装配闸绿着而登录全失败。
    if (name === 'login_ecdh_private_key') {
      const { privateKey } = crypto.generateKeyPairSync('ec', {
        namedCurve: 'prime256v1',
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
        publicKeyEncoding: { type: 'spki', format: 'pem' },
      });
      fs.writeFileSync(file, privateKey, 'utf8');
      return file;
    }
    fs.writeFileSync(file, `${STRONG_DUMMY}:${name}`, 'utf8');
    return file;
  }
  const interpolation = raw.match(/^\$\{([A-Z0-9_]+)(?::?[-?][^}]*)?\}$/);
  if (interpolation) {
    const def = raw.match(/:-([^}]*)\}/);
    if (def) return def[1];
    const sample = INTERPOLATION_SAMPLES[interpolation[1]];
    if (sample !== undefined) return sample;
    // 其余 `${X:?}` 按变量名单独造替身：多个强制项共用同一个值会互相"撞库"，
    // 让按值比较的判据（如两把 JWT 密钥不得相同）测到替身而不是被测拓扑
    return `${STRONG_DUMMY}:${interpolation[1]}`;
  }
  return raw;
}

/**
 * app 服务 environment 段里指向 /run/secrets 的 <NAME>_FILE 指针：
 * 返回 Map<变量名, 挂载名>。入参是 compose 文本而非文件路径——装配完整性
 * 用例要拿"改过的文本"复跑同一条判据（见该用例的反向自证）。
 */
function fileSecretPointers(text) {
  const envAt = text.indexOf('\n    environment:');
  const endAt = text.indexOf('\n    secrets:', envAt);
  const block = text.slice(envAt, endAt < 0 ? text.length : endAt);
  const pointers = new Map();
  for (const rawLine of block.split('\n')) {
    const m = rawLine.trim().match(/^- ([A-Z0-9_]+_FILE)=\/run\/secrets\/([\w-]+)$/);
    if (m) pointers.set(m[1], m[2]);
  }
  return pointers;
}

/** app 服务 secrets 清单：实际挂载进容器的 secret 名 */
function appSecretMounts(text) {
  const envAt = text.indexOf('\n    environment:');
  const listAt = text.indexOf('\n    secrets:', envAt);
  const endAt = text.indexOf('\n    depends_on:', listAt);
  if (listAt < 0 || endAt < 0) {
    throw new Error('docker-compose.yml 里找不到 app 服务的 secrets 清单段');
  }
  return text
    .slice(listAt, endAt)
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.startsWith('- '))
    .map((line) => line.slice(2).trim());
}

/** 顶层 secrets 定义：secret 名 → file: 指向的文件名 */
function topLevelSecretFiles(text) {
  const topAt = text.indexOf('\nsecrets:');
  if (topAt < 0) throw new Error('docker-compose.yml 里找不到顶层 secrets 段');
  const block = text.slice(topAt, text.indexOf('\nvolumes:', topAt));
  const defs = new Map();
  let current = null;
  for (const rawLine of block.split('\n')) {
    const name = rawLine.match(/^ {2}([\w-]+):\s*$/);
    if (name) {
      current = name[1];
      continue;
    }
    const file = rawLine.match(/^ {4}file:\s*\.\/secrets\/([\w-]+)\s*$/);
    if (file && current) defs.set(current, file[1]);
  }
  return defs;
}

/** 轮换手册「各密钥轮换影响面」表第一列点名的密钥标识符 */
function rotationManualSecretNames(manualText) {
  return [...manualText.matchAll(/^\|\s*`?([A-Z][A-Z0-9_]+)`?[^|]*\|/gm)].map((m) => m[1]);
}

/**
 * 文件注入密钥的装配完整性问题清单（空数组＝齐装）。
 *
 * 2026-10-10 审计 finding：`FILE_BACKED_SECRETS` 支持
 * `LOGIN_ECDH_PRIVATE_KEY_FILE`、`generate-secrets.js` 也产出
 * `login_ecdh_private_key`，但 compose 三处全漏——服务每次启动惰性生成临时
 * 密钥对，手册里这把钥匙的轮换流程从不生效，重启前的历史登录密文永久无法
 * 解密。三类漏法各能造出"部署看起来齐了"：有指针没挂载、有挂载没顶层定义、
 * 手册点名而 compose 没有，故收进同一条判据。
 */
function wiringProblems(text, manualFileBacked) {
  const problems = [];
  const pointers = fileSecretPointers(text);
  const appMounts = appSecretMounts(text);
  const topDefs = topLevelSecretFiles(text);

  for (const [varName, mount] of pointers) {
    if (!appMounts.includes(mount)) {
      problems.push(`${varName} 指向 /run/secrets/${mount}，但 app secrets 清单没有挂载它`);
    }
    if (topDefs.get(mount) !== mount) {
      problems.push(
        `${mount} 在顶层 secrets 没有 file: ./secrets/${mount} 定义（或指向了别的文件）`
      );
    }
  }
  for (const mount of appMounts) {
    if (!topDefs.has(mount)) {
      problems.push(`app secrets 清单挂载了 ${mount}，顶层 secrets 却没有定义它`);
    }
  }
  for (const name of manualFileBacked) {
    if (!pointers.has(`${name}_FILE`)) {
      problems.push(
        `轮换手册点名了 ${name}（FILE_BACKED_SECRETS 成员），但 app environment 没有 ${name}_FILE 指针——手册里的轮换流程从不生效`
      );
    }
  }
  return problems;
}

/** 跑一次真实的 validateConfig，返回它以什么退出码终止 + 期间记下的日志 */
function runValidate() {
  mockLogLines.length = 0;
  mockErrors.length = 0;
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
  return { exitedWith, output: mockLogLines.join('\n'), errors: mockErrors.join('\n') };
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
    // 2026-10-10 补装的登录 ECDH 静态私钥：hydration 会把文件内容回填进
    // LOGIN_ECDH_PRIVATE_KEY，指针与目标值两个名字都必须保存/还原
    'LOGIN_ECDH_PRIVATE_KEY_FILE',
    'LOGIN_ECDH_PRIVATE_KEY',
    'REDIS_PASSWORD',
    'REDIS_PASSWORD_FILE',
    'ADMIN_INITIAL_PASSWORD_FILE',
    // 2026-10-24 审计：/metrics 鉴权令牌与 TLS/环境闸的三个显式开关
    'METRICS_TOKEN',
    'METRICS_TOKEN_FILE',
    'TLS_TERMINATED_UPSTREAM',
    'REQUIRE_PRODUCTION_CONFIG',
    'TRUSTED_PROXY_CIDRS',
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
      // 登录口令信封加密的服务端静态私钥（2026-10-10 补装）：与生产同形态
      // 经 *_FILE 注入，目标变量由 validateConfig → hydrateSecretsFromFiles 回填
      LOGIN_ECDH_PRIVATE_KEY_FILE: 'LOGIN_ECDH_PRIVATE_KEY',
      // 2026-10-01 认证闸：compose 拓扑的 redis 凭据经同一 *_FILE 注入路径进入
      REDIS_PASSWORD_FILE: 'REDIS_PASSWORD',
      // 2026-10-24 审计：#6 的闭合口——compose 必须能把 METRICS_TOKEN 真的传进容器
      METRICS_TOKEN_FILE: 'METRICS_TOKEN',
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

  /**
   * 文件注入密钥的装配完整性（2026-10-10 审计 finding 的回归闸）
   *
   * 判据不是"变量名出现过"：三方（environment 的 `*_FILE` 指针、app 服务
   * `secrets:` 挂载清单、顶层 `secrets:` 定义）必须逐一对应，且轮换手册点名、
   * `FILE_BACKED_SECRETS` 收录的密钥必须全部经指针进容器。只验装配不验手册
   * 覆盖，就会出现"手册写着能轮换、compose 却没接"的缺口——那正是
   * LOGIN_ECDH_PRIVATE_KEY 此前的状态。
   */
  test('文件注入密钥装配三方一致，且轮换手册点名的密钥全部在装', () => {
    const text = fs.readFileSync(COMPOSE, 'utf8');
    const manual = fs.readFileSync(
      path.join(__dirname, '../../../deployment/secret-rotation.md'),
      'utf8'
    );
    const { FILE_BACKED_SECRETS } = require('../../config/secrets');
    const manualFileBacked = rotationManualSecretNames(manual).filter((name) =>
      FILE_BACKED_SECRETS.includes(name)
    );

    // 前提自证：手册点名集与装配集都不是空的（空集合会让下面的判据恒绿）
    expect(manualFileBacked).toEqual(
      expect.arrayContaining([
        'JWT_SECRET',
        'JWT_REFRESH_SECRET',
        'AES_SECRET_KEY',
        'HMAC_SECRET',
        'LOGIN_ECDH_PRIVATE_KEY',
        'MONGODB_URI',
      ])
    );
    expect(fileSecretPointers(text).size).toBeGreaterThanOrEqual(8);

    expect(wiringProblems(text, manualFileBacked)).toEqual([]);

    // 反向自证①：删掉 app environment 的 LOGIN_ECDH_PRIVATE_KEY_FILE 行，
    // 「手册点名必须装配」通道必须点名它（2026-10-10 缺口的原样复现）
    const noEnvLine = text.replace(
      /^[ \t]*- LOGIN_ECDH_PRIVATE_KEY_FILE=\/run\/secrets\/login_ecdh_private_key\r?\n/m,
      ''
    );
    expect(noEnvLine).not.toBe(text);
    expect(wiringProblems(noEnvLine, manualFileBacked).join('\n')).toContain(
      'LOGIN_ECDH_PRIVATE_KEY_FILE'
    );

    // 反向自证②：删掉 app secrets 清单里的挂载项，三方一致通道必须红
    const noMount = text.replace(/^[ \t]*- login_ecdh_private_key\r?\n/m, '');
    expect(noMount).not.toBe(text);
    expect(wiringProblems(noMount, manualFileBacked).join('\n')).toContain(
      'login_ecdh_private_key'
    );
  });

  test('替身密钥自身不被判弱（否则「校验通过」是假绿）', () => {
    jest.resetModules();
    const { isWeakSecret } = require('../../config/validate');
    expect(isWeakSecret(STRONG_DUMMY)).toBe(false);
  });

  test('按 compose 给的环境变量，生产配置校验必须通过（服务起得来）', () => {
    const { exitedWith, output, errors } = runValidate();
    expect(exitedWith).toBeNull();
    // 只否定"致命项"的名字（error 级），**不否定告警文案**——reportProductionWarnings
    // 允许有内容，且合法告警会点名密钥（如 pepper 轮换告警必须说清是 HMAC_SECRET）。
    // 2026-09-30 修正：原实现对该匹配跑在 `output`（全量、含 warn）上，与本注释的
    // 意图相反，任何合法告警都会被误判。现改为只匹配 error 级输出。
    expect(errors).not.toMatch(/ALLOWED_HOSTS|REDIS_URL|JWT_SECRET|AES_SECRET_KEY|HMAC_SECRET/);
    // 前提自证：errors 分桶确实能装东西（否则上面那条恒真）——见下一条负向自证用例
    expect(typeof output).toBe('string');
  });

  test('负向自证：抹掉 ALLOWED_HOSTS 后同一流程必须致命退出', () => {
    const keep = process.env.ALLOWED_HOSTS;
    delete process.env.ALLOWED_HOSTS;
    try {
      const { exitedWith, output, errors } = runValidate();
      expect(exitedWith).toBe(1);
      expect(output).toMatch(/ALLOWED_HOSTS/);
      // 同时证伪 errors 分桶：致命项必须落进 errors，否则上一条的 not.toMatch(errors)
      // 就是一条恒真断言（空桶永远不匹配任何模式 = 永远绿）
      expect(errors).toMatch(/ALLOWED_HOSTS/);
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

/**
 * TRUSTED_PROXY_CIDRS 的「部署可达性」契约（F-01 闭合口，2026-10-21）
 *
 * 这不是"变量名出现过"式的静态断言，而是钉一条**部署链**：
 *   · 代码层写着「闭合方式只有一个：配置 TRUSTED_PROXY_CIDRS」（utils/ipUtils.js），
 *     未配置时判据退回「对端属私网/回环即可信」；
 *   · README 的上线清单要求"已按反向代理实际所在网段设置"；
 *   · 但 compose 是实际部署入口 —— environment 段不传它，运维在 .env 里配了
 *     也进不了容器，判据静默退回兼容档，而清单会显示"已做"。
 *
 * 两个方向都要钉住：
 *   · **必须传**：漏传 ⇒ 配了等于没配（2026-10-21 实测的缺陷形态，
 *     见 deliverables/预发动态验证-核对结论-2026-10-21.md）；
 *   · **必须是 `:?` 而不是 `:-`**（2026-10-24 审计修正）：`:-` 默认留空有两个
 *     叠加问题——(a) README 上线清单写着"已按反向代理实际所在网段设置"，
 *     而留空时判据静默退回「私网/回环即可信」的兼容档，配置意图与实际不符；
 *     (b) 空串在解析侧等价于未配置，运维无法从部署入口区分"我确实选择兼容档"
 *     与"我忘了配置"。`config/trustedProxies.js` 的运行时判据对非 compose
 *     部署仍保持兼容档（不传即兼容），但**本仓的生产部署入口**要求显式声明：
 *     要么给网段，要么在部署前明确删掉这一行并记录理由。
 */
describe('TRUSTED_PROXY_CIDRS 必须在部署入口上真实可达（F-01 闭合口）', () => {
  /** 返回问题描述数组（空数组＝契约成立），供"真文件"与"改坏文本"两侧共用 */
  const problemsOf = (text) => {
    const problems = [];
    const raw = readAppEnvironmentFrom(text).TRUSTED_PROXY_CIDRS;
    if (raw === undefined) {
      problems.push('app environment 没有 TRUSTED_PROXY_CIDRS：.env 里配了也进不了容器');
      return problems;
    }
    if (!/^\$\{TRUSTED_PROXY_CIDRS:\?[^}]*\}$/.test(raw)) {
      problems.push(
        `TRUSTED_PROXY_CIDRS 必须写成 \${TRUSTED_PROXY_CIDRS:?...}（强制显式），实际是 ${raw}`
      );
    }
    return problems;
  };

  test('compose 强制该变量显式配置（缺省不得静默退化为兼容档）', () => {
    expect(problemsOf(fs.readFileSync(COMPOSE, 'utf8'))).toEqual([]);

    // 形状自证：替换值必须是"该拓扑下合法的 CIDR"，否则下面的校验通过是假绿
    const { parseTrustedProxyCidrs } = require('../../config/trustedProxies');
    const sample = materialize('${TRUSTED_PROXY_CIDRS:?必须配置}', null);
    expect(parseTrustedProxyCidrs(sample).errors).toEqual([]);
    expect(parseTrustedProxyCidrs(sample).configured).toBe(true);
  });

  test('可证伪：删掉这一行、或改回默认留空的 `:-`，判据都必须报错', () => {
    const text = fs.readFileSync(COMPOSE, 'utf8');

    // 行尾按 `\r?\n` 取：本仓 docker-compose.yml 是 CRLF，而 src/** 里有 LF-only 文件，
    // 把 `\n` 硬编码进锚点会静默零命中（替换没发生 ⇒ 下面的"可证伪"变成恒真）。
    const removed = text.replace(
      /\r?\n[ \t]*- TRUSTED_PROXY_CIDRS=\$\{TRUSTED_PROXY_CIDRS:\?[^}]*\}\r?\n/,
      '\n'
    );
    expect(removed).not.toBe(text); // 前提：替换真的发生了（否则下面等于没测）
    expect(problemsOf(removed).length).toBeGreaterThan(0);

    const loosened = text.replace(/\$\{TRUSTED_PROXY_CIDRS:\?[^}]*\}/, '${TRUSTED_PROXY_CIDRS:-}');
    expect(loosened).not.toBe(text);
    expect(problemsOf(loosened).length).toBeGreaterThan(0);
  });
});
