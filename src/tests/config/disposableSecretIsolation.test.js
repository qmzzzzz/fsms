/**
 * 一次性开发密钥隔离：宿主残留的 *_FILE 不得覆写 e2e / 压测 / 生产演练 harness
 * （scripts/devSecretIsolation.js 与 scripts/{e2e-smoke,load-test,production-drill}.js）
 *
 * 为什么值得一个专门闸：`src/config/index.js:10-11` 在 require 期就 hydrate，而冲突规则
 * 是**文件优先**（`src/config/secrets.js:113` 无条件 `process.env[name] = value`）。
 * 三个 harness 的形状是「先设一次性 env，再 require ../src/index.js」，所以只要宿主上
 * 还有 `*_FILE`，回填就会把一次性 `MONGODB_URI` 覆写成真实库连接串——**并且不报错**。
 * 后果不是冒烟变红，是**写**：`npm run test:e2e` 往生产/开发库播种管理员、建用户、发告警，
 * `npm run test:load` 往那个库打五相压测流量并写审计。
 *
 * 判据是真子进程 + 真 `src/config`，断言的是"配置对象里的 URI 到底是哪一个"，
 * 不是脚本文件里有没有某个字符串。六格真值表（用例 1–3）：
 *   none  × {export, .env} ⇒ 都被覆写（前提自证：危害是真的，且**两条来源都会**）
 *   blank × {export, .env} ⇒ 都不覆写（当前实现）
 *   del   × export         ⇒ 不覆写；del × .env ⇒ 仍覆写（置空而非删除是承重的）
 * 第三行是防"有人觉得 delete 更干净"——把守卫改成 delete，用例 2 的 .env 臂立刻红。
 */

'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const ROOT = path.resolve(__dirname, '../../..');
const { FILE_BACKED_SECRETS } = require('../../config/secrets');
const { isolateDisposableSecrets } = require('../../../scripts/devSecretIsolation');

// 一次性值与"真实库/真实密钥"值：两者必须能被配置对象区分开
const DISPOSE_URI = 'mongodb://127.0.0.1:59999/disposable_e2e';
const DISPOSE_JWT = 'disposable-jwt-0123456789abcdef';
const PROD_URI = 'mongodb://prod-host:27017/fire_safety_prod';
const PROD_JWT = 'prod-jwt-secret-from-mounted-file';
// harness **从不赋值**的名字：回填的危害不止于它记得覆写的那几个键
// （REDIS_URL / MONGO_ROOT_PASSWORD / ADMIN_INITIAL_PASSWORD 等会原样接上真实基础设施）。
// 它也顺带钉住"守卫绝不 hydrate"：有人为了过 scriptSecretHydration 闸而在守卫里加
// hydrateSecretsFromFiles()，行为用例必须当场变红，而不是靠注释讲道理。
const PROD_ROOT_PW = 'prod-root-pw-from-mounted-file';

/** 子进程里跑的那段夹具：__MODE__ 决定守卫形态，cwd 决定 *_FILE 从哪来 */
const PROBE = [
  "const path = require('path');",
  `const REPO = ${JSON.stringify(ROOT)};`,
  'const mode = process.env.__MODE__;',
  "if (mode === 'blank') {",
  "  require(path.join(REPO, 'scripts/devSecretIsolation.js'))",
  "    .isolateDisposableSecrets({ scriptName: 'probe' });",
  '} else if (mode === "del") {',
  '  for (const n of require(path.join(REPO, "src/config/secrets")).FILE_BACKED_SECRETS) {',
  "    delete process.env[n + '_FILE'];",
  '  }',
  '}',
  `process.env.MONGODB_URI = ${JSON.stringify(DISPOSE_URI)};`,
  `process.env.JWT_SECRET = ${JSON.stringify(DISPOSE_JWT)};`,
  "const cfg = require(path.join(REPO, 'src/config/index.js'));",
  'console.log(JSON.stringify({',
  '  uri: cfg.mongodbUri,',
  '  jwt: cfg.jwt.secret,',
  '  uriFile: process.env.MONGODB_URI_FILE,',
  '  rootPw: process.env.MONGO_ROOT_PASSWORD,',
  '}));',
].join('\n');

let work;
beforeAll(() => {
  work = fs.mkdtempSync(path.join(os.tmpdir(), 'fsms-isolation-'));
  fs.writeFileSync(path.join(work, 'mongodb_uri'), `${PROD_URI}\n`);
  fs.writeFileSync(path.join(work, 'jwt_secret'), PROD_JWT);
  fs.writeFileSync(path.join(work, 'mongo_root_password'), `${PROD_ROOT_PW}\n`);
  fs.writeFileSync(path.join(work, 'probe.js'), PROBE);
  // export 臂的 cwd：空目录 ⇒ dotenv 读不到 .env，来源只有 process.env
  fs.mkdirSync(path.join(work, 'clean-cwd'));
  // .env 臂的 cwd：宿主把 *_FILE 写进 .env（.env.example:12 的生产口径 b）
  fs.mkdirSync(path.join(work, 'dotenv-cwd'));
  fs.writeFileSync(
    path.join(work, 'dotenv-cwd', '.env'),
    `MONGODB_URI_FILE=${path.join(work, 'mongodb_uri')}\n` +
      `JWT_SECRET_FILE=${path.join(work, 'jwt_secret')}\n` +
      `MONGO_ROOT_PASSWORD_FILE=${path.join(work, 'mongo_root_password')}\n` +
      'NODE_ENV=development\n'
  );
});

afterAll(() => {
  if (work) fs.rmSync(work, { recursive: true, force: true });
});

/** 子进程环境：剥掉 jest worker 预置的四把 *_FILE 与密钥，避免夹具继承本机状态 */
function childEnv(extra) {
  const env = { ...process.env };
  for (const name of FILE_BACKED_SECRETS) {
    delete env[name];
    delete env[`${name}_FILE`];
  }
  delete env.NODE_ENV;
  return { ...env, ...extra };
}

function runProbe({ mode, source }) {
  const env = { __MODE__: mode };
  if (source === 'export') {
    env.MONGODB_URI_FILE = path.join(work, 'mongodb_uri');
    env.JWT_SECRET_FILE = path.join(work, 'jwt_secret');
    env.MONGO_ROOT_PASSWORD_FILE = path.join(work, 'mongo_root_password');
  }
  const r = spawnSync(process.execPath, [path.join(work, 'probe.js')], {
    cwd: path.join(work, source === 'export' ? 'clean-cwd' : 'dotenv-cwd'),
    encoding: 'utf8',
    timeout: 60000,
    env: childEnv(env),
  });
  const lines = String(r.stdout).trim().split(/\r?\n/).filter(Boolean);
  let out;
  try {
    out = JSON.parse(lines[lines.length - 1]);
  } catch (e) {
    throw new Error(
      `探针未输出 JSON（mode=${mode} source=${source}）：` +
        `rc=${r.status} stderr=${String(r.stderr).slice(0, 400)}`
    );
  }
  return { ...out, stderr: String(r.stderr) };
}

describe('宿主 *_FILE 与一次性 harness 的隔离', () => {
  test.each([
    ['export', '宿主 shell export'],
    ['dotenv', '.env 里的 *_FILE'],
  ])('前提自证：没有守卫时 %s 会把一次性 URI 覆写成真实库', (_src, label) => {
    const r = runProbe({ mode: 'none', source: _src });
    // 两条来源都得红，否则本闸的另一半是在自证空气
    expect({ label, uri: r.uri, jwt: r.jwt }).toEqual({
      label,
      uri: PROD_URI,
      jwt: PROD_JWT,
    });
    // 危害不止 harness 记得覆写的那两个键：MONGO_ROOT_PASSWORD 它从不赋值，
    // 却照样被文件里的真实值填上 ⇒ "只盯 MONGODB_URI"的修法是不够的。
    expect({ label, rootPw: r.rootPw }).toEqual({ label, rootPw: PROD_ROOT_PW });
  });

  test.each([
    ['export', '宿主 shell export'],
    ['dotenv', '.env 里的 *_FILE'],
  ])('守卫（置空）挡住 %s', (_src, label) => {
    const r = runProbe({ mode: 'blank', source: _src });
    expect({ label, uri: r.uri, jwt: r.jwt, uriFile: r.uriFile }).toEqual({
      label,
      uri: DISPOSE_URI,
      jwt: DISPOSE_JWT,
      // 置空而不是删除：见下一条用例
      uriFile: '',
    });
    // 守卫只置空指针、绝不代做回填（回填正是它要防的动作；见 scriptSecretHydration 的豁免二）
    expect({ label, rootPw: r.rootPw }).toEqual({ label, rootPw: undefined });
    // 静默吞掉运维显式配置是另一种误导
    expect(r.stderr).toContain('MONGODB_URI_FILE=');
    expect(r.stderr).toContain('已置空');
    expect(r.stderr).toContain('MONGO_ROOT_PASSWORD_FILE=');
  });

  test('delete 反证：只删 process.env 挡不住 .env 那条路（所以实现必须置空）', () => {
    // dotenv 在 hydrate 的前一行（src/config/index.js:6 → :11）：键被 delete 后
    // dotenv 认为它"不存在"，又从句柄目录的 .env 填回来。
    const viaDotenv = runProbe({ mode: 'del', source: 'dotenv' });
    expect(viaDotenv.uri).toBe(PROD_URI);
    // 同一条漏网不只覆写 harness 赋过值的键：它把全部 15 个名字都接回真实值
    expect(viaDotenv.rootPw).toBe(PROD_ROOT_PW);
    // export 臂则真的挡住了 ⇒ 差异只来自"删"与"空"，不是夹具本身没生效
    const viaExport = runProbe({ mode: 'del', source: 'export' });
    expect(viaExport.uri).toBe(DISPOSE_URI);
  });

  test('告警只打路径，不把密钥内容带进输出', () => {
    const r = runProbe({ mode: 'blank', source: 'export' });
    expect(r.stderr).toContain(path.join(work, 'mongodb_uri'));
    expect(r.stderr).not.toContain(PROD_URI);
    expect(r.stderr).not.toContain(PROD_JWT);
  });
});

describe('isolateDisposableSecrets 的本体行为', () => {
  let snapshot;
  let warn;
  beforeEach(() => {
    snapshot = { ...process.env };
    warn = [];
    jest.spyOn(console, 'warn').mockImplementation((...a) => warn.push(a.join(' ')));
  });
  afterEach(() => {
    jest.restoreAllMocks();
    for (const key of Object.keys(process.env)) {
      if (!(key in snapshot)) delete process.env[key];
    }
    Object.assign(process.env, snapshot);
  });

  test('清单从 FILE_BACKED_SECRETS 派生：全量置空，非密钥的 *_FILE 不动', () => {
    // 夹具本身来自 secrets.js 的导出，所以将来加第 16 个名字时这里自动覆盖：
    // 若守卫改成抄一份字面量，新名字不会被置空 ⇒ 本用例红（不需要另立静态闸）。
    expect(FILE_BACKED_SECRETS.length).toBeGreaterThanOrEqual(15);
    for (const name of FILE_BACKED_SECRETS) {
      process.env[`${name}_FILE`] = `/run/secrets/${name.toLowerCase()}`;
    }
    process.env.ZZ_NOT_A_SECRET_FILE = '/keep/me';

    const isolated = isolateDisposableSecrets({ scriptName: 'unit' });

    expect(isolated.map((i) => i.name).sort()).toEqual([...FILE_BACKED_SECRETS].sort());
    for (const name of FILE_BACKED_SECRETS) {
      expect(process.env[`${name}_FILE`]).toBe('');
    }
    expect(process.env.ZZ_NOT_A_SECRET_FILE).toBe('/keep/me');
    expect(warn.join('\n')).toContain(`检测到 ${FILE_BACKED_SECRETS.length} 个`);
  });

  test('幂等且宿主本来干净时不告警', () => {
    for (const name of FILE_BACKED_SECRETS) {
      delete process.env[`${name}_FILE`];
    }
    // 第一次调用会吃掉 dotenv 从句柄 cwd 的 .env 里读出来的任何 *_FILE；
    // 之后再调应当干净返回，否则"是否告警"就随本机 .env 漂移了。
    isolateDisposableSecrets({ scriptName: 'unit' });
    warn.length = 0;
    const again = isolateDisposableSecrets({ scriptName: 'unit' });
    expect(again).toEqual([]);
    expect(warn).toEqual([]);
    // 且键仍在（空串），否则 dotenv 会把 .env 的值填回来
    for (const name of FILE_BACKED_SECRETS) {
      expect(process.env[`${name}_FILE`]).toBe('');
    }
  });

  test('返回值带上原路径，便于运维定位来源', () => {
    process.env.HMAC_SECRET_FILE = '/run/secrets/hmac_secret';
    const isolated = isolateDisposableSecrets({ scriptName: 'unit' });
    const hit = isolated.find((i) => i.name === 'HMAC_SECRET');
    expect(hit && hit.filePath).toBe('/run/secrets/hmac_secret');
  });
});

describe('三个 harness 的接线（枚举派生自脚本本身）', () => {
  const SCRIPTS = path.join(ROOT, 'scripts');
  const CALL_RE = /^\s*isolateDisposableSecrets\s*\(/;
  const BOOT_RE = /require\('\.\.\/src\/index\.js'\)/;

  /**
   * 判据只有一件事：守卫调用必须**早于** require 到 src/index.js
   * （hydrate 与 dotenv 都发生在那一刻）。
   * 不要求它早于一次性赋值：守卫只动 `*_FILE`，先设值再置空同样安全，
   * 把非必要的顺序也钉住只会让将来的合理重排变成红灯。
   */
  function lateIsolation(src) {
    const lines = src.split(/\r?\n/);
    const callAt = lines.findIndex((l) => CALL_RE.test(l));
    const bootAt = lines.findIndex((l) => BOOT_RE.test(l));
    if (bootAt === -1) return 'not-a-harness';
    if (callAt === -1) return 'missing';
    return callAt < bootAt ? null : 'late';
  }

  /**
   * 递归收集 scripts 下任意深度的 .js。
   * 不递归的话「第四个 harness 写在 scripts/perf/ 下而忘了守卫」这条形态看不见——
   * 同型漏判本轮已被另一条闸抓过一次（手册闸的 `[\w.-]+` 跨不过目录分隔符）。
   */
  function listJs(dir) {
    const out = [];
    for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
      if (ent.name === 'node_modules' || ent.name.startsWith('.')) continue;
      const p = path.join(dir, ent.name);
      if (ent.isDirectory()) out.push(...listJs(p));
      else if (ent.name.endsWith('.js')) out.push(p);
    }
    return out;
  }

  // 「哪些脚本算 harness」不写字面量清单，而是按形状派生：
  // 设一次性 MONGODB_URI 且 require 即启动的 src/index.js。新写第四个脚本而忘了守卫，这里就红。
  const harnesses = listJs(SCRIPTS)
    .map((p) => [path.relative(SCRIPTS, p).split(path.sep).join('/'), fs.readFileSync(p, 'utf8')])
    .filter(([, src]) => /process\.env\.MONGODB_URI\s*=[^=]/.test(src) && BOOT_RE.test(src));

  test('前提自证：派生出的 harness 集合非空且含已知的三个', () => {
    expect(harnesses.length).toBeGreaterThanOrEqual(3);
    const names = harnesses.map(([f]) => f);
    for (const known of ['e2e-smoke.js', 'load-test.js', 'production-drill.js']) {
      expect(names).toContain(known);
    }
  });

  test('每个 harness 都在 require 启动之前置空 *_FILE', () => {
    for (const [file, src] of harnesses) {
      expect({ file, verdict: lateIsolation(src) }).toEqual({ file, verdict: null });
    }
  });

  test('减法自证：挪到 require 之后 / 整段删掉，判据都能点亮', () => {
    const [, real] = harnesses.find(([f]) => f === 'e2e-smoke.js');
    const lines = real.split(/\r?\n/);
    const callAt = lines.findIndex((l) => CALL_RE.test(l));
    const bootAt = lines.findIndex((l) => BOOT_RE.test(l));
    expect(callAt !== -1 && bootAt !== -1 && callAt < bootAt).toBe(true);

    const moved = [...lines];
    const [call] = moved.splice(callAt, 1);
    moved.splice(bootAt, 0, call);
    expect(lateIsolation(moved.join('\n'))).toBe('late');
    expect(
      lateIsolation(
        real
          .split('\n')
          .filter((_, i) => i !== callAt)
          .join('\n')
      )
    ).toBe('missing');
    // 形状判据本身也不能空转：不是 harness 的脚本必须被判成 not-a-harness
    expect(lateIsolation(fs.readFileSync(path.join(SCRIPTS, 'lint-ratchet.js'), 'utf8'))).toBe(
      'not-a-harness'
    );
  });
});
