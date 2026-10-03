/**
 * 一次性开发密钥隔离：宿主残留的 *_FILE 与明文密钥都不得接上 e2e / 压测 / 生产演练 harness
 * （scripts/devSecretIsolation.js 与 scripts/{e2e-smoke,load-test,production-drill}.js）
 *
 * 为什么值得一个专门闸：`src/config/index.js:10-11` 在 require 期就 hydrate，而冲突规则
 * 是**文件优先**（`src/config/secrets.js:134` 无条件 `process.env[name] = value`）。
 * 三个 harness 的形状是「先设一次性 env，再 require ../src/index.js」，所以只要宿主上
 * 还有 `*_FILE`，回填就会把一次性 `MONGODB_URI` 覆写成真实库连接串——**并且不报错**。
 * 后果不是冒烟变红，是**写**：`npm run test:e2e` 往生产/开发库播种管理员、建用户、发告警，
 * `npm run test:load` 往那个库打五相压测流量并写审计。
 *
 * 暴露面有两根**正交**的轴，两根都要钉（第一版只钉了指针那根，实测被打回）：
 *   轴 A 形态：`<NAME>_FILE` 指针（经 hydrate 覆写）与 `<NAME>` 明文值（直接被读取点读到）。
 *            `.env.example:2` 就明写「JWT_SECRET / AES_SECRET_KEY 等可以直接写在本文件
 *            （适合本地开发）」，所以明文是**被官方推荐的形态**，不是事故形态。
 *   轴 B 通道：宿主 shell export 与 `.env`（`src/config/index.js:6` 的 dotenv 在 hydrate 前一行）。
 * 三个来源臂各覆盖一格通道，且每个名字只承担一种形态，红的归因不含糊：
 *   export   ⇒ 指针 + 明文都走 process.env（干净 cwd，无 .env）
 *   dotenv   ⇒ 指针 + 明文都走 .env
 *   plain    ⇒ **只有明文**走 .env：这一臂是"只堵 *_FILE 的第一版"的靶子——
 *              它的 uri/jwt 本来就是一次性值，漏的只有 REDIS_URL / ADMIN_INITIAL_PASSWORD。
 * 九格真值表（3 臂 × 3 形态守卫）：
 *   none  × {export, dotenv, plain} ⇒ 全部接上真实值（前提自证：危害是真的，两条轴都是）
 *   blank × {export, dotenv, plain} ⇒ 全部置空（当前实现）
 *   del   × export                 ⇒ 挡住；del × {dotenv, plain} ⇒ 仍接回真实值
 * 第三行是防"有人觉得 delete 更干净"，而且它现在对**两类**都成立：
 * 把守卫改成 delete，dotenv 臂与 plain 臂立刻红。
 */

'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync, execFileSync } = require('child_process');

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
// 明文轴的两个名字：e2e-smoke / load-test 一个都不设（production-drill 只设 REDIS_URL，
// 且设在守卫之后）。宿主上只要有这两行明文，冒烟就直接连真 Redis、用真初始口令播种。
const PROD_REDIS = 'redis://real-redis-host:6379';
const PROD_ADMIN_PW = 'prod-admin-initial-password';

/** 指针轴用的三个名字（*_FILE）与明文轴用的两个名字：两轴的断言各自归位 */
const POINTER_NAMES = ['MONGODB_URI', 'JWT_SECRET', 'MONGO_ROOT_PASSWORD'];
const PLAIN_NAMES = ['REDIS_URL', 'ADMIN_INITIAL_PASSWORD'];

/** 子进程里跑的那段夹具：__MODE__ 决定守卫形态，cwd 决定密钥从哪来 */
const PROBE = [
  "const path = require('path');",
  `const REPO = ${JSON.stringify(ROOT)};`,
  'const mode = process.env.__MODE__;',
  'const NAMES = require(path.join(REPO, "src/config/secrets")).FILE_BACKED_SECRETS;',
  "if (mode === 'blank') {",
  "  require(path.join(REPO, 'scripts/devSecretIsolation.js'))",
  "    .isolateDisposableSecrets({ scriptName: 'probe' });",
  '} else if (mode === "del") {',
  '  for (const n of NAMES) {',
  '    delete process.env[n];',
  "    delete process.env[n + '_FILE'];",
  '  }',
  '}',
  `process.env.MONGODB_URI = ${JSON.stringify(DISPOSE_URI)};`,
  `process.env.JWT_SECRET = ${JSON.stringify(DISPOSE_JWT)};`,
  "const cfg = require(path.join(REPO, 'src/config/index.js'));",
  '// REDIS_URL / ADMIN_INITIAL_PASSWORD / MONGO_ROOT_PASSWORD 在 src/config 里没有字段：',
  '// 消费方直读 env（sharedCache.js:52、initData.js:770），所以 require 之后的 env 就是',
  '// 消费方看到的那一份。断言这一层不是降级，是这几个名字唯一的可观测面。',
  '// ?? null 是必须的：JSON.stringify 会**丢掉** undefined 键，那样 r.x 恒为 undefined，',
  '// "守卫挡住了"与"夹具压根没跑"就分不开——那正是一条空断言。',
  'console.log(JSON.stringify({',
  '  uri: cfg.mongodbUri,',
  '  jwt: cfg.jwt.secret,',
  '  uriFile: process.env.MONGODB_URI_FILE ?? null,',
  '  rootPw: process.env.MONGO_ROOT_PASSWORD ?? null,',
  '  redisUrl: process.env.REDIS_URL ?? null,',
  '  adminPw: process.env.ADMIN_INITIAL_PASSWORD ?? null,',
  '}));',
].join('\n');

let work;

/** 两类密钥一起写进同一个载体（.env 或进程环境），每个名字只走一种形态 */
function secretPair() {
  return {
    MONGODB_URI_FILE: path.join(work, 'mongodb_uri'),
    JWT_SECRET_FILE: path.join(work, 'jwt_secret'),
    MONGO_ROOT_PASSWORD_FILE: path.join(work, 'mongo_root_password'),
    REDIS_URL: PROD_REDIS,
    ADMIN_INITIAL_PASSWORD: PROD_ADMIN_PW,
  };
}

beforeAll(() => {
  work = fs.mkdtempSync(path.join(os.tmpdir(), 'fsms-isolation-'));
  fs.writeFileSync(path.join(work, 'mongodb_uri'), `${PROD_URI}\n`);
  fs.writeFileSync(path.join(work, 'jwt_secret'), PROD_JWT);
  fs.writeFileSync(path.join(work, 'mongo_root_password'), `${PROD_ROOT_PW}\n`);
  fs.writeFileSync(path.join(work, 'probe.js'), PROBE);
  // export 臂的 cwd：空目录 ⇒ dotenv 读不到 .env，来源只有 process.env
  fs.mkdirSync(path.join(work, 'clean-cwd'));
  // dotenv 臂的 cwd：宿主把 *_FILE 写进 .env（.env.example:12 的生产口径 b）
  fs.mkdirSync(path.join(work, 'dotenv-cwd'));
  fs.writeFileSync(
    path.join(work, 'dotenv-cwd', '.env'),
    POINTER_NAMES.map((n) => `${n}_FILE=${path.join(work, n.toLowerCase())}`).join('\n') +
      `\n${PLAIN_NAMES.map((n) => `${n}=${secretPair()[n]}`).join('\n')}\nNODE_ENV=development\n`
  );
  // plain 臂的 cwd：**.env 里只有明文密钥，一个 *_FILE 都没有**。这一臂单独存在是因为
  // 第一版守卫只处理 *_FILE：在这里 uri/jwt 天生就是安全的一次性值（没有指针可覆写），
  // 于是"全绿"完全可以和"真 Redis、真初始口令已被接上"同时成立。
  fs.mkdirSync(path.join(work, 'plain-cwd'));
  fs.writeFileSync(
    path.join(work, 'plain-cwd', '.env'),
    `${PLAIN_NAMES.map((n) => `${n}=${secretPair()[n]}`).join('\n')}\nNODE_ENV=development\n`
  );
});

afterAll(() => {
  if (work) fs.rmSync(work, { recursive: true, force: true });
});

/** 子进程环境：剥掉 jest worker 预置的密钥与 *_FILE，避免夹具继承本机状态 */
function childEnv(extra) {
  const env = { ...process.env };
  for (const name of FILE_BACKED_SECRETS) {
    delete env[name];
    delete env[`${name}_FILE`];
  }
  delete env.NODE_ENV;
  return { ...env, ...extra };
}

const SOURCE_CWD = { export: 'clean-cwd', dotenv: 'dotenv-cwd', plain: 'plain-cwd' };

function runProbe({ mode, source }) {
  const env = { __MODE__: mode };
  // export 臂：两类密钥都经宿主进程环境进来，且 cwd 里没有 .env 可回填
  if (source === 'export') Object.assign(env, secretPair());
  const r = spawnSync(process.execPath, [path.join(work, 'probe.js')], {
    cwd: path.join(work, SOURCE_CWD[source]),
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

const SOURCES = [
  ['export', '宿主 shell export（指针 + 明文）'],
  ['dotenv', '.env 里的 *_FILE 与明文'],
  ['plain', '.env 里只有明文（无 *_FILE）'],
];

/**
 * 每条臂"没有守卫时"应泄漏什么——按形态而非按臂统一：
 * plain 臂压根没有 *_FILE，所以指针轴（uri/jwt/rootPw）在这里本来就是安全的，
 * 它红的是明文轴。把两轴的期望写死成一张表，是为了让"这一臂没证到东西"
 * 变成可见的差异，而不是让 uniform 断言把臂与臂之间的差别抹平。
 */
const LEAKS = {
  export: {
    uri: PROD_URI,
    jwt: PROD_JWT,
    rootPw: PROD_ROOT_PW,
    redisUrl: PROD_REDIS,
    adminPw: PROD_ADMIN_PW,
  },
  dotenv: {
    uri: PROD_URI,
    jwt: PROD_JWT,
    rootPw: PROD_ROOT_PW,
    redisUrl: PROD_REDIS,
    adminPw: PROD_ADMIN_PW,
  },
  plain: {
    uri: DISPOSE_URI,
    jwt: DISPOSE_JWT,
    rootPw: null,
    redisUrl: PROD_REDIS,
    adminPw: PROD_ADMIN_PW,
  },
};

/** 指针轴的告警条目只有该臂真的配了 *_FILE 才该出现（plain 臂不能凭空点名） */
const POINTER_SOURCES = ['export', 'dotenv'];

describe('宿主残留密钥与一次性 harness 的隔离', () => {
  test.each(SOURCES)('前提自证：没有守卫时 %s 把真实值接进一次性进程', (_src, label) => {
    const r = runProbe({ mode: 'none', source: _src });
    const seen = {
      uri: r.uri,
      jwt: r.jwt,
      rootPw: r.rootPw,
      redisUrl: r.redisUrl,
      adminPw: r.adminPw,
    };
    // 三条臂都得红，否则本闸的另一半是在自证空气
    expect({ label, ...seen }).toEqual({ label, ...LEAKS[_src] });
    // 明文轴：守卫第一版只置空指针时，redisUrl/adminPw 在三条臂上都接得上真值，
    // 且一条都不报错。
    expect({ label, plainAxis: [seen.redisUrl, seen.adminPw] }).toEqual({
      label,
      plainAxis: [PROD_REDIS, PROD_ADMIN_PW],
    });
  });

  test('plain 臂的前提自证不含运气：它确实一个 *_FILE 都没配', () => {
    // 上面那条用 uri/jwt 在 plain 臂等于一次性值——如果 .env 里其实混进了 *_FILE，
    // 那句断言就退化成了"跟 dotenv 臂一样"，明文轴等于没单独证过。这里直接验夹具形状。
    const env = fs.readFileSync(path.join(work, 'plain-cwd', '.env'), 'utf8');
    expect(env).not.toMatch(/_FILE=/);
    expect(env).toContain(`REDIS_URL=${PROD_REDIS}`);
    expect(env).toContain(`ADMIN_INITIAL_PASSWORD=${PROD_ADMIN_PW}`);
  });

  test.each(SOURCES)('守卫（置空）挡住 %s', (_src, label) => {
    const r = runProbe({ mode: 'blank', source: _src });
    expect({ label, uri: r.uri, jwt: r.jwt, uriFile: r.uriFile }).toEqual({
      label,
      uri: DISPOSE_URI,
      jwt: DISPOSE_JWT,
      // 置空而不是删除：见下一条用例
      uriFile: '',
    });
    // 守卫只置空、绝不代做回填（回填正是它要防的动作；见 scriptSecretHydration 的豁免二）
    // rootPw 从第一版的 undefined 改成 ''：守卫现在主动置空了这个名字，
    // undefined 只能证"没 hydrate"，'' 才证"宿主明文也没接上"。
    expect({ label, rootPw: r.rootPw, redisUrl: r.redisUrl, adminPw: r.adminPw }).toEqual({
      label,
      rootPw: '',
      redisUrl: '',
      adminPw: '',
    });
    // 静默吞掉运维显式配置是另一种误导：两类都要点名
    expect(r.stderr).toContain('已置空');
    expect(r.stderr).toContain('REDIS_URL（明文值');
    expect(r.stderr).toContain('ADMIN_INITIAL_PASSWORD（明文值');
    for (const pointer of ['MONGODB_URI_FILE=', 'MONGO_ROOT_PASSWORD_FILE=']) {
      expect({ label, pointer, present: r.stderr.includes(pointer) }).toEqual({
        label,
        pointer,
        present: POINTER_SOURCES.includes(_src),
      });
    }
  });

  test('置空后真实读取点得到"宿主本来没配"的形态，不是空串陷阱', () => {
    // 置空的代价必须是零：这几个名字没有 config 字段，消费方直读 env，
    // 而它们的判据都把空串当假 ⇒ harness 落回进程内语义/随机口令，
    // 而不是"配置存在但为空"的第三种状态。判据写法一改（例如改成 `!== undefined`），
    // 置空就会变成"已配置一个空 Redis"，本用例当场点名。
    const sharedCache = fs.readFileSync(path.join(ROOT, 'src/services/sharedCache.js'), 'utf8');
    const redisCheck = sharedCache.match(/return \(process\.env\.REDIS_URL[^\n]*/)[0].trim();
    expect({ redisCheck }).toEqual({
      redisCheck: `return (process.env.REDIS_URL || '').trim() !== '';`,
    });
    const initData = fs.readFileSync(path.join(ROOT, 'src/services/initData.js'), 'utf8');
    expect({
      adminCheck: initData.match(/if \(process\.env\.ADMIN_INITIAL_PASSWORD\) \{/) !== null,
    }).toEqual({ adminCheck: true });
    // 判据本身有牙：合成一条 `!== undefined` 的改写形态，必须不被接受
    const undefForm = 'if (process.env.ADMIN_INITIAL_PASSWORD !== undefined) {';
    expect({
      undefForm,
      accepted: /if \(process\.env\.ADMIN_INITIAL_PASSWORD\) \{/.test(undefForm),
    }).toEqual({ undefForm, accepted: false });
  });

  test('delete 反证：只删 process.env 挡不住 .env 那两条路（所以实现必须置空）', () => {
    // dotenv 在 hydrate 的前一行（src/config/index.js:6 → :11）：键被 delete 后
    // dotenv 认为它"不存在"，又从句柄 cwd 的 .env 填回来。
    const viaDotenv = runProbe({ mode: 'del', source: 'dotenv' });
    expect(viaDotenv.uri).toBe(PROD_URI);
    // 同一条漏网不只覆写 harness 赋过值的键：它把指针轴与明文轴一起接回真实值
    expect(viaDotenv.rootPw).toBe(PROD_ROOT_PW);
    expect(viaDotenv.redisUrl).toBe(PROD_REDIS);
    const viaPlain = runProbe({ mode: 'del', source: 'plain' });
    expect(viaPlain.uri).toBe(DISPOSE_URI);
    expect({ plainDel: viaPlain.adminPw }).toEqual({ plainDel: PROD_ADMIN_PW });
    // export 臂则真的挡住了 ⇒ 差异只来自"删"与"空"，不是夹具本身没生效
    const viaExport = runProbe({ mode: 'del', source: 'export' });
    expect(viaExport.uri).toBe(DISPOSE_URI);
    expect({ exportDel: viaExport.redisUrl, exportDelAdmin: viaExport.adminPw }).toEqual({
      exportDel: null,
      exportDelAdmin: null,
    });
  });

  test('告警只打路径与名字，不把任何密钥内容带进输出', () => {
    const r = runProbe({ mode: 'blank', source: 'export' });
    expect(r.stderr).toContain(path.join(work, 'mongodb_uri'));
    for (const secret of [PROD_URI, PROD_JWT, PROD_ROOT_PW, PROD_REDIS, PROD_ADMIN_PW]) {
      expect(r.stderr).not.toContain(secret);
    }
    // 明文轴必须"点名不取值"：只列名字，值一个字符都不出现
    expect(r.stderr).toMatch(/ADMIN_INITIAL_PASSWORD（明文值[^\n]*）/);
  });

  test('减法自证：守卫只置空指针时，明文轴立刻漏且用例能抓到', () => {
    // 真文件做减法：把置空明文名字的那两行擦掉，探针必须看到真实值。
    // 少了这条，上面的明文断言有可能只是"实现碰巧对了"。
    const src = fs.readFileSync(path.join(ROOT, 'scripts/devSecretIsolation.js'), 'utf8');
    const stripped = src.replace(
      /^\s*if \(isSet\(process\.env\[name\]\)\)[\s\S]*?\n\s*process\.env\[name\] = '';\n/m,
      ''
    );
    expect(stripped).not.toBe(src);
    expect(stripped).not.toMatch(/process\.env\[name\] = ''/);
    expect(stripped).toMatch(/process\.env\[filePathVar\] = ''/);

    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fsms-isolation-mutant-'));
    const mutant = path.join(dir, 'devSecretIsolation.js');
    // 变异体落在临时目录，两处相对 require 必须换成绝对路径才解析得到。
    // 这只动模块解析、不动行为——下面对"擦掉了什么、留下了什么"的断言才是判据。
    const toAbs = (s) => s.replace(/\\/g, '/');
    const mutantSrc = stripped
      .replace(
        "require('../src/config/secrets')",
        `require(${JSON.stringify(toAbs(path.join(ROOT, 'src/config/secrets')))})`
      )
      .replace(
        "require('dotenv')",
        `require(${JSON.stringify(toAbs(path.join(ROOT, 'node_modules/dotenv')))})`
      );
    expect(mutantSrc).not.toContain("require('../src/config/secrets')");
    fs.writeFileSync(mutant, mutantSrc);
    // 变异体必须仍然是合法 JS：否则子进程是"崩了"而不是"漏了"，红得没有信息量
    expect(execFileSync(process.execPath, ['--check', mutant], { encoding: 'utf8' })).toBe('');
    try {
      const env = childEnv({
        ...secretPair(),
        __FS_MS_MUTANT__: mutant,
      });
      const r = spawnSync(process.execPath, ['-e', MUTANT_PROBE], {
        cwd: path.join(work, 'plain-cwd'),
        encoding: 'utf8',
        timeout: 60000,
        env,
      });
      expect({ rc: r.status, err: String(r.stderr).slice(0, 300) }).toMatchObject({ rc: 0 });
      // 变异体的告警仍然会打（指针条目带路径），但它绝不能把明文值带出去
      expect(String(r.stderr)).not.toContain(PROD_ADMIN_PW);
      const out = JSON.parse(String(r.stdout).trim().split(/\r?\n/).pop());
      // 明文轴漏：真值原样接上；指针轴仍然被挡住 ⇒ 红的是这一类，不是整个守卫失灵
      expect({ adminPw: out.adminPw, redisUrl: out.redisUrl }).toEqual({
        adminPw: PROD_ADMIN_PW,
        redisUrl: PROD_REDIS,
      });
      expect(out.uriFile).toBe('');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

/** 减法自证用的探针：与 PROBE 同形状，只是守卫从改写的副本加载 */
const MUTANT_PROBE = [
  "const path = require('path');",
  `const REPO = ${JSON.stringify(ROOT)};`,
  "require(process.env.__FS_MS_MUTANT__).isolateDisposableSecrets({ scriptName: 'mutant' });",
  "const cfg = require(path.join(REPO, 'src/config/index.js'));",
  'console.log(JSON.stringify({',
  '  uri: cfg.mongodbUri,',
  '  uriFile: process.env.MONGODB_URI_FILE ?? null,',
  '  redisUrl: process.env.REDIS_URL ?? null,',
  '  adminPw: process.env.ADMIN_INITIAL_PASSWORD ?? null,',
  '}));',
].join('\n');

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

  test('清单从 FILE_BACKED_SECRETS 派生：指针与明文两类全量置空，非密钥不动', () => {
    // 夹具本身来自 secrets.js 的导出，所以将来加第 16 个名字时这里自动覆盖两类：
    // 若守卫改成抄一份字面量，新名字的两类都不会被置空 ⇒ 本用例红（不需要另立静态闸）。
    expect(FILE_BACKED_SECRETS.length).toBeGreaterThanOrEqual(15);
    for (const name of FILE_BACKED_SECRETS) {
      process.env[`${name}_FILE`] = `/run/secrets/${name.toLowerCase()}`;
      process.env[name] = `plaintext-${name}`;
    }
    process.env.ZZ_NOT_A_SECRET_FILE = '/keep/me';
    process.env.ZZ_NOT_A_SECRET = '/keep/me2';

    const isolated = isolateDisposableSecrets({ scriptName: 'unit' });

    expect(isolated.map((i) => i.name).sort()).toEqual(
      [...FILE_BACKED_SECRETS, ...FILE_BACKED_SECRETS].sort()
    );
    expect(new Set(isolated.map((i) => i.kind))).toEqual(new Set(['file', 'plain']));
    for (const name of FILE_BACKED_SECRETS) {
      expect(process.env[`${name}_FILE`]).toBe('');
      expect(process.env[name]).toBe('');
    }
    expect(process.env.ZZ_NOT_A_SECRET_FILE).toBe('/keep/me');
    expect(process.env.ZZ_NOT_A_SECRET).toBe('/keep/me2');
    const text = warn.join('\n');
    expect(text).toContain(`检测到 ${FILE_BACKED_SECRETS.length} 个 *_FILE 注入项`);
    expect(text).toContain(`与 ${FILE_BACKED_SECRETS.length} 个明文密钥`);
    // 点名不取值：`plaintext-XXX` 是我们的夹具值，实现若把它打进告警就是泄漏
    for (const name of FILE_BACKED_SECRETS) {
      expect(text).not.toContain(`plaintext-${name}`);
    }
  });

  /**
   * 把两类键全部置空，构造"宿主本来干净"。
   * 用 `''` 而不是 delete 是**必须的**：本 describe 的 cwd 是仓库根，那里可能真有一个
   * 开发用 `.env`；delete 之后守卫内的 dotenv 会把它填回来，"干净"就成了看本机运气。
   * 这也正是实现选择置空而非删除的同一条理由（见上面的 delete 反证）。
   */
  function blankAllNames() {
    for (const name of FILE_BACKED_SECRETS) {
      process.env[`${name}_FILE`] = '';
      process.env[name] = '';
    }
  }

  test('幂等且宿主本来干净时不告警', () => {
    blankAllNames();
    const first = isolateDisposableSecrets({ scriptName: 'unit' });
    expect(first).toEqual([]);
    expect(warn).toEqual([]);
    const again = isolateDisposableSecrets({ scriptName: 'unit' });
    expect(again).toEqual([]);
    expect(warn).toEqual([]);
    // 且键仍在（空串），否则 dotenv 会把 .env 的值填回来——两类都是
    for (const name of FILE_BACKED_SECRETS) {
      expect(process.env[`${name}_FILE`]).toBe('');
      expect(process.env[name]).toBe('');
    }
  });

  test('返回值带上原路径，便于运维定位来源；明文条目不带值', () => {
    process.env.HMAC_SECRET_FILE = '/run/secrets/hmac_secret';
    process.env.SENTRY_DSN = 'https://real-public-key@real-ingest/0';
    const isolated = isolateDisposableSecrets({ scriptName: 'unit' });
    const hit = isolated.find((i) => i.name === 'HMAC_SECRET' && i.kind === 'file');
    expect(hit && hit.filePath).toBe('/run/secrets/hmac_secret');
    const plain = isolated.find((i) => i.name === 'SENTRY_DSN' && i.kind === 'plain');
    expect(plain).toBeDefined();
    expect(JSON.stringify(plain)).not.toContain('real-public-key');
  });

  test('只有空白值的 *_FILE 不进告警，但仍被置空（与 hydrate 的 :71 同判据）', () => {
    blankAllNames();
    process.env.JWT_SECRET_FILE = '   ';
    process.env.JWT_SECRET = '';
    const isolated = isolateDisposableSecrets({ scriptName: 'unit' });
    expect(isolated).toEqual([]);
    expect(warn).toEqual([]);
    expect(process.env.JWT_SECRET_FILE).toBe('');
    expect(process.env.JWT_SECRET).toBe('');
  });
});

describe('三个 harness 的接线（枚举派生自脚本本身）', () => {
  const SCRIPTS = path.join(ROOT, 'scripts');
  const CALL_RE = /^\s*isolateDisposableSecrets\s*\(/;
  const BOOT_RE = /require\('\.\.\/src\/index\.js'\)/;
  /**
   * harness 对任一密钥名（指针形态或明文形态）的赋值。守卫现在两类都置空，
   * 所以"赋值必须晚于守卫"从可选变成不变量：先赋值再调守卫会把一次性值擦掉。
   */
  const SECRET_ASSIGN_RE = new RegExp(
    String.raw`^\s*process\.env\s*[.[]\s*['"]?(?:${FILE_BACKED_SECRETS.join('|')})(?:_FILE)?` +
      String.raw`['"]?\s*\]?\s*=(?!=)`
  );
  /** 生成的子脚本片段（整行是字符串字面量）不是本进程的赋值，不得参与顺序判定 */
  const QUOTED_LINE_RE = /^\s*['"`]/;

  /**
   * 判据两件事：守卫调用必须**早于** require 到 src/index.js（hydrate 与 dotenv
   * 都发生在那一刻），也必须**早于**任何一次性密钥赋值（守卫两类都置空）。
   */
  function lateIsolation(src) {
    const lines = src.split(/\r?\n/);
    const callAt = lines.findIndex((l) => CALL_RE.test(l));
    const bootAt = lines.findIndex((l) => BOOT_RE.test(l));
    if (bootAt === -1) return 'not-a-harness';
    if (callAt === -1) return 'missing';
    if (callAt > bootAt) return 'late-boot';
    const assignAt = lines.findIndex((l) => SECRET_ASSIGN_RE.test(l) && !QUOTED_LINE_RE.test(l));
    if (assignAt !== -1 && assignAt < callAt) return 'late-assign';
    return null;
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

  test('每个 harness 都在 require 启动与任何密钥赋值之前置空宿主密钥', () => {
    for (const [file, src] of harnesses) {
      expect({ file, verdict: lateIsolation(src) }).toEqual({ file, verdict: null });
    }
    // 顺序判据必须真的有事可做：三个 harness 都得至少有一条赋值晚于守卫
    for (const [file, src] of harnesses) {
      const lines = src.split(/\r?\n/);
      const callAt = lines.findIndex((l) => CALL_RE.test(l));
      const assignAt = lines.findIndex((l) => SECRET_ASSIGN_RE.test(l) && !QUOTED_LINE_RE.test(l));
      expect({ file, assignAfterGuard: assignAt > callAt && assignAt !== -1 }).toEqual({
        file,
        assignAfterGuard: true,
      });
    }
  });

  test('赋值顺序判据本身不空转：非密钥赋值与字符串行都不算', () => {
    const guardFirst = ["isolateDisposableSecrets({ scriptName: 'x' });", ''].join('\n');
    const boot = "require('../src/index.js');";
    expect(lateIsolation(`${guardFirst}${boot}\nprocess.env.LOG_LEVEL = 'error';\n`)).toBeNull();
    // 生成的子脚本里那句 `process.env.JWT_SECRET = …` 整行是字符串：它不是本进程的赋值
    expect(lateIsolation(`${guardFirst}${boot}\n  "process.env.JWT_SECRET = 'x';",\n`)).toBeNull();
    // 真赋值提到守卫之前 ⇒ 必须点名（证明这条不是靠"永远放行"过审的）
    expect(lateIsolation(`process.env.JWT_SECRET = 'x';\n${guardFirst}${boot}\n`)).toBe(
      'late-assign'
    );
    // 指针形态同样在判据内（守卫两类都置空）
    expect(
      lateIsolation(`process.env.MONGODB_URI_FILE = '/run/secrets/x';\n${guardFirst}${boot}\n`)
    ).toBe('late-assign');
  });

  test('减法自证：挪到 require 之后 / 整段删掉 / 挪到赋值之后，判据都能点亮', () => {
    const [, real] = harnesses.find(([f]) => f === 'e2e-smoke.js');
    const lines = real.split(/\r?\n/);
    const callAt = lines.findIndex((l) => CALL_RE.test(l));
    const bootAt = lines.findIndex((l) => BOOT_RE.test(l));
    const assignAt = lines.findIndex((l) => SECRET_ASSIGN_RE.test(l) && !QUOTED_LINE_RE.test(l));
    expect(callAt !== -1 && bootAt !== -1 && assignAt !== -1).toBe(true);
    expect(callAt < bootAt && callAt < assignAt).toBe(true);

    const moved = [...lines];
    const [call] = moved.splice(callAt, 1);
    moved.splice(bootAt, 0, call);
    expect(lateIsolation(moved.join('\n'))).toBe('late-boot');
    expect(
      lateIsolation(
        real
          .split('\n')
          .filter((_, i) => i !== callAt)
          .join('\n')
      )
    ).toBe('missing');
    // 守卫落到赋值之后：一次性密钥先被写好、再被守卫擦掉
    const afterAssign = [...lines];
    const [g] = afterAssign.splice(callAt, 1);
    afterAssign.splice(assignAt + 1, 0, g);
    expect(lateIsolation(afterAssign.join('\n'))).toBe('late-assign');
    // 形状判据本身也不能空转：不是 harness 的脚本必须被判成 not-a-harness
    expect(lateIsolation(fs.readFileSync(path.join(SCRIPTS, 'lint-ratchet.js'), 'utf8'))).toBe(
      'not-a-harness'
    );
  });
});
