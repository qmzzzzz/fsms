/**
 * 部署脚本副作用层（main）端到端行为回归：**真跑脚本**，观测它实际发起的命令序列
 *
 * 为什么还要测一遍（deployScript.test.js 已测纯逻辑）：
 *   已实证的假绿窗口——buildPlan() 只用于**打印计划**，main() 里的调用顺序是另一份
 *   硬编码的代码。把「切换容器」提到「应用迁移」之前（真实危险：新代码依赖新索引，
 *   先切后迁会 500），旧的 21 例**全绿**——因为它们只读 buildPlan() 的声明。
 *   本套件直接观测脚本实际发起的命令，把那层硬编码顺序也锁住。
 *
 * 怎么测：用 --require 预加载 helpers/stubExec.js 接管 child_process，以真实
 * 子进程跑 scripts/deploy.js，把每条对外命令记到日志，再对日志断言顺序/失败分支/
 * 退出码。生产代码未因测试动一行，脚本自身也不知道命令被接管了。
 *
 * 隔离：密钥目录指向临时目录（仓库 secrets/ 是 gitignore 的，CI 上不存在；
 * 测试既不向仓库写密钥，也不依赖本机是否恰好生成过）。
 */
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const ROOT = path.resolve(__dirname, '../../..');
const SCRIPT = path.join(ROOT, 'scripts', 'deploy.js');
const HOOK = path.join(__dirname, 'helpers', 'stubExec.js');
const NODE = process.execPath;
const SECRET_NAMES = require('../../../scripts/deploy').REQUIRED_SECRET_FILES;

const staged = [];
afterAll(() => {
  for (const dir of staged) fs.rmSync(dir, { recursive: true, force: true });
});

/** 一次部署演练的隔离环境：临时密钥目录 + 命令日志 */
function makeStage() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'deployrun-'));
  const secrets = path.join(dir, 'secrets');
  fs.mkdirSync(secrets);
  for (const n of SECRET_NAMES) {
    const v = n === 'mongodb_uri' ? 'mongodb://127.0.0.1:27017/x\n' : `v-${n}\n`;
    fs.writeFileSync(path.join(secrets, n), v);
  }
  staged.push(dir);
  return { dir, secrets, log: path.join(dir, 'cmd.log'), rules: ['*||0'] };
}

/**
 * 跑一次部署脚本（真子进程）。
 * @param {object} o
 * @param {string} [o.readyz] 健康探针固定返回码（默认 200）
 * @param {boolean} [o.noPrevious] true 时模拟「首次部署」：docker compose ps -q app 无输出
 * @param {string[]} [o.failOn] 命令前缀列表：命中则该命令非零退出
 * @param {string[]} [o.args] 额外命令行参数
 */
function runDeploy({
  readyz = '200',
  readyzSeq = null,
  noPrevious = false,
  failOn = [],
  failExact = false,
  healthTimeoutMs = '400',
  args = [],
} = {}) {
  const stage = makeStage();
  const compose = 'docker compose -f ' + path.join(ROOT, 'docker-compose.yml');
  // 规则按顺序匹配、先命中先返回；具体前缀一律排在 `*` 兜底之前。
  stage.rules = [
    // ① 指定的失败命令（前缀命中即非零退出）
    ...failOn.map((f) => `${f}||1`),
    // ② 健康探针：固定码或逐次变化的序列
    `curl|${readyzSeq ? '@seq:' + readyzSeq.join(',') : readyz}|0`,
    // ③ 回滚目标：inspect 返回上一版本镜像（非空才会触发回滚）
    `docker inspect|ghcr.io/qmzzzzz/fsms:sha-previous|0`,
    // ④ ps -q app：默认返回一个容器 ID；noPrevious 时返回空（=首次部署）
    `${compose} ps -q app|${noPrevious ? '' : 'fake-container-id'}|0`,
    // ⑤ 兜底：其余命令一律成功、空输出
    '*||0',
  ];
  const env = {
    ...process.env,
    // 正斜杠：NODE_OPTIONS 内的反斜杠会被 Node 当转义字符吃掉（实测：直接拼路径会 MODULE_NOT_FOUND）
    NODE_OPTIONS: `--require "${HOOK.replace(/\\/g, '/')}"`,
    STUB_LOG: stage.log,
    STUB_RESPONSES: stage.rules.join('\n'),
    STUB_SECRETS_DIR: stage.secrets,
  };
  env.APP_IMAGE = 'ghcr.io/qmzzzzz/fsms:sha-abc1234';
  env.CORS_ORIGIN = 'https://admin.example.com';
  env.DEPLOY_HEALTH_TIMEOUT_MS = healthTimeoutMs;
  // 回滚后复检也要短：否则失败路径会真等 60 秒（测试挂死）
  env.DEPLOY_ROLLBACK_TIMEOUT_MS = '400';
  if (failExact) {
    // 精确失败：只让 `migrate-mongo up` 非零退出，拉取/其余命令照常成功
    const composePrefix = 'docker compose -f ' + path.join(ROOT, 'docker-compose.yml');
    stage.rules = [
      `${composePrefix} run --rm --no-deps app node node_modules/.bin/migrate-mongo up||1`,
      ...stage.rules,
    ];
    env.STUB_RESPONSES = stage.rules.join('\n');
  }
  const r = spawnSync(NODE, [SCRIPT, ...args], { cwd: ROOT, env, encoding: 'utf8' });
  const log = fs.existsSync(stage.log) ? fs.readFileSync(stage.log, 'utf8') : '';
  return {
    code: r.status,
    stdout: r.stdout || '',
    stderr: r.stderr || '',
    lines: log.split(/\r?\n/).filter(Boolean),
  };
}

const idx = (lines, needle) => lines.findIndex((l) => l.includes(needle));
const count = (lines, needle) => lines.filter((l) => l.includes(needle)).length;

describe('D-1 部署脚本实际发起的命令序列（端到端观测）', () => {
  test('成功路径顺序：备份 → pull → migrate status → migrate up → 切换，退出码 0', () => {
    const r = runDeploy();
    expect(r.code).toBe(0);

    const iBackup = idx(r.lines, 'backup-mongo.sh');
    const iPull = idx(r.lines, 'pull app');
    const iStatus = idx(r.lines, 'migrate-mongo status');
    const iUp = idx(r.lines, 'migrate-mongo up');
    const iSwitch = idx(r.lines, 'up -d --no-build app');
    for (const [name, v] of [
      ['备份', iBackup],
      ['拉取镜像', iPull],
      ['迁移位点', iStatus],
      ['应用迁移', iUp],
      ['切换容器', iSwitch],
    ]) {
      expect({ name, found: v >= 0 }).toMatchObject({ name, found: true });
    }
    expect(iBackup).toBeLessThan(iPull);
    expect(iPull).toBeLessThan(iUp);
    expect(iStatus).toBeLessThan(iUp);
    // 这条是旧测试拦不住的：迁移必须在切换之前
    expect(iUp).toBeLessThan(iSwitch);
  });

  test('回滚目标必须在切换之前读取（inspect 早于 up -d）', () => {
    const r = runDeploy();
    expect(idx(r.lines, 'inspect --format={{.Config.Image}}')).toBeGreaterThan(-1);
    expect(idx(r.lines, 'inspect --format={{.Config.Image}}')).toBeLessThan(
      idx(r.lines, 'up -d --no-build app')
    );
  });

  test('备份失败 → 立即中止：不拉镜像、不迁移、不切换，退出码 1', () => {
    const r = runDeploy({ failOn: ['bash '] });
    expect(r.code).toBe(1);
    expect(count(r.lines, 'backup-mongo.sh')).toBe(1);
    expect(count(r.lines, 'pull app')).toBe(0);
    expect(count(r.lines, 'migrate-mongo')).toBe(0);
    expect(count(r.lines, 'up -d --no-build app')).toBe(0);
  });

  test('应用迁移失败 → 不切换容器（线上保持原版本），退出码 1', () => {
    // 只用 failExact（精确命中迁移那一条）：若再用宽前缀 failOn，会连 pull 一起失败，
    // 就测不到「迁移失败」这一分支了（实测旧写法即如此）。
    const r = runDeploy({ failExact: true });
    expect(r.code).toBe(1);
    expect(count(r.lines, 'migrate-mongo up')).toBe(1);
    expect(count(r.lines, 'up -d --no-build app')).toBe(0);
  });

  test('健康门禁未通过 + 有上一版本 → 自动以旧镜像再次 up -d 回滚', () => {
    const r = runDeploy({ readyz: '503' });
    expect(r.code).toBe(1);
    // 回滚动作 = 第二次 up -d（第一次是发布切换）
    expect(count(r.lines, 'up -d --no-build app')).toBe(2);
    expect(r.stdout).toContain('切回上一镜像');
  });

  test('首次部署（无上一版本）+ 健康失败 → 不回滚，但仍以退出码 1 收口', () => {
    const r = runDeploy({ readyz: '503', noPrevious: true });
    expect(r.code).toBe(1);
    expect(count(r.lines, 'up -d --no-build app')).toBe(1);
    expect(r.stdout).toContain('需人工介入');
  });

  test('--no-rollback 时健康失败也不回滚（尊重显式选择）', () => {
    const r = runDeploy({ readyz: '503', args: ['--no-rollback'] });
    expect(r.code).toBe(1);
    expect(count(r.lines, 'up -d --no-build app')).toBe(1);
  });

  test('--skip-backup 时不调用备份脚本（且其余步骤照常）', () => {
    const r = runDeploy({ args: ['--skip-backup'] });
    expect(r.code).toBe(0);
    expect(count(r.lines, 'backup-mongo.sh')).toBe(0);
    expect(count(r.lines, 'migrate-mongo up')).toBe(1);
    expect(count(r.lines, 'up -d --no-build app')).toBe(1);
  });

  test('脚本真的把 .env 读进来了（拦截 dotenv.config，观测它的实际调用与后果）', () => {
    // 为什么不能只 grep 源码：`require('dotenv').config(...)` 写在源码里不等于生效——
    // 写进 if(false)、被后面的直接赋值取代、或 path 指向别处，grep 都照样命中。
    // 此处直接接管 dotenv 模块：记录 deploy.js 实际传入的 path，并把读取重定向到
    // 临时 .env——若前置校验能靠那份临时内容通过，就证明「加载 → 生效」这条链真的接上了。
    const stage = makeStage();
    const tempEnv = path.join(stage.dir, 'temp.env');
    fs.writeFileSync(
      tempEnv,
      [
        'APP_IMAGE=ghcr.io/qmzzzzz/fsms:sha-fromdotenv',
        'CORS_ORIGIN=https://from-dotenv.example.com',
      ].join('\n')
    );
    const preload = path.join(stage.dir, 'dotenvSpy.js');
    fs.writeFileSync(
      preload,
      [
        `const fs = require('fs');`,
        `const path = require('path');`,
        `const realDotenv = require(${JSON.stringify(path.join(ROOT, 'node_modules/dotenv'))});`,
        `const record = ${JSON.stringify(path.join(stage.dir, 'dotenv-path.log'))};`,
        `const TEMP = ${JSON.stringify(tempEnv.replace(/\\/g, '/'))};`,
        `const realConfig = realDotenv.config;`,
        `realDotenv.config = (opts = {}) => {`,
        `  fs.appendFileSync(record, String((opts && opts.path) || '<no-path>') + '\\n');`,
        `  // 用临时内容替代真实 .env，但保留调用方传入的 path 作为证据`,
        `  return realConfig.call(realDotenv, { ...opts, path: TEMP, quiet: true });`,
        `};`,
        `module.exports = {};`,
      ].join('\n')
    );
    const compose = 'docker compose -f ' + path.join(ROOT, 'docker-compose.yml');
    const env = {
      ...process.env,
      NODE_OPTIONS: `--require "${preload.replace(/\\/g, '/')}" --require "${HOOK.replace(/\\/g, '/')}"`,
      STUB_LOG: stage.log,
      STUB_RESPONSES: [
        'curl|200|0',
        `docker inspect|ghcr.io/qmzzzzz/fsms:sha-previous|0`,
        `${compose} ps -q app|fake-id|0`,
        '*||0',
      ].join('\n'),
      STUB_SECRETS_DIR: stage.secrets,
    };
    // 清掉父进程传来的值：使「通过前置校验」只能靠临时 .env
    delete env.APP_IMAGE;
    delete env.CORS_ORIGIN;
    delete env.DEPLOY_HEALTH_TIMEOUT_MS;
    delete env.DEPLOY_ROLLBACK_TIMEOUT_MS;
    const r = spawnSync(NODE, [SCRIPT, '--dry-run'], { cwd: ROOT, env, encoding: 'utf8' });

    // ① 实际调用证据：dotenv.config 被调用，且 path 指向仓库根 .env
    const recorded = fs.readFileSync(path.join(stage.dir, 'dotenv-path.log'), 'utf8');
    expect(recorded.trim().split(/\r?\n/)).toContain(path.join(ROOT, '.env'));

    // ② 后果证据：前置校验真的通过了（子进程里除临时 .env 外无任何来源）
    expect({
      code: r.status,
      tail: (r.stdout || '').split('\n').slice(-3).join('|'),
    }).toMatchObject({
      code: 0,
    });
    expect(r.stdout).toContain('前置条件校验通过');
  });

  test('健康探针先失败后成功 → 属于正常发布（不得误判为失败）', () => {
    // 轮询间隔固定 2s：超时若缩到 400ms 则只能探一次，序列永远走不到 200
    // （实测：旧写法因此误判为失败）。这里给 5s，足以容纳 3 次探测。
    const r = runDeploy({
      readyz: '200',
      readyzSeq: ['503', '503', '200'],
      healthTimeoutMs: '5000',
    });
    expect(r.code).toBe(0);
    expect(count(r.lines, 'up -d --no-build app')).toBe(1);
  });
});
