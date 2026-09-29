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
const SECRET_NAMES = require('../../../scripts/deployPolicy').REQUIRED_SECRET_FILES;

/** 本次要发布的目标镜像引用（env.APP_IMAGE）。 */
const TARGET_IMAGE = 'ghcr.io/qmzzzzz/fsms:sha-abc1234';
/** inspect 默认返回的「当前运行中的上一版本」引用：与 TARGET_IMAGE 不同串 = 正常可回滚场景。 */
const PREVIOUS_IMAGE = 'ghcr.io/qmzzzzz/fsms:sha-previous';

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
  // 告警接收端：preflight 现在会校验"webhook 是否已注入"（Top-2），而仓库里那份
  // deployment/observability/alertmanager.yml 是**占位模板**（仓库必须保持占位，
  // 真实 access_token 不入库）。故这里造一份"已注入"的配置并让脚本读它——
  // 与 ALLOWED_HOSTS 同理：不补这一项，本套件全部用例会卡在退出码 2
  // （那正是"早于任何变更就拒绝"的证据，但不是本套件要测的命令序列）。
  const alertmanager = path.join(dir, 'alertmanager.yml');
  fs.writeFileSync(
    alertmanager,
    [
      'receivers:',
      '  - name: ops-critical',
      '    webhook_configs:',
      "      - url: 'https://oapi.dingtalk.com/robot/send?access_token=0f1e2d3c4b5a6978'",
      '  - name: ops-warning',
      '    webhook_configs:',
      "      - url: 'https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=0f1e2d3c4b5a6978'",
      '',
    ].join('\n')
  );
  staged.push(dir);
  return { dir, secrets, alertmanager, log: path.join(dir, 'cmd.log'), rules: ['*||0'] };
}

/**
 * stubExec 的规则表（先命中先返回；具体前缀一律排在 `*` 兜底之前）。
 * 单独成函数：runDeploy 的分支密度已在 eslint complexity 上限（15）上，
 * 再加一个默认参数就会棘轮回退——判据抽出来既降密度，也让「规则顺序」这件事只有一处。
 */
function buildRules({ readyz, readyzSeq, noPrevious, previousImage, failOn, compose }) {
  return [
    // ① 指定的失败命令（前缀命中即非零退出）
    ...failOn.map((f) => `${f}||1`),
    // ② 健康探针：固定码或逐次变化的序列
    `curl|${readyzSeq ? '@seq:' + readyzSeq.join(',') : readyz}|0`,
    // ③ 回滚目标：inspect 返回上一版本镜像（非空才会触发回滚）
    `docker inspect|${previousImage}|0`,
    // ④ ps -q app：默认返回一个容器 ID；noPrevious 时返回空（=首次部署）
    `${compose} ps -q app|${noPrevious ? '' : 'fake-container-id'}|0`,
    // ⑤ 兜底：其余命令一律成功、空输出
    '*||0',
  ];
}

/**
 * 跑一次部署脚本（真子进程）。
 * @param {object} o
 * @param {string} [o.readyz] 健康探针固定返回码（默认 200）
 * @param {boolean} [o.noPrevious] true 时模拟「首次部署」：docker compose ps -q app 无输出
 * @param {string[]} [o.failOn] 命令前缀列表：命中则该命令非零退出
 * @param {string} [o.previousImage] `docker inspect` 返回的当前镜像引用；传 TARGET_IMAGE
 *   即模拟「按可变标签发布」——回滚目标与目标同引用
 * @param {string[]} [o.args] 额外命令行参数
 */
function runDeploy({
  readyz = '200',
  readyzSeq = null,
  noPrevious = false,
  previousImage = PREVIOUS_IMAGE,
  failOn = [],
  failExact = false,
  healthTimeoutMs = '400',
  args = [],
} = {}) {
  const stage = makeStage();
  const compose = 'docker compose -f ' + path.join(ROOT, 'docker-compose.yml');
  stage.rules = buildRules({
    readyz,
    readyzSeq,
    noPrevious,
    previousImage,
    failOn,
    compose,
  });
  const env = {
    ...process.env,
    // 正斜杠：NODE_OPTIONS 内的反斜杠会被 Node 当转义字符吃掉（实测：直接拼路径会 MODULE_NOT_FOUND）
    NODE_OPTIONS: `--require "${HOOK.replace(/\\/g, '/')}"`,
    STUB_LOG: stage.log,
    STUB_RESPONSES: stage.rules.join('\n'),
    STUB_SECRETS_DIR: stage.secrets,
  };
  env.APP_IMAGE = TARGET_IMAGE;
  env.CORS_ORIGIN = 'https://admin.example.com';
  // compose 里同为 `:?` 硬声明项，preflight 现在会一起校验，不补这一行会让
  // 本套件全部用例卡在退出码 2（那正是「早于任何变更就拒绝」的证据，但不是被测路径）
  env.ALLOWED_HOSTS = 'fsms.example.com';
  // 告警接收端指向本 stage 里那份"已注入"的配置（理由见 makeStage）
  env.ALERTMANAGER_CONFIG_PATH = stage.alertmanager;
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
/** 容器切换那条命令的完整前缀（要精确失败切换、不误伤回滚之外的步骤） */
const SWITCH_CMD = `docker compose -f ${path.join(ROOT, 'docker-compose.yml')} up -d --no-build app`;

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
    // 回滚只切镜像、不切 schema：此刻库已被迁移改写。走 stderr（失败路径判据
    // 一律与变更日志分流），不打印出来操作员会以为「✓ 回滚后服务就绪」= 回到发布前状态。
    expect(r.stderr).toContain('回滚只切镜像');
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

  test('--skip-backup + 健康失败 → 拒绝自动回滚（无备份即无回滚资格）', () => {
    // 修复前这里是**第二次 up -d**：脚本自己头注释写着「没有备份的发布不具备回滚资格」，
    // 但 --skip-backup 完全不参与回滚决策。于是最危险的组合被自动放行——
    // 迁移已改写数据库 + 一份备份都没有 + 把镜像切回旧版本 ⇒
    // 旧版本在没有退路的新 schema 上续写，写坏了连现场都取不回来。
    const r = runDeploy({ readyz: '503', args: ['--skip-backup'] });
    expect(r.code).toBe(1);
    // 只有一次 up -d = 只做了发布切换，没有回滚
    expect(count(r.lines, 'up -d --no-build app')).toBe(1);
    expect(count(r.lines, 'backup-mongo.sh')).toBe(0);
    expect(r.stdout).toContain('不具备回滚资格');
    // 拒绝必须带可执行的前置动作，而不是只说「需人工介入」
    expect(r.stdout).toContain('backup-mongo.sh');
  });

  test('回滚目标与目标镜像同引用（:latest 这类可变标签）→ 不执行空操作回滚，且切换前就说明', () => {
    // 回滚的动作 = `up -d` 用 previousImage 这个**引用**再拉一次容器。按可变标签发布时
    // previousImage 与 APP_IMAGE 同串 ⇒ 解析到同一个构建 ⇒ "回滚"什么都没换回来。
    // 两种收场都坏：容器照旧不健康 → 退出 1（看不出是空操作）；
    // 容器被重启后健康 → 打印「✓ 回滚后服务就绪」，操作员以为已退回旧版本，
    // 而线上跑的仍是刚把这个库迁移坏的那个版本。现在两处都必须拒。
    const r = runDeploy({ readyz: '503', previousImage: TARGET_IMAGE });
    expect(r.code).toBe(1);
    // 只有一次 up -d = 只做了发布切换，没有那次空操作回滚
    // （对照上面「有上一版本 → 自动回滚」用例的 2 次：引用不同才回滚，正向控制即那条）
    expect(count(r.lines, 'up -d --no-build app')).toBe(1);
    // ① 提前说破：此时迁移还没跑，还有「换个带版本的 tag 重发」的选择
    expect(r.stderr).toContain('不具备版本级回滚能力');
    // ② 决策理由与提前告警同源（同一判据），并给出可执行的替代动作
    expect(r.stdout).toContain('回滚决策');
    expect(r.stdout).toContain('回滚目标与本次目标镜像引用相同');
    expect(r.stdout).toContain('digest');
    // ③ 走了拒绝分支，就不该再出现回滚执行过程的打印
    expect(r.stdout).not.toContain('切回上一镜像');
  });

  test('超时配置写成 120s → 退出码 2 且不发起任何对外命令', () => {
    // 修复前：Number('120s')=NaN ⇒ 健康门禁一次都不探测 ⇒ 判为失败 ⇒
    // 对一个**完全健康**的版本发起回滚（实测 readyz=200 也照回）。
    // 现在必须在任何副作用之前拒掉：命令日志必须为空。
    const r = runDeploy({ healthTimeoutMs: '120s' });
    expect(r.code).toBe(2);
    expect(r.stderr).toContain('DEPLOY_HEALTH_TIMEOUT_MS');
    expect(r.lines.length).toBe(0);
    // 双保险：不依赖日志文件是否被创建
    expect(count(r.lines, 'up -d --no-build app')).toBe(0);
  });

  test('容器切换失败 → 说明「迁移已执行、版本未切换」的此刻状态', () => {
    // 该分支在 migrate-up 之后，且不进回滚决策（容器没切，线上仍是旧版本 + 新 schema）。
    // 不打印状态，操作员会以为「切换失败 = 什么都没发生」。
    const r = runDeploy({ failOn: [SWITCH_CMD] });
    expect(r.code).toBe(1);
    expect(count(r.lines, 'migrate-mongo up')).toBe(1);
    expect(count(r.lines, SWITCH_CMD)).toBe(1);
    expect(r.stderr).toContain('迁移已执行、容器未切换');
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
        'ALLOWED_HOSTS=from-dotenv.example.com',
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
        `docker inspect|${PREVIOUS_IMAGE}|0`,
        `${compose} ps -q app|fake-id|0`,
        '*||0',
      ].join('\n'),
      STUB_SECRETS_DIR: stage.secrets,
      // 与 runDeploy 同口径：preflight 会校验「告警接收端是否已注入」（Top-2），
      // 缺省退回仓库占位模板 ⇒ 前置校验拒绝（退出码 2，本用例曾因此假红）。
      // 指向本 stage 那份"已注入"的 alertmanager 配置后，前置校验的通过就只能
      // 依赖临时 .env 的三个变量——正是本用例要证明的链路。
      ALERTMANAGER_CONFIG_PATH: stage.alertmanager,
    };
    // 清掉父进程传来的值：使「通过前置校验」只能靠临时 .env
    delete env.APP_IMAGE;
    delete env.CORS_ORIGIN;
    delete env.ALLOWED_HOSTS;
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
