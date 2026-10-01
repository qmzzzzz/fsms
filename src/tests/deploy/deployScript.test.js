/**
 * 部署自动化（D-1）回归
 *
 * 被测对象：scripts/deployPolicy.js（部署判据层；原先与执行层挤在 scripts/deploy.js，
 * 因体积棘轮 max-lines=300 触顶而按「判据 / 执行」边界切分）
 *
 * 为什么要测一个「运维脚本」：
 *   部署脚本的失效形态最恶劣——它**只在最紧张的时刻执行**（上线窗口），
 *   且一旦判断错就是「带着问题的版本留在线上」或「该回滚时没回滚」。
 *   而这些判据全部是纯逻辑（该不该拒绝、该不该回滚、步骤顺序对不对），
 *   完全可以在毫秒级断言清楚，不必真的去跑 docker。
 *
 * 因此本套件只测纯逻辑层（validatePreflight / buildPlan / decideRollback）——
 * 它们被刻意做成无副作用的纯函数正是为了可测。
 * 端到端的 compose 行为由 deployment/rollback-drill.md 的演练流程覆盖。
 */

const path = require('path');
const {
  ROOT,
  REQUIRED_SECRET_FILES,
  REQUIRED_COMPOSE_ENV,
  validatePreflight,
  checkAlertingEndpoint,
  buildPlan,
  isSameImageRef,
  decideRollback,
  parseArgs,
} = require('../../../scripts/deployPolicy');

/** 构造一个「全部合法」的环境，供各用例按需覆盖单项 */
const validEnv = () => ({
  APP_IMAGE: 'ghcr.io/qmzzzzz/fsms:sha-abc1234',
  CORS_ORIGIN: 'https://admin.example.com',
  // 与 CORS_ORIGIN 同为 compose 的 `:?` 硬声明项，缺一即 compose 拒绝整个项目
  ALLOWED_HOSTS: 'fsms.example.com',
});

/** 内存文件系统替身：只实现 validatePreflight 用到的方法 */
const fakeFs = (files) => {
  const map = new Map(Object.entries(files));
  return {
    existsSync: (p) => map.has(p),
    readFileSync: (p) => {
      if (!map.has(p)) throw new Error(`ENOENT: ${p}`);
      return map.get(p);
    },
  };
};

/** 生成一套完整的密钥文件路径映射（值非空，即「合法」状态） */
const fullSecrets = (rootOverride) => {
  const root = rootOverride || require('path').join(__dirname, '..', '..', '..');
  const secretsDir = path.join(root, 'secrets');
  const out = { [secretsDir]: '' };
  for (const name of REQUIRED_SECRET_FILES) {
    out[path.join(secretsDir, name)] = `value-of-${name}\n`;
  }
  return out;
};

/** compose 实际挂载的那个告警配置文件路径（docker-compose.yml 的 :258 行） */
const AM_PATH = path.join(ROOT, 'deployment', 'observability', 'alertmanager.yml');

/** 一份「已注入真实通道」的告警配置（无占位、全 https） */
const configuredAlertmanager = () =>
  [
    'receivers:',
    '  - name: ops-critical',
    '    webhook_configs:',
    "      - url: 'https://oapi.dingtalk.com/robot/send?access_token=0f1e2d3c4b5a6978'",
    '        send_resolved: true',
    '  - name: ops-warning',
    '    webhook_configs:',
    "      - url: 'https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=0f1e2d3c4b5a6978'",
    '',
  ].join('\n');

/** 一份仍是占位形态的告警配置（= 仓库模板的形态） */
const placeholderAlertmanager = () =>
  [
    'receivers:',
    '  - name: ops-critical',
    '    webhook_configs:',
    "      - url: 'https://hooks.example.com/<替换为critical通知通道access_token>'",
    '',
  ].join('\n');

/** 「全部合法」的文件系统替身：密钥齐全 + 告警通道已注入 */
const okFs = () => fakeFs({ ...fullSecrets(), [AM_PATH]: configuredAlertmanager() });

describe('D-1 部署前置校验：fail-closed', () => {
  test('全部条件满足时放行', () => {
    const r = validatePreflight(validEnv(), okFs());
    expect(r).toEqual({ ok: true, errors: [], warnings: [] });
  });

  test('APP_IMAGE 缺失即拒绝（不去猜镜像）', () => {
    const env = validEnv();
    delete env.APP_IMAGE;
    const r = validatePreflight(env, fakeFs(fullSecrets()));
    expect(r.ok).toBe(false);
    expect(r.errors.join('\n')).toContain('APP_IMAGE 未设置');
  });

  test('APP_IMAGE 为本地开发默认值时拒绝（防止把未版本化构建推上生产）', () => {
    // 这是最隐蔽的一种「有值但不可用」：compose 的默认值恰好是这个字符串，
    // 直接照抄会得到「部署成功但线上是 local tag」——无法回答跑的是哪个 commit。
    const env = { ...validEnv(), APP_IMAGE: 'fire-safety-app:local' };
    const r = validatePreflight(env, fakeFs(fullSecrets()));
    expect(r.ok).toBe(false);
    expect(r.errors.join('\n')).toContain('本地开发默认值');
  });

  test('密钥目录整体缺失即拒绝，并给出生成命令', () => {
    const r = validatePreflight(validEnv(), fakeFs({}));
    expect(r.ok).toBe(false);
    expect(r.errors.join('\n')).toContain('generate-secrets.js');
  });

  test('缺任何一个密钥文件都拒绝，且逐个点名', () => {
    const files = fullSecrets();
    const missing = REQUIRED_SECRET_FILES[3];
    delete files[path.join(require('path').join(__dirname, '..', '..', '..'), 'secrets', missing)];
    const r = validatePreflight(validEnv(), fakeFs(files));
    expect(r.ok).toBe(false);
    expect(r.errors.join('\n')).toContain(missing);
  });

  test('密钥文件存在但内容为空 → 同样拒绝（比缺失更隐蔽）', () => {
    // 空文件会让 compose 校验通过、应用拿到空串，失败推迟到运行期。
    const root = path.join(__dirname, '..', '..', '..');
    const files = fullSecrets();
    files[path.join(root, 'secrets', 'hmac_secret')] = '   \n';
    const r = validatePreflight(validEnv(), fakeFs(files));
    expect(r.ok).toBe(false);
    expect(r.errors.join('\n')).toContain('hmac_secret');
    expect(r.errors.join('\n')).toContain('内容为空');
  });

  test('多个问题一次列全（不是遇到第一个就返回）', () => {
    // 一次只报一个错会让运维陷入「改一个、再跑一次、又报一个」的循环。
    const env = { APP_IMAGE: '', CORS_ORIGIN: '', ALLOWED_HOSTS: '' };
    const r = validatePreflight(env, fakeFs({}));
    expect(r.ok).toBe(false);
    expect(r.errors.length).toBeGreaterThanOrEqual(4);
  });

  test('CORS_ORIGIN 缺失即拒绝（compose 用 :? 硬声明）', () => {
    const env = validEnv();
    delete env.CORS_ORIGIN;
    const r = validatePreflight(env, fakeFs(fullSecrets()));
    expect(r.ok).toBe(false);
    expect(r.errors.join('\n')).toContain('CORS_ORIGIN 未设置');
  });

  test('ALLOWED_HOSTS 缺失即拒绝——漏了它会在「迁移已执行、容器未切换」处才炸', () => {
    // 这是本清单此前的真实缺口：compose 第 41 行对 ALLOWED_HOSTS 用了 `:?`，
    // 而 preflight 只校验 CORS_ORIGIN。后果不是「提示不友好」，而是顺序问题——
    // 备份与 migrate-up 都在「切换容器」之前，compose 到那一步才拒绝，
    // 于是数据库已被改写而线上仍跑旧版本（CI 两条部署路径当时都没下发该变量）。
    const env = validEnv();
    delete env.ALLOWED_HOSTS;
    const r = validatePreflight(env, fakeFs(fullSecrets()));
    expect(r.ok).toBe(false);
    expect(r.errors.join('\n')).toContain('ALLOWED_HOSTS 未设置');
  });

  test('preflight 清单 = docker-compose.yml 里全部 `:?` 变量（双向、不漂移）', () => {
    // 判据从 compose 反向推导：将来给 compose 新增一个 `:?` 变量而忘了同步 preflight，
    // 上面那条手工用例不会红（它只覆盖 ALLOWED_HOSTS），而这条会。
    const fs = require('fs');
    const yml = fs.readFileSync(
      path.join(__dirname, '..', '..', '..', 'docker-compose.yml'),
      'utf8'
    );
    const hard = [...yml.matchAll(/\$\{([A-Z0-9_]+):\?/g)].map((m) => m[1]);
    // 前提自证：正则真的抓到了硬声明项（抓空会让本用例恒绿）
    expect(hard.length).toBeGreaterThanOrEqual(2);
    expect([...hard].sort()).toEqual(REQUIRED_COMPOSE_ENV.map(([n]) => n).sort());

    // 行为侧：清单里每一项被抽掉都必须拒绝（清单存在≠校验生效）
    for (const [name] of REQUIRED_COMPOSE_ENV) {
      const env = validEnv();
      delete env[name];
      const r = validatePreflight(env, fakeFs(fullSecrets()));
      expect({ name, ok: r.ok, hit: r.errors.join('\n').includes(name) }).toMatchObject({
        name,
        ok: false,
        hit: true,
      });
    }
  });

  test('REQUIRED_SECRET_FILES 与 docker-compose.yml 的 secrets 段完全一致', () => {
    // 这是本清单的核心不变量：清单与 compose 声明漂移时，
    // 要么校验漏掉真实需要的密钥（部署到一半才炸），
    // 要么要求一个 compose 根本不用的文件（永远校验不过）。
    const fs = require('fs');
    const yml = fs.readFileSync(
      path.join(__dirname, '..', '..', '..', 'docker-compose.yml'),
      'utf8'
    );
    const idx = yml.lastIndexOf('\nsecrets:');
    expect(idx).toBeGreaterThan(-1);
    const block = yml.slice(idx);
    const declared = [...block.matchAll(/^ {2}([a-z_]+):$/gm)].map((m) => m[1]);

    expect([...declared].sort()).toEqual([...REQUIRED_SECRET_FILES].sort());
  });
});

describe('D-1 部署步骤顺序（顺序错=流程错）', () => {
  const ids = (plan) => plan.map((s) => s.id);

  test('备份必须早于迁移与切换（无备份不具备回滚资格）', () => {
    const order = ids(buildPlan({}));
    expect(order.indexOf('backup')).toBeGreaterThan(-1);
    expect(order.indexOf('backup')).toBeLessThan(order.indexOf('migrate-up'));
    expect(order.indexOf('backup')).toBeLessThan(order.indexOf('up'));
  });

  test('记录回滚目标必须早于切换（切完再读就晚了）', () => {
    const order = ids(buildPlan({}));
    expect(order.indexOf('record-current')).toBeLessThan(order.indexOf('up'));
  });

  test('健康门禁必须晚于切换（先切后验才是对部署结果的检验）', () => {
    const order = ids(buildPlan({}));
    expect(order.indexOf('up')).toBeLessThan(order.indexOf('health'));
  });

  test('迁移必须早于容器切换（新代码可能依赖新索引/新字段）', () => {
    const order = ids(buildPlan({}));
    expect(order.indexOf('migrate-up')).toBeLessThan(order.indexOf('up'));
  });

  test('备份必须紧跟在「记录回滚目标」之后、任何变更动作之前', () => {
    // 【本次改动补强】上面三条只断言了 backup 早于 migrate-up / up，
    // 把 backup 挪到 pull **之后**仍然全绿——因为 pull 也会改本地状态
    // （拉取占磁盘、覆盖旧镜像 tag），而「发布前先备份」的意图是
    // **在动任何东西之前**先拿到回滚抓手。
    // 这里锚定它与前两步的相邻关系，把顺序钉死：
    //   preflight → record-current → backup → （其余）
    const order = ids(buildPlan({}));
    expect(order.slice(0, 3)).toEqual(['preflight', 'record-current', 'backup']);
  });

  test('--skip-backup 时计划里确实没有备份步骤（且其余步骤保持）', () => {
    const withB = ids(buildPlan({}));
    const without = ids(buildPlan({ skipBackup: true }));
    expect(withB).toContain('backup');
    expect(without).not.toContain('backup');
    expect(without).toContain('migrate-up');
  });

  test('--no-rollback 时计划里没有自动回滚步骤', () => {
    expect(ids(buildPlan({}))).toContain('rollback-on-failure');
    expect(ids(buildPlan({ noRollback: true }))).not.toContain('rollback-on-failure');
  });

  test('健康门禁超时值体现在步骤描述里（不是写死的文案）', () => {
    const plan = buildPlan({ healthTimeoutMs: 30000 });
    const health = plan.find((s) => s.id === 'health');
    expect(health.desc).toContain('30s');
  });
});

describe('D-1 回滚决策', () => {
  test('健康通过 → 不回滚', () => {
    expect(
      decideRollback({ healthOk: true, noRollback: false, hasPreviousImage: true })
    ).toMatchObject({ rollback: false });
  });

  test('健康失败 + 有上一版本 → 回滚', () => {
    expect(
      decideRollback({ healthOk: false, noRollback: false, hasPreviousImage: true })
    ).toMatchObject({ rollback: true });
  });

  test('健康失败 + 无上一版本（首次部署）→ 不回滚，但必须说明需人工介入', () => {
    // 首次部署没有可回的目标，此时「假装回滚」比不回滚更危险：
    // 会让脚本打印"已回滚"，而线上其实还是失败的版本。
    const d = decideRollback({ healthOk: false, noRollback: false, hasPreviousImage: false });
    expect(d.rollback).toBe(false);
    expect(d.reason).toContain('人工介入');
  });

  test('--no-rollback 时即使健康失败也不回滚（尊重显式选择）', () => {
    const d = decideRollback({ healthOk: false, noRollback: true, hasPreviousImage: true });
    expect(d.rollback).toBe(false);
    expect(d.reason).toContain('--no-rollback');
  });

  test('缺省 backupTaken 时按「已备份」处理（既有调用点语义不变）', () => {
    // 新增入参必须向后兼容：不传该字段的调用（含上面几条用例）仍走自动回滚。
    expect(
      decideRollback({ healthOk: false, noRollback: false, hasPreviousImage: true })
    ).toMatchObject({ rollback: true });
    expect(
      decideRollback({
        healthOk: false,
        noRollback: false,
        hasPreviousImage: true,
        backupTaken: true,
      })
    ).toMatchObject({ rollback: true });
  });

  test('--skip-backup 后健康失败 → 拒绝自动回滚，并给出可执行的前置动作', () => {
    // 脚本自己的铁律写在文件头：「没有备份的发布不具备回滚资格」。
    // 而迁移已改写数据库时自动切旧镜像 = 旧版本在**无任何退路**的新 schema 上续写，
    // 写坏了连现场都取不回来。此时可用性本就已失，停住不比自动回滚更糟。
    const d = decideRollback({
      healthOk: false,
      noRollback: false,
      hasPreviousImage: true,
      backupTaken: false,
    });
    expect(d.rollback).toBe(false);
    expect(d.reason).toContain('备份');
    // 拒绝之外必须给动作：先抢救当前库，再人工判断迁移兼容性
    expect(d.reason).toContain('backup-mongo.sh');
    expect(d.reason).toContain('人工回滚');
  });

  test('健康通过时 backupTaken=false 也不改变结论（不得把警告当失败）', () => {
    expect(
      decideRollback({
        healthOk: true,
        noRollback: false,
        hasPreviousImage: true,
        backupTaken: false,
      })
    ).toMatchObject({ rollback: false, reason: '健康门禁通过' });
  });
});

describe('D-1 数值配置解析：写错必须拒绝，不得静默失真', () => {
  test('前提自证：NaN 超时会让健康门禁一次都不探测', () => {
    // 这条不测生产代码，测的是「为什么 Number(env) 不能留着」这个机制本身：
    // Date.now() + NaN = NaN ⇒ while (Date.now() < NaN) 直接不进循环 ⇒
    // 门禁返回「超时（尚未探测）」⇒ 健康的版本被判失败并触发回滚。
    const deadline = Date.now() + Number('120s');
    expect(Number.isNaN(Number('120s'))).toBe(true);
    expect(Date.now() < deadline).toBe(false);
  });

  test('未设置时取默认值（120000 / 60000 / 3000）', () => {
    const { args, errors } = parseArgs([], {});
    expect(errors).toEqual([]);
    expect(args).toMatchObject({
      healthTimeoutMs: 120000,
      rollbackTimeoutMs: 60000,
      probePort: 3000,
    });
  });

  test('空串等同于未设置（shell 里 export X="" 很常见）', () => {
    const { args, errors } = parseArgs([], {
      DEPLOY_HEALTH_TIMEOUT_MS: '',
      DEPLOY_ROLLBACK_TIMEOUT_MS: '  ',
    });
    expect(errors).toEqual([]);
    expect(args.healthTimeoutMs).toBe(120000);
    expect(args.rollbackTimeoutMs).toBe(60000);
  });

  test.each([
    ['DEPLOY_HEALTH_TIMEOUT_MS', '120s'],
    ['DEPLOY_HEALTH_TIMEOUT_MS', '120000ms'],
    ['DEPLOY_HEALTH_TIMEOUT_MS', '-1'],
    ['DEPLOY_HEALTH_TIMEOUT_MS', '0'],
    ['DEPLOY_PROBE_PORT', '99999'],
    ['DEPLOY_PROBE_PORT', '3000.5'],
    ['DEPLOY_ROLLBACK_TIMEOUT_MS', 'abc'],
  ])('%s=%s 被拒绝并指名该项', (name, raw) => {
    const { errors } = parseArgs([], { [name]: raw });
    expect(errors.length).toBe(1);
    expect(errors[0]).toContain(name);
  });

  test('多个非法项一次列全 + 合法值照常生效', () => {
    const { args, errors } = parseArgs(['--dry-run', '--skip-backup'], {
      DEPLOY_HEALTH_TIMEOUT_MS: '120s',
      DEPLOY_PROBE_PORT: '0',
      DEPLOY_ROLLBACK_TIMEOUT_MS: '30000',
    });
    expect(errors.length).toBe(2);
    expect(args).toMatchObject({ dryRun: true, skipBackup: true, rollbackTimeoutMs: 30000 });
    // 出错时对应字段不会被写入（避免 undefined 冒充合法值流到下游）
    expect('healthTimeoutMs' in args).toBe(false);
  });
});

describe('F-159 同引用发布（:latest 这类可变标签）时的自动回滚拒绝', () => {
  const unhealthy = {
    healthOk: false,
    noRollback: false,
    hasPreviousImage: true,
    backupTaken: true,
  };

  test('isSameImageRef：trim + 小写判等；任一侧为空必须判「不同」', () => {
    expect(isSameImageRef('Repo:Latest', ' repo:latest ')).toBe(true);
    expect(isSameImageRef('ghcr.io/o/r:sha-1', 'ghcr.io/o/r:sha-2')).toBe(false);
    // 空值若被判「相同」，首次部署会误进这一支，把「无可回滚目标」这个真原因盖掉
    for (const [a, b] of [
      [null, 'x'],
      [undefined, 'x'],
      ['', 'x'],
      ['x', ''],
      ['x', undefined],
    ]) {
      expect(isSameImageRef(a, b)).toBe(false);
    }
  });

  test('回滚目标与本次目标同串 → 不回滚，理由要点破谎害与替代口径', () => {
    const d = decideRollback({
      ...unhealthy,
      previousImage: 'ghcr.io/o/r:latest',
      targetImage: 'ghcr.io/o/r:latest',
    });
    expect(d.rollback).toBe(false);
    expect(d.reason).toContain('相同');
    // 必须说清危害本身：同引用「回滚」照样能探测到健康，于是打印「✓ 回滚后服务就绪」，
    // 而线上其实还是刚发布的那个版本
    expect(d.reason).toContain('已回滚');
    expect(d.reason).toContain('digest');
  });

  test('正对照：不同引用照常自动回滚（拒绝分支不是无条件关门）', () => {
    expect(
      decideRollback({ ...unhealthy, previousImage: 'r:sha-1', targetImage: 'r:sha-2' }).rollback
    ).toBe(true);
  });

  test('两串缺省时语义不变（既有调用点与 D-1 各条用例不受影响）', () => {
    expect(decideRollback({ ...unhealthy }).rollback).toBe(true);
    expect(decideRollback({ ...unhealthy, previousImage: 'r:latest' }).rollback).toBe(true);
    expect(decideRollback({ ...unhealthy, targetImage: 'r:latest' }).rollback).toBe(true);
  });

  test('写法门禁：deploy.js 必须把两串喂进判据，且同引用判定只有 isSameImageRef 一处口径', () => {
    // 判据写对但调用点不传参 ⇒ 这一支永不进入，全套逻辑用例仍绿、线上照旧谎报「已回滚」。
    // 与 §67.2 同族：钉的是「判定与其唯一消费方同口径」，不是判定的返回值。
    const fs = require('fs');
    const code = fs
      .readFileSync(path.join(__dirname, '..', '..', '..', 'scripts', 'deploy.js'), 'utf8')
      .split('\n')
      .filter((line) => !/^\s*(\/\/|\*|\/\*)/.test(line))
      .join('\n');
    const call = code.match(/decideRollback\(\{[\s\S]*?\}\)/);
    // 前提自证：正则真抓到了那个调用（抓空会让本用例恒绿）
    expect(call).not.toBeNull();
    expect(call[0]).toContain('previousImage');
    expect(call[0]).toContain('targetImage');
    // 提前告警与决策必须共用同一判定；执行层不得再手写一份比较
    expect(code).toContain('isSameImageRef(');
    expect(code).not.toMatch(/previousImage\s*===/);
  });
});

/**
 * 2026-09-26 审计 Top-2：告警接收端占位 URL + 无接入防线。
 *
 * 缺陷形态最隐蔽的一点是「部署成功、页面全绿、却没有人被叫醒」：
 * docker-compose.yml 把仓库内的 alertmanager.yml 直接挂进容器，文件里是
 * https://hooks.example.com/<替换为…>，于是 critical 告警（BackendDown /
 * HighErrorRate）全部发往一个不存在的域名，Prometheus 页面看不出任何异常。
 * 仓内原有的合规检查有生产闸（ALERT_WEBHOOK_CHECK=production），但它只能人工
 * 手动触发，而 CI 又不能设（仓库模板本身就是占位，设了必红）——「忘了注入」
 * 这条路上此前没有任何守卫。本组用例把守卫钉在真实部署路径（validatePreflight）上。
 */
describe('Top-2 部署前置：告警接收端未注入即拒绝（fail-closed）', () => {
  test('前提自证：仓库里那份 alertmanager.yml 仍是占位形态（真实文件，非构造夹具）', () => {
    // 若这条红了，说明有人把真实 access_token 提交进了仓库——那本身是更严重的问题。
    const { extractWebhookEndpoints } = require('../../../scripts/compliance-alerting');
    const endpoints = extractWebhookEndpoints(require('fs').readFileSync(AM_PATH, 'utf8'));
    expect(endpoints.length).toBeGreaterThan(0);
    expect(endpoints.filter((e) => e.status === 'placeholder').length).toBeGreaterThan(0);
  });

  test('契约：仓库模板态下 preflight 必须拒绝发布，并把「怎么修」写进错误里', () => {
    const r = checkAlertingEndpoint({}, require('fs'));
    expect(r.errors.length).toBe(1);
    expect(r.errors[0]).toMatch(/占位/);
    // 拒绝之外必须给动作，否则运维只知道"不行"
    expect(r.errors[0]).toMatch(/ALLOW_PLACEHOLDER_ALERT_WEBHOOK=true/);
    expect(r.errors[0]).toMatch(/私有副本|模板渲染|ALERT_WEBHOOK_CHECK=production/);
  });

  test('接线：validatePreflight 必须把告警判据合并进 errors（判据存在≠生效）', () => {
    // 只测 checkAlertingEndpoint 的返回值，删掉 validatePreflight 里的那两行 push
    // 仍然全绿——而线上照旧无人被叫醒。故此处走完整入口（真 fs + 真仓库文件）。
    const r = validatePreflight(validEnv(), require('fs'));
    expect(r.ok).toBe(false);
    expect(r.errors.join('\n')).toMatch(/占位/);
  });

  test('已注入真实通道 → 不再因告警拦人（正对照，拒绝分支不是无条件关门）', () => {
    expect(checkAlertingEndpoint({}, okFs())).toEqual({ errors: [], warnings: [] });
    expect(validatePreflight(validEnv(), okFs())).toEqual({ ok: true, errors: [], warnings: [] });
  });

  test('ALERTMANAGER_CONFIG_PATH 可指向独立挂载的真实配置（同判据，非绕过）', () => {
    // 文件头注释里的第 2 种注入方式会改挂载点；指向的文件仍要过同一道闸。
    const alt = path.join(ROOT, 'secrets', 'alertmanager.prod.yml');
    const fsStub = fakeFs({ ...fullSecrets(), [alt]: configuredAlertmanager() });
    expect(checkAlertingEndpoint({ ALERTMANAGER_CONFIG_PATH: alt }, fsStub)).toEqual({
      errors: [],
      warnings: [],
    });
    // 指向一个仍是占位的文件 ⇒ 照旧拒绝（换路径不等于换判据）
    const fsStub2 = fakeFs({ ...fullSecrets(), [alt]: placeholderAlertmanager() });
    expect(checkAlertingEndpoint({ ALERTMANAGER_CONFIG_PATH: alt }, fsStub2).errors.length).toBe(1);
  });

  test('显式声明允许占位 → 降级为 warning，且必须说清"告警不会触达任何人"', () => {
    const fsStub = fakeFs({ ...fullSecrets(), [AM_PATH]: placeholderAlertmanager() });
    const r = checkAlertingEndpoint({ ALLOW_PLACEHOLDER_ALERT_WEBHOOK: 'true' }, fsStub);
    expect(r.errors).toEqual([]);
    expect(r.warnings.join('\n')).toContain('不会触达任何人');
    // 只认字面 'true'（大小写敏感）：'1' / 'yes' / 'on' 这类常见真值写法不构成豁免——
    // 这是**故意**保守的一侧：豁免是"让告警静默丢失"的许可，不该靠猜写法给出。
    for (const v of ['1', 'yes', 'on', 'TRUE']) {
      expect(
        checkAlertingEndpoint({ ALLOW_PLACEHOLDER_ALERT_WEBHOOK: v }, fsStub).errors.length
      ).toBe(1);
    }
    // 但两侧空白照惯例抹掉（`export X=true ` 是真实写法，不该因此判成不豁免）
    expect(
      checkAlertingEndpoint({ ALLOW_PLACEHOLDER_ALERT_WEBHOOK: ' true ' }, fsStub).errors.length
    ).toBe(0);
  });

  test('误配（明文 http）在仓库态也红 ⇒ 任何豁免声明都不接受', () => {
    const bad = [
      'receivers:',
      '  - name: ops-critical',
      '    webhook_configs:',
      '      - url: http://ops.internal.example/hook',
      '',
    ].join('\n');
    const r = checkAlertingEndpoint(
      { ALLOW_PLACEHOLDER_ALERT_WEBHOOK: 'true' },
      fakeFs({ ...fullSecrets(), [AM_PATH]: bad })
    );
    expect(r.errors.length).toBe(1);
    expect(r.errors[0]).toContain('不接受豁免声明');
  });

  test('整条链断开（一个接收端都没有）同样拒绝', () => {
    const none = 'receivers:/n  - name: ops-critical\n';
    const r = checkAlertingEndpoint({}, fakeFs({ ...fullSecrets(), [AM_PATH]: none }));
    expect(r.errors.length).toBe(1);
    expect(r.errors[0]).toMatch(/未发现任何 webhook 接收端|断开/);
  });

  test('读不到配置 ⇒ 判不过（2026-10-01 修正：只写 warning 等于门禁判绿）', () => {
    // 旧行为：errors 为空 + 一条 warning。而本函数的裁决位是 `ok = errors.length === 0`
    // （deployPolicy.js:109）⇒ alertmanager.yml 被删/未挂载/无读权限时，告警链必然不可用，
    // 发布却照样通过。2026-09-26 那次修复的标题就是「fail-closed」，这一支恰好没关上。
    const r = checkAlertingEndpoint({}, fakeFs(fullSecrets()));
    expect(r.errors.length).toBe(1);
    expect(r.errors[0]).toContain('无法确认 webhook 是否已注入');
    expect(r.errors[0]).toContain('「判不了」按不通过处理');
    // 必须给动作：只说"不行"的门禁让人无法收尾
    for (const hint of ['ALERTMANAGER_CONFIG_PATH', 'ALLOW_PLACEHOLDER_ALERT_WEBHOOK=true']) {
      expect(r.errors[0]).toContain(hint);
    }
    expect(r.warnings).toEqual([]);
  });

  test('接线：读不到配置时完整 preflight 入口也必须拒绝（判据存在≠生效）', () => {
    const r = validatePreflight(validEnv(), fakeFs(fullSecrets()));
    expect(r.ok).toBe(false);
    expect(r.errors.join('\n')).toContain('未能读取告警接收端配置');
  });

  test('ALERT_CHECK_SKIPPED=true 是唯一放行口，且放行必须显形', () => {
    // 存在这个口的理由不是"方便"：deployPolicy.js 也被非部署流程当库调用（静态合规脚本、
    // CI 里只解析资源参数的那一步），那些现场没有 alertmanager.yml 属正常，
    // 硬拦会把合法用法变成必然失败——而"必然失败的门禁"的下一站就是 continue-on-error。
    const r = checkAlertingEndpoint({ ALERT_CHECK_SKIPPED: 'true' }, fakeFs(fullSecrets()));
    expect(r.errors).toEqual([]);
    expect(r.warnings.join('\n')).toContain('没有任何证据表明');
    // 与 ALLOW_PLACEHOLDER_ALERT_WEBHOOK 同一套严格度：只认字面 'true'，
    // 放行口靠猜写法给出等于把"告警静默丢失"的许可发给任何拼错的人
    for (const v of ['1', 'yes', 'on', 'TRUE', '']) {
      expect(
        checkAlertingEndpoint({ ALERT_CHECK_SKIPPED: v }, fakeFs(fullSecrets())).errors.length
      ).toBe(1);
    }
    expect(
      checkAlertingEndpoint({ ALERT_CHECK_SKIPPED: ' true ' }, fakeFs(fullSecrets())).errors.length
    ).toBe(0);
  });
});
