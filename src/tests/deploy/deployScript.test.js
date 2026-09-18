/**
 * 部署自动化（D-1）回归
 *
 * 被测对象：scripts/deploy.js
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
  REQUIRED_SECRET_FILES,
  validatePreflight,
  buildPlan,
  decideRollback,
} = require('../../../scripts/deploy');

/** 构造一个「全部合法」的环境，供各用例按需覆盖单项 */
const validEnv = () => ({
  APP_IMAGE: 'ghcr.io/qmzzzzz/fsms:sha-abc1234',
  CORS_ORIGIN: 'https://admin.example.com',
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

describe('D-1 部署前置校验：fail-closed', () => {
  test('全部条件满足时放行', () => {
    const r = validatePreflight(validEnv(), fakeFs(fullSecrets()));
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

  test('CORS_ORIGIN 缺失即拒绝', () => {
    const env = validEnv();
    delete env.CORS_ORIGIN;
    const r = validatePreflight(env, fakeFs(fullSecrets()));
    expect(r.ok).toBe(false);
    expect(r.errors.join('\n')).toContain('CORS_ORIGIN 未设置');
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
    const env = { APP_IMAGE: '', CORS_ORIGIN: '' };
    const r = validatePreflight(env, fakeFs({}));
    expect(r.ok).toBe(false);
    expect(r.errors.length).toBeGreaterThanOrEqual(3);
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
    // 【本轮补强】上面三条只断言了 backup 早于 migrate-up / up，
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
});
