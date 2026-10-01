/**
 * 发布/破坏性脚本的参数解析必须拒绝未知参数（ops 审计批次）
 *
 * 两条脚本原先共用同一个形状：「只认白名单里的 token，其余当没看见」。
 * - `scripts/deploy.js`：`argv.includes('--dry-run')` —— 于是 `--dryrun`
 *   （少一个连字符，最容易敲错的一种）得到的不是一次干跑，而是一次完整发布：
 *   校验、备份、迁移、切容器全做，退出码 0。
 * - `scripts/run-rollback-drill.js`：三个 `if` 各自独立且 `--backup-dir` 取了
 *   `argv[index + 1]` 却不消耗它 —— `--backup-dir --apply-source` 把目录名设成
 *   字面量「--apply-source」（mkdir 造出垃圾目录），**同时** applySource 仍为真。
 *
 * 「干跑还是实发」「演练还是落斧」是这些脚本唯一的危险边界，
 * 而这条边界原先只靠人敲对连字符维持。参数解析成错误集合后，
 * 两条入口都已在产生任何副作用之前以退出码 2 拒绝（deploy.js:255、本套件用例 5 实测）。
 *
 * 2026-09-25 扩到本仓**其余**两个 CLI 入口（用例 11-18），因为它们坏在同一处：
 *   - `scripts/check-bundle-budget.js`：`--dist web-admin/dist-new`（空格形态）两个 token
 *     都不报错 ⇒ 门禁量的是**默认 dist**，新产物超重灾区也能报"通过"——一条以"量对东西"
 *     为全部价值的门禁，被一个空格作废；
 *   - `scripts/generate-secrets.js`：`--output ./secrets` 与末尾裸 `--out` 都取不到目录
 *     ⇒ 静默走"打印到 stdout"分支，把全套密钥（含 EC 私钥 PEM）装进终端历史/CI 日志，
 *     而操作者以为已经落成 0600 文件。
 * 同族另三个只带 `--apply` 的脚本（fix-token-blacklist-index / sync-audit-indexes /
 * revoke-user-sessions）仍接受未知参数，但它们的降级方向是**干跑**（安全侧），故未一并整改。
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const { parseArgs: parseDeployArgs, DEPLOY_FLAGS } = require('../../../scripts/deployPolicy');
const { parseArgs: parseDrillArgs } = require('../../../scripts/run-rollback-drill');
const { parseCliArgs: parseBudgetArgs } = require('../../../scripts/check-bundle-budget');

describe('scripts/deployPolicy.js parseArgs：未知参数即拒绝', () => {
  test('1 三个合法开关全给：不报错且逐项置真（证明闸门没有反向误伤）', () => {
    const { args, errors } = parseDeployArgs(['--dry-run', '--skip-backup', '--no-rollback'], {});
    expect(errors).toEqual([]);
    expect(args).toMatchObject({ dryRun: true, skipBackup: true, noRollback: true });
  });

  test('2 --dryrun（少一个连字符）必须报错，且点名该 token 并给出正确写法', () => {
    const { args, errors } = parseDeployArgs(['--dryrun'], {});
    expect(errors).toHaveLength(1);
    expect(errors[0]).toContain('--dryrun');
    // 判据是「报错文案可直接照抄修复」：拼错形态抹平后应命中 --dry-run
    expect(errors[0]).toContain('--dry-run');
    expect(errors[0]).toContain('是否想写');
    // 且绝不因" unrecognized 但看着像"而把 dryRun 置真
    expect(args.dryRun).toBe(false);
  });

  test('3 无任何相似形状的未知参数：不得凭空给出建议', () => {
    const { errors } = parseDeployArgs(['--frobnicate'], {});
    expect(errors).toHaveLength(1);
    expect(errors[0]).toContain('--frobnicate');
    expect(errors[0]).not.toContain('是否想写');
  });

  test('4 位置参数同样拒绝（deploy.js 无位置参数）+ 多个未知一次列全', () => {
    const { errors } = parseDeployArgs(['production', '--skipbackup', '--no-rollbackx'], {});
    expect(errors).toHaveLength(3);
    for (const token of ['production', '--skipbackup', '--no-rollbackx']) {
      expect(errors.join('\n')).toContain(token);
    }
    // 合法项与未知项混排时，合法项照常解析（报错由调用方统一拒绝执行）
    expect(DEPLOY_FLAGS).toEqual(['--dry-run', '--skip-backup', '--no-rollback']);
  });

  test('5 未知参数与环境变量非法同时出现：两类错误一起列全，不互相吞', () => {
    const { errors } = parseDeployArgs(['--dryrun'], { DEPLOY_PROBE_PORT: '0' });
    expect(errors).toHaveLength(2);
    expect(errors.join('\n')).toContain('DEPLOY_PROBE_PORT');
    expect(errors.join('\n')).toContain('--dryrun');
  });
});

describe('scripts/run-rollback-drill.js parseArgs：落斧开关不接受歧义输入', () => {
  const defaults = () => ({
    applySource: false,
    confirmYes: false,
    backupDir: path.join('backups', 'rollback-drill'),
    errors: [],
  });

  test('6 完整合法参数：解析正确且 errors 为空', () => {
    const r = parseDrillArgs(['--backup-dir', '/tmp/bk', '--apply-source', '--yes']);
    expect(r.errors).toEqual([]);
    expect(r.backupDir).toBe('/tmp/bk');
    expect(r.applySource).toBe(true);
    expect(r.confirmYes).toBe(true);
  });

  test('7 --backup-dir 的下一个 token 是开关时：报缺值，且绝不落斧', () => {
    // 修复前实测：applySource=true 且 backupDir='--apply-source'
    // ——一次输入同时踩中「目录没设上」和「意外清空集合」
    const r = parseDrillArgs(['--backup-dir', '--apply-source']);
    expect(r.errors).toEqual(['--backup-dir 缺少目录参数']);
    expect(r.applySource).toBe(false);
    expect(r.confirmYes).toBe(false);
    expect(r.backupDir).toBe(defaults().backupDir);
  });

  test('8 --backup-dir 位于末尾（值缺失）：报缺值而不是把 undefined 交给 mkdir', () => {
    const r = parseDrillArgs(['--yes', '--backup-dir']);
    expect(r.errors).toEqual(['--backup-dir 缺少目录参数']);
    expect(r.backupDir).toBe(defaults().backupDir);
    expect(r.confirmYes).toBe(true);
  });

  test('9 未知参数拒绝，文案点名本脚本的全部可接受项', () => {
    const r = parseDrillArgs(['--dryrun']);
    expect(r.errors).toHaveLength(1);
    expect(r.errors[0]).toContain('--dryrun');
    for (const flag of ['--apply-source', '--yes', '--backup-dir']) {
      expect(r.errors[0]).toContain(flag);
    }
    expect(r.applySource).toBe(false);
  });

  test('10 合法值消耗掉自己的参数：--backup-dir 的目录名不会被当成第二个开关', () => {
    // 修复前 `--backup-dir --yes` 走的是「值=--yes 且 confirmYes=true」；
    // 而 `--backup-dir ok --yes` 里 --yes 必须仍然生效（消耗一格不能吃掉后续 token）
    const r = parseDrillArgs(['--backup-dir', 'ok-dir', '--yes']);
    expect(r.errors).toEqual([]);
    expect(r.backupDir).toBe('ok-dir');
    expect(r.confirmYes).toBe(true);
  });
});

const ROOT = path.resolve(__dirname, '../../..');
const BUDGET_SCRIPT = path.join(ROOT, 'scripts/check-bundle-budget.js');
const GEN_SCRIPT = path.join(ROOT, 'scripts/generate-secrets.js');
const NODE = process.execPath;

const runNode = (script, args) =>
  spawnSync(NODE, [script, ...args], { cwd: ROOT, encoding: 'utf8', timeout: 60000 });

const tempDirs = [];
/** 每次调用给一个独立的临时目录，用例之间无顺序依赖（三 seed 门禁要求） */
const mkdtemp = (label) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `cliargs-${label}-`));
  tempDirs.push(dir);
  return dir;
};
afterAll(() => {
  for (const dir of tempDirs) fs.rmSync(dir, { recursive: true, force: true });
});

describe('scripts/check-bundle-budget.js parseCliArgs：门禁必须量对的东西', () => {
  test('11 完整合法参数逐项生效（证明严格化没有反向误伤）', () => {
    const r = parseBudgetArgs([
      '--update-baseline',
      '--allow-growth',
      '--dist=a/dist',
      '--baseline=a/b.json',
    ]);
    expect(r.errors).toEqual([]);
    expect([r.updateMode, r.allowGrowth, r.dist, r.baseline]).toEqual([
      true,
      true,
      'a/dist',
      'a/b.json',
    ]);
  });

  test('12 `--dist <目录>` 写成空格分隔：报错且 dist 保持 null（不得回退默认 dist）', () => {
    // 修复前实测：errors 为空数组、dist 为 null ⇒ main() 用 DEFAULT_DIST_DIR 量默认产物。
    // 于是「给新产物做预算检查」这条命令量的却是旧产物，超重灾区照样报"通过"。
    const r = parseBudgetArgs(['--dist', 'web-admin/dist-new', '--update-baseline']);
    expect(r.dist).toBeNull();
    const joined = r.errors.join('\n');
    expect(joined).toContain('--dist 需要非空值');
    expect(joined).toContain('web-admin/dist-new'); // 那个目录名也得被当成未知参数点名
  });

  test('13 --dist= 空值：报错而不是把空串交给 path.resolve（那会量到进程 cwd）', () => {
    const r = parseBudgetArgs(['--dist=']);
    expect(r.dist).toBeNull();
    expect(r.errors.join('\n')).toContain('--dist 需要非空值');
  });

  test('14 未知参数：点名全部可接受项；拼错给可照抄的建议；无相似项不凭空建议', () => {
    const typo = parseBudgetArgs(['--update-baselines']);
    expect(typo.errors).toHaveLength(1);
    for (const f of ['--update-baseline', '--allow-growth', '--dist', '--baseline']) {
      expect(typo.errors[0]).toContain(f);
    }
    expect(typo.errors[0]).toContain('是否想写 --update-baseline');
    const nonsense = parseBudgetArgs(['--frobnicate']);
    expect(nonsense.errors[0]).toContain('--frobnicate');
    expect(nonsense.errors[0]).not.toContain('是否想写');
  });

  test('15 用法错误发生在读产物之前：退出码 2、stdout 一个字节都没有', () => {
    const r = runNode(BUDGET_SCRIPT, ['--dist', 'web-admin/dist']);
    expect(r.status).toBe(2);
    expect(r.stdout).toBe('');
    expect(r.stderr).toContain('用法错误');
  });
});

describe('scripts/generate-secrets.js：参数手误不得把密钥打进 stdout', () => {
  // 三种形态是同一个洞的三张脸：--out 取不到值 ⇒ outDir 为空 ⇒ 走"打印"分支。
  // 断言的重点是 stdout 完全为空——修复前这里装着全套密钥（jwt_secret=…、EC 私钥 PEM）。
  const TYPO_CASES = [
    ['--output ./secrets（多打两个字母）', ['--output', './zz-should-not-exist']],
    ['--out 打在末尾（目录忘了给）', ['--out']],
    ['--out --force（目录槽被开关占掉）', ['--out', '--force']],
  ];

  test.each(TYPO_CASES)('16 %s：退出码 2 且 stdout 没有任何密钥', ([, args]) => {
    const r = runNode(GEN_SCRIPT, args);
    expect(r.status).toBe(2);
    expect(r.stdout).toBe('');
    expect(r.stderr).not.toMatch(/jwt_secret|AES_SECRET|BEGIN [A-Z ]*PRIVATE KEY/);
    expect(r.stderr).toContain('generate-secrets');
  });

  test('17 拒绝发生在落盘之前：--output <目录> 不会创建那个目录', () => {
    const target = path.join(mkdtemp('gs-reject-'), 'nested', 'secrets');
    const r = runNode(GEN_SCRIPT, ['--output', target]);
    expect(r.status).toBe(2);
    expect(fs.existsSync(target)).toBe(false);
    expect(r.stderr).toContain('是否想写 --out'); // 文案可直接照抄修复
  });

  test('18 正向对照：--help 退出 0，合法 --out <目录> 退出 0 且整套密钥落地', () => {
    expect(runNode(GEN_SCRIPT, ['--help']).status).toBe(0);
    const out = path.join(mkdtemp('gs-accept-'), 'secrets');
    const r = runNode(GEN_SCRIPT, ['--out', out]);
    expect(r.status).toBe(0);
    // 清单写死在这里是故意的：脚本新增一个密钥项时，这条用例会红着要求确认
    // （从脚本自身推导 keys 就永远不会报警，而那正是"整套密钥"这句话的含义所在）
    const expected = [
      'admin_initial_password',
      'aes_secret_key',
      'grafana_admin_password',
      'hmac_secret',
      'login_ecdh_private_key',
      'mongo_root_password',
      'mongo_root_username',
      'mongodb_uri',
      'jwt_refresh_secret',
      'jwt_secret',
      // 2026-10-01 审计 finding：redis 认证口令（compose 的 redis --requirepass
      // 与 app 侧 REDIS_PASSWORD_FILE 共用）——清单写死即为此刻意设计的确认点
      'redis_password',
    ].sort();
    expect(fs.readdirSync(out).sort()).toEqual(expected);
  });
});
