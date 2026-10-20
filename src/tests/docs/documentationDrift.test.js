/**
 * 文档对账（D-1～D-4）
 *
 * 审计报告指出的不是「文档缺失」，而是「文档跑在代码前面」：README 的 ADR/告警计数、
 * 已拆分的中间件路径，`.env.example` 的初始口令语义与发布必填项，部署/应急文档里的
 * 迁移器位置与 WAL 文件名，都在多点漂移。这些数字与路径**没有测试盯着**，就会在每次
 * 拆分/新增后继续偏。
 *
 * 本套件只核对「可从代码/目录直接数出来」的事实，不做全文校验：
 *   - 计数由目录/规则文件实时数出，文档只提供被读的那个数字；
 *   - 路径以文件是否存在为准，不绑定行号（行号会随编辑漂移，绑它等于制造下一次误报）。
 */

'use strict';

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '../../..');
const read = (rel) => fs.readFileSync(path.join(ROOT, rel), 'utf8');
const exists = (rel) => fs.existsSync(path.join(ROOT, rel));

describe('文档与代码对账（D-1～D-4）', () => {
  test('D-1：README 的 ADR 计数 = docs/adr 实际篇数，且最新编号被点名', () => {
    const files = fs
      .readdirSync(path.join(ROOT, 'docs/adr'))
      .filter((f) => /^ADR-\d+.*\.md$/.test(f));
    const readme = read('README.md');
    const claimed = readme.match(/架构决策记录（(\d+) 篇/);
    expect(claimed).toBeTruthy();
    expect(Number(claimed[1])).toBe(files.length);

    // 新增 ADR-010 时，README 若没同步点名这一编号，本断言会红
    const maxAdr = Math.max(...files.map((f) => Number(f.match(/^ADR-(\d+)/)[1])));
    expect(readme).toContain(`ADR-${String(maxAdr).padStart(3, '0')}`);
  });

  test('D-1：README 的告警条数 = alert-rules.yml 实际条数', () => {
    const rules = read('deployment/observability/alert-rules.yml');
    const actual = (rules.match(/^\s*- alert:/gm) || []).length;
    const readme = read('README.md');
    const claimed = readme.match(/(\d+) 条内置告警/);
    expect(claimed).toBeTruthy();
    expect(Number(claimed[1])).toBe(actual);
    // 目录树里的那条也要同数：正文改对、树里仍写 13 条时，原判据看不见（实测漂移）
    expect(readme).toMatch(new RegExp(`alert-rules\\.yml\\s+# 告警规则（${actual} 条`));
  });

  test('D-1：README 引用的是拆分后的 security 目录，不是已不存在的 security.js', () => {
    const readme = read('README.md');
    expect(readme).not.toMatch(/src\/middleware\/security\.js/);
    expect(readme).toContain('src/middleware/security/');
    expect(exists('src/middleware/security/index.js')).toBe(true);
  });

  test('D-2：.env.example 的初始口令语义、发布必填项与备份收件人均已更正', () => {
    const env = read('.env.example');
    // 随机初始口令落盘到 .admin-initial-password，绝不进日志
    expect(env).not.toContain('创建随机口令并打印到启动日志');
    expect(env).toContain('.admin-initial-password');
    expect(env).not.toContain('initData.js:780');

    // RPO/RTO 是发布硬门禁，模板里必须处于生效状态
    expect(env).toMatch(/^BACKUP_RPO_HOURS=24$/m);
    expect(env).toMatch(/^BACKUP_RTO_HOURS=4$/m);

    // gpg 是备份默认模式，收件人变量必须出现在模板里
    expect(env).toContain('BACKUP_GPG_RECIPIENT');
  });

  test('D-3：部署/应急文档与迁移器、WAL、Node 版本口径一致', () => {
    const drill = read('deployment/rollback-drill.md');
    expect(drill).not.toMatch(/migrate-mongo[\s\S]{0,20}devDependencies/);

    const incident = read('docs/incident-response.md');
    expect(incident).not.toContain('logs/audit.wal');
    expect(incident).toContain('audit-buffer');

    const pkg = JSON.parse(read('package.json'));
    const engine = pkg.engines.node.match(/(\d+)\.(\d+)/);
    expect(engine).toBeTruthy();
    expect(read('CONTRIBUTING.md')).toContain(`≥${engine[1]}.${engine[2]}`);
  });

  test('D-4：ADR-003 已记录 AES 的 PII 用途、轮换旧钥与 .env 现状', () => {
    const adr = read('docs/adr/ADR-003-密钥管理策略.md');
    expect(adr).toContain('piiCrypto.js');
    expect(adr).toContain('migrate-pii-encryption.js');
    expect(adr).toContain('PII_ROTATION_OLD_AES_KEY');
    expect(adr).toContain('当前状态');
    expect(adr).toContain('未入库');
  });

  test('O-5/T-4/S-9：运维留痕文档仍保留可执行步骤，且与工作流互相引用', () => {
    // O-5：真实演练步骤与留证表格；工作流必须指向它（否则「从未跑过」没有关闭路径）
    const rehearsal = read('deployment/deploy-workflow-rehearsal.md');
    expect(rehearsal).toContain('gh workflow run deploy.yml');
    expect(rehearsal).toContain('dry_run=true');
    expect(rehearsal).toContain('scripts/deployCommands.js');
    expect(read('.github/workflows/deploy.yml')).toContain(
      'deployment/deploy-workflow-rehearsal.md'
    );

    // T-4：预发定期演练命令必须带库名白名单与自动登记，且指出 CI 只判时效
    const drill = read('deployment/rollback-drill.md');
    expect(drill).toContain('预发环境定期自动演练');
    expect(drill).toMatch(/ALLOWED_SOURCE_DB=fsms_staging[\s\S]{0,200}--apply-source --yes/);
    expect(drill).toMatch(/record-rollback-drill\.js[\s\S]{0,200}--write/);
    expect(drill).toContain('dr-readiness.yml');

    // S-9：dev 树 advisory 的隔离口径必须写清执行面（托管 runner / 部署 runner 分离）
    const watch = read('docs/security-dependency-watch.md');
    expect(watch).toContain('CI 开发机隔离');
    expect(watch).toContain('ubuntu-latest');
    expect(watch).toMatch(/deploy[\s\S]{0,80}分开注册/);
  });
});
