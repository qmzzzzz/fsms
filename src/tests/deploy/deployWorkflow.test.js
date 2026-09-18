/**
 * 部署工作流（.github/workflows/deploy.yml）结构与不变量回归
 *
 * 为什么要测一个 YAML：工作流的失效形态很难在本地发现——
 * YAML 语法错误、job 名引用错、当“没配密钥就静默跳过”写成默认行为时，
 * 这些在本地完全不会报错，而在 GitHub 上则以“看不出来”的方式失败（最坏的一种：
 * 绿了但没部署）。本文件把那些“改了就会出事”的结构锁住。
 *
 * 能力边界（如实说明）：这是**静态断言**，不代表工作流真的能跑通。
 * 本地无 GitHub 控制权与部署机；“能不能跑”需首次配置后实践。
 * 但“不静默假绿”、“镜像 tag 校验在前”、“密钥不进命令行”这三条是结构性质，
 * 可以也应当在本地就被锁住。
 */
'use strict';

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '../../..');
const WF = path.join(ROOT, '.github/workflows/deploy.yml');

const src = fs.readFileSync(WF, 'utf8');
/**
 * 取某个 job 下 `run: |` 块的可执行内容（剔除注释行与空行）。
 *
 * 为什么要剔除注释：本文件的一条用例曾因为匹配到注释里的
 * “:local” 而在拦截语句被删后依然绿——注释不执行，不能当证据。
 */
function runScriptOf(job) {
  const block = jobBlock(job);
  const idx = block.indexOf('run: |');
  if (idx < 0) return '';
  const after = block.slice(idx + 'run: |'.length);
  const lines = after.split('\n').filter((l) => l.trim() && !l.trim().startsWith('#'));
  // 去掉各行的共同缩进，便于匹配
  const indent = Math.min(
    ...lines.filter((l) => /^\s+\S/.test(l)).map((l) => l.match(/^\s*/)[0].length)
  );
  return lines.map((l) => l.slice(indent)).join('\n');
}
/** 取某个 job 的文本块（从 `  <name>:` 到下个顶层 job），用于“断言它在该 job 内” */
function jobBlock(name) {
  const start = src.indexOf(`\n  ${name}:`);
  if (start < 0) throw new Error(`未找到 job：${name}`);
  const rest = src.slice(start + 1);
  const next = rest.slice(1).search(/\n {2}[a-zA-Z0-9_-]+:/);
  return next < 0 ? rest : rest.slice(0, next + 1);
}

describe('D-1 部署工作流：结构与关键不变量', () => {
  test('YAML 语法可被解析（格式错误会让整个工作流无法加载）', async () => {
    // 用 prettier（直接 devDependency）的 yaml 解析器做语法校验：
    // 不引入新依赖，也不依赖树里 hoisted 的传递包。
    // 意义：YAML 结构错位、缩进错误等“本地看不出来”的问题会在本测试就暴露，
    // 而不是等到推上 GitHub 才发现工作流加载失败。
    // 走 prettier 的 CLI（子进程）而不是 require('prettier')：
    // prettier 3 是纯 ESM，jest 的 CJS 运行时 require 它会报
    // "A dynamic import callback was invoked without --experimental-vm-modules"。
    // 用 CLI 既避开这个工具链差异，又和 CI 粒度一致（那边跑的也是 CLI）。
    const { spawnSync } = require('child_process');
    const r = spawnSync(
      process.execPath,
      [path.join(ROOT, 'node_modules/prettier/bin/prettier.cjs'), '--check', WF],
      { cwd: ROOT, encoding: 'utf8' }
    );
    expect({ code: r.status, out: (r.stdout || '') + (r.stderr || '') }).toMatchObject({ code: 0 });
    // 不得含未解析的占位符（如误写的 ${{ ... }）
    expect(src).not.toMatch(/\$\{\s*$/m);
  });

  test('存在且为手动触发（部署时机是人的判断，不能跟 push 绑定）', () => {
    expect(src).toMatch(/^\s*on:\s*$/m);
    expect(src).toMatch(/workflow_dispatch:/);
    // 若出现 push 触发，则 push 即上线——本项目不接受该行为
    const onBlock = src.slice(src.indexOf('on:'), src.indexOf('permissions:'));
    expect(onBlock).not.toMatch(/^\s{2}push:/m);
  });

  test('强制走 Environment（人工审批门的挂载点）', () => {
    // environment 必须出现在**两个部署 job** 上：只挂一个等于绕过另一条路径的审批
    for (const job of ['deploy-self-hosted', 'deploy-ssh']) {
      const block = jobBlock(job);
      expect({ job, hasEnv: /environment:/.test(block) }).toMatchObject({ job, hasEnv: true });
    }
    expect(src).toMatch(/environment:\s*\$\{\{\s*inputs\.environment\s*\}\}/);
  });

  test('镜像 tag 校验在前：preflight 先行，且两条部署路径都 needs 它', () => {
    for (const job of ['deploy-self-hosted', 'deploy-ssh']) {
      expect(jobBlock(job)).toMatch(/needs:\s*preflight/);
    }
    // 校验语句必须在 preflight 的 run 段里，不是注释里
    expect(runScriptOf('preflight')).toMatch(/exit 1/);
  });

  test(':local 标签必须被实际拦下（不能只写在注释里）', () => {
    // 【实证过的假绿】最初的写法是 `expect(pre).toMatch(/:local/)`，
    // 而 preflight 的**注释**里恰好有一句“不接受本地开发默认值 fire-safety-app:local”，
    // 于是把整段拦截语句删掉后用例**依然全绿**。
    // 现只在可执行的 run 段里取证，并锁住拦截后的退出码。
    const run = runScriptOf('preflight');
    expect(run).toMatch(/\*":local"/);
    expect(run).toMatch(/exit 1/);
    // 关键：拦截分支必须存在于 run 段（不是注释）
    const execLines = run
      .split('\n')
      .map((l) => l.trim())
      .filter((l) => l && !l.startsWith('#'));
    expect(execLines.some((l) => l.includes(':local') && l.includes('if'))).toBe(true);
  });

  test('没配部署凭据时不静默假绿（fail-closed）', () => {
    // 这是本工作流最危险的失效方式：“没配密钥 → 什么都没做 → 报绿”，
    // 人以为已发布。因此两条路径都必须有明确的前提强制。
    const selfHosted = jobBlock('deploy-self-hosted');
    expect(selfHosted).toMatch(/runs-on:\s*\[self-hosted,\s*deploy\]/);
    expect(selfHosted).toMatch(/if:\s*needs\.preflight\.outputs\.mode == 'self-hosted'/);
    const ssh = jobBlock('deploy-ssh');
    expect(ssh).toMatch(/if:\s*needs\.preflight\.outputs\.mode == 'ssh'/);
    // 两者互斥且必居一：mode 只有两个取值
    expect(src).toMatch(/echo "mode=ssh"/);
    expect(src).toMatch(/echo "mode=self-hosted"/);
  });

  test('密钥不进命令行（SSH key 走文件 + stdin，不直接拼进 ssh 参数）', () => {
    const ssh = jobBlock('deploy-ssh');
    // key 必须先写入文件并 chmod 600，再用 -i 引用
    expect(ssh).toMatch(/id_deploy/);
    expect(ssh).toMatch(/chmod 600/);
    expect(ssh).toMatch(/-i ~\/\.ssh\/id_deploy/);
    // 不得出现把密钥直接拼进命令的写法
    expect(ssh).not.toMatch(/ssh .*\$\{\{\s*secrets\.DEPLOY_SSH_KEY/);
    expect(ssh).not.toMatch(/--password|sshpass/);
  });

  test('真正调用 scripts/deploy.js（而不是在 workflow 里重写一遍部署判据）', () => {
    // 判据只能保留在一处：脚本里的前置校验/顺序/健康门禁已被
    // src/tests/deploy/deployScript.test.js 与 deployRun.test.js 覆盖；workflow 再实现一遍就会两处漂移。
    const selfHosted = jobBlock('deploy-self-hosted');
    const ssh = jobBlock('deploy-ssh');
    expect(selfHosted).toMatch(/node scripts\/deploy\.js/);
    expect(ssh).toMatch(/node scripts\/deploy\.js/);
    expect(selfHosted).toMatch(/APP_IMAGE:\s*\$\{\{\s*needs\.preflight\.outputs\.image_tag\s*\}\}/);
  });

  test('--dry-run / --skip-backup 能透传（且不会误传空参数）', () => {
    const selfHosted = jobBlock('deploy-self-hosted');
    expect(selfHosted).toMatch(/dry_run/);
    expect(selfHosted).toMatch(/skip_backup/);
    expect(selfHosted).toMatch(/--dry-run/);
    expect(selfHosted).toMatch(/--skip-backup/);
    // 参数必须先入数组再展开：直接拼串会产生空参数与引号问题
    expect(selfHosted).toMatch(/args\+=\(--dry-run\)/);
  });
});
