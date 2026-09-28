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

  test('compose 里每个 `:?` 变量都由两条部署路径下发（否则到切换那步才被拒）', () => {
    // 实证过的断裂链：compose 对 ALLOWED_HOSTS 用了 `${VAR:?}`，而本工作流只下发
    // CORS_ORIGIN；scripts/deploy.js 的前置校验当时也只查 CORS_ORIGIN。于是
    // 备份做完、迁移做完，才在 `docker compose up -d` 的插值阶段被拒——
    // 数据库已改写而版本没切。清单从 compose 反向推导，新增 `:?` 变量必须同步到这里。
    const yml = fs.readFileSync(path.join(ROOT, 'docker-compose.yml'), 'utf8');
    const hard = [...yml.matchAll(/\$\{([A-Z0-9_]+):\?/g)].map((m) => m[1]);
    // 前提自证：正则真的抓到硬声明项（抓空会让本用例恒绿）
    expect(hard.length).toBeGreaterThanOrEqual(2);

    for (const job of ['deploy-self-hosted', 'deploy-ssh']) {
      const block = jobBlock(job);
      for (const name of hard) {
        // 不用 $ 锚点：本仓库工作流是 CRLF，`\r` 会让行尾锚定的正则恒不匹配（实测过）
        const delivered = new RegExp(
          `^\\s+${name}: \\$\\{\\{\\s*secrets\\.${name}\\s*\\}\\}`,
          'm'
        ).test(block);
        expect({ job, name, delivered }).toMatchObject({ job, name, delivered: true });
      }
    }

    // SSH 路径还必须把它们列进 SendEnv：env 里有但没 SendEnv = 目标机收不到
    const sendEnv = (jobBlock('deploy-ssh').match(/SendEnv=([A-Za-z0-9_,-]+)/) || [])[1];
    expect(sendEnv).toBeTruthy();
    expect(sendEnv.split(',').sort()).toEqual([...hard].sort());
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

  /**
   * 收集全文件所有 `run: |` 块的行（含注释行，由调用方自行剔除）。
   * 不用 jobBlock+首个 run：一个 job 可能有多个 step，注入面必须整文件扫。
   */
  const allRunLines = () => {
    const lines = src.split(/\r?\n/);
    const out = [];
    let inRun = false;
    let runIndent = 0;
    for (const line of lines) {
      const head = /^(\s*)run: \|\S*\s*$/.exec(line);
      if (head) {
        inRun = true;
        runIndent = head[1].length;
        continue;
      }
      if (!inRun) continue;
      if (line.trim() === '') {
        out.push(line);
        continue;
      }
      if (line.match(/^\s*/)[0].length <= runIndent) {
        inRun = false;
        continue;
      }
      out.push(line);
    }
    return out;
  };

  test('前提：run 块扫描确实覆盖到脚本行（否则下面的零插值断言是空集假绿）', () => {
    const executable = allRunLines().filter((l) => l.trim() && !l.trim().startsWith('#'));
    expect(executable.length).toBeGreaterThan(20);
  });

  // GitHub 的 `${{ }}` 是**文本级**替换，早于 shell 解析与任何正则校验：
  // 写成 `tag="${{ inputs.image_tag }}"` 时，一个 `x" && id && "` 形态的输入
  // 就能在这个持有部署凭据的 runner 上执行任意命令（官方 script injection 口径）。
  // 唯一安全通道是 env: 赋值（env 值不参与 shell 文本展开）。
  test('所有 run 脚本内零 `${{ }}` 插值：外部值一律经 env 进入', () => {
    const interpolated = allRunLines()
      .filter((l) => !l.trim().startsWith('#') && l.includes('${{'))
      .map((l) => l.trim());
    expect(interpolated).toEqual([]);
  });

  test('镜像 tag 与两个开关都改走 env（正向锁住修复本身，而不是只锁"没有旧写法"）', () => {
    expect(src).toMatch(/INPUT_IMAGE_TAG: \$\{\{ inputs\.image_tag \}\}/);
    expect(src).toMatch(/tag="\$\{INPUT_IMAGE_TAG\}"/);
    expect(src).toMatch(/DRY_RUN: \$\{\{ inputs\.dry_run \}\}/);
    expect(src).toMatch(/SKIP_BACKUP: \$\{\{ inputs\.skip_backup \}\}/);
    expect(src).toMatch(/\[\[ "\$DRY_RUN" == "true" \]\]/);
  });

  /**
   * env 只是把注入时机从"文本替换那一刻"推到"拼远程命令那一刻"：
   * 校验后的 tag 仍要写进 `APP_IMAGE='<tag>' node scripts/deploy.js` 这句**单引号包裹**的
   * 远程命令里。仓库段字符集曾是 `.+`，`a/x';id;':latest` 完全通过校验，
   * 单引号提前闭合 ⇒ `id` 在持有部署凭据的目标机上执行。
   * 这里把正则从 yml 里抽出来当真值表跑（不是断言"源码里有某个字符串"）。
   */
  test('tag 校验正则必须拒掉一切能闭合远程单引号的字符', () => {
    const m = src.match(/=~ (\^\S+)\s+\]\]; then/);
    expect(m).not.toBeNull();
    const rx = new RegExp(m[1]);

    for (const ok of [
      'ghcr.io/acme/fire-safety-app:1.2.3',
      'registry.example.com:5000/org/app/release:sha-0a1b2c',
      'registry.local:5000/fire-safety/app:20260920',
    ]) {
      expect(rx.test(ok)).toBe(true);
    }
    for (const evil of [
      `a/x';id;':latest`,
      'a/x$(id):latest',
      'a/x`id`:latest',
      'a/x && reboot:t',
      'a/x;rm -rf /:latest',
      'a/x :latest',
      'a/x\n:latest',
    ]) {
      expect(rx.test(evil)).toBe(false);
    }
  });

  // 同一形状的第二个洞：DEPLOY_PATH 被单引号包进远程命令（cd '<path>'），
  // DEPLOY_USER/DEPLOY_HOST 合成 `user@host` 这一个 ssh argv。
  // 后者若为空或以 `-` 开头，ssh 的 getopt 会把它当选项吃下去
  // （-oProxyCommand=… ⇒ 在 runner 本机执行命令），所以首字符必须不是 `-`。
  // 三个 secret 都由仓库管理员设定，属"低可乘性"攻击面，但部署凭据不该依赖"管理员不会写错"。
  test('拼进 ssh 的三个 secret 都有字符集闸，且闸排在首次 ssh 之前', () => {
    const block = jobBlock('deploy-ssh');
    const patterns = [...block.matchAll(/=~ (\^\S+)\s+\]\]; then/g)].map((m) => m[1]);
    // 反向前提：抽到 3 条才说明三个 secret 各有一道闸；少一条就是漏了一个变量
    expect(patterns).toHaveLength(3);

    const [pathRx, userRx, hostRx] = patterns.map((s) => new RegExp(s));

    for (const ok of ['/srv/fsms', '/data/app-deploy', '/srv/a_b-c/', '/srv/fsms.1']) {
      expect(pathRx.test(ok)).toBe(true);
    }
    for (const bad of [
      `'/srv;id;'`,
      "/srv';id;'",
      '/srv/a b',
      '/srv;ls',
      '/srv/$(id)',
      '/srv/`id`',
      'srv/fsms',
      '',
      '/srv/a\nb',
    ]) {
      expect({ bad, hit: pathRx.test(bad) }).toEqual({ bad, hit: false });
    }

    for (const ok of ['deploy', 'app.user', 'svc_git', 'a-b', 'u1'])
      expect(userRx.test(ok)).toBe(true);
    // 反例必须**只能**被"首字符不得为 -"这条规则拒掉：
    // 写成 `-oProxyCommand=touch` 会被任何排除 `=` 的字符集拒掉，测不到前导 `-`（实测漏判一次）
    for (const bad of ['-oProxyCommand', '-x', '', 'a b', "a'b", 'a@b', '$(id)']) {
      expect({ bad, hit: userRx.test(bad) }).toEqual({ bad, hit: false });
    }
    for (const ok of ['deploy.example.com', 'host-1', '10.0.0.8'])
      expect(hostRx.test(ok)).toBe(true);
    for (const bad of ['-oProxyCommand', '-x', '', 'a b', '::1']) {
      expect({ bad, hit: hostRx.test(bad) }).toEqual({ bad, hit: false });
    }

    // 顺序：校验必须在第一条 ssh 之前，否则"合法字符集"的断言只是纸面
    const firstGate = block.search(/=~ \^\S+\s+\]\]; then/);
    const firstSsh = block.search(/^\s*ssh /m);
    expect(firstGate).toBeGreaterThan(-1);
    expect(firstSsh).toBeGreaterThan(firstGate);
    // 且 DEPLOY_PATH 必须真的出现在远程命令里（否则这道闸是死代码）
    expect(block).toMatch(/cd '\$DEPLOY_PATH'/);
  });

  // 部署编排是「备份 → 迁移 → 切镜像 → 健康门禁 → 失败自动回滚」。
  // 同一环境并发两个部署会互相踩：A 的回滚目标可能是 B 刚切上去的镜像。
  // cancel-in-progress 必须 false：跑到一半被取消会留下"迁移已执行、镜像未切换"的半程状态。
  test('按环境互斥，且不取消正在进行的部署', () => {
    const i = src.indexOf('\nconcurrency:');
    expect(i).toBeGreaterThan(-1);
    const block = src.slice(i, i + 260);
    expect(block).toMatch(/^concurrency:$/m);
    expect(block).toMatch(/group:\s*deploy-\$\{\{ inputs\.environment \}\}/);
    expect(block).toMatch(/cancel-in-progress:\s*false/);
  });
});
