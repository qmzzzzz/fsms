/**
 * 密钥载体的三条隔离闸（2026-10-03）
 *
 * 触发形态不是假想：`deployment/secret-rotation.md` 第 1 步把**新**全套密钥生成到
 * `./secrets-new`，第 4 步 `mv ./secrets ./secrets-old` 之后那里躺着**刚下线的全套生产密钥**。
 * 而 .gitignore 当时只有 `secrets/` 一条——目录名不同，一条都挡不住；本仓库是公开仓库
 * （github.com/qmzzzzz/fsms），轮换做完那天一次 `git add -A` 就把新旧两代真凭据推上去。
 * .dockerignore 同理：docker 的忽略模式按整段路径匹配，`secrets` 匹配不到 `secrets-new`。
 *
 * 三件事分别钉：
 *   1. **哪些目录会装凭据**由手册/compose 自己的文本决定（`--out <dir>` 与 `mv <src> <dst>`
 *      是唯二入口），不是写死一个清单——将来文档新起一个 `./secrets-staging` 而忘了忽略，
 *      本闸变红；写死清单的话它永远绿着，而漏的正是那个新名字。
 *   2. 判"是否被忽略"交给 **git 自己的解析器**（`git check-ignore`），不手写 gitignore 匹配。
 *      与 scripts/mongoUri.sh 同一条规矩：判据按参考解析器怎么读来定；手写规则与 git 的读法
 *      不一致时，失效方向恰好是"规则看起来覆盖到了、实际一个字节都没挡"。
 *      探针取**目录里的一个密钥文件名**（不是目录名），因为 `git add` 实际带走的是文件。
 *      一句自我纠正：原先这里写着"目录名探测会假绿"，实测三组形态（规则 `s/`、`s/`+反向
 *      `!s/jwt_secret`、文件先入 index 再补规则）里两种探针的命中结果**完全一致**，那句
 *      是没取证就下的结论；本闸的承重判据不是这条，而是下面第 3 点的 rc=1 两种形态。
 *   3. `generate-secrets.js` 的 `--out` 前置闸端到端跑真 git：在被忽略之前不落盘。
 *      这里断言的是脚本的真实行为（退出码 + 目录里到底有没有文件），不是源码里的某句 grep。
 *      rc=1 合并两种形态，两种都各有用例：没有规则命中它；规则有了但文件**已经在 index 里**
 *      （先 add 后补规则）。第二种尤其要紧——它正是"密钥已经进了公开仓库"的状态，
 *      所以判据刻意不加 `--no-index`（加了它就变 rc=0 而放行，实跑验证过危害）。
 */

'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const ROOT = path.resolve(__dirname, '../../..');
const GEN_SCRIPT = path.join(ROOT, 'scripts/generate-secrets.js');
// 生成器实际写出的第一个密钥文件名——git/docker 的探针都用它：目录规则必须连内容一起挡住
const SAMPLE_KEY = 'jwt_secret';

/** 会出现密钥载体目录名的文本：手册、compose 头注释、README、生成器自己的用法说明 */
const RUNBOOK_FILES = [
  'deployment/secret-rotation.md',
  'deployment/backup-encryption.md',
  'docker-compose.yml',
  'README.md',
  'scripts/generate-secrets.js',
];

const git = (args, cwd = ROOT) => spawnSync('git', args, { cwd, encoding: 'utf8' });

const requireGit = (r, what) => {
  if (r.error) throw new Error(`本机找不到 git，本闸无法执行（${what}）：${r.error.message}`);
  return r;
};

/**
 * 从文本收集"会装真凭据的目录名"。只认两个入口：`--out <dir>`（生成器的落盘口子）与
 * `mv <src> <dst>`（手册第 4 步的目录替换）。占位符形态（`--out <dir>`）与其它名词都被
 * "以 secrets 开头"这一步滤掉。
 */
function collectSecretDirs(text) {
  const names = new Set();
  const push = (raw) => {
    const name = String(raw)
      .replace(/^["']|["']$/g, '')
      .replace(/^\.\//, '');
    if (/^secrets[A-Za-z0-9_-]*$/.test(name)) names.add(name);
  };
  for (const m of text.matchAll(/--out\s+("[^"]+"|'[^']+'|\S+)/g)) push(m[1]);
  for (const m of text.matchAll(/\bmv\s+("[^"]+"|'[^']+'|\S+)\s+("[^"]+"|'[^']+'|\S+)/g)) {
    push(m[1]);
    push(m[2]);
  }
  return [...names];
}

const secretDirs = (() => {
  const text = RUNBOOK_FILES.map((f) => {
    const p = path.join(ROOT, f);
    if (!fs.existsSync(p)) throw new Error(`夹具前提失效：${f} 不存在，发现逻辑无从执行`);
    return fs.readFileSync(p, 'utf8');
  }).join('\n');
  const found = collectSecretDirs(text);
  if (found.length === 0) {
    throw new Error(
      '夹具前提失效：手册/compose 里一个密钥目录名都没抓到，下面的用例会因为集合为空而假绿'
    );
  }
  return found;
})();

/**
 * .dockerignore 的按行序求值：后面的模式（含 `!` 反选）覆盖前面的结论——这是 docker 自己的
 * 语义，写成"任一模式命中即忽略"会把 `!.env.example` 这类反选读成忽略。
 */
const DOCKER_PATTERNS = fs
  .readFileSync(path.join(ROOT, '.dockerignore'), 'utf8')
  .split(/\r?\n/)
  .map((l) => l.trim())
  .filter((l) => l !== '' && !l.startsWith('#'))
  .map((line) => {
    const negated = line.startsWith('!');
    const body = negated ? line.slice(1) : line;
    // 按 `**` 先切段（跨目录通配），段内再把单 `*` 换成"不跨 /"的通配：docker 走 Go 的
    // filepath.Match，单 `*` 确实不跨越目录分隔符。用切段而不是塞占位符——占位符要么用
    // 控制字符（eslint no-control-regex 直接报错），要么就可能撞进真实模式的字节里。
    const esc = (s) => s.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '[^/]*');
    return { negated, re: new RegExp(`^${body.split('**').map(esc).join('.*')}$`) };
  });

const dockerIgnored = (name) => {
  let ignored = false;
  for (const p of DOCKER_PATTERNS) {
    if (p.re.test(name)) ignored = !p.negated;
  }
  return ignored;
};

const mkTmp = (label) => fs.mkdtempSync(path.join(os.tmpdir(), `sec-carriers-${label}-`));

describe('git 侧：手册点到的每个密钥载体目录都被忽略（连里面的文件一起）', () => {
  test('发现逻辑有效：至少抓到 secrets 之外的目录名（否则下面的用例会因集合单一而漏掉本次的洞）', () => {
    // 本闸起因就是 `secrets-new`/`secrets-old` 这两个"非同名"目录没被覆盖。
    // 只测 `secrets` 会让发现逻辑退化成一个字面量匹配而看不出来。
    const beyondPlain = secretDirs.filter((d) => d !== 'secrets');
    expect(beyondPlain).not.toHaveLength(0);
  });

  test.each(secretDirs)('%s 里的密钥文件必须命中忽略规则（git 自己的判定）', (dir) => {
    const r = requireGit(git(['check-ignore', '-v', '--', `${dir}/${SAMPLE_KEY}`]), 'check-ignore');
    expect({ dir, status: r.status, out: r.stdout.trim() }).toEqual(
      expect.objectContaining({ dir, status: 0 })
    );
    // 必须点名是哪条规则挡住的：没有规则行的 rc=0 形态不属于"被忽略"
    expect(r.stdout).toMatch(
      /\.gitignore:\d+|\.git\/info\/exclude|core\.excludesFile|command line/
    );
  });

  test('反向自证：没被忽略的目录在同一条命令下回 1（探测器不是恒 0）', () => {
    const r = requireGit(
      git(['check-ignore', '-v', '--', `zz-not-ignored-${Date.now()}/${SAMPLE_KEY}`])
    );
    // 1 = 在仓库内且未被忽略；128 = 判不了。这里必须正好是 1，否则上面那批 rc=0 说明不了什么。
    expect(r.status).toBe(1);
  });

  test('仓库里没有任何已跟踪的密钥载体文件（公开仓库，历史也不能带）', () => {
    const r = requireGit(git(['ls-files']));
    const strays = r.stdout.split(/\r?\n/).filter((f) => /(^|\/)secrets(-[^/]*)?\//.test(f));
    expect(strays).toEqual([]);
  });
});

describe('.dockerignore 侧：同一批目录不进构建上下文', () => {
  // 这里只判**目录名本身**是否被模式命中，不去判 `secrets-new/jwt_secret` 这种子路径：
  // docker 的真实语义是"目录被排除 ⇒ 整棵子树都不进上下文"，要在测试里复现这套求值
  // （含父目录排除后子项反选无效那个坑）就等于自己写一个第二解析器——而那正是本文件
  // 头注释里要避免的事。git 那一侧没有这个问题：判据是 git 自己给的，所以能拿子路径探针。
  test.each(secretDirs)('%s 被 .dockerignore 覆盖', (dir) => {
    expect({ dir, ignored: dockerIgnored(dir) }).toMatchObject({ dir, ignored: true });
  });

  test('匹配器读得懂反选：.env 被忽略而 .env.example 被放回（否则"任一模式命中"就是假阴）', () => {
    expect(dockerIgnored('.env')).toBe(true);
    expect(dockerIgnored('.env.example')).toBe(false);
    // 单 * 不跨目录分隔符：web-admin/secrets 这种带路径的形态不该被裸 `secrets` 规则命中
    expect(dockerIgnored('somewhere-else')).toBe(false);
  });
});

describe('generate-secrets.js 的 --out 前置闸（端到端跑真 git）', () => {
  let dirs = [];
  const tmp = () => {
    const d = mkTmp('run');
    dirs.push(d);
    return d;
  };
  afterEach(() => {
    for (const d of dirs) fs.rmSync(d, { recursive: true, force: true });
    dirs = [];
  });

  const runGen = (outDir, extra = []) =>
    spawnSync(process.execPath, [GEN_SCRIPT, '--out', outDir, ...extra], { encoding: 'utf8' });

  test('目标在一个 git 仓库内且未被忽略 ⇒ 生成前就拒绝，且一个文件都不落', () => {
    const repo = tmp();
    requireGit(git(['init', '-q'], repo), 'git init');
    const target = path.join(repo, 'keys'); // 故意不起名为 secrets*：本条测的是 git 的判定而非名字
    const r = runGen(target);
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/不认它是被忽略的/);
    expect(r.stderr).toMatch(/没有 \.gitignore 规则命中/);
    expect(fs.existsSync(target)).toBe(false);
    // 拒绝信息不回显任何密钥值
    expect(r.stdout + r.stderr).not.toMatch(/BEGIN [A-Z ]*PRIVATE KEY|jwt_secret=/);
  });

  test('规则写了、但密钥文件已经在 index 里 ⇒ 照样拒绝（这条钉住"不加 --no-index"）', () => {
    // 实测形态（`git check-ignore -v` 对目录名与文件名探针给同一个 rc=1）：先 `git add`、
    // 事后才补 .gitignore 时，git 对已在 index 里的路径一律不再报"已忽略"。
    // 为什么这里必须拒而不是放行：加 `--no-index` 会让这种形态变成 rc=0，于是生成器把
    // **新一套**真凭据写进一个"上一套已经进了版本库"的目录——那次拒绝是现场唯一的声音，
    // 而公开仓库里的那一份才是真正要处理的事。所以本条同时是"不许顺手加 --no-index"的 mutation 闸。
    // 这条 mutation 实跑过：给 execFileSync 的参数加上 `--no-index` 后，前置检查 A 放行，
    // 而 `--force` 一路 rc=0 把已入库那颗 `jwt_secret` 覆盖成了新生成的随机值
    // （仓库历史里是一份、工作目录里是另一份，且再没有任何一环报警）。
    // 上面那句"已有密钥 ⇒ 拒绝"（前置检查 B）在这条 mutation 下恰好也红，但它守的是
    // 代次一致性、不是入库风险，且 `--force` 直接绕过它——所以真正承重的是最后那条 --force。
    const repo = tmp();
    requireGit(git(['init', '-q'], repo), 'git init');
    const target = path.join(repo, 'keys');
    fs.mkdirSync(target);
    fs.writeFileSync(path.join(target, SAMPLE_KEY), 'already-in-the-repo\n', 'utf8');
    const added = git(['add', path.join('keys', SAMPLE_KEY)], repo);
    requireGit(added, 'git add');
    expect(added.status).toBe(0);
    expect(git(['ls-files'], repo).stdout).toContain(SAMPLE_KEY); // 前提自证：确实进 index 了
    fs.writeFileSync(path.join(repo, '.gitignore'), 'keys/\n', 'utf8'); // 规则**事后**才补

    const r = runGen(target);
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/已经在 index 里/);
    // 已入库那颗不能被覆盖：拒绝发生在 mkdir/写入之前，旧字节必须原样还在
    expect(fs.readFileSync(path.join(target, SAMPLE_KEY), 'utf8')).toBe('already-in-the-repo\n');
    // 出路不是"再试一次"：话术必须把它当失陷事件，而不是一个可以用 --force 拧开的开关
    expect(r.stderr).toMatch(/git rm --cached/);
    expect(runGen(target, ['--force']).status).toBe(1);
  });

  test('反向自证：给那个仓库写上忽略规则之后，同一个目标就放行并整套落地', () => {
    // 上一条的红不来自"脚本见谁都拒"：同一目录、同一命令，只是 .gitignore 多了一行。
    const repo = tmp();
    requireGit(git(['init', '-q'], repo), 'git init');
    fs.writeFileSync(path.join(repo, '.gitignore'), 'keys/\n', 'utf8');
    const target = path.join(repo, 'keys');
    const r = runGen(target);
    expect({ status: r.status, stderr: r.stderr.slice(0, 200) }).toMatchObject({ status: 0 });
    expect(fs.existsSync(path.join(target, SAMPLE_KEY))).toBe(true);
    expect(fs.existsSync(path.join(target, 'mongodb_uri'))).toBe(true);
  });

  test('目录里已有密钥时不再"缺哪个补哪个"：第二次运行拒绝，--force 才重做整套', () => {
    // 混合代次的实际形状：mongodb_uri 是把 mongo_root_password 拼进去生成的。
    // 上一代的密码 + 这一代的 URI 同时躺在"新代次"目录里 ⇒ mongo 用旧口令建用户、
    // 应用用对不上号的连接串连库，轮换"成功"结束后第一次连库就认证失败。
    // 用仓库外的临时目录：这里的判点是前置检查 B，不是忽略规则。
    const target = path.join(tmp(), 'secrets');
    const first = runGen(target);
    expect(first.status).toBe(0);
    const second = runGen(target);
    expect(second.status).toBe(1);
    expect(second.stderr).toMatch(/已经有/);
    expect(second.stderr).toMatch(/mongodb_uri/);
    expect(second.stdout + second.stderr).not.toMatch(/BEGIN [A-Z ]*PRIVATE KEY/);
    // --force 重做整套之后，"同一代次"这条不变量必须真的成立：mongodb_uri 里拼的就是
    // 同目录那份 mongo_root_password。之所以现场验一次：整条前置检查 B 的理由就是这一对
    // 字段的耦合，把它写成注释而不测，下一个改动生成器的人看不见承重墙。
    const forced = runGen(target, ['--force']);
    expect({ status: forced.status, stderr: forced.stderr.slice(0, 200) }).toMatchObject({
      status: 0,
    });
    const pw = fs.readFileSync(path.join(target, 'mongo_root_password'), 'utf8');
    const uri = fs.readFileSync(path.join(target, 'mongodb_uri'), 'utf8');
    expect(uri).toContain(encodeURIComponent(pw));
  });
});
