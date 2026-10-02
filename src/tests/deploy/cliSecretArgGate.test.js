/**
 * 密钥类命令行选项只能是「路径」形态：值一律不许上 argv
 *
 * 缺陷本体：`--new-key <KEY>` 让同一个密钥同时出现在
 *   · `/proc/<pid>/cmdline`（Linux 默认 0444 ⇒ 同机任意本地用户可读；一次全量迁移跑几分钟，
 *     窗口足够长），`ps(1)` / 任务管理器同理；
 *   · shell 历史（`HISTCONTROL=ignorespace` 是"记得加空格"的人为约定，不是机制）；
 *   · 任何 `set -x` 的 CI 日志。
 * 仓里其余密钥早已统一成 `<NAME>_FILE`，只有密钥轮换这一族还留着 argv 形态——
 * 同一门安全要求上的两个标准。现在两个脚本只收 `--new-key-file`/`--old-key-file`，
 * 旧的 argv 形态改成**具名拒绝**（exit 2 + 指向替代写法）。
 *
 * 三层判据，一层比一层强：
 * 1. 静态完备性（派生枚举，不写字面量清单）：任何"从 argv 取值"的密钥类选项必须以 `-file` 结尾；
 *    任何文档命令里出现的密钥类选项必须是该脚本确实接受的那个。于是新写第三个轮换脚本时
 *    这条闸自动对它提要求，而不需要有人记得来登记。
 * 2. 行为闸（canary）：真起子进程传 `--new-key <CANARY>`，断言 exit 2、点名替代写法、
 *    **CANARY 一个字节都不许出现在 stdout/stderr**，且不出现"已连接"（拒绝早于连库）。
 *    这一层是"具名拒绝"分支存在的理由：默认分支 `未知参数：${argv[i]}` 会打印 argv[i]，
 *    而循环下一步就是那个密钥本身——报错本身就成了第二次泄漏。
 * 3. 读文件的形状判据：单行、去 BOM/CR、多行或含空白即硬失败；`--*-file` 优先于环境变量。
 *
 * 为什么不但管脚本、还要管文档：手册里一条 `--new-key "$NEW" --apply` 是**可复制执行**的东西，
 * 运维照抄会得到 exit 2，下一步往往是"把护栏关掉"——文档漂移能把 fail-closed 反噬成更危险的操作
 * （与 runbookApplyCommandContract 同一条教训）。
 * CHANGELOG 里"移除了 `--new-key`"这种散文不在判据内：本闸只认 `node scripts/…` 形态的命令行。
 */

'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');

const ROOT = path.resolve(__dirname, '../../..');
const SCRIPTS = path.join(ROOT, 'scripts');
const NODE = process.execPath;

/** 名字本身就带着秘密的选项（key/secret/password/token/uri/dsn/credential/salt） */
const SECRET_OPT = /key|secret|passw|token|uri|dsn|credential|salt/i;
/** 只接受「路径」的形态约定 */
const FILE_FORM = /-file$/;

/**
 * 「这个选项从 argv 取了一个值」的判据：`argv[i] === '--x'` 之后紧跟 `argv[++i]`。
 * 60 字符窗口是刻意的：具名拒绝分支后面跟着整段 console.error，窗口内取不到 argv[++i]，
 * 于是"拒绝 --new-key"不会被误判成"还在收密钥"。
 */
const VALUE_OPT_RE = /argv\[\s*i\s*\]\s*===\s*'(--[a-z0-9-]+)'[\s\S]{0,60}?argv\[\s*\+\+i\s*\]/g;

/** 递归列 scripts 下的 .js/.cjs：audit-probes 用的是 .cjs，只收 .js 会漏掉整个子目录 */
function listScripts(dir) {
  const out = [];
  for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
    if (ent.name === 'node_modules' || ent.name.startsWith('.')) continue;
    const abs = path.join(dir, ent.name);
    if (ent.isDirectory()) out.push(...listScripts(abs));
    else if (/\.(js|cjs)$/.test(ent.name))
      out.push(path.relative(ROOT, abs).split(path.sep).join('/'));
  }
  return out;
}

function argvValueOptions(src) {
  VALUE_OPT_RE.lastIndex = 0;
  return [...src.matchAll(VALUE_OPT_RE)].map((m) => m[1]);
}

/** 脚本 → 它从 argv 取的密钥类选项（含不合规的，供判据自己筛） */
const secretOptionsByScript = new Map();
for (const rel of listScripts(SCRIPTS)) {
  const flags = argvValueOptions(fs.readFileSync(path.join(ROOT, rel), 'utf8')).filter((f) =>
    SECRET_OPT.test(f.slice(2))
  );
  if (flags.length > 0) secretOptionsByScript.set(rel, flags);
}
/** 文档命令里允许的形态：脚本确实接受的 `-file` 选项 */
const acceptedByScript = new Map(
  [...secretOptionsByScript].map(([rel, flags]) => [rel, flags.filter((f) => FILE_FORM.test(f))])
);

function acceptedFor(citedScript) {
  const rel = [...acceptedByScript.keys()].find(
    (k) => k === `scripts/${citedScript}` || k.endsWith(`/${citedScript}`)
  );
  return rel ? acceptedByScript.get(rel) : [];
}

const joinContinuations = (text) => text.replace(/\\\r?\n\s*/g, ' ');
const DOC_FILES = ['README.md', 'CHANGELOG.md'];
for (const dir of ['docs', 'deployment']) {
  const abs = path.join(ROOT, dir);
  if (fs.existsSync(abs)) {
    for (const f of fs.readdirSync(abs)) if (f.endsWith('.md')) DOC_FILES.push(`${dir}/${f}`);
  }
}

/** 从文档里抽出"可复制执行的 node scripts/… 命令"及其密钥类选项 */
const docCommands = [];
for (const rel of DOC_FILES) {
  const abs = path.join(ROOT, rel);
  if (!fs.existsSync(abs)) continue;
  for (const line of joinContinuations(fs.readFileSync(abs, 'utf8')).split(/\r?\n/)) {
    const m = line.match(/node\s+scripts\/([\w./-]+\.js)([^\n]*)/);
    if (!m) continue;
    const flags = [...m[2].matchAll(/(?:^|\s)(--[a-z0-9][a-z0-9-]*)/g)]
      .map((x) => x[1])
      .filter((f) => SECRET_OPT.test(f));
    if (flags.length === 0) continue;
    docCommands.push({ origin: rel, script: m[1], flags, line: line.trim() });
  }
}

const badDocFlags = (item) => item.flags.filter((f) => !acceptedFor(item.script).includes(f));

// ── 行为闸夹具：一个真密钥文件 + 一个绝不该出现在任何输出里的 canary ──
const KEY_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'fsms-cli-secret-'));
const KEY_VALUE = crypto.randomBytes(32).toString('hex');
const KEY_FILE = path.join(KEY_DIR, 'hmac_new');
const CANARY = crypto.randomBytes(32).toString('hex');
fs.writeFileSync(KEY_FILE, `${KEY_VALUE}\n`);

/** 子进程环境：把两处 argv 兜底用的环境变量清空，保证"值只能从命令行来" */
function baseEnv(extra) {
  return {
    ...process.env,
    HMAC_SECRET: '11'.repeat(32),
    AES_SECRET_KEY: '11'.repeat(32),
    NEW_HMAC_SECRET: '',
    NEW_AES_SECRET_KEY: '',
    ...extra,
  };
}

function run(script, argv, env) {
  const r = spawnSync(NODE, [path.join(ROOT, 'scripts', script), ...argv], {
    cwd: ROOT,
    encoding: 'utf8',
    timeout: 30000,
    env: baseEnv(env),
  });
  return { code: r.status, out: `${r.stdout || ''}${r.stderr || ''}` };
}

afterAll(() => {
  fs.rmSync(KEY_DIR, { recursive: true, force: true });
});

describe('密钥类 argv 选项的静态判据', () => {
  test('前提自证：判据集非空，且全部已是 -file 形态（否则本套件在自证空气）', () => {
    expect(secretOptionsByScript.size).toBeGreaterThanOrEqual(2);
    expect([...acceptedByScript.keys()].sort()).toEqual(
      ['scripts/migrate-mfa-secret.js', 'scripts/resign-audit-hmac.js'].sort()
    );
    expect([...acceptedByScript.values()].flat().sort()).toEqual([
      '--new-key-file',
      '--new-key-file',
      '--old-key-file',
    ]);
    // 文档侧同样要有料：真存在带密钥选项的手册命令，否则第 3 条用例是空集恒真
    expect(docCommands.length).toBeGreaterThanOrEqual(4);
  });

  test.each([...secretOptionsByScript].map(([rel, flags]) => [rel, flags]))(
    '%s：从 argv 取值的密钥类选项必须只收路径',
    (rel, flags) => {
      const offenders = flags.filter((f) => !FILE_FORM.test(f));
      expect({ rel, flags, offenders }).toEqual({ rel, flags, offenders: [] });
    }
  );

  test.each(docCommands.map((c) => [`${c.origin} → ${c.script}`, c]))(
    '%s：手册里的密钥选项必须是脚本确实接受的 -file 选项',
    (_label, item) => {
      expect({ origin: item.origin, line: item.line, bad: badDocFlags(item) }).toEqual({
        origin: item.origin,
        line: item.line,
        bad: [],
      });
    }
  );

  test('判据有牙：合成违规 + 真文件减法都必须被点亮', () => {
    const mk = (flag) =>
      `function p(argv){for(let i=2;i<argv.length;i+=1){if (argv[i] === '${flag}') args.k = argv[++i];}}`;
    // 违规形态：密钥值直接上 argv
    expect(argvValueOptions(mk('--new-key'))).toEqual(['--new-key']);
    expect(argvValueOptions(mk('--db-password')).includes('--db-password')).toBe(true);
    // 合规形态与非密钥形态
    expect(FILE_FORM.test(argvValueOptions(mk('--new-key-file'))[0])).toBe(true);
    expect(SECRET_OPT.test('out')).toBe(false);
    // 真文件减法：把 scripts/resign-audit-hmac.js 的 --new-key-file 改回 --new-key，静态判据必须红
    const real = fs.readFileSync(path.join(ROOT, 'scripts/resign-audit-hmac.js'), 'utf8');
    const reverted = secretOptionsByScript.get('scripts/resign-audit-hmac.js').map((f) => f);
    expect(reverted).toEqual(['--new-key-file']);
    const drift = argvValueOptions(real.replace("'--new-key-file'", "'--new-key'")).filter((f) =>
      SECRET_OPT.test(f.slice(2))
    );
    expect(drift).toEqual(['--new-key']);
    // 文档减法：把手册命令的 -file 去掉，第 3 条用例的判据必须报出来
    const docItem = { origin: 'synthetic', script: 'resign-audit-hmac.js', flags: ['--new-key'] };
    expect(badDocFlags(docItem)).toEqual(['--new-key']);
    expect(
      badDocFlags({ origin: 'x', script: 'resign-audit-hmac.js', flags: ['--new-key-file'] })
    ).toEqual([]);
    // 未被任何脚本接受的密钥选项也不许出现在文档命令里（防"给不接密钥的脚本硬塞一个"）
    expect(
      badDocFlags({ origin: 'x', script: 'verify-audit-chain.js', flags: ['--hmac-key'] })
    ).toEqual(['--hmac-key']);
  });
});

describe('行为闸：argv 形态的密钥必须被拒绝，且拒绝时不许把值再打一遍', () => {
  // 用例标题只点名选项，不带 canary：把值打进测试输出等于在另一个地方复现同一个泄漏形状
  test.each([
    ['resign-audit-hmac.js', '--new-key', ['--new-key', CANARY, '--apply', '--yes']],
    ['migrate-mfa-secret.js', '--new-key', ['--new-key', CANARY, '--apply']],
    ['migrate-mfa-secret.js', '--old-key', ['--old-key', CANARY, '--apply']],
  ])('%s 收到 %s ⇒ exit 2、点名替代写法、canary 不落输出', (script, flag, argv) => {
    const { code, out } = run(script, argv);
    expect(code).toBe(2);
    // 具名拒绝：报错里必须有被移除的选项名与替代写法，否则运维只能猜
    expect(out).toContain(flag);
    expect(out).toContain(`${flag}-file`);
    // 核心判据：错误信息把密钥再打一遍 = 把泄漏从 argv 换成 stdout/CI 日志
    expect(out).not.toContain(CANARY);
    // 拒绝早于连库：不该有连接痕迹（被拒绝的执行不去碰目标库）
    expect(out).not.toContain('已连接');
  });

  test('--new-key-file 真被接受：文件内容进了内存，但一个字节都不进输出', () => {
    // 环境变量给一个**不同**的值，顺带钉住"--*-file 优先于环境变量"这条优先级
    const { code, out } = run('resign-audit-hmac.js', ['--new-key-file', KEY_FILE], {
      NEW_HMAC_SECRET: '22'.repeat(32),
    });
    expect(code).toBe(0);
    expect(out).toContain('预检分类');
    expect(out).toContain('同时存在');
    expect(out).not.toContain(KEY_VALUE);
    expect(out).not.toContain('22'.repeat(32));
  });

  test('--new-key-file 指向不存在的路径 ⇒ exit 2、点名路径、不连库', () => {
    const missing = path.join(KEY_DIR, 'does_not_exist');
    const { code, out } = run('resign-audit-hmac.js', ['--new-key-file', missing]);
    expect(code).toBe(2);
    expect(out).toContain('does_not_exist');
    expect(out).not.toContain('已连接');
  });
});

describe('readSecretFile / resolveSecretSource 的形状判据', () => {
  const { readSecretFile, resolveSecretSource } = require(
    path.join(ROOT, 'scripts', 'secretFileArg.js')
  );

  const write = (name, body) => {
    const p = path.join(KEY_DIR, name);
    fs.writeFileSync(p, body);
    return p;
  };

  test('去掉 BOM 与 CR/尾换行，取到的就是密钥本身', () => {
    expect(readSecretFile(write('ok_lf', `${KEY_VALUE}\n`), '测试密钥')).toBe(KEY_VALUE);
    expect(readSecretFile(write('ok_bom', `\uFEFF${KEY_VALUE}\r\n`), '测试密钥')).toBe(KEY_VALUE);
    expect(readSecretFile(write('ok_pad', `  ${KEY_VALUE}  \n`), '测试密钥')).toBe(KEY_VALUE);
  });

  test('形状不认识就硬失败，绝不"取第一条非空行"蒙过去', () => {
    expect(() => readSecretFile(write('two', `${KEY_VALUE}\nsecond\n`), '测试密钥')).toThrow(
      /1 行/
    );
    expect(() => readSecretFile(write('empty', '\n \n'), '测试密钥')).toThrow(/0 行/);
    expect(() => readSecretFile(write('mid', 'ab cd\n'), '测试密钥')).toThrow(/不可打印字符/);
    expect(() => readSecretFile(write('wide', '密钥密钥密钥\n'), '测试密钥')).toThrow(/环境变量/);
    expect(() => readSecretFile('', '测试密钥')).toThrow(/路径为空/);
    // 报错只点名标签与路径：把内容抄进错误信息等于换个地方泄漏
    const msg = (() => {
      try {
        readSecretFile(write('two2', `${KEY_VALUE}\nsecond\n`), '测试密钥');
        return '';
      } catch (e) {
        return e.message;
      }
    })();
    expect(msg).toContain('two2');
    expect(msg).not.toContain(KEY_VALUE);
  });

  test('来源优先级：显式 --*-file 赢过环境变量，且两者都给时只点名不取值', () => {
    const warns = [];
    const spy = jest.spyOn(console, 'error').mockImplementation((...a) => warns.push(a.join(' ')));
    try {
      const p = write('prio', 'from-file-value\n');
      expect(
        resolveSecretSource({
          filePath: p,
          envValue: 'from-env',
          label: 'K',
          flagName: '--k-file',
          envName: 'K',
        })
      ).toBe('from-file-value');
      expect(warns.join('\n')).toContain('同时存在');
      expect(warns.join('\n')).not.toContain('from-env');
      warns.length = 0;
      expect(
        resolveSecretSource({
          filePath: undefined,
          envValue: 'from-env',
          label: 'K',
          flagName: '--k-file',
          envName: 'K',
        })
      ).toBe('from-env');
      expect(warns).toEqual([]);
      expect(() =>
        resolveSecretSource({
          filePath: undefined,
          envValue: '',
          label: 'K',
          flagName: '--k-file',
          envName: 'K',
        })
      ).toThrow(/--k-file/);
      expect(() =>
        resolveSecretSource({
          filePath: undefined,
          envValue: '',
          label: 'K',
          flagName: '--k-file',
          envName: 'K',
        })
      ).toThrow(/K 环境变量/);
    } finally {
      spy.mockRestore();
    }
  });
});
