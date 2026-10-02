/**
 * scripts/capture-image-digests.sh 的行为回归（供应链钉版脚本）
 *
 * 这个脚本的职责是**供应链完整性**：把 Dockerfile / compose 的基础镜像从可变 tag
 * 换成 registry digest。它的失效形态恰好都是"看起来成功"：
 *   - `sed` 没匹配到任何内容时退出码仍是 0 ⇒ 已钉过之后再跑一次会报"已替换"而一字未改；
 *     而 Dockerfile 里的 tag 若与脚本顶部常量漂移，同样静默跳过 ⇒ 未钉版的镜像引用
 *     被当成"已按 digest 固定"提交上去；
 *   - `docker inspect --format='{{index .RepoDigests 0}}'` 对 build/load 来的镜像
 *     可能返回 `<no value>` 或空 ⇒ 直接写进 Dockerfile 会得到 `FROM <no value>`，
 *     失败推迟到构建期，且现场看起来"已经钉过版"；
 *   - "边检查边落笔、两个目标顺序跑"会留下**半钉仓库**（Dockerfile 已改、compose 仍指向
 *     可变 tag），而且此后唯一能修它的脚本自己拒绝再跑；`sed > tmp; mv tmp file` 还会
 *     把上一次中断留下的同名临时文件**静默吞掉**。
 * 全部由真跑证明（PATH 里插 docker stub），不用扫源码文本 —— 同仓 backup-mongo.sh
 * 的既有覆盖就是文本契约，证明不了任何运行时行为。
 *
 * 平台前提：需要 POSIX sh；探测不到时整组显式跳过并打印原因（CI ubuntu 真跑）。
 */

'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const ROOT = path.resolve(__dirname, '../..');
const SCRIPT = path.join(ROOT, 'scripts', 'capture-image-digests.sh');

function findShell() {
  for (const c of ['/bin/sh', 'sh', 'C:/Program Files/Git/bin/sh.exe', 'bash']) {
    const r = spawnSync(c, ['-c', 'exit 0'], { encoding: 'utf8' });
    if (!r.error && r.status === 0) return c;
  }
  return null;
}
const SH = findShell();
if (!SH) {
  console.warn(
    '[跳过] 未找到 POSIX sh：capture-image-digests.sh 的行为用例在本平台无法执行（CI ubuntu 会跑）'
  );
}

const group = SH ? describe : describe.skip;

const HEX_A = 'a'.repeat(64);
const HEX_B = 'b'.repeat(64);
const NODE_REF = `node@sha256:${HEX_A}`;
const MONGO_REF = `mongo@sha256:${HEX_B}`;

/** docker 替身：按模式返回正常 digest / `<no value>` / 空；并把调用记进日志 */
const DOCKER_STUB = `#!/bin/bash
echo "docker $*" >> "$STUB_LOG"
sub="$1"
case "$sub" in
  info) exit 0 ;;
  pull) exit 0 ;;
  inspect)
    case "$DOCKER_STUB_MODE" in
      novalue) echo "<no value>" ;;
      empty)   echo "" ;;
      wrongarch) echo "node@sha256:short" ;;
      *)
        case "$*" in
          *node:*) echo "${NODE_REF}" ;;
          *)       echo "${MONGO_REF}" ;;
        esac
    esac
    exit 0 ;;
esac
exit 0
`;

const tracked = [];
afterAll(() => {
  for (const d of tracked) fs.rmSync(d, { recursive: true, force: true });
});

/**
 * 零串扰自检：本套件跑的是一个**会改文件**的脚本，而它的默认 ROOT 是脚本自身的仓库根。
 * 实测踩过：一次漏传 --root 的 --apply 把假 digest 直接写进了真实 Dockerfile
 * 与 docker-compose.yml（3 处 FROM + 1 处 image + 1 处注释），当场靠 git diff 定位后
 * 定点复原。所以这里把"没有碰到真实文件"变成断言，而不是靠我记得传参。
 */
const REAL_TARGETS = ['Dockerfile', 'docker-compose.yml'];
const realSha = () =>
  Object.fromEntries(
    REAL_TARGETS.map((f) => [f, fs.readFileSync(path.join(ROOT, f)).toString('base64')])
  );
let realBefore;
beforeAll(() => {
  realBefore = realSha();
});
afterAll(() => {
  expect(realSha()).toEqual(realBefore);
});

/** 造一个仓库副本夹具：两阶段 Dockerfile + 含 mongo 的 compose */
function fixture() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'digests-'));
  tracked.push(dir);
  const bin = path.join(dir, 'bin');
  fs.mkdirSync(bin);
  const dockerPath = path.join(bin, 'docker');
  fs.writeFileSync(dockerPath, DOCKER_STUB, { mode: 0o755 });
  try {
    fs.chmodSync(dockerPath, 0o755);
  } catch (_) {
    /* Windows 上 mode 参数已足够 */
  }
  const dockerfile =
    'FROM node:22.14.0-alpine AS builder\nRUN echo build\n' +
    'FROM node:22.14.0-alpine AS runner\nUSER nodejs\n';
  // 注释里也放一份同样的字面串：真实 compose 就是这样（"把输出追加为
  // `image: mongo:6.0.20@sha256:<捕获值>`"），用来验"只改指令行、不改注释"。
  const compose =
    'services:\n  mongo:\n    # 用法示例：image: mongo:6.0.20@sha256:<捕获值>\n' +
    '    image: mongo:6.0.20\n  app:\n    image: x\n';
  fs.writeFileSync(path.join(dir, 'Dockerfile'), dockerfile, 'utf8');
  fs.writeFileSync(path.join(dir, 'docker-compose.yml'), compose, 'utf8');
  return { dir, log: path.join(dir, 'argv.log'), dockerfile, compose };
}

function run(fx, args, mode = 'good') {
  // 防呆：任何会改文件的调用都被强制隔离到夹具目录，除非该次调用显式给了 --root
  const withRoot = args.some((a) => a.startsWith('--root=')) ? args : ['--root=<ROOT>', ...args];
  const env = {
    ...process.env,
    PATH: `${path.join(fx.dir, 'bin')}${path.delimiter}${process.env.PATH}`,
    STUB_LOG: fx.log,
    DOCKER_STUB_MODE: mode,
  };
  const r = spawnSync(SH, [SCRIPT, ...withRoot.map((a) => a.replace('<ROOT>', fx.dir))], {
    env,
    encoding: 'utf8',
  });
  return {
    code: r.status,
    out: (r.stdout || '') + (r.stderr || ''),
    dockerfile: fs.readFileSync(path.join(fx.dir, 'Dockerfile'), 'utf8'),
    compose: fs.readFileSync(path.join(fx.dir, 'docker-compose.yml'), 'utf8'),
    // 临时文件也是产物的一部分：它既是"预演过"的证据，也是下一次运行的门禁
    // （脚本拒绝覆盖已存在的同名文件）。失败矩阵用"应当为空"、
    // 残留用例用"应当看得见"，两边共用同一个过滤器 ⇒ 见下面那条非空集自证。
    tmps: fs
      .readdirSync(fx.dir)
      .filter((f) => f.endsWith('.pin.tmp'))
      .sort(),
    calls: fs.existsSync(fx.log)
      ? fs.readFileSync(fx.log, 'utf8').split(/\r?\n/).filter(Boolean)
      : [],
  };
}

/** 只把 compose 的 mongo **指令行**换成常量表里没有的 tag（注释里那份演示保持原样） */
const driftCompose = (src) => src.replace(/^ {4}image: mongo:6\.0\.20$/m, '    image: mongo:9.9.9');
const driftComposeTag = (fx) =>
  fs.writeFileSync(path.join(fx.dir, 'docker-compose.yml'), driftCompose(fx.compose), 'utf8');
const driftDockerfileTag = (fx) =>
  fs.writeFileSync(
    path.join(fx.dir, 'Dockerfile'),
    fx.dockerfile.replace(/node:22\.14\.0-alpine/g, 'node:22.99.9-alpine'),
    'utf8'
  );
const noMutation = () => {};

/**
 * 所有可达失败臂的**共同后置条件**：两个目标各自保持"本次运行开始前"的字节，
 * 目录里没有 `*.pin.tmp`（失败不许留 litter，成功也不留——见成功用例）。
 * 基准取"变异之后"的内容而不是夹具原文：漂移用例改的就是被检查的那个文件，
 * 拿夹具原文当基准会把"脚本没动"和"脚本把它改了回去"混成一条。
 *
 * 行宽必须等于处理函数的形参个数：jest-each 少喂一格会把 `done` 当成第 N 个实参注入，
 * 用例既不通过也不失败，而是卡满 30s 超时（本仓实测踩过）。下面那条"表宽"用例钉住它。
 */
const failureArms = [
  ['Dockerfile tag 漂移', driftDockerfileTag, 'good', ['--apply']],
  ['compose tag 漂移', driftComposeTag, 'good', ['--apply']],
  ['digest 取不到（<no value>）', noMutation, 'novalue', ['--apply']],
  ['digest 长度不足（伪 digest）', noMutation, 'wrongarch', ['--apply']],
  ['未知参数', noMutation, 'good', ['--aply']],
];

function checkFailure(_label, mutate, mode, args) {
  const fx = fixture();
  mutate(fx);
  const before = {
    dockerfile: fs.readFileSync(path.join(fx.dir, 'Dockerfile'), 'utf8'),
    compose: fs.readFileSync(path.join(fx.dir, 'docker-compose.yml'), 'utf8'),
  };
  const r = run(fx, args, mode);
  expect(r.code).not.toBe(0);
  expect({ dockerfile: r.dockerfile, compose: r.compose, tmps: r.tmps }).toEqual({
    dockerfile: before.dockerfile,
    compose: before.compose,
    tmps: [],
  });
}

group('capture-image-digests.sh 真跑行为', () => {
  test('不加 --apply：只打印两个 digest，且一个文件都不改', () => {
    const fx = fixture();
    const before = { d: fx.dockerfile, c: fx.compose };
    const r = run(fx, []);
    expect(r.code).toBe(0);
    expect(r.out).toContain(NODE_REF);
    expect(r.out).toContain(MONGO_REF);
    expect(r.dockerfile).toBe(before.d);
    expect(r.compose).toBe(before.c);
    // 未 --apply 时不该出现"已替换"
    expect(r.out).not.toMatch(/已替换|→/);
  });

  test('--apply：两阶段 Dockerfile 与 compose 全部钉成 digest，旧 tag 不再残留', () => {
    const fx = fixture();
    const r = run(fx, ['--apply']);
    expect({ code: r.code, out: r.out.slice(-160) }).toMatchObject({ code: 0 });
    // 两个 FROM 都要换（原实现用 g 标志，这条把它真的钉住）
    expect(r.dockerfile.split('FROM ').length - 1).toBe(2);
    expect(r.dockerfile.match(/@sha256:/g) || []).toHaveLength(2);
    expect(r.dockerfile).toContain('AS builder');
    expect(r.dockerfile).toContain('AS runner');
    expect(r.dockerfile).not.toContain('node:22.14.0-alpine');
    // compose 只钉指令行；注释里那份"用法示例"必须原样留着
    // （不带行定位的全文 sed 会把它一起改掉，改完注释就成了错误示例）
    expect(r.compose).toMatch(/^ {4}image: mongo@sha256:b{64}$/m);
    expect(r.compose).toContain('# 用法示例：image: mongo:6.0.20@sha256:<捕获值>');
    expect(r.compose).toContain('image: x'); // 其它 image 不受影响
    // 目标根必须被打印出来：默认值是脚本自己的仓库根，看不见它就会把测试打到真仓库上。
    // 只比对临时目录名：MSYS/Git Bash 会把 C:\... 回显成 /tmp/... 形式，完整路径不可比。
    expect(r.out).toContain('目标仓库根：');
    expect(r.out).toContain(path.basename(fx.dir));
    // 未知参数不得被静默接受；调用序列里确实只碰了 docker
    expect(r.calls.length).toBeGreaterThanOrEqual(4);
  });

  test('幂等重跑必须报错，而不是"报告成功但一字未改"（sed 无匹配仍返回 0 的老缺陷）', () => {
    const fx = fixture();
    const first = run(fx, ['--apply']);
    expect(first.code).toBe(0);
    const second = run(fx, ['--apply']);
    expect(second.code).not.toBe(0);
    expect(second.out).toContain('已经存在');
    // 第二次失败不得破坏已钉好的内容
    expect(second.dockerfile).toBe(first.dockerfile);
    expect(second.compose).toBe(first.compose);
  });

  test('脚本常量与仓库文件漂移（tag 变了）⇒ 必须报错，不得静默跳过', () => {
    const fx = fixture();
    fs.writeFileSync(
      path.join(fx.dir, 'Dockerfile'),
      fx.dockerfile.replace(/node:22\.14\.0-alpine/g, 'node:22.99.9-alpine'),
      'utf8'
    );
    const r = run(fx, ['--apply']);
    expect(r.code).not.toBe(0);
    expect(r.out).toContain('漂移');
    // compose 那一步还没跑到，Dockerfile 必须保持未改（失败要早于动作）
    expect(r.dockerfile).toContain('node:22.99.9-alpine');
    // 行锚定：注释里也有同名子串，用 toContain 会假通过
    expect(r.compose).toMatch(/^ {4}image: mongo:6\.0\.20$/m);
  });

  test('--apply 在前、--root 在后也必须生效（旧实现只看第一个参数）', () => {
    const fx = fixture();
    const r = run(fx, ['--apply', '--root=<ROOT>']);
    expect(r.code).toBe(0);
    expect(r.dockerfile).toContain('@sha256:');
  });

  test.each([
    ['<no value> 形态', 'novalue'],
    ['空输出形态', 'empty'],
    ['长度不足的伪 digest', 'wrongarch'],
  ])('digest 取不到（%s）⇒ 拒绝写入任何文件', (_label, mode) => {
    const fx = fixture();
    const r = run(fx, ['--apply'], mode);
    expect(r.code).not.toBe(0);
    expect(r.out).toContain('digest');
    // 最关键的一条：不能把 `FROM <no value>` 之类的东西写进 Dockerfile
    expect(r.dockerfile).toBe(fx.dockerfile);
    expect(r.compose).toBe(fx.compose);
  });

  test('参数顺序无关：--root 在前、--apply 在后也必须生效', () => {
    // 旧实现是 `[ "${1:-}" = "--apply" ] && APPLY=1`，只看第一个参数 ⇒
    // `sh x.sh --root=... --apply` 会静默地"什么都不做还报成功"。
    const fx = fixture();
    const r = run(fx, ['--root=<ROOT>', '--apply']);
    expect(r.code).toBe(0);
    expect(r.dockerfile).toContain('@sha256:');
  });

  test('未知参数直接拒绝（不得忽略后继续改文件）', () => {
    const fx = fixture();
    const r = run(fx, ['--aply']);
    expect(r.code).toBe(2);
    expect(r.out).toContain('未知参数');
    expect(r.dockerfile).toBe(fx.dockerfile);
  });

  /**
   * 半钉状态是这个脚本特有的失效形状，它同时踩中两条：
   * ① 供应链上 compose 仍指向**可变 tag**，而仓库看起来"已经钉过版"；
   * ② 唯一能修它的脚本从此**拒绝再跑**（下一次运行会在 Dockerfile 那一步撞
   *    "已经存在 @sha256 钉版引用"）。
   * 实测复现过：旧实现是"边检查边落笔、两个目标顺序跑"，compose 漂移时 Dockerfile 已写盘。
   * 所以这里必须逐字节比（`toBe`），`toContain('node:22.14.0-alpine')` 挡不住"改了一半"。
   */
  test('第二个目标（compose）漂移 ⇒ 第一个目标一个字都不写，也不留临时文件', () => {
    const fx = fixture();
    const drifted = driftCompose(fx.compose);
    driftComposeTag(fx);
    const r = run(fx, ['--apply']);
    expect(r.code).not.toBe(0);
    expect(r.out).toContain('漂移');
    expect(r.dockerfile).toBe(fx.dockerfile);
    expect(r.compose).toBe(drifted);
    expect(r.tmps).toEqual([]);
  });

  test('半钉不是死路：照报错修好 compose 之后重跑，两个目标都能钉上', () => {
    // 旧顺序下这一条跑不通——第一轮已经把 Dockerfile 钉了，第二轮在第一步就退出。
    const fx = fixture();
    driftComposeTag(fx);
    expect(run(fx, ['--apply']).code).not.toBe(0);
    expect(fs.readFileSync(path.join(fx.dir, 'Dockerfile'), 'utf8')).toBe(fx.dockerfile);
    fs.writeFileSync(path.join(fx.dir, 'docker-compose.yml'), fx.compose, 'utf8');
    const second = run(fx, ['--apply']);
    expect({ code: second.code, tail: second.out.slice(-120) }).toMatchObject({ code: 0 });
    expect(second.dockerfile).toContain(`FROM ${NODE_REF}`);
    expect(second.compose).toMatch(/^ {4}image: mongo@sha256:b{64}$/m);
    expect(second.tmps).toEqual([]);
  });

  test('同名临时文件已存在：拒绝、不覆盖，退出时也不删（trap 只清自己创建的）', () => {
    const fx = fixture();
    const tmp = path.join(fx.dir, 'Dockerfile.pin.tmp');
    const SENTINEL = '上一次中断留下的产物，或别人手工放的：脚本既不能改它也不能删它\n';
    fs.writeFileSync(tmp, SENTINEL, 'utf8');
    const r = run(fx, ['--apply']);
    expect(r.code).not.toBe(0);
    expect(r.out).toContain('临时文件已存在');
    expect(r.out).toContain('Dockerfile.pin.tmp');
    expect(r.dockerfile).toBe(fx.dockerfile);
    expect(r.compose).toBe(fx.compose);
    // 最关键的一条：这次非零退出会走 EXIT trap，trap 必须**没有**碰到它。
    // 直觉写法 `trap 'rm -f "$ROOT"/*.pin.tmp' EXIT` 就是在这里删掉运维的文件。
    expect(fs.readFileSync(tmp, 'utf8')).toBe(SENTINEL);
    // 非空集自证：同一个 readdir 过滤器看得见这个文件。少了它，上面/下面的
    // `tmps === []` 都可能是"过滤器永远返回空"造成的假绿。
    expect(r.tmps).toEqual(['Dockerfile.pin.tmp']);
    // 报错也不是死路：人工删除后必须能正常钉版，且成功运行自己不留临时文件
    fs.rmSync(tmp);
    const after = run(fx, ['--apply']);
    expect({ code: after.code, tmps: after.tmps }).toMatchObject({ code: 0, tmps: [] });
    expect(after.dockerfile).toContain(`FROM ${NODE_REF}`);
  });

  test('反向自证：失败矩阵的表宽 = 处理函数形参个数（窄一格是超时假绿，不是失败）', () => {
    expect({ declared: checkFailure.length }).toEqual({ declared: 4 });
    expect({ width: failureArms.map((row) => row.length) }).toEqual({
      width: [4, 4, 4, 4, 4],
    });
    // 判据本身非空集：把行削窄一格必须点亮
    const narrow = failureArms.map((row) => row.slice(0, 3));
    expect(narrow.every((row) => row.length === checkFailure.length)).toBe(false);
  });

  test.each(failureArms)('%s ⇒ 目标文件逐字节不变且不留临时文件', checkFailure);
});
