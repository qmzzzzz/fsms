/**
 * 热升级脚本（scripts/hotUpgrade.js）的失败现场抓取：真跑脚本，观测两条通道
 *
 * 守的失效形态（都是「现场没能留到能看的地方」的变体）：
 *   · 备色未就绪时，容器日志尾巴必须同时进**两张表**——宿主留痕（logs/hot-upgrade-*.json
 *     的 targetLogsTail，供事后复盘）与任务说明（status message 的截断片段，供界面直接看）；
 *   · 抓取必须先于停容器执行（stop 之后再抓，拿到的就只剩 docker 自己记的那截）；
 *   · 抓取失败不得改变主判决：logs 命令非零退出时任务说明里**不留**空话式附录，
 *     终态仍是 aborted_not_ready；
 *   · 片段按行边界截断（半行开头会让运维误以为日志缺行）——纯函数用例直接钉。
 *
 * 怎么测（与 deployRun.test.js 同手法）：--require 预加载 stubExec 接管 child_process
 * （hooks 以 **argv 形态**传入：node --require a.js --require b.js script.js，不经
 * NODE_OPTIONS 字符串拼接），以真子进程跑 scripts/hotUpgrade.js，把每条对外命令记到日志
 * 再断言。就绪判据走的是全局 fetch（不是子进程），stubExec 够不到它——另加一个只影响
 * 被测子进程的 hook 把 fetch 固定为「立即连接失败」，让门控稳定落入 aborted_not_ready，
 * 不依赖本机 3001 端口是否恰好被占。
 */
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const ROOT = path.resolve(__dirname, '../../..');
const SCRIPT = path.join(ROOT, 'scripts', 'hotUpgrade.js');
const HOOK = path.join(__dirname, 'helpers', 'stubExec.js');
const NODE = process.execPath;

const { buildLogSnippet } = require('../../../scripts/hotUpgrade');

const IMAGE = `ghcr.io/acme/fsms@sha256:${'d'.repeat(64)}`;
const ALLOWLIST = 'ghcr.io/acme/';
/** 档板返回的假日志行：单行（STUB_RESPONSES 以换行分条，行内不能再放换行）但有辨识度 */
const FAKE_LOG_LINE = 'FATAL fake-standby-log-mongo-transaction-capability-lost';

const staged = [];
afterAll(() => {
  for (const dir of staged) fs.rmSync(dir, { recursive: true, force: true });
});

/**
 * 一次升级的隔离环境：nginx 配置（蓝为当前色 → 目标色 green/3001）、compose 占位文件、
 * 就绪 hook、状态文件、命令日志。
 */
function makeStage(label) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `upgradelogs-${label}-`));
  staged.push(dir);
  const nginxConf = path.join(dir, 'nginx.conf');
  fs.writeFileSync(
    nginxConf,
    ['http {', '    upstream fsms_app {', '        server 127.0.0.1:3000;', '    }', '}'].join(
      '\n'
    ),
    'utf8'
  );
  const composeFile = path.join(dir, 'docker-compose.yml');
  fs.writeFileSync(composeFile, 'services: {}\n', 'utf8');
  // 只影响被测子进程：把就绪探测的 fetch 固定为「立即连接失败」。
  // hotUpgrade.js 的 probeReadyz 用全局 fetch，stubExec 只接管 child_process。
  const readyzOff = path.join(dir, 'readyz-off.js');
  fs.writeFileSync(
    readyzOff,
    [
      "'use strict';",
      '// 测试自造：仅影响被测子进程的就绪探测（详见套件头注释）',
      "globalThis.fetch = () => Promise.reject(new Error('connect ECONNREFUSED 127.0.0.1:3001'));",
      '',
    ].join('\n'),
    'utf8'
  );
  const statusFile = path.join(dir, 'status.json');
  const stubLog = path.join(dir, 'cmd.log');
  const composePrefix = ['docker', 'compose', '-f', composeFile, '--profile', 'green'].join(' ');
  return { dir, nginxConf, composeFile, readyzOff, statusFile, stubLog, composePrefix };
}

/**
 * 真跑一次升级脚本（失败路径终结于 exit 1）。
 * @param {object} stage makeStage() 的产物
 * @param {string[]} rules stubExec 规则表（先命中先返回，具体前缀排在 * 兜底之前）
 */
function runUpgrade(stage, rules) {
  const env = {
    ...process.env,
    STUB_LOG: stage.stubLog,
    STUB_RESPONSES: rules.join('\n'),
    HOT_UPGRADE_COMPOSE_FILE: stage.composeFile,
    HOT_UPGRADE_REGISTRY_ALLOWLIST: ALLOWLIST,
  };
  const args = [
    '--image',
    IMAGE,
    '--nginx-conf',
    stage.nginxConf,
    '--status-file',
    stage.statusFile,
    '--readyz-timeout',
    '1',
    '--apply',
  ];
  const r = spawnSync(NODE, ['--require', HOOK, '--require', stage.readyzOff, SCRIPT, ...args], {
    cwd: ROOT,
    env,
    encoding: 'utf8',
  });
  const lines = fs.existsSync(stage.stubLog)
    ? fs.readFileSync(stage.stubLog, 'utf8').split(/\r?\n/).filter(Boolean)
    : [];
  return { code: r.status, stdout: r.stdout || '', stderr: r.stderr || '', lines };
}

const readStatus = (stage) => JSON.parse(fs.readFileSync(stage.statusFile, 'utf8'));

/**
 * 热升级留痕落在仓库 logs/（脚本的既有行为）。用例只清理**本轮新造出来的**那几条：
 * 按文件名差集删，避免误删并行会话或人工演练的真实留痕（同 importOfflineBundle.test.js）。
 * 文件名带毫秒级时间戳，字典序即时间序；取 `.at(-1)` 即当前用例刚写的那条。
 */
const logsDir = path.join(ROOT, 'logs');
const preExistingLogs = fs.existsSync(logsDir)
  ? new Set(fs.readdirSync(logsDir).filter((n) => n.startsWith('hot-upgrade-')))
  : new Set();
afterAll(() => {
  if (!fs.existsSync(logsDir)) return;
  for (const name of fs.readdirSync(logsDir)) {
    if (name.startsWith('hot-upgrade-') && !preExistingLogs.has(name)) {
      fs.rmSync(path.join(logsDir, name), { force: true });
    }
  }
});
const newestForensic = () => {
  const fresh = fs
    .readdirSync(logsDir)
    .filter((n) => n.startsWith('hot-upgrade-') && !preExistingLogs.has(n))
    .sort();
  expect(fresh.length).toBeGreaterThan(0);
  return JSON.parse(fs.readFileSync(path.join(logsDir, fresh[fresh.length - 1]), 'utf8'));
};

describe('备色未就绪 ⇒ 现场抓取（真跑脚本 + 档板观测）', () => {
  test('日志尾巴进留痕与任务说明；抓取发生在停容器之前', () => {
    const stage = makeStage('ok');
    const logsCall = [stage.composePrefix, 'logs', '--no-color', '--tail', '80', 'app-green'].join(
      ' '
    );
    const { code, lines } = runUpgrade(stage, [`${logsCall}|${FAKE_LOG_LINE}|0`, '*||0']);

    // 失败路径以 1 退出（fail 分支的既有语义），且判决落在 aborted_not_ready
    expect(code).toBe(1);
    const status = readStatus(stage);
    expect(status.state).toBe('failed');
    expect(status.outcome).toBe('aborted_not_ready');
    expect(status.message).toContain('备色未就绪');
    // 任务说明里的截断片段（界面直接可见的那份）
    expect(status.message).toContain('目标色容器日志末尾');
    expect(status.message).toContain(FAKE_LOG_LINE);

    // 留痕里的完整尾巴（事后复盘的那份）
    const record = newestForensic();
    expect(record.outcome).toBe('aborted_not_ready');
    expect(record.targetLogsTail).toContain(FAKE_LOG_LINE);

    // 顺序：抓取先于停容器（stop 之后再抓只剩 docker 自己记的那截）
    const iLogs = lines.findIndex((l) => l === logsCall);
    const iStop = lines.findIndex((l) => l === `${stage.composePrefix} stop app-green`);
    expect(iLogs).toBeGreaterThanOrEqual(0);
    expect(iStop).toBeGreaterThanOrEqual(0);
    expect(iLogs).toBeLessThan(iStop);
  });

  test('抓取失败（logs 命令非零退出）⇒ 不留空话式附录，主判决不变', () => {
    const stage = makeStage('fail');
    const logsCall = [stage.composePrefix, 'logs', '--no-color', '--tail', '80', 'app-green'].join(
      ' '
    );
    const { code, lines } = runUpgrade(stage, [`${logsCall}||3`, '*||0']);

    expect(code).toBe(1);
    const status = readStatus(stage);
    expect(status.state).toBe('failed');
    expect(status.outcome).toBe('aborted_not_ready');
    expect(status.message).toContain('备色未就绪');
    // 抓不到时说明里一个字节都不加（「日志如下：无」这种空话比没有更糟）
    expect(status.message).not.toContain('目标色容器日志末尾');

    // 抓取是被尝试过的（档板记下了这次调用）；留痕里尾巴为空串
    expect(lines.some((l) => l === logsCall)).toBe(true);
    expect(newestForensic().targetLogsTail).toBe('');

    // 停容器照常执行（抓取失败不阻断收尾）
    expect(lines.some((l) => l === `${stage.composePrefix} stop app-green`)).toBe(true);
  });
});

describe('buildLogSnippet（纯函数）', () => {
  test('非字符串/空白输入 ⇒ 空串（附录一个字节都不加）', () => {
    expect(buildLogSnippet(null)).toBe('');
    expect(buildLogSnippet(undefined)).toBe('');
    expect(buildLogSnippet(123)).toBe('');
    expect(buildLogSnippet('')).toBe('');
    expect(buildLogSnippet('  \n\t ')).toBe('');
  });

  test('未超上限：原样保留（只 trim 首尾，行结构不动）', () => {
    expect(buildLogSnippet('line-1\nline-2\nline-3')).toBe('line-1\nline-2\nline-3');
    expect(buildLogSnippet('  only-line  ')).toBe('only-line');
  });

  test('超上限：从截断点之后的第一处换行起步——半行开头会让运维误以为日志缺行', () => {
    // 三行等长：A 行 10 字、B 行 10 字、C 行 10 字，共 32 字符（含两个换行）
    const raw = `${'A'.repeat(10)}\n${'B'.repeat(10)}\n${'C'.repeat(10)}`;
    const snippet = buildLogSnippet(raw, 14);
    // 末 14 字符 = B 行后 3 字 + 换行 + C 行；截断点落在 B 行中间 ⇒ B 的残段必须被丢掉
    expect(snippet).toBe('C'.repeat(10));
  });

  test('上限恰好落在行边界之后：整行保留，不从行内开剪', () => {
    const raw = 'AA\nBBBBBBBBBB';
    // 末 10 字符 = 'BBBBBBBBBB'，起点恰在换行后 ⇒ 原样保留
    expect(buildLogSnippet(raw, 10)).toBe('BBBBBBBBBB');
  });
});
