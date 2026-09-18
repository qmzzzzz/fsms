/**
 * 部署脚本端到端测试的子进程档板（--require 预加载）
 *
 * 为什么需要它：scripts/deploy.js 的副作用层会真发起
 * `docker compose ...` / `bash backup-mongo.sh` / `curl` 子进程，而 CI 里
 * 没有 docker daemon、更不能去真把生产库备份。
 * 但「不能真跑」不等于「只能测纯函数」：
 * 部署流程最脆弱的地方恰恰是**步骤顺序与失败分支**，
 * 而它们只有跑起来才会暴露。
 *
 * 做法：拦截 child_process 的四个入口（execFileSync / execFile /
 * spawnSync / spawn），把每一次调用以 `<工具> <参数...>` 的形式
 * 追加到 STUB_LOG 指定的日志文件，并按 STUB_RESPONSES 里的规则返回预设结果。
 * 被测脚本对外部命令的观测与控制因此完全可观测且可确定。
 *
 * 注意：只替换上述四个导出函数，不动 child_process 的其他部分；
 * 被测脚本自身也不知道命令被接管了（无需为测试开后门）。
 */
'use strict';

const fs = require('fs');
const real = require('child_process');

const LOG = process.env.STUB_LOG;
/** 每行一条规则：`匹配前缀|stdout|退出码`（匹配前缀为 `*` 表示命中所有） */
const RULES = (process.env.STUB_RESPONSES || '')
  .split('\n')
  .filter(Boolean)
  .map((line) => {
    const [prefix, stdout, code] = line.split('|');
    return { prefix, stdout: stdout || '', code: Number(code || 0) };
  });

function record(file, args) {
  if (LOG) fs.appendFileSync(LOG, file + ' ' + args.join(' ') + '\n');
}

/**
 * 按规则表推导本次调用的结果；无匹配则默认成功、空输出。
 *
 * 特殊语法 `@seq:a,b,c`：该命令连续调用时依次返回 a、b、c，之后固定为最后一项。
 * 用于模拟「服务先未就绪、随后就绪」这类随时间变化的状态（如健康探针）。
 * 计数器落在日志同目录，故各演练环境互不干扰。
 */
function resolveResult(file, args) {
  const cmd = file + ' ' + args.join(' ');
  for (const rule of RULES) {
    if (rule.prefix !== '*' && !cmd.startsWith(rule.prefix)) continue;
    if (!rule.stdout.startsWith('@seq:')) return rule;
    const seq = rule.stdout.slice('@seq:'.length).split(',');
    const counterFile = LOG + '.seq';
    let n = 0;
    try {
      n = Number(fs.readFileSync(counterFile, 'utf8')) || 0;
    } catch (_) {
      n = 0;
    }
    fs.writeFileSync(counterFile, String(n + 1));
    return { stdout: seq[Math.min(n, seq.length - 1)], code: rule.code };
  }
  return { stdout: '', code: 0 };
}

function makeSync() {
  return function execFileSync(file, args = [], opts = {}) {
    record(file, args);
    const rule = resolveResult(file, args);
    if (rule.code !== 0) {
      const err = new Error(`Command failed: ${file} ${args.join(' ')}`);
      err.status = rule.code;
      err.stdout = rule.stdout;
      err.stderr = '';
      throw err;
    }
    // 模拟 encoding: 'utf8' 时的返回值（字符串），否则返回 Buffer
    return opts && opts.encoding ? rule.stdout : Buffer.from(rule.stdout);
  };
}

// 把 `<ROOT>/secrets/**` 的读取重定向到 STUB_SECRETS_DIR：加固前检查要读 9 个密钥文件，
// 而仓库里的 secrets/ 是 gitignore 的（CI 上不存在）。测试不应向仓库写入密钥，
// 也不应依赖本机是否恰好生成过；故只针对这一个路径前缀做转发。
const SECRETS_DIR = process.env.STUB_SECRETS_DIR;
if (SECRETS_DIR) {
  const realFs = require('fs');
  const path = require('path');
  const repoSecrets = path.join(__dirname, '..', '..', '..', '..', 'secrets');
  const remap = (p) => {
    const s = String(p);
    if (s !== repoSecrets && !s.startsWith(repoSecrets + path.sep)) return p;
    return path.join(SECRETS_DIR, s === repoSecrets ? '' : s.slice(repoSecrets.length + 1));
  };
  const origExists = realFs.existsSync;
  const origRead = realFs.readFileSync;
  realFs.existsSync = (p) => origExists(remap(p));
  realFs.readFileSync = (p, ...rest) => origRead(remap(p), ...rest);
}

module.exports = {};
module.exports.execFileSync = makeSync();
real.execFileSync = module.exports.execFileSync;
real.execFile = function execFile(file, args, opts, cb) {
  if (typeof args === 'function') {
    cb = args;
    args = [];
    opts = {};
  } else if (typeof opts === 'function') {
    cb = opts;
    opts = {};
  }
  record(file, args || []);
  const rule = resolveResult(file, args || []);
  setImmediate(() => {
    if (rule.code !== 0) {
      const err = new Error(`Command failed: ${file}`);
      err.status = rule.code;
      return cb(err, rule.stdout, '');
    }
    cb(null, rule.stdout, '');
  });
};
real.spawnSync = function spawnSync(file, args = []) {
  record(file, args);
  const rule = resolveResult(file, args);
  return { status: rule.code, stdout: rule.stdout, stderr: '', signal: null, pid: 1 };
};
real.spawn = function spawn(file, args = []) {
  record(file, args);
  const rule = resolveResult(file, args);
  const { EventEmitter } = require('events');
  const child = new EventEmitter();
  child.stdout = new EventEmitter();
  child.stderr = new EventEmitter();
  child.kill = () => {};
  setImmediate(() => {
    if (rule.stdout) child.stdout.emit('data', Buffer.from(rule.stdout));
    child.emit('exit', rule.code, null);
    child.emit('close', rule.code, null);
  });
  return child;
};
