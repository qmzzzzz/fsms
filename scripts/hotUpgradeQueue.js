/**
 * 宿主热升级代理的队列与配置原语
 *
 * 应用与代理共享同一个 bind mount：
 *   requests/<uuid>.json   应用写 0600，代理消费后移走
 *   processing/<uuid>.json 代理领取后放在这里（同时记录 pid，用于崩溃恢复）
 *   status/<uuid>.json     代理写 0600（属主对齐队列目录），应用只读
 *   rejected/<uuid>.json   验签/校验失败的请求留证，不执行、不静默删
 *   heartbeat.json         代理每轮覆盖写 0644（不含镜像/操作人，仅在线与就绪判据）
 *
 * 这一层只负责「安全地读写这些文件与配置」；一条请求是否允许执行，
 * 由 hotUpgradeJob 在执行前重新判定。
 */

'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const VERSION = require('../package.json').version;

const MAX_JSON_BYTES = 64 * 1024;
const JOB_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const TERMINAL_STATES = new Set(['succeeded', 'failed']);
const LOCK_FILE = '.agent.lock';
// 锁龄上限：systemd 单元把单次升级限死在 2h（TimeoutStartSec），留 1h 余量。
const LOCK_STALE_MS = 3 * 60 * 60 * 1000;
const MAX_STEPS = 40;

const warn = (msg) => process.stderr.write(`[hot-upgrade-agent] 警告：${msg}\n`);

const toInt = (value, fallback, min, max) => {
  const n = Number.parseInt(value, 10);
  if (!Number.isFinite(n) || n < min || n > max) return fallback;
  return n;
};

function readJsonFile(file) {
  // 单 fd 读：先 statSync 再 readFileSync(路径) 是两次独立解析，中间可被换成符号链接
  // （应用对 requests/ 有写权限）⇒ 代理以 root 读到任意宿主文件的内容并按 JSON 解析。
  // O_NOFOLLOW 让「最后一段是符号链接」直接失败；fstat 作用在已打开的 fd 上，没有窗口。
  let fd;
  try {
    // O_NONBLOCK：应用对 requests/ 可写，被攻陷/存在任意写接口时可塞一个 FIFO 到
    // <uuid>.json——按 O_RDONLY 打开 FIFO 会**阻塞**，代理就此卡死、锁与心跳都不再推进。
    // 对普通文件它无副作用；非普通文件随后由 fstat 拒掉。
    fd = fs.openSync(
      file,
      fs.constants.O_RDONLY | fs.constants.O_NONBLOCK | (fs.constants.O_NOFOLLOW || 0)
    );
  } catch {
    return null;
  }
  try {
    const stat = fs.fstatSync(fd);
    if (!stat.isFile() || stat.size > MAX_JSON_BYTES) return null;
    return JSON.parse(fs.readFileSync(fd, 'utf8'));
  } catch {
    return null;
  } finally {
    try {
      fs.closeSync(fd);
    } catch {
      /* 已关闭 */
    }
  }
}

/**
 * 把临时文件的属主对齐到所在目录的属主（只在以 root 运行时动作）。
 *
 * 为什么需要：status/processing 是 root 代理写的 0640 文件，而读它们的是容器内
 * 非 root 的 nodejs（UID 1001）。队列目录的属主已被入口脚本改成 nodejs，若新文件属 root，
 * 应用会因为 EACCES 读不到「谁的升级、到哪一步了」——把权限收紧变成把功能弄坏。
 * 对齐后权限仍是 0640（属主可读写、属组只读），并保证属组是队列目录的属组。
 * Windows 等平台没有 chown，静默跳过。
 */
function adoptDirOwner(dir, file) {
  if (typeof process.getuid !== 'function' || process.getuid() !== 0) return;
  let dirStat;
  try {
    dirStat = fs.statSync(dir);
    const fileStat = fs.statSync(file);
    if (fileStat.uid !== dirStat.uid || fileStat.gid !== dirStat.gid) {
      fs.chownSync(file, dirStat.uid, dirStat.gid);
    }
  } catch {
    // chown 不被支持或权限不足：不改属主也不阻断写入
  }
}

/**
 * 原子写 JSON。
 *
 * 临时文件名必须不可预测、且必须以「已存在即失败」的方式创建：
 * 代理以 root 运行，共享队列目录则对容器内应用可写——若临时名可预测且用
 * writeFileSync（跟随符号链接）写，应用侧只要预先把该名字做成指向任意宿主文件的
 * 符号链接，代理就会以 root 身份覆盖那个文件（本地提权）。
 * 因此：名字带随机后缀 + openSync(tmp,'wx',0o600) + 写完 fsync + rename 前 lstat 复核。
 */
function writeJsonAtomic(file, value, mode = 0o644, { adoptOwner = false } = {}) {
  const dir = path.dirname(file);
  const tmp = path.join(dir, `.${path.basename(file)}.${process.pid}.${crypto.randomUUID()}.tmp`);
  let fd = null;
  try {
    // 'wx'：目标已存在（含预置的符号链接）即失败，绝不跟随链接写入
    fd = fs.openSync(tmp, 'wx', 0o600);
    fs.writeFileSync(fd, JSON.stringify(value, null, 2), 'utf8');
    fs.fsyncSync(fd);
  } finally {
    if (fd !== null) fs.closeSync(fd);
  }
  // rename 之前复核：此刻它必须是我们刚写的普通文件，不是链接
  const stat = fs.lstatSync(tmp);
  if (!stat.isFile() || stat.isSymbolicLink()) {
    fs.unlinkSync(tmp);
    throw new Error('临时文件在写入期间被替换（疑似符号链接劫持），已放弃本次写入');
  }
  fs.chmodSync(tmp, mode);
  if (adoptOwner) adoptDirOwner(dir, tmp);
  fs.renameSync(tmp, file);
}

function listJsonFiles(dir) {
  try {
    return fs
      .readdirSync(dir)
      .filter((name) => name.endsWith('.json') && !name.startsWith('.'))
      .map((name) => path.join(dir, name));
  } catch {
    return [];
  }
}

/**
 * 认领顺序：按 requestedAt 升序（最早发起的先执行）。
 *
 * readdir 的顺序与「请求何时到达」无关（它取决于目录内部的哈希顺序），
 * 直接用 readdir 顺序会先执行后发的请求——用户连点两次时，先发的那个反而被压后。
 * 解析不出 requestedAt 的畸形文件排最后：它们会被判据拒绝并留证，
 * 但不得因此挡住排在后面的合法请求。
 */
function orderByRequestedAt(files) {
  return files
    .map((file, index) => {
      const raw = readJsonFile(file);
      const at = raw && typeof raw.requestedAt === 'string' ? Date.parse(raw.requestedAt) : NaN;
      return { file, index, at: Number.isFinite(at) ? at : Number.POSITIVE_INFINITY };
    })
    .sort((a, b) => a.at - b.at || a.index - b.index)
    .map((entry) => entry.file);
}

function readHmacSecret(env) {
  if (env.HMAC_SECRET && String(env.HMAC_SECRET).trim()) {
    return { secret: String(env.HMAC_SECRET).trim(), error: '' };
  }
  const file = String(env.HMAC_SECRET_FILE || '').trim();
  if (!file) return { secret: '', error: '' };
  try {
    const raw = fs
      .readFileSync(file, 'utf8')
      .replace(/^\uFEFF/, '')
      .replace(/[\r\n]+$/, '');
    // 文案刻意不带宿主绝对路径：这条原因会经心跳回给上层（应用）展示
    if (raw.includes('\u0000')) {
      return { secret: '', error: 'HMAC 密钥文件含 NUL 字符（HMAC_SECRET_FILE 指向的文件）' };
    }
    return { secret: raw, error: '' };
  } catch (err) {
    return {
      secret: '',
      error: `HMAC 密钥文件不可读（HMAC_SECRET_FILE 指向的文件）：${err.code || '读取失败'}`,
    };
  }
}

function loadConfig(env = process.env) {
  const queueDir = String(env.UPGRADE_QUEUE_DIR || '').trim() || '/var/lib/fsms/upgrade';
  const hmac = readHmacSecret(env);
  return {
    queueDir,
    requestsDir: path.join(queueDir, 'requests'),
    statusDir: path.join(queueDir, 'status'),
    processingDir: path.join(queueDir, 'processing'),
    rejectedDir: path.join(queueDir, 'rejected'),
    heartbeatFile: path.join(queueDir, 'heartbeat.json'),
    allowlist: String(env.HOT_UPGRADE_REGISTRY_ALLOWLIST || '')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean),
    nginxConf: String(env.HOT_UPGRADE_NGINX_CONF || '').trim() || '/etc/nginx/nginx.conf',
    composeFile: String(env.HOT_UPGRADE_COMPOSE_FILE || '').trim(),
    hmacSecret: hmac.secret,
    hmacError: hmac.error,
    requestTtlMs: toInt(env.UPGRADE_REQUEST_TTL_SECONDS, 1800, 60, 86400) * 1000,
    historyLimit: toInt(env.UPGRADE_HISTORY_LIMIT, 50, 1, 500),
    heartbeatIntervalMs: 10_000,
  };
}

function ensureDirs(cfg) {
  for (const dir of [
    cfg.queueDir,
    cfg.requestsDir,
    cfg.statusDir,
    cfg.processingDir,
    cfg.rejectedDir,
  ]) {
    fs.mkdirSync(dir, { recursive: true, mode: 0o750 });
  }
}

/**
 * 写心跳。
 *
 * ready 与 reasons 必须显式给出，且缺省是**未就绪**：心跳是应用判断「代理在线且能升级」
 * 的唯一依据，早期默认 ready:true 会让应用在代理自检还没跑完（甚至白名单没配）时
 * 就把按钮点亮，用户点下去只会拿到一次静默失败。调用方没给就绪判据时，
 * 这里补一条原因，而不是替它宣布就绪。
 */
function writeHeartbeat(cfg, status = {}) {
  const { ready: rawReady, reasons: rawReasons, ...rest } = status;
  const ready = rawReady === true;
  const reasons = (Array.isArray(rawReasons) ? rawReasons : []).filter(
    (r) => typeof r === 'string' && r.trim() !== ''
  );
  if (!ready && reasons.length === 0) {
    reasons.push('代理尚未给出就绪判据（不得默认按就绪处理）');
  }
  writeJsonAtomic(
    cfg.heartbeatFile,
    {
      lastSeenAt: new Date().toISOString(),
      pid: process.pid,
      version: VERSION,
      ready,
      reasons,
      ...rest,
    },
    0o644
  );
}

function pidAlive(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    // EPERM：进程存在但属于别的用户（代理以 root 跑，正常不会遇到）
    return err.code === 'EPERM';
  }
}

/**
 * 单实例锁。systemd 的 oneshot 服务天然不会并发，但人工执行 + timer 同时触发时
 * 仍可能两个进程同时认领请求。锁内记录 pid：持有者已死则视为陈旧锁并接管。
 */
function acquireLock(cfg, { isAlive = pidAlive } = {}) {
  const file = path.join(cfg.processingDir, LOCK_FILE);
  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      const token = crypto.randomUUID();
      const fd = fs.openSync(file, 'wx', 0o600);
      fs.writeFileSync(
        fd,
        JSON.stringify({
          pid: process.pid,
          token,
          startTime: procStartTime(process.pid),
          startedAt: new Date().toISOString(),
        })
      );
      fs.fsyncSync(fd);
      fs.closeSync(fd);
      return {
        token,
        release: () => {
          // 释放前必须回读比对：这把锁文件此刻可能已经不属于我
          //（我的锁被判定陈旧并删除，另一个实例刚写下它自己的锁）。
          // 无脑 unlink 会删掉别人的锁 ⇒ 两个代理同时执行升级。
          const held = readJsonFile(file);
          if (!held || held.token !== token) return;
          try {
            fs.unlinkSync(file);
          } catch {
            // 已被清理——不是错误
          }
        },
      };
    } catch (err) {
      if (err.code !== 'EEXIST') throw err;
      if (isLockStale(readJsonFile(file), isAlive)) {
        try {
          fs.unlinkSync(file);
        } catch {
          return null;
        }
      } else {
        return null;
      }
    }
  }
  return null;
}

/**
 * 锁是否陈旧（可以接管）。三个条件任一成立即陈旧，其余一律按「忙」处理。
 *
 * 1) 文件读不出对象（空文件/半写/损坏）：崩溃可能停在 open 与 write 之间，
 *    这种锁没人持有，等下去就是永久忙。
 * 2) pid 不存在，或**活着但已不是当初那个进程**：pid 会被复用（升级后重启、
 *    容器重建都会重新分配）。只判 `kill(pid,0)` 时，一个恰好复用了旧 pid 的
 *    无关进程会让升级按钮永远显示「另一个升级正在进行」。
 * 3) 锁龄超过 LOCK_STALE_MS：systemd 单元把单次升级限死在 2h，超过 3h 的锁
 *    没有对应的活着的升级，留着只会挡住所有后续请求。
 */
function isLockStale(holder, isAlive) {
  if (!holder || typeof holder !== 'object') return true;
  const pid = Number.isInteger(holder.pid) ? holder.pid : 0;
  if (!pid) return true;
  if (!isAlive(pid)) return true;
  const recorded = typeof holder.startTime === 'string' ? holder.startTime : '';
  const actual = procStartTime(pid);
  if (recorded && actual && recorded !== actual) return true;
  const startedAt = Date.parse(holder.startedAt);
  if (Number.isFinite(startedAt) && Date.now() - startedAt > LOCK_STALE_MS) return true;
  return false;
}

/**
 * 进程启动时刻（/proc/<pid>/stat 第 22 字段，单位 jiffies）。仅 Linux 可得。
 * 非 Linux 返回空串：此时陈旧判定退化为「pid 是否存活」，仍然安全（宁可误判为忙）。
 */
function procStartTime(pid) {
  if (process.platform !== 'linux') return '';
  try {
    const stat = fs.readFileSync(`/proc/${pid}/stat`, 'utf8');
    // comm 可能含空格与括号（如 "node (x)"）：从最后一个 ')' 之后按空格切
    const tail = stat.slice(stat.lastIndexOf(')') + 2).split(' ');
    // tail[0] 是 state（第 3 字段），故第 22 字段 = tail[19]
    return String(tail[19] || '');
  } catch {
    return '';
  }
}

function writeStatus(cfg, id, patch) {
  const file = path.join(cfg.statusDir, `${id}.json`);
  const base = readJsonFile(file) || {};
  const next = { ...base, ...patch, id, updatedAt: new Date().toISOString() };
  if (Array.isArray(next.steps) && next.steps.length > MAX_STEPS) {
    next.steps = next.steps.slice(-MAX_STEPS);
  }
  // 0640 + 属主 root、属组＝队列目录属组：status 含镜像 digest 与发起人
  // （requestedBy/sourceIp），不能给 other；而读它的是容器内 nodejs，故留组读。
  writeJsonAtomic(file, next, 0o640, { adoptOwner: true });
}

function statusOf(cfg, id) {
  return readJsonFile(path.join(cfg.statusDir, `${id}.json`));
}

function isTerminal(status) {
  return Boolean(status && TERMINAL_STATES.has(status.state));
}

function quarantine(cfg, file, id) {
  const name = id && JOB_ID_RE.test(id) ? `${id}.json` : `${Date.now()}-${path.basename(file)}`;
  try {
    fs.renameSync(file, path.join(cfg.rejectedDir, name));
  } catch (err) {
    warn(`无法把非法请求移入 rejected/：${err.message}`);
  }
}

function updateProcessing(cfg, file, patch) {
  const raw = readJsonFile(file);
  if (!raw || typeof raw !== 'object') return;
  writeJsonAtomic(file, { ...raw, _agent: { ...(raw._agent || {}), ...patch } }, 0o640, {
    adoptOwner: true,
  });
}

function pruneStatus(cfg) {
  const entries = listJsonFiles(cfg.statusDir)
    .map((file) => {
      try {
        return { file, mtime: fs.statSync(file).mtimeMs };
      } catch {
        return null;
      }
    })
    .filter(Boolean)
    .sort((a, b) => b.mtime - a.mtime);
  for (const entry of entries.slice(cfg.historyLimit)) {
    const status = readJsonFile(entry.file);
    if (status && (status.state === 'queued' || status.state === 'running')) continue;
    try {
      fs.unlinkSync(entry.file);
    } catch {
      // 清理失败不影响升级
    }
  }
}

module.exports = {
  MAX_JSON_BYTES,
  LOCK_STALE_MS,
  JOB_ID_RE,
  readJsonFile,
  writeJsonAtomic,
  listJsonFiles,
  readHmacSecret,
  orderByRequestedAt,
  adoptDirOwner,
  loadConfig,
  ensureDirs,
  writeHeartbeat,
  pidAlive,
  acquireLock,
  isLockStale,
  procStartTime,
  writeStatus,
  statusOf,
  isTerminal,
  quarantine,
  updateProcessing,
  pruneStatus,
};
