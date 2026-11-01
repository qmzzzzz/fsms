/** 取证清单的跨进程互斥锁（B-1）。 为什么需要：appendBatch 的动作是「读末行 chainHash → 算新哈希 → appendFile」，这是典型的读-改-写。进程内的并发由 forensicManifest 的 appendChain 串行化解决，但**多副本部署/多进程**同时写同一份清单时，两个进程会各自读到同一个末行，各写一条以它为首的记录 —— 链就地分叉，之后 verifyManifest 会把合法数据报成断链。 方案取舍： - 不用 flock/文件描述符锁：Windows 上语义不同（Node 也没有跨平台 flock）。 - 用 O_CREAT|O_EXCL 创建锁文件：这是 POSIX 与 Windows 上**都原子**的唯一操作。 - 必须能接管崩溃残留：持锁者进程被 kill 时锁文件留了下来，若不能接管，整个清单从此写不进去。接管判据是锁文件 mtime 超过 staleMs。 - 接管次数与超时次数都计数：锁失效是「取证静默降级」的入口，必须可见。 / / / */
const fs = require('fs');
const os = require('os');
const path = require('path');

const LOCK_FILE = '.manifest.lock';
const DEFAULT_TIMEOUT_MS = 3000;
const DEFAULT_STALE_MS = 60000;
const RETRY_MIN_MS = 5;
const RETRY_MAX_MS = 50;

const state = { acquired: 0, lockTimeouts: 0, staleTakeovers: 0, releaseFailures: 0 };

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const readEnvInt = (name, fallback) => {
  const v = Number.parseInt(process.env[name] || '', 10);
  return Number.isFinite(v) && v >= 0 ? v : fallback;
};

/** 尝试创建锁：成功返回 true，已存在返回 false（原子，不检查后创建） */
const tryCreate = (lockPath) => {
  try {
    const fd = fs.openSync(lockPath, 'wx', 0o600);
    fs.writeSync(fd, `${os.hostname()}:${process.pid}`); // 持有者标识只为排障，不参与判据
    fs.closeSync(fd);
    return true;
  } catch (e) {
    if (e && e.code === 'EEXIST') return false;
    throw e;
  }
};

/** 陈锁接管：持锁者崩溃后锁文件会留下，超过 staleMs 视为无主 */
const tryTakeOverStale = (lockPath, staleMs) => {
  let st;
  try {
    st = fs.statSync(lockPath);
  } catch (e) {
    // 刚好被别人释放了：直接当作可以重新抢，不算接管
    return Boolean(e && e.code === 'ENOENT');
  }
  if (Date.now() - st.mtimeMs <= staleMs) return false;
  try {
    fs.unlinkSync(lockPath);
  } catch (e) {
    if (e && e.code !== 'ENOENT') return false; // 别人先删了/删不掉：都下次再试
  }
  state.staleTakeovers += 1;
  // 接管后立即重新抢；抢不到说明有第三方同时在抢，交给外层重试
  return tryCreate(lockPath);
};

/** 在锁保护下执行 fn。 返回 {ok:true, value} 或 {ok:false, reason:'lock_timeout'}；**不抛**（appendBatch 依赖这条）。但 fn 自己抛的错误会原样抛出去 —— 调用方要能看见真实失败，而不是被锁逻辑吞成「超时」。 / */
async function withLock(dir, opts, fn) {
  const options = opts || {};
  const timeoutMs =
    options.timeoutMs != null
      ? options.timeoutMs
      : readEnvInt('FORENSIC_MANIFEST_LOCK_TIMEOUT_MS', DEFAULT_TIMEOUT_MS);
  const staleMs =
    options.staleMs != null
      ? options.staleMs
      : readEnvInt('FORENSIC_MANIFEST_LOCK_STALE_MS', DEFAULT_STALE_MS);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const lockPath = path.join(dir, LOCK_FILE);
  const deadline = Date.now() + Math.max(0, timeoutMs);
  let got = false;
  while (!got) {
    got = tryCreate(lockPath);
    if (!got) got = tryTakeOverStale(lockPath, staleMs);
    if (got) break;
    if (Date.now() >= deadline) {
      state.lockTimeouts += 1;
      return { ok: false, reason: 'lock_timeout' };
    }
    await sleep(Math.min(RETRY_MAX_MS, Math.max(RETRY_MIN_MS, Math.floor(Math.random() * 25))));
  }
  state.acquired += 1;
  // 临界区必须 try/finally 释放：fn 抛错时若漏放，一次异常就把清单永久锁死
  try {
    const value = await fn();
    return { ok: true, value };
  } finally {
    try {
      fs.unlinkSync(lockPath);
    } catch (e) {
      // 释放失败不改写结果：陈锁接管会兜住，但要留痕
      if (e && e.code !== 'ENOENT') state.releaseFailures += 1;
    }
  }
}

const getLockStats = () => ({ ...state });

const resetLockState = () => {
  state.acquired = 0;
  state.lockTimeouts = 0;
  state.staleTakeovers = 0;
  state.releaseFailures = 0;
};

module.exports = { LOCK_FILE, withLock, getLockStats, resetLockState };
