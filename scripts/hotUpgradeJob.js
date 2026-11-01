/**
 * 单条热升级请求的校验与执行（宿主代理侧）
 *
 * 应用侧（upgradeService）也会校验一遍，但那只是为了尽早给出可读的拒绝原因；
 * 这里才是执行前的最终判定：文件名 id、TTL、HMAC 签名、digest 钉扎、白名单，
 * 任何一条不满足都写 failed/rejected 并把原文件移入 rejected/ 留证。
 *
 * 执行只调用固定脚本、固定参数（buildHotUpgradeInvocation），镜像经环境变量传入，
 * 不经过 shell —— 请求内容永远不会被拼进命令行。
 */

'use strict';

const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');

const policy = require('./hotUpgradePolicy');
const queue = require('./hotUpgradeQueue');
const { verifyUpgradeRequest } = require('../src/services/upgradeRequestSignature');
const { buildHotUpgradeInvocation } = require('./deployCommands');

const ROOT = path.resolve(__dirname, '..');
const { JOB_ID_RE, MAX_JSON_BYTES, readJsonFile, writeJsonAtomic, writeStatus, statusOf } = queue;
const { isTerminal, quarantine, updateProcessing } = queue;

function validateRequest(request, cfg, now) {
  if (!request || typeof request !== 'object') return { ok: false, reason: '请求不是 JSON 对象' };
  if (!JOB_ID_RE.test(request.id)) return { ok: false, reason: 'id 格式非法' };
  if (typeof request.image !== 'string' || !request.image.trim()) {
    return { ok: false, reason: '缺少镜像引用' };
  }
  const requestedAt = Date.parse(request.requestedAt);
  if (!Number.isFinite(requestedAt)) return { ok: false, reason: 'requestedAt 非法' };
  if (now - requestedAt > cfg.requestTtlMs) {
    return { ok: false, reason: '请求已超过 TTL（代理离线期间积压，需重新发起）' };
  }
  if (requestedAt - now > 5 * 60 * 1000) {
    return { ok: false, reason: 'requestedAt 在未来，拒绝执行' };
  }
  const userId =
    request.requestedBy && typeof request.requestedBy.userId === 'string'
      ? request.requestedBy.userId
      : '';
  const signatureOk = verifyUpgradeRequest(
    cfg.hmacSecret,
    {
      id: request.id,
      image: request.image,
      requestedAt: request.requestedAt,
      userId,
    },
    request.signature
  );
  if (!signatureOk) {
    return { ok: false, reason: '签名校验失败（请求被篡改，或代理与应用密钥不一致）' };
  }
  try {
    const parsed = policy.parseImageRef(request.image);
    policy.assertImageAllowed(parsed, cfg.allowlist);
  } catch (err) {
    return { ok: false, reason: err.message };
  }
  return { ok: true };
}

/** 子进程回收的宽限期：SIGTERM 之后等这么久还没退出就升级为 SIGKILL */
const CHILD_KILL_GRACE_MS = 10 * 1000;

/**
 * 收回子进程并**等它真的退出**。
 *
 * 只发一个 SIGTERM 就往下走是不够的：信号是异步投递的，而下游 processRequest 紧接着
 * 会写失败终态、删请求文件、释放锁——三者完成后就再没人知道那个升级进程还活着。
 * 返回的 Promise 在 close 事件或宽限期用尽后必定 resolve，绝不 reject（收尾路径不许抛）。
 * @param {import('child_process').ChildProcess} child
 * @param {number} [graceMs]
 * @returns {Promise<void>}
 */
function killChildAndWait(child, graceMs = CHILD_KILL_GRACE_MS) {
  return new Promise((done) => {
    let settled = false;
    const finish = () => {
      if (settled) return;
      settled = true;
      done();
    };
    if (child.exitCode !== null || child.signalCode !== null) return finish();
    child.once('close', finish);
    // 子进程可能已经退出：kill 会抛 ESRCH，而 error 事件若没人接就是未处理异常。
    child.on('error', () => {});
    try {
      child.kill('SIGTERM');
    } catch {
      /* 已退出 */
    }
    setTimeout(() => {
      if (settled) return;
      try {
        child.kill('SIGKILL');
      } catch {
        /* 已退出 */
      }
      setTimeout(finish, graceMs);
    }, graceMs);
  });
}

/**
 * 默认执行器：固定脚本、固定参数、镜像走环境变量。
 * 不做 shell 拼接——请求里的 image 已经过 parseImageRef 校验，但「不经过 shell」
 * 才是这条链上真正不可绕过的约束。
 */

function runUpgrade({ cfg, request, statusFile, claimedFile }) {
  const invocation = buildHotUpgradeInvocation({ nginxConf: cfg.nginxConf, statusFile });
  return new Promise((resolve) => {
    const child = spawn(invocation.file, invocation.args, {
      cwd: ROOT,
      stdio: 'inherit',
      env: {
        ...process.env,
        HOT_UPGRADE_IMAGE: request.image,
        HOT_UPGRADE_REGISTRY_ALLOWLIST: cfg.allowlist.join(','),
        HOT_UPGRADE_NGINX_CONF: cfg.nginxConf,
        ...(cfg.composeFile ? { HOT_UPGRADE_COMPOSE_FILE: cfg.composeFile } : {}),
      },
    });
    // 先记 pid 再等结果：记不下去（磁盘满、processing/ 不可写、原子写复核失败）时
    // 必须把子进程收回来——否则 processRequest 会按 spawn_failed 收尾、删掉请求文件、
    // 释放锁，而升级本身仍在跑并可能已经切流：宿主上留着一个没人跟踪的升级进程。
    try {
      updateProcessing(cfg, claimedFile, { childPid: child.pid });
    } catch (err) {
      // 收尾必须等到「确认死透」再返回：SIGTERM 是异步的，立即 resolve 会让
      // processRequest 马上写 spawn_failed、删掉请求文件、释放锁，而升级脚本（连同它的
      // docker / nginx 子进程）还在跑——宿主上就留下一个没人跟踪的升级，可能与下一次
      // 升级并发切流。故：SIGTERM → 等 close → SIGKILL → 再等。
      killChildAndWait(child).then(() =>
        resolve({ code: -1, error: `记录子进程 pid 失败：${err.message}` })
      );
      return;
    }
    child.on('error', (err) => resolve({ code: -1, error: err.message }));
    child.on('close', (code) => resolve({ code }));
  });
}

function prepareRequest(cfg, file, now) {
  const name = path.basename(file);
  const id = name.slice(0, -'.json'.length);
  if (!JOB_ID_RE.test(id)) {
    quarantine(cfg, file, '');
    return { ok: false, reason: '请求文件名不是合法任务 id' };
  }
  let stat;
  try {
    stat = fs.lstatSync(file);
  } catch {
    return { ok: false, reason: '请求文件已消失' };
  }
  if (!stat.isFile() || stat.size > MAX_JSON_BYTES) {
    quarantine(cfg, file, id);
    return { ok: false, reason: '请求文件不是普通文件或尺寸超限' };
  }
  const request = readJsonFile(file);
  if (!request || typeof request !== 'object') {
    quarantine(cfg, file, id);
    return { ok: false, reason: '请求不是合法 JSON' };
  }
  if (request.id !== id) {
    quarantine(cfg, file, id);
    return { ok: false, reason: '请求 id 与文件名不一致' };
  }
  if (isTerminal(statusOf(cfg, id))) {
    // 重复投递：上一轮已经处理过，直接移除，避免每轮重试
    try {
      fs.unlinkSync(file);
    } catch {
      // 下一轮再清
    }
    return { ok: false, reason: '该任务已有终态，忽略重复请求' };
  }
  const validation = validateRequest(request, cfg, now);
  if (!validation.ok) {
    writeStatus(cfg, id, {
      state: 'failed',
      outcome: 'rejected',
      image: typeof request.image === 'string' ? request.image : '',
      requestedAt: typeof request.requestedAt === 'string' ? request.requestedAt : null,
      requestedBy: request.requestedBy,
      sourceIp: request.sourceIp,
      finishedAt: new Date(now).toISOString(),
      message: validation.reason,
    });
    quarantine(cfg, file, id);
    return { ok: false, reason: validation.reason };
  }
  return { ok: true, id, request };
}

async function processRequest(cfg, file, { executor = runUpgrade, now = Date.now() } = {}) {
  const prepared = prepareRequest(cfg, file, now);
  if (!prepared.ok) return { status: 'skipped', reason: prepared.reason };

  const { id, request } = prepared;
  const claimedFile = path.join(cfg.processingDir, `${id}.json`);
  const statusFile = path.join(cfg.statusDir, `${id}.json`);
  try {
    fs.renameSync(file, claimedFile);
  } catch (err) {
    return { status: 'skipped', reason: `认领失败：${err.message}` };
  }
  writeJsonAtomic(
    claimedFile,
    {
      ...request,
      _agent: { pid: process.pid, claimedAt: new Date(now).toISOString() },
    },
    0o640,
    // processing/ 也是应用读得到的兜底来源（status 尚未写出时）；属主对齐到队列目录，
    // 0640 让容器内 nodejs 读得到、other 读不到。
    { adoptOwner: true }
  );
  writeStatus(cfg, id, {
    state: 'running',
    image: request.image,
    requestedAt: request.requestedAt,
    requestedBy: request.requestedBy,
    sourceIp: request.sourceIp,
    startedAt: new Date(now).toISOString(),
    finishedAt: null,
    outcome: '',
    message: '',
    steps: [],
  });

  let result;
  try {
    result = await executor({ cfg, request, statusFile, claimedFile });
  } catch (err) {
    result = { code: -1, error: err.message };
  }

  if (!isTerminal(statusOf(cfg, id))) {
    if (result.error) {
      writeStatus(cfg, id, {
        state: 'failed',
        outcome: 'spawn_failed',
        message: `无法启动升级脚本：${result.error}`,
        finishedAt: new Date().toISOString(),
      });
    } else if (result.code !== 0) {
      writeStatus(cfg, id, {
        state: 'failed',
        outcome: 'exit_nonzero',
        message: `升级脚本退出码 ${result.code}（详细原因见宿主 journal 与 logs/hot-upgrade-*.json）`,
        finishedAt: new Date().toISOString(),
      });
    } else {
      writeStatus(cfg, id, {
        state: 'failed',
        outcome: 'missing_terminal',
        message: '升级脚本退出码 0，但没有写入终态；拒绝把未知结果标记为成功',
        finishedAt: new Date().toISOString(),
      });
    }
  }
  try {
    fs.unlinkSync(claimedFile);
  } catch {
    // 下一轮恢复逻辑会处理
  }
  return { status: 'executed', id, code: result.code, error: result.error || '' };
}

module.exports = {
  validateRequest,
  runUpgrade,
  prepareRequest,
  processRequest,
};
