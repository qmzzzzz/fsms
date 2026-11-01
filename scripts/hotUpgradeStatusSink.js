/**
 * 升级进度回写（status/<id>.json）
 *
 * 宿主代理在文件里预置 id/requestedBy/requestedAt，本模块只合并进度字段。
 * 写失败不中止升级：升级本身已经够危险，不能因为「进度条没更新」在切流中途退出；
 * 但要在 stderr 说出来，否则代理会把一次没有留痕的升级当成正常完成。
 *
 * 写盘用 0600（显式 mode）：这份文件含镜像 digest 与发起人，且与容器内应用共享同一目录；
 * 属主对齐队列目录属主，否则非 root 的应用会读不到它（权限收紧不能变成功能坏掉）。
 */

'use strict';

const queue = require('./hotUpgradeQueue');

const MAX_STEPS = 40;

function createStatusSink(file) {
  if (!file) return null;
  let base = {};
  try {
    // 与只读侧同一条取证口径：单 fd + O_NOFOLLOW + 64KB 上限。状态文件在 root 代理
    // 与应用共享的目录里，按路径读会被换成符号链接（读走宿主任意文件）。
    base = queue.readJsonFile(file) || {};
  } catch {
    base = {};
  }
  const state = {
    id: typeof base.id === 'string' ? base.id : '',
    image: typeof base.image === 'string' ? base.image : '',
    requestedAt: typeof base.requestedAt === 'string' ? base.requestedAt : null,
    requestedBy:
      base.requestedBy && typeof base.requestedBy === 'object' ? base.requestedBy : undefined,
    sourceIp: typeof base.sourceIp === 'string' ? base.sourceIp : undefined,
    state: 'running',
    startedAt: typeof base.startedAt === 'string' ? base.startedAt : new Date().toISOString(),
    finishedAt: null,
    updatedAt: null,
    outcome: '',
    message: '',
    activeColor: typeof base.activeColor === 'string' ? base.activeColor : '',
    targetColor: typeof base.targetColor === 'string' ? base.targetColor : '',
    steps: Array.isArray(base.steps) ? base.steps.slice(-MAX_STEPS) : [],
  };

  const flush = () => {
    state.updatedAt = new Date().toISOString();
    try {
      // 复用队列那份「随机临时名 + 'wx' + fsync + rename 前复核」的实现：
      // 状态文件同样落在应用可写的共享目录里，可预测的临时名会被符号链接劫持。
      // 0640：里面有镜像 digest 与发起人，故不能给 other 读；但容器内的 nodejs 必须
      // 读得到——否则升级成功后 processing 被删、status 又打不开，界面看到的是「任务消失」。
      queue.writeJsonAtomic(file, state, 0o640, { adoptOwner: true });
    } catch (err) {
      process.stderr.write(`[hot-upgrade] 警告：状态文件写入失败（${err.message}）\n`);
    }
  };
  flush();

  return {
    detail(patch) {
      Object.assign(state, patch);
      flush();
    },
    step(entry) {
      state.steps.push(entry);
      if (state.steps.length > MAX_STEPS) state.steps = state.steps.slice(-MAX_STEPS);
      flush();
    },
    finish(nextState, { outcome = '', message = '' } = {}) {
      state.state = nextState;
      state.outcome = outcome;
      state.message = message;
      state.finishedAt = new Date().toISOString();
      flush();
    },
  };
}

module.exports = { createStatusSink };
