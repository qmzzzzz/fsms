#!/usr/bin/env node
/**
 * 宿主机热升级代理（由 systemd timer 每 15s 拉起一次）
 *
 * 应用容器没有 docker socket，也不该有：把宿主 docker 控制面交给一个对外提供
 * HTTP 的进程，等于把「容器逃逸」做成常驻攻击面。因此应用只往共享目录里放一份
 * 签名的升级请求（requests/<uuid>.json），真正的 docker/nginx 动作由本脚本执行。
 *
 * 每轮动作：
 *   1. 写心跳（应用据此判断代理是否在线；升级期间每 10s 续一次）
 *   2. 自检（白名单 / HMAC / nginx 配置）——任一不满足就只写心跳，不消费请求
 *   3. 扫描离线包目录（OFFLINE_BUNDLE_DIR，只读 manifest + 白名单，不算 payload 哈希），
 *      把可用包摘要并入心跳 bundles——应用侧「一键离线升级」的下拉候选来自这里，
 *      全量校验仍只在执行时由 importOfflineBundle.js 做
 *   4. 认领最早的一条请求（requests → processing），由 hotUpgradeJob 重新做全部判据
 *   5. 用固定脚本、固定参数执行（镜像经 HOT_UPGRADE_IMAGE 传入，不进 argv）
 *   6. 把终态写回 status/<uuid>.json，应用侧轮询展示
 *
 * 安全边界：签名只防「能写队列目录的本机用户伪造升级指令」，不防应用被攻陷
 * （应用与代理共用同一把 HMAC）。真正的边界在这里——无论签名是否通过，都重新
 * 跑 digest 钉扎 + 白名单，且只执行 scripts/hotUpgrade.js。
 *
 * 用法：
 *   node scripts/hotUpgradeAgent.js --once      # systemd timer 的调用形态
 *   node scripts/hotUpgradeAgent.js --help
 */

'use strict';

const fs = require('fs');
const path = require('path');

const queue = require('./hotUpgradeQueue');
const { processRequest, runUpgradeByMode } = require('./hotUpgradeJob');
const { scanBundles } = require('./offlineBundleScan');

const { JOB_ID_RE, readJsonFile, listJsonFiles, writeStatus, statusOf, isTerminal } = queue;
const { pidAlive, LOCK_STALE_MS } = queue;

const log = (msg) => process.stdout.write(`[hot-upgrade-agent] ${msg}\n`);
const warn = (msg) => process.stderr.write(`[hot-upgrade-agent] 警告：${msg}\n`);

/**
 * 自检。reasons 会原样经心跳回给上层（应用端展示），因此：
 *   · 文案必须运维可读（「白名单为空」这类说法要能一眼看懂）；
 *   · 不得泄漏宿主绝对路径（nginx 主配置、密钥文件都只说逻辑名）。
 */
function assessReadiness(cfg) {
  const reasons = [];
  if (cfg.allowlist.length === 0) {
    reasons.push('镜像仓库白名单为空（HOT_UPGRADE_REGISTRY_ALLOWLIST 为空，空白名单按全拒处理）');
  }
  if (cfg.hmacError) reasons.push(cfg.hmacError);
  else if (!cfg.hmacSecret) reasons.push('缺少 HMAC 密钥（HMAC_SECRET / HMAC_SECRET_FILE）');
  else if (cfg.hmacSecret.length < 16) reasons.push('HMAC 密钥短于 16 字符，无法验签');
  if (!fs.existsSync(cfg.nginxConf)) {
    reasons.push('nginx 主配置不存在（--nginx-conf / HOT_UPGRADE_NGINX_CONF 指定的文件）');
  }
  return { ready: reasons.length === 0, reasons };
}

/**
 * 崩溃恢复：processing/ 里还留着任务，说明上一轮代理没有正常收尾。
 * 若记录的子进程仍活着，说明升级还在跑，本轮直接让路；否则写失败终态。
 */
function recoverStale(cfg, { isAlive = pidAlive, now = Date.now() } = {}) {
  for (const file of listJsonFiles(cfg.processingDir)) {
    const raw = readJsonFile(file);
    const id = path.basename(file, '.json');
    const agent = raw && raw._agent && typeof raw._agent === 'object' ? raw._agent : {};
    // 认领超过 3h 一律按「代理已中断」处理：pid 会被复用，而只判存活时一个恰好复用了
    // 旧 pid 的无关进程会让队列永久 busy（systemd 单元把单次升级限死在 2h；超过它还没有
    // 终态，本身已是异常状态，继续让路只会把所有后续请求一起挡住）。
    const claimedAt = Date.parse(agent.claimedAt || '');
    const tooOld = Number.isFinite(claimedAt) && now - claimedAt > LOCK_STALE_MS;
    if (!tooOld && (isAlive(agent.pid) || isAlive(agent.childPid))) {
      return { busy: true, id };
    }
    if (tooOld) {
      warn(`processing/${id} 的认领已超过上限（按代理中断处理，避免 pid 复用让队列永久忙）`);
    }
    if (JOB_ID_RE.test(id) && !isTerminal(statusOf(cfg, id))) {
      writeStatus(cfg, id, {
        state: 'failed',
        outcome: 'agent_lost',
        message: '升级代理中断且子进程已退出，无法确认最终状态；请检查当前线上色后再重试',
        finishedAt: new Date(now).toISOString(),
      });
    }
    try {
      fs.unlinkSync(file);
    } catch {
      // 下一轮再清
    }
  }
  return { busy: false };
}

async function runOnce({ env = process.env, executor = runUpgradeByMode, now = Date.now } = {}) {
  const cfg = queue.loadConfig(env);
  queue.ensureDirs(cfg);

  const lock = queue.acquireLock(cfg);
  if (!lock) {
    queue.writeHeartbeat(cfg, {
      busy: true,
      ready: false,
      reasons: ['另一个代理实例正在执行升级'],
    });
    log('已有代理实例持有锁，本轮跳过');
    return 0;
  }

  let beat = { ready: false, reasons: ['自检尚未完成'] };
  const timer = setInterval(() => {
    try {
      queue.writeHeartbeat(cfg, beat);
    } catch (err) {
      warn(`心跳写入失败：${err.message}`);
    }
  }, cfg.heartbeatIntervalMs);

  try {
    const readiness = assessReadiness(cfg);
    // 离线包扫描只影响心跳内容，不影响 ready：离线通道坏了（目录不可读、全是坏包）
    // 不许把在线升级一起拖红。目录不可读的原因折进 reasons 让应用侧如实展示。
    const bundles = scanBundles({ bundlesDir: cfg.bundlesDir, allowlist: cfg.allowlist });
    const reasons = [...readiness.reasons];
    if (bundles.error) reasons.push(bundles.error);
    beat = {
      ready: readiness.ready,
      reasons,
      bundles: { available: bundles.available, invalid: bundles.invalid },
    };
    queue.writeHeartbeat(cfg, beat);
    if (!readiness.ready) {
      log(`代理未就绪：${readiness.reasons.join('；')}`);
      return 0;
    }

    const recovered = recoverStale(cfg);
    if (recovered.busy) {
      log(`上一轮任务 ${recovered.id} 仍在执行，本轮跳过`);
      return 0;
    }

    // 按 requestedAt 升序认领：readdir 的顺序与「请求何时到达」无关，
    // 不排序时后发的请求有可能先被执行（用户连点两次时表现为「最新那次先生效」）
    for (const file of queue.orderByRequestedAt(listJsonFiles(cfg.requestsDir))) {
      const outcome = await processRequest(cfg, file, { executor, now: now() });
      if (outcome.status === 'executed') {
        log(`任务 ${outcome.id} 结束（退出码 ${outcome.code}）`);
        break;
      }
      if (outcome.status === 'skipped') log(`跳过请求 ${path.basename(file)}：${outcome.reason}`);
    }
    queue.pruneStatus(cfg);
    return 0;
  } finally {
    clearInterval(timer);
    lock.release();
    try {
      queue.writeHeartbeat(cfg, beat);
    } catch {
      // 退出前的心跳失败不值得让服务判失败
    }
  }
}

function main(argv) {
  if (argv.includes('--help')) {
    process.stdout.write(
      [
        '宿主机热升级代理。默认执行一轮队列检查（给 systemd timer 用）。',
        '',
        '  --once    执行一轮后退出（默认行为，显式写出便于 unit 文件自解释）',
        '  --help    本帮助',
        '',
      ].join('\n')
    );
    return Promise.resolve(0);
  }
  const unknown = argv.filter((arg) => arg !== '--once');
  if (unknown.length > 0) {
    process.stderr.write(`未知参数：${unknown.join(' ')}\n`);
    return Promise.resolve(1);
  }
  return runOnce();
}

if (require.main === module) {
  main(process.argv.slice(2))
    .then((code) => process.exit(code))
    .catch((err) => {
      process.stderr.write(`[hot-upgrade-agent] 失败：${err && err.message ? err.message : err}\n`);
      process.exit(1);
    });
}

module.exports = {
  runOnce,
  main,
  assessReadiness,
  recoverStale,
};
