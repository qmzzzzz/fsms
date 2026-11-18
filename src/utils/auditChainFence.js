/**
 * 审计链僵尸写入围栏（与 auditChain.js 拆分：后者卡在体积棘轮上限）
 *
 * 锁持有超时只停止**等待** fn，不会取消它（Promise.race 没有取消语义）。
 * 僵尸 fn 随后仍可能把批次提交到 DB。若此时放行下一批，它会从「僵尸写之前」
 * 的链尾续链，而僵尸提交的记录也引用同一父哈希 ⇒ 一父两子（分叉）。
 *
 * 围栏负责三件事，缺一不可：
 *  1. 本进程冻结链写入，直到僵尸落定（check 在进入临界区前调用）；
 *  2. 跨实例：超时后不释放分布式锁并周期续租，其他实例拿不到锁就无法续链；
 *  3. 僵尸落定后先强制重同步（DB 是唯一权威），再解冻、再释放锁。
 * 进程崩溃时续租停止，锁按最后一个 PX 自然到期——不会永久占锁。
 */

const logger = require('./logger');
const metrics = require('./metrics');

let frozen = false;

/** 进入链写入临界区前调用：冻结窗口内直接失败，由调用方回退（缓冲重试 / 无哈希降级） */
const check = () => {
  if (frozen) {
    // 措辞覆盖两种冻结来源（持锁超时的僵尸 / 前驱等待超时），只陈述共同事实：
    // 上一批还没落定。两种冻结都有唯一解冻归属（waitForZombie：落定→重同步→解冻）。
    throw new Error('审计链处于僵尸写入冻结窗口（上一批尚未落定），本批回退');
  }
};

const freeze = () => {
  frozen = true;
};

const reset = () => {
  frozen = false;
};

const isFrozen = () => frozen;

const renewalBudgetMs = (ttlMs) =>
  require('./envNumber').readPositiveNumberEnv(
    'AUDIT_CHAIN_ZOMBIE_RENEWAL_BUDGET_MS',
    Math.max(ttlMs * 10, 60000),
    {
      onInvalid: (name, raw, d) =>
        logger.error(`${name}=${JSON.stringify(raw)} 非法（须为正的毫秒数），已按默认 ${d} 处理`),
    }
  );

/**
 * 僵尸 fn 落定前的收尾：保持/续租分布式锁；落定后重同步再解冻、释放。
 * @param {Promise} work 仍在飞行的临界区 fn
 * @param {{release:Function, renew?:Function}|null} distLock 超时前持有的分布式锁
 * @param {object} opts
 * @param {number} opts.ttlMs 锁租约（PX）与续租基准
 * @param {Function} opts.resync 落定后的强制重同步（须在解冻前 await 完成）
 */
const waitForZombie = (work, distLock, { ttlMs, resync }) => {
  let renewTimer = null;
  if (distLock && typeof distLock.renew === 'function') {
    // 续租间隔取租约的 1/3：留两次重试余量。下限 10ms 只防极小配置下的忙循环。
    const renewEveryMs = Math.max(10, Math.floor(ttlMs / 3));
    const renewDeadline = Date.now() + renewalBudgetMs(ttlMs);
    renewTimer = setInterval(() => {
      if (Date.now() >= renewDeadline) {
        clearInterval(renewTimer); // P3 续租上界：超界停手，让锁按 PX 过期（无限续租=链锁永久占死）
        renewTimer = null;
        logger.error(
          `审计链僵尸写入超过续租上界（ttl=${ttlMs}ms），已停止续租分布式锁——锁将按 PX 过期，` +
            '其余实例可接管；请排查悬挂的审计写入（Mongo 无响应/网络半开等）'
        );
        try {
          metrics.incSecurityAlert('audit_chain_zombie_renewal_exceeded', 'high');
        } catch (_) {}
        return;
      }
      Promise.resolve(distLock.renew(ttlMs)).catch(() => {});
    }, renewEveryMs);
    if (renewTimer.unref) renewTimer.unref();
  }

  const settle = async () => {
    if (renewTimer) clearInterval(renewTimer);
    try {
      // 顺序不能反：先解冻会让后继批次在重同步完成前读到僵尸写之前的旧尾
      await resync();
    } catch (_) {
      /* resync 自身吞错；这里只保证冻结一定解除 */
    } finally {
      frozen = false;
      if (distLock) {
        try {
          await distLock.release();
        } catch (_) {
          /* 锁会随 PX 到期 */
        }
      }
    }
  };
  // 两个分支都接：僵尸失败时的 rejection 绝不能变成 unhandledRejection
  work.then(settle, settle);
};

/** 冻结后继链写入并挂上唯一解冻归属（work 落定 → resync → 解冻）。
 * 「本调用持锁超时」与「前驱等待超时」两处冻结共用这一入口：
 * 冻结本身不产生解冻路径，解冻归属一律由这里的 waitForZombie 登记。 */
const freezeAndWaitFor = (work, ttlMs, resync) => {
  freeze();
  waitForZombie(work, null, { ttlMs, resync });
};

module.exports = { check, freeze, reset, isFrozen, waitForZombie, freezeAndWaitFor };
