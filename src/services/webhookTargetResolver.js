/**
 * Webhook 目标的域名解析与 IP 钉扎（DNS 重绑定防护）。
 *
 * `isWebhookTargetAllowed` 只能判定 URL 里的字面量；域名在「校验」与「连接」之间
 * 还能被重新解析（TOCTOU）：校验时解析到公网地址通过检查，连接时第二次解析
 * 指向 127.0.0.1 / 169.254.169.254。这里只解析一次，把结果钉进 http 客户端的
 * lookup 选项，连接期不再发起 DNS 查询。
 *
 * 多地址口径：任一 A/AAAA 落在禁止网段就拒绝整条投递。轮询 DNS 可能返回
 * 「一个公网 + 一个内网」，只挑看起来合法的那个等于把选择权交给解析器。
 *
 * 解析设绝对超时：DNS 卡死时告警投递不能无限挂起（登录/导出路径会 await 它）。
 */

const dns = require('dns');
const net = require('net');
const logger = require('../utils/logger');

const DEFAULT_DNS_TIMEOUT_MS = 3000;

const dnsTimeoutMs = () => {
  const configured = Number(process.env.SECURITY_ALERT_DNS_TIMEOUT_MS);
  return Number.isFinite(configured) && configured > 0 ? configured : DEFAULT_DNS_TIMEOUT_MS;
};

const lookupAll = (hostname) =>
  new Promise((resolve, reject) => {
    let done = false;
    const timer = setTimeout(() => {
      if (done) return;
      done = true;
      reject(Object.assign(new Error('DNS 解析超时'), { code: 'ETIMEDOUT' }));
    }, dnsTimeoutMs());
    if (timer.unref) timer.unref();

    dns.promises.lookup(hostname, { all: true, verbatim: true }).then(
      (rows) => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        resolve(rows);
      },
      (err) => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        reject(err);
      }
    );
  });

/**
 * 解析目标主机并返回需要钉住的地址
 * @param {string} hostname `URL.hostname` 原值（IPv6 可能带方括号）
 * @param {(address: string) => boolean} isForbidden 地址是否禁止，由调用方提供网域策略
 * @returns {Promise<{ok: true, address: string, family: number}|{ok: false}>}
 */
async function resolvePinnedTarget(hostname, isForbidden) {
  const bare = hostname.replace(/^\[/, '').replace(/\]$/, '');
  const literalFamily = net.isIP(bare);
  if (literalFamily) return { ok: true, address: bare, family: literalFamily };

  let rows;
  try {
    rows = await lookupAll(bare);
  } catch (err) {
    logger.warn(`安全告警 webhook 域名解析失败，跳过投递（${bare}）：${err.code || err.message}`);
    return { ok: false };
  }
  if (!Array.isArray(rows) || rows.length === 0) {
    logger.warn(`安全告警 webhook 域名未解析到任何地址，跳过投递（${bare}）`);
    return { ok: false };
  }

  for (const row of rows) {
    if (isForbidden(row.address)) {
      logger.warn(`安全告警 webhook 域名解析到禁止地址，跳过投递（${bare} → ${row.address}）`);
      return { ok: false };
    }
  }

  return { ok: true, address: rows[0].address, family: rows[0].family };
}

module.exports = { resolvePinnedTarget };
