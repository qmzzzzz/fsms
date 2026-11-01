/**
 * 出站目标地址判据 + 发送前钉扎（DNS 重绑定防护）：①主机名/字面量能不能发 ②解析出的地址能不能发。
 * 判据与钉扎同文件：两处各写一份时一处收紧另一处没跟，缺口会原样打开。解析只做一次并交给 http lookup（连接期不再查询，关闭 TOCTOU）。原委见 tests/observability/logShipperDnsPinning.test.js。
 */

'use strict';

const dns = require('dns');
const net = require('net');
const { isPrivateOrLoopback, ipMatchesEntry } = require('./ipUtils');

/** 显式放行内网目标的变量名（运维面契约，改它等于改部署配置） */
const SHIPPING_ALLOW_PRIVATE_ENV = 'LOG_SHIPPING_ALLOW_PRIVATE_HOSTS';

const shippingAllowEntries = () =>
  (process.env[SHIPPING_ALLOW_PRIVATE_ENV] || '')
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);

/** 该主机名/地址是否禁止作为出站目标：解析期与发送期必须同一把尺；显式放行优先（是"我知道目标在内网"的决策，不是判据看不出来）。 */
function isForbiddenShippingAddress(target) {
  const host = String(target || '')
    .toLowerCase()
    .replace(/^\[|\]$/g, '');
  if (!host) return false;
  if (
    shippingAllowEntries().some((entry) => entry === host || ipMatchesEntry(host, entry) === true)
  ) {
    return false;
  }
  // 歧义 IPv4（127.1 / 2130706433 / 0x7f.0.0.1）：严格解析判 null，OS 仍按 127.0.0.1 连；这类串永不可能是合法域名，按歧义拒绝（allowlist 仍可显式放行）。
  const looksLikeAmbiguousIpv4 =
    /^\d+(\.\d+){0,2}$/.test(host) || /^0[xX][0-9a-fA-F.]+$/.test(host);
  return isPrivateOrLoopback(host) || looksLikeAmbiguousIpv4;
}

/** 出站域名解析的绝对超时：DNS 卡死不能挂住冲刷器（同 webhookTargetResolver） */
const SHIPPING_DNS_TIMEOUT_MS = 3000;

/** 解析全部 A/AAAA 记录，带绝对超时（socket 级超时对 DNS 无效） */
function lookupAllAddresses(hostname) {
  return new Promise((resolve, reject) => {
    let done = false;
    const timer = setTimeout(() => {
      if (done) return;
      done = true;
      reject(Object.assign(new Error('DNS 解析超时'), { code: 'ETIMEDOUT' }));
    }, SHIPPING_DNS_TIMEOUT_MS);
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
}

/** 发送前钉死目标地址：只解析一次并交给 http lookup，关闭"判据通过→真正连接"的 TOCTOU；多地址任一落在禁止网段即拒绝整条投递（不把选择权交给解析器）。 */
async function pinShippingTarget(parsed) {
  const host = (parsed.hostname || '').toLowerCase().replace(/^\[|\]$/g, '');
  const literalFamily = net.isIP(host);
  // IP 字面量没有解析这一步，也就没有重绑定窗口（判据已在 resolveShippingTarget 里跑过）
  if (literalFamily) return { address: host, family: literalFamily };

  // 主机名条目被显式放行时不再按解析地址二次判禁（地址可能随轮询 DNS 变，按地址判会让放行时灵时不灵）；IP/网段条目仍按地址判。
  const nameExempted = shippingAllowEntries().some((entry) => entry === host);

  let rows;
  try {
    rows = await lookupAllAddresses(host);
  } catch (err) {
    throw new Error(
      `LOG_SHIPPING_URL 的域名无法解析（${host}）：${err.code || err.message}；本次投递已放弃`
    );
  }
  if (!Array.isArray(rows) || rows.length === 0) {
    throw new Error(`LOG_SHIPPING_URL 的域名未解析到任何地址（${host}）：本次投递已放弃`);
  }
  for (const row of nameExempted ? [] : rows) {
    if (isForbiddenShippingAddress(row.address)) {
      throw new Error(
        `LOG_SHIPPING_URL 的域名 ${host} 解析到内网/回环/链路本地地址（${row.address}）：` +
          '日志与 Bearer 令牌不得发往私网目标（DNS 重绑定防护）。确属内网 SIEM 时，' +
          '把该主机或网段加入 LOG_SHIPPING_ALLOW_PRIVATE_HOSTS'
      );
    }
  }
  return { address: rows[0].address, family: rows[0].family };
}

/** http.request 的 lookup：只回答钉住的地址，连接期不再解析（all:true 形态同样支持，否则 Node 20+ autoSelectFamily 会退化成"无可用地址"）。 */
const pinnedLookup = (pinned) => (hostname, options, callback) =>
  options && options.all
    ? callback(null, [{ address: pinned.address, family: pinned.family }])
    : callback(null, pinned.address, pinned.family);

function assertPublicShippingTarget(parsed) {
  // URL.hostname 对 IPv6 字面量保留方括号（'[::1]'），判据内部会剥掉
  const host = (parsed.hostname || '').toLowerCase().replace(/^\[|\]$/g, '');
  if (!host) return;
  if (isForbiddenShippingAddress(host)) {
    throw new Error(
      `LOG_SHIPPING_URL 指向内网/回环/链路本地地址（${host}）：日志与 Bearer 令牌不得发往私网目标。` +
        '确属内网 SIEM 时，把该主机或网段加入 LOG_SHIPPING_ALLOW_PRIVATE_HOSTS'
    );
  }
}

module.exports = {
  SHIPPING_ALLOW_PRIVATE_ENV,
  isForbiddenShippingAddress,
  pinShippingTarget,
  pinnedLookup,
  assertPublicShippingTarget,
};
