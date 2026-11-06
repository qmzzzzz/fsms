/**
 * 取证专用设备键：不含任何地址，因此跨网段、跨 IP 池稳定（会话指纹含网段，换段就换键）。
 * 只用客户端可交付的头：能挡「换 IP 继续打」的低成本轮换，挡不住定向改头；
 * 共享出口会多台设备同键，聚合结果必须与 IP 数一起看，不能单凭设备键封禁。
 */
const crypto = require('crypto');

const MAX_HEADER_LEN = 512;
const DEVICE_HEADERS = [
  'user-agent',
  'accept-language',
  'accept-encoding',
  'sec-ch-ua',
  'sec-ch-ua-mobile',
  'sec-ch-ua-platform',
];

const readHeader = (req, name) => String(req.get(name) || '').slice(0, MAX_HEADER_LEN);

const computeDeviceKey = (req) => {
  if (!req || typeof req.get !== 'function') return null;
  const parts = DEVICE_HEADERS.map((name) => readHeader(req, name));
  if (parts.every((part) => !part)) return null;
  const esc = (s) => s.replace(/\\/g, '\\\\').replace(/\|/g, '\\|');
  const material = parts.map(esc).join('|');
  return crypto.createHash('sha256').update(material, 'utf8').digest('hex').slice(0, 32);
};

module.exports = { computeDeviceKey, DEVICE_KEY_LEN: 32, DEVICE_HEADERS };
