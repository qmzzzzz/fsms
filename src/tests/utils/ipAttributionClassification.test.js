/**
 * 客户端 IP 的**来源分类**（utils/ipUtils.js → classifyIpAttribution）
 *
 * 由来（2026-10-01 审计第 3 轮）：权限滥用检测把 `req.ip` 直接当**封禁目标**
 * （rbac.js:76 → securityAlert.js:407 → securityAlertPermissionAbuse.js:96）。
 * 实测：`trust proxy=1` + 回环/内网对端时，请求方自带
 * `X-Forwarded-For: 203.0.113.9` 就让 `req.ip === 203.0.113.9`，而本仓读侧判据
 * `isClientIpIdentityTrustworthy` 对该形态返回 **true**——它本来就是为"经 nginx 的
 * 真实客户"设计的。于是同一个字段在两侧要的信任规则相反：
 *   - 读侧（准入 allowedIPs、白名单豁免、限流配额）：采信代理写入的值是对的；
 *   - 写侧（把一个地址封进黑名单 = 对该地址的所有使用者施加动作）：这个值可能是
 *     请求方自己写的，也可能确实是它的源地址——**应用内部无法区分**
 *     「互联网客户经 nginx」与「同网络内另一容器直连 app:3000 并自带 XFF」。
 * 因此本函数不假装能区分，而是把来源**分类并留痕**，让惩罚动作知道自己踩在哪块地上。
 *
 * 关键不变式（第 6 条用例钉住）：TRUSTED_PROXY 与"可信"是可以同时成立的——
 * 所以任何"封禁前先用 isClientIpIdentityTrustworthy 把关"的直觉修法都是**无效修复**，
 * 它拦不住上面那条伪造路径。出路只能是架构层（应用端口只允许代理可达）或
 * 改按不可伪造的 userId 遏制。
 */

const express = require('express');
const request = require('supertest');
const {
  classifyIpAttribution,
  isClientIpIdentityTrustworthy,
  IP_ATTRIBUTION_KINDS,
} = require('../../utils/ipUtils');

/** 替身 req：分类只读两个面（ip 与 socket 对端），不猜任何头 */
const makeReq = ({ ip, peer }) => ({
  ip,
  socket: peer === undefined ? undefined : { remoteAddress: peer },
});

/** 起一个真实 express app，按生产口径配 trust proxy，回传分类结果 */
const probe = async ({ hops, xff }) => {
  const app = express();
  app.set('trust proxy', hops > 0 ? hops : false);
  app.get('/probe', (req, res) => res.json(classifyIpAttribution(req)));
  const server = await new Promise((resolve) => {
    const s = app.listen(0, '127.0.0.1', () => resolve(s));
  });
  try {
    const res = await request(server)
      .get('/probe')
      .set(xff === undefined ? {} : { 'X-Forwarded-For': xff });
    return res.body;
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
};

describe('客户端 IP 来源分类（classifyIpAttribution）', () => {
  test('真实链路·trust proxy 关闭：自带 XFF 也改不动 req.ip ⇒ DIRECT', async () => {
    const got = await probe({ hops: 0, xff: '203.0.113.9' });
    expect({ kind: got.kind, spoofed: got.reportedIp === '203.0.113.9' }).toMatchObject({
      kind: IP_ATTRIBUTION_KINDS.DIRECT,
      spoofed: false,
    });
    expect(got.reportedIp).toBe(got.socketPeer);
  });

  test('真实链路·trust proxy=1 + 回环对端 + 自带 XFF ⇒ TRUSTED_PROXY（P1 的实测形状）', async () => {
    const got = await probe({ hops: 1, xff: '203.0.113.9' });
    expect(got.kind).toBe(IP_ATTRIBUTION_KINDS.TRUSTED_PROXY);
    expect(got.reportedIp).toBe('203.0.113.9');
    // 对端是回环（测试进程自己），报出来的"客户端"却是被写入的地址——两者必然不同
    expect(got.socketPeer).not.toBe(got.reportedIp);
  });

  test('真实链路·无 XFF 时经代理也算 DIRECT 之外的可信形态不成立', async () => {
    // trust proxy 开着但请求没带 XFF：express 的 req.ip 只能是对端 ⇒ 惩罚可执行
    const got = await probe({ hops: 1, xff: undefined });
    expect(got.kind).toBe(IP_ATTRIBUTION_KINDS.DIRECT);
  });

  test('公网对端却收到 XFF ⇒ PUBLIC_PEER_HEADER（与读侧「不可信」同口径）', () => {
    // 形状要自洽：req.ip 与对端不同，本身就意味着 trust proxy 开着且头起了作用
    const req = {
      app: { get: (k) => (k === 'trust proxy' ? 1 : undefined) },
      get: (h) => (h.toLowerCase() === 'x-forwarded-for' ? '203.0.113.9' : undefined),
      socket: { remoteAddress: '8.8.8.8' },
      ip: '203.0.113.9',
    };
    expect(classifyIpAttribution(req).kind).toBe(IP_ATTRIBUTION_KINDS.PUBLIC_PEER_HEADER);
    expect(isClientIpIdentityTrustworthy(req)).toBe(false);
  });

  test('取不到 socket 对端 ⇒ UNVERIFIABLE（不猜测，惩罚侧按不可执行处理）', () => {
    const req = makeReq({ ip: '203.0.113.9' });
    expect(classifyIpAttribution(req).kind).toBe(IP_ATTRIBUTION_KINDS.UNVERIFIABLE);
  });

  test('IPv4-mapped 与纯 IPv4 是同一地址 ⇒ DIRECT（与名单侧共用 normalizeIP 这把尺）', () => {
    for (const [ip, peer] of [
      ['::ffff:127.0.0.1', '127.0.0.1'],
      ['127.0.0.1', '::ffff:127.0.0.1'],
      ['::FFFF:203.0.113.9', '203.0.113.9'],
    ]) {
      expect({ ip, peer, kind: classifyIpAttribution(makeReq({ ip, peer })).kind }).toMatchObject({
        ip,
        peer,
        kind: IP_ATTRIBUTION_KINDS.DIRECT,
      });
    }
  });

  test('不变式：TRUSTED_PROXY 与「读侧可信」同时成立——所以读侧判据不能当封禁闸门', () => {
    const req = {
      app: { get: (k) => (k === 'trust proxy' ? 1 : undefined) },
      get: (h) => (h.toLowerCase() === 'x-forwarded-for' ? '203.0.113.9' : undefined),
      socket: { remoteAddress: '172.18.0.3' },
      ip: '203.0.113.9',
    };
    expect(classifyIpAttribution(req).kind).toBe(IP_ATTRIBUTION_KINDS.TRUSTED_PROXY);
    // 这一行就是"直觉修法无效"的证据：拿它当封禁闸门，同网络内伪造 XFF 照样通过
    expect(isClientIpIdentityTrustworthy(req)).toBe(true);
  });
});
