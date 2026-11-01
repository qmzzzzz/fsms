/* ===== 附录（2026-10-31 注释密度治理迁出）：src/utils/logShippingTarget.js 的原委 =====
 * * 出站目标的地址判据与「发送前钉扎」（DNS 重绑定防护）。
 * *
 * * 从 utils/logShipper.js 抽出（2026-10-31，审计一-4 后续加固项）：该文件已顶
 * * `max-lines` 棘轮阈值，而这一整块判据与 winston 传输层零耦合——它只回答两个问题：
 * *   ① 这个主机名/地址能不能发？（私网/回环/链路本地/歧义 IPv4 默认拒，显式放行优先）
 * *   ② 域名解析出的**地址**能不能发？（解析只做一次，结果交给 http 客户端的 lookup，
 * *      连接期不再查询——关闭"判据通过 → 真正连接"之间的 TOCTOU 窗口）
 * * 判据与钉扎放在同一文件里是刻意的：两处各写一份时，一处收紧、另一处没跟，缺口
 * * 会从没跟的那一侧原样打开，而两条路径看起来都"有校验"。
 * *
 * * 与 services/webhookTargetResolver 同形（告警 webhook 早已这么做）；差别只在
 * * 放行变量的名字与文案，故未强行合并——合并会让两处运维语义绑死，而告警与日志
 * * 转发是两个可独立关闭的功能。
 * 迁出理由：NEW_FILE_MAX=0.30 的密度上限；正文当前约束在源码一行内保留，完整权衡留在这里。
 */

/**
 * 日志转发的出站目标：DNS 重绑定窗口收口（2026-10-31，审计一-4 的后续加固项）
 *
 * 缺口形状（原实现）：判据只看 URL 里的**字面量**，域名在"判据通过"与"真正连接"
 * 之间还能被重新解析一次（TOCTOU）——判据通过时解析到公网地址，连接时第二次解析
 * 指向 127.0.0.1 / 169.254.169.254（云元数据端点），于是日志批与 Bearer 令牌
 * 发给了一个从未被任何判据看过的主机。头注释当时如实登记了这个窗口，
 * 本套件把它钉住：解析只做一次，结果进 http 客户端的 lookup，连接期不再查询。
 *
 * 判据可用性依赖两件事，缺一条结论就不成立：
 *   ① 解析出的地址要过与字面量**同一把尺**（私网/回环/链路本地/歧义 IPv4 一律拒）；
 *   ② 解析只发生一次 —— 只测 ① 的话，"先校验后重解析"的实现照样能通过 ①。
 *      第 ② 条用"lookup 调用次数"与"本地真实 server 是否收到批"共同钉住
 *      （mock 只能验证调用序列，真实 server 才验证真的连到了钉住的那个地址）。
 */

'use strict';

const dns = require('dns');
const http = require('http');

const { HttpShipperTransport } = require('../../utils/logShipper');
// 判据与钉扎住在独立模块里（logShipper 顶 max-lines 棘轮阈值，2026-10-31 抽出）
const { isForbiddenShippingAddress, pinShippingTarget } = require('../../utils/logShippingTarget');

const ALLOW_ENV = 'LOG_SHIPPING_ALLOW_PRIVATE_HOSTS';
const savedAllow = process.env[ALLOW_ENV];

/** 用 dns.promises.lookup 的替身喂确定的解析结果（不出网） */
const stubLookup = (rows) => {
  const spy = jest.spyOn(dns.promises, 'lookup');
  if (rows instanceof Error) {
    spy.mockRejectedValue(rows);
    return spy;
  }
  spy.mockResolvedValue(rows);
  return spy;
};

afterEach(() => {
  jest.restoreAllMocks();
  if (savedAllow === undefined) delete process.env[ALLOW_ENV];
  else process.env[ALLOW_ENV] = savedAllow;
});

describe('isForbiddenShippingAddress：禁止地址的真值表', () => {
  test('私网 / 回环 / 链路本地（含 IPv6 与 IPv4-mapped）一律判禁', () => {
    delete process.env[ALLOW_ENV];
    for (const addr of [
      '127.0.0.1',
      '10.1.2.3',
      '192.168.1.1',
      '172.16.0.9',
      '169.254.169.254',
      '::1',
      'fd00::1',
      '::ffff:127.0.0.1',
    ]) {
      expect(isForbiddenShippingAddress(addr)).toBe(true);
    }
  });

  test('歧义 IPv4 形态判禁（OS 会当 127.0.0.1 连，严格解析却看不出私网）', () => {
    delete process.env[ALLOW_ENV];
    for (const addr of ['127.1', '2130706433', '0x7f.0.0.1']) {
      expect(isForbiddenShippingAddress(addr)).toBe(true);
    }
  });

  test('公网地址判放行（判据不是"一律拒绝"）', () => {
    delete process.env[ALLOW_ENV];
    for (const addr of ['203.0.113.9', '198.51.100.4', '8.8.8.8', '2606:4700::1111']) {
      expect(isForbiddenShippingAddress(addr)).toBe(false);
    }
  });

  test('显式放行优先：IP/网段条目命中即放行，未声明的地址仍判禁', () => {
    process.env[ALLOW_ENV] = '10.0.0.5,192.168.5.0/24,::1';
    expect(isForbiddenShippingAddress('10.0.0.5')).toBe(false);
    expect(isForbiddenShippingAddress('192.168.5.9')).toBe(false);
    expect(isForbiddenShippingAddress('::1')).toBe(false);
    // 只放行声明的目标：同网段的近邻不因"看着像"而免检
    expect(isForbiddenShippingAddress('10.0.0.6')).toBe(true);
  });
});

describe('pinShippingTarget：解析一次并钉住', () => {
  test('IP 字面量直接返回（没有解析这一步，也就没有重绑定窗口）', async () => {
    delete process.env[ALLOW_ENV];
    const spy = stubLookup(new Error('不应被调用'));
    await expect(pinShippingTarget({ hostname: '203.0.113.9' })).resolves.toEqual({
      address: '203.0.113.9',
      family: 4,
    });
    expect(spy).not.toHaveBeenCalled();
  });

  test('域名解析到公网地址 ⇒ 返回该地址；多地址里任一为禁止地址 ⇒ 整体拒绝', async () => {
    delete process.env[ALLOW_ENV];
    stubLookup([{ address: '203.0.113.9', family: 4 }]);
    await expect(pinShippingTarget({ hostname: 'siem.example' })).resolves.toEqual({
      address: '203.0.113.9',
      family: 4,
    });

    // 轮询 DNS 返回"一个公网 + 一个内网"时不得只挑合法的那个：
    // 挑法等于把"发给谁"的决定权交给解析器
    stubLookup([
      { address: '203.0.113.9', family: 4 },
      { address: '169.254.169.254', family: 4 },
    ]);
    await expect(pinShippingTarget({ hostname: 'siem.example' })).rejects.toThrow(/DNS 重绑定防护/);
  });

  test('解析失败 / 零地址 ⇒ 明确拒绝，不静默降级成"照发"', async () => {
    delete process.env[ALLOW_ENV];
    stubLookup(Object.assign(new Error('not found'), { code: 'ENOTFOUND' }));
    await expect(pinShippingTarget({ hostname: 'nope.invalid' })).rejects.toThrow(/ENOTFOUND/);

    stubLookup([]);
    await expect(pinShippingTarget({ hostname: 'nope.invalid' })).rejects.toThrow(
      /未解析到任何地址/
    );
  });

  test('主机名被显式放行时按名称放行（不按动态解析出的地址二次判禁）', async () => {
    process.env[ALLOW_ENV] = 'siem.internal';
    stubLookup([{ address: '10.0.0.9', family: 4 }]);
    await expect(pinShippingTarget({ hostname: 'siem.internal' })).resolves.toEqual({
      address: '10.0.0.9',
      family: 4,
    });
    // 反面对照：没被放行的名字解析到同一地址 ⇒ 拒绝
    stubLookup([{ address: '10.0.0.9', family: 4 }]);
    await expect(pinShippingTarget({ hostname: 'other.internal' })).rejects.toThrow(
      /DNS 重绑定防护/
    );
  });
});

describe('_post：连接期不再解析（重绑定窗口闭合的实证）', () => {
  let server;
  let received;

  afterEach(async () => {
    if (server) {
      await new Promise((resolve) => server.close(resolve));
      server = null;
    }
  });

  test('域名只解析一次，且批真的发到那个被钉住的地址', async () => {
    received = [];
    server = http.createServer((req, res) => {
      let body = '';
      req.on('data', (c) => {
        body += c;
      });
      req.on('end', () => {
        received.push(body);
        res.writeHead(200);
        res.end('{}');
      });
    });
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = server.address().port;

    // 放行该主机名并把解析钉到回环地址：连接必须用这个地址，且不得再查一次 DNS
    process.env[ALLOW_ENV] = 'siem.internal';
    process.env.LOG_SHIPPING_ALLOW_INSECURE = 'true';
    const spy = stubLookup([{ address: '127.0.0.1', family: 4 }]);

    const t = new HttpShipperTransport({
      url: `http://siem.internal:${port}/logs`,
      timeoutMs: 2000,
      intervalMs: 60000,
    });
    try {
      await t._post(['line-1']);
    } finally {
      delete process.env.LOG_SHIPPING_ALLOW_INSECURE;
      await t.close();
    }

    // 关键判据：解析只发生一次（若连接期二次解析，这里会是 2 次）
    expect(spy).toHaveBeenCalledTimes(1);
    expect(received).toHaveLength(1);
    expect(received[0]).toContain('line-1');
  });
});
