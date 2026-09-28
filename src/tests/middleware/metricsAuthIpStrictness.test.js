'use strict';

/**
 * /metrics 的内网判据必须用严格解析（ipUtils.parseIP）——定级：加固
 *
 * 先说可达性，免得后人把这段读成"这里曾有个高危洞"：
 * 唯一生产调用方 `createMetricsAuth` 传的是 `req.socket.remoteAddress`（M-07 修复），
 * 不受任何请求头影响、且由 OS 给出规范形态 ⇒ 宽松数值形态**今天进不到这个函数**。
 * 所以本文件钉的不是"当前可被绕过"，而是"这个 exported 判据收到请求文本时不许放行"。
 *
 * 为什么仍值得钉：函数名与签名都不体现"输入必须是 socket 对端"这层契约。
 * 一旦有人拿它去判 req.ip（或 M-07 被回退），修复前的实现会把下面五种文本
 * 一律判成"环回"⇒ 放行 /metrics（实测，直接调用本函数）：
 *   0177.0.0.1 / 0x7f.0.0.1 / 2130706433 / 017700000001 / 127.1
 * 而 /metrics 暴露 QPS、延迟、错误率与**安全告警计数**。
 * 与 同一根因，收口的也是同一类"第二把尺子"。
 *
 * 每条拒绝用例都配一条"这段文本确实指向 127.0.0.1"的正证
 * （lenientAddressHint 仍按 ipaddr 的宽松解释给出地址）：
 * 否则用例可能只是在证明"这串垃圾解析不出"，那不是本判据要钉的东西。
 */

const { isPrivateOrLoopback } = require('../../middleware/metricsAuth');
const { lenientAddressHint } = require('../../utils/ipUtils');

const AMBIGUOUS_LOOPBACK = ['0177.0.0.1', '0x7f.0.0.1', '2130706433', '017700000001', '127.1'];

describe('zzqA /metrics 内网判据的严格形态', () => {
  test.each(AMBIGUOUS_LOOPBACK)('伪装成环回的 %s 必须被拒', (text) => {
    expect(isPrivateOrLoopback(text)).toBe(false);
  });

  test('拒绝的理由是"形态有歧义"，不是"根本解析不出"', () => {
    for (const text of AMBIGUOUS_LOOPBACK) {
      // 宽松解释确实得到 127.0.0.1 —— 旧实现正是据此放行的
      expect(lenientAddressHint(text)).toBe('127.0.0.1');
      expect(isPrivateOrLoopback(text)).toBe(false);
    }
  });

  test('真内网/回环形态一律照常放行（严格化不许把 Prometheus 挡在门外）', () => {
    for (const ok of [
      '127.0.0.1',
      '127.15.9.4',
      '10.0.0.5',
      '192.168.1.7',
      '172.16.0.9',
      '::1',
      '0:0:0:0:0:0:0:1',
      'fe80::1',
      'fd00::1234',
      'fc00::1',
    ]) {
      expect(isPrivateOrLoopback(ok)).toBe(true);
    }
  });

  test('IPv4 映射写法必须继续等价（本文件头的既有不变量，不被严格化误伤）', () => {
    // trust proxy 未启用时 req.ip 常是 ::ffff:a.b.c.d；按 IPv6 段判会误拒本机抓取
    expect(isPrivateOrLoopback('::ffff:127.0.0.1')).toBe(true);
    expect(isPrivateOrLoopback('::ffff:10.1.2.3')).toBe(true);
    // 而"映射 + 歧义"两头都不可信
    expect(isPrivateOrLoopback('::ffff:0177.0.0.1')).toBe(false);
    expect(isPrivateOrLoopback('::ffff:127.1')).toBe(false);
  });

  test('公网与坏输入仍然拒绝（原 fail-safe 方向不变）', () => {
    for (const bad of ['8.8.8.8', '203.0.113.9', '11.0.0.1', 'not-an-ip', '', null, undefined]) {
      expect(isPrivateOrLoopback(bad)).toBe(false);
    }
  });

  test('映射地址解包后按 IPv4 段判定：私有映射放行、公网映射拒绝', () => {
    expect(isPrivateOrLoopback('::ffff:192.168.0.1')).toBe(true);
    expect(isPrivateOrLoopback('::ffff:8.8.8.8')).toBe(false);
  });
});
