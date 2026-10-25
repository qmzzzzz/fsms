/**
 * cidrUnionCoversAll：名单条目**并集**的地址族覆盖判定
 *
 * 存在理由：单条 isFullRangeCIDR 只看 bits===0，两条互补的 /1 合起来等价于 /0
 * 却都能通过。本套件锁死「按并集判定」这一行为，并覆盖 IPv4/IPv6、空洞、
 * 映射地址与非法输入。
 */

const { cidrUnionCoversAll, cidrRemovalBreaksFullCoverage } = require('../../utils/cidrCoverage');

describe('cidrUnionCoversAll', () => {
  test('两条互补 /1 覆盖整个 IPv4；缺一条即不覆盖', () => {
    expect(cidrUnionCoversAll(['0.0.0.0/1', '128.0.0.0/1'])).toEqual({
      ipv4: true,
      ipv6: false,
    });
    expect(cidrUnionCoversAll(['0.0.0.0/1']).ipv4).toBe(false);
    expect(cidrUnionCoversAll(['128.0.0.0/1']).ipv4).toBe(false);
  });

  test('单条 /0 覆盖对应地址族，且两族互不串扰', () => {
    expect(cidrUnionCoversAll(['0.0.0.0/0'])).toEqual({ ipv4: true, ipv6: false });
    expect(cidrUnionCoversAll(['::/0'])).toEqual({ ipv4: false, ipv6: true });
    expect(cidrUnionCoversAll(['0.0.0.0/0', '::/0'])).toEqual({ ipv4: true, ipv6: true });
  });

  test('中间有空洞时不判覆盖（覆盖 0~191.255.255.255 仍缺 192/2）', () => {
    expect(cidrUnionCoversAll(['0.0.0.0/2', '64.0.0.0/2', '128.0.0.0/2']).ipv4).toBe(false);
    // 补齐第四块才覆盖
    expect(cidrUnionCoversAll(['0.0.0.0/2', '64.0.0.0/2', '128.0.0.0/2', '192.0.0.0/2']).ipv4).toBe(
      true
    );
  });

  test('乱序输入与主机位非零的网段按网络地址归一后合并', () => {
    // 10.1.2.3/1 的主机位被掩掉后是 0.0.0.0/1
    expect(cidrUnionCoversAll(['128.0.0.0/1', '10.1.2.3/1']).ipv4).toBe(true);
  });

  test('IPv6 的两条 /1 同样识别为全覆盖', () => {
    expect(cidrUnionCoversAll(['::/1', '8000::/1']).ipv6).toBe(true);
    expect(cidrUnionCoversAll(['::/1']).ipv6).toBe(false);
  });

  test('单地址条目不会凑成覆盖；非法与映射地址按同一口径处理', () => {
    // 单地址是宽度 1 的区间
    expect(cidrUnionCoversAll(['0.0.0.0', '255.255.255.255']).ipv4).toBe(false);
    // IPv4 映射形态的网段被换算成 IPv4（/97 → /1），不得被当成 IPv6 区间
    expect(cidrUnionCoversAll(['::ffff:0.0.0.0/97', '::ffff:128.0.0.0/97'])).toEqual({
      ipv4: true,
      ipv6: false,
    });
    // 无法解析的条目被跳过，不扩大覆盖面
    expect(cidrUnionCoversAll(['bad/8', '', null, undefined, 123]).ipv4).toBe(false);
    expect(cidrUnionCoversAll(['0.0.0.0/1', 'bad/8', '128.0.0.0/1']).ipv4).toBe(true);
  });

  test('非数组/空输入返回双 false 且不抛错', () => {
    expect(cidrUnionCoversAll(undefined)).toEqual({ ipv4: false, ipv6: false });
    expect(cidrUnionCoversAll([])).toEqual({ ipv4: false, ipv6: false });
  });
});

describe('cidrRemovalBreaksFullCoverage', () => {
  test('删掉互补 /1 中的任意一条都会失去 IPv4 全覆盖', () => {
    const pair = ['0.0.0.0/1', '128.0.0.0/1'];
    expect(cidrRemovalBreaksFullCoverage(pair, '0.0.0.0/1')).toEqual({
      ipv4: true,
      ipv6: false,
    });
    expect(cidrRemovalBreaksFullCoverage(pair, '128.0.0.0/1')).toEqual({
      ipv4: true,
      ipv6: false,
    });
  });

  test('单条 /0 被删除同样算破坏；冗余条目被删则不算', () => {
    expect(cidrRemovalBreaksFullCoverage(['0.0.0.0/0'], '0.0.0.0/0').ipv4).toBe(true);
    // /0 + 一条冗余 /1：删 /1 后仍由 /0 覆盖，不应拦截
    expect(cidrRemovalBreaksFullCoverage(['0.0.0.0/0', '0.0.0.0/1'], '0.0.0.0/1')).toEqual({
      ipv4: false,
      ipv6: false,
    });
    // 删 /0 后只剩 /1，覆盖不再完整
    expect(cidrRemovalBreaksFullCoverage(['0.0.0.0/0', '0.0.0.0/1'], '0.0.0.0/0').ipv4).toBe(true);
  });

  test('IPv6 分片同样识别，且两族互不串扰', () => {
    const pair = ['::/1', '8000::/1'];
    expect(cidrRemovalBreaksFullCoverage(pair, '::/1')).toEqual({
      ipv4: false,
      ipv6: true,
    });
    // IPv4 全覆盖状态下删除 IPv6 条目：IPv6 本来就没铺满，不触发
    expect(cidrRemovalBreaksFullCoverage(['0.0.0.0/0', '2001:db8::/32'], '2001:db8::/32')).toEqual({
      ipv4: false,
      ipv6: false,
    });
  });

  test('未覆盖状态下的删除一律不触发；空输入安全', () => {
    expect(cidrRemovalBreaksFullCoverage(['0.0.0.0/1'], '0.0.0.0/1')).toEqual({
      ipv4: false,
      ipv6: false,
    });
    expect(cidrRemovalBreaksFullCoverage(undefined, '0.0.0.0/0')).toEqual({
      ipv4: false,
      ipv6: false,
    });
    expect(cidrRemovalBreaksFullCoverage(['0.0.0.0/0'], undefined)).toEqual({
      ipv4: false,
      ipv6: false,
    });
  });
});
