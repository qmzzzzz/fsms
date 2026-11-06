/** 取证设备键：跨 IP 稳定、与审计指纹互不干扰、可被分隔符伪造则不算数 */
const { computeDeviceKey, DEVICE_KEY_LEN } = require('../../utils/forensicDeviceKey');

const req = (headers) => ({ get: (name) => headers[name] });
const UA = 'Mozilla/5.0 (Windows NT 10.0) Chrome/120';

describe('computeDeviceKey', () => {
  test('同一组头得同一个键，长度 32 位小写十六进制', () => {
    const key = computeDeviceKey(req({ 'user-agent': UA }));
    expect(key).toBe(computeDeviceKey(req({ 'user-agent': UA })));
    expect(key).toHaveLength(DEVICE_KEY_LEN);
    expect(key).toMatch(/^[0-9a-f]{32}$/);
  });

  test('IP 相关的头不参与：换地址不换键（这正是它和审计指纹的区别）', () => {
    expect(computeDeviceKey(req({ 'user-agent': UA, 'x-forwarded-for': '1.2.3.4' }))).toBe(
      computeDeviceKey(req({ 'user-agent': UA, 'x-forwarded-for': '9.9.9.9' }))
    );
  });

  test('客户端提示头参与区分：同 UA 不同平台不同键', () => {
    const win = computeDeviceKey(req({ 'user-agent': UA, 'sec-ch-ua-platform': 'Windows' }));
    const mac = computeDeviceKey(req({ 'user-agent': UA, 'sec-ch-ua-platform': 'macOS' }));
    expect(win).not.toBe(mac);
  });

  test('分隔符不能把两串头拼出同一个键', () => {
    const left = computeDeviceKey(req({ 'user-agent': 'A|B', 'accept-language': 'C' }));
    const right = computeDeviceKey(req({ 'user-agent': 'A', 'accept-language': 'B|C' }));
    expect(left).not.toBe(right);
  });

  test('无任何特征头：返回 null，不产出全网共用的固定键', () => {
    expect(computeDeviceKey(req({}))).toBeNull();
    expect(computeDeviceKey(null)).toBeNull();
    expect(computeDeviceKey({})).toBeNull();
  });
});
