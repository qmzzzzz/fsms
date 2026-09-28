/**
 * 报表接口 tz（浏览器时区）参数解析的单元测试
 *
 * 「今日」按浏览器所在时区计算的前提是时区串可信：非法 IANA 名必须 400，
 * 而不能吞掉——静默回落业务时区会让两个时区的用户看到同一份数据却各自
 * 以为是自己的"今天"，且 Intl 在聚合路径上抛 RangeError 会变成 500。
 */

const controller = require('../../controllers/reportController');

/** 最小 res 替身：捕获 status/json（ApiResponse.error 走这两个方法） */
const fakeRes = () => {
  const res = {};
  res.status = jest.fn(() => res);
  res.json = jest.fn(() => res);
  res.headersSent = false;
  return res;
};

describe('reportController.resolveQueryTimezone（tz 参数解析）', () => {
  test('未传 tz：回落业务时区（既有口径不变，不写响应）', () => {
    const res = fakeRes();
    expect(controller.resolveQueryTimezone({ query: {} }, res)).toBe(
      require('../../constants/timezone').BUSINESS_TIMEZONE
    );
    // 纯空白按「未传」同一口径（query 形态污染不改变语义）
    expect(controller.resolveQueryTimezone({ query: { tz: '   ' } }, res)).toBe(
      require('../../constants/timezone').BUSINESS_TIMEZONE
    );
    expect(res.status).not.toHaveBeenCalled();
  });

  test('合法 IANA 时区原样返回', () => {
    const res = fakeRes();
    expect(controller.resolveQueryTimezone({ query: { tz: 'America/New_York' } }, res)).toBe(
      'America/New_York'
    );
    expect(res.status).not.toHaveBeenCalled();
  });

  test.each([
    ['非法 IANA 名', 'Not/AZone'],
    ['路径穿越形态', '../../etc/passwd'],
  ])('非法时区（%s）：400 且返回 null（调用方短路）', (_name, tz) => {
    const res = fakeRes();
    expect(controller.resolveQueryTimezone({ query: { tz } }, res)).toBeNull();
    expect(res.status).toHaveBeenCalledWith(400);
  });

  test('非字符串类型（数字注入形态）按未传处理', () => {
    const res = fakeRes();
    expect(controller.resolveQueryTimezone({ query: { tz: 20260801 } }, res)).toBe(
      require('../../constants/timezone').BUSINESS_TIMEZONE
    );
  });
});
