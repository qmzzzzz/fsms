/**
 * Security alert timer and business-hour guards.
 */

describe('security alert lifecycle', () => {
  test('starts the cleanup timer once and stops it cleanly', () => {
    const securityAlert = require('../../services/securityAlert');
    const timer = { unref: jest.fn() };
    const setIntervalSpy = jest.spyOn(global, 'setInterval').mockReturnValue(timer);
    const clearIntervalSpy = jest.spyOn(global, 'clearInterval').mockImplementation(() => {});

    securityAlert.startAlertCleanup();
    securityAlert.startAlertCleanup();
    securityAlert.stopAlertCleanup();
    securityAlert.stopAlertCleanup();
    securityAlert.startAlertCleanup();
    securityAlert.stopAlertCleanup();

    expect(setIntervalSpy).toHaveBeenCalledWith(expect.any(Function), 10 * 60 * 1000);
    expect(clearIntervalSpy).toHaveBeenCalledWith(timer);
    expect(setIntervalSpy).toHaveBeenCalledTimes(2);

    setIntervalSpy.mockRestore();
    clearIntervalSpy.mockRestore();
  });

  test('flags early-morning activity in the business timezone', () => {
    const securityAlert = require('../../services/securityAlert');

    expect(securityAlert.checkUnusualTime('2026-09-08T18:00:00Z')).toEqual({
      isUnusual: true,
      hour: 2,
    });
  });
});
