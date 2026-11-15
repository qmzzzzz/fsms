/**
 * WebSocket 握手认证 catch 的非 Error 拒绝值兜底（审计 2026-11-15）
 *
 * 缺陷形状：authenticateSocket 的 catch 直接读 `err.message`。链路上的依赖
 * （jwt.verify / 模型查询 / 内部 _assert* 家族）并不保证拒绝 Error——
 * `Promise.reject('boom')`、`reject(null)`、driver 的裸对象都出现过。
 * 非 Error 值让 catch 自身抛 TypeError：客户端既收不到 auth-error 也不会被
 * 断开，连接悬挂在未认证态。
 *
 * 修复口径：catch 内对拒绝值 String() 安全化 + 清洗控制字符，保证错误路径
 * 必然回应（auth-error）并断开。本文件用持柄直测（同
 * websocketHandlerRejectionGuard.test.js 的观测方式）逐种拒绝值钉住。
 */

const WebSocketService = require('../../services/websocketService');

const makeSocket = () => {
  const socket = {
    id: 'ws-nonerr-1',
    connected: true,
    authenticated: false,
    emitted: [],
    emit: (ev, data) => socket.emitted.push({ ev, data }),
    disconnect: jest.fn(() => {
      socket.connected = false;
    }),
  };
  return socket;
};

const makeService = (rejection) => {
  const svc = Object.create(WebSocketService.prototype);
  // 只注入第一个 await 点：catch 之前唯一被等待的依赖，注入即直达 catch
  svc._assertHandshakeIpNotBanned = jest.fn().mockRejectedValue(rejection);
  return svc;
};

describe('authenticateSocket 的非 Error 拒绝值兜底', () => {
  test('字符串拒绝值：仍回 auth-error 并断开，catch 自身不得抛 TypeError', async () => {
    const svc = makeService('plain-string-rejection');
    const socket = makeSocket();
    await expect(svc.authenticateSocket(socket, 'tok', null)).resolves.toBe(false);
    expect(socket.emitted).toEqual([{ ev: 'auth-error', data: { message: '认证失败' } }]);
    expect(socket.disconnect).toHaveBeenCalledWith(true);
  });

  test('null 拒绝值：同样兜底，不得产生 TypeError 逃逸', async () => {
    const svc = makeService(null);
    const socket = makeSocket();
    await expect(svc.authenticateSocket(socket, 'tok', null)).resolves.toBe(false);
    expect(socket.emitted).toHaveLength(1);
    expect(socket.disconnect).toHaveBeenCalledWith(true);
  });

  test('含换行的拒绝值：日志理由必须清洗成单行（拒绝值可能内嵌请求方可控内容）', async () => {
    const logger = require('../../utils/logger');
    const warnSpy = jest.spyOn(logger, 'warn').mockImplementation(() => {});
    try {
      const svc = makeService('boom\n2026-11-15 ERROR fake line');
      const socket = makeSocket();
      await svc.authenticateSocket(socket, 'tok', null);
      const logged = warnSpy.mock.calls.map((c) => String(c[0])).join('\n');
      expect(logged).not.toContain('boom\n2026-11-15');
      expect(logged).toContain('boom 2026-11-15 ERROR fake line');
    } finally {
      warnSpy.mockRestore();
    }
  });

  test('正向对照：Error 拒绝值仍按 message 记录（安全化不改变既有日志语义）', async () => {
    const logger = require('../../utils/logger');
    const warnSpy = jest.spyOn(logger, 'warn').mockImplementation(() => {});
    try {
      const svc = makeService(new Error('常规失败原因'));
      const socket = makeSocket();
      await svc.authenticateSocket(socket, 'tok', null);
      expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('常规失败原因'));
      expect(socket.disconnect).toHaveBeenCalledWith(true);
    } finally {
      warnSpy.mockRestore();
    }
  });
});
