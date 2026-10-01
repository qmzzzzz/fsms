/**
 * WebSocket Redis adapter mounting behavior.
 *
 * 两条用例一起钉住「降级必须是可见的」：挂载失败要记 warn（否则推送退化成单实例语义
 * 却无人知道），订阅端要带上与主连接同源的口令（否则 requirepass 下失败形态只有日志）。
 */

jest.mock('@socket.io/redis-adapter', () => ({
  createAdapter: jest.fn(),
}));

jest.mock('socket.io', () => jest.fn(() => ({ adapter: jest.fn() })));
jest.mock('../../utils/logger', () => ({
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
}));
jest.mock('../../services/sharedCache', () => ({
  isRedisEnabled: jest.fn(() => true),
  getRedisClient: jest.fn(() => 'redis-client'),
  // 订阅端与主连接同源的取密函数（2816d68 Redis 认证）。桩返回哨兵值而不是 undefined：
  // 只有能断言「这个值确实进了 new Redis 的 options.password」，才证伪「adapter 客户端
  // 漏传凭据」——requirepass 场景下那是一条 NOAUTH 降级日志，业务面只表现为"推送不跨实例"。
  redisConnectionPassword: jest.fn(() => 'sentinel-redis-secret'),
}));
jest.mock('ioredis', () => jest.fn(() => ({ disconnect: jest.fn() })));

describe('WebSocket Redis adapter', () => {
  const originalRedisUrl = process.env.REDIS_URL;

  beforeEach(() => {
    jest.resetModules();
    process.env.REDIS_URL = 'redis://redis-test:6379';
    const { createAdapter } = require('@socket.io/redis-adapter');
    createAdapter.mockReturnValue('socket-adapter');
  });

  afterEach(() => {
    if (originalRedisUrl === undefined) delete process.env.REDIS_URL;
    else process.env.REDIS_URL = originalRedisUrl;
  });

  test('mounts an independent subscription client for cross-instance delivery', async () => {
    const WebSocketService = require('../../services/websocketService');
    const Redis = require('ioredis');
    const { createAdapter } = require('@socket.io/redis-adapter');
    const sharedCache = require('../../services/sharedCache');
    const service = Object.create(WebSocketService.prototype);
    service._adapterClients = [];
    service.io = { adapter: jest.fn() };

    await service.initSharedAdapter();

    expect(sharedCache.isRedisEnabled).toHaveBeenCalled();
    expect(Redis).toHaveBeenCalledWith('redis://redis-test:6379', {
      lazyConnect: false,
      enableOfflineQueue: true,
      password: 'sentinel-redis-secret',
    });
    expect(createAdapter).toHaveBeenCalledWith('redis-client', service._adapterClients[0]);
    expect(service.io.adapter).toHaveBeenCalledWith('socket-adapter');
  });

  test('degrades to in-memory delivery when mounting fails', async () => {
    const { createAdapter } = require('@socket.io/redis-adapter');
    createAdapter.mockImplementationOnce(() => {
      throw new Error('adapter unavailable');
    });
    const WebSocketService = require('../../services/websocketService');
    const logger = require('../../utils/logger');
    const service = Object.create(WebSocketService.prototype);
    service._adapterClients = [];
    service.io = { adapter: jest.fn() };

    await expect(service.initSharedAdapter()).resolves.toBeUndefined();

    expect(logger.warn).toHaveBeenCalledWith(expect.stringContaining('adapter unavailable'));
    expect(service.io.adapter).not.toHaveBeenCalled();
  });
});
