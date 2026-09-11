/**
 * WebSocket Redis adapter mounting behavior.
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
