/**
 * logShipper (HttpShipperTransport) 分支覆盖率补齐测试
 *
 * 目标：将 branches 从 0% 提到 >=70%。
 * 覆盖路径：constructor、log()、_trimToCap()、_flush() 成功/失败/串行闩、
 * _post() HTTP/HTTPS/token/超时/错误/无效URL、close()。
 *
 * 约束：不用 jest.useFakeTimers（与 mongodb-memory-server 冲突），
 * 改用 spyOn(setInterval) 捕获回调后手动触发。
 */

const http = require('http');

// mock setInterval 以避免真实定时器泄漏
let tickFn = null;
const fakeHandle = { unref: jest.fn() };
const siSpy = jest.spyOn(global, 'setInterval').mockImplementation((cb) => {
  tickFn = cb;
  return fakeHandle;
});

const { HttpShipperTransport, BUFFER_CAP } = require('../../utils/logShipper');

afterAll(() => {
  siSpy.mockRestore();
});

/**
 * 创建一个指向本地 dummy HTTP server 的 transport，
 * 或者 mock _post 来避免真实网络。
 */
function createTransport(opts = {}) {
  return new HttpShipperTransport({
    url: opts.url || 'http://localhost:19999/logs',
    token: opts.token,
    batchSize: opts.batchSize || 5,
    intervalMs: opts.intervalMs || 60000, // 大间隔，手动触发
    timeoutMs: opts.timeoutMs || 2000,
  });
}

describe('HttpShipperTransport', () => {
  afterEach(() => {
    tickFn = null;
  });

  // ---- constructor ----
  describe('constructor', () => {
    test('缺少 url 抛错', () => {
      expect(() => new HttpShipperTransport({})).toThrow(/需要 url/);
    });

    test('使用默认值填充可选参数', () => {
      const t = createTransport();
      expect(t.batchSize).toBe(5); // 我们传的
      expect(t.buffer).toEqual([]);
      t.close();
    });
  });

  // ---- log() ----
  describe('log()', () => {
    test('字符串 info 直接 push 到缓冲', () => {
      const t = createTransport();
      const cb = jest.fn();
      t.log('plain string log', cb);
      expect(t.buffer.length).toBe(1);
      expect(t.buffer[0]).toBe('plain string log');
      expect(cb).toHaveBeenCalled();
      t.close();
    });

    test('对象 info JSON.stringify 后入缓冲', () => {
      const t = createTransport();
      t.log({ level: 'info', message: 'test' }, () => {});
      expect(t.buffer.length).toBe(1);
      expect(JSON.parse(t.buffer[0])).toEqual({ level: 'info', message: 'test' });
      t.close();
    });

    test('callback 为 undefined 时不报错', () => {
      const t = createTransport();
      expect(() => t.log('no callback')).not.toThrow();
      t.close();
    });

    test('满额触发 _flush', async () => {
      const t = createTransport({ batchSize: 3 });
      const postSpy = jest.spyOn(t, '_post').mockResolvedValue(undefined);

      for (let i = 0; i < 3; i++) {
        t.log(`msg${i}`, () => {});
      }

      // flush 是异步的
      await new Promise((r) => setTimeout(r, 100));
      expect(postSpy).toHaveBeenCalled();
      postSpy.mockRestore();
      t.close();
    });
  });

  // ---- _trimToCap ----
  describe('_trimToCap()', () => {
    test('缓冲未超限时不做任何操作', () => {
      const t = createTransport();
      t.buffer.push('a', 'b');
      t._trimToCap();
      expect(t.buffer.length).toBe(2);
      t.close();
    });

    test('超限丢弃最旧行并写入 gap 标记', () => {
      const t = createTransport();
      // 填满超过 BUFFER_CAP
      for (let i = 0; i < BUFFER_CAP + 10; i++) {
        t.buffer.push(`line_${i}`);
      }
      const consoleSpy = jest.spyOn(console, 'error').mockImplementation(() => {});

      t._trimToCap();

      expect(t.buffer.length).toBe(BUFFER_CAP);
      // 头部应是 gap 标记
      const gapLine = JSON.parse(t.buffer[0]);
      expect(gapLine.__log_shipper_gap__).toBeGreaterThan(0);
      expect(gapLine.level).toBe('error');

      consoleSpy.mockRestore();
      t.close();
    });

    test('告警节流：60s 内只输出一次 console.error', () => {
      const t = createTransport();
      const consoleSpy = jest.spyOn(console, 'error').mockImplementation(() => {});

      // 第一次超限
      for (let i = 0; i < BUFFER_CAP + 5; i++) t.buffer.push(`x${i}`);
      t._trimToCap();
      expect(consoleSpy).toHaveBeenCalledTimes(1);

      // 第二次超限（仍在 60s 窗口内）
      for (let i = 0; i < BUFFER_CAP + 5; i++) t.buffer.push(`y${i}`);
      t._trimToCap();
      expect(consoleSpy).toHaveBeenCalledTimes(1); // 仍为 1

      consoleSpy.mockRestore();
      t.close();
    });
  });

  // ---- _flush ----
  describe('_flush()', () => {
    test('缓冲为空时直接返回', async () => {
      const t = createTransport();
      const postSpy = jest.spyOn(t, '_post').mockResolvedValue(undefined);
      await t._flush();
      expect(postSpy).not.toHaveBeenCalled();
      postSpy.mockRestore();
      t.close();
    });

    test('发送成功后缓冲被消费', async () => {
      const t = createTransport({ batchSize: 5 });
      const postSpy = jest.spyOn(t, '_post').mockResolvedValue(undefined);

      t.buffer.push('a', 'b', 'c');
      await t._flush();

      expect(postSpy).toHaveBeenCalledTimes(1);
      expect(t.buffer.length).toBe(0);
      postSpy.mockRestore();
      t.close();
    });

    test('发送失败后整批回到缓冲头部', async () => {
      const t = createTransport({ batchSize: 5 });
      const postSpy = jest.spyOn(t, '_post').mockRejectedValue(new Error('network down'));
      const consoleSpy = jest.spyOn(console, 'error').mockImplementation(() => {});

      t.buffer.push('x', 'y');
      await t._flush();

      // 失败的批次应 unshift 回头部
      expect(t.buffer.length).toBe(2);
      expect(t.buffer[0]).toBe('x');

      postSpy.mockRestore();
      consoleSpy.mockRestore();
      t.close();
    });

    test('串行闩：并发 flush 只执行一个', async () => {
      const t = createTransport({ batchSize: 10 });
      let resolvePost;
      const postSpy = jest.spyOn(t, '_post').mockImplementation(
        () =>
          new Promise((resolve) => {
            resolvePost = resolve;
          })
      );

      t.buffer.push('a', 'b', 'c');

      // 同时发起两个 flush
      const p1 = t._flush();
      const p2 = t._flush(); // 应被串行闩拦截

      // 此时只有一个 _post 在途
      expect(postSpy).toHaveBeenCalledTimes(1);

      resolvePost();
      await p1;
      await p2;

      postSpy.mockRestore();
      t.close();
    });

    test('失败回退后触发 _trimToCap（缓冲可能再次超限）', async () => {
      const t = createTransport({ batchSize: 5 });
      const postSpy = jest.spyOn(t, '_post').mockRejectedValue(new Error('fail'));
      const consoleSpy = jest.spyOn(console, 'error').mockImplementation(() => {});

      // 先填满接近 cap
      for (let i = 0; i < BUFFER_CAP - 2; i++) t.buffer.push(`fill_${i}`);
      // 再添加几条使 flush 失败后 unshift 回来会超限
      t.buffer.push('extra1', 'extra2', 'extra3', 'extra4', 'extra5');

      await t._flush();

      // 即使失败回退，缓冲也不应超过 BUFFER_CAP
      expect(t.buffer.length).toBeLessThanOrEqual(BUFFER_CAP);

      postSpy.mockRestore();
      consoleSpy.mockRestore();
      t.close();
    });
  });

  // ---- _post ----
  describe('_post()', () => {
    let server;
    let port;

    beforeAll((done) => {
      // 启动一个真实的本地 HTTP 服务器用于集成测试
      server = http.createServer((req, res) => {
        // data 监听器职责是消费请求流推进到 'end'（不消费则 end 永不触发、
        // 响应挂起）；请求体内容本测试并不关心，按 lint 约定以 _ 前缀标注有意不用
        let _body = '';
        req.on('data', (chunk) => {
          _body += chunk;
        });
        req.on('end', () => {
          if (req.url === '/ok') {
            res.writeHead(200);
            res.end('ok');
          } else if (req.url === '/server-error') {
            res.writeHead(500);
            res.end('error');
          } else if (req.url === '/slow') {
            // 不响应，让客户端超时
          } else {
            res.writeHead(200);
            res.end('ok');
          }
        });
      });
      server.listen(0, () => {
        port = server.address().port;
        done();
      });
    });

    afterAll((done) => {
      server.close(done);
    });

    test('POST 成功（2xx）resolve', async () => {
      const t = createTransport({ url: `http://127.0.0.1:${port}/ok` });
      await expect(t._post(['test'])).resolves.toBeUndefined();
      t.close();
    });

    test('POST 非 2xx reject', async () => {
      const t = createTransport({ url: `http://127.0.0.1:${port}/server-error` });
      await expect(t._post(['test'])).rejects.toThrow(/HTTP 500/);
      t.close();
    });

    test('携带 Bearer token', async () => {
      const t = createTransport({
        url: `http://127.0.0.1:${port}/ok`,
        token: 'my-secret-token',
      });
      // 如果 token 正确传递，请求应成功（服务端不校验，只是确认不报错）
      await expect(t._post(['auth-test'])).resolves.toBeUndefined();
      t.close();
    });

    test('无效 URL reject', async () => {
      const t = createTransport({ url: 'not-a-valid-url' });
      await expect(t._post(['test'])).rejects.toThrow(/无效的 LOG_SHIPPING_URL/);
      t.close();
    });

    test('请求超时 reject', async () => {
      const t = createTransport({
        url: `http://127.0.0.1:${port}/slow`,
        timeoutMs: 200,
      });
      await expect(t._post(['test'])).rejects.toThrow(/超时|destroy/i);
      t.close();
    }, 5000);

    test('连接错误 reject', async () => {
      // 用一个不可能连上的端口
      const t = createTransport({ url: 'http://127.0.0.1:1/bad' });
      await expect(t._post(['test'])).rejects.toThrow();
      t.close();
    });

    test('HTTPS 协议选择 https 库（URL 解析分支）', () => {
      const t = createTransport({ url: 'https://example.com/logs' });
      // 仅验证构造不报错；实际 HTTPS 请求会在 _post 里选 https 库
      expect(t.url).toBe('https://example.com/logs');
      t.close();
    });
  });

  // ---- close ----
  describe('close()', () => {
    test('清除定时器并排空缓冲', async () => {
      const t = createTransport({ batchSize: 100 });
      const postSpy = jest.spyOn(t, '_post').mockResolvedValue(undefined);

      t.buffer.push('final1', 'final2');
      await t.close();

      expect(t.timer).toBeNull();
      expect(postSpy).toHaveBeenCalled();
      postSpy.mockRestore();
    });

    test('close 期间 flush 失败不抛异常', async () => {
      const t = createTransport({ batchSize: 100 });
      const postSpy = jest.spyOn(t, '_post').mockRejectedValue(new Error('shutdown'));

      t.buffer.push('will-fail');
      await expect(t.close()).resolves.toBeUndefined();

      postSpy.mockRestore();
    });

    test('重复 close 幂等', async () => {
      const t = createTransport();
      await t.close();
      await expect(t.close()).resolves.toBeUndefined();
    });
  });

  // ---- 定时器触发 ----
  describe('定时器回调', () => {
    test('setInterval 注册的回调触发 _flush', async () => {
      // tickFn 由模块顶层 spyOn 捕获
      // 创建新 transport 时 _startTimer 会调 setInterval，
      // 但我们的 mock 只会更新 tickFn 为最新的回调
      const t = createTransport({ batchSize: 100 });
      const postSpy = jest.spyOn(t, '_post').mockResolvedValue(undefined);

      t.buffer.push('timer-msg');

      // 手动触发定时器回调
      if (tickFn) {
        tickFn();
        await new Promise((r) => setTimeout(r, 100));
      }

      expect(postSpy).toHaveBeenCalled();
      postSpy.mockRestore();
      t.close();
    });
  });

  // ---- BUFFER_CAP export ----
  test('BUFFER_CAP 已导出且为正整数', () => {
    expect(typeof BUFFER_CAP).toBe('number');
    expect(BUFFER_CAP).toBeGreaterThan(0);
  });
});
