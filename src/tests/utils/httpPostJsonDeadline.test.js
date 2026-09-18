/**
 * httpPostJson 安全兜底路径（B-M2）
 *
 * 为什么要单独一个文件：这是安全告警 webhook 的投递出口，两条路径此前零覆盖——
 *  1. 非 http/https 协议必须在进入 http 模块前被拒（纵深防御，防 file:/ftp: 等被
 *     误当外发目标）；
 *  2. **绝对截止时间**：实现注释明确写着「socket 空闲超时可被慢滴漏对端重置绕过，
 *     因此另设同值绝对截止兜底」，而这条兜底此前没有任何测试——一旦被删，
 *     webhook 对端持续滴漏就能让 promise 永不 settle，登录/导出路径被拖死。
 *
 * 手法：起**真实**本地 HTTP server 做对端，不 mock node:http。
 * mock 只能验证「我以为的调用序列」，真实 server 能验证真实 socket 行为——
 * 尤其第 2 条（滴漏对端）依赖真实 TCP 才会暴露。
 *
 * 变异验证记录（2026-09-18，对实现注入变异后逐一实测）：
 *   ✅ 删除协议白名单整段 → 红（本文件协议用例）
 *   ✅ 删除绝对截止 setTimeout 整段 → 红（滴漏用例）
 *   ✅ 删除 res.on('error') 接管 → 红（ECONNRESET 退化为 5 秒后的截止错误）
 *   ✅ URL 解析失败不 reject → 红
 *   ✅ 协议判据只留 http:（去掉 https）→ 红（由既有 coverageBoostBatch3 的
 *      「https: 协议走 https 模块」用例捕获，两文件合起来覆盖该判据的两侧）
 *   ➖ settled 守卫（if (settled) return）删除后**不红**：经探针实测，Promise 的
 *      settle 本身幂等（重复 resolve/reject 只第一次生效），且 destroy 触发的底层
 *      error 复用同一 Error 对象，故该守卫是**等价冗余**，无可观测差异。
 *      不为它编造恒真断言——保留它是防御性写法（未来若在 settle 里加入副作用即生效）。
 *   ➖ timeout 处理器里 settle 与 destroy 的先后顺序对调后**不红**：同上，Promise
 *      结算幂等；先 destroy 会同步触发 'error' 事件走同一条 settle(reject)，
 *      最终 reject 的错误对象与消息完全一致（探针实测三次均 ECONNRESET）。
 */
const http = require('http');
const { postJson } = require('../../utils/httpPostJson');

describe('postJson 协议白名单（纵深防御）', () => {
  test('非 http/https 协议在建立连接之前即被拒（且不产生真连接）', async () => {
    for (const url of [
      'ftp://evil.local/x',
      'file:///etc/passwd',
      'gopher://x/1',
      'data:text/plain,x',
      'ws://x/y',
    ]) {
      await expect(postJson(url, {}, '{}')).rejects.toThrow(/仅允许 http\/https/);
    }
  });

  test('非 URL 串与空串同样走拒绝分支，不抛未捕获异常', async () => {
    for (const url of ['not-a-url', '', 'http://', '://x']) {
      await expect(postJson(url, {}, '{}')).rejects.toThrow();
    }
  });
});

describe('postJson 绝对截止时间（慢滴漏对端不得拖死调用方）', () => {
  let server;
  let base;
  const openSockets = new Set();

  afterEach(async () => {
    for (const s of openSockets) s.destroy();
    openSockets.clear();
    if (server) {
      await new Promise((r) => server.close(r));
      server = null;
    }
  });

  /** 起一个「接受连接并持续滴漏、永不结束响应」的对端 */
  const startDripServer = (dripMs) =>
    new Promise((resolve) => {
      server = http.createServer((req, res) => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.write('{"partial":');
        const timer = setInterval(() => {
          if (res.writableEnded) return;
          try {
            res.write('1');
          } catch (_) {
            clearInterval(timer);
          }
        }, dripMs);
        res.on('close', () => clearInterval(timer));
      });
      server.on('connection', (s) => {
        openSockets.add(s);
        s.on('close', () => openSockets.delete(s));
      });
      server.listen(0, '127.0.0.1', () => {
        base = 'http://127.0.0.1:' + server.address().port;
        resolve();
      });
    });

  test('滴漏对端下：到达绝对截止即 reject，不因有空闲流量而无限等待', async () => {
    // 每 20ms 滴一个字节 → socket 空闲超时被反复重置，只有绝对截止能救场
    await startDripServer(20);
    const started = Date.now();
    await expect(postJson(base + '/hook', {}, '{}', 400)).rejects.toThrow(/请求截止/);
    const elapsed = Date.now() - started;
    // 截止语义：不得显著晚于 400ms（给事件循环留余量，但必须远小于「永不返回」）
    expect(elapsed).toBeLessThan(3000);
  });

  test('正常回包时截止计时器不误伤：2xx 正常 resolve', async () => {
    server = http.createServer((req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end('{"ok":true}');
    });
    await new Promise((r) => server.listen(0, '127.0.0.1', r));
    base = 'http://127.0.0.1:' + server.address().port;
    await expect(postJson(base + '/hook', {}, '{}', 5000)).resolves.toEqual({
      ok: true,
      status: 200,
    });
    // 结算后再等过截止点，进程不得因残留计时器报错（unref 已生效）
    await new Promise((r) => setTimeout(r, 50));
  });

  test('非 2xx 真实回包：ok=false 且带上真实状态码', async () => {
    server = http.createServer((req, res) => {
      res.writeHead(503, { 'Content-Type': 'text/plain' });
      res.end('unavailable');
    });
    await new Promise((r) => server.listen(0, '127.0.0.1', r));
    base = 'http://127.0.0.1:' + server.address().port;
    await expect(postJson(base + '/hook', { 'X-Test': '1' }, '{"a":1}')).resolves.toEqual({
      ok: false,
      status: 503,
    });
  });

  test('对端在响应体传输中途断连 → 立即以连接错误 reject（B-M2）', async () => {
    server = http.createServer((req, res) => {
      res.writeHead(200, { 'Content-Length': '100' });
      res.write('{"partial":');
      // 立刻强拆，模拟传输中途断连
      setImmediate(() => res.socket && res.socket.destroy());
    });
    await new Promise((r) => server.listen(0, '127.0.0.1', r));
    base = 'http://127.0.0.1:' + server.address().port;
    const started = Date.now();
    // 断言的是**错误来源**，不是「有错就算」：
    // 实测确认（2026-09-18）——若删掉 res.on('error', ...) 这一行接管，
    // 底层 ECONNRESET 变成未监听事件，promise 只能等绝对截止才 settle，
    // 错误信息从 'ECONNRESET' 退化为 '请求截止 5000ms 内未完成'，且延迟 5 秒。
    // 因此这里必须钉住 (a) 错误码是 ECONNRESET (b) 远早于截止时间。
    await expect(postJson(base + '/hook', {}, '{}', 5000)).rejects.toMatchObject({
      code: 'ECONNRESET',
    });
    expect(Date.now() - started).toBeLessThan(4000);
  });
});
