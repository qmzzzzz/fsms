/**
 * postJson 的 lookup 选项必须真的被连接层采用：
 * 把目标主机名指向回调返回的 IP（不经过系统 DNS），Host 头仍是原域名。
 */

const http = require('http');
const { postJson } = require('../../utils/httpPostJson');

describe('postJson 钉住解析结果', () => {
  test('连接使用 lookup 返回的地址，Host/URL 主机名保持不变', async () => {
    const seenHosts = [];
    const server = http.createServer((req, res) => {
      seenHosts.push(req.headers.host);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true }));
    });
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = server.address().port;

    const lookupCalls = [];
    try {
      const result = await postJson(`http://pinned.example.test:${port}/hook`, {}, '{}', 2000, {
        lookup: (hostname, options, callback) => {
          lookupCalls.push([hostname, options.all]);
          // Node 的自动地址族选择会以 all:true 调用 lookup，两种签名都要支持
          if (options.all) callback(null, [{ address: '127.0.0.1', family: 4 }]);
          else callback(null, '127.0.0.1', 4);
        },
      });

      expect(result).toEqual({ ok: true, status: 200 });
      expect(lookupCalls.map(([hostname]) => hostname)).toEqual(['pinned.example.test']);
      expect(seenHosts).toEqual([`pinned.example.test:${port}`]);
    } finally {
      await new Promise((resolve) => server.close(resolve));
    }
  });
});
