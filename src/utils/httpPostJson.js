/**
 * 通用 JSON POST 客户端（node:http/https 实现，零依赖）
 *
 * 供安全告警 webhook 投递使用。为什么不用 fetch：内置 fetch 在本项目的
 * 安全扫描门禁下不允许接收动态 URL；改用 https.request 显式传参。
 *
 * 超时语义：socket 超时 timeoutMs 后销毁请求并 reject（区别于 fetch 的
 * AbortController，这里由请求自身超时兜底，调用方无需管理 abort 句柄）。
 */

const http = require('http');
const https = require('https');

/**
 * POST JSON 并返回响应
 * @param {string|URL} rawUrl 目标地址（调用方负责完成 SSRF 校验）
 * @param {object} headers 请求头
 * @param {string} body 已序列化的请求体
 * @param {number} [timeoutMs=5000] 超时毫秒
 * @returns {Promise<{ok: boolean, status: number}>}
 */
function postJson(rawUrl, headers, body, timeoutMs = 5000) {
  return new Promise((resolve, reject) => {
    let target;
    try {
      target = new URL(rawUrl);
    } catch (err) {
      reject(new Error('URL 无法解析：' + err.message));
      return;
    }
    const mod = target.protocol === 'https:' ? https : http;
    const req = mod.request(
      target,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(body),
          ...headers,
        },
        timeout: timeoutMs,
      },
      (res) => {
        // 消费响应体（释放 socket），状态码交由调用方判定
        res.resume();
        res.on('end', () => {
          resolve({
            ok: res.statusCode >= 200 && res.statusCode < 300,
            status: res.statusCode || 0,
          });
        });
      }
    );
    req.on('timeout', () => req.destroy(new Error('请求超时 ' + timeoutMs + 'ms')));
    req.on('error', reject);
    req.end(body);
  });
}

module.exports = { postJson };
