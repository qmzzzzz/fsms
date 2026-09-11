/**
 * 通用 JSON POST 客户端（node:http/https 实现，零依赖）
 *
 * 供安全告警 webhook 投递使用。为什么不用 fetch：内置 fetch 在本项目的
 * 安全扫描门禁下不允许接收动态 URL；改用 https.request 显式传参。
 *
 * 超时语义（双层）：
 * - `timeout` 选项是 socket 空闲超时：对端每收到一个字节就重置计时，
 *   慢滴漏式对端可绕过——因此另设同值的**绝对截止时间**兜底，
 *   到点 destroy 请求并 reject，promise 必然 settle；
 * - 结算由 settled 守卫保证只发生一次（end / req error / res error /
 *   截止四方竞态互不重复）。
 */

const http = require('http');
const https = require('https');

/**
 * POST JSON 并返回响应
 * @param {string|URL} rawUrl 目标地址（调用方负责完成 SSRF 校验）
 * @param {object} headers 请求头
 * @param {string} body 已序列化的请求体
 * @param {number} [timeoutMs=5000] 超时毫秒（空闲超时 + 绝对截止共用）
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
    // 纵深断言：调用方（securityAlert）已做 SSRF 校验，此处仅放行 http/https，
    // 其余协议不再落到 http 模块
    if (target.protocol !== 'http:' && target.protocol !== 'https:') {
      reject(new Error('仅允许 http/https 协议'));
      return;
    }

    // settled 守卫：end / req error / res error / 绝对截止任意先到者结算，
    // 其余调用静默忽略（含各自的 clearTimeout）
    let settled = false;
    let deadlineTimer = null;
    const settle = (fn, value) => {
      if (settled) return;
      settled = true;
      if (deadlineTimer) clearTimeout(deadlineTimer);
      fn(value);
    };

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
        // 消费响应体（释放 socket），状态码交由调用方判定。
        // B-M2：对端在响应体传输中途断连时 IncomingMessage 会 emit 'error'
        //（ECONNRESET），无监听器即 uncaughtException → 进程 exit(1)——
        // 一次失败的 webhook 投递不能打死服务器，必须显式接管
        res.on('error', (e) => settle(reject, e));
        res.resume();
        res.on('end', () => {
          settle(resolve, {
            ok: res.statusCode >= 200 && res.statusCode < 300,
            status: res.statusCode || 0,
          });
        });
      }
    );
    req.on('error', (e) => settle(reject, e));
    req.on('timeout', () => {
      const err = new Error('请求超时 ' + timeoutMs + 'ms');
      settle(reject, err);
      // destroy 触发底层 'error' 时经上方 settle 已被守卫吞掉
      req.destroy(err);
    });
    // 绝对截止（B-M2）：空闲超时可被慢滴漏对端重置绕过，这里保证 promise
    // 在 timeoutMs 内必然 settle，调用方（登录/导出路径）不会无限挂起
    deadlineTimer = setTimeout(() => {
      const err = new Error('请求截止 ' + timeoutMs + 'ms 内未完成');
      settle(reject, err);
      try {
        req.destroy(err);
      } catch (_) {
        /* 已销毁则忽略 */
      }
    }, timeoutMs);
    if (deadlineTimer.unref) deadlineTimer.unref();
    req.end(body);
  });
}

module.exports = { postJson };
