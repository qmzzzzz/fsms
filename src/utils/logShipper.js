/**
 * SIEM / 日志中心可选转发 transport
 *
 * 将 winston 日志缓冲后批量 HTTP POST 到外部日志收集端（SIEM/ELK/Loki 等）。
 * 默认关闭，仅在配置 LOG_SHIPPING_URL 时由 logger.js 挂载。
 *
 * 设计原则：
 * - 永不阻塞主日志：log() 立即 callback，行进内存缓冲，定时/满额批量发送
 * - 永不影响主流程：发送失败仅告警（节流），绝不抛出
 * - 内存保护：缓冲上限 BUFFER_CAP，超限丢弃最旧行（保留近期），并写入
 *   一条 __log_shipper_gap__ 标记行，使 SIEM 侧能看到「这里丢了 N 行」
 * - 非可靠网络：单次 flush 失败将整批放回缓冲头部重试（保留未发送行）
 * - 串行发送：同一时刻只允许一个 flush 在途（P3-31）。定时 flush 与满额
 *   flush 若并发，两批各自 splice 出不同区段，失败方 unshift 回头部时会
 *   排到已成功发送的较新批之后 —— SIEM 收到的行序与产生顺序不一致，
 *   而日志行序正是事件重建与关联分析的基础
 *
 * 环境变量：
 *   LOG_SHIPPING_URL          必填，目标 HTTP(S) 端点
 *   LOG_SHIPPING_TOKEN        可选，Bearer 鉴权
 *   LOG_SHIPPING_BATCH        满额条数，默认 100
 *   LOG_SHIPPING_INTERVAL_MS  定时毫秒，默认 5000
 *   LOG_SHIPPING_TIMEOUT_MS   单次请求超时，默认 5000
 */

const TransportStream = require('winston-transport');
const http = require('http');
const https = require('https');
const { URL } = require('url');

const DEFAULT_BATCH = 100;
const DEFAULT_INTERVAL_MS = 5000;
const DEFAULT_TIMEOUT_MS = 5000;
// 缓冲硬上限：超限丢最旧，防止网络长期中断导致 OOM
const BUFFER_CAP = 5000;

class HttpShipperTransport extends TransportStream {
  constructor(opts = {}) {
    super(opts);
    if (!opts.url) throw new Error('HttpShipperTransport 需要 url');
    this.url = opts.url;
    this.token = opts.token;
    this.batchSize = opts.batchSize || DEFAULT_BATCH;
    this.intervalMs = opts.intervalMs || DEFAULT_INTERVAL_MS;
    this.timeoutMs = opts.timeoutMs || DEFAULT_TIMEOUT_MS;
    this.buffer = [];
    this.timer = null;
    this._warnedAt = 0;
    // P3-31：flush 串行化闩。定时器与满额触发是两个独立入口，
    // 并发进入会各自 splice 出不同区段，破坏行序
    this._flushing = false;
    // 因缓冲超限被丢弃的累计行数（写入 gap 标记后归零）
    this._droppedCount = 0;
    this._startTimer();
  }

  /**
   * 缓冲超限裁剪：丢最旧，并在缓冲头部留下可被 SIEM 检索的断档标记
   *
   * P3-31：原实现只是 splice 掉最旧行，下游完全无法感知丢失——
   * SIEM 上看到的是一段连续日志，中间少了 N 行且无任何痕迹，
   * 事件重建时会得出错误结论（「这段时间没有异常请求」）。
   * @returns {void}
   */
  _trimToCap() {
    if (this.buffer.length <= BUFFER_CAP) return;
    const dropped = this.buffer.length - BUFFER_CAP;
    this.buffer.splice(0, dropped);
    this._droppedCount += dropped;
    // 标记行本身占一个槽位，故先腾出空间再写入，避免标记又被立刻裁掉
    this.buffer.shift();
    this.buffer.unshift(
      JSON.stringify({
        level: 'error',
        message: `[logShipper] 缓冲区超过上限 ${BUFFER_CAP}，已丢弃最旧 ${this._droppedCount} 行日志`,
        __log_shipper_gap__: this._droppedCount + 1,
        timestamp: new Date().toISOString(),
      })
    );
    this._droppedCount = 0;
    // 本地也留一条（节流复用同一时间窗），否则运维只能在 SIEM 侧发现
    const now = Date.now();
    if (now - this._warnedAt > 60000) {
      this._warnedAt = now;
      console.error(`[logShipper] 缓冲区已满，正在丢弃最旧日志行（cap=${BUFFER_CAP}）`);
    }
  }

  _startTimer() {
    if (this.timer) return;
    this.timer = setInterval(() => this._flush().catch(() => {}), this.intervalMs);
    if (this.timer && this.timer.unref) this.timer.unref();
  }

  // winston transport 接口：立即 ack，行进缓冲
  log(info, callback) {
    setImmediate(() => this.emit('logged', info));
    try {
      this.buffer.push(typeof info === 'string' ? info : JSON.stringify(info));
      // 缓冲保护：超限丢最旧并留断档标记
      this._trimToCap();
      if (this.buffer.length >= this.batchSize) {
        this._flush().catch(() => {});
      }
    } catch {
      // 永不影响日志主路径
    }
    if (typeof callback === 'function') callback();
  }

  async _flush() {
    // P3-31：在途 flush 期间直接返回，保证同一时刻只有一批在网络上，
    // 失败批 unshift 回头部后仍是缓冲中最旧的一段，行序得以保持
    if (this._flushing) return;
    if (this.buffer.length === 0) return;
    this._flushing = true;
    // 取本批发送，发送期间新行继续进缓冲
    const batch = this.buffer.splice(0, this.batchSize);
    try {
      await this._post(batch);
    } catch (err) {
      // 发送失败：整批放回缓冲头部（unshift）重试——
      // 若放回尾部，这批旧行会排到发送期间新到的行之后，破坏 SIEM 侧的原始行序
      this.buffer.unshift(...batch);
      // 超限再次裁剪（同样留断档标记）
      this._trimToCap();
      // 节流告警（每分钟最多一条），避免日志风暴
      const now = Date.now();
      if (now - this._warnedAt > 60000) {
        this._warnedAt = now;
        console.error(`[logShipper] 转发失败（${batch.length} 行）：${err.message}`);
      }
    } finally {
      this._flushing = false;
    }
  }

  _post(batch) {
    return new Promise((resolve, reject) => {
      let parsed;
      try {
        parsed = new URL(this.url);
      } catch (e) {
        return reject(new Error(`无效的 LOG_SHIPPING_URL：${e.message}`));
      }
      const lib = parsed.protocol === 'https:' ? https : http;
      const body = JSON.stringify(batch);
      const headers = {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
      };
      if (this.token) headers['Authorization'] = `Bearer ${this.token}`;

      const req = lib.request(
        {
          method: 'POST',
          host: parsed.hostname,
          port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
          path: `${parsed.pathname || '/'}${parsed.search || ''}`,
          headers,
          timeout: this.timeoutMs,
        },
        (res) => {
          // 消费响应体避免 socket 泄漏
          res.resume();
          if (res.statusCode >= 200 && res.statusCode < 300) resolve();
          else reject(new Error(`HTTP ${res.statusCode}`));
        }
      );
      req.on('error', reject);
      req.on('timeout', () => {
        req.destroy(new Error('转发请求超时'));
      });
      req.write(body);
      req.end();
    });
  }

  async close() {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    // P3-31：串行闩会让 close 期间的 _flush 直接返回。等在途批次结束后再排空，
    // 否则关闭时缓冲里的行会被静默丢弃（关停正是最需要日志的时刻）
    const deadline = Date.now() + this.timeoutMs + 1000;
    while (this._flushing && Date.now() < deadline) {
      await new Promise((resolve) => {
        setTimeout(resolve, 20).unref?.();
      });
    }
    try {
      await this._flush();
    } catch {
      /* best-effort */
    }
  }
}

module.exports = { HttpShipperTransport, BUFFER_CAP };
