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
 *   一条 __log_shipper_gap__ 标记行，使 SIEM 侧能看到「这里丢了 N 行」；
 *   标记行由本实例随机签发的身份字段认领，形状照抄的业务日志不算标记
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
const crypto = require('crypto');
const http = require('http');
const https = require('https');
const { URL } = require('url');
// 运行时信号（转发失败 / 缓冲丢行）。本文件**不**反向被 metricsRuntime 引用，
// 因此不存在 util ↔ util 的加载环（metricsAuditDrops 那边的拉取式 require 才需要惰性）。
const runtimeMetrics = require('./metricsRuntime');

const DEFAULT_BATCH = 100;
const DEFAULT_INTERVAL_MS = 5000;
const DEFAULT_TIMEOUT_MS = 5000;
// 缓冲硬上限：超限丢最旧，防止网络长期中断导致 OOM
const BUFFER_CAP = 5000;

/** 断档标记的消息前缀：只用于**渲染**人读文案；认出标记靠的是身份字段 */
const GAP_MESSAGE_PREFIX = '[logShipper] 缓冲区超过上限';

// 标记行的两个字段名。写与读必须共用这两个常量：本仓出现过一次"读侧漏掉尾部 `__`"
// 的键名漂移，症状是标记永远认不出来、断档计数退回旧缺陷（每轮只报本轮行数）。
const GAP_COUNT_FIELD = '__log_shipper_gap__';
const GAP_AUTH_FIELD = '__log_shipper_gap_auth__';

/**
 * 这条缓冲行是不是我们自己写的断档标记？
 *
 * 判据必须是"本实例签发的身份字段"，不能是文本形状。形状判据（`level==='error'` +
 * 前缀 + 正整数 `__log_shipper_gap__`）此前被注释说成"构造不出第二份"——**不成立**：
 * `log()` 把 winston 的 info 原样 `JSON.stringify` 进缓冲，业务侧一句
 * `logger.error('[logShipper] 缓冲区超过上限 …', { __log_shipper_gap__: 999 })`
 * 就造出一行合法形状的标记，裁剪时它被当标记摘除（不计入丢失）并把 999 带给 SIEM。
 * 现在伪造者要同时猜中一个每实例 128-bit 随机值；猜不中就是普通一行日志。
 * @param {unknown} line
 * @param {string} gapAuth 本 transport 的实例身份（见构造函数）；空值一律不认
 * @returns {number|null} 标记自报的累计丢失行数；不是标记则 null
 */
function readGapLine(line, gapAuth) {
  if (typeof line !== 'string' || line.charCodeAt(0) !== 123 /* { */) return null;
  let obj;
  try {
    obj = JSON.parse(line);
  } catch {
    return null;
  }
  if (!obj || typeof obj !== 'object') return null;
  if (!gapAuth || obj[GAP_AUTH_FIELD] !== gapAuth) return null;
  if (obj.level !== 'error' || typeof obj.message !== 'string') return null;
  if (!obj.message.startsWith(GAP_MESSAGE_PREFIX)) return null;
  return Number.isInteger(obj[GAP_COUNT_FIELD]) && obj[GAP_COUNT_FIELD] > 0
    ? obj[GAP_COUNT_FIELD]
    : null;
}

/** 生成标记行：人读文案与机器字段**共用同一个数**（曾各报一个，见下方 _trimToCap 注释） */
function makeGapLine(totalDropped, gapAuth) {
  return JSON.stringify({
    level: 'error',
    message: `${GAP_MESSAGE_PREFIX} ${BUFFER_CAP}，已丢弃最旧 ${totalDropped} 行日志`,
    [GAP_COUNT_FIELD]: totalDropped,
    [GAP_AUTH_FIELD]: gapAuth,
    timestamp: new Date().toISOString(),
  });
}

/**
 * 解析出站目标并选定 http/https 客户端（纯判定，便于真值表断言）。
 *
 * 为什么不能写成 `parsed.protocol === 'https:' ? https : http`：
 * 那等价于"凡不是 https 就当 http 发"，于是**任何拼错的 scheme 都会静默降级成明文出站**，
 * 而且带着 Bearer 令牌。实测（WHATWG URL 对非特殊协议照样解析 host/port）：
 *   htps://siem.internal:9999/logs → protocol='htps:' host='siem.internal' port='9999'
 *     ⇒ 旧写法把整批日志 + `Authorization: Bearer …` 以明文 POST 给同一台主机的同一端口
 *   htp://169.254.169.254/latest/meta-data → host 保留 ⇒ 明文打到云元数据地址
 *   file:///var/log/app.log → host='' ⇒ Node 回落 localhost:80
 * 全程不报错、不告警（对端多半只是回 4xx，然后进入节流重试），
 * 运维看到的仍是"日志转发已启用 → htps://…"。
 * 同仓 `utils/httpPostJson.js` 对同一风险已有判例（"仅允许 http/https 协议"）
 * ——出站路径的松紧不该取决于哪个模块发起。
 */
function resolveShippingTarget(rawUrl) {
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch (e) {
    // 消息文案是既有契约（用例断言 `无效的 LOG_SHIPPING_URL`），不得改动
    throw new Error(`无效的 LOG_SHIPPING_URL：${e.message}`);
  }
  if (parsed.protocol === 'https:') return { parsed, lib: https };
  if (parsed.protocol === 'http:') return { parsed, lib: http };
  throw new Error(`LOG_SHIPPING_URL 仅支持 http/https，收到 ${parsed.protocol}`);
}

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
    // 断档标记的签发身份：每实例随机，只存在于本进程内存与它自己写出的标记行里。
    // 见 readGapLine——标记行落在自由格式的日志缓冲里，形状可被业务日志仿造，
    // 所以"是不是标记"必须由这个值决定，而不是由文案形状决定。
    this.gapAuth = crypto.randomBytes(16).toString('hex');
    // P3-31：flush 串行化闩。定时器与满额触发是两个独立入口，
    // 并发进入会各自 splice 出不同区段，破坏行序
    this._flushing = false;
    this._startTimer();
  }

  /**
   * 缓冲超限裁剪：丢最旧，并在缓冲头部维护**一条可累计的**断档标记
   *
   * P3-31：原实现只是 splice 掉最旧行，下游完全无法感知丢失——
   * SIEM 上看到的是一段连续日志，中间少了 N 行且无任何痕迹，
   * 事件重建时会得出错误结论（「这段时间没有异常请求」）。
   *
   * 为什么标记必须当累加器（判据见 `src/tests/observability/logShipperGapMarkerAccounting.test.js`）：
   * 缓冲满顶后**每来一行都会再触发一次裁剪**，于是旧实现每次都把头部那条标记当成
   * "最旧的一行日志" splice 掉，再写一条只报本轮 1 行的新标记，而本轮计数
   * （`_droppedCount`）在函数末尾归零 ⇒ 标记之间互相吞噬、计数永不能跨事件累计。
   * 实测：喂进 2×BUFFER_CAP 行时真实丢失 5001 行，缓冲里那条标记自报 2 行
   * （且人读文案与机器字段还各说一个数）。SIEM 侧于是把"少了一万行"读成"少了两行"。
   *
   * 现在的三条不变量：
   *   ① 头部若有尚未送达的标记，先摘出来、把它已报的数并入新标记；
   *      标记占一格但它**不是**一行日志，不计入丢失行数；
   *   ② 计数只随标记一起被送达：发送成功 ⇒ 标记离开缓冲，下轮从 0 起；
   *      发送失败整批 unshift 回头部 ⇒ 标记连同它的累计继续留在缓冲里。
   *      因此不需要额外的实例状态——标记行本身就是唯一事实源，
   *      也就没有"字段与真实缓冲状态对不上"的可能。
   *      （`gapAuth` 不算这里的"状态"：它是常量身份，只回答"这行是不是我写的"，
   *      不参与计数，也不与缓冲内容对账。）
   *   ③ 人读文案与机器字段共用同一个数。
   * 内存上限不放宽：裁剪后长度仍严格 ≤ BUFFER_CAP（标记占的那一格由多丢一行真日志换来）。
   * @returns {void}
   */
  _trimToCap() {
    if (this.buffer.length <= BUFFER_CAP) return;
    const carried = readGapLine(this.buffer[0], this.gapAuth);
    if (carried !== null) this.buffer.shift(); // 摘出旧标记：它腾出的那一格由新标记回占
    // 标记要占一个槽位 ⇒ 为它腾一格（无旧标记时，这一格由多丢一行真日志换）
    const dropReal = Math.max(0, this.buffer.length + 1 - BUFFER_CAP);
    this.buffer.splice(0, dropReal);
    // 丢行数上报：此前只有 SIEM 侧的断档标记与一条节流 console.error，
    // 监控侧看不见 —— 日志链路在丢数据，而所有面板照常满格。
    runtimeMetrics.incLogShipperDroppedLines(dropReal);
    this.buffer.unshift(
      makeGapLine(carried === null ? dropReal : carried + dropReal, this.gapAuth)
    );
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
      // 转发失败上报（节流告警只管"当场喊一声"，可查询的信号在这里）
      runtimeMetrics.incLogShipperFlushFailure();
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
      let target;
      try {
        target = resolveShippingTarget(this.url);
      } catch (e) {
        return reject(e);
      }
      const { parsed, lib } = target;
      const body = JSON.stringify(batch);
      const headers = {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
      };
      if (this.token) headers['Authorization'] = `Bearer ${this.token}`;

      // settle 守卫 + 绝对截止（对齐 httpPostJson B-M2）：
      // options.timeout 只是 socket 空闲超时，会被"每 <timeout 滴一个字节"的对端无限重置，
      // 使本 Promise 永不 settle → _flushing 永挂 → 缓冲堆到上限后旧日志被静默丢弃。
      let settled = false;
      let deadlineTimer = null;
      const settle = (fn, arg) => {
        if (settled) return;
        settled = true;
        if (deadlineTimer) clearTimeout(deadlineTimer);
        fn(arg);
      };

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
          // 【M-06 修复】必须先接管响应流错误：对端在响应体传输中途断连时
          // IncomingMessage 会 emit 'error'（典型 ECONNRESET），无监听器即
          // uncaughtException → index.js 的处理器会 process.exit(1)。
          // 后果：一个不稳定的日志后端可反复打死业务进程（重启后又重试投递，
          // 形成崩溃循环）。一次失败的投递绝不应终止服务。
          res.on('error', (e) => settle(reject, e));
          // 消费响应体避免 socket 泄漏
          res.resume();
          if (res.statusCode >= 200 && res.statusCode < 300) settle(resolve);
          else settle(reject, new Error(`HTTP ${res.statusCode}`));
        }
      );
      req.on('error', (e) => settle(reject, e));
      req.on('timeout', () => {
        req.destroy(new Error('转发请求超时'));
      });
      // 绝对截止：保证在 timeoutMs 内必然 settle 一次，慢速/悬挂的日志后端卡不住冲刷器。
      deadlineTimer = setTimeout(() => {
        settle(reject, new Error(`日志转发超时：${this.timeoutMs}ms 内未完成`));
        try {
          req.destroy(new Error('转发请求超时（绝对截止）'));
        } catch (_) {
          /* 已销毁则忽略 */
        }
      }, this.timeoutMs);
      if (deadlineTimer.unref) deadlineTimer.unref();
      req.write(body);
      req.end();
    });
  }

  async close() {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    const sleep = (ms) =>
      new Promise((resolve) => {
        setTimeout(resolve, ms).unref?.();
      });
    const deadline = Date.now() + this.timeoutMs + 1000;
    // P3-31：串行闩会让 close 期间的 _flush 直接返回。等在途批次结束后再排空，
    // 否则关闭时缓冲里的行会被静默丢弃（关停正是最需要日志的时刻）
    while (this._flushing && Date.now() < deadline) await sleep(20);

    // P3-31 的第二半（本次修）：一次 _flush 只发 batchSize 行（默认 100），
    // 而缓冲上限是 BUFFER_CAP=5000 ⇒ 原先 close() 只冲**一批**就返回，
    // 进程随后退出，剩下最多 4900 行**无声消失**——失败路径有 console.error，
    // 这条没有，所以谁都不知道丢了。关停时丢的往往正是"为什么关停"的那条线索。
    // 现在按批排空，并且不再冲完一批就走（后端挂掉时不会把退出流程无限卡死）。
    // 预算口径要说准：deadline 只在**批次之间**检查，所以最坏退出耗时是
    // `timeoutMs + 1000 + 单批最坏耗时`，而不是"恰好 deadline"。单批最坏耗时由 _post
    // 里的绝对截止给出上界（≈ timeoutMs），因此关停上界约为 2×timeoutMs + 1000ms。
    while (this.buffer.length > 0) {
      if (Date.now() >= deadline) break;
      if (this._flushing) {
        await sleep(20);
        continue;
      }
      const before = this.buffer.length;
      try {
        await this._flush();
      } catch {
        /* best-effort：_flush 内部已把批次放回缓冲并节流告警 */
      }
      // 没推进（发送失败或被子闩挡回）就歇一拍，不空转打满 CPU
      if (this.buffer.length >= before) await sleep(20);
    }

    if (this.buffer.length > 0) {
      // 关停丢日志是**无声**的：失败路径的节流告警只在 _post 抛错时说话，
      // "批次还没发完就到预算边界"这种情况原先一句都不报。这里报的是**剩余行数**
      // （不是缓冲上限），让"到底丢了多少"可核对。
      console.error(
        `[logShipper] 关闭时仍有 ${this.buffer.length} 行未送达 SIEM` +
          `（排空预算 ${this.timeoutMs + 1000}ms 用尽，可能因后端不可达），已放弃`
      );
    }
  }
}

// F-215：挂载期也要用（logger.js 在 logger.add 之前先解析一次），故导出。
module.exports = { HttpShipperTransport, BUFFER_CAP, resolveShippingTarget };
