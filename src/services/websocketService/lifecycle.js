/**
 * WebSocket 连接生命周期与周期复查（2026-10-18 自 services/websocketService.js 拆出）
 *
 * Redis adapter 挂载/回收、优雅关闭、周期清扫（AuthGhost/授权复查/运行期 IP 封禁
 * 复查 _sweepBannedIps）与 revalidateSocket。方法是 mixin 形态，由 index.js 挂到
 * WebSocketService.prototype，对外只有门面可见。
 *
 * fail-open 计数（ip_blacklist_failopen）站点之一落于本文件（_sweepBannedIps），
 * 台账见 constants/failOpenSites.js；另一处握手站点在 handshake.js。
 */

const logger = require('../../utils/logger');
const sharedCache = require('../sharedCache');
const { HEARTBEAT_INTERVAL, isTemporarilyLocked, roomRolesSatisfied } = require('./shared');
const { resolveHandshakeIPForSecurityDecision, resolveTrustProxyHops } = require('./handshake');

const methods = {
  /**
   * 挂载 Redis adapter（R-3/收尾）：配置 REDIS_URL 且共享缓存就绪时，
   * 房间/定向投递跨实例生效——权限变更推送能触达连接在其他实例上的用户。
   * 未配置时保持默认内存 adapter，单实例行为与历史完全一致。
   * 由 index.js 启动期调用；失败仅告警降级，不阻断服务。
   */
  async initSharedAdapter() {
    if (!sharedCache.isRedisEnabled()) return;
    let subClient = null;
    try {
      const { createAdapter } = require('@socket.io/redis-adapter');
      const Redis = require('ioredis');
      const url = (process.env.REDIS_URL || '').trim();
      // 订阅端必须独立连接（ioredis 进入订阅模式后禁用普通命令）；
      // 发布端复用共享缓存主连接，少占一条连接。
      // password 与主连接同源（sharedCache.redisConnectionPassword，REDIS_PASSWORD
      // 经 *_FILE 注入）：缺了它，requirepass 的 redis 会让 adapter 以 NOAUTH 失败
      subClient = new Redis(url, {
        lazyConnect: false,
        enableOfflineQueue: true,
        password: sharedCache.redisConnectionPassword(),
      });
      this.io.adapter(createAdapter(sharedCache.getRedisClient(), subClient));
      logger.info('WebSocket 已挂载 Redis adapter：推送跨实例生效');
      // 登记放最后一条可执行语句：catch 里「没登记 ⇒ 就地断开」由此恒成立
      this._adapterClients.push(subClient);
    } catch (err) {
      // 挂载失败时这条订阅端连接已经建立，而 _adapterClients 只在成功路径登记
      // ⇒ dispose() 永远回收不到它；它带 enableOfflineQueue，会一直重连到 Redis
      // 恢复为止。于是"降级"顺手留下一个没人认领的连接——就地断开它。
      if (subClient) {
        try {
          subClient.disconnect();
        } catch (_) {
          /* 连接可能已断（与 dispose() 的回收同一口径） */
        }
      }
      logger.warn(`WebSocket Redis adapter 挂载失败（推送降级为单实例语义）：${err.message}`);
    }
  },

  /**
   * 停止 WebSocket 服务并清理资源（供优雅关闭调用）
   */
  dispose() {
    if (this._cleanupTimer) {
      clearInterval(this._cleanupTimer);
      this._cleanupTimer = null;
    }
    // 断开所有客户端连接
    for (const [socketId] of this.clients) {
      const socket = this.io.sockets.sockets.get(socketId);
      if (socket) socket.disconnect(true);
    }
    this.clients.clear();
    this.userConnections.clear();

    // 回收 Redis adapter 专用连接（无 adapter 时为空数组，无副作用）
    for (const client of this._adapterClients) {
      try {
        client.disconnect();
      } catch (_) {
        /* 连接可能已断 */
      }
    }
    this._adapterClients = [];

    // best-effort 关闭底层 Socket.IO 服务（会一并关闭其挂载的 HTTP server），
    // 释放端口监听与内部资源；失败不阻断优雅关闭流程
    try {
      this.io.close();
    } catch (err) {
      logger.warn(`WebSocket io.close() 失败：${err.message}`);
    }
  },

  /**
   * 运行期 IP 黑名单复查（2026-10-01 第 4 轮，闭合 _assertHandshakeIpNotBanned 的会话面残留）
   *
   * HTTP 侧的 checkIPBlacklist 是逐请求复查，长连接没有"下一个请求"：IP 在建连后被
   * 拉黑时，该 socket 会带着已通过的握手校验一直收实时推送到自然断开。本方法把同一道
   * 闸挂进周期清扫，判据与握手面**完全同源**——同一个 resolveHandshakeIPForSecurityDecision、
   * 同一份名单快照（白名单优先）、同一条 fail-open 口径与同一个 ip_blacklist_failopen
   * 计数。任何一处与握手侧分叉都会变成「握手拦得住、清扫拦不住」的第二扇门。
   *
   * 与握手面的两处**刻意**差异：
   *  1. 取不到地址的连接不参与判定、也**不**断开：握手期"解析不出地址"意味着这次认证
   *     本身可疑（还没有任何信任给过它），清扫期断开一个已在收数据的连接则是处置。
   *     无地址即无从判定封禁，断开它只会误伤。
   *  2. 按 IP 去重后批量并发：同一 NAT 出口下的多条连接只打一次库。
   *     L-29 的教训（for...await 逐连接打库，1000 连接串行 875.92ms）在这里同样成立。
   *
   * fail-open 计数**每轮最多一次**（而非每个失败地址一次）：一次名单库抖动会让全部
   * 待查地址同时失败，逐地址计数把一个根因放大成 N 倍的告警量，时间序列失去意义。
   *
   * @param {import('socket.io').Socket[]} sockets 本轮待复查的已认证连接
   * @returns {Promise<{alive: import('socket.io').Socket[], kicked: number}>}
   *          alive = 未被封禁、可继续参与后续授权复查的连接（保持入参顺序）
   */
  async _sweepBannedIps(sockets) {
    const hops = resolveTrustProxyHops();
    const ipById = new Map();
    for (const socket of sockets) {
      const ip = resolveHandshakeIPForSecurityDecision(socket.handshake, hops);
      if (ip) ipById.set(socket.id, ip);
    }
    // 无任何可判定地址时连模型都不加载：纯内存快速返回，
    // 也让"测试替身没有 handshake"与"生产环境取不到地址"走同一条路径。
    if (ipById.size === 0) return { alive: sockets, kicked: 0 };

    const IPBlacklist = require('../../models/IPBlacklist');
    const verdicts = await Promise.all(
      [...new Set(ipById.values())].map(async (ip) => {
        try {
          const [whitelisted, blocked] = await Promise.all([
            IPBlacklist.isWhitelisted(ip),
            IPBlacklist.isBlocked(ip),
          ]);
          return { ip, banned: !whitelisted && blocked, failed: false };
        } catch (err) {
          logger.error(
            `WebSocket 周期名单复查失败，该地址本轮 fail-open 放行：${ip} ${err.message}`
          );
          return { ip, banned: false, failed: true };
        }
      })
    );
    if (verdicts.some((v) => v.failed)) {
      try {
        require('../../utils/metrics').incSecurityAlert('ip_blacklist_failopen', 'high');
      } catch (_) {
        /* 指标端不可用不影响放行主流程 */
      }
    }
    const bannedByIp = new Map(verdicts.map((v) => [v.ip, v.banned]));

    const alive = [];
    let kicked = 0;
    for (const socket of sockets) {
      const ip = ipById.get(socket.id);
      if (!ip || !bannedByIp.get(ip)) {
        alive.push(socket);
        continue;
      }
      kicked++;
      logger.warn('WebSocket 运行期封禁：建连后该地址被拉黑，主动断开', {
        socketId: socket.id,
        userId: socket.userId ? String(socket.userId) : undefined,
        ip,
      });
      // 处置与通知解耦：auth-error 发送失败不得推迟断开（本仓多处共用的纪律），
      // 两条各自兜底而不是共用一个 try。
      try {
        socket.emit('auth-error', { message: '当前网络已被封禁' });
      } catch (_) {
        /* 通知失败不影响遏制 */
      }
      try {
        socket.disconnect(true);
      } catch (_) {
        /* 客户端可能已断开：遏制意图已达成，且不能中断其余连接的复查 */
      }
    }
    return { alive, kicked };
  },

  /**
   * 复查长连接的当前授权状态
   *
   * 认证只发生在连接建立时，之后 socket.roleCodes / status / tokenVersion
   * 全是快照。长连接可存活数小时，期间用户可能被降级、停权或强制下线，
   * 而受限房间的准入判断若继续读快照，就等于「一次认证、永久有效」。
   *
   * 本方法在受限房间入房前重查数据库：
   * - 用户不存在 / 非 active / 临时锁定 / tokenVersion 已推进 → 断开连接（会话已被吊销）
   * - 否则刷新 socket.roleCodes、把已不满足角色要求的房间 leave 掉，并返回最新角色码
   *
   * 断开而非仅拒绝入房：这三种情形说明整个连接的身份已失效，
   * 不能只拦住一个房间却让它继续留在其他房间收消息。
   *
   * @param {import('socket.io').Socket} socket
   * @returns {Promise<{ok: boolean, roleCodes: string[]}>}
   */
  async revalidateSocket(socket) {
    try {
      const User = require('../../models/User');
      const fresh = await User.findById(socket.userId)
        .select('status tokenVersion lockUntil')
        .populate({ path: 'roles', select: 'code', match: { status: 'active' } });
      return this._applyRevalidation(socket, fresh);
    } catch (err) {
      // fail-closed：复查不可用时不得放行受限房间
      logger.error(`WebSocket 授权复查异常，按拒绝处理: ${socket.id} - ${err.message}`);
      socket.emit('error', { message: '权限校验暂不可用，请稍后重试' });
      return { ok: false, roleCodes: [] };
    }
  },

  /**
   * 授权复查的判定体（L-29 抽出）
   *
   * 与取数解耦，供两条路径共用同一套判定，避免「批量版」与「单连接版」
   * 各写一份而逐渐漂移：
   *  - revalidateSocket：单连接取数后调用（入房复查）
   *  - runCleanupSweep：批量取数后逐连接调用（周期清扫）
   *
   * @param {import('socket.io').Socket} socket
   * @param {object|null} fresh 该 socket.userId 对应的最新用户文档（已 populate roles.code）
   * @returns {{ok: boolean, roleCodes: string[]}}
   */
  _applyRevalidation(socket, fresh) {
    const kick = (message, logMsg) => {
      logger.warn(logMsg);
      socket.emit('auth-error', { message });
      socket.disconnect(true);
      return { ok: false, roleCodes: [] };
    };

    if (!fresh) {
      return kick('用户不存在', `WebSocket 复查失败（用户已删除）: ${socket.id}`);
    }
    if (fresh.status !== 'active') {
      return kick(
        '账户已被禁用或锁定',
        `WebSocket 复查失败（status=${fresh.status}）: ${socket.id}`
      );
    }
    // 临时锁定：写入方只动 lockUntil（不动 status、不推进 tokenVersion），
    // 少了这一条臂，被锁账户的既有连接会一路活到下次自然重连
    if (isTemporarilyLocked(fresh)) {
      return kick(
        '账户已被临时锁定，请稍后重试',
        `WebSocket 复查失败（账户临时锁定至 ${fresh.lockUntil}）: ${socket.id}`
      );
    }
    // tokenVersion 推进意味着该用户的全部会话已被吊销（改密/管理员强制下线）
    const currentVersion = fresh.tokenVersion ?? 0;
    if (socket.tokenVersion !== undefined && socket.tokenVersion !== currentVersion) {
      return kick(
        '会话已失效，请重新登录',
        `WebSocket 复查失败（tokenVersion 已推进）: ${socket.id}`
      );
    }

    const roleCodes = (fresh.roles || []).map((r) => r?.code).filter(Boolean);
    // 回写快照，供无角色要求的房间与统计使用
    socket.roleCodes = roleCodes;

    // 降级即出房（L1-F1）：授/撤角色**不推进 tokenVersion**（只有"吊销全部会话"才推进），
    // 所以只复查 status/tokenVersion 的清扫放不倒已被降级但仍 active 的连接。
    // 封住的是「入房」面——已驻留在 role-management 的管理员被降级后，
    // 若不在此主动 leave，他会在整个连接生命周期内继续收 role-updated /
    // permissions-updated 广播（内容含权限码全集），直到浏览器刷新。
    // 房间清单取自本服务自己的记账（clients.get(id).rooms，join/leave 两处维护），
    // 不读 socket.rooms：后者是 socket.io 内部结构，与本服务的白名单记账并不等价。
    const client = this.clients?.get(socket.id);
    for (const room of client ? [...client.rooms] : []) {
      if (roomRolesSatisfied(room, roleCodes)) continue;
      socket.leave(room);
      client.rooms.delete(room);
      logger.warn(`WebSocket 复查：角色不再满足房间要求，已移出 ${room}`, {
        socketId: socket.id,
        userId: String(socket.userId),
        roleCodes,
      });
    }

    return { ok: true, roleCodes };
  },

  /**
   * 定期清理假死连接 + 周期授权复查（R-2，会话期收尾）
   *
   * 只封住了「入房」面：受限房间 join-room 时 revalidateSocket 复查。
   * 但已驻留在 role-management 房间的长连接，会话期间被降级/停权/强制下线后
   * 不会被主动移出，可继续接收 role-updated/permissions-updated 广播直至重连——
   * 破坏「停权即失效」契约。本清扫对每个已认证连接周期重查
   * status/tokenVersion/角色，命中失效即断开（复用 revalidateSocket 的 kick 路径）。
   *
   * 第 4 轮起本清扫还承担**运行期 IP 封禁**复查（_sweepBannedIps）：与上面的授权
   * 复查是同一处挂载点、同一条「握手拦过就不再看」的补集，理由见该方法头注释。
   */
  setupConnectionCleanup() {
    this._cleanupTimer = setInterval(() => {
      // 防重入：此前复查若因 DB 慢查询未结束，跳过本次改动而非并发叠加打库
      if (this._sweepRunning) return;
      this._sweepRunning = true;
      this.runCleanupSweep()
        .catch((err) => logger.warn(`WebSocket 周期清扫异常：${err.message}`))
        .finally(() => {
          this._sweepRunning = false;
        });
    }, HEARTBEAT_INTERVAL);
    if (this._cleanupTimer && this._cleanupTimer.unref) this._cleanupTimer.unref();
  },

  /**
   * 执行一轮清扫（清理失效记录 + 运行期封禁复查 + 已认证连接授权复查）
   * 独立成方法便于测试直接驱动（不必等 30s 定时器）
   *
   * 三趟顺序固定，每趟的早退互不影响：
   *  1. 纯内存回收 + 收集待查清单（不碰库）
   *  1.5. 名单复查（被拉黑的连接当场断开，不再进入授权复查）
   *  2. 单次 $in 批量授权复查
   * 名单复查排在授权批量查询之前，是为了让 User.find 抖动那一轮仍能完成遏制。
   */
  async runCleanupSweep() {
    let cleanedCount = 0;
    let kickedCount = 0;

    // 第一趟：先做纯内存的「记录回收 + 待查清单」，不碰数据库。
    // 把不需要 DB 的工作与需要 DB 的工作分开，是为了让下面的批量查询
    // 只针对真正要复查的连接（未认证连接在认证成功前不参与）。
    const pending = [];
    for (const socketId of this.clients.keys()) {
      const socket = this.io.sockets.sockets.get(socketId);
      if (!socket) {
        // Socket 已不存在，清理记录
        this.clients.delete(socketId);
        cleanedCount++;
        continue;
      }

      // 未认证/认证中的连接不复查：认证超时由 authTimer 负责
      if (!socket.authenticated || !socket.userId) continue;

      pending.push(socket);
    }

    if (pending.length === 0) {
      this._logSweepResult(cleanedCount, kickedCount);
      return;
    }

    // 第 1.5 趟：运行期封禁复查。放在**授权批量查询之前**是刻意的——
    // User.find 抖动时下面会整轮早退（保留连接等下一轮），若把名单复查排在它后面，
    // 一次与封禁无关的用户表故障就会顺带推迟遏制。判定按 IP 去重、批量并发
    // （L-29 的教训：不得 for...await 逐连接打库）。
    const banPass = await this._sweepBannedIps(pending);
    kickedCount += banPass.kicked;
    const reviewable = banPass.alive;

    if (reviewable.length === 0) {
      this._logSweepResult(cleanedCount, kickedCount);
      return;
    }

    // 第二趟：一次批量查询取回全部待复查用户，再逐连接判定。
    //
    // L-29 修复：原实现是 `for ... await this.revalidateSocket(socket)`，
    // 每个连接一次 findById。上限 1000 连接（见 HEARTBEAT_INTERVAL 注释）时
    // 每轮固定串行 1000 次 DB 往返——实测 875.92ms，且因为 await 串行，
    // 这段时间事件循环被反复让出，30 秒一轮等于周期性钝化。
    // 改为单次 $in 查询后实测 5.55ms（157.8x），存活判定结果完全一致（980/980）。
    // 以上为 2026-09-16 实测值。
    //
    // 去重：同一用户的多个标签页/设备会产生多个 socket，只需查一次。
    const uniqueUserIds = [...new Set(reviewable.map((s) => String(s.userId)))];
    let freshByUser = new Map();
    let dbUnavailable = false;
    try {
      const User = require('../../models/User');
      const docs = await User.find({ _id: { $in: uniqueUserIds } })
        .select('status tokenVersion lockUntil')
        .populate({ path: 'roles', select: 'code', match: { status: 'active' } });
      freshByUser = new Map(docs.map((doc) => [String(doc._id), doc]));
    } catch (err) {
      // DB 瞬时故障：不能因为一次抖动清场全部在线连接。
      // 保持原语义——fail-closed 拒绝入房，但周期复查仅告警、等下一轮重试。
      dbUnavailable = true;
      logger.error(`WebSocket 批量授权复查异常，本轮跳过: ${err.message}`);
    }

    if (dbUnavailable) {
      logger.warn(`WebSocket 周期复查暂不可用，保留 ${reviewable.length} 个连接等待下轮`);
      this._logSweepResult(cleanedCount, kickedCount);
      return;
    }

    for (const socket of reviewable) {
      const fresh = freshByUser.get(String(socket.userId)) || null;
      const result = this._applyRevalidation(socket, fresh);
      if (!result.ok && !socket.connected) {
        // kick 路径（用户删除/停权/tokenVersion 推进）内部已 disconnect(true)
        kickedCount++;
      }
    }

    this._logSweepResult(cleanedCount, kickedCount);
  },

  /**
   * 输出一轮清扫的结果（仅在确有变化时打日志，避免 30s 一次的空转噪声）
   * @param {number} cleanedCount 回收的失效记录数
   * @param {number} kickedCount 踢出的失效会话数
   */
  _logSweepResult(cleanedCount, kickedCount) {
    if (cleanedCount > 0 || kickedCount > 0) {
      logger.info(
        `WebSocket 清扫: 移除 ${cleanedCount} 个失效记录, 复查踢出 ${kickedCount} 个失效会话, ` +
          `当前总连接: ${this.clients.size}`
      );
    }
  },
};

module.exports = { methods };
