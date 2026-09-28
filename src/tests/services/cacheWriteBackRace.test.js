'use strict';

/**
 * "先查库、后写缓存"的写回竞态：查库期间的主动失效不得被撤销
 *
 * 两处缓存都是同一个形状：读路径 miss → `await` 查库 → `set` 写回。
 * 而失效通知（管理员改权限 / 吊销会话）落在这一趟往返中间时，它 delete 的是
 * 一个**还不存在**的条目（no-op），随后 in-flight 的读取拿着"失效之前"的结论
 * 把条目重新种回去 —— 主动失效被静默撤销，最长要到 TTL 才收敛。
 *
 * 方向上这不是"数据旧一点"的显示问题，两处都是授权判定：
 *   · userPermissionService.getPermissions：被收回的权限在 30 秒里照常放行；
 *   · sessionService.validateSession：刚被踢下线的设备在 15 秒里继续通过认证。
 * 而两处代码各自的注释都明写着"必须立即失效"（前者见 populate match 处、
 * 后者见 validateSession 的"吊销不需要在这里重查"），即口径本来就不允许这个窗口。
 *
 * middleware/auth.js 的用户缓存早已用 queryStartedAt/invalidatedDuringQuery 关掉
 * 同一扇窗，本文件钉的是另外两处补齐后的行为。
 *
 * 竞态靠"手动延后一次数据库返回"造出来，不靠 sleep 赌时序：
 * mock 掉查询方法，先让读路径挂起，再触发失效，最后才 resolve 查询。
 * 反向对照钉住"闸门不是干脆不缓存"：没有并发失效时写回照常生效。
 */

const mongoose = require('mongoose');
const User = require('../../models/User');
const UserSession = require('../../models/UserSession');

require('../../models/Role');
require('../../models/Permission');

const deferred = () => {
  let resolve;
  const promise = new Promise((r) => {
    resolve = r;
  });
  return { promise, resolve };
};

describe('缓存写回竞态：查库期间的失效必须赢', () => {
  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) await mongoose.connect(process.env.MONGODB_URI);
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) await mongoose.connection.close();
  });

  describe('权限缓存（userPermissionService）', () => {
    let service;
    let findById;

    beforeAll(() => {
      service = require('../../services/userPermissionService');
    });

    beforeEach(() => {
      findById = jest.spyOn(User, 'findById');
      // 清空模块级缓存并推进代际，用例之间不串扰
      service.invalidatePermissionCacheLocal();
    });

    afterEach(() => {
      findById.mockRestore();
    });

    test('失效落在查库期间 ⇒ 旧结果不得写回，下一次读取必须重新查库', async () => {
      const userId = new mongoose.Types.ObjectId().toString();
      const q1 = deferred();
      // getPermissions 走的是 `User.findById(key).populate({...})`，同步挂到 promise 上
      findById.mockReturnValue({ populate: () => q1.promise });

      const inflight = service.getPermissions(userId);
      expect(findById).toHaveBeenCalledTimes(1); // 已发起查询并挂起

      // 管理员此刻改了这个人的权限：本地失效（delete 一个还不存在的条目）
      service.invalidatePermissionCacheLocal(userId);

      // 失效之前读到的结果现在才落地
      q1.resolve({ roles: [{ permissions: [{ code: 'report:export' }] }] });
      expect(await inflight).toEqual(['report:export']);

      // 关键：这次读取必须是**新的一趟查询**，而不是命中刚被撤销的旧结果
      const q2 = deferred();
      findById.mockReturnValue({ populate: () => q2.promise });
      const after = service.getPermissions(userId);
      expect(findById).toHaveBeenCalledTimes(2);
      q2.resolve({ roles: [{ permissions: [{ code: 'report:view' }] }] });
      expect(await after).toEqual(['report:view']);
    });

    test('全局失效（改的是角色本身的权限定义）落在查库期间 ⇒ 同样不得写回', async () => {
      const userId = new mongoose.Types.ObjectId().toString();
      const q1 = deferred();
      findById.mockReturnValue({ populate: () => q1.promise });

      const inflight = service.getPermissions(userId);
      service.invalidatePermissionCacheLocal(); // 不传 userId ⇒ 走全局清空分支
      q1.resolve({ roles: [{ permissions: [{ code: 'old:perm' }] }] });
      expect(await inflight).toEqual(['old:perm']);

      const q2 = deferred();
      findById.mockReturnValue({ populate: () => q2.promise });
      const after = service.getPermissions(userId);
      expect(findById).toHaveBeenCalledTimes(2);
      q2.resolve({ roles: [{ permissions: [{ code: 'new:perm' }] }] });
      expect(await after).toEqual(['new:perm']);
    });

    test('反向对照：查库期间没有失效时，写回照常生效（闸门不是干脆不缓存）', async () => {
      const userId = new mongoose.Types.ObjectId().toString();
      const q1 = deferred();
      findById.mockReturnValue({ populate: () => q1.promise });

      const first = service.getPermissions(userId);
      q1.resolve({ roles: [{ permissions: [{ code: 'a:read' }] }] });
      expect(await first).toEqual(['a:read']);

      await service.getPermissions(userId);
      expect(findById).toHaveBeenCalledTimes(1); // 第二次命中缓存
    });
  });

  describe('会话缓存（sessionService）', () => {
    let service;
    let findOne;
    const sid = 'race-sid-not-a-real-session';

    beforeAll(() => {
      service = require('../../services/sessionService');
    });

    beforeEach(() => {
      findOne = jest.spyOn(UserSession, 'findOne');
      service.clearSessionCache(); // 本地清空 + 代际推进
    });

    afterEach(() => {
      findOne.mockRestore();
    });

    const usableDoc = () => ({
      isUsable: () => true,
      expiresAt: new Date(Date.now() + 600_000),
    });

    test('吊销落在查库期间 ⇒ "仍可用"的旧结论不得写回', async () => {
      const q1 = deferred();
      findOne.mockReturnValue(q1.promise);

      const inflight = service.validateSession(sid);
      expect(findOne).toHaveBeenCalledTimes(1);

      // 管理员此刻把这台设备踢下线：本地 delete（条目还不存在）+ 广播
      service.invalidateSessionCache(sid);

      q1.resolve(usableDoc());
      expect((await inflight).usable).toBe(true);

      // 吊销之后再校验：必须重新查库，并给出吊销后的结论
      const q2 = deferred();
      findOne.mockReturnValue(q2.promise);
      const after = service.validateSession(sid);
      expect(findOne).toHaveBeenCalledTimes(2);
      q2.resolve(null); // 会话已不存在
      expect((await after).usable).toBe(false);
    });

    test('全局吊销（改密/强制下线）落在查库期间 ⇒ 旧结论同样不得写回', async () => {
      const q1 = deferred();
      findOne.mockReturnValue(q1.promise);

      const inflight = service.validateSession(sid);
      service.clearSessionCache(); // 全量分支
      q1.resolve(usableDoc());
      expect((await inflight).usable).toBe(true);

      const q2 = deferred();
      findOne.mockReturnValue(q2.promise);
      const after = service.validateSession(sid);
      expect(findOne).toHaveBeenCalledTimes(2);
      q2.resolve(null);
      expect((await after).usable).toBe(false);
    });

    test('反向对照：没有并发吊销时，结论照常缓存（不放大打库）', async () => {
      const q1 = deferred();
      findOne.mockReturnValue(q1.promise);
      const first = service.validateSession(sid);
      q1.resolve(usableDoc());
      expect((await first).usable).toBe(true);

      const second = await service.validateSession(sid);
      expect(second.usable).toBe(true);
      expect(findOne).toHaveBeenCalledTimes(1);
    });
  });
});
