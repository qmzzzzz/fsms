'use strict';

/**
 * P2-3 验收：「审计记录 jwt_key_rotated」。
 *
 * 判据是**变化检测**而不是每次启动都记：连续重启不得重复记账（否则轮换事件
 * 淹没在重启噪音里），首次登记基线不记（首次配置不是轮换），只有当前生效的
 * kid 与基线不同才记一条。另钉住两条失效方向：
 *   · 并发认领失败（另一副本已改基线）⇒ 不重复记；
 *   · 审计落库失败 ⇒ 基线退回旧值，下次启动重试（宁可重复，不可缺席）。
 *
 * 本组直接改进程内 config（jwtKeys 每次调用都读它），不重走 env 解析——
 * env 形状与启动校验已由 jwtKeyRotation.test.js 覆盖。
 */

const mongoose = require('mongoose');
const SystemConfig = require('../../models/SystemConfig');
const AuditLog = require('../../models/AuditLog');
const config = require('../../config');
const { recordJwtKeyRotation, MARKER_KEY } = require('../../services/jwtKeyRotationAudit');

const SAVED = {
  secrets: config.jwt.secrets,
  currentKid: config.jwt.currentKid,
  refreshSecrets: config.jwt.refreshSecrets,
  refreshCurrentKid: config.jwt.refreshCurrentKid,
};

let K1;
let K2;
let R1;
let R2;

/** 每个用例用一组唯一 kid：审计集合 append-only（禁止 deleteMany），靠 kid 区分归属 */
const freshKids = () => {
  const salt = `${Date.now().toString(36)}${Math.random().toString(36).slice(2, 8)}`;
  K1 = `k1_${salt}`;
  K2 = `k2_${salt}`;
  R1 = `r1_${salt}`;
  R2 = `r2_${salt}`;
};

const setKids = (accessKid, refreshKid) => {
  config.jwt.secrets = { [K1]: 'secret-access-1', [K2]: 'secret-access-2' };
  config.jwt.currentKid = accessKid || '';
  config.jwt.refreshSecrets = { [R1]: 'secret-refresh-1', [R2]: 'secret-refresh-2' };
  config.jwt.refreshCurrentKid = refreshKid || '';
};

const markerDoc = () => SystemConfig.findOne({ key: MARKER_KEY }).lean();
const rotationAudits = () =>
  AuditLog.find({ action: 'jwt_key_rotated', reason: new RegExp(K1) }).lean();
const storedMarker = async () => JSON.parse((await markerDoc()).value);

describe('JWT 密钥轮换留痕（启动期）', () => {
  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
  });

  beforeEach(async () => {
    await SystemConfig.deleteMany({ key: MARKER_KEY });
    freshKids();
    setKids(K1, R1);
  });

  afterEach(() => jest.restoreAllMocks());

  afterAll(async () => {
    Object.assign(config.jwt, SAVED);
    if (mongoose.connection.readyState !== 0) {
      await SystemConfig.deleteMany({ key: MARKER_KEY });
      await mongoose.disconnect();
    }
  });

  test('首次启动只登记基线，不落审计', async () => {
    expect(await recordJwtKeyRotation()).toBeNull();
    expect(await storedMarker()).toEqual({ access: K1, refresh: R1 });
    expect(await rotationAudits()).toHaveLength(0);
  });

  test('同一组 kid 连续重启不重复记账', async () => {
    await recordJwtKeyRotation();
    expect(await recordJwtKeyRotation()).toBeNull();
    expect(await rotationAudits()).toHaveLength(0);
  });

  test('access 侧切换：记一条，含前后 kid 且不含密钥本身', async () => {
    await recordJwtKeyRotation();
    setKids(K2, R1);

    const ret = await recordJwtKeyRotation();
    expect(ret).toEqual({
      before: { access: K1, refresh: R1 },
      after: { access: K2, refresh: R1 },
    });

    const audits = await rotationAudits();
    expect(audits).toHaveLength(1);
    expect(audits[0]).toMatchObject({
      action: 'jwt_key_rotated',
      category: 'system',
      username: 'system',
      success: true,
      riskLevel: 'medium',
    });
    expect(audits[0].reason).toContain(`${K1} → ${K2}`);
    // 审计集合 append-only 且会导出 CSV：密钥（连指纹）都不得进入 reason
    expect(audits[0].reason).not.toMatch(/secret-access|secret-refresh/);

    // 基线与记录同步推进：再次启动不重复
    expect(await storedMarker()).toEqual({ access: K2, refresh: R1 });
    expect(await recordJwtKeyRotation()).toBeNull();
    expect(await rotationAudits()).toHaveLength(1);
  });

  test('refresh 侧切换同样记账（两个域各自留痕）', async () => {
    await recordJwtKeyRotation();
    setKids(K1, R2);
    await recordJwtKeyRotation();
    const audits = await rotationAudits();
    expect(audits).toHaveLength(1);
    expect(audits[0].reason).toContain(`${R1} → ${R2}`);
  });

  test('单钥 → 密钥集同样是一次切换（single 标签可读）', async () => {
    setKids('', '');
    await recordJwtKeyRotation();
    expect(await storedMarker()).toEqual({ access: null, refresh: null });

    setKids(K1, R1);
    await recordJwtKeyRotation();
    const audits = await rotationAudits();
    expect(audits).toHaveLength(1);
    expect(audits[0].reason).toContain(`access single → ${K1}`);
  });

  test('并发启动：另一副本已认领基线 ⇒ 本副本不再记（不重复审计）', async () => {
    await recordJwtKeyRotation();
    setKids(K2, R1);
    jest.spyOn(SystemConfig, 'findOneAndUpdate').mockResolvedValue(null);
    expect(await recordJwtKeyRotation()).toBeNull();
    expect(await rotationAudits()).toHaveLength(0);
  });

  test('并发首次启动撞唯一索引 ⇒ 视为无变化，不抛', async () => {
    jest
      .spyOn(SystemConfig, 'findOneAndUpdate')
      .mockRejectedValue(Object.assign(new Error('dup'), { code: 11000 }));
    await expect(recordJwtKeyRotation()).resolves.toBeNull();
    expect(await rotationAudits()).toHaveLength(0);
  });

  test('审计落库失败 ⇒ 基线退回旧值，下次启动仍能补记', async () => {
    await recordJwtKeyRotation();
    setKids(K2, R1);
    jest.spyOn(AuditLog, 'record').mockResolvedValue(null);

    expect(await recordJwtKeyRotation()).toBeNull();
    expect(await storedMarker()).toEqual({ access: K1, refresh: R1 });

    jest.restoreAllMocks();
    await recordJwtKeyRotation();
    expect(await rotationAudits()).toHaveLength(1);
  });

  test('基线读取失败向上抛（启动侧只告警，不阻断）', async () => {
    jest
      .spyOn(SystemConfig, 'findOne')
      .mockReturnValue({ lean: () => Promise.reject(new Error('db down')) });
    await expect(recordJwtKeyRotation()).rejects.toThrow('db down');
  });
});
