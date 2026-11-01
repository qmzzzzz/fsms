/**
 * 隐私同意记录（一-7）：模型三条不变式 + 服务层派生/幂等/范围清单
 *
 * 为什么这些断言值得写：同意记录是**合规证据**，它的失效形态都是"看起来有、实际不能用"——
 *   · 能改能删 ⇒ 证据可被事后抹掉（append-only 是唯一有效形态）；
 *   · 重复提交产生第二条 ⇒ "同意了几次"不再可判定；
 *   · 版本号不由服务层决定 ⇒ 写入侧绕过改版就能让旧同意冒充新版；
 *   · 范围清单在本文件里手抄一份 ⇒ 与数据分类分级台账漂移且无信号。
 * 可证伪点：append-only 四条写入口逐个真调（不是只查钩子挂没挂）；
 * 幂等用「同账号同版本提交两次」实测条数；范围清单与 CONSENT_SCOPES 的 notice 项逐字比对。
 */
'use strict';

const mongoose = require('mongoose');

describe('隐私同意记录（一-7）', () => {
  let ConsentRecord;
  let consentService;
  const { CONSENT_SCOPES } = require('../../constants/dataClassification');

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    ConsentRecord = require('../../models/ConsentRecord');
    consentService = require('../../services/consentService');
    // 唯一索引那条用例断言的是**数据库**行为：Mongoose 建索引是异步的，不 await init
    // 时是否命中唯一键取决于建索引与首次 create 的竞态（并行跑套件时实测会假绿/假红）。
    await ConsentRecord.init();
  });

  afterEach(async () => {
    // 清库靠显式 bypassAppendOnly：与审计链护栏同一契约（NODE_ENV=test 才放行）
    await ConsentRecord.deleteMany({}, null, { bypassAppendOnly: true }).catch(() => {});
  });

  afterAll(async () => {
    await ConsentRecord.deleteMany({}, null, { bypassAppendOnly: true }).catch(() => {});
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  test('前提自证：范围清单来自分级台账的 notice 项，且不是空表', () => {
    const noticeScopes = Object.entries(CONSENT_SCOPES)
      .filter(([, s]) => s.basis === 'notice')
      .map(([k]) => k)
      .sort();
    expect(noticeScopes.length).toBeGreaterThanOrEqual(3);
    expect(consentService.scopesForPrivacyNotice().slice().sort()).toEqual(noticeScopes);
    // 反向：组织法定基础项（audit/security/…）不得混进同意范围清单
    expect(
      consentService.scopesForPrivacyNotice().filter((k) => CONSENT_SCOPES[k].basis !== 'notice')
    ).toEqual([]);
  });

  test('recordConsent：落一条记录，版本由服务层决定，范围与告知一致', async () => {
    const userId = new mongoose.Types.ObjectId();
    const req = { ip: '127.0.0.1', get: () => 'jest-consent-agent' };
    const result = await consentService.recordConsent({ userId, username: 'consent_a', req });
    expect(result.recorded).toBe(true);
    expect(result.version).toBe(consentService.PRIVACY_NOTICE_VERSION);

    const doc = await ConsentRecord.findOne({ userId }).lean();
    expect(doc).toBeTruthy();
    expect(doc.policy).toBe('privacy');
    expect(doc.version).toBe(consentService.PRIVACY_NOTICE_VERSION);
    expect(doc.scopes.slice().sort()).toEqual(
      consentService.scopesForPrivacyNotice().slice().sort()
    );
    expect(doc.ip).toBe('127.0.0.1');
    expect(doc.userAgent).toBe('jest-consent-agent');
    expect(doc.source).toBe('self-register');
    expect(doc.acceptedAt).toBeInstanceOf(Date);
  });

  test('幂等：同账号同版本再提交一次不产生第二条记录', async () => {
    const userId = new mongoose.Types.ObjectId();
    await consentService.recordConsent({ userId, username: 'consent_b' });
    const second = await consentService.recordConsent({ userId, username: 'consent_b' });
    expect(second.recorded).toBe(false);
    expect(await ConsentRecord.countDocuments({ userId })).toBe(1);
  });

  test('consentStatus：现行版本未同意时 accepted=false，同意后带出时间与范围', async () => {
    const userId = new mongoose.Types.ObjectId();
    const before = await consentService.consentStatus(userId);
    expect(before.accepted).toBe(false);
    expect(before.acceptedAt).toBeNull();
    expect(before.version).toBe(consentService.PRIVACY_NOTICE_VERSION);

    await consentService.recordConsent({ userId, username: 'consent_c' });
    const after = await consentService.consentStatus(userId);
    expect(after.accepted).toBe(true);
    expect(after.acceptedAt).toBeInstanceOf(Date);
    expect(after.requiredScopes).toEqual(consentService.scopesForPrivacyNotice());
  });

  test('旧版本同意不算作对现行版本的同意（改版后必须重新征得）', async () => {
    const userId = new mongoose.Types.ObjectId();
    await ConsentRecord.create({
      userId,
      username: 'consent_old',
      policy: 'privacy',
      version: '2025-01-01',
      scopes: ['account'],
      acceptedAt: new Date('2025-01-01T00:00:00Z'),
      source: 'self-register',
    });
    const status = await consentService.consentStatus(userId);
    expect(status.accepted).toBe(false);
    expect(status.acceptedAt).toBeNull();
  });

  test('append-only：save 改写与四类批量写入口逐条被拒', async () => {
    const userId = new mongoose.Types.ObjectId();
    await consentService.recordConsent({ userId, username: 'consent_d' });

    const doc = await ConsentRecord.findOne({ userId });
    doc.username = 'tampered';
    await expect(doc.save()).rejects.toThrow(/append-only/);

    const cases = [
      () => ConsentRecord.updateOne({ userId }, { $set: { username: 'tampered' } }),
      () => ConsentRecord.updateMany({ userId }, { $set: { username: 'tampered' } }),
      () => ConsentRecord.findOneAndUpdate({ userId }, { $set: { username: 'tampered' } }),
      () =>
        ConsentRecord.bulkWrite([
          { updateOne: { filter: { userId }, update: { $set: { username: 'tampered' } } } },
        ]),
      () => ConsentRecord.deleteOne({ userId }),
      () => ConsentRecord.deleteMany({ userId }),
    ];
    for (const run of cases) {
      await expect(run()).rejects.toThrow(/append-only/);
    }
    // 前提自证：记录仍在，说明上面不是"因为没匹配到文档才没改"
    expect((await ConsentRecord.findOne({ userId }).lean()).username).toBe('consent_d');
  });

  test('唯一索引：(同账号, 同政策, 同版本) 第二条 create 被数据库拒绝（并发下也只有一个成功）', async () => {
    const userId = new mongoose.Types.ObjectId();
    const base = {
      userId,
      username: 'consent_e',
      policy: 'privacy',
      version: consentService.PRIVACY_NOTICE_VERSION,
      scopes: ['account'],
      acceptedAt: new Date(),
      source: 'self-register',
    };
    await ConsentRecord.create(base);
    await expect(ConsentRecord.create({ ...base, username: 'consent_e2' })).rejects.toThrow(
      /E11000|duplicate key/
    );
  });
});
