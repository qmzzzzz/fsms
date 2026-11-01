/**
 * 数据分类分级门禁（审计一-7）
 *
 * 缺口本体：仓里此前没有一处「字段属于第几级、依据是什么、静态是否加密」的声明，
 * 于是等保 2.0 三级的数据分类分级要求不可核对——新增一个手机号/姓名字段时，
 * 没有任何机制会问「它该不该加密、该不该进审计脱敏名单、该不该单独同意」。
 *
 * 本闸把 `constants/dataClassification` 变成**可机械核对**的台账，六条判据各有牙：
 *   ① 模型清单双向闭合：models/index.js 里的每个模型都要分级，分级表里也不许有僵尸模型；
 *   ② 每条字段声明的路径必须真的存在于 schema（防"声明了一个不存在的字段"看起来像已覆盖）；
 *   ③ 个人信息正则命中的路径必须逐条声明且等级 ≥ L3（漏一个字段就红，不是抽查）；
 *   ④ select:false 的路径必须逐条声明（凭证/检索键不会因为"忘了登记"而变成未分级）；
 *   ⑤ atRest='gcm' 与 schema getter 双向对拍：声明加密但没 getter（读不到明文）、
 *      有 getter 却声明明文（说一套做一套）都红；唯一豁免走 GCM_WITHOUT_GETTER 且要写理由；
 *   ⑥ 反空自证：模型数 / 路径数 / 正则命中数都有下界——把扫描器改成恒空时这组断言立刻红。
 *
 * 为什么用**运行期 schema**而不是静态正则：`select:false` 与 getter 都是 schema 选项，
 * 静态正则数不出"嵌套路径里的 select:false"，也分不清 `{ get: ... }` 是字段选项还是别的对象属性。
 */
'use strict';

const {
  MODEL_LEVELS,
  FIELD_LEVELS,
  LEVEL_CODES,
  AT_REST_FORMS,
  CONSENT_SCOPES,
  GCM_WITHOUT_GETTER,
} = require('../../constants/dataClassification');

const models = require('../../models');

/** 与基线时间戳同口径的"非业务路径"：_id/timestamps/版本号不参与分级 */
const SKIP = new Set(['_id', '__v', 'createdAt', 'updatedAt']);

/**
 * 个人信息候选判定（键名口径，与 utils/helpers 的 SENSITIVE_KEY_SUBSTRINGS 同源思路：
 * 宁可多收）。**它不是分级依据**，只是"哪些字段必须被显式声明过"的探针——
 * 命中即要求台账里有条目，等级与理由仍由人写。
 */
const PII_KEY = new RegExp(
  '(^|\\.)((?:user)?name|username|realName|phone|phoneKey|email|emailKey|emailGrams|' +
    'password|passwordHistory|mfaSecret|mfaRecoveryCodes|tokenHash|jti|sid|sessionId|' +
    'fingerprint|userAgent|ip|lastIp|lastLoginIp|reportedIp|socketPeer|allowedIPs|' +
    'department|avatar)$',
  'i'
);

/** 把 17 个模型的 schema 摊平成 [{model, path, selectFalse, hasGetter}] */
const schemaPaths = () => {
  const out = [];
  for (const [model, M] of Object.entries(models)) {
    for (const [path, schemaType] of Object.entries(M.schema.paths)) {
      if (SKIP.has(path)) continue;
      const opts = schemaType.options || {};
      out.push({
        model,
        path,
        full: model + '.' + path,
        selectFalse: opts.select === false,
        hasGetter: typeof opts.get === 'function',
      });
    }
  }
  return out;
};

const PATHS = schemaPaths();

describe('数据分类分级台账（一-7）', () => {
  test('反空自证：模型数、路径数、个人信息命中数都在量级上（扫描器失效时后面全绿也没意义）', () => {
    expect(Object.keys(models).length).toBeGreaterThanOrEqual(17);
    expect(PATHS.length).toBeGreaterThanOrEqual(300);
    const hits = PATHS.filter((p) => PII_KEY.test(p.path));
    expect(hits.length).toBeGreaterThanOrEqual(40);
    // 反向：把后缀换成不存在的形态必须归零——否则上面的下界可能只是"什么都算命中"
    expect(PATHS.filter((p) => PII_KEY.test(p.path + '.zzz')).length).toBe(0);
    expect(Object.keys(MODEL_LEVELS).length).toBeGreaterThanOrEqual(17);
    expect(Object.keys(FIELD_LEVELS).length).toBeGreaterThanOrEqual(50);
  });

  test('① 模型清单双向闭合：models/index.js 的每个模型都分级，分级表里没有僵尸模型', () => {
    const actual = Object.keys(models).sort();
    expect(Object.keys(MODEL_LEVELS).sort()).toEqual(actual);
    for (const [model, entry] of Object.entries(MODEL_LEVELS)) {
      expect({ model, level: LEVEL_CODES.includes(entry.level) }).toEqual({ model, level: true });
      expect({ model, basis: entry.basis.length }).toEqual({ model, basis: expect.any(Number) });
      expect(entry.basis.trim().length).toBeGreaterThan(0);
    }
  });

  test('② 同意范围表自身成立：每项都有 label/notice，且 basis 只取两种法定基础', () => {
    const scopes = Object.entries(CONSENT_SCOPES);
    expect(scopes.length).toBeGreaterThanOrEqual(6);
    for (const [key, s] of scopes) {
      expect({ key, label: String(s.label).trim().length > 0 }).toEqual({ key, label: true });
      expect({ key, notice: String(s.notice).trim().length > 0 }).toEqual({ key, notice: true });
      expect({ key, basis: ['notice', 'legalBasis'].includes(s.basis) }).toEqual({
        key,
        basis: true,
      });
    }
    // 反向：basis 写成别的词必须被抓住（不是"只要不是空就算过"）
    expect(scopes.filter(([, s]) => !['notice', 'legalBasis'].includes(s.basis)).length).toBe(0);
  });

  test('③ 每条字段声明的路径都真的存在于 schema（声明不存在的字段 = 假覆盖）', () => {
    const real = new Set(PATHS.map((p) => p.full));
    const ghosts = Object.keys(FIELD_LEVELS).filter((k) => !real.has(k));
    expect(ghosts).toEqual([]);
    for (const [key, entry] of Object.entries(FIELD_LEVELS)) {
      expect({ key, level: LEVEL_CODES.includes(entry.level) }).toEqual({ key, level: true });
      expect({ key, atRest: AT_REST_FORMS.includes(entry.atRest) }).toEqual({ key, atRest: true });
      expect({ key, pii: typeof entry.pii }).toEqual({ key, pii: 'boolean' });
      expect(entry.reason.trim().length).toBeGreaterThan(0);
    }
  });

  test('④ 个人信息正则命中的每个路径都必须声明；标为个人信息的必须 ≥ L3 且归属某个同意范围', () => {
    const declared = new Set(Object.keys(FIELD_LEVELS));
    const undeclared = PATHS.filter((p) => PII_KEY.test(p.path) && !declared.has(p.full)).map(
      (p) => p.full
    );
    expect(undeclared).toEqual([]);
    const entries = Object.entries(FIELD_LEVELS);
    // 个人信息不得悄悄降级：标了 pii:true 却停在 L2，等于把个人信息按配置元数据保护
    expect(entries.filter(([, e]) => e.pii && !/^L3|^L4/.test(e.level)).map(([k]) => k)).toEqual(
      []
    );
    // 敏感及以上（L3/L4）的字段必须归属某个同意/告知范围，否则 consentService 派不出范围清单
    expect(
      entries.filter(([, e]) => /^L3|^L4/.test(e.level) && !e.consent).map(([k]) => k)
    ).toEqual([]);
    // consent 标签只能取 CONSENT_SCOPES 的键（写散文等于范围清单拼不起来，且无信号）
    expect(
      entries
        .filter(
          ([, e]) => e.consent && !Object.prototype.hasOwnProperty.call(CONSENT_SCOPES, e.consent)
        )
        .map(([k, e]) => k + ' -> ' + e.consent)
    ).toEqual([]);
    // 反向：L2 配置元数据不得挂同意范围（否则会把"系统开关"当成需征得同意的对象）
    expect(entries.filter(([, e]) => e.level === 'L2' && e.consent).map(([k]) => k)).toEqual([]);
  });

  test('⑤ select:false 的每个路径都必须声明（凭证材料不会因漏登记而变成未分级）', () => {
    const declared = new Set(Object.keys(FIELD_LEVELS));
    const hidden = PATHS.filter((p) => p.selectFalse);
    expect(hidden.length).toBeGreaterThanOrEqual(13);
    expect(hidden.filter((p) => !declared.has(p.full)).map((p) => p.full)).toEqual([]);
  });

  test('⑥ atRest=gcm 与 schema getter 双向对拍（含 GCM_WITHOUT_GETTER 的豁免理由）', () => {
    const byFull = new Map(PATHS.map((p) => [p.full, p]));
    const declaredGcm = Object.keys(FIELD_LEVELS).filter((k) => FIELD_LEVELS[k].atRest === 'gcm');
    expect(declaredGcm.length).toBeGreaterThanOrEqual(3);
    for (const key of declaredGcm) {
      if (Object.prototype.hasOwnProperty.call(GCM_WITHOUT_GETTER, key)) {
        expect({ key, reason: GCM_WITHOUT_GETTER[key].trim().length }).toEqual({
          key,
          reason: expect.any(Number),
        });
        expect(GCM_WITHOUT_GETTER[key].trim().length).toBeGreaterThan(0);
        continue;
      }
      expect({ key, getter: byFull.get(key).hasGetter }).toEqual({ key, getter: true });
    }
    // 反向：schema 上有 getter 的路径，台账必须声明它是 gcm（"有解密却说存明文"同样红）
    const getterPaths = PATHS.filter((p) => p.hasGetter).map((p) => p.full);
    expect(getterPaths.length).toBeGreaterThanOrEqual(3);
    expect(getterPaths.filter((k) => !FIELD_LEVELS[k] || FIELD_LEVELS[k].atRest !== 'gcm')).toEqual(
      []
    );
    // 豁免清单不得有僵尸条目（列了一个没有 gcm 声明的键）
    expect(
      Object.keys(GCM_WITHOUT_GETTER).filter((k) => FIELD_LEVELS[k]?.atRest !== 'gcm')
    ).toEqual([]);
  });
});
