/**
 * 业务数据保留期：合规判据与 TTL 索引接线（F-07，2026-10-17）
 *
 * 缺陷形状（已回源复核）：
 *   - `complianceVerdicts.businessRetentionVerdict()` 的 passed 只看
 *     `adjusted.length === 0`——**未启用本身不会让 allPassed 变 false**。
 *     于是「业务数据永久保留」与「保留策略已执行」在发布流程读的字段上同一个值。
 *   - `assertBusinessRetentionEnforceable()` 只看 `enabled`（= 环境变量配了），
 *     不要求 `declaredDays` 非 null，也不检查生效值是否超过声明天数。
 *   - 四个业务集合的模型都没有 TTL 索引（`expireAfterSeconds` 零命中）。
 *
 * 本套件钉住修复后的四件事：
 *   ① 未启用 ⇒ 判据不通过（不再被一句"就绪"盖过去）；
 *   ② 全部按 180 天启用 ⇒ 判据通过；
 *   ③ 生效值超过声明天数 ⇒ 判据不通过且拒绝建索引；
 *   ④ 三个业务集合的 schema 在配置后真的带上 TTL 索引，且字段取事件时间。
 */

const { businessRetentionVerdict } = require('../../../scripts/complianceVerdicts');

const MODELS = ['FireAlarm', 'Inspection', 'FireDevice', 'User'];
const ENV_KEYS = MODELS.map(
  (m) => `BUSINESS_RETENTION_DAYS_${m.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toUpperCase()}`
);

const clearAll = () => ENV_KEYS.forEach((k) => delete process.env[k]);

afterEach(clearAll);

describe('F-07 合规判据：未启用必须显形为"未就绪"，配置矛盾必须转红', () => {
  test('全部未配置 ⇒ passed=true（代码不矛盾）但 notReady=true，detail 写明"数据永久保留"', () => {
    clearAll();
    const v = businessRetentionVerdict();
    // 两档语义：passed 回答"代码/配置有没有自相矛盾"，notReady 回答"治理能力有没有开起来"。
    // 仓库态（CI 无生产库）不该因为"没开开关"而红——那会让门禁永远红、最后被人绕过；
    // 部署门禁（COMPLIANCE_STRICT=1）读 notReady，未启用即阻断。
    expect(v.passed).toBe(true);
    expect(v.notReady).toBe(true);
    expect(v.detail).toContain('未启用');
    expect(v.detail).toContain('数据永久保留');
  });

  test('按 180 天全部启用 ⇒ passed=true 且 notReady=false', () => {
    ENV_KEYS.forEach((k) => {
      process.env[k] = '180';
    });
    const v = businessRetentionVerdict();
    expect(v.passed).toBe(true);
    expect(v.notReady).toBe(false);
    expect(v.detail).not.toContain('数据永久保留');
  });

  test('只启用一部分 ⇒ notReady=true，且点名未启用的集合', () => {
    process.env.BUSINESS_RETENTION_DAYS_FIRE_ALARM = '180';
    const v = businessRetentionVerdict();
    expect(v.notReady).toBe(true);
    expect(v.detail).toContain('未启用');
    expect(v.detail).toMatch(/Inspection|FireDevice|User/);
  });

  test('生效值超过声明天数 ⇒ passed=false（"只留 180 天"在数据面上不成立）', () => {
    ENV_KEYS.forEach((k) => {
      process.env[k] = '180';
    });
    process.env.BUSINESS_RETENTION_DAYS_FIRE_ALARM = '365';
    const v = businessRetentionVerdict();
    expect(v.passed).toBe(false);
    expect(v.detail).toContain('超过业务声明');
  });

  test('越界值被钳制 ⇒ passed=false（配置意图与生效值不一致）', () => {
    ENV_KEYS.forEach((k) => {
      process.env[k] = '180';
    });
    process.env.BUSINESS_RETENTION_DAYS_FIRE_ALARM = '99999';
    const v = businessRetentionVerdict();
    expect(v.passed).toBe(false);
    expect(v.detail).toContain('配置意图与生效值不一致');
  });
});

describe('F-07 TTL 索引接线：配置后 schema 真的带上 TTL', () => {
  const loadSchemaIndexes = (modelName, envValue) => {
    let indexes = null;
    jest.isolateModules(() => {
      const mongoose = require('mongoose');
      try {
        mongoose.deleteModel(modelName);
      } catch (_) {
        /* 首次加载时不存在，忽略 */
      }
      if (envValue === undefined)
        delete process.env[
          `BUSINESS_RETENTION_DAYS_${modelName.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toUpperCase()}`
        ];
      else
        process.env[
          `BUSINESS_RETENTION_DAYS_${modelName.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toUpperCase()}`
        ] = envValue;
      indexes = require(`../../models/${modelName}`).schema.indexes();
    });
    return indexes;
  };

  test.each([
    ['FireAlarm', 'occurredAt', 'ttl_occurredAt'],
    ['Inspection', 'planStartTime', 'ttl_planStartTime'],
    ['FireDevice', 'createdAt', 'ttl_createdAt'],
  ])('%s：配置 180 天后存在 TTL 索引（字段 %s）', (modelName, field, name) => {
    const indexes = loadSchemaIndexes(modelName, '180');
    const ttl = indexes.find(([, opts]) => opts && opts.name === name);
    expect(ttl).toBeTruthy();
    expect(ttl[0]).toEqual({ [field]: 1 });
    expect(ttl[1].expireAfterSeconds).toBe(180 * 24 * 60 * 60);
  });

  test.each([
    ['FireAlarm', 'ttl_occurredAt'],
    ['Inspection', 'ttl_planStartTime'],
    ['FireDevice', 'ttl_createdAt'],
  ])('%s：未配置开关时不建 TTL（数据永久保留是"未启用"，不是"已合规"）', (modelName, name) => {
    const indexes = loadSchemaIndexes(modelName, undefined);
    expect(indexes.some(([, opts]) => opts && opts.name === name)).toBe(false);
  });

  test('User 永远不建 TTL（删账号会让审计链上的操作者悬空）', () => {
    const indexes = loadSchemaIndexes('User', '180');
    expect(indexes.some(([, opts]) => opts && opts.expireAfterSeconds !== undefined)).toBe(false);
  });
});
