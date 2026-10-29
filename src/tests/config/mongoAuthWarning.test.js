/**
 * Mongo 认证缺口告警（H-1 的代码侧落点，**只告警不阻断**）
 *
 * 由来：2026-10-29 二轮渗透实证「mongod 未开 auth + 应用连接串无凭据 ⇒ 任何能到达
 * 27017 的对端可读写全库」。同一份配置里 Redis 早有认证闸（collectRedisAuthErrors），
 * Mongo 侧没有——本文件钉住这条缺口**每次启动都会被说出来**。
 *
 * 为什么不是致命闸（这是本文件最容易被改错的一格）：存量部署与开发/预览实例普遍
 * 无凭据直连本机 mongod，做成 fail-closed 等于下一次重启直接停机，而修复动作必须
 * 与运维同步。故第 7 例专门断言"collectTransportErrors 对无凭据 URI 不出错"——
 * 若有人把告警顺手升级成致命闸，这一例会红，从而强制那次升级变成显式决定。
 */
'use strict';

const {
  collectMongoAuthWarnings,
  collectTransportErrors,
} = require('../../config/transportSecurity');

const ENV_KEYS = ['MONGODB_URI', 'MONGODB_AUTH_EXEMPT', 'MONGODB_TLS_EXEMPT', 'REDIS_URL'];

describe('Mongo 认证缺口告警（H-1）', () => {
  let saved;

  beforeEach(() => {
    saved = Object.fromEntries(ENV_KEYS.map((k) => [k, process.env[k]]));
    for (const k of ENV_KEYS) delete process.env[k];
  });

  afterEach(() => {
    for (const k of ENV_KEYS) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  });

  test('无凭据连接串 ⇒ 告警一条，点名 MONGODB_URI 与 27017 的后果', () => {
    process.env.MONGODB_URI = 'mongodb://localhost:27017/fire_safety_db';

    const warnings = collectMongoAuthWarnings();

    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toContain('MONGODB_URI 未携带凭据');
    expect(warnings[0]).toContain('27017');
    expect(warnings[0]).toContain('MONGODB_AUTH_EXEMPT=true');
  });

  test('带 user:pass 的连接串 ⇒ 不告警', () => {
    process.env.MONGODB_URI = 'mongodb://fsms:p%40ss@mongo:27017/fire_safety_db?authSource=admin';

    expect(collectMongoAuthWarnings()).toEqual([]);
  });

  test('mongodb+srv 形态同样按 userinfo 判定', () => {
    process.env.MONGODB_URI = 'mongodb+srv://u:p@cluster0.example.net/db';
    expect(collectMongoAuthWarnings()).toEqual([]);

    process.env.MONGODB_URI = 'mongodb+srv://cluster0.example.net/db';
    expect(collectMongoAuthWarnings()).toHaveLength(1);
  });

  test('只有用户名没有口令 ⇒ 仍告警（驱动按"无口令"处理，未开 auth 的实例照样连得上）', () => {
    process.env.MONGODB_URI = 'mongodb://fsms@mongo:27017/fire_safety_db';

    expect(collectMongoAuthWarnings()).toHaveLength(1);
  });

  test('MONGODB_AUTH_EXEMPT=true ⇒ 豁免（豁免必须显式说出来）', () => {
    process.env.MONGODB_URI = 'mongodb://mongo:27017/fire_safety_db';
    process.env.MONGODB_AUTH_EXEMPT = 'true';

    expect(collectMongoAuthWarnings()).toEqual([]);
  });

  test('完全未设置 MONGODB_URI ⇒ 不产生噪声（缺失由连接层报错，不在这里重复）', () => {
    expect(collectMongoAuthWarnings()).toEqual([]);
  });

  test('只告警不阻断：无凭据但传输合规的 URI 不得进入 collectTransportErrors', () => {
    // 这条是"降级为告警"这个决定的锚点：一旦有人把它改成致命闸，此处转红
    process.env.MONGODB_URI = 'mongodb://prod-server:27017/db?tls=true';
    const errors = [];
    collectTransportErrors(errors);

    expect(errors).toEqual([]);
  });
});
