/**
 * 布尔型系统配置的取值口径：'false' 不得被读成"开"
 *
 * 三个开关原先都写 `!!doc.value`。`value` 是 Mixed，落库形态不止 boolean：
 * 运维直连库改配置（`$set:{value:'false'}`）是非人类入口里最常见的一种，
 * 而 `'false'` 的非空字符串真值是 true ——
 * **一次想关掉公开注册的操作，反而把公开注册打开了**，且全程没有任何报错。
 * 公开注册 + GUEST 角色是这条链上唯一能被匿名触达的写入面，方向不能错。
 *
 * 同一次复核也确认了 `valueType` 这个"声明了但没人读"的字段，这里只把事实写进 schema 注释，
 * 不虚构保护：`valueType` 由写入侧派生、读取侧不依赖。`modifiable` 已按 Q-4 直接删除——
 * 预留位没有消费方，留着只会被误认为已生效的保护。
 *
 * set() 的并发 upsert（F7，第十一轮）：两个请求同时看到 key 不存在、各自插入，后到者必然撞 {key:1}
 * 唯一索引（E11000）抛错给调用方。修复在 model 内部重试一次（转为普通更新命中对方文档），仍失败再向上抛
 * ——与 IPBlacklist.blockIP / TokenBlacklist.blacklistToken 的既有形态一致。判据见下方「③ set() 的并发 upsert」。
 */
const mongoose = require('mongoose');

describe('SystemConfig 布尔口径', () => {
  let SystemConfig;
  const KEYS = ['allowPublicRegistration', 'loginCaptchaEnabled', 'registerCaptchaEnabled'];
  const snapshot = new Map();

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    SystemConfig = require('../models/SystemConfig');
    for (const key of KEYS) {
      const doc = await SystemConfig.collection.findOne({ key });
      snapshot.set(key, doc);
    }
  });

  afterAll(async () => {
    // 恢复原值：这些 key 被登录/注册相关的其他套件共用，脏值会造成跨文件假红
    for (const key of KEYS) {
      const doc = snapshot.get(key);
      if (doc) {
        await SystemConfig.collection.updateOne({ key }, { $set: { value: doc.value } });
      } else {
        await SystemConfig.collection.deleteOne({ key });
      }
    }
    SystemConfig.invalidateRegistrationCache();
    SystemConfig.invalidateLoginCaptchaCache();
    SystemConfig.invalidateRegisterCaptchaCache();
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  describe('① 纯函数口径（可确定性覆盖全部落库形态）', () => {
    // 注意：不能在 describe 体里解构 SystemConfig.__test —— 那在收集阶段执行，
    // 早于 beforeAll 的 require，拿到的是 undefined。

    test.each([
      ['boolean true', true, false, true],
      ['boolean false', false, true, false],
      ["字符串 'false'（运维直连库的写法）", 'false', true, false],
      ["字符串 'TRUE'（大小写不敏感）", 'TRUE', false, true],
      ["字符串 '1'", '1', false, true],
      ["字符串 '0'", '0', true, false],
      ["带空格的 ' false '", ' false ', true, false],
      ['数字 0', 0, true, false],
      ['数字 1', 1, false, true],
      ['null', null, true, true],
      ['null 且 fallback=false', null, false, false],
      ['空串', '', true, false],
      ['认不出的字符串按 fallback', 'maybe', true, true],
      ['数组按 fallback', ['x'], false, false],
      ['对象按 fallback', { a: 1 }, true, true],
    ])('%s（输入 %p，fallback %p）→ %p', (_label, value, fallback, expected) => {
      const { toConfigBoolean } = SystemConfig.__test;
      expect(toConfigBoolean(value, fallback)).toBe(expected);
    });
  });

  describe('② 端到端：直连库写字符串也能关掉开关', () => {
    const writeRaw = async (key, value) => {
      await SystemConfig.collection.updateOne({ key }, { $set: { value } }, { upsert: true });
      SystemConfig.invalidateRegistrationCache();
      SystemConfig.invalidateLoginCaptchaCache();
      SystemConfig.invalidateRegisterCaptchaCache();
    };

    test("allowPublicRegistration='false' → 公开注册关闭（修复前为 true）", async () => {
      await writeRaw('allowPublicRegistration', 'false');
      expect(await SystemConfig.isRegistrationAllowed()).toBe(false);
    });

    test('反向保护：真 boolean true 仍然打开（收口不得变成永远关）', async () => {
      await writeRaw('allowPublicRegistration', true);
      expect(await SystemConfig.isRegistrationAllowed()).toBe(true);
    });

    test("loginCaptchaEnabled='1' → 验证码开启（同一份口径，不是各写一遍）", async () => {
      await writeRaw('loginCaptchaEnabled', '1');
      expect(await SystemConfig.isLoginCaptchaEnabled()).toBe(true);
      await writeRaw('loginCaptchaEnabled', 'off');
      expect(await SystemConfig.isLoginCaptchaEnabled()).toBe(false);
    });

    test('认不出来的取值必须落到"关"（fail-closed 的方向本身也要可证伪）', async () => {
      // 'maybe' 既不在 truthy 也不在 falsy 词表里：此时唯一正确的兜底方向是关。
      // 若有人把注册开关的 fallback 写成 true，这条会转红——
      // 上面几条用的都是"能识别的取值"，测不到这个分支。
      await writeRaw('allowPublicRegistration', 'maybe');
      expect(await SystemConfig.isRegistrationAllowed()).toBe(false);
      await writeRaw('allowPublicRegistration', { unexpected: 'shape' });
      expect(await SystemConfig.isRegistrationAllowed()).toBe(false);
    });

    test('key 不存在时仍是关（负缓存路径不得因为新口径变成开）', async () => {
      await SystemConfig.collection.deleteOne({ key: 'allowPublicRegistration' });
      SystemConfig.invalidateRegistrationCache();
      expect(await SystemConfig.isRegistrationAllowed()).toBe(false);
    });

    test('经 set() 正常写入后立刻读到新值（缓存失效链没被这次改动破坏）', async () => {
      await SystemConfig.set('allowPublicRegistration', false);
      expect(await SystemConfig.isRegistrationAllowed()).toBe(false);
      await SystemConfig.set('allowPublicRegistration', true);
      expect(await SystemConfig.isRegistrationAllowed()).toBe(true);
    });
  });
  describe('③ set() 的并发 upsert（F7）', () => {
    test('撞唯一索引（E11000）时重试一次，调用方不看到异常', async () => {
      const key = 'zzProbeUpsertRetry';
      await SystemConfig.collection.deleteOne({ key });

      // 确定性复现并发 upsert 的失败形态：两个请求同时看到「key 不存在」，各自插入，
      // 后到者撞 {key:1} 唯一索引抛 E11000。这里把第一次 findOneAndUpdate 钉成抛 11000，
      // 第二次交回真实实现——重试逻辑缺席时 set() 直接 reject（红），有重试时成功（绿）。
      const real = SystemConfig.findOneAndUpdate.bind(SystemConfig);
      const spy = jest
        .spyOn(SystemConfig, 'findOneAndUpdate')
        .mockImplementationOnce(() => {
          const err = new Error('E11000 duplicate key error collection: test.systemconfigs');
          err.code = 11000;
          return Promise.reject(err);
        })
        .mockImplementation((...args) => real(...args));

      try {
        await expect(SystemConfig.set(key, 'retried')).resolves.toBeTruthy();
        expect(spy).toHaveBeenCalledTimes(2);
      } finally {
        spy.mockRestore();
        await SystemConfig.collection.deleteOne({ key });
      }
    });

    test('20 个并发 set 同一 key：都不抛错，且只留一行', async () => {
      const key = 'zzProbeConcurrentSet';
      await SystemConfig.collection.deleteOne({ key });

      const results = await Promise.allSettled(
        Array.from({ length: 20 }, (_, i) => SystemConfig.set(key, 'v' + i))
      );
      const rejected = results.filter((r) => r.status === 'rejected');
      expect(rejected.map((r) => String(r.reason && r.reason.message))).toEqual([]);

      const docs = await SystemConfig.collection.find({ key }).toArray();
      expect(docs).toHaveLength(1);
      expect(docs[0].value).toMatch(/^v\d+$/);

      await SystemConfig.collection.deleteOne({ key });
    });
  });
});
