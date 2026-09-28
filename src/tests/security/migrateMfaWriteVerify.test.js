/**
 * MFA 密钥轮换脚本的"写没写进去"判据（scripts/migrate-mfa-secret.js）
 *
 * 缺陷形态：迁移循环里
 *   await coll.updateOne({ _id: doc._id }, { $set: { mfaSecret: next } });
 *   migrated += 1;
 * 结果对象被整个丢弃 ⇒ matchedCount=0（并发删除、集合名写错、写关注降级）照样记成
 * "已迁移"。报告说「本次迁移：N」、退出码 0，运维照着脚本头部第 4 步换钥——
 * 那批账户的 mfaSecret 仍是旧钥密文，而 utils/mfaSecret.decryptMfaSecret 解不开时
 * 静默返回空串，症状恰好是本脚本开头要防的那个："验证码总是错"、无显眼报错。
 * 这是"报告了没做到的事"这一类（同 改密假成功 / 解锁假成功）。
 *
 * 判据分工（缺一条就留有假绿空间）：
 * 1. writeAndVerify 的分支表：用注入的假集合把六条分支各自打中，
 *    特别是 matchedCount!==1 —— 旧实现根本不读这个字段，必然漏；
 * 2. 真库端到端：migrateAll 是 runCli 实际调用的那一个函数，所以对它下断言
 *    就是对的脚本本身下断言（含真加解密、真落库、幂等重跑）；
 * 3. 落到调用路径上的拒绝：假集合恒返回 matchedCount=0 ⇒ migrated 必须为 0
 *    且每条都进 failures；配一条对照组（matchedCount=1 ⇒ migrated 必须 > 0），
 *    否则"writeAndVerify 永远返回错误"也能让这一组全绿。
 */

const path = require('path');
const mongoose = require('mongoose');

const SCRIPT = path.resolve(__dirname, '../../../scripts/migrate-mfa-secret.js');
const { migrateAll, writeAndVerify } = require(SCRIPT);
const { AESCipher } = require('../../../src/utils/encryption');
const { ENC_PREFIX } = require('../../../src/utils/mfaSecret');

const OLD_KEY = 'aa'.repeat(32);
const NEW_KEY = 'bb'.repeat(32);
const oldCipher = new AESCipher(OLD_KEY);
const newCipher = new AESCipher(NEW_KEY);

const stamp = `mfa${Date.now()}`.replace(/\D/g, '');
const wrap = (cipher, plain) => ENC_PREFIX + cipher.encrypt(plain);

/** 只喂数据、不碰库的假集合：用来把 writeAndVerify / migrateAll 的每条分支打中 */
function fakeColl(docs, { updateResult, updateThrows } = {}) {
  const stored = new Map(docs.map((d) => [String(d._id), d.mfaSecret]));
  const calls = { updateOne: 0, findOne: 0 };
  return {
    calls,
    stored,
    find: () => ({
      [Symbol.asyncIterator]: async function* iter() {
        for (const d of docs) yield d;
      },
    }),
    updateOne: async (filter, update) => {
      calls.updateOne += 1;
      if (updateThrows) throw new Error(updateThrows);
      const id = String(filter._id);
      if (!stored.has(id)) return { matchedCount: 0, modifiedCount: 0 };
      stored.set(id, update.$set.mfaSecret);
      return updateResult || { matchedCount: 1, modifiedCount: 1 };
    },
    findOne: async (filter) => {
      calls.findOne += 1;
      if (!stored.has(String(filter._id))) return null;
      return { mfaSecret: stored.get(String(filter._id)) };
    },
  };
}

describe('migrate-mfa-secret：写库结果必须被核验，否则不许报"已迁移"', () => {
  describe('writeAndVerify 分支表', () => {
    const doc = { _id: new mongoose.Types.ObjectId(), username: 'u1' };
    const NEXT = wrap(newCipher, 'plain-seed');

    test('演练模式：一个字节都不写，也不算失败', async () => {
      const coll = fakeColl([doc]);
      await expect(writeAndVerify(coll, doc, NEXT, false)).resolves.toBeNull();
      expect(coll.calls.updateOne).toBe(0);
      expect(coll.calls.findOne).toBe(0);
    });

    test('对照组：写命中 + 回读一致 ⇒ null（判据不是"永远拒绝"）', async () => {
      const coll = fakeColl([{ ...doc, mfaSecret: NEXT }]);
      await expect(writeAndVerify(coll, doc, NEXT, true)).resolves.toBeNull();
      expect(coll.calls.updateOne).toBe(1);
      expect(coll.calls.findOne).toBe(1);
    });

    test('matchedCount=0 ⇒ 必须报失败（旧实现根本不看这个字段）', async () => {
      const coll = fakeColl([], { updateResult: { matchedCount: 0, modifiedCount: 0 } });
      const reason = await writeAndVerify(coll, doc, NEXT, true);
      expect(typeof reason).toBe('string');
      expect(reason).toMatch(/matchedCount=0/);
      // 回读根本不该发生：没命中的情况下"库里对不对"无从谈起
      expect(coll.calls.findOne).toBe(0);
    });

    test('回读时文档已消失 ⇒ 报失败', async () => {
      const coll = fakeColl([{ ...doc, mfaSecret: 'placeholder-not-read' }]);
      coll.findOne = async () => null;
      expect(await writeAndVerify(coll, doc, NEXT, true)).toMatch(/文档已不存在/);
    });

    test('落库值与预期密文不一致（被别的写覆盖/序列化走样）⇒ 报失败', async () => {
      const coll = fakeColl([{ ...doc, mfaSecret: 'other' }]);
      coll.findOne = async () => ({ mfaSecret: 'stale-value' });
      expect(await writeAndVerify(coll, doc, NEXT, true)).toMatch(/回读与预期密文不一致/);
    });

    test('updateOne 抛错 ⇒ 折成失败原因，而不是把异常冒出去中断整批', async () => {
      const coll = fakeColl([doc], { updateThrows: 'write concern timeout' });
      expect(await writeAndVerify(coll, doc, NEXT, true)).toMatch(/写入\/回读抛错.*timeout/);
    });
  });

  describe('migrateAll 落到真实集合（真加解密 + 真落库 + 幂等）', () => {
    let coll;
    let ids;

    const seedSamples = async () => {
      await coll.deleteMany({ username: new RegExp(`^zzmfa\\d_${stamp}$`) });
      await coll.insertMany([
        { ...ids[0], mfaSecret: wrap(oldCipher, 'seed-old') }, // 存量旧钥密文
        { ...ids[1], mfaSecret: 'plain-legacy-value' }, // 存量明文
        { ...ids[2], mfaSecret: wrap(newCipher, 'seed-new') }, // 已迁移过
        { ...ids[3], mfaSecret: `${ENC_PREFIX}not-a-real-payload` }, // 新旧钥都解不开
      ]);
    };

    beforeAll(async () => {
      if (mongoose.connection.readyState === 0) await mongoose.connect(process.env.MONGODB_URI);
      coll = mongoose.connection.collection('users');
      ids = [1, 2, 3, 4].map((n) => ({
        _id: new mongoose.Types.ObjectId(),
        username: `zzmfa${n}_${stamp}`,
        email: `zzmfa${n}_${stamp}@example.com`,
      }));
    });

    afterAll(async () => {
      if (coll) await coll.deleteMany({ username: new RegExp(`^zzmfa\\d_${stamp}$`) });
      // 本文件自己 connect 的就要自己收，否则 worker 退不干净（实测会报 force exited）
      if (mongoose.connection.readyState !== 0) await mongoose.disconnect();
    });

    const readBack = async (id) => (await coll.findOne({ _id: id })).mfaSecret;

    // 四条样本原本是**隐式流水线**（前提 → 演练 → APPLY → 幂等重跑，后一条吃前一条的库状态）。
    // `--randomize` 会打乱同一 describe 内的用例顺序 ⇒ 流水线一断就红（实测 seed 20260917 红 4 条）。
    // 改成每条自己播种：断言一字不改，前置状态改为显式自造。
    test('前提自证：四条样本各归一类（否则上面的计数是凑出来的）', async () => {
      await seedSamples();
      expect((await readBack(ids[0]._id)).startsWith(ENC_PREFIX)).toBe(true);
      expect((await readBack(ids[1]._id)).startsWith(ENC_PREFIX)).toBe(false);
      // 新旧钥都解不开 ⇒ "失败 1 条"来自样本本身，而不是脚本判据写错
      const junk = (await readBack(ids[3]._id)).slice(ENC_PREFIX.length);
      expect(() => oldCipher.decrypt(junk)).toThrow();
      expect(() => newCipher.decrypt(junk)).toThrow();
      // 第三条已是新钥密文 ⇒ unchanged 那一格有实据
      expect(newCipher.decrypt((await readBack(ids[2]._id)).slice(ENC_PREFIX.length))).toBe(
        'seed-new'
      );
    });

    test('演练：报告分类计数正确，且库里一个字节都没变', async () => {
      await seedSamples();
      const snapshot = await Promise.all(ids.map((d) => readBack(d._id)));
      const stat = await migrateAll({ coll, oldCipher, newCipher, apply: false });
      // encryptedCount 数的是"带 enc:v1: 前缀"，含已迁移那条（它与 unchanged 不互斥）
      expect(stat).toMatchObject({
        encryptedCount: 3,
        plaintextCount: 1,
        migrated: 2,
        unchanged: 1,
      });
      expect(stat.failures).toHaveLength(1);
      expect(stat.failures[0].username).toBe(ids[3].username);
      const after = await Promise.all(ids.map((d) => readBack(d._id)));
      expect(after).toEqual(snapshot);
    });

    test('APPLY：migrated 计入的每条都真的落库、且新钥解得出原明文', async () => {
      await seedSamples();
      const stat = await migrateAll({ coll, oldCipher, newCipher, apply: true });
      expect(stat.migrated).toBe(2);
      expect(stat.failures).toHaveLength(1);

      expect(newCipher.decrypt((await readBack(ids[0]._id)).slice(ENC_PREFIX.length))).toBe(
        'seed-old'
      );
      expect(newCipher.decrypt((await readBack(ids[1]._id)).slice(ENC_PREFIX.length))).toBe(
        'plain-legacy-value'
      );
      // 未迁移成功的那条必须保持原样（不许被"顺手改写"成更难判断的状态）
      expect(await readBack(ids[3]._id)).toBe(`${ENC_PREFIX}not-a-real-payload`);
      const stillNew = await readBack(ids[2]._id);
      expect(newCipher.decrypt(stillNew.slice(ENC_PREFIX.length))).toBe('seed-new');
    });

    test('幂等重跑：全部已是新钥 ⇒ 零改写、旧钥密文计数归零在"跳过"里', async () => {
      await seedSamples();
      // 自造"已迁移完"的前置状态（原先靠上一条 APPLY 顺手留下，随机化后那条可能还没跑）
      await migrateAll({ coll, oldCipher, newCipher, apply: true });
      const stat = await migrateAll({ coll, oldCipher, newCipher, apply: true });
      expect(stat.migrated).toBe(0);
      expect(stat.unchanged).toBe(3);
      expect(stat.encryptedCount).toBe(4);
      expect(stat.failures).toHaveLength(1);
    });
  });

  test('调用路径上的拒绝：写不进去时 migrated 必须为 0，且每条都进 failures', async () => {
    const docs = [
      { _id: new mongoose.Types.ObjectId(), username: 'a', mfaSecret: wrap(oldCipher, 'sa') },
      { _id: new mongoose.Types.ObjectId(), username: 'b', mfaSecret: wrap(oldCipher, 'sb') },
    ];
    const dead = fakeColl(docs, { updateResult: { matchedCount: 0, modifiedCount: 0 } });
    const stat = await migrateAll({ coll: dead, oldCipher, newCipher, apply: true });
    expect(stat.migrated).toBe(0);
    expect(stat.failures).toHaveLength(2);
    expect(stat.failures.every((f) => /matchedCount=0/.test(f.reason))).toBe(true);

    // 对照组：同一个假集合只要真的命中，就必须计入 migrated —— 否则上面那条
    // 只是"writeAndVerify 永远返回错误"的假绿
    const live = fakeColl(docs, { updateResult: { matchedCount: 1, modifiedCount: 1 } });
    const ok = await migrateAll({ coll: live, oldCipher, newCipher, apply: true });
    expect(ok.migrated).toBe(2);
    expect(ok.failures).toHaveLength(0);
  });
});
