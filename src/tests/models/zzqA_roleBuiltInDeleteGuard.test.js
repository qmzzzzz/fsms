/**
 * ─────────────────────────────────────────────────────────────────────────
 * 被测对象：Role.js 的内置角色删除护栏（protectBuiltInRole + protectBuiltInRoleBulk）
 *
 * 本文件的由来（F-115，2026-09-24）：一条子 agent 结论称"mongoose 8 里 schema.pre('deleteOne')
 * 只注册为 query 中间件，因此 doc.deleteOne() 会绕过护栏"。实测**证伪**：文档级 deleteOne()
 * 内部仍构造 Query 并走 query 前置钩子 ⇒ 被拦；而 Document#remove 在 mongoose 8 已不存在。
 *
 * 同一轮实测出的**真实缺口**（本文件连同修复一起钉住）：
 *   Model.bulkWrite([{deleteOne|deleteMany}]) 原先不经过任何护栏 ⇒ 内置角色可被批量写删掉。
 *   钩子签名实测为 (next, operations, options)——operations 是第二个实参，
 *   所以"看清过滤器再决定"的 bulkWrite 护栏是可实现的（已实现于 Role.js）。
 *
 * 为什么每条都用 expect 而不是只 console 一下：护栏一旦因 mongoose 升级或误删挂载而静默失效，
 * 内置角色就能被删——那是 RBAC 的地基。本文件的作用是把"覆盖了哪几个删除入口"从注释里的
 * 断言变成机器判据。
 *
 * 仍不经 ODM 护栏的入口（不在此断言，别以为都在这里测了）：原生驱动
 * collection.deleteMany（全仓仅 scripts/resign-audit-chain-v3.js / run-rollback-drill.js 用，
 * 且都不动 roles）。
 * ─────────────────────────────────────────────────────────────────────────
 */

const mongoose = require('mongoose');

describe('内置角色删除护栏：覆盖的删除入口逐个钉住', () => {
  let Role;
  let stamp;
  let builtIn;
  let custom;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    Role = require('../../models/Role');
    stamp = Date.now();
    builtIn = await Role.create({
      name: `zz护栏内置${stamp}`,
      code: `ZZ_BUILTIN_${stamp}`,
      isBuiltIn: true,
    });
    custom = await Role.create({
      name: `zz护栏自建${stamp}`,
      code: `ZZ_CUSTOM_${stamp}`,
      isBuiltIn: false,
    });
  });

  afterAll(async () => {
    // 护栏会连清理一起挡住（内置角色的删除必抛），所以清理走原生驱动，与护栏语义无关
    await mongoose.connection
      .collection('roles')
      .deleteMany({ _id: { $in: [builtIn._id, custom._id] } });
    if (mongoose.connection.readyState !== 0) await mongoose.connection.close();
  });

  const stillExists = async (_id) => !!(await Role.findById(_id).lean());

  describe('内置角色：每一种删除写法都必须被拦，且记录必须还在', () => {
    const cases = [
      ['Model.deleteOne(filter)', (r) => Role.deleteOne({ _id: r._id })],
      ['Model.deleteMany({_id})', (r) => Role.deleteMany({ _id: r._id })],
      ['Model.findByIdAndDelete(id)', (r) => Role.findByIdAndDelete(r._id)],
      ['Model.findOneAndDelete({_id})', (r) => Role.findOneAndDelete({ _id: r._id })],
      ['query.deleteOne()', (r) => Role.find({ _id: r._id }).deleteOne()],
      ['doc.deleteOne()  [文档级]', (r) => Role.findById(r._id).then((d) => d.deleteOne())],
      [
        'bulkWrite([{deleteOne}])',
        (r) => Role.bulkWrite([{ deleteOne: { filter: { _id: r._id } } }]),
      ],
      [
        'bulkWrite([{deleteMany}])',
        (r) => Role.bulkWrite([{ deleteMany: { filter: { _id: r._id } } }]),
      ],
      [
        'bulkWrite 混合批量（updateOne + deleteOne）',
        (r) =>
          Role.bulkWrite([
            { updateOne: { filter: { _id: r._id }, update: { $set: { level: 3 } } } },
            { deleteOne: { filter: { _id: r._id } } },
          ]),
      ],
      ['bulkWrite 无过滤器的全表删除', () => Role.bulkWrite([{ deleteMany: { filter: {} } }])],
      [
        'bulkWrite 多过滤器（$or 合并，任一命中内置即拒）',
        (r) =>
          Role.bulkWrite([
            { deleteOne: { filter: { _id: custom._id } } },
            { deleteOne: { filter: { _id: r._id } } },
          ]),
      ],
    ];

    test.each(cases)('%s 被拦', async (_label, fn) => {
      await expect(fn(builtIn)).rejects.toThrow(/内置角色不可删除/);
      expect(await stillExists(builtIn._id)).toBe(true);
    });

    test('钩子签名实测：pre(bulkWrite) 的第二实参就是 operations（护栏可实现的依据）', async () => {
      const seen = [];
      const s = new mongoose.Schema({ n: Number }, { collection: 'zzbulksig' });
      s.pre('bulkWrite', function (next, ops, options) {
        seen.push({
          thisIsModel: typeof this.modelName === 'string',
          nextIsFn: typeof next === 'function',
          opsIsArray: Array.isArray(ops),
          opsKeys: (ops || []).map((o) => Object.keys(o).join('+')),
          optionsType: typeof options,
        });
        next();
      });
      const M = mongoose.model('ZzBulkSig', s);
      await M.bulkWrite([{ deleteOne: { filter: { n: 1 } } }]);
      expect(seen).toHaveLength(1);
      expect(seen[0]).toEqual({
        thisIsModel: true,
        nextIsFn: true,
        opsIsArray: true,
        opsKeys: ['deleteOne'],
        optionsType: 'object',
      });
      await mongoose.connection.collection('zzbulksig').deleteMany({});
    });

    test('Document#remove 在 mongoose 8 已不存在（不必为它设防）', () => {
      expect(typeof builtIn.remove).toBe('undefined');
    });

    // 上一版这里写的是「findOneAndRemove 若存在则必须与 findOneAndDelete 同被拦」，
    // 但 mongoose 8.24.1 上 Model.findOneAndRemove 与 Query.prototype.findOneAndRemove
    // **都不存在**（2026-09-25 用 node 直接探得），于是那条用例的 if 恒真、真正的判据
    // 永不执行——它断的是驱动版本，不是本仓护栏。改成"枚举驱动实际暴露的删除入口，
    // 与护栏清单逐一对账"：驱动将来加回 remove/findOneAndRemove 或另起新名，这条立刻红。
    const PINNED_DELETE_SURFACE = [
      'deleteMany',
      'deleteOne',
      'findByIdAndDelete',
      'findOneAndDelete',
    ];
    // EventEmitter 继承来的两个 remove* 不是数据删除入口，按名字排除而不是按语义猜
    const EVENT_EMITTER_NOISE = ['removeAllListeners', 'removeListener'];

    const deleteNamesOf = (obj) => {
      const names = new Set();
      let cursor = obj;
      while (cursor && cursor !== Function.prototype && cursor !== Object.prototype) {
        for (const key of Object.getOwnPropertyNames(cursor)) {
          if (key.startsWith('_') || EVENT_EMITTER_NOISE.includes(key)) continue;
          let isFn = false;
          try {
            isFn = typeof obj[key] === 'function';
          } catch (_) {
            /* 取值抛错的属性（需要实参的 getter 等）：不当删除入口 */
          }
          if (isFn && /delete|remove/i.test(key)) names.add(key);
        }
        cursor = Object.getPrototypeOf(cursor);
      }
      return [...names].sort();
    };

    test('ODM 删除入口清单与驱动实际暴露的方法一致（新增删除面必须先补护栏）', () => {
      expect(deleteNamesOf(Role)).toEqual(PINNED_DELETE_SURFACE);
      expect(deleteNamesOf(Role.find())).toEqual(PINNED_DELETE_SURFACE);
      // 枚举器本身不许"扫了个空"：扫不到任何删除方法时上面两条也会红，这里再自证一次
      expect(deleteNamesOf(Role).length).toBeGreaterThan(0);
    });
  });

  describe('非内置角色与正常批量写：护栏不得顺手挡掉（挡住了就是启动路径回归）', () => {
    const cases = [
      ['Model.deleteOne(filter)', (r) => Role.deleteOne({ _id: r._id })],
      ['Model.findByIdAndDelete(id)', (r) => Role.findByIdAndDelete(r._id)],
      ['doc.deleteOne()  [文档级]', (r) => Role.findById(r._id).then((d) => d.deleteOne())],
      [
        'bulkWrite([{deleteOne}])',
        (r) => Role.bulkWrite([{ deleteOne: { filter: { _id: r._id } } }]),
      ],
    ];

    // 每条自己造一个临时角色、自己确认"删掉了"，不依赖上一条的残留状态
    test.each(cases)('%s 放行', async (_label, fn) => {
      const tag = Math.random().toString(36).slice(2, 8);
      const tmp = await Role.create({
        name: `zz临时${stamp}${tag}`,
        code: `ZZ_TMP_${stamp}_${tag}`,
        isBuiltIn: false,
      });
      await fn(tmp);
      expect(await stillExists(tmp._id)).toBe(false);
    });

    test('纯 updateOne 的 bulkWrite 放行（initData 对账/授权批量写就是这一形）', async () => {
      const r = await Role.create({
        name: `zz对账${stamp}`,
        code: `ZZ_REC_${stamp}`,
        isBuiltIn: false,
        level: 2,
      });
      await Role.bulkWrite([
        { updateOne: { filter: { _id: r._id }, update: { $set: { level: 5 } } } },
        { updateOne: { filter: { _id: r._id }, update: { $set: { description: 'reconciled' } } } },
      ]);
      const after = await Role.findById(r._id).lean();
      expect(after.level).toBe(5);
      await mongoose.connection.collection('roles').deleteMany({ _id: r._id });
    });
  });

  test('护栏判据是 isBuiltIn，而内置编码经 pre-save 自动置真（两半都在护范围内）', async () => {
    // code 上有唯一索引，全量跑时 initData 可能已经建过 USER：存在就复用，不存在才新建。
    // 两种情况下判据一致——内置编码落库时必须带 isBuiltIn=true
    const existing = await Role.findOne({ code: 'USER' }).lean();
    const doc = existing || (await Role.create({ name: `zzUSER映射${stamp}`, code: 'USER' }));
    expect(doc.isBuiltIn).toBe(true);
    await expect(Role.deleteOne({ _id: doc._id })).rejects.toThrow(/内置角色不可删除/);
    if (!existing) await mongoose.connection.collection('roles').deleteMany({ _id: doc._id });
  });
});
