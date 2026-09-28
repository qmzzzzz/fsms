/**
 * 自动编号：并发诞生 vs 计数器丢失，两种"拿到 1 号"必须分得开（plugins/autoIncrement.js）
 *
 * `seq === 1` 这一格同时代表两件事：
 *   ① 本前缀的第一条记录正在被创建（一生一次，且此刻可能还有兄弟在飞）；
 *   ② counters 丢失后计数器被重建（存量里已有大批编号）。
 * 只按"存量最大号 ≥ 我拿到的号"判 ②，①就会误伤：取到 1 号的那条读存量时，
 * 兄弟的 2 号、3 号可能已经落库，于是它判定"计数器坏了"，把计数器往前推 ——
 * 结果是这一批编号**静默跳号**，还留下一条指控 counters/备份恢复的 warn，
 * 把运维的排查方向整个指错。
 *
 * 本文件钉七格：
 *   ① 并发诞生不得跳号、不得留下 warn（把时序做成确定的，不靠概率复现）；
 *   ② 真的丢失计数器时仍必须对齐（防止把"救活"这一半一起关掉）；
 *   ③ 存量恰好只剩一条同号文档那个角落：数值上两种情形重合，仍必须靠"我这个号已被占"救回；
 *   ④ 更狠的一档：计数器被发到 N、存量最大也是 N（并发在飞），"本轮没发放过这么大号"
 *      这条证据彻底失灵，此时必须换成占用证据，否则这一条必撞唯一键、warn 也无从留下；
 *   ⑤ 反过来：存量最大号超出本轮发放、而我手里的小号空着时，必须靠"脱节"续号（编号单调不回退）；
 *   ⑥ 占用探测自身失败时不得静默退回——要留下点名根因的 error；
 *   ⑦ 计数器文档在"读存量之后、推进之前"消失时，对齐必须退回原号——绝不能拿 null 去读
 *      字段，否则一次可恢复的失败会变成写路径上的 TypeError（500）。
 */
const mongoose = require('mongoose');
const logger = require('../../utils/logger');
const autoIncrement = require('../../plugins/autoIncrement');

const PAD = 4;
const PREFIX = 'ZZQ';
const COUNTER_ID = `zzb_birth_${PREFIX}`;
const codeOf = (seq) => `${PREFIX}-${String(seq).padStart(PAD, '0')}`;
const seqOf = (code) => Number(code.slice(PREFIX.length + 1));

const probeSchema = new mongoose.Schema(
  {
    code: { type: String, required: true, unique: true },
    note: String,
  },
  { collection: 'zzb_autoincrement_birth_probe', versionKey: false }
);
probeSchema.plugin(autoIncrement, {
  field: 'code',
  counterPrefix: 'zzb_birth',
  seqPadding: PAD,
  generatePrefix: () => PREFIX,
});

describe('autoIncrement 并发诞生不得被当成计数器丢失', () => {
  let Probe;
  let counters;

  /** 直连写库造存量：绕过插件，才能造出"编号在但计数器不在/或与我拿到的号错位"的状态 */
  const seedCodes = async (codes) => {
    await Probe.collection.insertMany(codes.map((code) => ({ code })));
  };
  const counterSeq = async () => {
    const doc = await counters.findOne({ _id: COUNTER_ID });
    return doc && doc.seq;
  };
  const persistedCodes = async () =>
    (await Probe.find({}).select('code').lean()).map((r) => r.code);

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    Probe = mongoose.model('ZzbAutoIncrementBirthProbe', probeSchema);
    counters = mongoose.connection.db.collection('counters');
    // ③ 那格靠 unique 索引兑现，索引不在它就只是个空话
    await Probe.syncIndexes();
  });

  afterAll(async () => {
    await Probe.deleteMany({}).catch(() => {});
    await counters.deleteMany({ _id: COUNTER_ID }).catch(() => {});
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  beforeEach(async () => {
    await Probe.deleteMany({});
    await counters.deleteMany({ _id: COUNTER_ID });
  });

  test('并发诞生：取到 1 号的那条看见兄弟的 2、3 号后，必须照原号落库且不留 warn', async () => {
    const warn = jest.spyOn(logger, 'warn').mockImplementation(() => {});
    const realAggregate = Probe.aggregate.bind(Probe);
    let injected = false;
    const spy = jest.spyOn(Probe, 'aggregate').mockImplementation(async (...args) => {
      // 在外层那条"读存量"的中途放进两个兄弟：它们各自取号 2、3 并已落库。
      // 这正是本前缀第一批并发记录的真实交错，而不是计数器丢失。
      if (!injected) {
        injected = true;
        await Promise.all([
          Probe.create({ note: 'sibling-2' }),
          Probe.create({ note: 'sibling-3' }),
        ]);
      }
      return realAggregate(...args);
    });
    try {
      const first = await Probe.create({ note: 'me' });
      expect(injected).toBe(true); // 注入点真的被走到（否则本用例只是空转）
      expect(first.code).toBe(codeOf(1));
      expect((await persistedCodes()).sort()).toEqual([codeOf(1), codeOf(2), codeOf(3)]);
      // 计数器没有被往前推：跳号的所有代价都从"推进计数器"这一动作来
      expect(await counterSeq()).toBe(3);
      expect(warn.mock.calls.map((c) => String(c[0])).join('\n')).not.toContain(COUNTER_ID);
    } finally {
      spy.mockRestore();
      warn.mockRestore();
    }
  });

  test('反向对照：计数器真的丢失时仍必须续上存量最大编号，并且留下点名根因的 warn', async () => {
    const warn = jest.spyOn(logger, 'warn').mockImplementation(() => {});
    try {
      await seedCodes([codeOf(1), codeOf(2), codeOf(3)]);
      await counters.deleteMany({ _id: COUNTER_ID });
      const recovered = await Probe.create({ note: 'after-loss' });
      expect(recovered.code).toBe(codeOf(4));
      expect(await counterSeq()).toBe(4);
      const logged = warn.mock.calls.map((c) => String(c[0])).join('\n');
      expect(logged).toContain(COUNTER_ID);
      expect(logged).toContain(codeOf(3));
      expect(logged).toContain(codeOf(4));
    } finally {
      warn.mockRestore();
    }
  });

  test('数值重合的角落：存量恰好只剩一条同号文档时，靠"我这个号已被占"仍然救得回来', async () => {
    await seedCodes([codeOf(1)]);
    await counters.deleteMany({ _id: COUNTER_ID });
    const recovered = await Probe.create({ note: 'overlap' });
    expect(recovered.code).toBe(codeOf(2));
    expect(await counterSeq()).toBe(2);
  });

  test('两条证据数值重合且并发在飞：脱节看不出来时，占用这条必须把创建救回来', async () => {
    const warn = jest.spyOn(logger, 'warn').mockImplementation(() => {});
    const realAggregate = Probe.aggregate.bind(Probe);
    let injected = false;
    const spy = jest.spyOn(Probe, 'aggregate').mockImplementation(async (...args) => {
      if (!injected) {
        injected = true;
        // 上一轮遗留的 0001/0002/0003 就是冲突源：兄弟这次取号成功、落库必撞唯一键
        await Promise.all([
          Probe.create({ note: 'sibling-2' }).catch(() => {}),
          Probe.create({ note: 'sibling-3' }).catch(() => {}),
        ]);
      }
      return realAggregate(...args);
    });
    try {
      await seedCodes([codeOf(1), codeOf(2), codeOf(3)]);
      await counters.deleteMany({ _id: COUNTER_ID });
      const recovered = await Probe.create({ note: 'me' });
      expect(seqOf(recovered.code)).toBeGreaterThan(3);
      expect(warn.mock.calls.map((c) => String(c[0])).join('\n')).toContain(COUNTER_ID);
    } finally {
      spy.mockRestore();
      warn.mockRestore();
    }
  });

  test('编号单调不回退：存量最大号超出本轮发放时，我手里的小号空着也必须续到它之后', async () => {
    const warn = jest.spyOn(logger, 'warn').mockImplementation(() => {});
    try {
      // 故意空着 0001：这时"我这个号已被占"那条证据看不出来，只能靠"脱节"续号。
      // 少了这条，新建记录的编号会比存量里最老的还小 —— 审计上读不成序列。
      await seedCodes([codeOf(2), codeOf(3)]);
      await counters.deleteMany({ _id: COUNTER_ID });
      const created = await Probe.create({ note: 'monotonic' });
      expect(created.code).toBe(codeOf(4));
      expect(await counterSeq()).toBe(4);
      expect(warn.mock.calls.map((c) => String(c[0])).join('\n')).toContain(COUNTER_ID);
    } finally {
      warn.mockRestore();
    }
  });

  test('占用探测失败时不能静默：退回原号交给 unique 索引，但必须留下点名根因的 error', async () => {
    const error = jest.spyOn(logger, 'error').mockImplementation(() => {});
    const realAggregate = Probe.aggregate.bind(Probe);
    let injected = false;
    const spy = jest.spyOn(Probe, 'aggregate').mockImplementation(async (...args) => {
      if (!injected) {
        injected = true;
        await Promise.all([
          Probe.create({ note: 'sibling-2' }).catch(() => {}),
          Probe.create({ note: 'sibling-3' }).catch(() => {}),
        ]);
      }
      return realAggregate(...args);
    });
    const existsSpy = jest.spyOn(Probe, 'exists').mockRejectedValue(new Error('探测必须失败'));
    try {
      await seedCodes([codeOf(1), codeOf(2), codeOf(3)]);
      await counters.deleteMany({ _id: COUNTER_ID });
      let err;
      await Probe.create({ note: 'probe-fails' }).catch((e) => {
        err = e;
      });
      // 探测失败 ⇒ 不对齐 ⇒ 拿到的 1 号确实被占：可重试冲突，而不是无声改写语义
      expect(err && err.code).toBe(11000);
      expect(error.mock.calls.map((c) => String(c[0])).join('\n')).toContain(
        '自动编号占用探测失败'
      );
    } finally {
      existsSpy.mockRestore();
      spy.mockRestore();
      error.mockRestore();
    }
  });

  test('计数器文档在"读存量之后、推进之前"消失：退回原号交给 unique 索引，不得抛 TypeError', async () => {
    const error = jest.spyOn(logger, 'error').mockImplementation(() => {});
    const db = mongoose.connection.db;
    const realCollection = db.collection.bind(db);
    let readCounterThenItVanished = false;
    // 只包 counters 这一个集合：读到了就算"当时还在"，随即删掉它，
    // 复刻"运维清空 counters / 备份恢复中途"与在飞创建交错的真实时序。
    db.collection = (name, ...rest) => {
      const c = realCollection(name, ...rest);
      if (name !== 'counters') return c;
      return {
        findOneAndUpdate: (filter, update, options) => c.findOneAndUpdate(filter, update, options),
        findOne: async (filter, options) => {
          const doc = await c.findOne(filter, options);
          if (doc) {
            readCounterThenItVanished = true;
            // 按 filter 删而不是按 doc._id：那一读带的是 `{ _id: 0, seq: 1 }` 投影，
            // 返回的文档根本没有 _id，拿 doc._id 去删等于什么都没删（用例假绿）。
            await c.deleteOne(filter);
          }
          return doc;
        },
      };
    };
    try {
      await seedCodes([codeOf(1)]);
      await counters.deleteMany({ _id: COUNTER_ID });
      let err;
      await Probe.create({ note: 'counter-vanished' }).catch((e) => {
        err = e;
      });
      // 注入点真的被走到：否则本用例只是在测"什么都没发生"
      expect(readCounterThenItVanished).toBe(true);
      expect(err).toBeTruthy();
      // 判据是"失败形态可归因"：拿到一次可重试的唯一键冲突，而不是读 null 的 TypeError
      expect(err.name).not.toBe('TypeError');
      expect(err.code).toBe(11000);
      expect(error.mock.calls.map((c) => String(c[0])).join('\n')).toContain('计数器文档已不存在');
    } finally {
      delete db.collection;
      error.mockRestore();
    }
  });
});
