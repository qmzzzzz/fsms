'use strict';

/**
 * （2026-09-19）：scripts/perf/explain-spotcheck.js 的「绿但不设防」契约
 *
 * 原缺陷两条，都属于同一类假绿灯：
 *  1) 脚本从不 require 模型 → 4 个 explain 用例全部抛 MissingSchemaError，
 *     被 catch 打成 [SKIP] 后不计入任何计数 → 输出「结论：全部走索引」；
 *  2) 脚本没有退出码：COLLSCAN 与「一条都没测到」同样以 0 结束，
 *     CI/人工复核读到的都是成功。
 * 本文件锁死：模型必须注册、判定与展示同源、failed 优先于 collscan、退出码可区分三种结局。
 */

const mongoose = require('mongoose');
const spot = require('../../scripts/perf/explain-spotcheck');

const explainWith = (winningPlan) => ({ queryPlanner: { winningPlan } });

describe('explain-spotcheck 退出码契约', () => {
  test('加载脚本即注册全部用例模型（漏 require 的用例不再可能静默跳过）', () => {
    expect(spot.cases).toHaveLength(4);
    spot.cases.forEach((c) => {
      expect(() => mongoose.model(c.model)).not.toThrow();
    });
    // 负向自证：未注册的名字确实抛 MissingSchemaError——否则上面三条断言等于没断言
    expect(() => mongoose.model('NoSuchModel')).toThrow(/hasn't been registered/);
  });

  test('用例把模型名/排序/分页与 executionStats 逐条透传（拼错即测不到目标索引）', async () => {
    const original = mongoose.model;
    const seen = [];
    mongoose.model = (name) => {
      const call = { name };
      seen.push(call);
      const q = {
        find: (f) => {
          call.filter = f;
          return q;
        },
        sort: (s) => {
          call.sort = s;
          return q;
        },
        limit: (n) => {
          call.limit = n;
          return q;
        },
        explain: (verb) => {
          call.verb = verb;
          return Promise.resolve({});
        },
      };
      return q;
    };

    try {
      for (const c of spot.cases) await spot.runCase(c);
    } finally {
      mongoose.model = original;
    }

    expect(seen.map((s) => s.name)).toEqual(['FireAlarm', 'Inspection', 'FireDevice', 'AuditLog']);
    // 与**服务层调用点的 .sort() 逐字段一致**（游标续页的平局裁决要同向，
    // 见 docs/adr/ADR-006-高量级列表游标分页选型.md）：脚本若只排主键，
    // 这里绿、线上却是 COLLSCAN + 跨页漂移，抽查结论与真实查询脱节。
    expect(seen.map((s) => s.sort)).toEqual([
      { occurredAt: -1, _id: -1 },
      { planStartTime: -1, _id: -1 },
      { deviceCode: 1 },
      { timestamp: -1, _id: -1 },
    ]);
    expect(seen.every((s) => s.limit === spot.PAGE_SIZE)).toBe(true);
    expect(seen.every((s) => s.verb === 'executionStats')).toBe(true);
    expect(seen.every((s) => s.limit > 0)).toBe(true);
    // 前提自证：还原生效，mongoose.model 未被测试污染
    expect(mongoose.model).toBe(original);
  });

  test('COLLSCAN 判定与展示的计划串同源（含嵌套/多分支计划）', () => {
    const ix = spot.summarize(explainWith({ stage: 'FETCH', inputStage: { stage: 'IXSCAN' } }));
    expect(ix.hasPlan).toBe(true);
    expect(ix.decidable).toBe(true);
    expect(ix.plan).toBe('FETCH -> IXSCAN');
    expect(ix.isCollScan).toBe(false);

    const nested = spot.summarize(
      explainWith({
        stage: 'SORT',
        inputStage: { stage: 'PROJECTION', inputStage: { stage: 'IXSCAN' } },
      })
    );
    expect(nested.plan).toBe('SORT -> PROJECTION -> IXSCAN');
    expect(nested.decidable).toBe(true);
    expect(nested.isCollScan).toBe(false);

    const bad = spot.summarize(explainWith({ stage: 'SORT', inputStage: { stage: 'COLLSCAN' } }));
    expect(bad.isCollScan).toBe(true);
    expect(bad.decidable).toBe(true);
    expect(bad.plan).toContain('COLLSCAN');

    const branch = spot.summarize(
      explainWith({ stage: 'SORT_MERGE', inputStages: [{ stage: 'IXSCAN' }, { stage: 'IXSCAN' }] })
    );
    expect(branch.plan).toBe('SORT_MERGE -> [IXSCAN, IXSCAN]');
    expect(branch.isCollScan).toBe(false);

    // 内层分支里的 COLLSCAN 也逃不掉（原实现靠 JSON.stringify 侥幸覆盖，此处显式锁定）
    const halfBad = spot.summarize(
      explainWith({
        stage: 'SORT_MERGE',
        inputStages: [{ stage: 'IXSCAN' }, { stage: 'COLLSCAN' }],
      })
    );
    expect(halfBad.isCollScan).toBe(true);
  });

  test('F-63b：EOF 之类的短路计划不可判定，不能读成「走索引」', () => {
    // 实测：索引尚未就绪/集合完全没有索引时，空集合的 explain 直接给 stage='EOF'
    const eof = spot.summarize(explainWith({ stage: 'EOF' }));
    expect(eof.hasPlan).toBe(true);
    expect(eof.decidable).toBe(false);
    expect(eof.isCollScan).toBe(false);
    expect(spot.decideExit({ total: 4, collscan: 0, inconclusive: 4 }).code).toBe(1);
  });

  test('空库上的 IXSCAN 记 0 扫描量：结论成立但要显式提示，别被抄成基线', () => {
    const empty = spot.summarize({
      ...explainWith({ stage: 'LIMIT', inputStage: { stage: 'IXSCAN' } }),
      executionStats: { nReturned: 0, totalKeysExamined: 0, totalDocsExamined: 0 },
    });
    expect(empty.decidable).toBe(true);
    expect(empty.noWork).toBe(true);

    const real = spot.summarize({
      ...explainWith({ stage: 'LIMIT', inputStage: { stage: 'IXSCAN' } }),
      executionStats: { nReturned: 20, totalKeysExamined: 20, totalDocsExamined: 20 },
    });
    expect(real.noWork).toBe(false);

    const v = spot.decideExit({ total: 4, collscan: 0, inconclusive: 0, zeroTouch: 4 });
    expect(v.code).toBe(0);
    expect(v.note).toContain('4/4');
    expect(v.note).toContain('勿抄进基线表');
    // 有数据时不许印这句（否则提示会被读成常态噪音）
    expect(spot.decideExit({ total: 4, collscan: 0, inconclusive: 0, zeroTouch: 0 }).note).toBe('');
  });

  test('拿不到 winningPlan 记为「未测到」而不是「没有 COLLSCAN」', () => {
    const empty = spot.summarize({});
    expect(empty.hasPlan).toBe(false);
    expect(empty.decidable).toBe(false);
    expect(empty.plan).toBe('UNKNOWN');
    expect(empty.isCollScan).toBe(false);

    const nullish = spot.summarize(explainWith(undefined));
    expect(nullish.hasPlan).toBe(false);

    // 原实现在此处会 JSON.stringify(undefined) → undefined.includes 抛错，
    // 且抛错同样被当成可忽略的 [SKIP]
    expect(() => spot.summarize(explainWith(undefined))).not.toThrow();
  });

  test('decideExit：不可判定优先于 COLLSCAN，且「全部走索引」只在零不可判定零 COLLSCAN 时出现', () => {
    const clean = spot.decideExit({ total: 4, collscan: 0, inconclusive: 0 });
    expect(clean.code).toBe(0);
    expect(clean.line).toContain('4/4 个查询全部走索引');

    const scan = spot.decideExit({ total: 4, collscan: 2, inconclusive: 0 });
    expect(scan.code).toBe(1);
    expect(scan.line).toContain('2/4 个查询存在 COLLSCAN');
    expect(scan.line).toContain('需补索引后复测');

    // 核心回归：全部用例没跑成时，措辞与退出码都必须翻红
    const allSkipped = spot.decideExit({ total: 4, collscan: 0, inconclusive: 4 });
    expect(allSkipped.code).toBe(1);
    expect(allSkipped.line).toContain('4/4 个用例未取得可判定的执行计划');
    expect(allSkipped.line).not.toContain('全部走索引');

    // 部分跑成也不算通过（旧实现里坏一半仍报「全部走索引」）
    expect(spot.decideExit({ total: 4, collscan: 0, inconclusive: 1 }).code).toBe(1);
    // 既没测准又发现 COLLSCAN：先报「抽查无效」，不给出「补索引后复测」这种承认结论有效的措辞
    expect(spot.decideExit({ total: 4, collscan: 1, inconclusive: 1 }).line).toContain(
      '本次抽查无效'
    );
    // 可操作性：提示造数，而不是让人去猜为什么没结论
    expect(allSkipped.line).toContain('10k');
  });

  test('缺 MONGODB_URI 时 main 直接抛出，且不会去连接', async () => {
    const saved = process.env.MONGODB_URI;
    delete process.env.MONGODB_URI;
    try {
      await expect(spot.main()).rejects.toThrow(/缺少 MONGODB_URI/);
    } finally {
      if (saved === undefined) delete process.env.MONGODB_URI;
      else process.env.MONGODB_URI = saved;
    }
    expect(mongoose.connection.readyState).toBe(0);
  });
});
