/**
 * 含 dev 依赖审计门禁（`scripts/check-audit-allowlist.js`）的可证伪性自检。
 *
 * 为什么要这条测试：该脚本是「dev 树 advisory 已全部被看见」这一结论的**唯一依据**。
 * 门禁本身一旦退化成恒绿（判据写错、via 的字符串项被当成根因、清单被塞成通配、
 * 阈值比较反了），CI 会继续全绿而 dev 树可以带任意条高危合并 —— 与它要修的
 * 那个缺陷一模一样。故每条断言都由 mutate 实测确认「改坏必红」。
 *
 * 【为什么真调判据而不是复刻】本仓已有先例（installScriptGate.test.js 的文件头）：
 * 初版把判定语义复刻一份，把真脚本的筛选条件写反后复刻版仍 6/6 全绿。
 * 复刻一份判据等于测试了一个平行实现，与被测对象是否还正确无关。
 *
 * 本套件**不连网、不起子进程**：audit 报告用内存构造的样本注入，
 * 清单读仓内真实文件 ⇒ 判定完全确定，可在任意环境跑。
 *
 * 【变异实测证据（2026-10-09）】对 `evaluate` / `collectRootAdvisories` / `advisoryId`
 * 注入 7 个变异，逐个定向跑本套件对应断言，**7/7 全部转红**：
 *   M1 `!registered.has(a.id)` → 去 `!`；M2 `!gateIds.has(e.id)` → 去 `!`；
 *   M3 `a.rank >= thresholdRank` → `<=`；M4 `e.reviewBy < today` → `<=`；
 *   M5 `advisoryId` 降级为恒返数字 source；M6 最高严重度比较 `>` → `<`；
 *   M7 去掉 `typeof via !== 'object'` 守卫（传递依赖的字符串项被当成根因）。
 * 复跑命令：见 deliverables 留档的 mutation harness（读源码 → 字符串替换 →
 * `new Function` 装载 → 断言同一组期望）。
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..', '..', '..');
const ALLOWLIST = path.join(ROOT, 'deployment', 'audit-allowlist.json');
const SCRIPT = path.join(ROOT, 'scripts', 'check-audit-allowlist.js');

/** 被测对象的真判据（不许在本文件里另写一份） */
const {
  evaluate,
  collectRootAdvisories,
  loadAllowlist,
  advisoryId,
  reconcileReportCounts,
} = require(SCRIPT);
const { spawnSync } = require('child_process');

const allowlist = loadAllowlist(ALLOWLIST);

/**
 * 历史登记形状：两项曾因「上游无补丁」进入清单，2026-10-24 复核时
 * npm audit 已不再报告它们，按判据③从现网清单删除。判据本身仍需这两项做夹具，
 * 否则「过期/陈旧」两条反向用例会退化成空跑。
 */
const HISTORIC_ALLOWLIST = {
  threshold: 'moderate',
  entries: [
    {
      id: 'GHSA-vfj7-8cjw-p6xm',
      reviewBy: '2027-01-31',
      noPatch: true,
      reason: '历史夹具：braces 栈耗尽 DoS，登记时上游无修复版本，用于验证清单判据。',
      reachability: '历史夹具：braces 仅被 jest CLI 与 nodemon ignore 配置使用，非远程可控。',
    },
    {
      id: 'GHSA-hp3w-g68c-fv3c',
      reviewBy: '2027-01-31',
      noPatch: true,
      reason: '历史夹具：sprintf-js 无界精度 DoS，登记时上游无修复版本，用于验证清单判据。',
      reachability: '历史夹具：argparse 仅在 js-yaml CLI 路径加载，jest 运行时不经过该链。',
    },
  ],
};
const TODAY = '2026-10-09';

/** 造一个 audit 报告片段：pkg → via 列表（字符串=传递依赖，对象=根因公告） */
const reportOf = (vulnerabilities) => ({ metadata: { vulnerabilities: {} }, vulnerabilities });

const advisory = (id, pkg, severity) => ({
  source: 1,
  name: pkg,
  dependency: pkg,
  title: `${pkg} injected`,
  url: `https://github.com/advisories/${id}`,
  severity,
  range: '<1.0.0',
});

/** 与 2026-10-09 实测同形的报告：30 high 与 5 moderate 全部只由 2 条根因传染而来 */
const REAL_SHAPE = reportOf({
  braces: { severity: 'high', via: [advisory('GHSA-vfj7-8cjw-p6xm', 'braces', 'high')] },
  micromatch: { severity: 'high', via: ['braces'] },
  chokidar: { severity: 'high', via: ['braces'] },
  nodemon: { severity: 'high', via: ['chokidar'] },
  sprintfjs: {
    severity: 'moderate',
    via: [advisory('GHSA-hp3w-g68c-fv3c', 'sprintf-js', 'moderate')],
  },
  argparse: { severity: 'moderate', via: ['sprintfjs'] },
  'js-yaml': { severity: 'moderate', via: ['argparse'] },
});

const ids = (list) => list.map((x) => x.id);

describe('含 dev 审计门禁：判据可证伪且与允许清单一致', () => {
  test('前提自证：清单读到了、阈值是 moderate、存量项字段完备（清空也合法）', () => {
    expect(allowlist.threshold).toBe('moderate');
    expect(Array.isArray(allowlist.entries)).toBe(true);
    // 登记项必须带理由与可达性判断——只有 id 的清单等于静默放行
    for (const e of allowlist.entries) {
      expect(String(e.reason).length).toBeGreaterThan(80);
      expect(String(e.reachability).length).toBeGreaterThan(40);
      expect(e.noPatch).toBe(true);
    }
  });

  test('根因聚合：一个 advisory 传染出的包只算一条，字符串项（传递依赖）不算根因', () => {
    const roots = collectRootAdvisories(REAL_SHAPE);
    // 7 个受影响包 → 只有 2 条根因。若把字符串项也当根因，这里会变成 7。
    expect(roots).toHaveLength(2);
    expect(ids(roots).sort()).toEqual(['GHSA-hp3w-g68c-fv3c', 'GHSA-vfj7-8cjw-p6xm']);
    // 高严重度排在前（排序判据本身也要可失败）
    expect(roots[0].severity).toBe('high');
  });

  test('正向：历史登记形状的报告通过（未登记 0 / 未过期 / 未陈旧）', () => {
    const r = evaluate({ report: REAL_SHAPE, allowlist: HISTORIC_ALLOWLIST, today: TODAY });
    expect(r.gate).toHaveLength(2);
    expect(r.offenders).toEqual([]);
    expect(r.expired).toEqual([]);
    expect(r.stale).toEqual([]);
  });

  test('现网清单已清空：任何达阈值公告都必须阻断（空清单不等于放行）', () => {
    const r = evaluate({ report: REAL_SHAPE, allowlist, today: TODAY });
    expect(ids(r.offenders).sort()).toEqual(['GHSA-hp3w-g68c-fv3c', 'GHSA-vfj7-8cjw-p6xm']);
  });

  // —— 判据①未登记 ——
  // 变异实测：把 evaluate 里 `!registered.has(a.id)` 的 `!` 去掉，本条必须变红。
  test('反向对照：注入一条未登记公告，判据必须判红（证明不是恒绿）', () => {
    const tampered = reportOf({
      ...REAL_SHAPE.vulnerabilities,
      zzq: { severity: 'high', via: [advisory('GHSA-zzzz-zzzz-zzzz', 'zzq', 'high')] },
    });
    const r = evaluate({ report: tampered, allowlist: HISTORIC_ALLOWLIST, today: TODAY });
    expect(ids(r.offenders)).toEqual(['GHSA-zzzz-zzzz-zzzz']);
  });

  test('反向对照：低于阈值的未登记公告不阻断（否则门禁会永远红）', () => {
    const tampered = reportOf({
      zzq: { severity: 'low', via: [advisory('GHSA-llll-llll-llll', 'zzq', 'low')] },
    });
    const r = evaluate({ report: tampered, allowlist, today: TODAY });
    expect(r.gate).toEqual([]);
    expect(r.offenders).toEqual([]);
    // 但它必须仍被聚合出来（否则"低于阈值"与"读不到"无法区分）
    expect(ids(r.advisories)).toEqual(['GHSA-llll-llll-llll']);
  });

  // —— 判据②已过期 ——
  test('反向对照：清单项过期必须判红（登记不是永久豁免）', () => {
    const r = evaluate({ report: REAL_SHAPE, allowlist: HISTORIC_ALLOWLIST, today: '2027-12-31' });
    expect(ids(r.expired).sort()).toEqual(['GHSA-hp3w-g68c-fv3c', 'GHSA-vfj7-8cjw-p6xm']);
    expect(r.offenders).toEqual([]); // 过期与未登记是两条独立判据
  });

  test('边界：reviewBy 当天不算过期（比较是 < 而不是 <=）', () => {
    const r = evaluate({ report: REAL_SHAPE, allowlist: HISTORIC_ALLOWLIST, today: '2027-01-31' });
    expect(r.expired).toEqual([]);
  });

  // —— 判据③已陈旧 ——
  // 变异实测：把 `!gateIds.has(e.id)` 改成 `gateIds.has(e.id)`，本条必须变红。
  test('反向对照：上游修好后清单未删行必须判红（防清单只增不减）', () => {
    const clean = reportOf({});
    const r = evaluate({ report: clean, allowlist: HISTORIC_ALLOWLIST, today: TODAY });
    expect(ids(r.stale).sort()).toEqual(['GHSA-hp3w-g68c-fv3c', 'GHSA-vfj7-8cjw-p6xm']);
  });

  test('反向对照：公告被降级到阈值以下，登记项同样算陈旧（否则会长期挂着无效豁免）', () => {
    const downgraded = reportOf({
      braces: { severity: 'low', via: [advisory('GHSA-vfj7-8cjw-p6xm', 'braces', 'low')] },
      // 另一条保持原样，用来隔离出「只有被降级的那条算陈旧」
      sprintfjs: {
        severity: 'moderate',
        via: [advisory('GHSA-hp3w-g68c-fv3c', 'sprintf-js', 'moderate')],
      },
    });
    const r = evaluate({ report: downgraded, allowlist: HISTORIC_ALLOWLIST, today: TODAY });
    expect(ids(r.stale)).toEqual(['GHSA-vfj7-8cjw-p6xm']);
    expect(r.offenders).toEqual([]);
  });

  test('id 解析：优先取 url 末段的 GHSA 号，取不到才回退数字 source', () => {
    expect(
      advisoryId({ url: 'https://github.com/advisories/GHSA-aaaa-bbbb-cccc', source: 42 })
    ).toBe('GHSA-aaaa-bbbb-cccc');
    expect(advisoryId({ url: 'https://example.com/x', source: 42 })).toBe('42');
  });

  test('同一 GHSA 命中多包时取最高严重度（防降级绕过阈值）', () => {
    const mixed = reportOf({
      a: { severity: 'high', via: [advisory('GHSA-mmmm-mmmm-mmmm', 'a', 'high')] },
      b: { severity: 'low', via: [advisory('GHSA-mmmm-mmmm-mmmm', 'b', 'low')] },
    });
    const roots = collectRootAdvisories(mixed);
    expect(roots).toHaveLength(1);
    expect(roots[0].severity).toBe('high');
    expect(roots[0].packages.sort()).toEqual(['a', 'b']);
  });

  test('fail-closed：清单缺字段 / 日期格式错必须抛错，不得静默放行', () => {
    const tmp = path.join(ROOT, '.audit-zzq-bad.json');
    const write = (o) => fs.writeFileSync(tmp, JSON.stringify(o));
    try {
      write({ threshold: 'moderate', entries: [{ id: 'GHSA-x', reviewBy: '2027-01-31' }] });
      expect(() => loadAllowlist(tmp)).toThrow(/id\/reason/);
      write({
        threshold: 'moderate',
        entries: [{ id: 'GHSA-x', reason: 'r', reviewBy: '2027/01/31' }],
      });
      expect(() => loadAllowlist(tmp)).toThrow(/YYYY-MM-DD/);
      write({ threshold: 'nope', entries: [] });
      expect(() => loadAllowlist(tmp)).toThrow(/threshold/);
    } finally {
      fs.unlinkSync(tmp);
    }
  });

  // —— 判据④「汇总计数与明细自洽」（2026-10-31 补：报告自称有洞、明细却缺席）——
  // 变异实测：删掉 readReport 里的 `if (!r.consistent)` 整段（或让 reconcileReportCounts
  // 恒返 consistent:true），下面 CLI 两条断言转红（打印「✅ 通过」并退 0）。
  test('自洽判据：汇总计数 > 0 而明细缺席 ⇒ 不一致（本轮实测的假绿形状）', () => {
    const fake = {
      metadata: {
        vulnerabilities: { info: 0, low: 0, moderate: 0, high: 3, critical: 0, total: 3 },
      },
    };
    const r = reconcileReportCounts(fake);
    expect(r.totalCount).toBe(3);
    expect(r.severitySum).toBe(3);
    expect(r.detailCount).toBe(0);
    expect(r.consistent).toBe(false);
    expect(r.detail).toContain('明细条目=0');
  });

  test('自洽判据：真实报告形状必须判为一致（防"一收紧就把正常报告也判红"）', () => {
    expect(
      reconcileReportCounts({ metadata: { vulnerabilities: { total: 0 } }, vulnerabilities: {} })
    ).toMatchObject({ totalCount: 0, severitySum: 0, detailCount: 0, consistent: true });
    const five = {
      metadata: {
        vulnerabilities: { info: 0, low: 5, moderate: 0, high: 0, critical: 0, total: 5 },
      },
      vulnerabilities: { a: {}, b: {}, c: {}, d: {}, e: {} },
    };
    expect(reconcileReportCounts(five)).toMatchObject({
      totalCount: 5,
      severitySum: 5,
      detailCount: 5,
      consistent: true,
    });
    // 明细比计数多/少两个方向都要判不一致，不是只拦缺席
    expect(reconcileReportCounts({ ...five, vulnerabilities: { a: {}, b: {} } }).consistent).toBe(
      false
    );
    expect(
      reconcileReportCounts({
        metadata: { vulnerabilities: { low: 1, total: 1 } },
        vulnerabilities: { a: {}, b: {} },
      }).consistent
    ).toBe(false);
  });

  test('夹具自觉：REAL_SHAPE 是策略样本而非"合法报告"（metadata 计数为空 ⇒ 判不一致）', () => {
    // 这条把判据④的边界写清楚：夹具的 metadata.vulnerabilities 是 {}，明细有 7 个包，
    // 于是它本身就不自洽。故 CLI 段必须自己造一份自洽报告，不能拿夹具直接喂 CLI。
    const r = reconcileReportCounts(REAL_SHAPE);
    expect(r.detailCount).toBe(7);
    expect(r.totalCount).toBe(0);
    expect(r.consistent).toBe(false);
  });

  // 变异实测：把 readReport 的 `if (!allowMissingDetails) throw` 改成无条件 return，
  // 或删掉 run() 里的 `report.detailsAcknowledgedMissing` 分支 ⇒ 下面两条同时红。
  test('CLI：缺明细的报告必须非 0（红先绿后的"红"就是这条）', () => {
    const tmp = path.join(ROOT, '.audit-zzq-missing.json');
    fs.writeFileSync(tmp, JSON.stringify({ metadata: { vulnerabilities: { high: 3, total: 3 } } }));
    try {
      const r = spawnSync(process.execPath, [SCRIPT, '--report', tmp], {
        cwd: ROOT,
        encoding: 'utf8',
      });
      expect(r.status).not.toBe(0);
      expect(r.stderr).toContain('汇总计数与明细对不上');
      // 修复前的形态是这一行；它是反向判据，必须消失
      expect(r.stdout).not.toContain('✅ 含 dev 依赖审计通过');
    } finally {
      fs.unlinkSync(tmp);
    }
  });

  test('CLI：--allow-missing-details 降级也要非 0 并打印 WARN（降级≠通过）', () => {
    // 清单必须用空夹具而非现网文件：本条判的是「降级≠通过」，与现网登记了哪些条目无关。
    // 现网清单非空时，合成报告里没有对应公告 ⇒ 登记项被判「已陈旧」提前返回，
    // 走不到 WARN 分支，测试就会随登记状态漂移而误红（2026-11-03 实测）。
    const tmpAllow = path.join(ROOT, '.audit-zzq-empty-allowlist.json');
    fs.writeFileSync(tmpAllow, JSON.stringify({ threshold: 'moderate', entries: [] }));
    const tmp = path.join(ROOT, '.audit-zzq-missing2.json');
    fs.writeFileSync(tmp, JSON.stringify({ metadata: { vulnerabilities: { high: 3, total: 3 } } }));
    try {
      const r = spawnSync(
        process.execPath,
        [SCRIPT, '--report', tmp, '--allowlist', tmpAllow, '--allow-missing-details'],
        {
          cwd: ROOT,
          encoding: 'utf8',
        }
      );
      expect(r.status).not.toBe(0);
      expect(r.stderr).toContain('WARN: --allow-missing-details');
      expect(r.stdout).toContain('计数自洽：否');
    } finally {
      fs.unlinkSync(tmp);
      fs.unlinkSync(tmpAllow);
    }
  });

  test('CLI：自洽且无洞的真实形状仍判绿（防"堵假绿把真绿也堵了"）', () => {
    // 同上：清单用空夹具——本条判的是「零公告报告必须能绿」，不应随现网登记状态漂移。
    const tmpAllow = path.join(ROOT, '.audit-zzq-empty-allowlist.json');
    fs.writeFileSync(tmpAllow, JSON.stringify({ threshold: 'moderate', entries: [] }));
    const tmp = path.join(ROOT, '.audit-zzq-clean.json');
    fs.writeFileSync(
      tmp,
      JSON.stringify({ metadata: { vulnerabilities: { total: 0 } }, vulnerabilities: {} })
    );
    try {
      const r = spawnSync(process.execPath, [SCRIPT, '--report', tmp, '--allowlist', tmpAllow], {
        cwd: ROOT,
        encoding: 'utf8',
      });
      expect(r.status).toBe(0);
      expect(r.stdout).toContain('✅ 含 dev 依赖审计通过');
      expect(r.stdout).toContain('计数自洽：是');
    } finally {
      fs.unlinkSync(tmp);
      fs.unlinkSync(tmpAllow);
    }
  });

  test('判据本身被 require 时不执行 CLI（否则测试进程会被 process.exit 带走）', () => {
    expect(typeof evaluate).toBe('function');
    expect(typeof loadAllowlist).toBe('function');
  });
});
