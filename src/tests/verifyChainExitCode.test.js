/**
 * `scripts/verify-audit-chain.js` 的退出码语义（不能把"没验完"报成"链是好的"）
 *
 * 原实现只要 `breaks===0` 就 `exit 0`，而头注释写着"0 = 完整"。两处让它实际不完整：
 *  - 命中 maxRecords 上限（只看了一个窗口，其余没验）；
 *  - 未配置 HMAC_SECRET —— 按 auditChainVerify 自己的头注释，无密钥 SHA-256
 *    可被"有 DB 写权限者整条链重算"，hmac 才是唯一真正的防线；跳过它却退 0，
 *    等于 deployment/secret-rotation.md 里"预期零失配"那一步走的是假绿。
 * 另外 `--limit=abc` 经 parseInt 得 NaN ⇒ falsy ⇒ 静默退回默认上限；
 * 未知参数（`--limitt=1`）被 parseArgs 直接跳过 —— 都是"参数没生效但看起来生效"。
 *
 * 本文件真跑子进程验退出码，尤其验**豁免的边界**：
 * --allow-no-hmac 只能豁免 hmac，不得把截断一起放过（这是修 时最容易写错的一行）。
 * 全程用测试库（HMAC_SECRET 由 setup.js 注入），不需要外部 MongoDB。
 */

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const mongoose = require('mongoose');

const ROOT = path.resolve(__dirname, '../..');
const CLI = path.join(ROOT, 'scripts/verify-audit-chain.js');
const NODE = process.execPath;
const TAG = 'zzverifyExit';

const AuditLog = require('../models/AuditLog');

const runCli = (args = [], envOverride = {}) => {
  const r = spawnSync(NODE, [CLI, ...args], {
    cwd: ROOT,
    encoding: 'utf8',
    timeout: 60000,
    env: { ...process.env, ...envOverride },
  });
  // stdout 是 JSON 报告，stderr 是告警/错误；断言时分开用，避免把两路拼起来再猜边界
  return {
    code: r.status,
    stdout: r.stdout || '',
    out: `${r.stdout || ''}${r.stderr || ''}`,
  };
};

const mkDoc = (i) => ({
  action: 'device_export',
  category: 'system',
  username: `${TAG}_${i}`,
  ip: '10.7.7.7',
  method: 'GET',
  path: `/api/devices/export?i=${i}`,
  success: true,
});

/**
 * 判据调用点的静态枚举 —— "回传全字段"门禁的取证面
 *
 * 为什么要枚举而不是点名文件：点名清单默认"调用方是固定的那几个"，而 2026-10-03
 * 实测的两个漏传（verify-audit-chain.js 与 resign-audit-chain-v3.js 都少传
 * hashComputeFailed，导致链尾有不可追认记录时 CLI 打 PASS 退 0）恰恰都在
 * **已有清单里**；判据的 JSDoc 当时还写着"唯一漏传路径是旧调用方"。
 * 清单管不住"新字段 × 旧调用方"，枚举管得住。
 *
 * 判据对缺 hashComputeFailed 的调用按 0 处理（不像 scanned/legacy 那样 fail-closed，
 * 理由见 auditChainVerify.hasUnattestableGapOf），所以这条枚举是该缺口的唯一防线。
 * 残留上限：`computeChainVerdict(外部对象)` 这种形态看不到字段，这里按"该文件没有
 * 字面量调用"处理并点名——要求调用点以字面量写出，正是让本门禁看得见。
 */
const VERDICT_CALL_RE = /(?:computeChainVerdict|computeVerdict)\s*\(\s*\{/g;
const VERDICT_ANY_CALL_RE = /(?:computeChainVerdict|computeVerdict)\s*\(/;
const FORWARDED_FIELDS = ['scanned', 'hashComputeFailed'];

/** 取出 `xxx({ … })` 调用的对象字面量本体（花括号深度配对） */
const literalCallBodies = (code) => {
  const bodies = [];
  for (const m of code.matchAll(VERDICT_CALL_RE)) {
    const start = code.indexOf('{', m.index);
    let depth = 0;
    for (let i = start; i < code.length; i += 1) {
      if (code[i] === '{') depth += 1;
      else if (code[i] === '}' && (depth -= 1) === 0) {
        bodies.push(code.slice(start, i + 1));
        break;
      }
    }
  }
  return bodies;
};

/** src/（不含 src/tests/）+ scripts/ 下所有 .js，按相对路径归一化 */
const readVerdictCallers = () => {
  const walk = (dir, acc) => {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      const p = path.join(dir, e.name);
      if (e.isDirectory()) {
        if (p === path.join(ROOT, 'src', 'tests')) continue;
        walk(p, acc);
      } else if (e.name.endsWith('.js')) {
        const code = fs.readFileSync(p, 'utf8');
        if (VERDICT_ANY_CALL_RE.test(code)) acc[path.relative(ROOT, p).replace(/\\/g, '/')] = code;
      }
    }
    return acc;
  };
  return { ...walk(path.join(ROOT, 'src'), {}), ...walk(path.join(ROOT, 'scripts'), {}) };
};

const verdictCallOffenders = (sources) => {
  const out = [];
  for (const [rel, code] of Object.entries(sources)) {
    const bodies = literalCallBodies(code);
    if (bodies.length === 0) {
      out.push(`${rel}：调用判据却没有一处字面量对象，回传内容静态不可见`);
      continue;
    }
    for (const body of bodies) {
      for (const field of FORWARDED_FIELDS) {
        if (!new RegExp(`${field}\\s*:`).test(body)) {
          out.push(`${rel}：判据调用少传 ${field}`);
        }
      }
    }
  }
  return out;
};

describe('完整性判据只有一份实现', () => {
  /** 任何"跑链核验"的脚本都必须把结论交给 computeChainVerdict */
  const offenders = (sources) =>
    Object.entries(sources)
      .filter(([, code]) => /verifyAuditChain\(/.test(code) && !/computeChainVerdict/.test(code))
      .map(([name]) => name);

  test('scripts/ 下调用 verifyAuditChain 的脚本一律委托判据（不得自行重写）', () => {
    const dir = path.join(ROOT, 'scripts');
    const sources = {};
    for (const f of fs.readdirSync(dir)) {
      if (f.endsWith('.js')) sources[f] = fs.readFileSync(path.join(dir, f), 'utf8');
    }
    // 前提自证：抽到的源码里确实有调用方，否则这条断言是空转
    const callers = Object.entries(sources).filter(([, code]) => /verifyAuditChain\(/.test(code));
    expect(callers.length).toBeGreaterThanOrEqual(2);
    expect(offenders(sources)).toEqual([]);
  });

  test('反向前提：自己重写判据的脚本会被抓出（防空集恒绿）', () => {
    expect(
      offenders({
        'fake-resign.js':
          'const r = await verifyAuditChain(M);\nprocess.exit(r.breaks === 0 ? 0 : 1);\n',
      })
    ).toEqual(['fake-resign.js']);
    // 没跑核验的脚本不该被误伤
    expect(offenders({ 'other.js': 'console.log(1);\n' })).toEqual([]);
  });
});

describe('判据调用方必须把报告字段回传全', () => {
  test('全仓枚举：每个判据调用点都回传 scanned 与 hashComputeFailed', () => {
    const sources = readVerdictCallers();
    const sites = Object.values(sources).reduce((n, c) => n + literalCallBodies(c).length, 0);
    // 前提自证：在线接口 + 周期核验 + 两个运维脚本，少一个说明枚举没跑起来
    expect(sites).toBeGreaterThanOrEqual(4);
    expect(verdictCallOffenders(sources)).toEqual([]);
  });

  test('反向前提：少传字段与"外部对象调用"都会被点名（防空集恒绿）', () => {
    const okBody =
      'computeChainVerdict({ breaks: 0, scanned: r.scanned, hashComputeFailed: r.hashComputeFailed })';
    expect(verdictCallOffenders({ 'ok.js': okBody })).toEqual([]);

    expect(
      verdictCallOffenders({
        'gap.js': 'computeChainVerdict({ breaks: 0, scanned: r.scanned })',
      })
    ).toEqual(['gap.js：判据调用少传 hashComputeFailed']);

    expect(
      verdictCallOffenders({
        'scope.js': 'computeChainVerdict({ breaks: 0, hashComputeFailed: r.hashComputeFailed })',
      })
    ).toEqual(['scope.js：判据调用少传 scanned']);

    // 同一文件里第二个调用点漏传也要抓到（整文件正则匹配会放过它）
    expect(
      verdictCallOffenders({
        'two.js': `computeVerdict({ scanned: r.scanned, hashComputeFailed: r.hashComputeFailed });
computeChainVerdict({ scanned: r.scanned });`,
      })
    ).toEqual(['two.js：判据调用少传 hashComputeFailed']);

    // 非字面量调用看不到字段 ⇒ 点名（而不是静默跳过）
    expect(
      verdictCallOffenders({ 'wrap.js': 'function f(p){ return computeChainVerdict(p); }' })
    ).toEqual(['wrap.js：调用判据却没有一处字面量对象，回传内容静态不可见']);
  });
});

describe('verify-audit-chain 退出码', () => {
  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    await AuditLog.deleteMany({ username: new RegExp(`^${TAG}_`) }, { bypassAppendOnly: true });
    // 经真实写入路径建 3 条（pre-save 会串链并签 hmac）；不用 insertMany 以免绕过哈希层
    for (let i = 0; i < 3; i += 1) await AuditLog.create(mkDoc(i));
  }, 30000);

  afterAll(async () => {
    await AuditLog.deleteMany({ username: new RegExp(`^${TAG}_`) }, { bypassAppendOnly: true });
    if (mongoose.connection.readyState !== 0) await mongoose.connection.close();
  });

  test('全量、无断裂、hmac 已校验 ⇒ exit 0 且 VERDICT PASS', () => {
    const { code, out } = runCli([]);
    expect(out).toContain('VERDICT: PASS');
    expect(code).toBe(0);
  });

  test('命中 maxRecords 上限（窗口没覆盖全表）⇒ exit 2 并说明只覆盖了多少', () => {
    const { code, out } = runCli(['--limit=1']);
    expect(code).toBe(2);
    expect(out).toContain('INCOMPLETE');
    expect(out).toMatch(/仅覆盖 1\/\d+/);
    // 关键：绝不能既报"不完整"又给 PASS
    expect(out).not.toContain('VERDICT: PASS');
  });

  test('本机环境前提：配置里确有 HMAC 密钥 ⇒ 报告 hmacChecked=true 且判 0', () => {
    const { code, stdout } = runCli([]);
    const report = JSON.parse(stdout.slice(stdout.indexOf('{'), stdout.lastIndexOf('}') + 1));
    expect(report.hmacChecked).toBe(true);
    expect(code).toBe(0);
  });

  // 灭迹现场的真实形态：脚本对着一个空集合跑（这里用同实例的另一个空库模拟，
  // 不动本文件已种下的 3 条）。旧实现在这一格退 0 并打印 PASS —— 也就是
  // "绕过 ODM 钩子直连 deleteMany({}) 清空审计"能拿到校验器签发的合格证明。
  test('CLI 端到端：空集合 ⇒ exit 2 且绝不出现 PASS；--allow-empty 才放行', () => {
    const emptyUri = `${process.env.MONGODB_URI.replace(/\/[^/?]*$/, '')}/zz_empty_chain_${TAG}`;
    const blocked = runCli([], { MONGODB_URI: emptyUri });
    expect(blocked.code).toBe(2);
    expect(blocked.out).toContain('INCOMPLETE');
    expect(blocked.out).toMatch(/审计集合为空/);
    expect(blocked.out).not.toContain('VERDICT: PASS');

    const waived = runCli(['--allow-empty'], { MONGODB_URI: emptyUri });
    expect({ code: waived.code, pass: waived.out.includes('VERDICT: PASS') }).toEqual({
      code: 0,
      pass: true,
    });
  });

  test('豁免的边界（CLI 侧）：--allow-no-hmac 不得把"截断"一起放过', () => {
    const { code, out } = runCli(['--limit=1', '--allow-no-hmac']);
    expect(code).toBe(2);
    expect(out).toContain('INCOMPLETE');
    expect(out).toMatch(/仅覆盖 1\/\d+/);
  });

  test('参数写错不得静默按默认跑', () => {
    const cases = [
      [['--limit=abc'], /--limit 必须是正整数/],
      [['--limit=0'], /--limit 必须是正整数/],
      [['--limitt=1'], /不支持的选项/],
      [['位置参数也不放过'], /无法识别的参数/],
      [['--from=middle'], /--from 只能是 latest 或 earliest/],
    ];
    for (const [args, expectMsg] of cases) {
      const { code, out } = runCli(args);
      expect(out).toMatch(expectMsg);
      expect(code).not.toBe(0); // 绝不能"看起来验过了"
    }
  });

  describe('computeVerdict 真值表（不依赖本机是否配了 HMAC）', () => {
    const { computeVerdict } = require(path.join(ROOT, 'scripts/verify-audit-chain.js'));
    /**
     * 默认补一份"全量、无 filter"的扫描口径：判据对**缺 scanned** 的调用按局部校验处理
     * （fail-closed），真值表要验的是各条否决本身，不是"漏传参数"那一格——
     * 那一格有专门用例（见下面「缺口径即否决」）。
     *
     * `legacy: 0` 同理（2026-09-26 追加）：判据对**缺 legacy** 的调用按"整窗无哈希"处理
     * （同向 fail-closed），而本真值表的默认现场是"全量扫过、记录都带 hash"，
     * 所以默认口径里 legacy 必须是 0；`nothingHashed` 那一格另有专门用例。
     */
    const V = (o) => {
      const args = {
        breaks: 0,
        total: 3,
        maxRecords: 200000,
        collectionTotal: 3,
        hmacChecked: true,
        legacy: 0,
        allowNoHmac: false,
        allowEmpty: false,
        allowAllLegacy: false,
        ...o,
      };
      return computeVerdict({
        scanned: { maxRecords: args.maxRecords, fromLatest: true, filter: {} },
        ...args,
      });
    };
    /** 绕过 V 的默认口径，直接构造"调用方没回传 scanned"的现场 */
    const VnoScope = (o) =>
      computeVerdict({
        breaks: 0,
        total: 3,
        maxRecords: 200000,
        collectionTotal: 3,
        hmacChecked: true,
        legacy: 0,
        ...o,
      });

    test('全量 + 无断裂 + hmac 已校验 ⇒ 0', () => expect(V({}).code).toBe(0));
    test('有断裂优先于一切 ⇒ 1（即便同时截断/无 hmac）', () =>
      expect(
        V({ breaks: 2, total: 5, maxRecords: 5, collectionTotal: 9, hmacChecked: false }).code
      ).toBe(1));
    test('窗口没覆盖全表 ⇒ 2', () => {
      const r = V({ total: 5, maxRecords: 5, collectionTotal: 9 });
      expect(r.code).toBe(2);
      expect(r.truncated).toBe(true);
      expect(r.reasons.join('')).toMatch(/仅覆盖 5\/9/);
    });
    test('hmac 未校验 ⇒ 2；--allow-no-hmac 可豁免 ⇒ 0', () => {
      expect(V({ hmacChecked: false }).code).toBe(2);
      expect(V({ hmacChecked: false, allowNoHmac: true }).code).toBe(0);
    });

    // ★ 灭迹即通过的那一格：集合空 + 无断裂 + hmac 正常，旧实现退 0 并打印
    //   「PASS（全量、无断裂、hmac 已校验）」——直连驱动 deleteMany({}) 绕过模型钩子
    //   就能得到这个现场，校验器反而为篡改背书。
    test('集合为空 ⇒ 2（"无记录可验"不得当成"链完好"）', () => {
      const r = V({ total: 0, collectionTotal: 0 });
      expect(r.code).toBe(2);
      expect(r.empty).toBe(true);
      expect(r.reasons.join('')).toMatch(/审计集合为空/);
    });

    // ★ 同一族缺陷的另一半：collectionTotal 来自 estimatedDocumentCount()（元数据估算），
    //   total 来自游标实际读回并逐条重算哈希的条数。旧判据只认前者为 0，
    //   于是"估算说有、扫描一条没验到"直接得 code 0：一条都没验的链被签了合格证。
    //   在线侧 scan 与估算之间隔一个 await、脚本侧估算在 scan 之前取，两处都能交错出来。
    test('扫到 0 条但估算非 0 ⇒ 2，且不受 --allow-empty 豁免', () => {
      const r = V({ total: 0, collectionTotal: 5000 });
      expect(r.code).toBe(2);
      expect(r.empty).toBe(true);
      expect(r.nothingVerified).toBe(true);
      expect(r.reasons.join('')).toMatch(/扫到并核验 0 条/);
      // 豁免不得越界：--allow-empty 说的是"我知道集合是空的"（首次部署），
      // 盖不住"估算与扫描互相矛盾"这个异常现场
      expect(V({ total: 0, collectionTotal: 5000, allowEmpty: true }).code).toBe(2);
      // 反向闸：估算与扫描都为 0 时仍走可豁免的那一格，别把首次部署一起堵死
      expect(V({ total: 0, collectionTotal: 0, allowEmpty: true }).code).toBe(0);
    });

    // ★ 同一族缺陷的第三格（2026-09-26 追加）：扫到了记录，但**一条都没带 hash**。
    //   legacy 同时容纳"链启用前的存量集合"与"整表 $unset 掉 hash/prevHash/hmac"两种成因，
    //   后者是彻底灭迹（直连驱动/mongosh 可绕过模型中间件）。旧判据只把 legacy 当计数回显、
    //   **没有任何否决基于它**，于是实测出现反向激励：只抹链尾 ⇒ 1（断裂）；
    //   整表全抹 ⇒ 0（**"审计链完整"**、核验审计记 riskLevel=low）——抹得越干净判得越干净。
    test('整窗无哈希（全 legacy）⇒ 2，且不受 --allow-empty 豁免', () => {
      const r = V({ total: 3, legacy: 3 });
      expect(r.code).toBe(2);
      expect(r.nothingHashed).toBe(true);
      expect(r.reasons.join('')).toMatch(/全部无哈希/);
      // 豁免不得越界：--allow-empty 说的是"我知道集合是空的"，与"有记录但都没 hash"无关
      expect(V({ total: 3, legacy: 3, allowEmpty: true }).code).toBe(2);
      // 反向闸：混合窗口（部分带 hash）不得被误伤——那正是正常的"链启用后叠加存量"形态
      expect(V({ total: 3, legacy: 1 }).code).toBe(0);
      expect(V({ total: 3, legacy: 2 }).code).toBe(0);
    });

    test('allowAllLegacy 只豁免整窗无哈希，不得顶替截断 / hmac 否决', () => {
      expect(V({ total: 3, legacy: 3, allowAllLegacy: true }).code).toBe(0);

      const noHmac = V({ total: 3, legacy: 3, allowAllLegacy: true, hmacChecked: false });
      expect(noHmac.code).toBe(2);
      expect(noHmac.reasons.join('')).toMatch(/HMAC_SECRET/);

      const truncated = V({
        total: 3,
        legacy: 3,
        maxRecords: 3,
        collectionTotal: 9,
        allowAllLegacy: true,
      });
      expect(truncated.code).toBe(2);
      expect(truncated.truncated).toBe(true);
    });

    test('漏传 legacy 按"未知"处理 ⇒ 保守否决（不产生假 PASS）', () => {
      const r = computeVerdict({
        breaks: 0,
        total: 3,
        maxRecords: 200000,
        collectionTotal: 3,
        hmacChecked: true,
        scanned: { maxRecords: 200000, fromLatest: true, filter: {} },
      });
      expect(r.nothingHashed).toBe(true);
      expect(r.code).toBe(2);
      // 与"缺口径即否决"同向：漏传参数只得到偏保守的 INCOMPLETE，不会得到假 PASS
    });

    test('空集合可被 --allow-empty 单独豁免 ⇒ 0；豁免不外溢到截断/无 hmac', () => {
      expect(V({ total: 0, collectionTotal: 0, allowEmpty: true }).code).toBe(0);
      const both = V({
        total: 0,
        collectionTotal: 0,
        allowEmpty: true,
        hmacChecked: false,
      });
      expect(both.code).toBe(2);
      expect(both.reasons.join('')).toMatch(/HMAC_SECRET/);
    });

    test('空集合 + 真的有断裂时仍是 1（断裂优先于"没数据"）', () =>
      expect(V({ breaks: 1, total: 0, collectionTotal: 0 }).code).toBe(1));
    test('★ 豁免只作用于 hmac：截断仍在 ⇒ 2（这一格杀"两条理由被与成一个布尔式"的写法）', () => {
      const r = V({
        total: 5,
        maxRecords: 5,
        collectionTotal: 9,
        hmacChecked: false,
        allowNoHmac: true,
      });
      expect(r.code).toBe(2);
      expect(r.truncated).toBe(true);
      expect(r.hmacSkipped).toBe(false); // 豁免确实生效了
      expect(r.reasons.join('')).toMatch(/仅覆盖 5\/9/); // 但截断理由还在
    });
    test('刚好等于上限且已覆盖全表 ⇒ 不算截断（避免误报）', () =>
      expect(V({ total: 5, maxRecords: 5, collectionTotal: 5 }).code).toBe(0));

    // ★ 估算滞后**偏低**时撤销截断否决的那一行：旧式 `total < collectionTotal`
    //   把元数据估算当作"库里还有更多"的唯一证据，估算偏低 ⇒ 条件为假 ⇒ 窗口结论被盖章。
    //   新式 `total !== collectionTotal`：两个数不一致本身就是"估算不可信"的证据。
    test('窗口打满 + 估算低于扫描数 ⇒ 2（两个数矛盾时不以估算撤销截断）', () => {
      const r = V({ total: 50, maxRecords: 50, collectionTotal: 45 });
      expect(r.code).toBe(2);
      expect(r.truncated).toBe(true);
      expect(r.reasons.join('')).toMatch(/估算与扫描互相矛盾/);
    });

    // ★ 子集校验：服务层的 filter 是公开选项（JSDoc 写着"只校验某个子集"），
    //   旧判据对它毫无察觉——total=5 / maxRecords=20000 / collectionTotal=5000
    //   三个条件全不触发 ⇒ code 0「审计链完整」，而实际只验了 5 条。
    //   （在线接口与两个运维脚本都不传 filter，所以这是**调用方 API 上的地雷**，
    //   不是 HTTP 面可利用的绕过。）
    test('带 filter 的子集校验 ⇒ 2，且没有豁免口子', () => {
      const r = V({
        total: 5,
        maxRecords: 20000,
        collectionTotal: 5000,
        scanned: { maxRecords: 20000, fromLatest: true, filter: { username: 'only_me' } },
      });
      expect(r.code).toBe(2);
      expect(r.scoped).toBe(true);
      expect(r.truncated).toBe(false); // 不是靠截断过的：子集自己没撞上限
      expect(r.reasons.join('')).toMatch(/子集校验/);
      // 空对象 filter 不算子集（服务层对无过滤的扫描就是回显 {}）
      expect(
        V({
          total: 5,
          maxRecords: 20000,
          collectionTotal: 5,
          scanned: { maxRecords: 20000, fromLatest: true, filter: {} },
        }).code
      ).toBe(0);
    });

    test('缺口径即否决：调用方没回传 scanned ⇒ 2（漏传只能更保守，不能更乐观）', () => {
      const r = VnoScope({});
      expect(r.code).toBe(2);
      expect(r.scoped).toBe(true);
      expect(r.canAttestIntact).toBe(false);
      expect(r.reasons.join('')).toMatch(/无从判断这是全量还是子集/);
      // 反向闸：每个生产调用方（在线接口 + 周期核验 + 两个运维脚本）都回传了 scanned，
      // 漏传一个就必须红——门禁式断言，防"判据改成忽略 scanned"混过上面几格。
      // 调用方靠枚举而不是点名（点名为何不够见文件头 verdictCallOffenders 的注释）。
      expect(verdictCallOffenders(readVerdictCallers())).toEqual([]);
    });
  });

  // ★ 2026-10-03 实测的漏传现场：链**尾**一条 hashFailure 记录（写侧算 hash 抛错后照常落库，
  //   真实形态见 AuditLog.hashFailure 的字段注释）。报告里 hashComputeFailed=1、breaks=0，
  //   而 CLI 构造 verdict 时没有回传该字段 ⇒ 判据拿不到缺口 ⇒
  //   「VERDICT: PASS（全量、无断裂、hmac 已校验）」exit 0。手册正是按退出码 0 验收的
  //   （deployment/rollback-drill.md:111-112、deployment/secret-rotation.md:397），
  //   于是缺口穿过验收。判据本身的这一格早有覆盖
  //   （src/tests/services/auditChainGuardedIntegrity.test.js 的 B 组），
  //   缺的是**出口到判据这一段**——所以本用例走真 CLI，不走 computeVerdict。
  test('链尾有"算 hash 失败"记录 ⇒ exit 2，且四个豁免都盖不住', async () => {
    const tail = await AuditLog.findOne({ username: `${TAG}_2` })
      .sort({ timestamp: -1 })
      .lean();
    expect(tail).not.toBeNull();
    const pristine = { hash: tail.hash, hmac: tail.hmac };
    expect(pristine.hash).toBeTruthy();

    // 原生集合改写（绕开 ODM 钩子），只抹链尾：它是最新一条，没有后继 ⇒ breaks 仍为 0
    await AuditLog.collection.updateOne(
      { _id: tail._id },
      { $unset: { hash: '', hmac: '' }, $set: { hashFailure: 'crypto error (test seed)' } }
    );

    try {
      const { code, stdout, out } = runCli([]);
      const report = JSON.parse(stdout.slice(stdout.indexOf('{'), stdout.lastIndexOf('}') + 1));
      // 前提自证：现场确实构造成了"报告看得见缺口、但不是篡改"
      expect({ gaps: report.hashComputeFailed, breaks: report.breaks }).toEqual({
        gaps: 1,
        breaks: 0,
      });

      expect(code).toBe(2);
      expect(out).toContain('INCOMPLETE');
      expect(out).toMatch(/哈希计算失败/);
      expect(out).not.toContain('VERDICT: PASS');

      // 缺口没有任何豁免口子：三个豁免同时给也仍是 2
      expect(runCli(['--allow-empty', '--allow-no-hmac', '--allow-all-legacy']).code).toBe(2);
    } finally {
      await AuditLog.collection.updateOne(
        { _id: tail._id },
        { $set: { hash: pristine.hash, hmac: pristine.hmac }, $unset: { hashFailure: '' } }
      );
      // 还原自证：链回到"全量、无断裂、无缺口"，否则后面的用例会带着本用例的尾巴跑
      expect(runCli([]).code).toBe(0);
    }
  });

  test('篡改一条记录（绕过 ODM 直改字段）⇒ exit 1 且报断裂', async () => {
    // 用原生集合绕开 mongoose 中间件，等价于"拿到 DB 写权限的人改了明文字段"
    const target = await AuditLog.findOne({ username: `${TAG}_1` }).lean();
    expect(target).not.toBeNull();
    await AuditLog.collection.updateOne(
      { _id: target._id },
      { $set: { path: '/tampered-by-attacker' } }
    );

    const { code, stdout, out } = runCli(['--from=earliest']);
    expect(code).toBe(1);
    expect(out).toContain('VERDICT: FAIL');
    // JSON 报告与 VERDICT 同路 stdout，取第一个 { 到最后一个 } 之间即为报告本体
    const report = JSON.parse(stdout.slice(stdout.indexOf('{'), stdout.lastIndexOf('}') + 1));
    expect(report.breaks).toBeGreaterThan(0);

    // 还原，避免污染后续（同库同集合）
    await AuditLog.collection.updateOne({ _id: target._id }, { $set: { path: mkDoc(1).path } });
    expect(runCli(['--from=earliest']).code).toBe(0);
  });
});
