/**
 * F-178：备用恢复码「格式谓词单一来源」+ 生成侧模偏差的可证伪门禁
 *
 * 覆盖三件事，缺一不可：
 *  1) 绝对值：字母表到底是哪 31 个字符、剔除了哪些易混字符（mfaService 的注释
 *     一直声称「去除 0/O/1/I/L」，此前无人验证）；以及 256 % 31 = 8 带来的模偏差量级。
 *  2) 行为：生成侧产出的字符分布**没有**模偏差——并且先用同一段检测器去打一个
 *     手写「取模 oracle」，证明检测器看得见偏差（否则「没测出偏差」可能只是检测器失灵）。
 *  3) 漂移：登录侧与入参侧两份手写正则与字母表**逐字符**等价（交给 JS 正则引擎判定，
 *     不在测试里重实现区间展开），并整串比对接受/拒绝结果。
 *
 * 对端若把两处手写正则换成 `isRecoveryCodeFormat`，本门禁的「收敛态」分支会直接放行；
 * 但「判定被整段删掉」会落进「既没字面量也没收敛引用」的分支变红。
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const {
  RECOVERY_CODE_ALPHABET,
  RECOVERY_CODE_PATTERN,
  isRecoveryCodeFormat,
  generateRecoveryCodes,
} = require('../../services/mfaService');

const SRC_ROOT = path.join(__dirname, '../..');
const readSource = (rel) => fs.readFileSync(path.join(SRC_ROOT, rel), 'utf8');

/** 按形状定位源码里的恢复码正则字面量（内容不硬编码：门禁要判的是「与字母表等价」）。
 *  两层收口都是实测出来的：
 *   - 必须「两组 4 位字符类被一个连字符连接」——否则 authRoutes.js 里的 UUID
 *     校验 `/^[0-9a-f]{8}-[0-9a-f]{4}-…{12}$/i` 会被捞进来误判（它含 `{4}-` 片段）；
 *   - 再要求整串恰好只有 2 个 `{4}` 量词——UUID 字面量有 3 个，正是靠这条被剔掉。
 *  允许字符类两侧还有别的分组括号（入参侧是 `^(\d{6}|…{4})$` 这种并列结构）。 */
const harvestRecoveryLiterals = (source) =>
  (
    source.match(/\/\^[^\r\n]*?\[[^\]\r\n]+\]\{4\}-\[[^\]\r\n]+\]\{4\}[^\r\n]*?\$\/[a-z]*/g) || []
  ).filter((text) => (text.match(/\{4\}/g) || []).length === 2);

/** '/^abc$/i' 这种字面量文本 → 真 RegExp */
const literalToRegExp = (text) => {
  const last = text.lastIndexOf('/');
  return new RegExp(text.slice(1, last), text.slice(last + 1));
};

const CONSUMERS = [
  { file: 'services/authService.js', what: '登录侧恢复码校验（大写化后判定）' },
  { file: 'routes/authRoutes.js', what: '入参校验（与 6 位动态口令并列）' },
];

// ── 模偏差检测器 ────────────────────────────────────────────────
// 256 % 31 = 8 ⇒ 取模实现里字母表前 8 个字符各由 9 个字节值映射、其余 23 个各由 8 个映射，
// 于是「前 8 组的均值」高出 12.5%。分组就叫 BIAS_GROUP。
const BIAS_GROUP = 256 % RECOVERY_CODE_ALPHABET.length;
const SAMPLE_CODES = 25000; // ×8 位 = 200000 个字符

const charCounts = (codes) => {
  const counts = new Array(RECOVERY_CODE_ALPHABET.length).fill(0);
  const unknown = [];
  for (const code of codes) {
    for (const ch of code.replace('-', '')) {
      const idx = RECOVERY_CODE_ALPHABET.indexOf(ch);
      if (idx < 0) unknown.push(ch);
      else counts[idx] += 1;
    }
  }
  return { counts, unknown };
};

/** 前 BIAS_GROUP 组与其余组的均值差，折算成 z 分数（均匀 ⇒ ~N(0,1)；取模 ⇒ 数量级 20+） */
const biasZ = (counts) => {
  const g1 = counts.slice(0, BIAS_GROUP);
  const g2 = counts.slice(BIAS_GROUP);
  const mean = (a) => a.reduce((x, y) => x + y, 0) / a.length;
  const varr = (a) => a.reduce((s, v) => s + (v - mean(a)) ** 2, 0) / (a.length - 1);
  return (mean(g1) - mean(g2)) / Math.sqrt(varr(g1) / g1.length + varr(g2) / g2.length);
};

/** 与 generateRecoveryCodes 逐行同构、唯独保留旧取模写法的 oracle */
const biasedOracle = (count) => {
  const codes = [];
  for (let i = 0; i < count; i++) {
    const bytes = crypto.randomBytes(8);
    let raw = '';
    for (let j = 0; j < 8; j++)
      raw += RECOVERY_CODE_ALPHABET[bytes[j] % RECOVERY_CODE_ALPHABET.length];
    codes.push(`${raw.slice(0, 4)}-${raw.slice(4)}`);
  }
  return codes;
};

describe('F-178 备用恢复码字母表（绝对值）', () => {
  it('字母表恰为 31 字符 = 26 字母剔除 I/L/O + 数字 2-9', () => {
    const expected = [...'ABCDEFGHJKMNPQRSTUVWXYZ', ...'23456789'];
    expect(RECOVERY_CODE_ALPHABET).toHaveLength(31);
    expect([...RECOVERY_CODE_ALPHABET].sort()).toEqual([...expected].sort());
  });

  it.each(['I', 'L', 'O', '0', '1'])(
    '易混字符 %s 不在字母表内（mfaService 注释声称的判据，此前无人验证）',
    (ch) => {
      expect(RECOVERY_CODE_ALPHABET.includes(ch)).toBe(false);
    }
  );

  it('字母表不含小写、不含连字符、不含正则元字符', () => {
    for (const ch of RECOVERY_CODE_ALPHABET) {
      expect(ch).toMatch(/[A-Z2-9]/);
    }
  });

  it('熵 = log2(31^8) ≈ 39.6 bit（注释里的数字要能被复算）', () => {
    const bits = 8 * Math.log2(RECOVERY_CODE_ALPHABET.length);
    expect(bits).toBeGreaterThan(39.5);
    expect(bits).toBeLessThan(39.7);
  });

  it('前提：长度 31 与 256 不整除 ⇒ 取模必然产生偏差（枚举 0..255 复现 9/8 两个台阶）', () => {
    expect(256 % RECOVERY_CODE_ALPHABET.length).toBe(8);
    const hist = new Array(RECOVERY_CODE_ALPHABET.length).fill(0);
    for (let b = 0; b < 256; b++) hist[b % RECOVERY_CODE_ALPHABET.length] += 1;
    expect(hist.slice(0, 8)).toEqual(new Array(8).fill(9));
    expect(hist.slice(8)).toEqual(new Array(23).fill(8));
    // 均匀取字节值时每个字符的映射数必须相同——旧实现不满足，这正是缺陷量级
    expect(Math.max(...hist) - Math.min(...hist)).toBe(1);
  });
});

describe('F-178 生成侧取字符不再有模偏差', () => {
  const { counts, unknown } = charCounts(generateRecoveryCodes(SAMPLE_CODES));

  it(`检测器有效：同段检测器打在「保留取模」的 oracle 上必须报警（${SAMPLE_CODES} 码）`, () => {
    const z = biasZ(charCounts(biasedOracle(SAMPLE_CODES)).counts);
    expect(Number.isFinite(z)).toBe(true);
    expect(z).toBeGreaterThan(10); // 取模实测 z ≈ 24；均匀实现 z ~ N(0,1)
  });

  it('真实实现测不出偏差（|z| < 6）', () => {
    expect(Math.abs(biasZ(counts))).toBeLessThan(6);
  });

  it('只产出字母表内字符，且 31 个字符在 200000 次抽样里全部出现过', () => {
    expect(unknown).toEqual([]);
    expect(counts.every((c) => c > 0)).toBe(true);
    expect(counts.reduce((a, b) => a + b, 0)).toBe(SAMPLE_CODES * 8);
  });

  it('格式 XXXX-XXXX：连字符固定在第 5 位，且一次生成不出现重复码', () => {
    const codes = generateRecoveryCodes(1000);
    for (const code of codes) {
      expect(code).toHaveLength(9);
      expect(code.indexOf('-')).toBe(4);
      expect(isRecoveryCodeFormat(code)).toBe(true);
      expect(RECOVERY_CODE_PATTERN.test(code)).toBe(true);
    }
    expect(new Set(codes).size).toBe(codes.length);
  });

  it('生成数量参数生效（含默认 10 个）', () => {
    expect(generateRecoveryCodes()).toHaveLength(10);
    expect(generateRecoveryCodes(1)).toHaveLength(1);
    expect(generateRecoveryCodes(0)).toEqual([]);
  });
});

describe('F-178 校验侧两份手写正则与字母表等价（漂移门禁）', () => {
  const probes = [
    'ABCD-EFGH',
    'abcd-efgh',
    'ZZZZ-9999',
    'ABCH-JKMN',
    '2345-6789',
    'ABCI-EFGH', // I 被剔除
    'ABCO-EFGH', // O 被剔除
    'ABCL-EFGH', // L 被剔除
    'ABC0-EFGH', // 0 被剔除
    'ABC1-EFGH', // 1 被剔除
    'ABCD-EFG',
    'ABCD-EFGHI',
    'ABCDE-FGHI',
    'ABCDEF GHI',
    'ABCDEF-GHI',
    '123456',
    '12345',
    '1234567',
    '',
    '--------',
    'ABCD_EFGH',
    'áBCD-EFGH',
  ];

  for (const consumer of CONSUMERS) {
    const source = readSource(consumer.file);
    const converged = /isRecoveryCodeFormat|RECOVERY_CODE_PATTERN/.test(source);
    const literals = harvestRecoveryLiterals(source);

    it(`${consumer.file}：${consumer.what}——已收敛到单一来源，或手写正则与字母表逐字符等价`, () => {
      if (converged && literals.length === 0) return; // 期望的最终形态
      // 抓不到字面量、又没有引用单一来源 ⇒ 这段判定被删了，必须红
      expect(literals.length).toBeGreaterThan(0);

      for (const text of literals) {
        const re = literalToRegExp(text);
        const classes = re.source.match(/\[[^\]]*\]/g) || [];
        expect(classes.length).toBeGreaterThanOrEqual(2); // {4}-前缀{4} ⇒ 至少两个字符类

        for (const cls of classes) {
          const one = new RegExp(`^${cls}$`);
          const offenders = [];
          for (let code = 33; code <= 126; code++) {
            const ch = String.fromCharCode(code);
            if (one.test(ch) !== RECOVERY_CODE_ALPHABET.includes(ch)) offenders.push(ch);
          }
          expect(offenders).toEqual([]);
        }

        const caseInsensitive = text.endsWith('i');
        const mismatches = [];
        for (const probe of probes) {
          const mine = caseInsensitive
            ? /^\d{6}$/.test(probe) || isRecoveryCodeFormat(probe.toUpperCase())
            : isRecoveryCodeFormat(probe);
          if (re.test(probe) !== mine) mismatches.push(`${probe} => ${re.test(probe)} vs ${mine}`);
        }
        expect(mismatches).toEqual([]);
      }
    });
  }

  it('两份手写正则彼此也等价（防「只跟权威比、两边一起错」）', () => {
    const all = CONSUMERS.map((c) => harvestRecoveryLiterals(readSource(c.file))).flat();
    expect(all.length).toBeGreaterThanOrEqual(2);
    const sets = all.map((text) => {
      const re = literalToRegExp(text);
      const cls = (re.source.match(/\[[^\]]*\]/g) || [])[0];
      const one = new RegExp(`^${cls}$`);
      const accepted = [];
      for (let code = 33; code <= 126; code++) {
        const ch = String.fromCharCode(code);
        if (one.test(ch)) accepted.push(ch);
      }
      return accepted.join('');
    });
    expect(new Set(sets).size).toBe(1);
  });

  it('格式谓词对非字符串一律 false（不抛、不做隐式强转）', () => {
    // 数组会被 String() 强转成 'ABCD-EFGH'——只测 null/数字的用例杀不掉 typeof 守卫（变异实测）
    for (const bad of [
      null,
      undefined,
      123,
      {},
      [],
      true,
      Buffer.from('ABCD-EFGH'),
      ['ABCD-EFGH'],
      ['ABCD', 'EFGH'],
    ]) {
      expect(isRecoveryCodeFormat(bad)).toBe(false);
    }
  });

  it('入参侧「6 位动态口令」与「恢复码」是并列两分支：口令不得被恢复码分支吞掉', () => {
    expect(isRecoveryCodeFormat('123456')).toBe(false);
    expect(RECOVERY_CODE_PATTERN.test('123456')).toBe(false);
    expect(/^\d{6}$/.test('123456')).toBe(true);
  });
});
