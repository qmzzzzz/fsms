/**
 * HMAC_SECRET 消费点清单的单一来源门禁（2026-10-01）
 *
 * 为什么需要：`HMAC_SECRET` 被多处复用，而「谁在用它」这件事**没有任何单一来源**——
 * 实测同一份仓库里存在三份互不相同的清单：
 *   - `deployment/secret-rotation.md` 写「**两个**消费点」（审计链 + 口令历史）；
 *   - `deliverables/AGENT工作总账与待办-*.md` 的 F-26 写「三个」（审计链 + MFA 恢复码
 *     pepper + 数据签名密钥）——**漏了口令历史**；
 *   - 真实源码是**四个**。
 *
 * 清单漂移的代价很具体：运维照着手册轮换，以为收口了，而恢复码 / 口令历史 /
 * HMACSigner 三处**静默失效**（无迁移手段）。其中恢复码最阴——它是用户丢掉
 * 认证器时的唯一逃生门，故障只在"某个人手机丢了"的那一天才暴露，
 * 那时运维早已忘记当天换过钥。
 *
 * 因此钉两条：
 *   ① 源码里**取值访问** `HMAC_SECRET` 的文件集合必须恰好等于 EXPECTED_CONSUMERS
 *      ——新增消费点而不登记，本用例变红；
 *   ② 轮换手册必须逐个点名这些文件，且必须提到「恢复码」
 *      ——手册回退到只写两个消费点的形态，本用例变红。
 *
 * 判据为什么是「取值访问」而不是「提到 HMAC_SECRET」：
 *   注释、报错文案、校验器里都会出现大写 `HMAC_SECRET`（如 `config/validate.js`
 *   的弱密钥校验、`services/auditChainVerify.js` 的降级说明），把它们算成消费点
 *   会让清单被噪声撑大、反而失去意义。取值访问只有两种写法：
 *   `config.hmacSecret` / `process.env.HMAC_SECRET`（后者见 `utils/encryption.js`）。
 *   `services/auditChainVerify.js` 是审计链的校验侧，但它 `computeHmac` 是从
 *   `utils/auditChain.js` 导入的——**密钥取值发生在 auditChain.js**，故不重复计。
 *
 * 行号故意不写进断言：手册里的行号会随改动漂移，判据是**文件路径**。
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '../../..');
const SRC_DIR = path.join(ROOT, 'src');
const ROTATION_DOC = path.join(ROOT, 'deployment/secret-rotation.md');

/**
 * 必须登记的消费点（相对仓库根，与手册表格里的写法一致）。
 * 新增消费点时必须同时补这里与 `deployment/secret-rotation.md`。
 */
const EXPECTED_CONSUMERS = [
  'src/utils/auditChain.js', // 审计记录 hmac 字段（唯一有重签工具的）
  'src/utils/passwordHistory.js', // 口令复用历史摘要的 pepper
  'src/services/mfaService.js', // 备用恢复码的 pepper
  'src/utils/encryption.js', // HMACSigner 数据签名密钥
];

/** 取值访问 HMAC_SECRET 的两种写法（见文件头判据说明） */
const KEY_ACCESS_PATTERN = /hmacSecret|process\.env\.HMAC_SECRET/;

/** 递归收集 src 下的 .js（排除测试与配置装载面） */
const collectSourceFiles = (dir) => {
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    const rel = path.relative(ROOT, full).split(path.sep).join('/');
    if (entry.isDirectory()) {
      // src/config 是密钥的**装载与校验面**（定义、secrets 清单、弱密钥校验），
      // 不是消费点；src/tests 是夹具。两者都不进清单。
      if (rel === 'src/config' || rel === 'src/tests') continue;
      out.push(...collectSourceFiles(full));
    } else if (entry.name.endsWith('.js')) {
      out.push(rel);
    }
  }
  return out;
};

describe('HMAC_SECRET 消费点清单的单一来源', () => {
  const sourceFiles = collectSourceFiles(SRC_DIR);

  test('扫描基线非空（防止扫描逻辑写错导致"零命中"被当成通过）', () => {
    expect(sourceFiles.length).toBeGreaterThan(100);
    expect(sourceFiles).toContain('src/utils/auditChain.js');
  });

  test('源码里的消费点集合必须恰好等于登记清单（新增消费点须同步登记）', () => {
    const found = sourceFiles
      .filter((rel) => KEY_ACCESS_PATTERN.test(fs.readFileSync(path.join(ROOT, rel), 'utf8')))
      .sort();
    expect(found).toEqual([...EXPECTED_CONSUMERS].sort());
  });

  describe('轮换手册必须与清单同源', () => {
    const doc = fs.readFileSync(ROTATION_DOC, 'utf8');

    test.each(EXPECTED_CONSUMERS)('手册必须点名 %s', (rel) => {
      expect(doc).toContain(rel);
    });

    // —— 本文件最关键的一条 ——
    // 变异：把手册的四消费点表删回「两个消费点」的旧形态 ⇒ 本条必须变红。
    // 恢复码是三条无迁移手段的消费点里**后果最隐蔽**的一条（逃生门在故障当天才暴露），
    // 所以用"必须出现恢复码"作为回归哨兵，而不是只数表格行数。
    test('手册必须点名「恢复码」——它曾整份缺失（全文 0 命中）', () => {
      expect(doc).toMatch(/恢复码/);
    });

    test('手册必须写明消费点总数为四个（防止表格被悄悄删行）', () => {
      expect(doc).toMatch(/四个消费点/);
    });

    test('手册必须说明"只有第 1 个有迁移工具"这一非对称事实', () => {
      // 只列清单而不说"其余三个没有迁移手段"，运维会默认"跑一下脚本就好"
      expect(doc).toMatch(/迁移手段/);
    });
  });
});
