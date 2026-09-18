/**
 * isWeakSecret 判据的行为测试（生产环境拒绝启动的唯一防线）
 *
 * 为什么需要它：isWeakSecret 是「生产环境密钥是否可接受」的唯一判据，
 * 任一判据失效 → 弱密钥放行 → 攻击者可离线伪造任意用户（含超管）令牌。
 * 既有 validate.test.js 只覆盖 collectProductionWarnings 与 validateConfig 编排，
 * 函数内部的**周期重复检测**与**香农熵**此前零覆盖（lcov 行 60-62 / 67-68）。
 *
 * 判据（源码 validate.js:80-85，逐条对齐）：
 *   1. 空值或命中 WEAK_SECRETS 黑名单
 *   2. 长度 < 32
 *   3. 命中 PLACEHOLDER_PATTERNS
 *   4. 周期 ≤ 16 的重复串
 *   5. 香农熵 < 2.0 bit/char
 * 两个方向都必须断言：弱值要判弱，**合法密钥要放行**——
 * 误伤的后果是标准生成流程起不来（源码注释记录过多次误伤校准）。
 *
 * 全部样本的期望值均经实测确认（2026-09-18，本机 Node v24.15.0），
 * 未凭推断书写；样本为固定字符串而非随机生成，避免 flaky。
 */
const { isWeakSecret } = require('../../config/validate');

describe('isWeakSecret：判据 1-3（空值 / 黑名单 / 长度 / 占位符）', () => {
  test('空值一律判弱（null / undefined / 空串）', () => {
    expect(isWeakSecret('')).toBe(true);
    expect(isWeakSecret(null)).toBe(true);
    expect(isWeakSecret(undefined)).toBe(true);
  });

  test('WEAK_SECRETS 黑名单逐项判弱（含 .env.example 的 <CHANGE_ME>）', () => {
    for (const s of [
      'default-secret-change-in-production',
      'default-aes-key-change-in-production',
      'default-hmac-secret',
      'your-super-secret-jwt-key-change-in-production',
      'your-refresh-token-secret',
      'change-this-secret',
      '<CHANGE_ME>',
    ]) {
      expect(isWeakSecret(s)).toBe(true);
    }
  });

  test('长度 31 判弱、32 放行（边界逐位，不取近似）', () => {
    // 用高熵字符集构造，确保只有长度这一条判据在起作用
    const base = 'aB3$xY7!qW2#eR9%tU4^iO6&pL1*zC5(dF8)gH0-J';
    expect(base.length).toBeGreaterThanOrEqual(32);
    expect(isWeakSecret(base.slice(0, 31))).toBe(true);
    expect(isWeakSecret(base.slice(0, 32))).toBe(false);
  });

  test('占位符形态逐项判弱（尖括号 / change-me / your- / xxx / todo 系）', () => {
    for (const s of [
      '<替换为 openssl rand -base64 48 的输出>',
      'change-me-please-change-me-now-1234',
      'your-secret-your-secret-your-secret',
      'placeholder-placeholder-placeholder',
      'replace-me-replace-me-replace-me-1',
      'dummy-dummy-dummy-dummy-dummy-dum',
      'x'.repeat(32),
      'todo-todo-todo-todo-todo-todo-todo',
      'fixme-fixme-fixme-fixme-fixme-fixm',
    ]) {
      expect(isWeakSecret(s)).toBe(true);
    }
  });

  test('example- 系占位符判弱（该样本 31 字符，长度与占位符两条判据都会命中）', () => {
    const s = 'example-example-example-example';
    expect(s.length).toBeLessThan(32);
    expect(isWeakSecret(s)).toBe(true);
  });
});

describe('isWeakSecret：判据 4（周期 ≤16 的重复串）', () => {
  test('短单元重复拼接判弱（password / qwerty / 1234567890 等真实弱密钥形态）', () => {
    for (const unit of ['password', 'qwerty', '1234567890', 'changeme', 'abcdefghij']) {
      const value = unit.repeat(Math.ceil(40 / unit.length)).slice(0, 40);
      expect(value.length).toBeGreaterThanOrEqual(32);
      expect(isWeakSecret(value)).toBe(true);
    }
  });

  test('末段截断的一轮（非整周期）同样判弱——截断不改变熵上界', () => {
    expect(isWeakSecret('1234567890'.repeat(3) + '1234')).toBe(true); // 周期 10
    expect(isWeakSecret('abcd'.repeat(9))).toBe(true); // 周期 4，36 字符
  });

  test('周期恰为 16 判弱（maxPeriod 上边界命中）', () => {
    const unit16 = 'aB3$xY7!qW2#eR9%';
    expect(unit16.length).toBe(16);
    const periodic16 = unit16 + unit16 + unit16.slice(0, 8);
    expect(periodic16.length).toBe(40);
    expect(isWeakSecret(periodic16)).toBe(true);
  });

  test('周期 17 不再命中「周期」判据（证明 maxPeriod=16 真的生效）', () => {
    // 若实现把 maxPeriod 放宽（如改成 32），本用例会红：periodic17 由 17 字符
    // 单元重复构成，字符分布与单元相同，熵约 4 bit/char，远高于 2.0 阈值，
    // 唯一可能判弱的原因就是周期判据。实测确认为放行。
    const unit17 = 'aB3$xY7!qW2#eR9%t';
    expect(unit17.length).toBe(17);
    const periodic17 = unit17 + unit17 + unit17.slice(0, 10);
    expect(periodic17.length).toBe(44);
    expect(isWeakSecret(periodic17)).toBe(false);
  });
});

describe('isWeakSecret：判据 5（香农熵）与合法密钥放行', () => {
  test('极低熵串判弱（字符分布高度倾斜）', () => {
    expect(isWeakSecret('a'.repeat(31) + 'b')).toBe(true); // 约 0.2 bit/char
    expect(isWeakSecret('ab'.repeat(16))).toBe(true); // 约 1.0 bit/char
  });

  test('16 种字符均匀分布但周期为 16 → 判弱（周期判据先于熵生效）', () => {
    const even16 = Array.from({ length: 48 }, (_, i) => '0123456789abcdef'[i % 16]).join('');
    expect(even16.length).toBe(48);
    // 熵恰为 4.0 bit/char（高于阈值），仍被判弱——证明周期判据独立生效
    expect(isWeakSecret(even16)).toBe(true);
  });

  test('不规则高熵串放行（周期 > 16 且熵充足）', () => {
    const irregular = 'a1b2c3d4e5f60718293a4b5c6d7e8f9012345678abcdef';
    expect(irregular.length).toBe(46);
    expect(isWeakSecret(irregular)).toBe(false);
  });

  test('低熵且排列不规则（周期 > 16）→ 仅由熵判据拦下', () => {
    const lowEntropy = 'aabbaabbababbaabbaababbaabbababbaabbaababbaababba';
    expect(lowEntropy.length).toBe(49);
    expect(isWeakSecret(lowEntropy)).toBe(true);
  });

  test('generate-secrets.js 的真实产出形式必须放行（不得误伤标准流程）', () => {
    // 固定样本：字符分布与真实产出同构（base64 64 字符 / hex 64 字符 / base64 32 字符）
    const samples = [
      'hUe65ONT+Uf+8bhWqDjT94s15137oS+jq+b4+grY78DvL4ehHWlkSDmesntODoAr',
      'kZ9mQ2xR7pL4wN8vT1yB6cF3jH5dG0sA2eU9iK7oM4nP8qW6zX1rV3tY5uI0aS2d',
      '3f8a91c47e2b6d05a8c3f1e94b7d206a5c8e3f1b9d4a7c2e5f8b1d6a3c9e4f7',
      'c4e8b1a7d3f6092e5a8c1f4b7d0e3a6c9f2b5d8e1a4c7f0b3d6e9a2c5f8b1d4',
      'QmFzZTY0RW5jb2RlZFNlY3JldEZvckFkbWluUGFzc3dvcmQxMjM0',
    ];
    for (const s of samples) {
      expect(s.length).toBeGreaterThanOrEqual(32);
      expect(isWeakSecret(s)).toBe(false);
    }
  });
});
