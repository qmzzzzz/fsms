/**
 * 口令复用历史：判定语义 + **接线不变量**（2026-09-30）
 *
 * 缺陷形态（改之前）：`changeUserPassword` 里只有 `SAME_PASSWORD`，即"不能与**当前**
 * 口令相同"。A→B→A 这种两步复用完全放行——而复用是真实攻击路径（口令泄露后
 * 施压改回原口令、或在多个系统间轮换同一弱口令）。`validatePasswordStrength`
 * 只管强度，全仓零处检查复用。
 *
 * 为什么接线部分要和语义部分放同一个文件：
 * 语义测对了而没接线，是这类修复最常见的落地失败形态——单元测试全绿，
 * 生产上仍可复用。这里把"两个控制器的 outcome 映射""select('+passwordHistory')"
 * "响应投影排除"三条**接线**钉成不变量，它们任一缺失，下面所有语义测试仍然全绿。
 *
 * 摘要为什么用 HMAC 而不是 bcrypt（用户建议里写的是 bcrypt，这里换掉了）：
 * 历史条目的用途是**等值比较**，比较时明文就在手里；bcrypt 的"慢"是为离线爆破
 * 服务的，此处不适用，而代价很实在——rounds=12 下每条 250~300ms，保留 5 条就是
 * 1.5 秒且全部挂在改密端点上，而 `passwordChangeLimiter` 只按 user+ip 限到
 * 5 次/15 分钟、没有全局护栏，N 个账号就能把 CPU 打满。
 * 本仓已有同形先例：`services/mfaService.hashRecoveryCode`（HMAC + pepper，
 * 未配密钥时退化 sha256）。两者威胁模型不同，此处与那处的差别已在
 * utils/passwordHistory.js 文件头写明。
 */

const mongoose = require('mongoose');

const {
  HISTORY_DEPTH,
  digestOf,
  sanitizeHistory,
  matchesHistory,
  withPrevious,
} = require('../../utils/passwordHistory');
const { ERROR_CODES, validateRegistry } = require('../../utils/errorCodes');
const User = require('../../models/User');

const AUTH_SERVICE = require('../../services/authService');

const OLD = 'Old-Passw0rd!x';
const NEW = 'New-Passw0rd!y';
const NEWER = 'N3wer-Passw0rd!z';

describe('passwordHistory：等值判定语义', () => {
  test('未配置 pepper 时也必须能判定（退化 sha256 不许静默失效）', () => {
    const digest = digestOf(OLD);
    expect(typeof digest).toBe('string');
    expect(digest).toHaveLength(64); // sha256 hex
    expect(matchesHistory([digest], OLD)).toBe(true);
    expect(matchesHistory([digest], NEW)).toBe(false);
  });

  test('空/畸形历史不得把任何口令判成复用（否则新用户改一次密就被锁死）', () => {
    for (const bad of [undefined, null, [], 'not-an-array', [null], [undefined], [''], [123]]) {
      expect(matchesHistory(bad, OLD)).toBe(false);
    }
  });

  test('空口令与非字符串不得产生摘要（否则 "" 会成为一条可命中的历史）', () => {
    expect(digestOf('')).toBeNull();
    expect(digestOf(null)).toBeNull();
    expect(digestOf(undefined)).toBeNull();
    expect(matchesHistory([], '')).toBe(false);
  });

  test('withPrevious：新条目在前，且深度封顶', () => {
    let history = [];
    // 依次退役 P1..P(N+3)，历史应只留最近 N 条
    for (let i = 1; i <= HISTORY_DEPTH + 3; i += 1) {
      history = withPrevious(history, `Pass-${i}!Aa1`);
    }
    expect(history).toHaveLength(HISTORY_DEPTH);
    // 最前面是最后退役的那条
    expect(matchesHistory(history, `Pass-${HISTORY_DEPTH + 3}!Aa1`)).toBe(true);
    // 最早的已被淘汰 ⇒ 不再命中（这就是"最近 N 条"的边界）
    expect(matchesHistory(history, 'Pass-1!Aa1')).toBe(false);
  });

  test('withPrevious 对脏历史同样封顶并去重（备份还原/裸写库的产物）', () => {
    const dirty = Array.from({ length: HISTORY_DEPTH * 2 }, (_, i) => digestOf(`x${i}`));
    dirty.push(digestOf('dup'), digestOf('dup'), null, 42, '');
    const out = withPrevious(dirty, 'fresh-one');
    expect(out).toHaveLength(HISTORY_DEPTH);
    expect(new Set(out).size).toBe(out.length);
    expect(matchesHistory(out, 'fresh-one')).toBe(true);
  });

  test('sanitizeHistory 剔除非字符串并截断（读取侧也必须封顶，不只写入侧）', () => {
    const out = sanitizeHistory([digestOf('a'), null, 7, {}, digestOf('b')]);
    expect(out).toHaveLength(2);
    expect(out.every((x) => typeof x === 'string')).toBe(true);
  });

  test('深度上限有上界（误配成 1000 会让单文档膨胀到 64KB/用户）', () => {
    expect(HISTORY_DEPTH).toBeGreaterThanOrEqual(1);
    expect(HISTORY_DEPTH).toBeLessThanOrEqual(24);
  });
});

describe('接线不变量（语义对了但没接线，是这类修复最常见的落地失败形态）', () => {
  test('authService.changeUserPassword 必须显式 select 出 passwordHistory', () => {
    // 漏了这条 ⇒ user.passwordHistory 恒为 undefined ⇒ matchesHistory 恒 false
    // ⇒ 复用防线静默归零，而下面所有语义测试仍然全绿
    const src = require('fs').readFileSync(
      require('path').join(__dirname, '../../services/authService.js'),
      'utf8'
    );
    const fn = src.slice(src.indexOf('async function changeUserPassword'));
    expect(fn).toMatch(/\.select\(\s*'\+password[^']*passwordHistory/);
  });

  test('改密成功后必须写入被替换掉的旧口令（否则历史永远是空的）', () => {
    const src = require('fs').readFileSync(
      require('path').join(__dirname, '../../services/authService.js'),
      'utf8'
    );
    const fn = src.slice(src.indexOf('async function changeUserPassword'));
    expect(fn).toMatch(/user\.passwordHistory\s*=\s*withPrevious\(/);
  });

  test('passwordHistory 是 select:false 凭证级字段，且被响应投影显式排除', () => {
    // 它是对口令明文的单向摘要：读到它等于拿到"这个口令用过没有"的预言机
    expect(User.schema.path('passwordHistory').options.select).toBe(false);
    expect(User.schema.statics.RESPONSE_EXCLUDE).toContain('-passwordHistory');
  });

  test('schema 层刻意不加长度 validator（上限调小会让存量超长文档无法 save）', () => {
    const path = User.schema.path('passwordHistory');
    expect(path.options.validate).toBeUndefined();
  });

  test('两个控制器的 changePassword outcome 映射都覆盖 PASSWORD_REUSED', () => {
    // 漏任何一个 ⇒ 该端点落进 default 分支按 INTERNAL_ERROR 返回，
    // 用户看到的是"服务器故障"而不是"这个密码用过"，且改密静默失败
    const fs = require('fs');
    const path = require('path');
    for (const file of ['authController.js', 'securityController.js']) {
      const src = fs.readFileSync(path.join(__dirname, '../../controllers', file), 'utf8');
      const caseAt = src.indexOf("case 'PASSWORD_REUSED':");
      expect(caseAt).toBeGreaterThan(-1);
      // 该 case 分支内必须映射到注册的错误码，而不是落进 default → INTERNAL_ERROR
      const branch = src.slice(caseAt, caseAt + 400);
      expect(branch).toContain('PASSWORD_REUSED_IN_HISTORY');
      // 必须 return 出去，不能落进下一个 case（switch 穿透会让后续分支重复执行）
      expect(branch).toMatch(/return\s+ApiResponse\.codeError/);
    }
  });

  test('新错误码已登记且是 400（4xx 而非 5xx —— 客户端能改，不是服务端故障）', () => {
    const def = ERROR_CODES.PASSWORD_REUSED_IN_HISTORY;
    expect(def).toBeTruthy();
    expect(def.status).toBe(400);
    // 文案必须点明"最近"而不是笼统说"不能重复"：用户需要知道边界才能换一个可用口令
    expect(def.message).toContain('最近');
  });

  test('错误码注册表仍然合法（新增条目不得越界）', () => {
    expect(validateRegistry()).toEqual([]);
  });

  test('前端已登记同一错误码（否则用户只看到后端中文原文，英文界面全中文）', () => {
    const fs = require('fs');
    const path = require('path');
    const apiSrc = fs.readFileSync(
      path.join(__dirname, '../../../web-admin/src/utils/api.js'),
      'utf8'
    );
    expect(apiSrc).toContain('PASSWORD_REUSED_IN_HISTORY');
    // 文案里的数字必须来自后端 params，前端不写死
    for (const locale of ['zh-CN', 'en-US']) {
      const s = fs.readFileSync(
        path.join(__dirname, `../../../web-admin/src/i18n/locales/${locale}.js`),
        'utf8'
      );
      const entry = s.slice(s.indexOf('passwordReusedInHistory:'));
      expect(entry.slice(0, 200)).toContain('{historyDepth}');
    }
  });
});

describe('changeUserPassword：复用被拒（行为级，走真实 Mongo 与真实 bcrypt）', () => {
  let userId;

  const change = (currentPassword, newPassword) =>
    AUTH_SERVICE.changeUserPassword(
      userId,
      { currentPassword, newPassword, confirmPassword: newPassword },
      { username: 'reuse-tester' }
    );

  /**
   * 把唯一测试用户重置回确定态（当前口令 = pass，历史 = historyPasswords 的摘要序列）。
   *
   * 为什么需要：下面的行为级用例原本是一条**隐式状态机**——上一条用例改成的口令
   * 是这一条的前置（"全新口令正常通过"把当前口令变成 NEWER，"深度边界"依赖它）。
   * 固定顺序下成立，`--randomize` 门禁（seed 20260917/31337/777001 实测）洗乱声明
   * 顺序后前置消失，CURRENT_WRONG 取代了预期 outcome。改为每条用例自置前置，
   * 与执行顺序彻底解耦；save 走模型预存钩子，bcrypt 语义与真实改密一致。
   */
  const resetTo = async (pass, historyPasswords = []) => {
    const doc = await User.findById(userId).select('+password +passwordHistory');
    doc.password = pass;
    doc.passwordHistory = historyPasswords.map((p) => digestOf(p));
    await doc.save();
  };

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) await mongoose.connect(process.env.MONGODB_URI);
    const uniq = Date.now().toString(36);
    const user = await User.create({
      username: `reuse_${uniq}`,
      email: `reuse_${uniq}@example.invalid`,
      password: OLD,
      roles: [],
    });
    userId = user._id;
  });

  afterAll(async () => {
    await User.deleteOne({ _id: userId }, { bypassAppendOnly: true });
    if (mongoose.connection.readyState !== 0) await mongoose.disconnect();
  });

  test('A→B→A：第二步（A 作为新口令）必须被复用历史拒绝', async () => {
    await resetTo(OLD);
    // 第一步：OLD → NEW。旧口令 OLD 此时进入历史
    const first = await change(OLD, NEW);
    expect(first.outcome).toBe('OK');

    // 第二步：NEW → OLD。OLD 不是当前口令（当前是 NEW），SAME_PASSWORD 挡不住，
    // 必须由复用历史挡住 —— 这正是本条用例存在的意义
    const second = await change(NEW, OLD);
    expect(second.outcome).toBe('PASSWORD_REUSED');
    expect(second.historyDepth).toBe(HISTORY_DEPTH);

    // 且口令确实没变（拒绝路径不得留下任何写入）
    const after = await User.findById(userId).select('+password +passwordHistory');
    expect(await after.comparePassword(NEW)).toBe(true);
  });

  test('拒绝时不写历史（否则一次被拒的尝试会污染历史，把合法口令也挡掉）', async () => {
    await resetTo(NEW, [OLD]);
    const before = await User.findById(userId).select('+passwordHistory');
    const depthBefore = before.passwordHistory.length;
    await change(NEW, OLD);
    const after = await User.findById(userId).select('+passwordHistory');
    expect(after.passwordHistory.length).toBe(depthBefore);
  });

  test('与当前口令相同仍报 SAME_PASSWORD（不复用码——两者是不同的事）', async () => {
    await resetTo(NEW, [OLD]);
    const r = await change(NEW, NEW);
    expect(r.outcome).toBe('SAME_PASSWORD');
  });

  test('全新口令正常通过，且旧口令进入历史', async () => {
    await resetTo(NEW, [OLD]);
    const r = await change(NEW, NEWER);
    expect(r.outcome).toBe('OK');
    const after = await User.findById(userId).select('+password +passwordHistory');
    expect(await after.comparePassword(NEWER)).toBe(true);
    expect(matchesHistory(after.passwordHistory, NEW)).toBe(true);
    expect(after.passwordHistory.length).toBeLessThanOrEqual(HISTORY_DEPTH);
  });

  test('超出深度的更早口令不再被拦（边界是"最近 N 条"，不是永久）', async () => {
    // 确定态：当前 = NEWER，历史里确有 OLD（等下要验证它会被挤出窗口）
    await resetTo(NEWER, [NEW, OLD]);
    // 把历史灌到超过深度，让 OLD 掉出窗口
    const doc = await User.findById(userId).select('+password +passwordHistory');
    // 逐条折叠（不能把数组一次性传给 withPrevious —— digestOf 只认字符串，
    // 传数组会静默返回 null，于是历史原样不变，这条用例会假绿）
    let hist = doc.passwordHistory;
    for (let i = 0; i < HISTORY_DEPTH; i += 1) hist = withPrevious(hist, `Fill${i}!Aa1`);
    doc.passwordHistory = hist;
    await doc.save();
    expect(matchesHistory(doc.passwordHistory, OLD)).toBe(false);

    const r = await change(NEWER, OLD);
    // OLD 已掉出窗口 ⇒ 放行。这条钉的是边界语义本身，
    // 免得日后有人把"最近 N 条"改成"全部历史"而无人察觉
    expect(r.outcome).toBe('OK');
  });
});
