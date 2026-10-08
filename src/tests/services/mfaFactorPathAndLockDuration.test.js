/**
 * ──────────────────────────────────────────────────────────────────────────
 * 被测对象：mfaService.resolveMfaFactorPaths / mfaService.recordMfaFailure
 * 守护的不变式：
 *   A. 身份路径选择器只返回原始布尔，返回值里不得携带口令明文；
 *   B. 「锁了多久」这句话（warn 载荷 lockMinutes + 审计 reason 里的分钟数）
 *      必须与真正写进 mfaLockUntil 的那个时长同源。
 * 可证伪性：见文件末「变异实测」注释；A 组在修复前直接转红，B 组靠常量漂移转红。
 * ──────────────────────────────────────────────────────────────────────────
 *
 * A 组的成因不是风格问题：`!codePath && typeof x === 'string' && x` 的求值结果是
 * **最后一个操作数**，也就是登录口令明文字符串本身。字段名叫 passwordPath、类型
 * 看着像布尔，现网调用方（controllers/mfaController.js:321）又只做真值判断，所以
 * 分支行为一直是对的——"目前没造成故障"不构成放行理由：这个对象一旦被记日志、
 * 进审计载荷或回给前端（没人会怀疑一个叫 *Path 的字段），口令就明文出现在那里。
 *
 * B 组原先是三处各抄一遍同一句话：真正生效的是 `new Date(Date.now() + MFA_LOCK_MS)`，
 * 而 warn 载荷写 `lockMinutes: 10`、审计 reason 写死"10 分钟"。今天三者数值相同，
 * 所以任何"值相等"的断言都区分不了实现与抄本——本文件的判据是**比对**：
 * 从写入给 User 集合的那条更新里量出真实时长，再要求留痕里的数字等于量出来的值。
 * 于是改动 MFA_LOCK_MS 而忘改文案时立刻转红（第 5–7 条），而抄本恰好同值时它不红
 * ——这条残余如实写明，不用文本匹配去伪装成更强的判据（按文本判式的门禁本身
 * 就是"判据什么都不判却报绿"的那一族）。
 *
 * 全部用例都不碰数据库：User/AuditLog/logger 三个依赖整体替身，recordMfaFailure
 * 的调用链形状按现网写法桩（计数那条 `findByIdAndUpdate(...).select().catch()`、
 * 锁定那条 `findByIdAndUpdate(...).catch()`）——桩的形状与真实链式不一致时
 * TypeError 会伪装成"降级路径已测"。
 */

jest.mock('../../models/User', () => ({
  findByIdAndUpdate: jest.fn(),
}));
jest.mock('../../models/AuditLog', () => ({
  record: jest.fn(() => Promise.resolve(null)),
}));
jest.mock('../../utils/logger', () => ({
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
}));

const User = require('../../models/User');
const AuditLog = require('../../models/AuditLog');
const logger = require('../../utils/logger');
const mfaService = require('../../services/mfaService');

const PASSWORD = 'correct-horse-battery-including';

/** 计数那条调用带第三个参数（{new:true}）；锁定那条没有——按这个形状分流 */
const mockCounterAndLock = ({ counterValue, counterError }) => {
  User.findByIdAndUpdate.mockImplementation((id, patch, opts) => {
    const settled = counterError
      ? Promise.reject(new Error(counterError))
      : Promise.resolve(counterValue);
    if (opts) return { select: () => ({ catch: (h) => settled.catch(h) }) };
    return { catch: (h) => settled.catch(h) };
  });
};

/** 从"锁定"那条更新里量出真实锁定时长（分钟），并与留痕里声称的值比对 */
const measuredLockMinutes = () => {
  const lockCall = User.findByIdAndUpdate.mock.calls.find((c) => c[2] === undefined);
  if (!lockCall) throw new Error('没有发出锁定写入：本条判据将无从比对（不得当作通过）');
  const lockUntil = lockCall[1].mfaLockUntil;
  if (!(lockUntil instanceof Date)) {
    throw new Error(`mfaLockUntil 不是 Date（实际 ${String(lockUntil)}）：写入形状变了`);
  }
  return Math.round((lockUntil.getTime() - Date.now()) / 60000);
};

describe('mfaService 身份路径选择器：只返回原始布尔，且不携带口令', () => {
  const { resolveMfaFactorPaths } = mfaService;

  test('给了 6 位动态口令 ⇒ codePath 为 true、passwordPath 严格 false（不是空串/不是字符串）', () => {
    expect(resolveMfaFactorPaths('123456', PASSWORD)).toEqual({
      codePath: true,
      passwordPath: false,
    });
  });

  test('没给码、有登录密码 ⇒ passwordPath 必须是布尔 true，而不是那句口令本身', () => {
    const paths = resolveMfaFactorPaths('', PASSWORD);
    expect(paths.passwordPath).toBe(true);
    expect(typeof paths.passwordPath).toBe('boolean');
  });

  test('返回值任何一层都不得出现口令明文（字段名看着像布尔，扩散时没人会犹豫）', () => {
    // 必须走**没有 6 位码**的那条臂：给了码就进 codePath，passwordPath 恒 false，
    // 这条断言在修复前的实现上也会绿（写这条时发现并改正——它是"看着严格却不可证伪"的形状）
    const paths = resolveMfaFactorPaths('', PASSWORD);
    const serialized = JSON.stringify(paths);
    expect(serialized).not.toContain(PASSWORD);
    // 遍历值而不是只看 JSON：undefined/NaN 在 JSON.stringify 里会被丢掉，
    // 只看串会漏掉"值就是那个字符串但键名没进串"的形状
    for (const value of Object.values(paths)) {
      expect(value === PASSWORD).toBe(false);
    }
  });

  test('空串口令 ⇒ 两条路径都 false（旧实现返回空串：falsy 但不是布尔）', () => {
    expect(resolveMfaFactorPaths('not-a-code', '')).toEqual({
      codePath: false,
      passwordPath: false,
    });
  });

  test('非字符串口令 / 非 6 位码 ⇒ 不因类型外输入而放行（反向自查：判据不是只认哨兵值）', () => {
    expect(resolveMfaFactorPaths(undefined, undefined)).toEqual({
      codePath: false,
      passwordPath: false,
    });
    expect(resolveMfaFactorPaths('12345', PASSWORD).codePath).toBe(false);
    expect(resolveMfaFactorPaths('1234567', PASSWORD).codePath).toBe(false);
    expect(resolveMfaFactorPaths({ toString: () => '123456' }, PASSWORD).codePath).toBe(false);
  });
});

describe('mfaService 防爆破锁定：留痕里声称的时长必须等于真正写进库的时长', () => {
  const user = { _id: '64f000000000000000000001', username: 'alice' };

  beforeEach(() => {
    jest.clearAllMocks();
  });

  test('达阈值锁定：warn 的 lockMinutes 与审计 reason 的分钟数都来自同一次写入', async () => {
    mockCounterAndLock({ counterValue: { mfaFailCount: 5 } });
    await mfaService.recordMfaFailure(user);

    const measured = measuredLockMinutes();
    // 先钉住"确实量到了一个正数"，否则比对可能在两边都拿到 undefined 时空转成绿
    expect(measured).toBeGreaterThan(0);

    const warnCall = logger.warn.mock.calls.find((c) => c[0] === 'MFA 验证触发临时锁定');
    if (!warnCall) throw new Error('没有写下锁定留痕：本条判据将无从比对（不得当作通过）');
    expect(warnCall[1].lockMinutes).toBe(measured);

    const auditCall = AuditLog.record.mock.calls.find((c) => c[0].action === 'mfa_attempt_locked');
    if (!auditCall) throw new Error('没有落审计：本条判据将无从比对（不得当作通过）');
    expect(auditCall[0].reason).toContain(`临时锁定 ${measured} 分钟`);
  });

  test('计数写不进库的那条臂（另一句 reason 文案）同样按实测时长写', async () => {
    mockCounterAndLock({ counterError: 'db down' });
    await mfaService.recordMfaFailure(user);

    const measured = measuredLockMinutes();
    expect(measured).toBeGreaterThan(0);

    const auditCall = AuditLog.record.mock.calls.find((c) => c[0].action === 'mfa_attempt_locked');
    if (!auditCall) throw new Error('计数故障臂没有落审计：不得当作通过');
    expect(auditCall[0].reason).toContain(`锁定验证通道 ${measured} 分钟`);
    // 这条臂里 failedCount 必须缺席：记不上计数时宁可缺字段也不写没发生过的数字
    const warnCall = logger.warn.mock.calls.find((c) => c[0] === 'MFA 验证触发临时锁定');
    expect(warnCall[1].failedCount).toBeUndefined();
    expect(warnCall[1].lockMinutes).toBe(measured);
  });

  test('未达阈值时不得锁定，也不得写下"已锁定"的留痕（防上面两条被无条件放行路径喂绿）', async () => {
    mockCounterAndLock({ counterValue: { mfaFailCount: 1 } });
    await mfaService.recordMfaFailure(user);

    expect(User.findByIdAndUpdate.mock.calls.filter((c) => c[2] === undefined)).toEqual([]);
    expect(logger.warn.mock.calls.filter((c) => c[0] === 'MFA 验证触发临时锁定')).toEqual([]);
    expect(AuditLog.record.mock.calls).toEqual([]);
  });
});

/**
 * 变异实测（2026-10-03，tools/ledger.js：先写预测再跑，台账见 tools/ledger-mfaFactorPathAndLockDuration.json）
 *  ① `passwordPath` 退回 `&& currentPassword`（修复前形状）
 *      ⇒ 实测红 3 条：第 2 条（必须是布尔 true）、第 3 条（明文不得出现）、第 4 条（空串要 false）；
 *        预测红 3 条——与实测逐条一致。第 1、5 条照常绿（它们不是为此而写的）。
 *  ② `lockMinutes: 11`（把留痕改成抄本）⇒ 实测红 2 条：第 6、7 条（两条臂都比对 warn 载荷）。
 *  ③ 达阈值那条 reason 写死"11 分钟" ⇒ 实测只有第 6 条红。
 *  ④ 计数故障那条 reason 写死"11 分钟" ⇒ 实测只有第 7 条红。
 * 四条变异全被杀，预测 0 处失配；台账结束时 sha256 校验 mfaService.js 与开始时逐字节相同。
 *
 * 残余（如实记录，不用文本匹配伪装成更强判据）：抄本与常量**同值**时第 6–7 条区分不了，
 * 它们的杀伤力来自"声称与实测脱钩"这一事件本身（改常量忘改文案、或文案被另行硬编码）。
 * 另外第 3 条最初写成 `resolveMfaFactorPaths('000000', PASSWORD)`——那是 6 位码，
 * 走 codePath 臂，passwordPath 在修复前后都是 false，等于一条不可证伪的断言；
 * 已改成无码臂。这条弯路正是第 4 族（断言无法被证伪）的现场样本。
 */
