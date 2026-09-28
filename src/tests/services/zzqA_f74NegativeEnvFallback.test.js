/**
 * 收口用例：数值型环境变量的负值不得被原样采纳
 *
 * 根因自证（不依赖任何被测模块，先把"为什么以前会错"钉住）：
 *   `Number('-1') || 10000 === -1` —— 负值是真值，`||` 兜不住它。
 * 实测过的后果：AUDIT_BUFFER_HARD_LIMIT=-1 时 push 5 条丢 10 条、缓冲被清空，
 * 审计记录停止落库（只剩 WAL）。
 *
 * ⚠ 加载期读取的常量要断言告警，必须先 jest.resetModules()、
 * 拿到**本代** logger 装上 spy，**再** require 被测模块；顺序反了值断言会过、
 * 日志断言永远听不到那一声。
 */

const ENV_CASES = [
  { name: 'AUDIT_BUFFER_HARD_LIMIT', bad: '-1' },
  { name: 'AUDIT_BUFFER_HARD_LIMIT', bad: '0' },
  { name: 'AUDIT_BUFFER_HARD_LIMIT', bad: 'abc' },
  { name: 'AUDIT_BUFFER_HARD_LIMIT', bad: '1.5' }, // integer:true 也必须拒
  { name: 'AUDIT_BUFFER_HARD_LIMIT', bad: '-9e99' }, // -Infinity
];

/** 在指定 env 下重载模块，返回模块与本次加载期 logger.error/warn 文本 */
const reloadWithEnv = (envName, value, modPath) => {
  jest.resetModules();
  const saved = process.env[envName];
  if (value === undefined) delete process.env[envName];
  else process.env[envName] = value;
  const logger = require('../../utils/logger');
  const errors = [];
  const warns = [];
  jest.spyOn(logger, 'error').mockImplementation((...a) => errors.push(a.join(' ')));
  jest.spyOn(logger, 'warn').mockImplementation((...a) => warns.push(a.join(' ')));
  const mod = require(modPath);
  if (saved === undefined) delete process.env[envName];
  else process.env[envName] = saved;
  return { mod, errors, warns };
};

describe('非法数值 env ⇒ 回落默认 + 运维可见告警', () => {
  afterEach(() => jest.restoreAllMocks());

  test('根因自证：负值是真值，`|| 默认值` 兜不住', () => {
    expect(Number('-1') || 10000).toBe(-1);
    expect(Number('abc') || 10000).toBe(10000); // 只有 NaN 才被 || 兜住——这就是旧写法的盲区
  });

  test.each(ENV_CASES)('AUDIT_BUFFER_HARD_LIMIT=%s ⇒ 回落 10000 并告警', async ({ bad }) => {
    const { mod, errors } = reloadWithEnv(
      'AUDIT_BUFFER_HARD_LIMIT',
      bad,
      '../../services/auditBuffer'
    );
    expect(mod.getStats().hardLimit).toBe(10000);
    expect(errors.join('\n')).toContain('AUDIT_BUFFER_HARD_LIMIT');
    expect(errors.join('\n')).toContain('非法');
  });

  test('合法正整数仍被采纳（防"改成恒用默认值"混过上面的用例）', () => {
    const { mod, errors } = reloadWithEnv(
      'AUDIT_BUFFER_HARD_LIMIT',
      '250',
      '../../services/auditBuffer'
    );
    expect(mod.getStats().hardLimit).toBe(250);
    expect(errors).toHaveLength(0);
  });

  test('未设置该 env ⇒ 静默用默认，不该制造噪音告警', () => {
    const { mod, errors } = reloadWithEnv(
      'AUDIT_BUFFER_HARD_LIMIT',
      undefined,
      '../../services/auditBuffer'
    );
    expect(mod.getStats().hardLimit).toBe(10000);
    expect(errors).toHaveLength(0);
  });

  test('负值不再丢弃缓冲：push 5 条后 buffer 仍在、droppedCount=0', async () => {
    const { mod } = reloadWithEnv('AUDIT_BUFFER_HARD_LIMIT', '-1', '../../services/auditBuffer');
    const doc = () => ({
      action: 'test',
      module: 'audit',
      result: 'success',
      timestamp: new Date(),
      userId: null,
      details: {},
    });
    for (let i = 0; i < 5; i++) mod.push(doc());
    const s = mod.getStats();
    // 修复前实测：droppedCount 随每次 push 增长（5 推 10 丢）、缓冲被 splice 空
    expect(s.droppedCount).toBe(0);
    expect(s.bufferLength).toBe(5);
  });

  test('securityAlert 侧同判据：ALERT_RATE_LIMIT_MAX=-1 ⇒ 回落默认且留下 error 告警', () => {
    const { mod, errors } = reloadWithEnv(
      'ALERT_RATE_LIMIT_MAX',
      '-1',
      '../../services/securityAlert'
    );
    expect(mod).toBeTruthy();
    const text = errors.join('\n');
    expect(text).toContain('ALERT_RATE_LIMIT_MAX');
    expect(text).toContain('非法');
  });
});
