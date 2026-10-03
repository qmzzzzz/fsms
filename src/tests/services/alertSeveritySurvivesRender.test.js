/**
 * F-212（Lane Z 提出、我方复测确认）：安全告警**自身的等级**不能搭在 winston 的保留字段上。
 *
 * `securityAlertDelivery.js` 把 `level` 放进 meta 对象：`logger[logMethod]('SECURITY_ALERT', payload)`。
 * winston 的 `log(level, msg)` 在 msg 是对象时会把这个对象的 `level` 覆盖成分派级别，
 * 而两种版式都因此丢掉告警等级：
 *  - 生产 jsonFormat：落盘 `"level":"error"`（critical 这个字面串整行消失）；
 *  - dev/test printfLayout（`src/utils/logger.js:115`）：`level` 被解构进 `[error]` 前缀，
 *    meta 里连这个键都不剩。
 * 后果：webhook 关掉 / 被级别过滤 / 被白名单拒掉时，**文件日志是唯一的取证通道**，
 * 而 ELK 上 `SECURITY_ALERT AND level:critical` 这类规则永远不会命中；
 * 更要紧的是 `low` 与 `medium` 都映射到 `info`（`securityAlertDelivery.js:156`），
 * 落盘之后**字面上不可区分**。
 *
 * 修法：告警等级另立键名 `alertLevel`，分派级别仍按原逻辑走 winston 的 `level`。
 *
 * 探针用**真 transport + 真 logger 单例**（不是 spy 调用参数），因为要钉的性质是
 * "渲染出来的那一行里到底有没有 critical"，spy 只能证明"传进去了"。
 */

const winston = require('winston');
const { Writable } = require('stream');
const logger = require('../../utils/logger');
// 直接钉投递模块本身：它才是 `level` 键的写入方，也是本次修法的落点。
// 不绕 securityAlert（那里只 re-export，却会牵进 AuditLog/mongoose 与频控表）。
const { sendNotification } = require('../../services/securityAlertDelivery');

/**
 * 轮询等 transport 真的落行，而不是拍一个"应该刷完了"的定长延时，
 * 也不是调 `logger.flush`（winston 3.11 的 Logger 上根本没有这个方法，
 * 写出来就是 `TypeError`，红在脚手架而不是红在性质上）。
 * 超时不是通过：宁可红也不要"还没落盘就断言空数组"的假绿。
 */
const waitForRecords = async (records, expected, timeoutMs = 2000) => {
  const deadline = Date.now() + timeoutMs;
  while (records.length < expected) {
    if (Date.now() > deadline) {
      throw new Error(`等待日志 transport 落行超时：已收到 ${records.length}/${expected} 条`);
    }
    await new Promise((resolve) => setImmediate(resolve));
  }
};

/** 把 logger 刷干净并取回本条告警渲染出的记录（键名/值都按 transport 实际所见） */
async function captureRecords(emit, expected = 1) {
  const records = [];
  const stream = new Writable({
    write(chunk, _enc, cb) {
      try {
        records.push(JSON.parse(String(chunk)));
      } catch (_) {
        records.push({ unparsed: String(chunk) });
      }
      cb();
    },
  });
  const transport = new winston.transports.Stream({ stream, format: winston.format.json() });
  logger.add(transport);
  const savedWebhook = process.env.SECURITY_ALERT_WEBHOOK;
  delete process.env.SECURITY_ALERT_WEBHOOK; // 本用例只关日志通道，不出网
  try {
    await emit();
    await waitForRecords(records, expected);
  } finally {
    logger.remove(transport);
    if (savedWebhook !== undefined) process.env.SECURITY_ALERT_WEBHOOK = savedWebhook;
  }
  return records;
}

describe('F-212 安全告警等级在日志行里必须活着', () => {
  test('critical 告警渲染出的记录必须带着 critical（winston 的 level 键会被分派级别占掉）', async () => {
    const records = await captureRecords(() =>
      sendNotification('brute_force_login', 'critical', '探针：口令爆破')
    );
    expect(records).toHaveLength(1);
    const rec = records[0];
    // 前提自证：winston 确实占用了 `level`（否则本用例是在测一个根本不存在的冲突，
    // 一旦哪天 winston 改了语义，这条会红并要求重新审视修法，而不是静默失效）
    expect(rec.level).toBe('error');
    expect(JSON.stringify(rec)).toContain('critical');
    expect(rec.alertLevel).toBe('critical');
    expect(rec.type).toBe('brute_force_login');
  });

  // 两条告警**串行**捕获：transport 挂在 logger 单例上是全局的，
  // 并发跑会让第二条的记录混进第一条的数组，届时长断言与索引断言测的都是脚手架竞态。
  test('low 与 medium 不得在落盘后不可区分（两者分派级别同为 info）', async () => {
    const [low] = await captureRecords(() =>
      sendNotification('unusual_time_access', 'low', '探针 low')
    );
    const [medium] = await captureRecords(() =>
      sendNotification('unusual_time_access', 'medium', '探针 medium')
    );
    // 反向对照：分派级别确实相同 ⇒ 唯一的区分度只能来自 alertLevel
    expect(low.level).toBe('info');
    expect(medium.level).toBe('info');
    expect(low.alertLevel).toBe('low');
    expect(medium.alertLevel).toBe('medium');
    expect(low.alertLevel).not.toBe(medium.alertLevel);
  });
});
