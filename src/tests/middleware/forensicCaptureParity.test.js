/**
 * 对拍（P2 验收硬性项）：捕获能力 开 / 关 / 抛错 三态下，
 * 客户端可见的响应与既有审计行为逐字不变。
 *
 * 判据不是"看起来一样"，而是**字节级**：
 *  ① 响应侧：status / content-type / 正文逐字相等（与不装捕获中间件时相比）；
 *  ② 审计侧：auditBuffer.push 收到的文档在剥掉必然变化的字段
 *     （_id、__walSeq、duration）后 JSON 逐字相等——捕获管道存在的唯一可观测
 *     差异只允许出现在 ForensicCapture 自己的集合里，不得溢到 AuditLog。
 *
 * 四态（关、开但未标记、开且标记、触发判据抛错）跑同一条请求，两两对比。
 */

const express = require('express');
const request = require('supertest');

const mockState = { on: false, throws: false, off: false };
jest.mock('../../services/forensicTrigger', () => ({
  isForensicTarget: () => {
    if (mockState.throws) throw new Error('trigger boom');
    return mockState.on;
  },
  getForensicTarget: () =>
    mockState.on ? { reason: 'honeypot_login', markedAt: new Date(0) } : null,
}));
jest.mock('../../models/ForensicCapture', () => ({ insertMany: jest.fn(async () => ({})) }));

const auditBuffer = require('../../services/auditBuffer');
const service = require('../../services/forensicCapture');
const { auditLog } = require('../../middleware/security');
const { forensicCapture } = require('../../middleware/security/forensicCapture');

const spyPush = jest.spyOn(auditBuffer, 'push');
const tick = () => new Promise((resolve) => setImmediate(resolve));

/** 必然变化或与业务无关的字段：剥掉后才允许做"逐字"比较 */
const VOLATILE = ['_id', '__walSeq', 'duration'];
const scrub = (doc) => {
  const copy = JSON.parse(JSON.stringify(doc));
  for (const k of VOLATILE) delete copy[k];
  return copy;
};

const runOnce = async () => {
  spyPush.mockClear();
  const app = express();
  app.use(express.json());
  app.use('/api/', auditLog());
  app.use('/api/', forensicCapture());
  app.post('/api/probe', (req, res) => res.status(201).json({ ok: true, got: req.body.x }));
  const res = await request(app)
    .post('/api/probe')
    .set('user-agent', 'parity-agent/1')
    // 每次 request(app) 都会起新监听端口，host 头随附端口必然不同；钉死才能做逐字对拍。
    .set('host', 'parity.example')
    .set('x-forwarded-for', '203.0.113.7')
    .send({ x: 7, password: 'S3NTINEL-PW-7f3a9c' });
  await tick();
  const docs = spyPush.mock.calls.map(([doc]) => doc).filter(Boolean);
  return {
    status: res.status,
    contentType: res.headers['content-type'],
    text: res.text,
    audit: docs.map(scrub),
  };
};

describe('捕获开/关/抛错三态：请求与审计行为逐字不变', () => {
  beforeEach(() => {
    service.resetForTests();
    mockState.on = false;
    mockState.throws = false;
  });

  test('四态对拍：响应字节相同、审计文档（剥易变字段后）逐字相同', async () => {
    // 态 1：捕获关闭（env 开关）
    process.env.FORENSIC_CAPTURE_ENABLED = 'false';
    const off = await runOnce();
    process.env.FORENSIC_CAPTURE_ENABLED = 'true';
    // 态 2：捕获开启但 IP 未被标记 ⇒ 与关闭态应当没有差异
    const unmarked = await runOnce();
    // 态 3：捕获开启且被标记（真捕获）
    mockState.on = true;
    const marked = await runOnce();
    // 态 4：触发判据抛错（降级路径）
    mockState.on = true;
    mockState.throws = true;
    const throwing = await runOnce();
    mockState.throws = false;

    const baselineAudit = JSON.stringify(off.audit);
    expect(baselineAudit).not.toBe('[]'); // 防"两边都空"的假对拍

    for (const [name, run] of [
      ['未标记', unmarked],
      ['已标记', marked],
      ['触发抛错', throwing],
    ]) {
      expect({ name, status: run.status }).toEqual({ name, status: off.status });
      expect({ name, ct: run.contentType }).toEqual({ name, ct: off.contentType });
      expect({ name, text: run.text }).toEqual({ name, text: off.text });
      expect({ name, audit: JSON.stringify(run.audit) }).toEqual({ name, audit: baselineAudit });
    }
    // 反向对照：捕获自身的产物必须只在第 3 态出现（否则"对拍"根本没覆盖捕获）
    expect(service.getForensicCaptureStats().captured).toBeGreaterThan(0);
    expect(service.getForensicCaptureStats().rejected).toBeGreaterThan(0);
  });

  test('审计体脱敏不受捕获影响：口令明文在两种状态下都不出现', async () => {
    mockState.on = false;
    const unmarked = await runOnce();
    mockState.on = true;
    const marked = await runOnce();
    for (const run of [unmarked, marked]) {
      const dumped = JSON.stringify(run.audit);
      expect(dumped).not.toContain('S3NTINEL-PW-7f3a9c');
      expect(run.audit[0].body.password).toBe('***');
    }
  });
});
