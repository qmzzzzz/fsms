/**
 * 业务级指标（2026-09-02 综合评估 P3）：登录成功率与 MFA 管理动作
 *
 * - 单元：incLoginAttempt / incMfaAction 计数、Prometheus 文本渲染、
 *   getSnapshot().business（含 loginSuccessRate 计算）
 * - 集成：真实登录失败请求经 authController.login 落入
 *   auth_login_total{result="failure"}——证明埋点接线生效而非死代码
 */

const request = require('supertest');
const mongoose = require('mongoose');
const metrics = require('../../utils/metrics');

describe('业务级指标', () => {
  describe('计数与渲染（单元）', () => {
    beforeEach(() => {
      metrics._loginCounters.clear();
      metrics._mfaCounters.clear();
    });

    test('登录结果计数并渲染为 auth_login_total', () => {
      metrics.incLoginAttempt('success');
      metrics.incLoginAttempt('success');
      metrics.incLoginAttempt('failure');
      metrics.incLoginAttempt('mfa_challenge');

      const text = metrics.formatPrometheus();
      expect(text).toContain('# TYPE auth_login_total counter');
      expect(text).toMatch(/auth_login_total\{result="success"\} 2/);
      expect(text).toMatch(/auth_login_total\{result="failure"\} 1/);
      expect(text).toMatch(/auth_login_total\{result="mfa_challenge"\} 1/);
    });

    test('MFA 动作计数并渲染为 auth_mfa_total', () => {
      metrics.incMfaAction('enable');
      metrics.incMfaAction('disable');
      metrics.incMfaAction('enable');

      const text = metrics.formatPrometheus();
      expect(text).toContain('# TYPE auth_mfa_total counter');
      expect(text).toMatch(/auth_mfa_total\{action="enable"\} 2/);
      expect(text).toMatch(/auth_mfa_total\{action="disable"\} 1/);
    });

    test('snapshot.business：结果分布 + 成功率（mfa_challenge 计入分母不计入分子）', () => {
      metrics.incLoginAttempt('success');
      metrics.incLoginAttempt('failure');
      metrics.incLoginAttempt('mfa_challenge');
      metrics.incMfaAction('recovery_regenerate');

      const snap = metrics.getSnapshot();
      expect(snap.business.login).toEqual(
        expect.arrayContaining([
          { result: 'success', count: 1 },
          { result: 'failure', count: 1 },
          { result: 'mfa_challenge', count: 1 },
        ])
      );
      expect(snap.business.loginSuccessRate).toBeCloseTo(1 / 3, 4);
      expect(snap.business.mfa).toEqual([{ action: 'recovery_regenerate', count: 1 }]);
    });

    test('无数据时成功率为 0 而非 NaN', () => {
      const snap = metrics.getSnapshot();
      expect(snap.business.login).toEqual([]);
      expect(snap.business.loginSuccessRate).toBe(0);
    });
  });

  describe('登录链路埋点（集成）', () => {
    let app;

    beforeAll(async () => {
      if (mongoose.connection.readyState === 0) {
        await mongoose.connect(process.env.MONGODB_URI);
      }
      require('../../models/User');
      const { createApp } = require('../../app');
      app = createApp();
    });

    afterAll(async () => {
      if (mongoose.connection.readyState !== 0) {
        await mongoose.connection.close();
      }
    });

    test('登录失败请求计入 auth_login_total{result="failure"}', async () => {
      const key = 'result="failure"';
      const before = metrics._loginCounters.get(key) || 0;

      const res = await request(app)
        .post('/api/auth/login')
        .send({ username: 'nosuchuser_metrics_probe', password: 'Whatever123!xyz' });
      // 无论走凭据错误还是验证码前置拦截，都属 failure 桶
      expect(res.status).toBeGreaterThanOrEqual(400);
      expect(res.status).toBeLessThan(500);

      const after = metrics._loginCounters.get(key) || 0;
      expect(after).toBe(before + 1);
    });
  });
});
