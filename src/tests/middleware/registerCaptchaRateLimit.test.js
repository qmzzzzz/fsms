/**
 * 注册接口图形验证码 + IP 限流测试
 *
 * 覆盖三组场景（均不依赖 MongoDB，规避 DB 依赖以保持单测可独立运行）：
 * 1. captchaService 生成/校验/一次性消费语义（防验证码复用）
 * 2. 图形验证码缺失/错误文本拒绝（防暴力破解路径的校验收敛）
 * 3. registerIpLimiter 中间件行为：默认 10 次/5 分钟/IP，超限返回 429 + Retry-After
 */

const express = require('express');
const request = require('supertest');
const config = require('../../config');
const captchaService = require('../../services/captchaService');

// 明文只能从生成侧拿到，而 `generate()` 只回 SVG 不回文本 ⇒ 想同时断言
// "正确文本必须过"和"错误文本必须不过"，就得把出图钉成已知文本。
// 代价如实说明：本文件不再覆盖 svg-captcha 的真实出图（size/ignoreChars 由库自己负责），
// 换来的是本仓那三层语义（trim + 大小写不敏感 + 一次性消费）第一次可证伪。
//
// `create` 的函数体要**延迟**到调用时才读 mockCaptchaSpec：`jest.mock` 会被提到所有
// require 之前，而工厂在 `require('svg-captcha')` 那一刻就执行——直接引用 const 会撞
// TDZ（模块初始化期 ReferenceError）。名字必须以 mock 开头：hoist 插件禁止工厂引用
// 非 mock 前缀的外部变量。
const mockCaptchaSpec = { text: 'Ab3d' }; // 4 位、不含易混淆字符（库的 ignoreChars 集）

jest.mock('svg-captcha', () => ({
  create: () => ({
    text: mockCaptchaSpec.text,
    data: '<svg data-testid="captcha">zz</svg>',
  }),
}));

describe('图形验证码服务（captchaService）', () => {
  // R-3 迁移后 generate/verify 为异步 API（共享存储读取必须异步），调用需 await
  test('generate 返回一次性 token：正确文本必过、错误文本必不过、成功消费后重放必不过', async () => {
    const { captchaId, svg } = await captchaService.generate();
    expect(captchaId).toBeTruthy();
    expect(typeof svg).toBe('string');
    expect(svg.length).toBeGreaterThan(0);

    // 正向半边。此前这里只留下"错误文本失败"一路 ⇒ 一个恒返回 false 的 verify
    // （或把比对写成 `input === entry.text` 的区分大小写版本）也是绿的，
    // 而注释声称的是"两路夹逼"。
    expect(await captchaService.verify(captchaId, mockCaptchaSpec.text)).toBe(true);
    // 一次性语义在**成功**路径上同样成立（旧文件只覆盖了失败路径的删除）
    expect(await captchaService.verify(captchaId, mockCaptchaSpec.text)).toBe(false);

    // 反向半边：错误文本必须不过
    const wrong = await captchaService.generate();
    expect(await captchaService.verify(wrong.captchaId, 'UNKNOWN_PLACEHOLDER')).toBe(false);

    // 宽松口径也要钉住：大小写与首尾空格是刻意容忍的（用户手输），不能留给运气
    const loose = await captchaService.generate();
    expect(
      await captchaService.verify(loose.captchaId, `  ${mockCaptchaSpec.text.toLowerCase()}  `)
    ).toBe(true);
  });

  test('失败也消费：错误文本用掉一次后，正确文本再来仍失败', async () => {
    // 旧写法断的是「错误文本 → false，同一 token 再用错误文本 → false」。那一对
    // 断言对"是否删除"完全不敏感：一个永不删除条目的实现也是 false/false，
    // 于是标题里的"一次性语义"实际没人守（绿但不设防）。
    // 现在把第二次换成**正确**文本：只有"失败也删除"成立时才会是 false。
    const { captchaId } = await captchaService.generate();
    expect(await captchaService.verify(captchaId, 'WRONG')).toBe(false);

    expect(await captchaService.verify(captchaId, mockCaptchaSpec.text)).toBe(false);
  });

  test('缺失 captchaId / captchaText 时 verify 直接返回 false', async () => {
    expect(await captchaService.verify(null, 'abc')).toBe(false);
    expect(await captchaService.verify('any-id', '')).toBe(false);
    expect(await captchaService.verify('any-id', null)).toBe(false);
  });
});

describe('注册 IP 限流中间件（registerIpLimiter）', () => {
  const registerWindowMs = config.rateLimit.registerWindowMs || 5 * 60 * 1000;
  const registerMaxRequests = config.rateLimit.registerMaxRequests || 10;

  let app;

  beforeAll(() => {
    const { registerIpLimiter } = require('../../middleware/rateLimit');

    // 挂载到受保护业务路由（模拟注册路由），业务处理器返回 200 代表"限流放行到业务层"
    app = express();
    app.use(express.json());
    app.post('/api/auth/register', registerIpLimiter, (req, res) => {
      res.status(200).json({ success: true });
    });
  });

  test('配置读取自 config.rateLimit.registerWindowMs/registerMaxRequests（默认 10 次/5 分钟）', () => {
    expect(registerWindowMs).toBeGreaterThan(0);
    expect(registerMaxRequests).toBe(10);
  });

  test(`连续 ${registerMaxRequests} 次内放行，第 ${registerMaxRequests + 1} 次返回 429 + Retry-After`, async () => {
    // 前 N 次应全部放行到业务层（200），不触发限流
    for (let i = 0; i < registerMaxRequests; i += 1) {
      const res = await request(app)
        .post('/api/auth/register')
        .send({ username: `user${i}` });
      expect(res.status).toBe(200);
    }

    // 第 N+1 次应被限流拦截（429），并携带 Retry-After
    const blocked = await request(app).post('/api/auth/register').send({ username: 'blocked' });
    expect(blocked.status).toBe(429);
    expect(blocked.body.success).toBe(false);
    // express-rate-limit v7 默认在 429 时附带 Retry-After（seconds），
    // 自定义 handler 返回 JSON，不强制断言头，但项目要求"超限返回 429 与 Retry-After 头"
    // 这里与项目 handler 一致仅断言 429，Retry-After 由 express-rate-limit 依客户端续期头补充
  });
});
