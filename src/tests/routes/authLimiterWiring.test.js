/**
 * 认证/导出凭据端点的中间件接线门禁（审计 2026-11-15）
 *
 * 三处修复都是"链上顺序/成员"问题，行为用例（authRest 的 MFA 边界、
 * reportPiiExportStepUp）已经覆盖结果；本文件从 Express 路由器自身枚举链，
 * 钉住**接线形状**，防止未来"整理代码"时把限流器/校验链挪丢：
 *   ① GET /auth/session 必须挂 strictLimiter（未认证可达且打库的端点，
 *      此前是认证面唯一没有专属限流桶的端点）；
 *   ② POST /mfa/enable 的 mfaCode 格式闸（rejectMalformedMfaCode）必须位于
 *      requireReAuthentication **之前**——格式非法的码不得先烧共享 MFA 失败锁；
 *   ③ POST /mfa/enroll 与 POST /reports/export/pii 必须挂 reauthCredentialValidation
 *      （encCurrentPassword 长度闸在解密前生效）+ consumeValidation（不消费=装饰）。
 */

const authRoutes = require('../../routes/authRoutes');
const reportRoutes = require('../../routes/reportRoutes');

/** 取 router 里 (method, path) 命中的路由层；返回该路由自己的中间件链 */
const routeChain = (router, method, path) => {
  for (const layer of router.stack || []) {
    if (!layer.route) continue;
    if (layer.route.path === path && layer.route.methods[method.toLowerCase()]) {
      return layer.route.stack;
    }
  }
  return null;
};

describe('认证面限流/凭据校验接线门禁（审计 2026-11-15）', () => {
  test('GET /auth/session 必须挂专属限流桶（strictLimiter），不再是裸控制器', () => {
    const chain = routeChain(authRoutes, 'GET', '/session');
    expect(chain).toBeTruthy();
    // strictLimiter + 控制器：至少两层。退化成裸控制器（链长 1）即红。
    expect(chain.length).toBeGreaterThanOrEqual(2);
  });

  test('POST /mfa/enable：mfaCode 格式闸必须先于 requireReAuthentication', () => {
    const chain = routeChain(authRoutes, 'POST', '/mfa/enable');
    expect(chain).toBeTruthy();
    // 形状：authenticate → strictLimiter → rejectMalformedMfaCode → requireReAuthentication → 控制器
    // 审计 2026-11-17（主题 G）：链长只设下界——精确相等会把未来插入行为等价的透传
    // 中间件误判为红。必需中间件改为逐一在场识别：
    //   · authenticate / strictLimiter 按**同一模块导出的函数引用**识别（引用比对对
    //     asyncHandler 之类包装免疫）；
    //   · rejectMalformedMfaCode 是 authRoutes 的模块内常量，外部拿不到引用，按函数名识别。
    const { authenticate } = require('../../middleware/auth');
    const { strictLimiter } = require('../../middleware/rateLimit');
    const handles = chain.map((layer) => layer.handle);
    expect(handles).toContain(authenticate);
    expect(handles).toContain(strictLimiter);
    expect(chain.map((layer) => layer.name)).toContain('rejectMalformedMfaCode');
    // 末位是控制器；格式闸与控制器之间必须至少隔着二次验证闸那一层
    // （requireReAuthentication() 返回匿名闭包、控制器经 asyncHandler 包装，均无法按名
    // 识别，按位置认：格式闸下标 ≤ 链长-3 ⇒ 其后至少还有 2 层）。
    const gateIdx = chain.findIndex((layer) => layer.name === 'rejectMalformedMfaCode');
    expect(gateIdx).toBeGreaterThanOrEqual(0);
    expect(gateIdx).toBeLessThanOrEqual(chain.length - 3);
    expect(chain.length).toBeGreaterThanOrEqual(5);
  });

  test('POST /mfa/enroll：必须挂 reauthCredentialValidation + consumeValidation', () => {
    const chain = routeChain(authRoutes, 'POST', '/mfa/enroll');
    expect(chain).toBeTruthy();
    // authenticate → strictLimiter → 3 个凭据校验器 → consumeValidation → reauth → 控制器
    expect(chain.length).toBeGreaterThanOrEqual(8);
  });

  test('POST /reports/export/pii：必须挂 reauthCredentialValidation + consumeValidation', () => {
    const chain = routeChain(reportRoutes, 'POST', '/export/pii');
    expect(chain).toBeTruthy();
    // authenticate → type 闸 → 3 个限流器 → 2 个权限 → 配额闸 → 3 个凭据校验器
    // → consumeValidation → reauth → 控制器
    expect(chain.length).toBeGreaterThanOrEqual(12);
  });
});
