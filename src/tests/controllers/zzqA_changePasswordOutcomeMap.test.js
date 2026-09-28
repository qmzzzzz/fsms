/**
 * changePasswordSecure 的 outcome → HTTP 映射表（直调控制器，绕开路由体校验）
 *
 * 为什么必须直调：`PUT /api/security/change-password` 在控制器之前挂了
 * `changePasswordValidation`，缺字段的请求在那里就以 `VALIDATION_FAILED` 被拦下，
 * 因此控制器里 `case 'MISSING'` 这一支**经 HTTP 永远走不到**
 * （实测：传 `{}` 得到的是 VALIDATION_FAILED + currentPassword/newPassword 两条 fieldErrors）。
 * 覆盖率门禁报的正是这里——它不是"没测到"，而是"这条守卫没有任何契约保护"：
 * 若有人把码名写错、或把某个 case 删掉让它掉进 default，
 * 全仓没有任何测试会红（`PASSWORD_CURRENT_AND_NEW_REQUIRED` 此前在 src/tests 里 0 引用）。
 *
 * 所以本套件不走 HTTP，直接把 authService 换成可控返回值，逐条验证映射表的完整性：
 * 每个 outcome 必须落到它声明的那个错误码上，且不得静默变成 2xx。
 */

jest.mock('../../services/authService', () => ({
  changeUserPassword: jest.fn(),
}));

const authService = require('../../services/authService');
const securityController = require('../../controllers/securityController');

/** 最小 HTTP 替身：只记录 status 与 json 载荷，够断言映射结果 */
const mkRes = () => {
  const res = {
    locals: {},
    statusCode: 200,
    payload: null,
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(body) {
      this.payload = body;
      return this;
    },
    set() {
      return this;
    },
    header() {
      return this;
    },
  };
  return res;
};

const mkReq = () => ({
  user: { userId: '507f1f77bcf86cd799439011', username: 'zzqa-map' },
  body: {
    currentPassword: 'aA1!abcdefgh',
    newPassword: 'aA1!abcdefgh',
    confirmPassword: 'aA1!abcdefgh',
  },
  ip: '127.0.0.1',
  headers: {},
  get: () => undefined,
});

/**
 * 期望表：outcome → 应出现的错误码。
 * 少一条就会让"新增 outcome 忘了映射"这种情况静默通过，所以这张表本身就是产物。
 */
const CASES = [
  ['ENC_INVALID', 'AUTH_ENCRYPTED_CREDENTIAL_INVALID'],
  ['MISSING', 'PASSWORD_CURRENT_AND_NEW_REQUIRED'],
  ['CONFIRM_MISMATCH', 'PASSWORD_CONFIRM_MISMATCH'],
  ['USER_NOT_FOUND', 'USER_NOT_FOUND_OR_DELETED'],
];

describe('changePasswordSecure 的 outcome 映射表', () => {
  test.each(CASES)('outcome=%s ⇒ 400 且带 %s（不得掉进 default）', async (outcome, code) => {
    authService.changeUserPassword.mockResolvedValueOnce({
      outcome,
      message: `业务层消息_${outcome}`,
    });
    const res = mkRes();
    await securityController.changePasswordSecure(mkReq(), res, jest.fn());

    // 具体 4xx 状态码由各错误码在 errorCodes.js 里的登记决定（如 USER_NOT_FOUND 是 401），
    // 本测试钉的是"映射到哪个码"这条契约，不重复钉状态码。
    expect(res.statusCode).toBeGreaterThanOrEqual(400);
    expect(res.statusCode).toBeLessThan(500);
    const text = JSON.stringify(res.payload || {});
    expect(text).toContain(code);
    // 反向保护：不得把失败伪装成成功（codeError 的 success 必须是 false）
    expect(res.payload.success).toBe(false);
  });

  test('映射表确实覆盖到 MISSING（这条就是不可达分支的证据）', async () => {
    authService.changeUserPassword.mockResolvedValueOnce({ outcome: 'MISSING' });
    const res = mkRes();
    await securityController.changePasswordSecure(mkReq(), res, jest.fn());
    expect(JSON.stringify(res.payload)).toContain('PASSWORD_CURRENT_AND_NEW_REQUIRED');
  });

  test('未知 outcome 不得被当成成功', async () => {
    authService.changeUserPassword.mockResolvedValueOnce({ outcome: 'SOMETHING_NEW' });
    const res = mkRes();
    const next = jest.fn();
    await securityController.changePasswordSecure(mkReq(), res, next).catch(() => {});
    // 2026-09-20（`deliverables/AGENT工作总账与待办-2026-09-21.md` §2.3 审计链与合规留痕）：原断言是否定式
    // `statusCode===200 && success===true` 为 false，而它当时之所以绿，靠的是
    // **一次无关的 ValidationError**——本用例没有 mock AuditLog，桩返回体没有 username
    // ⇒ AuditLog schema 的 username required 使写入 reject ⇒ 响应从未写出 ⇒
    // payload 停在 null ⇒ 断言通过。也就是说标题声称的不变量当时**源码里没守**：
    // securityController.js 的 `default: break;` 确实把未知 outcome 直落到成功分支。
    // 源码已改为 `case 'OK': break; default: → INTERNAL_ERROR`，断言随之收紧为正向判据。
    expect(res.statusCode).toBe(500);
    expect(res.payload.success).toBe(false);
    expect(res.payload.errors.errorCode).toBe('INTERNAL_ERROR');
  });
});
