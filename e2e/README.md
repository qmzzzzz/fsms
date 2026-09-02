# 浏览器 E2E 运行说明（T-2）

> 定位：真实浏览器里的核心旅程回归，与 `scripts/e2e-smoke.js`（HTTP 冒烟）互补：
> 冒烟保「服务起得来」，E2E 保「用户在界面上走得通」。

## 用例清单

| 文件                               | 旅程                                                              |
| ---------------------------------- | ----------------------------------------------------------------- |
| `journey-login.spec.js`            | 正确凭据登录 / 错误口令被拒                                       |
| `journey-mfa.spec.js`              | 口令+动态码两步登录 / 错误动态码被拒                              |
| `journey-inspection-alarm.spec.js` | 巡检/告警/设备列表只读巡场（不白屏）                              |
| `journey-permission-audit.spec.js` | 角色权限树可达 / 审计日志可追溯本次登录                           |
| `journey-fault-injection.spec.js`  | 依赖故障注入：连接被拒/超时/500 的界面韧性 + 会话期宕机降级与自愈 |

缺凭据时用例自动跳过（不计失败）——保证「未配置环境也能全绿」，
配置齐全后自动升级为真实断言。

## 运行步骤

```bash
# 1. 一次性安装浏览器内核
npx playwright install chromium

# 2. 起完整栈（后端 + 真实 Mongo + 前端产物）：
#    后端按 README 启动（或 docker compose），前端已构建并由后端托管（L-1）
#    关键开关：LOGIN_CAPTCHA_ENABLED=false（验证码无法自动化）

# 3. 配置演练账号（不落盘，终端内导出）
export E2E_USER=<账号>
export E2E_PASS=<口令>
# 可选（开启 MFA 旅程）：
export E2E_MFA_USER=<MFA账号>
export E2E_MFA_PASS=<MFA口令>
export E2E_MFA_SECRET=<base32种子>

# 4. 运行
npm run test:e2e:browser
# 或指定目标：E2E_BASE_URL=https://staging.example.com npx playwright test
```

## 约定

- 用例只读为主：写路径（改权限/处置告警）属破坏性操作，留给**人工演练**
  在专用演练账号与造数环境执行，避免共享环境被自动化污染。
- 选择器基于中文文案与 Element Plus 类名；界面改版导致漂移时，
  优先补 `data-testid` 再改用例，不要在用例里堆脆弱路径。
