# 依赖安全观察清单（L-2 / L-3）

> 两个「不立即更换、但必须盯住」的依赖，把监控动作与触发条件白纸黑字留下，
> 避免「中期评估」变成无人认领的口头承诺。

## svg-captcha（L-2）

- **现状**：停留在 `1.4.0`，上游长期无新发布（维护停滞）。
- **为什么不换**：验证码是登录/注册反自动化的关键一环，替换库意味着图形、
  难度参数、识别率全部重来，临近上线窗口收益低于风险；且当前无已知高危
  advisory 指向该版本。
- **监控动作**：
  - `npm audit`（CI `security-audit` job 每次合并跑，阈值 high）；
  - 每月人工查看一次 GitHub Security Advisories / OSV：`svg-captcha`。
- **更换触发条件**（满足其一即启动评估）：
  1. 出现 medium 及以上 advisory 且无补丁；
  2. 出现针对 svg-captcha 的公开识别/绕过工具并被实际利用；
  3. 下一个大版本迭代周期（有测试余量时）主动评估替代（如自建画布验证码
     或行为验证）。

## Express（L-3）

- **现状**：已升级并固定在 `^5.2.1`；迁移决策与行为差异记录见
  `docs/adr/ADR-007-express5迁移评估与决策.md`。
- **监控动作**：
  - 跟随 5.x 安全补丁：有新补丁发布时更新到最新补丁版本，并跑全量测试；
  - `npm audit` 常态门禁同前。
- **升级触发条件**（满足其一即排期评估大版本）：
  1. Express 5.x 停止接收安全补丁（EOL 公告）；
  2. 出现仅更高主版本修复的高危问题；
  3. 新框架能力能显著降低安全或维护成本，且有完整回归窗口。

## morgan（M-02，已修复 + 门禁已收紧）

- **问题**：`morgan < 1.12.0` 存在日志伪造（CWE-117 / GHSA-jxfw-x594-9x9m，
  CVSS 5.3）。不转义 `U+2028`/`U+2029`，攻击者可在 User-Agent / Referer / URL
  中嵌入这些字符，使单条访问日志在采集端被解析为**多行**，从而伪造看似合法的
  日志条目 → SIEM 解析规则错乱、告警被淹没或伪造、事后取证可信度下降。
- **为什么长期未被发现**：CI 原用 `npm audit --omit=dev --audit-level=high`，
  **moderate 不会导致构建失败**；同时本清单只登记了 svg-captcha 与 Express，
  **未包含 morgan** —— 既不会失败 CI，也不在任何人的监控清单上。
- **已采取的动作（2026-09-16）**：
  1. 升级 `morgan` → `^1.12.1`；
  2. **CI audit 阈值由 `high` 收紧至 `moderate`**（`.github/workflows/ci.yml`
     的 backend 与 web-admin 两处）——这才是根治：同类中危不会再静默通过；
  3. 顺带修复 devDependencies 中的 `js-yaml`（GHSA-2883-xcg3-v3hh，high）：
     eslint 链 4.3.1 → 4.3.2、jest 链 3.15.1 → 3.15.2，均在原 semver 范围内，
     无破坏性升级。
- **当前状态**：`npm audit`（含 dev）与 `npm audit --omit=dev` 均为 **0 漏洞**。

## 通用约定

- 任何依赖更换必须附：变更前后 `npm audit` 对比、全量测试结果、
  （涉及运行时行为的）冒烟走查记录。
- 例外登记：确需带洞上线的，在 `deliverables/security-scan-record-*.md`
  登记例外（编号、理由、关闭期限），不允许静默放行。
- **CI 阈值**：`security-audit` job 使用 `--audit-level=moderate`（2026-09-16 起）。
  即 moderate 及以上 advisory 一律阻断合并，不再区分「高危才拦」。
