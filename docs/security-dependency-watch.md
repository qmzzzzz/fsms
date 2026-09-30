# 依赖安全观察清单（L-2 / L-3）

> 两个「不立即更换、但必须盯住」的依赖，把监控动作与触发条件白纸黑字留下，
> 避免「中期评估」变成无人认领的口头承诺。

## svg-captcha（L-2）

- **现状**：停留在 `1.4.0`，上游长期无新发布（维护停滞）。
- **为什么不换**：验证码是登录/注册反自动化的关键一环，替换库意味着图形、
  难度参数、识别率全部重来，临近上线窗口收益低于风险；且当前无已知高危
  advisory 指向该版本。
- **监控动作**：
  - `npm audit`（CI `security-audit` job 每次合并跑，阈值 **moderate** —— 2026-09-16 起由 `high` 收紧，见文末「通用约定」）；
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

## 供应链完整性锚（lockfile semantic 哈希）

### 补的是什么缺口

上面的 `npm audit` \ Dependabot \ CodeQL \ gitleaks \ install-script 门禁，**全部只回答
一个问题**：「这个包有没有已知 CVE」。于是下面三类**全部漏检**：

- 包被投毒但未上 CVE（audit 查的是 advisory 库）；
- 发布者账号被盗、推恶意版本（版本号合法、无 CVE）；
- **lockfile 被静默篡改**——PR 里夹带改一个 `integrity` 字段、本地误跑一次
  `npm install` 改了分辨率后顺手提交、CI 缓存污染。此前**只有 code review 的人眼**
  （`dependency-review.yml` 只比对「新引入的依赖有无漏洞」，**不校验锁文件与上次是否一致**）。

本锚把「上次人工拍板时锁文件长什么样」固化为 `deployment/lockfile-anchor.json` 里的
semantic 哈希，CI 的 `security-audit` 作业每次比对。

### 口径：semantic 哈希，不是原始字节哈希

哈希 = `SHA-256(UTF-8(JSON 递归排序 + 紧凑序列化))`，即
`json-sort-keys-compact-utf8`。

**为什么不能用原始字节哈希**：开发机是 Windows/CRLF 工作区，CI 是 ubuntu-latest/LF
checkout，而 `.gitattributes` 对 `package-lock.json` 无规则。实测
`raw` 口径在 CRLF↔LF 之间**漂移** ⇒ 门禁会在 CI 上**恒假红** ⇒ 而假红第一次出现就会被
`continue-on-error` 或「先注释掉」消化掉，等于没有门禁。semantic 口径对该差异免疫
（已固化为 `src/tests/deploy/lockfileAnchor.test.js` 的回归断言）。

### 覆盖面与用法

- 覆盖 **2 份**：`package-lock.json`（后端）、`web-admin/package-lock.json`（前端）。
  **不纳入 `zznpmtest/package-lock.json`**——它是会话期脚手架，未入库
  （`.gitignore:106-110` 登记，`git ls-files` 为 0），锚无从比对。
- `npm run check:lockfile`（= `--verify`，CI 用）；变更依赖后由人工复核 diff 再跑
  `node scripts/check-lockfile-integrity.js --update` 重写锚，**必须显式指定**。
- **fail-closed**：锁文件缺失 / 解析失败 / 锚缺失或条目缺失 ⇒ 一律判红。

### 能力边界（如实声明，勿夸大）

- ✓ **能挡**：PR 夹带改 lockfile、本地误 `npm install` 改分辨率、CI 缓存污染、
  锚被静默改（锚文件本身在 git 里，任何改动必留 diff 并受评审）。
- ✗ **挡不了**：**上游包本身被投毒**而 lockfile/`integrity` 均未变的场景。
  这一类只有「SBOM + 来源证明 + CVE 面」能挡，本锚不声称覆盖。
- ✗ **它不是 SBOM。** 本锚是**篡改检测**（「依赖树自上次拍板以来有没有被改动」）；
  SBOM 是**合规与追溯**（「我声明用了哪些组件、什么版本、什么许可证」）。
  二者互补、不互相替代。**当前仓库仍然没有合规意义上的 SBOM**——组件清单/许可证/
  来源证明都不在本锚的输出里，请勿把「有了完整性锚」误当成「有了 SBOM」。

## 通用约定

- 任何依赖更换必须附：变更前后 `npm audit` 对比、全量测试结果、
  （涉及运行时行为的）冒烟走查记录。
- 例外登记：确需带洞上线的，在内部留档目录 `deliverables/` 下的
  `security-scan-record-*.md` 登记例外（编号、理由、关闭期限），不允许静默放行。
  该目录**不进版本库**（见 `CONTRIBUTING.md` §9）⇒ 例外必须在 PR 描述里同步摘要。
- **CI 阈值**：`security-audit` job 使用 `--audit-level=moderate`（2026-09-16 起）。
  即 moderate 及以上 advisory 一律阻断合并，不再区分「高危才拦」。
