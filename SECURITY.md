# 安全策略（Security Policy）

## 支持的版本

| 版本               | 支持状态        |
| ------------------ | --------------- |
| 1.0.x（main 分支） | ✅ 接收安全修复 |
| < 1.0              | ❌ 不再维护     |

## 报告漏洞

**请勿通过公开 Issue 报告安全漏洞。**

报告渠道（按优先顺序）：

1. **GitHub 私密漏洞报告**（Private Vulnerability Reporting，仓库 Security 标签页）——首选；
2. 通过 CONTRIBUTING.md 中列出的维护者联系方式私下同步。

报告时请尽量附上：影响的路径/文件与行号、复现步骤（含最小 PoC）、影响评估（保密性/完整性/可用性）、可能的修复思路。

### 响应时限（工作日）

| 阶段                    | 目标      |
| ----------------------- | --------- |
| 确认收到                | 48 小时内 |
| 初步分诊（定级 + 排期） | 7 天内    |
| High/Critical 修复发布  | 30 天内   |
| Medium/Low 修复发布     | 下一迭代  |

修复发布后，与报告者协商公开披露的时间与署名意愿；默认在 CHANGELOG 安全条目中致谢（可匿名）。

## 范围

**在范围内**：`src/`（后端）、`web-admin/src/`（前端）、`scripts/`、`deployment/`、Docker/CI 配置中的可利用漏洞——认证/授权绕过、注入（SQL/NoSQL/命令/公式）、XSS/CSRF、SSRF、敏感信息泄露、拒绝服务、供应链（依赖投毒信号）。

**不在范围内**（或有条件豁免）：

- 针对本地开发环境（`localhost` 明文 HTTP）的报告——生产 TLS 由前置 Nginx 终结，参见 README「传输层安全」节；
- 需要物理访问或已控主机的攻击；
- 无实际影响的理论问题（缺 CSP 子资源完整性等有明确取舍记录的项，见 docs/ADR）；
- 社会工程 / 对维护者的钓鱼。

## 自检基线

本项目定期执行：`npm audit --audit-level=high`（CI security-audit job）、Gitleaks 全量密钥扫描、`node scripts/compliance-check.js` 合规自检。已归档的渗透/白盒报告结论见 `deliverables/`。
