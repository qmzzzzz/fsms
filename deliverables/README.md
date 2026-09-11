# deliverables/ 交付物与留档

评估报告、安全扫描留档（`security-scan-record-*.md`）、演练记录等生成型文档的归档目录。

## 约定

- 生成型 HTML 产物已被 `.prettierignore` 排除（`deliverables/*.html`），不做格式化
- 新增的 Markdown 留档会纳入 `npm run format:check` 格式门禁
- 本 README 同时作为目录占位：CI 检出后 `prettier --check deliverables` 需要至少
  一个可匹配文件，目录为空时 prettier 会以退出码 2 失败（2026-09-11 CI 实证）
