# 部署工作流真实演练记录（O-5）

> 背景（2026-10-20 七维审计 O-5）：`.github/workflows/deploy.yml` 自陈
> **从未在 GitHub Actions 上真实跑过**。`src/tests/deploy/deployWorkflow.test.js`
> 只能证明接线形状（变量名、步骤顺序、fail-closed 分支），证明不了
> SSH 参数、Environment 密钥、目标机 checkout 路径在真实 runner 上可用。
>
> 本文件是那次演练的**唯一留档处**：在「三、真实演练记录」登记之前，
> deploy.yml 文件头的「未验证声明」继续有效——不要因为静态测试全绿就把它删掉。

## 一、代码侧已收口的部分（不替代真实演练）

| 项                    | 落点                                      | 证明了什么                                                               |
| --------------------- | ----------------------------------------- | ------------------------------------------------------------------------ |
| 命令拼装抽成纯函数    | `scripts/deployCommands.js`               | 每条外发命令的 argv（顺序、`--no-deps`/`--no-build` 位置）可逐项断言     |
| dry-run 打印真实 argv | `scripts/deploy.js` 的 `[命令计划]` 段    | 演练输出可与实际执行同源核对，而不是只有步骤描述                         |
| 工作流静态契约        | `src/tests/deploy/deployWorkflow.test.js` | RPO/RTO/告警配置下发、digest 钉扎、stdin `bash -s`（不再依赖 `SendEnv`） |
| 命令拼装单测          | `src/tests/deploy/deployCommands.test.js` | deploy.js 不再自带命令字面量；连接串不进 argv                            |

**这些都不算 O-5 关闭**：它们不经过 Actions 的 SSH 通道、Environment secrets
与目标机目录，而这三项正是历史上「按文档执行必失败」的来源。

## 二、首次真实演练步骤（预发环境，dry_run=true）

前置条件（缺一即演练无意义）：

- GitHub Environment `staging` 已配置；两种通道二选一：
  - 自托管 runner：打 `deploy` 标签、注册在预发部署机上；
  - SSH：`DEPLOY_HOST` / `DEPLOY_USER` / `DEPLOY_SSH_KEY` / `DEPLOY_PATH` 四个密钥齐备。
- 目标机已生成 `./secrets/`（11 个文件，含 `redis_password`），且 `.env` 里
  `CORS_ORIGIN` / `ALLOWED_HOSTS` / `BACKUP_RPO_HOURS=24` / `BACKUP_RTO_HOURS=4` 生效，
  告警配置已注入（占位模板会被 preflight 以退出码 2 拒绝）。
- 目标镜像真实存在、由本仓库 CI 构建并完成 cosign keyless 签名
  （preflight 会验签并解析 digest；`--dry-run` 也走 preflight）。

触发与留证：

```bash
# 只打印部署计划与真实 argv，不做任何变更
gh workflow run deploy.yml --ref main \
  -f image_tag=ghcr.io/qmzzzzz/fsms:sha-<7位> \
  -f environment=staging \
  -f dry_run=true
gh run watch

# 留证（把下列内容填进「三、真实演练记录」）：
#   · workflow run URL 与 conclusion
#   · preflight job 的 digest 解析输出（应为 <repo>:<tag>@sha256:<64位hex>）
#   · deploy job 日志里的 [命令计划] 段（与 scripts/deployCommands.js 同源）
#   · 退出码（要求 0）
```

边界声明：`dry_run=true` 只证明「凭据、网络、目标机路径、前置校验」这条链路可用，
**不证明**备份、迁移、切容器、健康门禁与自动回滚；那些要等一次非 dry-run 的
staging 真实发布（不在本文件的最小完成标准内）。

## 三、真实演练记录

| 演练 | 日期   | 环境    | 模式         | run URL | 结论 | 暴露的问题 / 跟进                                 |
| ---- | ------ | ------- | ------------ | ------- | ---- | ------------------------------------------------- |
| #1   | 待执行 | staging | dry_run=true | —       | —    | 阻塞项：需先注册 staging runner 或配置 SSH 四密钥 |

> 首次执行后：登记本行、删除「阻塞项」字样，并同步更新 `deploy.yml` 文件头的未验证声明。
