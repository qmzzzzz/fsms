# 贡献指南（CONTRIBUTING）

感谢参与本项目。本文约定开发环境、质量门禁与提交规范，保证每次合入都不降低现有的安全与可靠性水位。

## 1. 环境要求

| 依赖    | 版本                             | 说明                                                                        |
| ------- | -------------------------------- | --------------------------------------------------------------------------- |
| Node.js | ≥22.12.0（建议 22，CI 另测 24）  | `package.json` / `web-admin/package.json` 的 `engines` 与 Dockerfile 同口径 |
| MongoDB | 8.0（镜像钉 8.0.34；6.0 已 EOL） | 本地需先启动（`net start MongoDB`）；升级须逐级 6.0 → 7.0 → 8.0             |
| npm     | 随 Node                          | 后端在根目录、前端在 `web-admin/`                                           |

## 2. 本地启动

```bash
# 1. 安装依赖（前后端各一次；npm ci 严格按锁文件安装，与 CI 同口径）
npm ci
npm --prefix web-admin ci

# 2. 准备环境配置
cp .env.example .env          # 按需修改；密钥本地可留 .env，生产一律 *_FILE 注入

# 3. 启动（三选一）
./start.bat                   # Windows 一键：清端口 + 起前后端 + 打开登录页
./dev-backend.cmd             # 仅后端（3000）
./dev-vite.cmd                # 仅前端 dev server（3001，代理 /api 到 3000）
```

容器方式见 `README.md` 的 Docker Compose 章节；生产密钥与部署清单见
`deployment/secret-rotation.md`、`deployment/rollback-drill.md`。

## 3. 合并前必过的门禁（本地全部可跑）

```bash
npm test                      # 后端 jest（含覆盖率棘轮阈值，低于基线即红）
npm run test:coverage         # 覆盖率门禁口径
npm --prefix web-admin test   # 前端 vitest（含覆盖率阈值）
npm run lint:all              # 前后端 ESLint（recommended 全量 error）
npm run format:check          # prettier 全仓格式门禁
npm run test:e2e              # HTTP 冒烟（完整启动序列走查）
```

规则：

- **不许带红合并**。偶发失败不允许「重跑一次就好」——先定位根因（历史教训见
  `src/tests/setup.js` 的隔离注释）；确属环境抖动需在 PR 说明里给出证据。
- **覆盖率棘轮只升不降**：`jest.config.js` / `vite.config.js` 的
  `coverageThreshold` 基线贴着实测值，补测试后应顺手上调基线。
- **分层纪律**：`src/tests/architecture/layeringRatchet.test.js` 锁定
  「controller 直连 models 只减不增、新 controller 零容忍」。新功能的数据访问
  一律经 `src/services/`；确需下沉存量直连时，改完同步调低棘轮基线。
- **格式**：提交前跑 `npm run format`（不要手工对齐，交给 prettier）。

## 4. 代码约定（要点）

- **常量单一事实来源**：审计分类/动作枚举只改 `src/constants/audit.js`；
  路由前缀映射在 `src/utils/auditMeta.js`，两侧由启动断言防漂移。
- **密钥与敏感值**：不进 `environment`、不进日志、不进测试夹具。
  注入走 `src/config/secrets.js` 的 `*_FILE` 机制；新增密钥变量须登记进
  `FILE_BACKED_SECRETS` 与 `docker-compose.yml` 的 secrets 段。
- **日志**：结构化字段进 winston meta（`logger.warn('消息', { userId })`），
  不把用户标识拼进消息字符串。
- **错误处理**：控制器用 `asyncHandler` + `ApiError`；错误码新增须同时补
  前端映射（`web-admin/src/utils/api.js` 的 `ERROR_CODE_I18N_MAP`；对账测试 `web-admin/src/tests/utils/errorCodeI18n.test.js`）。
- **前端**：组件文案走 i18n（禁止中文裸键）；色值走 `--xf-*` 变量；
  会话身份状态只经 `@/store` 的 auth 域，令牌永不进 JS 可读存储。
- **审计**：新增写路由必须在 `AUDIT_LOG_ACTIONS` 白名单登记动作，
  否则审计页筛选会 400（白名单旁有历史教训注释，改前读一下）。

## 5. 提交与评审

- 一个变更只解决一件事；修复类提交在注释/描述里带问题编号（仓库惯例：
  `P*/R*/T*` 溯源），方便审计回溯。

> **关于历史「优化清单编号」（自本版本起废弃）**
>
> 仓库的 `docs/adr/`、`docs/architecture.md`、`CHANGELOG.md` 中散见 `M-2`、`R-3`、
> `A-1`、`O-15` 一类编号，它们出自建仓前的 `deliverables/待优化项总清单-2026-08-29.md`。
> 该文件**从未进入版本库、且本地已不存在**，编号无源可查，故：
>
> - **新提交一律使用 `P*/R*/T*` 编号**，不要再新增「优化清单」编号；
> - 文档中既有的历史编号**保留原样**（它们承载着当时的语义，如 `M-2` = TLS 纵深），
>   仅作历史标识，不影响其所在段落的结论；
> - 引用历史编号时无需再去查找源文件——它已不存在。

- PR 描述包含：**动机 → 方案要点 → 自测清单**（跑过的门禁命令与结果、
  手工验证路径）。涉及界面变化的附截图或录屏。
- 纯重构必须「行为不变 + 全量测试绿」，不与功能变更混在一个提交。

### 5.1 回滚与备份 ref（硬性规定）

**`refs/backup/*` 只保提交，不保工作区；而工作区才是这里最贵的东西。**

依据（2026-10-30 实测）：当时 `main` 上有 257 个暂存文件 + 113 个未暂存文件 + 9 个未跟踪项，
全部不在任何提交里；同一时间有并行会话在写同一份仓库（`docker/app-entrypoint.sh`、
`jest.config.js`、`CHANGELOG.md` 等在数分钟内被改）。这些内容没有任何 git 对象承载——
一次 `git reset --hard` 就没了，且**不可恢复**（不在 reflog、不在 stash、不在任何 ref）。

硬性规定：

1. **禁止**在本仓库执行 `git reset --hard`、`git checkout -- .`、`git restore .`、
   `git clean -fdx`。任何形式的「回滚」都不得以丢弃工作区为代价。
2. 回滚**已提交**内容用 `git revert <range>`（追加反向提交），不靠移动分支指针。
3. 只想「看/验一下旧状态」：`git switch --detach <ref>` 或
   `git worktree add ../fsms-old <ref>`，不移动 `main`。
4. 确需移动分支指针（如历史整理），先做齐三件事，缺一不可：
   - **两端钉 ref**：`git update-ref refs/backup/<用途>-<yyyymmdd> <sha>`（回滚前后各一个）；
   - **工作区快照**，且不得碰真索引：
     ```bash
     GIT_INDEX_FILE=/tmp/idx-snap git read-tree HEAD
     GIT_INDEX_FILE=/tmp/idx-snap git add -A          # 含未跟踪新文件
     TREE=$(GIT_INDEX_FILE=/tmp/idx-snap git write-tree)
     SNAP=$(git commit-tree "$TREE" -p HEAD -m "snapshot: <说明>")
     git update-ref refs/backup/worktree-<yyyymmdd> "$SNAP"
     ```
     为什么不用 stash：`git stash` 会清空工作区（直接违反第 1 条）；`git stash create`
     在索引 stat 过期时会直接失败（实测 `Entry … not uptodate. Cannot merge`）。
     临时索引两条都不碰。
   - **留指纹自证**：操作前后各取一次 `git diff --cached --binary | sha256sum` 与
     `git ls-files -s | sha256sum`，两者不变才说明没动到别人的暂存内容。
5. **reflog 不是备份**：默认 90 天，一次 `git gc --prune=now` 即清空。凡是「回滚之后可能
   还要回来」的节点，必须有 `refs/backup/*` 兜底。
6. 并行会话纪律：只 `git add <显式路径>`；**禁止** `git add -A` / `git commit -a`；提交前用
   `git diff --cached --name-only` 逐条核，确认没把别的会话的暂存项卷进本次提交。
7. 恢复姿势：
   ```bash
   git restore --source=refs/backup/worktree-<yyyymmdd> -- <path>   # 取回单个文件
   git switch --detach refs/backup/main-post-merge-<yyyymmdd>       # 整棵树回到回滚前
   ```

现存兜底 ref 用 `git for-each-ref refs/backup` 查看。本仓库按上述规则补了三类：
`main-pre-merge-<日期>`（回滚前）、`main-post-merge-<日期>`（回滚后）、
`worktree-<日期>`（工作区快照，含未跟踪文件）。

## 6. 测试要求

- 新功能/缺陷修复**必须附带测试**；安全相关路径（认证、权限、审计）
  要求错误分支与边界用例，不只走快乐路径。
- 源码级静态断言（读文件查字符串）只用于「无法用运行时断言的不变量」，
  且要容忍格式化换行；界面断言优先补 `data-testid`。
- E2E 增量见 `e2e/README.md`（Playwright 旅程）。

### 6.1 跨平台 shell 门禁（POSIX shell 解析）

`src/tests/deploy/**` 等套件用真实进程跑 `scripts/*.sh`，因此必须先有一个可用的 POSIX shell：

- **解析与接入**：`src/tests/helpers/posixShell.js` 负责**行为验证**候选 shell（跑得起来、
  `-c` 语义成立、探针标记能原样带回——文件存在不算数），`src/tests/globalSetup.js` 在 jest
  启动时把它接到 PATH 最前面并打印来源（`git-bash` / `posix` / `override`）。
  为什么在全局 setup：测试进程里改 `process.env.PATH` **不影响**子进程的可执行文件查找，
  只有主进程的环境变量才会随 worker 派生继承。
- **Windows 上的坑**：PATH 里的 `bash` 常是没装发行版的 WSL 启动桩（存在、退出非 0、
  什么也不执行）。自动探测会改用 Git for Windows 的 bash；都找不到时整族用例仍会红，
  并在启动日志里点名根因与修法（不静默跳过，也不给没有诊断的红）。
- **显式指定**：`FSMS_TEST_SHELL=<bash 绝对路径> npm test`。指错会**当场报错**，
  不会静默换成另一个 shell 顶上。
- **桩工具**：mongodump / gpg / date 一类桩必须经 `src/tests/helpers/stubPath.js` 在
  **子 shell 内**收口 PATH——MSYS 启动时会把 `/usr/bin` 前置，只在 env 里前置的桩目录
  会被同名系统工具顶掉（真二进制被执行，用例看起来像被测脚本有缺陷）。
- **口径**：Windows 上跑出来的绿是 **MSYS 语义的绿**，Linux 权威结论仍以 CI（ubuntu-latest）
  为准。

## 7. 文档同步

行为变更必须同步文档，否则视为未完成：

- 用户可见行为 → `README.md` 与 `CHANGELOG.md`（Keep a Changelog 格式）
- 架构/选型决策 → 新增 ADR（规范见 `docs/adr/README.md`，编号只增不复用）
- 运维动作 → 对应 Runbook（`deployment/` 下）

## 8. 安全问题请勿公开提交

发现漏洞请**私密**报告维护者（勿开公开 issue/PR）：附复现步骤、影响面与
建议修复方向；请勿在报告中携带真实生产凭据。修复与披露节奏遵循
90 天协调披露惯例。依赖漏洞以 `npm run security:audit` 与 CI
`security-audit` job 为门禁，例外登记制度见内部留档目录 `deliverables/` 下的
`security-scan-record-*.md`（该目录**不进版本库**，见 §9，故例外须在 PR 描述中同步摘要）。

## 9. 目录速览

```
src/            后端（config/ controllers/ services/ middleware/ models/ utils/）
web-admin/      前端（Vue3 + Pinia + Element Plus）
scripts/        运维脚本（备份/恢复/密钥生成与迁移/压测/漏扫辅助）
e2e/            Playwright 浏览器旅程
migrations/     数据库迁移（migrate-mongo）
deployment/     部署配置样例与演练手册
docs/           ADR、架构图、依赖观察清单
```

> **关于 `deliverables/`**：这是**内部留档目录**（评估报告、审计台账、性能/复杂度基线数据），
> **不进版本库**（`.gitignore` 已排除）—— 本仓库是公开仓库，而该目录含带 `file:line` 坐标的
> 可利用漏洞细节。本地文件完整保留；代码注释里出现的 `deliverables/...` 路径即指该内部留档，
> 在克隆仓库中**不存在**，属**有意为之**，不是断链。
