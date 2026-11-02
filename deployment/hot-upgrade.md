# 升级运行手册（蓝绿）

> 适用范围：单机 docker-compose 拓扑，宿主 nginx 反向代理。
> 对应代码：`scripts/hotUpgrade.js`（编排）、`scripts/hotUpgradePolicy.js`（判据）、
> `scripts/hotUpgradeAgent.js`（宿主队列代理；队列原语在 `hotUpgradeQueue.js`、
> 单条请求的校验与执行在 `hotUpgradeJob.js`）、`src/services/upgradeService.js`
> （应用侧队列读写）、`deployment/nginx.conf.example`（upstream）、
> `docker-compose.yml` 的 `app-green`、`deployment/systemd/`（代理服务单元）。
> 引入日期：2026-10-30。

---

## 0. 一句话说明

升级期间两色同时在线，nginx 的 upstream 指向哪一色，流量就去哪一色。
切流是原子的（改一行注释 + `nginx -s reload`），回滚就是把那行改回来。
**旧色容器在观察期内不销毁**——这是回滚能成立的前提。

触发有两个入口，执行侧是同一套脚本：**应用内按钮**（写队列，宿主代理执行，§3.1/§4）
与**命令行**（人工直接执行，§3.2）。应用容器**没有 docker socket**，任何版本都
不直接碰 docker/nginx。

---

## 1. 先分清三件「升级」

| 类型                                 | 机制                                                            | 生效方式                                     |
| ------------------------------------ | --------------------------------------------------------------- | -------------------------------------------- |
| 配置热更新（注册开关、验证码开关等） | `SystemConfig` + 30s 进程内缓存                                 | 改完等 30 秒，无需重启                       |
| 前端资源更新                         | Service Worker（`registerType: 'prompt'`）+ `/api/version` 轮询 | 用户点「立即刷新」；不会静默刷掉正在填的表单 |
| **版本升级（镜像替换）**             | 本文档                                                          | 脚本 + nginx 切流，中断 < 100ms              |

前两类不需要停机，第三类是本文档的主体。

---

## 2. 前置条件（缺一不可）

1. **nginx 必须有 `upstream fsms_app` 块**，且块内**恰好一行**未注释的 server。
   参照 `deployment/nginx.conf.example` 的 upstream 段改造实际配置。
   两行都放开 = nginx 轮询，两个版本混跑（比 502 更危险：能跑但语义错乱）；
   一行都不放开 = 全站 502。脚本对这两种形态直接报错，不猜。
2. **compose 里有 `app-green`**（`profiles: ['green']`）。不加 profile 时它不参与
   `docker compose up`，现有单色部署行为不变。
3. **镜像必须 digest 钉扎**：`registry/repo@sha256:<64hex>`。
   tag（含 `latest`）一律拒绝——tag 可被覆盖，无法证明线上跑的是审计里记的那一版。
4. **镜像白名单**：`HOT_UPGRADE_REGISTRY_ALLOWLIST`（逗号分隔仓库前缀，如
   `ghcr.io/qmzzzzz/`）。**空白名单 = 全拒**，不是全放。
5. **构建标识同源**：Dockerfile 已把 CI 的 `GIT_SHA` 同时注入前端构建（`__APP_BUILD_ID__`）
   与运行时（`APP_BUILD_ID`）。两侧不一致时前端会一直提示「有新版本」——
   这不是 bug，是比对键不同源，检查构建参数。
6. **一键升级入口另需宿主代理**（§4）：`fsms-hot-upgrade-agent.timer` 在跑且自检通过。
   只用命令行升级（§3.2）可以跳过这一条。
7. **宿主 3001 空闲**：备色固定 publish `127.0.0.1:3001`（`docker-compose.yml` 的 `app-green`）。
   Grafana 用的是同一个宿主端口，因此它已移入 `observability` profile，默认栈不含它。升级窗口内
   **不要**启用该 profile（`docker compose --profile observability up -d grafana`）：第 2 步起
   备色会报 `port is already allocated`。判据见 `src/tests/deploy/composeSegmentation.test.js`
   的「宿主端口互斥闸门」——它同时保证「grafana 必须带 profile」，删掉 profile 就会红。

---

## 3. 一次升级

### 3.1 应用内一键升级（需宿主代理）

入口在「关于」页的版本卡片：概览展示当前版本 / 颜色 / 构建号、代理在线状态与
最近任务历史；点「升级」打开弹窗，填 digest 镜像地址与二次验证凭据后提交。

```
GET  /api/security/upgrade               概览（security:config；3s 轮询，不进审计）
GET  /api/security/upgrade/jobs/:jobId   单任务状态与步骤（security:config）
POST /api/security/upgrade/requests      入队（security:config + 唯一超管 + 步进验证 + strictLimiter）
```

提交时的判据与拒绝码（前端逐条显示原因，按钮变灰时可对照概览里的 `reasons`）：

| 拒绝码                      | 含义                                            |
| --------------------------- | ----------------------------------------------- |
| `UPGRADE_DISABLED`          | `UPGRADE_ENABLED` 未开启                        |
| `UPGRADE_IMAGE_INVALID`     | 不是 `repo@sha256:<64hex>` 形态（tag 一律拒绝） |
| `UPGRADE_IMAGE_NOT_ALLOWED` | 仓库前缀不在白名单内                            |
| `UPGRADE_ALREADY_RUNNING`   | 已有任务排队/执行中（响应带 jobId）             |
| `UPGRADE_QUEUE_UNAVAILABLE` | 队列目录不可写（bind mount 或权限问题）         |
| `UPGRADE_JOB_NOT_FOUND`     | 任务 ID 非法或已不存在（按 404 处理，不拼路径） |

链路：应用把**签名请求**写成 `requests/<uuid>.json`（0600）→ 宿主代理最迟约 15s
认领 → 执行 `hotUpgrade.js` 并把每一步写进 `status/<uuid>.json` → 弹窗每 3s 轮询，
展示步骤、当前/目标颜色与终态。**代理会重新做一遍全部判据**，应用侧的校验只负责
尽早给出可读的拒绝原因。

### 3.2 命令行

```bash
# 1) 演练（默认行为，不改任何东西；退出码 2 表示「只是演练」）
node scripts/hotUpgrade.js \
  --image ghcr.io/<org>/<repo>@sha256:<64hex> \
  --nginx-conf /etc/nginx/nginx.conf

# 2) 真正执行
node scripts/hotUpgrade.js \
  --image ghcr.io/<org>/<repo>@sha256:<64hex> \
  --nginx-conf /etc/nginx/nginx.conf \
  --apply
```

脚本内部顺序（不可调换）：

1. **备份** `scripts/backup-mongo.sh` —— 失败即中止，此时还没动任何东西
2. **起备色** `docker compose --profile green up -d --no-deps app-green`（宿主 3001 必须空闲，见 §2 第 7 条）
   （`--no-deps` 是硬要求：绝不让 compose 顺带重建 mongo/redis，那才是真停机）
3. **等 `/readyz`** 变绿（默认 180s 超时）。**不是 `/health`**：后者只证明进程活着，
   而「升级后 Mongo 事务能力丢了」正是这类系统最常见的静默故障
4. **跑迁移** `docker compose run --rm --no-deps app-green ... migrate-mongo up`
   —— 用**新版本**的代码跑；失败就停在备色，旧色继续服务
5. **切流** 改 upstream + `nginx -t` + `nginx -s reload`（`-t` 不通过会原样恢复文件）
6. **观察** 默认 300s，持续探备色 `/readyz`；任何一次不 ok 即切回旧色
7. **停旧色** `docker compose stop app`（`stop` 而非 `rm`，保留回滚能力）

每一步都写进 `logs/hot-upgrade-<时间戳>.json`（审计链之外的第二份证据）；
一键升级时还会同步写入 `status/<uuid>.json` 供界面轮询。

### 3.3 离线（air-gap）升级：从离线包一键换装

前面两条入口都要求目标机能**从 registry 拉取**目标 digest。内网/断网机器上这条前提不成立，
因此另有一条离线通道：在联机侧把镜像导出成「离线包」搬到目标机，放进宿主受管的 bundles
目录后，管理员在**应用内**选包一键升级；导入与换装仍走**同一套**判据与蓝绿七步
（与 §3.1/§3.2 的差别只在镜像从哪来，切流与观察逻辑逐行相同）。

**离线包形态**（是目录，不是单个 tar——导入器刻意不自己解包，理由见 §9）：

```
<bundle>/
  manifest.json          # 包的自述：镜像 ref、字节数、sha256
  manifest.sig           # 对 manifest.json 原始字节的 Ed25519 签名（--sign-key 构建时产出）
  SHA256SUMS             # 传输完整性：覆盖 payload 与 manifest.sig；manifest 自身不能自我覆盖
  payload/fsms-app.tar   # docker save 的产物
```

manifest.json 的形状（判据在 `scripts/offlineBundlePolicy.js`）：

| 字段              | 约束                                                   | 为什么不能省                               |
| ----------------- | ------------------------------------------------------ | ------------------------------------------ |
| `format`          | 只认 `1`                                               | 老导入器读新包必须硬失败，不能「尽力而为」 |
| `images[].ref`    | `repo@sha256:<64hex>`，**tag 一律拒绝**                | 离线包不是 digest 钉扎的逃生通道           |
| `images[].file`   | 包内相对路径，`/` 分隔；`..`、绝对路径、反斜杠一律拒绝 | 上跳段能把文件写到包外                     |
| `images[].bytes`  | 正整数                                                 | 拷贝截断的包会被当成完整包装上             |
| `images[].sha256` | 64 位小写十六进制                                      | 摘要缺失 = 不校验                          |

**签名与信任链（ADR-019）**：`manifest.sig` 是构建机 Ed25519 私钥对 manifest.json **原始字节**
的签名（不做 JSON canonical——键序、空白、行尾任何字节动了就该验签失败）。目标机只钉一把
公钥（`OFFLINE_BUNDLE_VERIFY_PUBKEY`）：配置后**未签名或验签失败的包一律拒绝**（fail-closed）；
不配置则跳过验签，留痕明示 `signature: 'unchecked'`。payload 的完整性由 manifest 内的 sha256
逐字节比对承接，于是 `信任根(公钥) → manifest 字节 → payload 摘要` 传递覆盖整包——
「manifest 与 payload 被整体重写」从此是可检测的（此前只靠搬运通道可信）。

**第 1 步·构建（联机侧）**：

```bash
scripts/build-offline-bundle.sh --image ghcr.io/<org>/<repo>@sha256:<64hex> \
  --version <版本号> --out /tmp/fsms-offline-v1.2.3 \
  --sign-key /path/to/offline_bundle_sign.pem
```

（`FSMS_BUNDLE_REQUIRE_SIGNATURE=1` 可把「忘了带 --sign-key」变成构建期报错；
openssl 需 ≥ 3.0。私钥只在构建机，目标机永远只拿公钥。）

**第 2 步·搬运与落位（运维）**：把**整个目录**原样搬到目标机 `/var/lib/fsms/upgrade/bundles/`
下（scp / USB 均可），保持 0700 root。刻意不走应用内上传：应用容器只读、无 multipart 栈，
而 bundles 目录必须保持 root-only——**能写这个目录的账号 = 能决定线上跑什么代码**，
这个边界不因离线通道存在而松动。

**第 3 步·一键换装（应用内，推荐）**：代理每轮扫描 bundles 目录（只读 manifest + 白名单，
**不算 payload 哈希**——全量校验在执行时做），可用包摘要经心跳 `bundles` 字段公布；
「关于」页的升级弹窗会出现「离线包」来源，管理员从下拉选择包 → 二次验证 → 确认。
后续动作与在线一键升级完全一致：签名请求（mode=offline）→ 宿主代理重验全部判据 →
`importOfflineBundle.js --apply`（验签 → 逐字节比对 → `docker load` → RepoDigests 复核）→
`hotUpgrade.js --offline`（蓝绿七步，本地没有该 digest 就拒绝启动）。

**CLI 兜底（第 3 步的人工等价物）**：

```bash
# 演练（默认）：只校验不 load
node scripts/importOfflineBundle.js --bundle /var/lib/fsms/upgrade/bundles/v1.2.3 \
  --bundle-root /var/lib/fsms/upgrade/bundles --allowlist ghcr.io/<org>/ \
  --pubkey-file /etc/fsms/secrets/offline_bundle.pub
# 真正 docker load
node scripts/importOfflineBundle.js ... --apply
# 换装（离线模式：本地必须有该 digest，不联网拉取）
node scripts/hotUpgrade.js --image <同一个 ref> --offline --nginx-conf /etc/nginx/nginx.conf --apply
```

导入器按固定顺序做五件事，**任何一步不过都在碰 docker 之前中止**——顺序不能换：
先校验后 load，是因为一个损坏的包若先被 load，会在被拒绝之前就把半个镜像写进本地
docker（占盘，并与上一版抢同一个 repo 名），失败现场的清理成本远高于先校验。

1. 验签（配置了公钥时）：`manifest.sig` ↔ manifest.json 原始字节；未签名 = 拒绝；
2. `manifest.json` 结构与白名单（空白名单 = 全拒，与在线路径是**同一条**判据）；
3. 每个 payload 的实际字节数、sha256 ↔ manifest 声明；
4. `docker load`；
5. `docker image inspect` 的 `RepoDigests` 必须含 manifest 声明的那个 digest。
   load 的退出码**不是**答案：它只说明 tar 结构被接受了，装进来的完全可以是另一版。

`--offline` 只加一条前置判据：**本地 docker 必须已经有这个 digest 的镜像**，且它排在
备份之前（整条链上唯一不碰数据、只读本地状态的判据）。失败时报的是「本地没有这个镜像，
请先导入」——而不是让 `compose up` 去联网，把「包没导入」表现成一次漫长的拉取超时
（在断网机上是拉取报错，在内网机上则可能长时间卡住）。

| 变量（宿主代理侧）             | 用途                                                            |
| ------------------------------ | --------------------------------------------------------------- |
| `OFFLINE_BUNDLE_DIR`           | 离线包目录，默认 `/var/lib/fsms/upgrade/bundles`                |
| `OFFLINE_BUNDLE_VERIFY_PUBKEY` | Ed25519 验签公钥路径；**配置后未签名包一律拒绝**（fail-closed） |

默认值落在 `UPGRADE_QUEUE_DIR` 之内，因此已被单元现有的
`ReadWritePaths=-/var/lib/fsms/upgrade` 覆盖；**改到别处时必须同步改那一行**，
否则代理会在读包处 EACCES，而现场表现是「包读不了」，看起来像包坏了。
该目录属主只给 root（0700）：能把包放进这个目录的账号，等于能决定线上跑什么代码。
离线请求的终态码是 `aborted_import_failed`（定位不到包 / 导入失败都停在这一步：
未切流、未动数据），进度弹窗的步骤里会出现「导入离线包」与「启动离线换装」。
---

## 4. 宿主代理（一键升级的执行侧）

### 4.1 队列布局

宿主目录 `/var/lib/fsms/upgrade`（compose 的 `UPGRADE_QUEUE_HOST_DIR`）bind mount
到应用容器的 `/var/lib/fsms/upgrade`：

| 路径                     | 写入方 | 权限             | 用途                                                                                                                                                          |
| ------------------------ | ------ | ---------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 路径                     | 写入方 | 权限与属主       | 用途                                                                                                                                                          |
| ------------------------ | ------ | ---------------  | --------------------------------------------------------                                                                                                      |
| `requests/<uuid>.json`   | 应用   | 0600 nodejs      | 签名后的升级请求；代理消费时移走                                                                                                                              |
| `processing/<uuid>.json` | 代理   | 0640 root:nodejs | 已认领；同时记录子进程 pid，用于崩溃恢复                                                                                                                      |
| `status/<uuid>.json`     | 代理   | 0640 root:nodejs | 步骤与终态；应用只读（含镜像 digest 与发起人，故不给 other）                                                                                                  |
| `rejected/<uuid>.json`   | 代理   | 0600 root        | 验签/校验失败的请求留证（不执行、不静默删）                                                                                                                   |
| `heartbeat.json`         | 代理   | 0644 root        | 每次轮询覆盖写；应用据此判断在线/就绪。`bundles` 字段公布离线包候选（只读 manifest + 白名单的**自称**摘要，全量校验在执行时做；available/invalid 各限 10 条） |

目录本身：`/var/lib/fsms/upgrade` 与 `status/`、`processing/` 为 `0750 root:nodejs`，
`requests/` 为 `0700 nodejs`，`rejected/` 为 `0700 root`。

**为什么不是「一律 chown nodejs」**（2026-10-30 审计修正）：应用只需要**写 requests**、
**读 status/processing**。把后三者一起交给 nodejs，等于让被攻陷的应用能删
`processing/.agent.lock`（升级永久显示「另一个升级正在进行中」）、写
`status/<id>.json` 的 `state: succeeded`（界面假成功而请求被丢弃）、清空 `rejected/`
（验签失败的留证消失）——每一条都直接削弱这条链的取证价值。

**顺序必须是「收回 root → chmod → 交出属主」**：容器 `cap_drop: ALL` 且刻意不补
`FOWNER`，对已属 nodejs 的目录再 `chmod` 必然 EPERM，而入口脚本是 `set -eu`——
第二次启动、`app-green` 启动、`compose run` 的一次性迁移容器都会因此起不来。
入口脚本因此只对 `requests/` 做递归属主对齐，且用 `find -xdev` 不跨文件系统、
不跟随符号链接（应用可写该目录，可放指向宿主文件的链接）。`UPGRADE_QUEUE_DIR`
指向 `/`、`/etc` 等系统目录时，脚本拒绝改属主并告警——那会把宿主大量文件交给 UID 1001。

**属主对齐**：`status/`、`processing/` 由 root 代理写入（0640、属组＝队列目录属组），
而读它们的是容器内非 root 的应用用户。代理写完会**把新文件的属主/属组对齐到该目录**
（只在以 root 运行时动作，Windows 静默跳过），否则属主 root + 0600 会让应用 EACCES——
把权限收紧做成功能失效。`heartbeat.json` 保持 0644：它不含镜像/操作人，且是应用判断
在线与否的依据。

### 4.2 安装

```bash
# 1) 仓库副本与依赖（代理执行 scripts/hotUpgrade.js 需要完整仓库）
sudo git -C /opt/fsms fetch --prune origin && sudo git -C /opt/fsms checkout <tag>
sudo npm --prefix /opt/fsms ci --omit=dev

# 2) 环境文件（0640 root:root；模板见 deployment/systemd/hot-upgrade.env.example）
sudo install -d -m 0755 /etc/fsms
sudo install -m 0640 hot-upgrade.env /etc/fsms/hot-upgrade.env

# 3) systemd 单元
sudo install -m 0644 fsms-hot-upgrade-agent.service /etc/systemd/system/
sudo install -m 0644 fsms-hot-upgrade-agent.timer   /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now fsms-hot-upgrade-agent.timer
journalctl -u fsms-hot-upgrade-agent -f
```

配置对齐是硬要求（不对齐时**不会**「两边各自工作」，而是每次请求都验签失败或
被白名单拒绝）：

- `UPGRADE_QUEUE_DIR` 与 compose 的 `UPGRADE_QUEUE_HOST_DIR` 相同；
- `HOT_UPGRADE_REGISTRY_ALLOWLIST` 与应用容器内同名变量相同；
- `HMAC_SECRET_FILE` 与应用容器的 `/run/secrets/hmac_secret` 是**同一份**密钥。

### 4.3 一轮做什么

systemd timer 每 15s（`OnUnitInactiveSec`，上一轮没跑完不会叠加）拉起
`hotUpgradeAgent.js --once`：

1. 写心跳；跑自检（白名单非空、HMAC ≥ 16 字符、nginx 配置存在）。
   自检不过就**只写心跳并返回**，请求原样留在队列，概览显示「升级代理未就绪：…」。
2. 拿 `processing/.agent.lock`（O_EXCL），保证同一时刻只有一个消费者。
3. 恢复上次异常退出的任务：`processing` 里的子进程还活着就让路，否则写
   `failed/agent_lost` 并清理。
4. 按文件名顺序认领最早的一条请求（`rename` 到 `processing/`），重新校验：
   UUID 文件名、普通文件、JSON、id 一致、TTL、时间不在未来、HMAC 签名、
   digest 钉扎、白名单。任何一条不过 → 写 `failed/rejected` 状态并移入 `rejected/`。
5. 用固定命令执行：`node scripts/hotUpgrade.js --nginx-conf … --status-file … --apply`；
   镜像经环境变量 `HOT_UPGRADE_IMAGE` 传入（**不进 argv / 进程列表**）。
6. 升级期间每 10s 续心跳；子进程退出后必须有终态，否则记
   `spawn_failed` / `exit_nonzero` / `missing_terminal`，不把未知结果当成功。
7. 裁剪历史（默认保留最新 50 条，running/queued 永不删除）。

### 4.4 安全边界

- **签名防的是本机其它用户**：能写队列目录的本机用户不能伪造升级指令；它
  **不防应用被攻陷**（应用与代理共用同一把 HMAC）。真正的边界是代理执行前
  重新跑的 digest 钉扎 + 白名单 + 固定脚本——即使签名通过，也只能升级到白名单
  里、被 digest 钉死的镜像。
- 代理必须以 root 运行（要调 docker 与改 nginx 配置）。改成普通用户 + docker 组
  等价于 root，只是看起来不像。
- 队列目录里的文件只当**数据**读，文件名必须匹配 UUID；签名载荷绑定
  `id/image/requestedAt/userId`，请求被改过即验签失败。
- `rejected/` 是取证面：被拒绝的请求留在队列外，不会被下一轮重试。

---

## 5. 回滚

观察期内失败：脚本自动切回，旧色从未停止，**无需人工介入**。

观察期之后发现问题（此时旧色已 stop）：

```bash
# 1) 先把 upstream 改回旧色（改那一行注释）
# 2) 校验并重载
nginx -t && nginx -s reload
# 3) 把旧色容器起回来
docker compose start app
```

**数据不回滚**。回滚只回代码，所以迁移必须遵守下一节的约束。

离线路径（§3.3）的回滚与在线路径完全一致，且**不需要再搬一次包**：上一版镜像既然仍在
本地 docker 里，切回旧色就仍然只是「改 upstream 那一行注释 + `nginx -s reload` +
`docker compose start app`」。这也是把包留在 `OFFLINE_BUNDLE_DIR`（而不是导入完即删）
的理由——内网机重新搬一次包的成本，远高于留几 GB 磁盘。

---

## 6. 迁移硬约束：expand / contract

回滚只回代码不回数据，因此**升级窗口内的迁移只允许「加」，不允许破坏性变更**：

| 阶段     | 版本       | 动作                                 |
| -------- | ---------- | ------------------------------------ |
| expand   | 本版本     | 加字段 / 加索引 / 双写，旧代码仍能跑 |
| switch   | 下一版本   | 读切到新字段，旧字段保留             |
| contract | 再下一版本 | 删除旧字段                           |

禁止在升级窗口内 `drop` / `rename` / 改变既有字段语义。禁止的对象是**字段与数据语义**。

**例外口径：索引替换（create-new-then-drop-old）不受上面这条 `drop` 约束**——先建新索引、
确认可用后再删旧索引，任意时刻至少一条索引在服务，新索引以旧键为前缀，旧代码的等值与排序仍能命中，
回滚时按 `migrations/README.md` 的回滚语义表把旧索引按旧形态建回。先例：
`migrations/20260926000000-cursor-tiebreak-compound-indexes.js`、
`migrations/20261021000000-query-performance-indexes.js`、
`migrations/20261101000000-filter-tiebreak-compound-indexes.js`（六条三键索引的替换）。
**纯删索引**（无替代，如 `20261021000000` 里的 `usersessions.status_1`）不在此例外内，
必须在迁移文件头写明"为什么删掉之后查询仍然可接受"，本表不代替那段理由。

同时要求 **N-1 兼容**：新增字段一律可选，响应只增不减。
切换窗口内两版同时在服务，任何「新版本才有的必填字段」都会让旧版本的请求 500。

**离线路径（§3.3）受同一组约束，且不因「包在本地」而放松**：离线升级同样是「两版同时在
服务、回滚只回代码」，所以 expand/contract 与 N-1 兼容一条都不能少。反过来说，离线包里
**不包含数据库快照**——它换的是程序，不是数据。

---

## 7. 失败模式对照

脚本/判据层：

| 现象                       | 含义             | 处置                                             |
| -------------------------- | ---------------- | ------------------------------------------------ |
| `镜像必须用 digest 钉扎`   | 传了 tag         | 换成 `@sha256:...`                               |
| `镜像仓库不在白名单内`     | 前缀不匹配       | 显式改白名单并留痕                               |
| `upstream 内有 0 行未注释` | nginx 配置已坏   | 先修配置，别升级                                 |
| `upstream 内有 2 行未注释` | 会轮询混跑       | 注释掉一色                                       |
| `备色未就绪（mongo=...）`  | 新版本连不上依赖 | 未切流，旧色正常；容器日志尾巴已进任务说明与留痕 |
| `迁移失败`                 | 迁移脚本报错     | 未切流；备色容器保留以便排查                     |
| `观察期未通过`             | 切流后新色不稳   | 已自动切回；新色容器日志尾巴已进任务说明与留痕   |

**失败现场自动抓取**（2026-11-02）：`备色未就绪` 与 `观察期判负` 两条分支在收尾前会抓一次
目标色容器的日志尾巴（`docker compose logs --no-color --tail 80`，捕获超时 10s、总字节
封顶 64KB）——完整尾巴进宿主留痕 `logs/hot-upgrade-*.json` 的 `targetLogsTail`；按行边界
截断的短片段（默认 ≤1500 字）追加进任务说明（进度弹窗「说明」行）与宿主 journal——省掉
「再上一次机器看根因」那一步。三条边界：抓取**永不阻断**（docker 不可用/容器已停/输出超限
都只记一行，主判决始终来自就绪探测与观察窗口本身）；**有界**（行数与字符数都封顶，日志尾巴
是诊断样本不是归档）；`rollback_failed` 的紧急文案保持短句，日志只进留痕。

队列/代理层（一键升级）：

| 现象                       | 含义                                   | 处置                                            |
| -------------------------- | -------------------------------------- | ----------------------------------------------- |
| 按钮变灰，概览列 `reasons` | 开关/白名单/目录/心跳不满足            | 按每一条原因修配置，不猜                        |
| `升级代理从未上报心跳`     | 代理未安装或 timer 未启动              | `systemctl status fsms-hot-upgrade-agent.timer` |
| `升级代理心跳已过期`       | 代理停止（默认 120s 阈值）             | `journalctl -u fsms-hot-upgrade-agent`          |
| `升级代理未就绪：…`        | 代理自检不过（白名单/HMAC/nginx 配置） | 修 `/etc/fsms/hot-upgrade.env` 后下一轮自愈     |
| 任务 `failed/rejected`     | HMAC 不一致或请求被篡改                | 对齐两处密钥；原始请求见 `rejected/`            |
| 任务 `failed/agent_lost`   | 代理执行中被杀/重启                    | 先人工确认容器与 upstream 实际状态，再重试      |
| `failed/exit_nonzero`      | 升级脚本非 0 退出                      | 看 `logs/hot-upgrade-*.json` 与任务步骤         |
| `UPGRADE_ALREADY_RUNNING`  | 已有任务未终态                         | 用响应里的 jobId 查进度，不要重复提交           |

---

## 8. `/api/version` 契约

```
GET /api/version   （匿名，no-store）
→ { success: true, data: { version, buildId, buildTime, startedAt, uptimeSec } }
```

- 只暴露识别版本所需的最小字段：**不含** node 版本、依赖清单、镜像 digest、env 快照
  （这些是攻击者做指纹与 CVE 映射的原料）。
- 镜像 digest 记在启动日志与镜像 label（`org.opencontainers.image.revision`）里，运维可查。
- **不进审计**：它是高频轮询的只读元数据，进链只会稀释真实操作痕迹。
- 前端每 5 分钟查一次 + 标签页重新可见时补查；任一侧 buildId 为 `unknown`/`dev`/空
  时**不比对**（否则本地构建包连生产会立刻误报）。
- **缓存是唯一的失效形态**：中间层（nginx / CDN / 企业代理）缓存了这份 JSON，前端就
  一直比对到旧 buildId，「有更新」永远检测不到且**没有任何报错**。故响应同时带
  `Cache-Control: no-store, no-cache, must-revalidate, max-age=0` 与 `Pragma: no-cache`。
- **ETag 不做无效抵抗**：Express 在 `res.send` 阶段会无条件补 ETag（`removeHeader('ETag')`
  实测无效——`send` 里 `if (!this.get('ETag'))` 会重新生成；`res.set('ETag', false)` 则会
  写出字面量 `ETag: false`，更糟）。`no-store` 已使合规缓存不得存储，ETag 因此无从参与
  条件请求；真要全局关掉得改 `app.set('etag')`，会波及全部 API 的 304 语义，得不偿失。

---

## 9. 本方案刻意没做的事

- **不做自动升级**：代理只消费**人**显式提交、且带二次验证凭据的请求；没有定时
  检查新版本、没有「发现即升」。自动升级 + 迁移 = 半夜静默炸库。
- **不做「应用直连 docker / nginx」**：应用容器不挂 docker socket，也不拼接任何
  执行命令。应用能做的只有写一份签名请求；执行侧固定脚本、固定参数，并重跑全部
  判据。这比给应用一个「能指定跑什么代码」的 HTTP 入口窄得多。
- **不做灰度分流**（L3）：两色跑不同版本时按比例分流，需要先有稳定的错误率基线。
- **不自己做离线包的解包**（§3.3）：导入器只接受**已解压的目录**，在升级链路上再实现一次
  安全解包，等于再开一条路径穿越面，而这一步没有任何不可替代性。
  **签名已随 ADR-019 引入**（2026-11-02）：早期版本连签名也不做，可信度完全压在
  「搬运通道 + 逐字节比对」上——那挡不住「manifest 与 payload 被整体重写」（自带的
  sha256 只证明两者同源，证明不了出自构建机）。现在的信任链是
  `构建机私钥签 manifest 字节 → 目标机钉公钥验签 → manifest 内 sha256 覆盖 payload`，
  且目标机**配置公钥后未签名包一律拒绝**（fail-closed）；是否启用由部署显式选择，
  未配置公钥时留痕明示 `signature: 'unchecked'`。同理，**离线包不是绕开白名单的通道**：
  包内镜像引用仍要过与在线路径同一条前缀判据，空白名单依然全拒；
  **离线也不是绕开二次验证的通道**：应用内发起离线升级与在线升级走同一道
  security:config + 唯一超管 + 步进验证门。
- **不解决宿主机故障**：蓝绿只覆盖「应用版本切换」，宿主机宕机属高可用范畴。

---

## 10. 已知未验证的部分（如实记录）

- **没有在真实双色环境跑过完整执行路径**（起备色、迁移、reload、观察、回滚）。
  开发机没有可用的 Docker 守护进程（`docker version` 连不上
  `dockerDesktopLinuxEngine`），`docker compose config` 解析与演练模式之外的
  真实容器行为均未实测。已覆盖的部分：判据层、代理状态机（认领/验签/拒绝隔离/
  崩溃恢复/锁/裁剪）、队列目录契约、compose/systemd 静态契约、发布工作流结构，
  见 `src/tests/deploy/` 与 `src/tests/services/upgradeService.test.js`。
- `nginx -s reload` 的中断时长（文档写的 < 100ms）来自 nginx 的既有语义，
  **未在本项目实测**。
- 真实代理 systemd timer 的 15s 节奏、长任务期间 10s 心跳续期、以及 root 环境下
  的 `docker compose` 调用，均只在测试替身里验证过。
- **离线一键链路未在 air-gap 真机走通**（2026-11-02）：离线请求的两段执行
  （定位包 → `importOfflineBundle --apply` → `hotUpgrade --offline`）、心跳 bundles
  的真实扫描，目前由判据层测试与进程内档板
  （`src/tests/deploy/hotUpgradeOfflineDispatch.test.js`）覆盖。签名侧已实测两半：
  node 签 → node 验（`offlineBundleSignature.test.js` 回环）与 **openssl 签 → node 验**
  （`openssl pkeyutl -sign -rawin` 产出、node:crypto 验签通过，2026-11-02 手工实测）；
  `--offline` 换装在真实 docker/双色环境的行为仍未实测，首次离线升级前按 §3.3
  的三步在一套可丢弃环境里先演练一遍。

首次真实升级前，在一套可丢弃的环境里按下面清单走一遍：

| #   | 步骤                                     | 通过标准                                            |
| --- | ---------------------------------------- | --------------------------------------------------- |
| 1   | 装代理并 `systemctl enable --now …timer` | 关于页显示代理在线，`reasons` 为空                  |
| 2   | 停 timer                                 | 120s 内按钮变灰，原因显示「心跳已过期」             |
| 3   | 提交一条白名单外镜像                     | 400/403 且原因可读，不产生请求文件                  |
| 4   | 提交合法 digest（演练或可丢弃环境）      | 15s 内任务从 queued → running，步骤持续更新         |
| 5   | 观察切流瞬间                             | 并发压测 0 个 5xx；关于页颜色从 blue 变 green       |
| 6   | 在备色制造 `/readyz` 失败后重跑          | 自动切回旧色，任务终态 `failed/rolled_back`         |
| 7   | 升级途中 `systemctl stop` timer / 杀代理 | 下一轮写 `agent_lost`，不会重复执行同一请求         |
| 8   | 对齐/错开两处 HMAC 后各提交一次          | 错开时任务 `failed/rejected` 且请求进入 `rejected/` |
