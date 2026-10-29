# 热升级运行手册（蓝绿）

> 适用范围：单机 docker-compose 拓扑，宿主 nginx 反向代理。
> 对应代码：`scripts/hotUpgrade.js`（编排）、`scripts/hotUpgradePolicy.js`（判据）、
> `deployment/nginx.conf.example`（upstream）、`docker-compose.yml` 的 `app-green`。
> 引入日期：2026-10-30。

---

## 0. 一句话说明

升级期间两色同时在线，nginx 的 upstream 指向哪一色，流量就去哪一色。
切流是原子的（改一行注释 + `nginx -s reload`），回滚就是把那行改回来。
**旧色容器在观察期内不销毁**——这是回滚能成立的前提。

---

## 1. 先分清三件「升级」

| 类型 | 机制 | 生效方式 |
|---|---|---|
| 配置热更新（注册开关、验证码开关等） | `SystemConfig` + 30s 进程内缓存 | 改完等 30 秒，无需重启 |
| 前端资源更新 | Service Worker（`registerType: 'prompt'`）+ `/api/version` 轮询 | 用户点「立即刷新」；不会静默刷掉正在填的表单 |
| **版本升级（镜像替换）** | 本文档 | 脚本 + nginx 切流，中断 < 100ms |

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

---

## 3. 一次升级

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
2. **起备色** `docker compose --profile green up -d --no-deps app-green`
   （`--no-deps` 是硬要求：绝不让 compose 顺带重建 mongo/redis，那才是真停机）
3. **等 `/readyz`** 变绿（默认 180s 超时）。**不是 `/health`**：后者只证明进程活着，
   而「升级后 Mongo 事务能力丢了」正是这类系统最常见的静默故障
4. **跑迁移** `docker compose run --rm --no-deps app-green ... migrate-mongo up`
   —— 用**新版本**的代码跑；失败就停在备色，旧色继续服务
5. **切流** 改 upstream + `nginx -t` + `nginx -s reload`（`-t` 不通过会原样恢复文件）
6. **观察** 默认 300s，持续探备色 `/readyz`；任何一次不 ok 即切回旧色
7. **停旧色** `docker compose stop app`（`stop` 而非 `rm`，保留回滚能力）

每一步都写进 `logs/hot-upgrade-<时间戳>.json`（审计链之外的第二份证据）。

---

## 4. 回滚

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

---

## 5. 迁移硬约束：expand / contract

回滚只回代码不回数据，因此**升级窗口内的迁移只允许「加」，不允许破坏性变更**：

| 阶段 | 版本 | 动作 |
|---|---|---|
| expand | 本版本 | 加字段 / 加索引 / 双写，旧代码仍能跑 |
| switch | 下一版本 | 读切到新字段，旧字段保留 |
| contract | 再下一版本 | 删除旧字段 |

禁止在升级窗口内 `drop` / `rename` / 改变既有字段语义。

同时要求 **N-1 兼容**：新增字段一律可选，响应只增不减。
切换窗口内两版同时在服务，任何「新版本才有的必填字段」都会让旧版本的请求 500。

---

## 6. 失败模式对照

| 现象 | 含义 | 处置 |
|---|---|---|
| `镜像必须用 digest 钉扎` | 传了 tag | 换成 `@sha256:...` |
| `镜像仓库不在白名单内` | 前缀不匹配 | 显式改白名单并留痕 |
| `upstream 内有 0 行未注释` | nginx 配置已坏 | 先修配置，别升级 |
| `upstream 内有 2 行未注释` | 会轮询混跑 | 注释掉一色 |
| `备色未就绪（mongo=...）` | 新版本连不上依赖 | 未切流，旧色正常；查备色日志 |
| `迁移失败` | 迁移脚本报错 | 未切流；备色容器保留以便排查 |
| `观察期未通过` | 切流后新色不稳 | 已自动切回，查新色日志 |

---

## 7. `/api/version` 契约

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

---

## 8. 本方案刻意没做的事

- **不做自动升级**：自动升级 + 迁移 = 半夜静默炸库。触发必须是人的显式动作（`--apply`）。
- **不做 HTTP 触发接口**（方案里的 L2）：那等于新增一个「能指定跑什么代码」的高危入口，
  需要 reauth 票据 + 内置超管 + digest 白名单三重闸，另行评估。
- **不做灰度分流**（L3）：两色跑不同版本时按比例分流，需要先有稳定的错误率基线。
- **不解决宿主机故障**：蓝绿只覆盖「应用版本切换」，宿主机宕机属高可用范畴。

---

## 9. 已知未验证的部分（如实记录）

- 脚本的**执行路径**（起容器、跑迁移、reload、观察、回滚）**没有在真实双色环境跑过**：
  本地只验证了判据层（28 个用例）、`docker compose config` 解析、以及演练模式的输出。
  首次真实升级前，建议先在一套可丢弃的环境里走一遍，重点看第 3 步与第 6 步的耗时。
- `nginx -s reload` 的中断时长（文档写的 < 100ms）来自 nginx 的既有语义，
  **未在本项目实测**；验收时用并发压测确认 0 个 5xx。
