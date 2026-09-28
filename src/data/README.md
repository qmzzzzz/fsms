# ip2region.xdb — IP 归属地离线数据

- **来源**：ip2region 官方仓库 [lionsoul2014/ip2region](https://github.com/lionsoul2014/ip2region) 的 `data/ip2region.xdb`（v2 xdb 格式，IPv4，粒度 国家/省/市/ISP）。
- **入库版本**：通过 `ip2region-ts@2.0.1`（npm，fork 自官方数据）取得，头部创建时间 `2024-02-28`，11,070,083 字节。
- **许可证**：ip2region 整仓 Apache-2.0（含数据文件）。
- **刷新**：运行 `node scripts/update-ip2region.js`（自动从官方源下载最新版、校验结构后原子替换本文件）；只打印当前数据日期用 `node scripts/update-ip2region.js --check`。
- **为什么把数据文件入库而不是运行时下载**：后台会话列表的归属地查询必须在无外网/无第三方依赖下工作（与项目「离线优先、零新增依赖」的纪律一致）；入库后由 Docker `COPY src/` 一并带入镜像。
- **格式**：见 `src/utils/ip2regionSearcher.js` 头注释（头部 256B + 向量索引 256×256×8B + 定长 14B 段索引数组，全小端）。检索器不认 `.xdb` 以外的旧版格式（`.dat`/qqwry）。
