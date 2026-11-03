# 审计缓冲批量写入（auditBuffer）说明

承接 `src/services/auditBuffer.js` 文件头的论证。

## WAL 兜底（G4 不丢失）

WAL 文件层已拆至 `services/auditBufferWal.js`（O-3 体积棘轮，2026-09-17）：本模块保留内存缓冲、批量落库（flush）与进程生命周期；WAL 的路径派生、按行追加、前缀裁剪、大小上限、毒批序号与归档、以及串行化它们的 walChain 由 wal 模块负责。

对外行为约定：push 时同步追加 WAL 行，flush 落库成功后按**该批文档的 `__walSeq` 精确移除对应行**（F-97：原先按落库条数裁前 N 行，有空洞时会误删未落库行），崩溃后 start() 重放 WAL 残留（先按毒批归档序号过滤）。

## 批次上限（A7）

flush 单轮最多取 MAX_FLUSH_BATCH 条（默认 1000，env `AUDIT_FLUSH_BATCH_SIZE` 钳制 [100,5000]）。为什么必须有上限：15s 链锁 TTL 内，十 MB 级批次的 insertMany 必然超时，而超时的僵尸批次会整批回退缓冲、下一轮批次只会更大——正反馈直撞 flush 内的 isChainFrozen 冻结跳过分支。取不尽的余量留给下一轮定时/满额触发；关停排空不依赖单轮取光（flushAndStop 按缓冲空否循环收敛）。
