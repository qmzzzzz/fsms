/**
 * ip2region xdb 离线检索器（零依赖实现）
 *
 * 数据文件 src/data/ip2region.xdb 来自 ip2region 官方仓库
 * （github.com/lionsoul2014/ip2region，Apache-2.0），入库版本与刷新方式见
 * 同目录 README.md 与 scripts/update-ip2region.js。
 *
 * 为什么不用 npm 包（ip2region / ip2region-ts 等）：项目纪律是尽量不引入
 * 新依赖，而 xdb v2 格式是公开且稳定的定长索引结构，核心检索只需一个
 * Buffer + 向量索引 + 二分，约百行即可全覆盖——把「依赖」换成「数据文件」，
 * 检索代码自己持有，升级数据不升级代码。
 *
 * xdb v2 文件布局（全部小端）：
 *   [0, 256)     头部：version(2) + indexPolicy(2) + createTime(4) + startIndexPtr(4) + endIndexPtr(4)
 *   [256, 256+256*256*8)  向量索引：按 IP 前两字节 (il0<<8|il1) 定位该桶的段索引区间指针对
 *   之后          数据区：先是去重后的地区字符串，末尾是定长 14 字节/条的段索引数组
 *                （startIp(4) + endIp(4) + dataLen(2) + dataPtr(4)）
 * 检索：向量索引定位桶 → 桶内按 14 字节步长二分 → dataPtr 处取地区串
 * 「国家|区域|省份|城市|ISP」，未命中段返回 ''，'0' 为占位符。
 *
 * 仅支持 IPv4：v2 的 v6 库是另一个文件（ip2region_v6.xdb），本服务当前未随库
 * 分发，IPv6 查询在上层直接短路返回 null。
 */
const fs = require('fs');
const path = require('path');

/** 向量索引区起始偏移（头部固定 256 字节） */
const VECTOR_INDEX_BASE = 256;
/** 单条段索引的定长：startIp(4) + endIp(4) + dataLen(2) + dataPtr(4) */
const SEGMENT_INDEX_SIZE = 14;
/** 头部固定长度 */
const HEADER_SIZE = 256;

/** 数据文件位置固定在仓库内（Docker 镜像 COPY src/ 后相对路径不变），不接受运行时传参 */
const DATA_FILE = path.join(__dirname, '..', 'data', 'ip2region.xdb');

/** 严格 IPv4 点分十进制解析：非法/越界一律 null（不认八进制等歧义写法） */
const parseIPv4 = (text) => {
  if (typeof text !== 'string') return null;
  const m = text.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return null;
  const parts = [m[1], m[2], m[3], m[4]].map(Number);
  if (parts.some((n) => n > 255)) return null;
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
};

/**
 * 结构校验 + 构建检索句柄。坏数据在加载期即刻暴露（服务层 fail-soft 降级为
 * 不显示归属地并打日志），而不是每条查询都走一遍防御分支。
 *
 * @param {Buffer} buffer 完整的 xdb 文件内容
 * @returns {{ buffer: Buffer, version: number, startIndexPtr: number, endIndexPtr: number }}
 */
const loadFromBuffer = (buffer) => {
  // 最小长度 = 头部 + 向量索引区；小于它必然是截断/伪造文件
  if (!Buffer.isBuffer(buffer) || buffer.length < HEADER_SIZE + 256 * 256 * 8) {
    throw new Error('xdb 数据不完整：长度小于头部 + 向量索引区');
  }
  const version = buffer.readUInt16LE(0);
  const startIndexPtr = buffer.readUInt32LE(8);
  const endIndexPtr = buffer.readUInt32LE(12);
  if (version !== 2) {
    throw new Error(`不支持的 xdb 版本 ${version}（预期 2）`);
  }
  if (
    startIndexPtr <= 0 ||
    endIndexPtr <= startIndexPtr ||
    endIndexPtr + SEGMENT_INDEX_SIZE > buffer.length
  ) {
    throw new Error(
      `xdb 段索引指针越界（start=${startIndexPtr}, end=${endIndexPtr}, size=${buffer.length}）`
    );
  }
  return { buffer, version, startIndexPtr, endIndexPtr };
};

/** 加载仓库内置数据文件并校验（路径常量，无外部输入参与） */
const loadDataFile = () => loadFromBuffer(fs.readFileSync(DATA_FILE));

/**
 * 在已加载的数据上检索 IPv4 的原始地区串。
 *
 * @param {{ buffer: Buffer }} handle loadFromBuffer/loadDataFile 的返回值
 * @param {string} ipText 点分十进制 IPv4
 * @returns {string|null} 「国家|区域|省份|城市|ISP」原始串；非 IPv4 返回 null；
 *                          向量桶为空（保留地址等）返回 ''
 */
const searchRaw = (handle, ipText) => {
  const ip = parseIPv4(ipText);
  if (ip === null) return null;

  const { buffer } = handle;
  const bucket = ((ip >>> 24) & 0xff) * 256 + ((ip >>> 16) & 0xff);
  const sPtr = buffer.readUInt32LE(VECTOR_INDEX_BASE + bucket * 8);
  const ePtr = buffer.readUInt32LE(VECTOR_INDEX_BASE + bucket * 8 + 4);
  // 空桶：该前缀下无任何段（生成器保证指针为 0）
  if (sPtr === 0 || ePtr < sPtr) return '';

  let low = 0;
  let high = (ePtr - sPtr) / SEGMENT_INDEX_SIZE;
  while (low <= high) {
    const mid = (low + high) >> 1;
    const p = sPtr + mid * SEGMENT_INDEX_SIZE;
    const startIp = buffer.readUInt32LE(p);
    if (ip < startIp) {
      high = mid - 1;
      continue;
    }
    const endIp = buffer.readUInt32LE(p + 4);
    if (ip > endIp) {
      low = mid + 1;
      continue;
    }
    const dataLen = buffer.readUInt16LE(p + 8);
    const dataPtr = buffer.readUInt32LE(p + 10);
    return buffer.toString('utf-8', dataPtr, dataPtr + dataLen);
  }
  // 落在段间隙（理论不该发生：段连续覆盖全网）；按未命中处理
  return '';
};

/** 模块级单例：首次检索才加载 11MB 数据，避免拖慢应用启动 */
let cachedHandle = null;
const getHandle = () => {
  if (!cachedHandle) cachedHandle = loadDataFile();
  return cachedHandle;
};

/**
 * 检索 IPv4 归属地的原始地区串（进程内缓存数据句柄）。
 *
 * @param {string} ipText
 * @returns {string|null}
 */
const search = (ipText) => searchRaw(getHandle(), ipText);

/** 释放已加载数据句柄（仅测试用：验证懒加载/换数据重建句柄） */
const resetForTest = () => {
  cachedHandle = null;
};

module.exports = {
  DATA_FILE,
  parseIPv4,
  loadFromBuffer,
  loadDataFile,
  searchRaw,
  search,
  resetForTest,
};
