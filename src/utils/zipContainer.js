'use strict';

/**
 * 最小 ZIP 容器（只写、不读）
 *
 * ## 为什么手写而不是装一个包
 * 生产依赖树每多一个包，就多一条「上游何时修」的外部依赖。本仓 2026-11 的僵局
 * 正是这么来的：exceljs → archiver → archiver-utils → glob → minimatch，根因公告
 * 在上游，我们只能等。而 xlsx 需要的 ZIP 面极窄——只有 deflate + 中央目录，
 * 没有任何读取、没有 ZIP64、没有加密、没有 data descriptor。
 *
 * ## 依赖边界
 * 只用 `node:zlib`：`deflateRawSync` 出压缩流、`crc32` 出校验和。`zlib.crc32` 在
 * Node ≥22.2.0 才有，本仓 `engines` 是 `>=22.12.0`，故可用；放宽 engines 前必须先
 * 确认这一点（否则是运行期 `undefined is not a function`）。
 *
 * ## 不实现的 ZIP 特性（如实声明，勿夸大）
 * - **不读**：没有解析器，因此不存在「畸形归档导致死循环」这一类缺陷
 *   （对照：fflate 0.8.2 的 GHSA-px8p-9vwx-vf98 就在 `unzipSync` 里）；
 * - **不写 ZIP64**：单条目或总大小超过 4 GiB 会静默截断 u32 字段。本仓导出上限是
 *   `EXPORT_LIMIT` 行（5000），实测整包 0.17 MB，离 4 GiB 有四个数量级；
 * - **不写目录条目**：Excel 不需要，`[Content_Types].xml` 等路径自带目录语义；
 * - **文件名只支持 ASCII**：本写入器的条目名全是固定 ASCII，故不设 UTF-8 标志位。
 */

const zlib = require('zlib');

/**
 * DOS 时间戳固定为 1980-01-01 00:00。
 *
 * 不用当前时间：同一份数据每次导出应产出同样的字节，否则任何按字节比对的回归
 * （「这份文件与上一版有何不同」）都会被时间戳噪声淹没。Excel 不看这个字段。
 */
const DOS_TIME = 0;
const DOS_DATE = 0x21;

const u16 = (n) => {
  const b = Buffer.alloc(2);
  b.writeUInt16LE(n, 0);
  return b;
};

const u32 = (n) => {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(n >>> 0, 0);
  return b;
};

/** 单个条目的本地头 + 数据；method 8=deflate、0=store */
const buildLocalEntry = (entry) => {
  const name = Buffer.from(entry.name, 'utf8');
  const raw = entry.data;
  const deflated = zlib.deflateRawSync(raw, { level: 6 });
  // 压缩后反而更大时退回 store：小部件（如 200 字节的 workbook.xml）常见这种情况
  const useDeflate = deflated.length < raw.length;
  const body = useDeflate ? deflated : raw;
  return {
    method: useDeflate ? 8 : 0,
    crc: zlib.crc32(raw) >>> 0,
    compressed: body.length,
    uncompressed: raw.length,
    name,
    body,
  };
};

const localHeader = (e) =>
  Buffer.concat([
    u32(0x04034b50),
    u16(20), // version needed
    u16(0), // flags
    u16(e.method),
    u16(DOS_TIME),
    u16(DOS_DATE),
    u32(e.crc),
    u32(e.compressed),
    u32(e.uncompressed),
    u16(e.name.length),
    u16(0), // extra len
    e.name,
  ]);

const centralHeader = (e, offset) =>
  Buffer.concat([
    u32(0x02014b50),
    u16(20), // version made by
    u16(20), // version needed
    u16(0), // flags
    u16(e.method),
    u16(DOS_TIME),
    u16(DOS_DATE),
    u32(e.crc),
    u32(e.compressed),
    u32(e.uncompressed),
    u16(e.name.length),
    u16(0), // extra
    u16(0), // comment
    u16(0), // disk number
    u16(0), // internal attrs
    u32(0), // external attrs
    u32(offset),
    e.name,
  ]);

/**
 * @param {{name:string, data:Buffer}[]} entries 顺序即写入顺序
 *   （`[Content_Types].xml` 必须是第一个——Excel 按此定位包结构）
 * @returns {Buffer} 完整 ZIP
 */
const buildZip = (entries) => {
  const parts = [];
  const central = [];
  let offset = 0;

  for (const entry of entries) {
    const e = buildLocalEntry(entry);
    const local = Buffer.concat([localHeader(e), e.body]);
    parts.push(local);
    central.push(centralHeader(e, offset));
    offset += local.length;
  }

  const directory = Buffer.concat(central);
  const eocd = Buffer.concat([
    u32(0x06054b50),
    u16(0), // disk
    u16(0), // disk with CD
    u16(entries.length),
    u16(entries.length),
    u32(directory.length),
    u32(offset),
    u16(0), // comment len
  ]);
  return Buffer.concat([...parts, directory, eocd]);
};

module.exports = { buildZip };
