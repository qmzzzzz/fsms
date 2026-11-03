// PNG 结构校验（纯函数）：chunk 白名单 + 定长（含随色型变化的 sBIT/bKGD/tRNS）+ IHDR 语义 + IDAT 必须真能解压且字节数恰好等于声明尺寸
const zlib = require('zlib');
const { AvatarImageError } = require('./avatarImageError');

const PNG_SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
const VARIABLE_CHUNKS = ['PLTE', 'IDAT', 'sBIT', 'bKGD', 'tRNS'];
const FIXED_LENGTHS = { IHDR: 13, IEND: 0, sRGB: 1, gAMA: 4, cHRM: 32, pHYs: 9, acTL: 8 };
const ALLOWED_CHUNKS = Object.keys(FIXED_LENGTHS).concat(VARIABLE_CHUNKS);
const METADATA_CHUNKS = ['tEXt', 'zTXt', 'iTXt', 'eXIf', 'tIME'];
const DEPTHS = { 0: [1, 2, 4, 8, 16], 2: [8, 16], 3: [1, 2, 4, 8], 4: [8, 16], 6: [8, 16] };
const CHANNELS = { 0: 1, 2: 3, 3: 1, 4: 2, 6: 4 };
const AUX_LENGTHS = {
  sBIT: { 0: 1, 2: 3, 3: 3, 4: 2, 6: 4 },
  bKGD: { 0: 2, 2: 6, 3: 1, 4: 2, 6: 6 },
  tRNS: { 0: 2, 2: 6, 3: 0 },
};
const SINGLE_CHUNKS = ['PLTE', 'tRNS', 'bKGD', 'sBIT', 'sRGB', 'gAMA', 'cHRM', 'pHYs', 'acTL'];

function assertChunkLength(type, length, colorType) {
  if (type === 'IEND' && length !== 0)
    throw new AvatarImageError('PNG IEND 长度非法', 'PNG_MALFORMED');
  const fixed = FIXED_LENGTHS[type];
  if (fixed !== undefined && length !== fixed) {
    throw new AvatarImageError('PNG chunk 长度非法：' + type, 'PNG_MALFORMED');
  }
  if (type === 'PLTE') {
    if (length % 3 !== 0 || length === 0 || length > 768) {
      throw new AvatarImageError('PNG PLTE 长度非法', 'PNG_MALFORMED');
    }
    if (colorType === 0 || colorType === 4) {
      throw new AvatarImageError('PNG 灰度图不允许 PLTE', 'PNG_MALFORMED');
    }
  }
  const table = AUX_LENGTHS[type];
  if (!table) return;
  const expected = table[colorType];
  const ok = expected === 0 ? length >= 1 && length <= 256 : length === expected;
  if (!ok) throw new AvatarImageError('PNG chunk 长度非法：' + type, 'PNG_MALFORMED');
}

function classifyChunk(type, length, offset, colorType) {
  if (type === 'IHDR' && offset !== 8) throw new AvatarImageError('PNG 重复 IHDR', 'PNG_MALFORMED');
  if (METADATA_CHUNKS.includes(type)) return true;
  if (!ALLOWED_CHUNKS.includes(type)) {
    throw new AvatarImageError('PNG 含不受支持的 chunk：' + type, 'PNG_UNSUPPORTED_CHUNK');
  }
  assertChunkLength(type, length, colorType);
  return false;
}

function readIhdr(buffer) {
  const depth = buffer[24];
  const colorType = buffer[25];
  const legal = (DEPTHS[colorType] || []).includes(depth);
  if (!legal || buffer[26] !== 0 || buffer[27] !== 0 || buffer[28] > 1) {
    throw new AvatarImageError('PNG IHDR 参数非法', 'PNG_MALFORMED');
  }
  if (buffer[28] === 1) {
    throw new AvatarImageError('不支持隔行（Adam7）PNG', 'PNG_INTERLACE_UNSUPPORTED');
  }
  return { depth, colorType };
}

function absorbChunk(state, type, payload) {
  if (state.idat.length > 0 && type !== 'IDAT' && type !== 'IEND') {
    throw new AvatarImageError('PNG 在 IDAT 之后仍有 chunk：' + type, 'PNG_MALFORMED');
  }
  if (SINGLE_CHUNKS.includes(type)) {
    if (state.seen.has(type))
      throw new AvatarImageError('PNG 重复 chunk：' + type, 'PNG_MALFORMED');
    state.seen.add(type);
  }
  if (type === 'acTL') state.isAnimated = true;
  if (type === 'PLTE') state.hasPalette = true;
  if (type === 'IDAT') state.idat.push(payload);
}

function scanChunks(buffer, colorType) {
  const state = {
    idat: [],
    hasMetadata: false,
    isAnimated: false,
    hasPalette: false,
    seen: new Set(),
  };
  let offset = 8;
  while (offset + 12 <= buffer.length) {
    const length = buffer.readUInt32BE(offset);
    if (offset + 12 + length > buffer.length) {
      throw new AvatarImageError('PNG chunk 长度越界', 'PNG_MALFORMED');
    }
    const type = buffer.toString('latin1', offset + 4, offset + 8);
    if (
      zlib.crc32(buffer.subarray(offset + 4, offset + 8 + length)) !==
      buffer.readUInt32BE(offset + 8 + length)
    ) {
      throw new AvatarImageError('PNG chunk CRC 校验失败：' + type, 'PNG_MALFORMED');
    }
    if (classifyChunk(type, length, offset, colorType)) state.hasMetadata = true;
    absorbChunk(state, type, buffer.subarray(offset + 8, offset + 8 + length));
    if (type === 'IEND') {
      if (offset + 12 !== buffer.length) {
        throw new AvatarImageError('PNG 在 IEND 之后仍有数据', 'PNG_TRAILING_DATA');
      }
      state.hasIEND = true;
      return state;
    }
    offset += 12 + length;
  }
  throw new AvatarImageError('PNG 缺少 IEND', 'PNG_MALFORMED');
}

function expectedRawSize(width, height, depth, colorType) {
  const rowBytes = 1 + Math.ceil((width * CHANNELS[colorType] * depth) / 8);
  return rowBytes * height;
}

const readPngIhdrSize = (buffer) => ({
  width: buffer.readUInt32BE(16),
  height: buffer.readUInt32BE(20), // IHDR 声明尺寸（offset 16/20 大端 uint32，零分配）：供调用方在结构扫描/解压之前按业务尺寸闸早拒；IHDR 完整语义校验仍在 readPngMeta
});

function assertIdatDecodable(idat, expected) {
  expected = Math.min(expected, 16 * 1024 * 1024); // 绝对夹取 16MiB = 1024×1024 RGBA16 ≈8.4MB 的 2 倍余量：合法图无感；对声明巨额宽高的攻击样本，inflateSync 的 maxOutputLength 同步封顶（声明 16384² 不再触发按声明尺寸的解压分配）
  const raw = Buffer.concat(idat);
  let info;
  try {
    info = zlib.inflateSync(raw, { maxOutputLength: expected, info: true });
  } catch (error) {
    throw new AvatarImageError('PNG 图像数据无法解压', 'PNG_MALFORMED');
  }
  const consumed = info.engine.bytesWritten;
  if (info.buffer.length !== expected || consumed !== raw.length) {
    throw new AvatarImageError('PNG 图像数据与声明尺寸不符', 'PNG_MALFORMED');
  }
}

function readPngMeta(buffer) {
  if (buffer.length < 33 || !buffer.subarray(0, 8).equals(PNG_SIGNATURE)) {
    throw new AvatarImageError('不是有效的 PNG 图片', 'MAGIC_MISMATCH');
  }
  if (buffer.readUInt32BE(8) !== 13 || buffer.toString('latin1', 12, 16) !== 'IHDR') {
    throw new AvatarImageError('PNG 首个 chunk 必须是 IHDR', 'PNG_MALFORMED');
  }
  const width = buffer.readUInt32BE(16);
  const height = buffer.readUInt32BE(20);
  const { depth, colorType } = readIhdr(buffer);
  const state = scanChunks(buffer, colorType);
  if (state.idat.length === 0) throw new AvatarImageError('PNG 缺少 IDAT 数据', 'PNG_MALFORMED');
  if (colorType === 3 && !state.hasPalette) {
    throw new AvatarImageError('PNG 调色板图缺少 PLTE（或 PLTE 在 IDAT 之后）', 'PNG_MALFORMED');
  }
  assertIdatDecodable(state.idat, expectedRawSize(width, height, depth, colorType));
  return { width, height, hasMetadata: state.hasMetadata, isAnimated: state.isAnimated };
}

module.exports = { readPngMeta, readPngIhdrSize, PNG_SIGNATURE };
