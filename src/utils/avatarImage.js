// 头像图片校验（纯函数）：data URI → 严格 Base64 → magic bytes → 尺寸 → 结构白名单。
// 段/chunk 走白名单而非黑名单（黑名单漏一个 APPn/chunk 就是一条夹带通道），只放行
// Chromium canvas / System.Drawing 等真实编码器会产出的结构件；不做服务端重编码。

const crypto = require('crypto');
const { AvatarImageError } = require('./avatarImageError');
const { readPngMeta, readPngIhdrSize, PNG_SIGNATURE } = require('./pngStructure');

// 原始二进制上限：256 KiB（512×512 JPEG q0.85 的约 3 倍余量）
const MAX_AVATAR_BYTES = 256 * 1024;
const MAX_DATA_URI_CHARS = 400000;
const MIN_AVATAR_BYTES = 64;
const MIN_DIMENSION = 16;
const MAX_DIMENSION = 1024;
const MAX_PIXELS = 1024 * 1024;

const DATA_URI_RE = /^data:image\/(jpeg|png);base64,([A-Za-z0-9+/]+={0,2})$/;

// SOF0/1/2/3/5/6/7/9/10/11/13/14/15：含尺寸的帧头（0xC4/0xC8/0xCC 不是 SOF）
const JPEG_SOF_MARKERS = new Set([
  0xc0, 0xc1, 0xc2, 0xc3, 0xc5, 0xc6, 0xc7, 0xc9, 0xca, 0xcb, 0xcd, 0xce, 0xcf,
]);
// 只可能是元数据的段/chunk（EXIF/XMP、COM、PNG 文本与时间）：一律拒绝，不剥离
const JPEG_METADATA_MARKERS = new Set([0xe1, 0xed, 0xfe]);

// 其余允许的段：量化表/霍夫曼表/算术编码表/帧头/扫描/重启间隔（APP0、APP2 另做结构校验）
const JPEG_ALLOWED_MARKERS = new Set([0xc4, 0xcc, 0xda, 0xdb, 0xdd, ...JPEG_SOF_MARKERS]);

// 严格 Base64：Node 解码宽松（静默丢非法字符），用"重编码后逐字比对"挡住
function decodeStrictBase64(b64) {
  const normalized = b64.replace(/=+$/, '');
  const decoded = Buffer.from(b64, 'base64');
  if (decoded.length === 0 || decoded.toString('base64').replace(/=+$/, '') !== normalized) {
    throw new AvatarImageError('头像数据的 Base64 编码不规范', 'BASE64_INVALID');
  }
  return decoded;
}

function sniffMime(buffer) {
  if (buffer.length >= 3 && buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff) {
    return 'image/jpeg';
  }
  if (buffer.length >= 8 && buffer.subarray(0, 8).equals(PNG_SIGNATURE)) return 'image/png';
  return null;
}

function skipJpegFill(buffer, offset) {
  let next = offset;
  while (next < buffer.length && buffer[next] === 0xff) next += 1;
  return next;
}

function readJpegSegmentLength(buffer, offset) {
  if (offset + 2 > buffer.length) {
    throw new AvatarImageError('JPEG 段结构被截断', 'JPEG_MALFORMED');
  }
  const length = buffer.readUInt16BE(offset);
  if (length < 2 || offset + length > buffer.length) {
    throw new AvatarImageError('JPEG 段长度非法', 'JPEG_MALFORMED');
  }
  return length;
}

// SOF 的段长必须与分量数自洽（2+6+3Nf）：Nf=0 的帧头没有任何分量，解不出一个像素
function readJpegSofSize(buffer, offset, segmentLength) {
  if (segmentLength < 11) throw new AvatarImageError('JPEG 帧头过短', 'JPEG_MALFORMED');
  const components = buffer[offset + 7];
  if (components < 1 || components > 4 || segmentLength !== 8 + 3 * components) {
    throw new AvatarImageError('JPEG 帧头分量数非法', 'JPEG_MALFORMED');
  }
  return { height: buffer.readUInt16BE(offset + 3), width: buffer.readUInt16BE(offset + 5) };
}

// APP0 只接受 14 字节标准 JFIF 头；带缩略图或尾随字节等于在头像里再塞一张图
function assertJfifApp0(buffer, offset, segmentLength) {
  const start = offset + 2;
  const isJfif = segmentLength === 16 && buffer.toString('latin1', start, start + 5) === 'JFIF\0';
  const hasThumbnail = isJfif && (buffer[start + 12] !== 0 || buffer[start + 13] !== 0);
  if (!isJfif || hasThumbnail) {
    throw new AvatarImageError('JPEG APP0 段不是标准 JFIF 头', 'JPEG_UNSUPPORTED_SEGMENT');
  }
}

// APP2 只接受单段完整 ICC_PROFILE：序号/总数为 1、声明长度相符、带 'acsp' 签名
function assertIccApp2(buffer, offset, segmentLength) {
  const start = offset + 2;
  const payloadLength = segmentLength - 2;
  const isIcc =
    payloadLength >= 142 && buffer.toString('latin1', start, start + 12) === 'ICC_PROFILE\0';
  const profileStart = start + 14;
  const profileLength = payloadLength - 14;
  const complete =
    isIcc &&
    buffer[start + 12] === 1 &&
    buffer[start + 13] === 1 &&
    buffer.readUInt32BE(profileStart) === profileLength &&
    buffer.toString('latin1', profileStart + 36, profileStart + 40) === 'acsp';
  if (!complete) {
    throw new AvatarImageError('JPEG APP2 段不是完整的 ICC 色彩配置', 'JPEG_UNSUPPORTED_SEGMENT');
  }
}

// APP14 只接受 12 字节 Adobe 头（'Adobe' + 版本/flags/transform）：定长 12 字节无夹带空间
function assertAdobeApp14(buffer, offset, segmentLength) {
  const isAdobe =
    segmentLength === 14 && buffer.toString('latin1', offset + 2, offset + 7) === 'Adobe';
  if (!isAdobe) throw new AvatarImageError('JPEG APP14 段结构非法', 'JPEG_UNSUPPORTED_SEGMENT');
}

// DQT/DHT/SOS 的长度都由段内表结构决定：不校验就多出一段无人认领的夹带位（Pq/Tq+64|128、Tc/Th+16+符号、6+2Nf）
function assertDqtSegment(buffer, offset, segmentLength) {
  let cursor = offset + 2;
  const end = offset + segmentLength;
  while (cursor < end) {
    const pq = buffer[cursor] >> 4;
    if (pq > 1 || (buffer[cursor] & 0x0f) > 3) {
      throw new AvatarImageError('JPEG 量化表头非法', 'JPEG_MALFORMED');
    }
    cursor += 1 + (pq ? 128 : 64);
    if (cursor > end) throw new AvatarImageError('JPEG 量化表长度非法', 'JPEG_MALFORMED');
  }
}

function assertDhtSegment(buffer, offset, segmentLength) {
  let cursor = offset + 2;
  const end = offset + segmentLength;
  while (cursor < end) {
    if (buffer[cursor] >> 4 > 1 || (buffer[cursor] & 0x0f) > 3) {
      throw new AvatarImageError('JPEG 霍夫曼表头非法', 'JPEG_MALFORMED');
    }
    if (cursor + 17 > end) throw new AvatarImageError('JPEG 霍夫曼表长度非法', 'JPEG_MALFORMED');
    let symbols = 0;
    for (let i = 1; i <= 16; i += 1) symbols += buffer[cursor + i];
    cursor += 17 + symbols;
    if (cursor > end) throw new AvatarImageError('JPEG 霍夫曼表长度非法', 'JPEG_MALFORMED');
  }
}

function assertSosSegment(buffer, offset, segmentLength) {
  const components = buffer[offset + 2];
  if (components < 1 || components > 4 || segmentLength !== 6 + 2 * components) {
    throw new AvatarImageError('JPEG 扫描头分量数非法', 'JPEG_MALFORMED');
  }
}

// 段白名单：APP0/APP2/APP14 已单独校验，元数据段交给 hasMetadata，其余（APP3–APP15 等）一并拒
function assertJpegSegmentAllowed(buffer, marker, offset, segmentLength) {
  if (marker === 0xe0) return assertJfifApp0(buffer, offset, segmentLength);
  if (marker === 0xe2) return assertIccApp2(buffer, offset, segmentLength);
  if (marker === 0xee) return assertAdobeApp14(buffer, offset, segmentLength);
  if (marker === 0xdb) return assertDqtSegment(buffer, offset, segmentLength);
  if (marker === 0xc4) return assertDhtSegment(buffer, offset, segmentLength);
  if (marker === 0xda) return assertSosSegment(buffer, offset, segmentLength);
  if (JPEG_METADATA_MARKERS.has(marker)) return;
  if (!JPEG_ALLOWED_MARKERS.has(marker)) {
    const hex = '0x' + marker.toString(16);
    throw new AvatarImageError('JPEG 含不受支持的段（' + hex + '）', 'JPEG_UNSUPPORTED_SEGMENT');
  }
}

const isStandaloneJpegMarker = (marker) =>
  marker === 0x00 || marker === 0x01 || marker === 0xd8 || (marker >= 0xd0 && marker <= 0xd7);

const hasJpegSoi = (buffer) => buffer.length >= 4 && buffer[0] === 0xff && buffer[1] === 0xd8;

/** 扫描熵编码数据到下一个标记，返回该标记 0xFF 前缀的下标；FF00 与 RSTn 按规范跳过 */
function skipJpegScan(buffer, start) {
  let offset = start;
  while (offset < buffer.length) {
    if (buffer[offset] !== 0xff) {
      offset += 1;
      continue;
    }
    let codeOffset = offset + 1;
    while (codeOffset < buffer.length && buffer[codeOffset] === 0xff) codeOffset += 1;
    if (codeOffset >= buffer.length) {
      throw new AvatarImageError('JPEG 扫描数据被截断', 'JPEG_MALFORMED');
    }
    const code = buffer[codeOffset];
    if (code === 0x00 || (code >= 0xd0 && code <= 0xd7)) {
      offset = codeOffset + 1;
      continue;
    }
    return offset;
  }
  throw new AvatarImageError('JPEG 扫描数据缺少 EOI', 'JPEG_MALFORMED');
}

// 逐段遍历到 EOI：SOS 后按熵编码跳过 FF00/RSTn，并把 EOI 钉死在文件末尾
function readJpegMeta(buffer) {
  if (!hasJpegSoi(buffer)) {
    throw new AvatarImageError('不是有效的 JPEG 图片', 'MAGIC_MISMATCH');
  }
  let offset = 2;
  let width = 0;
  let height = 0;
  let hasMetadata = false;
  let sawEoi = false;
  while (offset < buffer.length) {
    offset = skipJpegFill(buffer, offset);
    if (offset >= buffer.length) break;
    const marker = buffer[offset];
    offset += 1;
    if (marker === 0xd9) {
      // EOI 必须钉在文件末尾：尾随字节否则会被静默存库并随头像响应发回
      if (offset !== buffer.length) {
        throw new AvatarImageError('JPEG 在 EOI 之后仍有数据', 'JPEG_TRAILING_DATA');
      }
      sawEoi = true;
      break;
    }
    if (isStandaloneJpegMarker(marker)) continue;
    const segmentLength = readJpegSegmentLength(buffer, offset);
    if (JPEG_METADATA_MARKERS.has(marker)) hasMetadata = true;
    assertJpegSegmentAllowed(buffer, marker, offset, segmentLength);
    if (JPEG_SOF_MARKERS.has(marker) && width === 0) {
      ({ width, height } = readJpegSofSize(buffer, offset, segmentLength));
    }
    if (marker === 0xda) {
      const scanEnd = skipJpegScan(buffer, offset + segmentLength);
      if (scanEnd === offset + segmentLength) {
        throw new AvatarImageError('JPEG 扫描数据为空', 'JPEG_MALFORMED');
      }
      offset = scanEnd;
      continue;
    }
    offset += segmentLength;
  }
  if (width === 0 || height === 0) {
    throw new AvatarImageError('JPEG 缺少帧头，无法确定尺寸', 'JPEG_MALFORMED');
  }
  if (!sawEoi) throw new AvatarImageError('JPEG 缺少 EOI', 'JPEG_MALFORMED');
  return { width, height, hasMetadata };
}

// 解析并校验 data URI 头像；任一环节不合法即抛 AvatarImageError
function assertFeatureAllowed(meta) {
  if (meta.isAnimated) {
    throw new AvatarImageError('不支持动图（APNG），请上传静态图片', 'ANIMATED_UNSUPPORTED');
  }
  if (meta.hasMetadata) {
    throw new AvatarImageError(
      '图片带有 EXIF/文本元数据，请先在客户端重编码后上传',
      'METADATA_PRESENT'
    );
  }
}

function assertDimensionAllowed(width, height) {
  const tooSmall = width < MIN_DIMENSION || height < MIN_DIMENSION;
  const tooLarge = width > MAX_DIMENSION || height > MAX_DIMENSION || width * height > MAX_PIXELS;
  if (tooSmall || tooLarge) {
    throw new AvatarImageError(
      '图片尺寸需在 16–1024 像素之间且不超过 1 百万像素',
      'DIMENSION_INVALID'
    );
  }
}

function parseAvatarImage(image) {
  if (typeof image !== 'string' || image === '') {
    throw new AvatarImageError('头像数据必须是非空字符串', 'TYPE_INVALID');
  }
  if (image.length > MAX_DATA_URI_CHARS) {
    throw new AvatarImageError('头像数据过大（上限约 256 KB 图片）', 'TOO_LARGE');
  }
  const matched = DATA_URI_RE.exec(image);
  if (!matched) {
    throw new AvatarImageError(
      '头像必须是 data:image/jpeg 或 data:image/png 的 Base64 数据',
      'FORMAT_INVALID'
    );
  }
  const declaredMime = 'image/' + matched[1];
  const buffer = decodeStrictBase64(matched[2]);

  if (buffer.length < MIN_AVATAR_BYTES) {
    throw new AvatarImageError('图片过小，无法作为头像', 'TOO_SMALL');
  }
  if (buffer.length > MAX_AVATAR_BYTES) {
    throw new AvatarImageError('图片超过 256 KB 上限，请压缩后重试', 'TOO_LARGE');
  }
  const sniffed = sniffMime(buffer);
  if (sniffed !== declaredMime) {
    throw new AvatarImageError('图片实际格式与声明不一致', 'MAGIC_MISMATCH');
  }

  let meta;
  if (sniffed === 'image/jpeg') {
    meta = readJpegMeta(buffer); // JPEG 分支不动：SOF 尺寸在逐段扫描里读出，无"按声明尺寸预分配"的放大面
  } else {
    const declared = readPngIhdrSize(buffer); // PNG 先按 IHDR 声明尺寸（零分配）过业务尺寸闸早拒再进解压——否则要等按声明尺寸的巨额 maxOutputLength 在 inflateSync 上撞满才报错（expected 另有 16MiB 绝对夹取兜底）
    assertDimensionAllowed(declared.width, declared.height);
    meta = readPngMeta(buffer);
  }
  assertFeatureAllowed(meta);
  assertDimensionAllowed(meta.width, meta.height);

  return {
    mime: sniffed,
    buffer,
    width: meta.width,
    height: meta.height,
    size: buffer.length,
    hash: crypto.createHash('sha256').update(buffer).digest('hex'),
  };
}

module.exports = {
  MAX_AVATAR_BYTES,
  MAX_DATA_URI_CHARS,
  MAX_DIMENSION,
  MAX_PIXELS,
  MIN_DIMENSION,
  AvatarImageError,
  parseAvatarImage,
  sniffMime,
};
