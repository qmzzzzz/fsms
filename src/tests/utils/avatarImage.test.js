/**
 * 头像图片校验纯函数（utils/avatarImage）
 *
 * 夹具全部在内存构造，不读二进制文件：判据是"段/chunk 结构"，不是某张具体照片。
 * 覆盖的拒绝面：非 data URI、非规范 Base64、MIME 与 magic 不一致、尺寸越界、
 * APNG、JPEG APP1/APP13/COM 元数据、PNG 文本 chunk、字节上限、
 * "文件尾之后夹带任意载荷"（JPEG 必须在 EOI 结束、PNG 必须在 IEND 结束），
 * 以及"合法但非必需的段/chunk 夹带"（JPEG APPn 白名单、PNG chunk 白名单）。
 */

const {
  parseAvatarImage,
  sniffMime,
  AvatarImageError,
  MAX_AVATAR_BYTES,
  MAX_DATA_URI_CHARS,
} = require('../../utils/avatarImage');

const zlib = require('zlib');

const PNG_SIG = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

// chunk 必须带真实 CRC：校验器会逐 chunk 核对（CRC 为零等于给自己伪造一张坏图）
function pngChunk(type, data) {
  const chunk = Buffer.alloc(12 + data.length);
  chunk.writeUInt32BE(data.length, 0);
  chunk.write(type, 4, 'latin1');
  data.copy(chunk, 8);
  const body = Buffer.concat([Buffer.from(type, 'latin1'), data]);
  chunk.writeUInt32BE(zlib.crc32(body), 8 + data.length);
  return chunk;
}

/** 一张真能被解码器解开的 PNG：IDAT 是按 IHDR 尺寸算出来的 zlib 流 */
function pngBuffer(width, height, extraChunks = [], ihdrOverride = {}) {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 6; // RGBA
  for (const [index, value] of Object.entries(ihdrOverride)) ihdr[Number(index)] = value;
  const channels = { 0: 1, 2: 3, 3: 1, 4: 2, 6: 4 }[ihdr[9]] || 4;
  const depth = [1, 2, 4, 8, 16].includes(ihdr[8]) ? ihdr[8] : 8;
  const raw = Buffer.alloc((1 + Math.ceil((width * channels * depth) / 8)) * height, 0);
  const idat = pngChunk('IDAT', zlib.deflateSync(raw));
  const iend = pngChunk('IEND', Buffer.alloc(0));
  return Buffer.concat([PNG_SIG, pngChunk('IHDR', ihdr), ...extraChunks, idat, iend]);
}

/** 一张 8 位量化表：Pq/Tq 1 字节 + 64 字节表值（段长 67，payload 65） */
function dqtSegment() {
  return jpegSegment(0xdb, Buffer.concat([Buffer.from([0x00]), Buffer.alloc(64, 0x10)]));
}

/** 一张霍夫曼表：Tc/Th 1 字节 + 16 字节码长 + 10 个符号（payload 27） */
function dhtSegment() {
  const counts = Buffer.alloc(16, 0);
  counts[15] = 10;
  return jpegSegment(0xc4, Buffer.concat([Buffer.from([0x00]), counts, Buffer.alloc(10, 0)]));
}
function jpegSegment(marker, payload) {
  const segment = Buffer.alloc(4 + payload.length);
  segment[0] = 0xff;
  segment[1] = marker;
  segment.writeUInt16BE(2 + payload.length, 2);
  payload.copy(segment, 4);
  return segment;
}

function jpegBuffer(width, height, extraSegments = [], scanData = Buffer.alloc(12, 0x11)) {
  const app0 = jpegSegment(0xe0, Buffer.from('JFIF\0\x01\x01\0\0\x01\0\x01\0\0', 'latin1'));
  const sof = jpegSegment(
    0xc0,
    Buffer.from([
      8,
      height >> 8,
      height & 0xff,
      width >> 8,
      width & 0xff,
      3,
      1,
      0x11,
      0,
      2,
      0x11,
      0,
      3,
      0x11,
      0,
    ])
  );
  const sos = jpegSegment(0xda, Buffer.from([3, 1, 0, 2, 0x11, 3, 0x11, 0, 0x3f, 0]));
  return Buffer.concat([
    Buffer.from([0xff, 0xd8]),
    app0,
    ...extraSegments,
    sof,
    sos,
    scanData,
    Buffer.from([0xff, 0xd9]),
  ]);
}

const toDataUri = (buffer, mime) => `data:${mime};base64,${buffer.toString('base64')}`;

const expectReason = (fn, reason) => {
  try {
    fn();
    throw new Error('应当被拒绝但没有');
  } catch (error) {
    expect(error).toBeInstanceOf(AvatarImageError);
    expect(error.reason).toBe(reason);
  }
};

describe('avatarImage.parseAvatarImage', () => {
  test('合法 PNG：尺寸/大小/hash 正确且 hash 稳定', () => {
    const uri = toDataUri(pngBuffer(32, 32), 'image/png');
    const first = parseAvatarImage(uri);
    const second = parseAvatarImage(uri);
    expect(first.mime).toBe('image/png');
    expect(first.width).toBe(32);
    expect(first.height).toBe(32);
    expect(first.size).toBe(pngBuffer(32, 32).length);
    expect(first.hash).toMatch(/^[0-9a-f]{64}$/);
    expect(second.hash).toBe(first.hash);
  });

  test('合法 JPEG：从 SOF0 读出宽高', () => {
    const result = parseAvatarImage(toDataUri(jpegBuffer(64, 48), 'image/jpeg'));
    expect(result.mime).toBe('image/jpeg');
    expect(result.width).toBe(64);
    expect(result.height).toBe(48);
  });

  test('sniffMime 只认 JPEG/PNG magic', () => {
    expect(sniffMime(jpegBuffer(32, 32))).toBe('image/jpeg');
    expect(sniffMime(pngBuffer(32, 32))).toBe('image/png');
    expect(sniffMime(Buffer.from('GIF89a'))).toBeNull();
  });

  test('非 data URI / 声明 SVG / 含空白 → 拒绝', () => {
    expectReason(() => parseAvatarImage('hello'), 'FORMAT_INVALID');
    expectReason(() => parseAvatarImage('data:image/svg+xml;base64,PHN2Zy8+'), 'FORMAT_INVALID');
    expectReason(() => parseAvatarImage('data:image/png;base64,AAA AAAA'), 'FORMAT_INVALID');
  });

  test('Base64 形态不合法（多重填充）→ 拒绝', () => {
    const uri = toDataUri(pngBuffer(32, 32), 'image/png');
    expectReason(() => parseAvatarImage(uri + '===='), 'FORMAT_INVALID');
  });

  test('MIME 与 magic 不一致 → 拒绝', () => {
    expectReason(
      () => parseAvatarImage(toDataUri(pngBuffer(32, 32), 'image/jpeg')),
      'MAGIC_MISMATCH'
    );
  });

  test('尺寸越界（过小/过大/超 1MP）→ 拒绝', () => {
    expectReason(
      () => parseAvatarImage(toDataUri(pngBuffer(8, 8), 'image/png')),
      'DIMENSION_INVALID'
    );
    expectReason(
      () => parseAvatarImage(toDataUri(pngBuffer(2048, 2048), 'image/png')),
      'DIMENSION_INVALID'
    );
    expectReason(
      () => parseAvatarImage(toDataUri(pngBuffer(1024, 1025), 'image/png')),
      'DIMENSION_INVALID'
    );
  });

  test('APNG（acTL）→ 拒绝', () => {
    const actl = pngChunk('acTL', Buffer.alloc(8));
    expectReason(
      () => parseAvatarImage(toDataUri(pngBuffer(32, 32, [actl]), 'image/png')),
      'ANIMATED_UNSUPPORTED'
    );
  });

  test('PNG 文本/EXIF chunk → 拒绝（不剥离，直接拒）', () => {
    for (const type of ['tEXt', 'zTXt', 'iTXt', 'eXIf', 'tIME']) {
      const chunk = pngChunk(type, Buffer.from('secret', 'latin1'));
      expectReason(
        () => parseAvatarImage(toDataUri(pngBuffer(32, 32, [chunk]), 'image/png')),
        'METADATA_PRESENT'
      );
    }
  });

  test('PNG 允许的辅助 chunk（sRGB/gAMA/pHYs）→ 接受（System.Drawing 形态）', () => {
    const extra = [
      pngChunk('sRGB', Buffer.from([0])),
      pngChunk('gAMA', Buffer.from([0, 0, 0xb1, 0x8f])),
      pngChunk('pHYs', Buffer.alloc(9, 1)),
    ];
    const result = parseAvatarImage(toDataUri(pngBuffer(32, 32, extra), 'image/png'));
    expect(result.width).toBe(32);
    expect(result.height).toBe(32);
  });

  test('PNG 白名单外的 chunk（iCCP/sPLT/私有）→ 拒绝', () => {
    for (const type of ['iCCP', 'sPLT', 'hIST', 'prVt']) {
      expectReason(
        () =>
          parseAvatarImage(
            toDataUri(pngBuffer(32, 32, [pngChunk(type, Buffer.alloc(20))]), 'image/png')
          ),
        'PNG_UNSUPPORTED_CHUNK'
      );
    }
  });

  test('PNG 定长 chunk 长度不符 → 拒绝', () => {
    expectReason(
      () =>
        parseAvatarImage(
          toDataUri(pngBuffer(32, 32, [pngChunk('sRGB', Buffer.alloc(2))]), 'image/png')
        ),
      'PNG_MALFORMED'
    );
  });

  test('JPEG APP2 完整 ICC_PROFILE → 接受（Chromium canvas 形态）', () => {
    const profile = Buffer.alloc(456);
    profile.writeUInt32BE(456, 0);
    profile.write('acsp', 36, 'latin1');
    const icc = jpegSegment(
      0xe2,
      Buffer.concat([Buffer.from('ICC_PROFILE\0', 'latin1'), Buffer.from([1, 1]), profile])
    );
    const result = parseAvatarImage(toDataUri(jpegBuffer(32, 32, [icc]), 'image/jpeg'));
    expect(result.width).toBe(32);
  });

  test('JPEG APP2 只带 ICC_PROFILE 前缀、结构不符 → 拒绝', () => {
    const fake = Buffer.concat([
      Buffer.from('ICC_PROFILE\0', 'latin1'),
      Buffer.from([1, 1]),
      Buffer.alloc(128, 0x41),
    ]);
    expectReason(
      () =>
        parseAvatarImage(toDataUri(jpegBuffer(32, 32, [jpegSegment(0xe2, fake)]), 'image/jpeg')),
      'JPEG_UNSUPPORTED_SEGMENT'
    );
  });

  test('JPEG APP14 Adobe（12 字节头）→ 接受，结构不符 → 拒绝', () => {
    const adobe = jpegSegment(
      0xee,
      Buffer.concat([Buffer.from('Adobe', 'latin1'), Buffer.alloc(7)])
    );
    const ok = parseAvatarImage(toDataUri(jpegBuffer(32, 32, [adobe]), 'image/jpeg'));
    expect(ok.width).toBe(32);
    const bad = jpegSegment(0xee, Buffer.concat([Buffer.from('AdobX', 'latin1'), Buffer.alloc(7)]));
    expectReason(
      () => parseAvatarImage(toDataUri(jpegBuffer(32, 32, [bad]), 'image/jpeg')),
      'JPEG_UNSUPPORTED_SEGMENT'
    );
  });

  test('JPEG 允许的 DQT/DHT/DRI 段 → 接受', () => {
    const segments = [dqtSegment(), dhtSegment(), jpegSegment(0xdd, Buffer.from([0, 2]))];
    const result = parseAvatarImage(toDataUri(jpegBuffer(32, 32, segments), 'image/jpeg'));
    expect(result.width).toBe(32);
  });

  test('JPEG 白名单外的 APPn（APP3/APP15）→ 拒绝', () => {
    for (const marker of [0xe3, 0xef]) {
      expectReason(
        () =>
          parseAvatarImage(
            toDataUri(
              jpegBuffer(32, 32, [jpegSegment(marker, Buffer.from('payload', 'latin1'))]),
              'image/jpeg'
            )
          ),
        'JPEG_UNSUPPORTED_SEGMENT'
      );
    }
  });

  test('JPEG APP0 带缩略图或非 JFIF → 拒绝', () => {
    const thumb = jpegSegment(
      0xe0,
      Buffer.concat([
        Buffer.from('JFIF\0\x01\x01\0\0\x01\0\x01\x01\x01', 'latin1'),
        Buffer.alloc(3),
      ])
    );
    expectReason(
      () => parseAvatarImage(toDataUri(jpegBuffer(32, 32, [thumb]), 'image/jpeg')),
      'JPEG_UNSUPPORTED_SEGMENT'
    );
    const jfxx = jpegSegment(0xe0, Buffer.from('JFXX\0\x10\0', 'latin1'));
    expectReason(
      () => parseAvatarImage(toDataUri(jpegBuffer(32, 32, [jfxx]), 'image/jpeg')),
      'JPEG_UNSUPPORTED_SEGMENT'
    );
  });

  test('JPEG APP1/APP13/COM 元数据段 → 拒绝', () => {
    for (const marker of [0xe1, 0xed, 0xfe]) {
      const segment = jpegSegment(marker, Buffer.from('EXIF', 'latin1'));
      expectReason(
        () => parseAvatarImage(toDataUri(jpegBuffer(32, 32, [segment]), 'image/jpeg')),
        'METADATA_PRESENT'
      );
    }
  });

  test('字节上限与字符上限 → 拒绝', () => {
    const big = pngBuffer(32, 32);
    const inflated = Buffer.concat([big, Buffer.alloc(MAX_AVATAR_BYTES, 0x00)]);
    expectReason(() => parseAvatarImage(toDataUri(inflated, 'image/png')), 'TOO_LARGE');
    expectReason(
      () => parseAvatarImage('data:image/png;base64,' + 'A'.repeat(MAX_DATA_URI_CHARS)),
      'TOO_LARGE'
    );
  });

  test('段长度越界 → JPEG_MALFORMED，且不发生越界读', () => {
    const broken = Buffer.concat([
      Buffer.from([0xff, 0xd8, 0xff, 0xc0, 0x13, 0x88]),
      Buffer.alloc(80, 0x00),
    ]);
    expectReason(() => parseAvatarImage(toDataUri(broken, 'image/jpeg')), 'JPEG_MALFORMED');
  });

  test('JPEG EOI 之后追加 HTML/任意载荷 → 拒绝', () => {
    const jpeg = Buffer.concat([
      jpegBuffer(32, 32),
      Buffer.from('<html><script>alert(1)</script></html>', 'latin1'),
    ]);
    expectReason(() => parseAvatarImage(toDataUri(jpeg, 'image/jpeg')), 'JPEG_TRAILING_DATA');
  });

  test('PNG IEND 之后追加 ZIP/HTML → 拒绝', () => {
    const png = Buffer.concat([
      pngBuffer(32, 32),
      Buffer.from('PK\x03\x04<html><script>alert(1)</script>', 'latin1'),
    ]);
    expectReason(() => parseAvatarImage(toDataUri(png, 'image/png')), 'PNG_TRAILING_DATA');
  });

  test('JPEG 缺少 EOI / PNG 缺少 IEND → 拒绝', () => {
    const jpeg = jpegBuffer(32, 32);
    expectReason(
      () => parseAvatarImage(toDataUri(jpeg.subarray(0, jpeg.length - 2), 'image/jpeg')),
      'JPEG_MALFORMED'
    );
    const png = pngBuffer(32, 32);
    expectReason(
      () => parseAvatarImage(toDataUri(png.subarray(0, png.length - 12), 'image/png')),
      'PNG_MALFORMED'
    );
  });

  test('PNG 缺少 IDAT → 拒绝', () => {
    const ihdr = Buffer.alloc(13);
    ihdr.writeUInt32BE(32, 0);
    ihdr.writeUInt32BE(32, 4);
    ihdr[8] = 8;
    ihdr[9] = 6;
    const noIdat = Buffer.concat([
      PNG_SIG,
      pngChunk('IHDR', ihdr),
      pngChunk('sRGB', Buffer.from([0])),
      pngChunk('pHYs', Buffer.alloc(9, 1)),
      pngChunk('IEND', Buffer.alloc(0)),
    ]);
    expectReason(() => parseAvatarImage(toDataUri(noIdat, 'image/png')), 'PNG_MALFORMED');
  });

  test('PNG 空 IDAT / 重复 IHDR → 拒绝', () => {
    const ihdr = Buffer.alloc(13);
    ihdr.writeUInt32BE(32, 0);
    ihdr.writeUInt32BE(32, 4);
    ihdr[8] = 8;
    ihdr[9] = 6;
    const emptyIdat = Buffer.concat([
      PNG_SIG,
      pngChunk('IHDR', ihdr),
      pngChunk('pHYs', Buffer.alloc(9, 1)),
      pngChunk('IDAT', Buffer.alloc(0)),
      pngChunk('IEND', Buffer.alloc(0)),
    ]);
    expectReason(() => parseAvatarImage(toDataUri(emptyIdat, 'image/png')), 'PNG_MALFORMED');
    expectReason(
      () => parseAvatarImage(toDataUri(pngBuffer(32, 32, [pngChunk('IHDR', ihdr)]), 'image/png')),
      'PNG_MALFORMED'
    );
  });

  test('JPEG 扫描数据为空 → 拒绝', () => {
    const filler = dqtSegment();
    expectReason(
      () =>
        parseAvatarImage(toDataUri(jpegBuffer(32, 32, [filler], Buffer.alloc(0)), 'image/jpeg')),
      'JPEG_MALFORMED'
    );
  });
  test('JPEG 熵编码中的 FF00 填充与 RSTn 不误判为文件尾', () => {
    const scanData = Buffer.concat([
      Buffer.alloc(10, 0x11),
      Buffer.from([0xff, 0x00, 0x11, 0xff, 0xd0, 0x11]),
    ]);
    const result = parseAvatarImage(toDataUri(jpegBuffer(32, 32, [], scanData), 'image/jpeg'));
    expect(result.width).toBe(32);
    expect(result.height).toBe(32);
  });

  test('PNG IHDR 位深/色型/压缩法/滤波法非法 → 拒绝', () => {
    for (const override of [{ 8: 3 }, { 8: 4, 9: 6 }, { 9: 7 }, { 10: 99 }, { 11: 99 }]) {
      expectReason(
        () => parseAvatarImage(toDataUri(pngBuffer(32, 32, [], override), 'image/png')),
        'PNG_MALFORMED'
      );
    }
  });

  test('PNG 隔行（Adam7）→ 拒绝，且理由单列', () => {
    expectReason(
      () => parseAvatarImage(toDataUri(pngBuffer(32, 32, [], { 12: 1 }), 'image/png')),
      'PNG_INTERLACE_UNSUPPORTED'
    );
    expectReason(
      () => parseAvatarImage(toDataUri(pngBuffer(32, 32, [], { 12: 9 }), 'image/png')),
      'PNG_MALFORMED'
    );
  });

  test('PNG 调色板图：有 PLTE → 接受；无 PLTE / PLTE 在 IDAT 之后 / 长度非 3 倍 → 拒绝', () => {
    const palette = pngChunk('PLTE', Buffer.alloc(12, 0x22));
    const ok = parseAvatarImage(
      toDataUri(pngBuffer(20, 20, [palette], { 8: 8, 9: 3 }), 'image/png')
    );
    expect(ok.width).toBe(20);
    expectReason(
      () => parseAvatarImage(toDataUri(pngBuffer(20, 20, [], { 8: 8, 9: 3 }), 'image/png')),
      'PNG_MALFORMED'
    );
    expectReason(
      () =>
        parseAvatarImage(
          toDataUri(
            pngBuffer(20, 20, [pngChunk('PLTE', Buffer.alloc(7, 1))], { 8: 8, 9: 3 }),
            'image/png'
          )
        ),
      'PNG_MALFORMED'
    );
    const ihdr = Buffer.alloc(13);
    ihdr.writeUInt32BE(20, 0);
    ihdr.writeUInt32BE(20, 4);
    ihdr[8] = 8;
    ihdr[9] = 3;
    const late = Buffer.concat([
      PNG_SIG,
      pngChunk('IHDR', ihdr),
      pngChunk('IDAT', zlib.deflateSync(Buffer.alloc(21 * 20, 0))),
      palette,
      pngChunk('IEND', Buffer.alloc(0)),
    ]);
    expectReason(() => parseAvatarImage(toDataUri(late, 'image/png')), 'PNG_MALFORMED');
  });

  test('PNG IDAT 不是 zlib 流 / 字节数与声明尺寸不符 / 尾部夹带 → 拒绝', () => {
    const ihdr = Buffer.alloc(13);
    ihdr.writeUInt32BE(32, 0);
    ihdr.writeUInt32BE(32, 4);
    ihdr[8] = 8;
    ihdr[9] = 6;
    const build = (payload) =>
      Buffer.concat([
        PNG_SIG,
        pngChunk('IHDR', ihdr),
        pngChunk('IDAT', payload),
        pngChunk('IEND', Buffer.alloc(0)),
      ]);
    expectReason(
      () => parseAvatarImage(toDataUri(build(Buffer.alloc(64, 0)), 'image/png')),
      'PNG_MALFORMED'
    );
    expectReason(
      () => parseAvatarImage(toDataUri(build(zlib.deflateSync(Buffer.alloc(16, 0))), 'image/png')),
      'PNG_MALFORMED'
    );
    const stream = zlib.deflateSync(Buffer.alloc((1 + 32 * 4) * 32, 0));
    const trailing = Buffer.concat([stream, Buffer.from('JUNKPAYLOAD', 'latin1')]);
    expectReason(() => parseAvatarImage(toDataUri(build(trailing), 'image/png')), 'PNG_MALFORMED');
  });

  test('PNG chunk CRC 被篡改 → 拒绝（CRC 为零的自造图不算合法 PNG）', () => {
    const good = pngBuffer(32, 32);
    const bad = Buffer.from(good);
    // IHDR 的 CRC 位于 8+4+4+13 = 29..32
    bad.writeUInt32BE(0, 29);
    expectReason(() => parseAvatarImage(toDataUri(bad, 'image/png')), 'PNG_MALFORMED');
    // 反过来：把 IDAT 数据改一个字节而不改 CRC，同样必须被抓住
    const flipped = Buffer.from(good);
    const idatDataStart = 8 + 12 + 13 + 12 + 8;
    flipped[idatDataStart] ^= 0xff;
    expectReason(() => parseAvatarImage(toDataUri(flipped, 'image/png')), 'PNG_MALFORMED');
  });

  test('PNG 变量长度 chunk 按色型定长：tRNS/sBIT/bKGD 塞大块字节 → 拒绝', () => {
    // 这三种 chunk 长度随色型固定；不校验长度，它们就是三条"合法 chunk 名 + 任意字节"的夹带通道
    const junk = Buffer.alloc(200000, 0x41);
    for (const type of ['tRNS', 'sBIT', 'bKGD']) {
      expectReason(
        () => parseAvatarImage(toDataUri(pngBuffer(32, 32, [pngChunk(type, junk)]), 'image/png')),
        'PNG_MALFORMED'
      );
    }
    // 灰度图 tRNS 必须是 2 字节，给 1 字节要拒
    expectReason(
      () =>
        parseAvatarImage(
          toDataUri(
            pngBuffer(32, 32, [pngChunk('tRNS', Buffer.alloc(1, 0))], { 9: 0 }),
            'image/png'
          )
        ),
      'PNG_MALFORMED'
    );
    // 灰度图不允许 PLTE
    expectReason(
      () =>
        parseAvatarImage(
          toDataUri(
            pngBuffer(32, 32, [pngChunk('PLTE', Buffer.alloc(6, 0x10))], { 9: 0 }),
            'image/png'
          )
        ),
      'PNG_MALFORMED'
    );
  });

  test('PNG 重复 chunk（PLTE/tRNS/sRGB）→ 拒绝', () => {
    const dupPalette = pngBuffer(
      32,
      32,
      [pngChunk('PLTE', Buffer.alloc(6, 0x10)), pngChunk('PLTE', Buffer.alloc(6, 0x20))],
      { 9: 3 }
    );
    expectReason(() => parseAvatarImage(toDataUri(dupPalette, 'image/png')), 'PNG_MALFORMED');
    const dupSrgb = pngBuffer(32, 32, [
      pngChunk('sRGB', Buffer.from([0])),
      pngChunk('sRGB', Buffer.from([1])),
    ]);
    expectReason(() => parseAvatarImage(toDataUri(dupSrgb, 'image/png')), 'PNG_MALFORMED');
  });

  test('PNG chunk 出现在 IDAT 之后 → 拒绝（规范只允许 IEND 收尾）', () => {
    const late = Buffer.concat([
      PNG_SIG,
      pngChunk('IHDR', pngBuffer(32, 32).subarray(16, 29)),
      pngChunk('IDAT', zlib.deflateSync(Buffer.alloc((1 + 32 * 4) * 32, 0))),
      pngChunk('tRNS', Buffer.alloc(6, 0)),
      pngChunk('IEND', Buffer.alloc(0)),
    ]);
    expectReason(() => parseAvatarImage(toDataUri(late, 'image/png')), 'PNG_MALFORMED');
  });

  test('PNG 解压炸弹（16×16 头 + 200 MB 解压输出）→ 拒绝', () => {
    const ihdr = Buffer.alloc(13);
    ihdr.writeUInt32BE(16, 0);
    ihdr.writeUInt32BE(16, 4);
    ihdr[8] = 8;
    ihdr[9] = 6;
    const bomb = Buffer.concat([
      PNG_SIG,
      pngChunk('IHDR', ihdr),
      pngChunk('IDAT', zlib.deflateSync(Buffer.alloc(200 * 1024 * 1024, 0))),
      pngChunk('IEND', Buffer.alloc(0)),
    ]);
    expectReason(() => parseAvatarImage(toDataUri(bomb, 'image/png')), 'PNG_MALFORMED');
  });

  test('JPEG 量化表/霍夫曼表/扫描头长度不自洽 → 拒绝（否则段尾就是夹带位）', () => {
    const badDqt = jpegSegment(0xdb, Buffer.alloc(64, 0x10)); // 缺 Pq/Tq 头字节
    const badPq = jpegSegment(0xdb, Buffer.concat([Buffer.from([0x20]), Buffer.alloc(64, 0x10)])); // Pq=2
    const badDht = jpegSegment(0xc4, Buffer.alloc(16, 0x00)); // 码长表都放不下
    const badDhtSym = jpegSegment(0xc4, Buffer.concat([Buffer.from([0]), Buffer.alloc(16, 0xff)])); // 声称 4080 个符号
    const badSos = jpegSegment(0xda, Buffer.from([3, 1, 0, 2, 0x11, 3, 0x11, 0, 0x3f, 0, 0xaa]));
    for (const segment of [badDqt, badPq, badDht, badDhtSym, badSos]) {
      expectReason(
        () => parseAvatarImage(toDataUri(jpegBuffer(32, 32, [segment]), 'image/jpeg')),
        'JPEG_MALFORMED'
      );
    }
  });

  test('JPEG 帧头分量数为 0/5 或与段长不自洽 → 拒绝', () => {
    const app0 = jpegSegment(0xe0, Buffer.from('JFIF\0\x01\x01\0\0\x01\0\x01\0\0', 'latin1'));
    for (const components of [0, 5]) {
      const payload = Buffer.from([8, 0, 32, 0, 32, components, 1, 0x11, 0]);
      const jpeg = Buffer.concat([
        Buffer.from([0xff, 0xd8]),
        app0,
        dqtSegment(),
        jpegSegment(0xc0, payload),
        jpegSegment(0xda, Buffer.from([1, 1, 0, 0, 0x3f, 0])),
        Buffer.alloc(12, 0x11),
        Buffer.from([0xff, 0xd9]),
      ]);
      expectReason(() => parseAvatarImage(toDataUri(jpeg, 'image/jpeg')), 'JPEG_MALFORMED');
    }
  });
});
