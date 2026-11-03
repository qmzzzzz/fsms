/**
 * xlsxWriter 的三处口径闸（E8）：
 * ① sst 的 count 改为**实计**引用数（空单元格写 <c/> 不引用共享串，不计入）——
 *    旧实现按 行数×列数 估算，空值越多偏差越大；
 * ② createWorkbook 对 width/defaultColWidth 做数值边界断言（OOXML 的数值属性，
 *    类型闸 fail-fast，坏值不进 XML）；
 * ③ orderValues 对象形态缺列 key ⇒ TypeError 带列名（静默写空格会让整列无声变空）。
 * 读取 sst 用一个 30 行的最小 zip 读端（zipContainer 无读侧；只认本仓 buildZip 的产物）。
 */

const zlib = require('zlib');
const { createWorkbook } = require('../../utils/xlsxWriter');

/** 最小 zip 读端：扫 local file header，按名字取条目并解压（只认 buildZip 的产物形态） */
const readPart = (buffer, name) => {
  let offset = 0;
  while (offset + 30 <= buffer.length) {
    if (buffer.readUInt32LE(offset) !== 0x04034b50) {
      offset += 1;
      continue;
    }
    const method = buffer.readUInt16LE(offset + 8);
    const compressedSize = buffer.readUInt32LE(offset + 18);
    const nameLen = buffer.readUInt16LE(offset + 26);
    const extraLen = buffer.readUInt16LE(offset + 28);
    const entryName = buffer.toString('latin1', offset + 30, offset + 30 + nameLen);
    const dataStart = offset + 30 + nameLen + extraLen;
    if (entryName === name) {
      const raw = buffer.subarray(dataStart, dataStart + compressedSize);
      return method === 0 ? Buffer.from(raw) : zlib.inflateRawSync(raw);
    }
    offset = dataStart + compressedSize;
  }
  return null;
};

const COLUMNS = [
  { header: '设备编号', key: 'deviceCode', width: 20 },
  { header: '位置', key: 'location', width: 20 },
];

describe('xlsxWriter 三处口径闸（E8）', () => {
  test('① sst.count 是实计引用数：空单元格不计入，uniqueCount 仍是去重数', () => {
    const wb = createWorkbook({ sheetName: '设备', columns: COLUMNS });
    wb.sheet.addRow({ deviceCode: 'A1', location: '东楼' });
    wb.sheet.addRow({ deviceCode: 'A1', location: '' }); // 空值 + 与上行重复的引用
    wb.sheet.addRow({ deviceCode: '', location: '' }); // 整行空
    const sst = readPart(wb.toBuffer(), 'xl/sharedStrings.xml').toString('utf8');
    const count = Number(/count="(\d+)"/.exec(sst)[1]);
    const uniqueCount = Number(/uniqueCount="(\d+)"/.exec(sst)[1]);
    // t="s" 引用：表头 2 + 行1 两个 + 行2 一个（deviceCode）= 5；旧行×列估算会算成 8
    expect(count).toBe(5);
    expect(uniqueCount).toBe(4); // '设备编号'/'位置'/'A1'/'东楼'（行2 的 'A1' 与行1 去重）
  });

  test('② width / defaultColWidth 越界或非数值 ⇒ TypeError（构造期 fail-fast）', () => {
    expect(() =>
      createWorkbook({ sheetName: 's', columns: [{ header: 'x', key: 'x', width: 0 }] })
    ).toThrow(TypeError);
    expect(() =>
      createWorkbook({ sheetName: 's', columns: [{ header: 'x', key: 'x', width: 256 }] })
    ).toThrow(TypeError);
    expect(() =>
      createWorkbook({ sheetName: 's', columns: [{ header: 'x', key: 'x', width: NaN }] })
    ).toThrow(TypeError);
    expect(() => createWorkbook({ sheetName: 's', columns: COLUMNS, defaultColWidth: -1 })).toThrow(
      TypeError
    );
    expect(() =>
      createWorkbook({ sheetName: 's', columns: COLUMNS, defaultColWidth: 300 })
    ).toThrow(TypeError);
    // 合法边界不误伤
    expect(() =>
      createWorkbook({
        sheetName: 's',
        columns: [{ header: 'x', key: 'x', width: 255 }],
        defaultColWidth: 15,
      })
    ).not.toThrow();
  });

  test('③ orderValues：对象缺列 key ⇒ TypeError 带列名；数组形态不受影响', () => {
    const wb = createWorkbook({ sheetName: 's', columns: COLUMNS });
    expect(() => wb.sheet.addRow({ deviceCode: 'A1' })).toThrow(/location/);
    expect(() => wb.sheet.addRow({ location: 'y' })).toThrow(/deviceCode/);
    expect(() => wb.sheet.addRow(['只有一格'])).not.toThrow(); // 数组形态（脚注/水印行）
    expect(() => wb.sheet.addRow('字符串行')).toThrow(TypeError);
  });
});
