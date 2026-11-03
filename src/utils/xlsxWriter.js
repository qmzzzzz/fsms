'use strict';

/**
 * 最小 xlsx 写入器（零第三方依赖）
 * ## 为什么自己写
 * 报表导出只需要「一张表 + 表头样式 + 列宽 + 工作簿属性」，用不到 exceljs 的读、
 * 公式、图表、合并、数据校验。而 exceljs 的生产依赖链（archiver → archiver-utils →
 * glob → minimatch）带一条**上游无解**的 moderate 公告：升 archiver 也没用，
 * 因为 archiver@8 用的 readdir-glob@3 仍依赖 minimatch@^10.2.2（< 11.0.1）。
 * 本仓已有同类先例：`utils/pngStructure.js` 就是手写二进制容器 + `node:zlib`。
 *
 * ## 本写入器覆盖的 OOXML 面（实测自 exceljs 4.4.0 的产物，逐部件对照）
 * `[Content_Types].xml`、`_rels/.rels`、`docProps/core.xml`、`docProps/app.xml`、
 * `xl/workbook.xml`、`xl/_rels/workbook.xml.rels`、`xl/styles.xml`、
 * `xl/sharedStrings.xml`、`xl/worksheets/sheet1.xml` —— 共 9 个部件。
 *
 * 有意**不**支持：多工作表、合并单元格、公式、图片、数据校验、条件格式、数字格式、
 * 日期类型。本仓导出的每个单元格都是**字符串**（`EXPORT_ROW_TRANSFORMS` 全部返回
 * 字符串），所以单元格一律以 `t="s"`（共享字符串）写出——这同时是公式注入防线的一半：
 * `'=1+1` 存成带类型的文本，Excel 打开时不求值（见 reportExportService 的
 * createSafeTransform 注释）。
 *
 * ## 依赖边界
 * 仅 `node:zlib`（经 `utils/zipContainer`）。没有解析器，故不存在「畸形归档」类缺陷。
 */

const { buildZip } = require('./zipContainer');

const XML_DECL = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>';
const NS_MAIN = 'http://schemas.openxmlformats.org/spreadsheetml/2006/main';
const NS_REL = 'http://schemas.openxmlformats.org/officeDocument/2006/relationships';
const NS_PKG_REL = 'http://schemas.openxmlformats.org/package/2006/relationships';
const NS_CONTENT_TYPES = 'http://schemas.openxmlformats.org/package/2006/content-types';

/** 表头样式：exceljs 侧原本写的是 `{ thin: true }`，那是 no-op（边框从未进过文件）。 */
const STYLE_DEFAULT = 0;
const STYLE_HEADER = 1;
const STYLE_WATERMARK = 2;

/** XML 1.0 不允许的控制字符必须剔除，否则 Excel 判「文件已损坏」 */
// eslint-disable-next-line no-control-regex
const ILLEGAL_XML = /[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g;

const escapeXml = (value) =>
  String(value)
    .replace(ILLEGAL_XML, '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');

/** 1 → A、27 → AA（列引用，只用于单元格坐标与 dimension） */
const columnName = (index) => {
  let name = '';
  let n = index;
  while (n > 0) {
    const rem = (n - 1) % 26;
    name = String.fromCharCode(65 + rem) + name;
    n = Math.floor((n - 1) / 26);
  }
  return name;
};

/**
 * 样式表：3 个字体（默认 / 表头粗白 / 水印斜灰）、3 个填充、2 个边框（空 / 细）。
 *
 * 颜色用 `rgb` 而不是 `theme`：theme 色引用需要 `xl/theme/theme1.xml`，本包不写该部件，
 * 指向不存在的主题会让严格的读端（Excel 本体）报「需要修复」。
 */
const buildStyles = () =>
  XML_DECL +
  `<styleSheet xmlns="${NS_MAIN}">` +
  '<fonts count="3">' +
  '<font><sz val="11"/><color rgb="FF000000"/><name val="Calibri"/><family val="2"/></font>' +
  '<font><b/><sz val="11"/><color rgb="FFFFFFFF"/><name val="Calibri"/><family val="2"/></font>' +
  '<font><i/><sz val="11"/><color rgb="FF808080"/><name val="Calibri"/><family val="2"/></font>' +
  '</fonts>' +
  '<fills count="3">' +
  '<fill><patternFill patternType="none"/></fill>' +
  '<fill><patternFill patternType="gray125"/></fill>' +
  '<fill><patternFill patternType="solid"><fgColor rgb="FF4472C4"/><bgColor indexed="64"/></patternFill></fill>' +
  '</fills>' +
  '<borders count="2">' +
  '<border><left/><right/><top/><bottom/><diagonal/></border>' +
  '<border><left style="thin"/><right style="thin"/><top style="thin"/><bottom style="thin"/><diagonal/></border>' +
  '</borders>' +
  '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>' +
  '<cellXfs count="3">' +
  '<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>' +
  '<xf numFmtId="0" fontId="1" fillId="2" borderId="1" xfId="0"' +
  ' applyFont="1" applyFill="1" applyBorder="1" applyAlignment="1">' +
  '<alignment horizontal="center" vertical="center"/></xf>' +
  '<xf numFmtId="0" fontId="2" fillId="0" borderId="0" xfId="0" applyFont="1"/>' +
  '</cellXfs>' +
  '<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>' +
  '</styleSheet>';

const buildWorkbookXml = (sheetName) =>
  XML_DECL +
  `<workbook xmlns="${NS_MAIN}" xmlns:r="${NS_REL}">` +
  '<workbookPr/>' +
  `<sheets><sheet name="${escapeXml(sheetName)}" sheetId="1" r:id="rId1"/></sheets>` +
  '</workbook>';

const buildWorkbookRels = () =>
  XML_DECL +
  `<Relationships xmlns="${NS_PKG_REL}">` +
  '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>' +
  '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>' +
  '<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/sharedStrings" Target="sharedStrings.xml"/>' +
  '</Relationships>';

const buildRootRels = () =>
  XML_DECL +
  `<Relationships xmlns="${NS_PKG_REL}">` +
  '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>' +
  '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>' +
  '<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>' +
  '</Relationships>';

const buildContentTypes = () =>
  XML_DECL +
  `<Types xmlns="${NS_CONTENT_TYPES}">` +
  '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>' +
  '<Default Extension="xml" ContentType="application/xml"/>' +
  '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>' +
  '<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>' +
  '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>' +
  '<Override PartName="/xl/sharedStrings.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"/>' +
  '<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>' +
  '<Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>' +
  '</Types>';

const buildAppXml = () =>
  XML_DECL +
  '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">' +
  '<Application>FSMS</Application>' +
  '</Properties>';

/**
 * 工作簿属性（水印的第三、四处：表尾行能被删，属性不能）。
 * 无水印时仍写出该部件、值为空——真实 GET 导出与蜜罐合成件因此**结构相同**，
 * 蜜罐的「与真实链逐一相同」契约不靠「都缺一个部件」来成立。
 */
const buildCoreXml = ({ creator = '', lastModifiedBy = '', description = '', keywords = '' }) => {
  const now = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
  return (
    XML_DECL +
    '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"' +
    ' xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/"' +
    ' xmlns:dcmitype="http://purl.org/dc/dcmitype/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">' +
    `<dc:creator>${escapeXml(creator)}</dc:creator>` +
    `<dc:description>${escapeXml(description)}</dc:description>` +
    `<cp:keywords>${escapeXml(keywords)}</cp:keywords>` +
    `<cp:lastModifiedBy>${escapeXml(lastModifiedBy)}</cp:lastModifiedBy>` +
    `<dcterms:created xsi:type="dcterms:W3CDTF">${now}</dcterms:created>` +
    `<dcterms:modified xsi:type="dcterms:W3CDTF">${now}</dcterms:modified>` +
    '</cp:coreProperties>'
  );
};

/** 单元格：空值写成无 `t` 的空 `<c/>`（Excel 视为空），其余一律共享字符串 */
const buildCell = (rowNumber, columnIndex, value, style, indexOf) => {
  const ref = `${columnName(columnIndex)}${rowNumber}`;
  const styleAttr = style === STYLE_DEFAULT ? '' : ` s="${style}"`;
  if (value === null || value === undefined || value === '') {
    return `<c r="${ref}"${styleAttr}/>`;
  }
  return `<c r="${ref}"${styleAttr} t="s"><v>${indexOf(String(value))}</v></c>`;
};

/**
 * 生成 sheet1.xml 与 sharedStrings.xml。
 * 表头由 columns 决定（第 1 行），数据行从第 2 行起——调用方只 addRow 数据。
 */
const buildSheetParts = ({ columns, rows, defaultColWidth }) => {
  const strings = new Map();
  const stringList = [];
  let refCount = 0; // 实计引用数（E8）：每次把单元格写成 t="s" 时 +1。空单元格走 <c/> 分支、不调用 indexOf，天然不计入——这正是 OOXML 里 count 的本义。
  const indexOf = (value) => {
    refCount += 1;
    if (!strings.has(value)) {
      strings.set(value, stringList.length);
      stringList.push(value);
    }
    return strings.get(value);
  };

  const headerCells = columns
    .map((column, i) => buildCell(1, i + 1, column.header, STYLE_HEADER, indexOf))
    .join('');
  const dataXml = rows
    .map((row, i) => {
      const rowNumber = i + 2;
      const style = row.watermark ? STYLE_WATERMARK : STYLE_DEFAULT;
      const cells = row.values
        .map((value, c) => buildCell(rowNumber, c + 1, value, style, indexOf))
        .join('');
      return `<row r="${rowNumber}">${cells}</row>`;
    })
    .join('');

  const lastRow = rows.length + 1;
  const lastColumn = columnName(Math.max(columns.length, 1));
  const colsXml = columns
    .map(
      (column, i) => `<col min="${i + 1}" max="${i + 1}" width="${column.width}" customWidth="1"/>`
    )
    .join('');

  const sheetXml =
    XML_DECL +
    `<worksheet xmlns="${NS_MAIN}" xmlns:r="${NS_REL}">` +
    `<dimension ref="A1:${lastColumn}${lastRow}"/>` +
    `<sheetFormatPr defaultRowHeight="15" defaultColWidth="${defaultColWidth}"/>` +
    (colsXml ? `<cols>${colsXml}</cols>` : '') +
    `<sheetData><row r="1">${headerCells}</row>${dataXml}</sheetData>` +
    '<pageMargins left="0.7" right="0.7" top="0.75" bottom="0.75" header="0.3" footer="0.3"/>' +
    '</worksheet>';

  // count = **实计**的 t="s" 引用数（E8 前按 行数×列数 估算，空值越多偏差越大）；
  // uniqueCount 是去重数。严格的读端按 count 预分配，两个数现在都是事实值。
  const sharedStringsXml =
    XML_DECL +
    `<sst xmlns="${NS_MAIN}" count="${refCount}" uniqueCount="${stringList.length}">` +
    stringList.map((value) => `<si><t xml:space="preserve">${escapeXml(value)}</t></si>`).join('') +
    '</sst>';

  return { sheetXml, sharedStringsXml };
};

// 行值：对象按 columns 的 key 取序，数组原样（脚注/水印行只给一格）；对象缺列 key 是编程错误——静默写空格会让整列无声变空，fail-fast 且带列名
const orderValues = (values, columns) => {
  if (Array.isArray(values)) return values;
  if (!values || typeof values !== 'object') {
    throw new TypeError(`行值必须是对象或数组，收到 ${values === null ? 'null' : typeof values}`);
  }
  for (const column of columns) {
    if (!Object.prototype.hasOwnProperty.call(values, column.key)) {
      throw new TypeError(`行值缺少列 key：${column.key}（列「${column.header}」）`);
    }
  }
  return columns.map((column) => values[column.key]);
};

/**
 * @param {object} options
 * @param {string} options.sheetName
 * @param {{header:string,key:string,width:number}[]} options.columns
 * @param {number} [options.defaultColWidth]
 * @param {{creator?:string,lastModifiedBy?:string,description?:string,keywords?:string}} [options.props]
 */
const assertWidthValue = (value, label) => {
  // 列宽是 OOXML 的数值属性：类型闸在这里做（fail-fast），不靠 XML 层把坏值转义掉
  if (!Number.isFinite(value) || value <= 0 || value > 255) {
    throw new TypeError(
      `${label} 必须是 (0, 255] 内的有限数值，收到 ${JSON.stringify(value) ?? String(value)}`
    );
  }
};

const createWorkbook = ({ sheetName, columns, defaultColWidth = 15, props = {} }) => {
  assertWidthValue(defaultColWidth, 'defaultColWidth');
  for (const column of columns || []) {
    assertWidthValue(column.width, `列「${column.header}」的 width`);
  }
  const rows = [];

  const sheet = {
    /**
     * @param {object|Array} values 对象按列 key 取值；数组按位置写（可只给第一格）
     * @param {{font?:{italic?:boolean}}} [options] 仅水印行用 italic
     */
    addRow(values, options = {}) {
      rows.push({
        values: orderValues(values, columns),
        watermark: options.font && options.font.italic === true,
      });
    },
  };

  const toBuffer = () => {
    const { sheetXml, sharedStringsXml } = buildSheetParts({
      columns,
      rows,
      defaultColWidth,
    });
    return buildZip([
      { name: '[Content_Types].xml', data: Buffer.from(buildContentTypes(), 'utf8') },
      { name: '_rels/.rels', data: Buffer.from(buildRootRels(), 'utf8') },
      { name: 'docProps/app.xml', data: Buffer.from(buildAppXml(), 'utf8') },
      { name: 'docProps/core.xml', data: Buffer.from(buildCoreXml(props), 'utf8') },
      { name: 'xl/workbook.xml', data: Buffer.from(buildWorkbookXml(sheetName), 'utf8') },
      { name: 'xl/_rels/workbook.xml.rels', data: Buffer.from(buildWorkbookRels(), 'utf8') },
      { name: 'xl/styles.xml', data: Buffer.from(buildStyles(), 'utf8') },
      { name: 'xl/sharedStrings.xml', data: Buffer.from(sharedStringsXml, 'utf8') },
      { name: 'xl/worksheets/sheet1.xml', data: Buffer.from(sheetXml, 'utf8') },
    ]);
  };

  return {
    sheet,
    toBuffer,
    /**
     * 交给目的流。**不等目的端收工**——「只对真正送完的响应报成功」这条判据在
     * reportWorkbookService.writeWorkbookToResponse 里，与 CSV 侧同一形状。
     */
    write(destination) {
      destination.end(toBuffer());
    },
  };
};

module.exports = { createWorkbook, STYLE_HEADER, STYLE_WATERMARK };
