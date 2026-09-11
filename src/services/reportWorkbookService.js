const ExcelJS = require('exceljs');
const {
  EXPORT_LIMIT,
  EXPORT_MODEL_CONFIG,
  EXPORT_SHEET_NAMES,
  EXPORT_COLUMN_DEFS,
  EXPORT_ROW_TRANSFORMS,
  createSafeTransform,
} = require('./reportExportService');

const streamExportRows = async (worksheet, config, query, safeTransform) => {
  if (config.populate && config.populate.length > 0) {
    const idDocs = await config.model
      .find(query)
      .sort({ ...config.sort, _id: 1 })
      .limit(EXPORT_LIMIT)
      .select('_id')
      .lean();
    const orderedIds = idDocs.map((d) => d._id);

    const BATCH_SIZE = 200;
    const docById = new Map();
    for (let i = 0; i < orderedIds.length; i += BATCH_SIZE) {
      const idBatch = orderedIds.slice(i, i + BATCH_SIZE);
      const docs = await config.model
        .find({ $and: [query, { _id: { $in: idBatch } }] })
        .populate(config.populate)
        .select(config.select)
        .lean();
      for (const doc of docs) docById.set(String(doc._id), doc);
    }

    for (const id of orderedIds) {
      const doc = docById.get(String(id));
      if (doc) worksheet.addRow(safeTransform(doc));
    }
  } else {
    const cursor = config.model
      .find(query)
      .sort(config.sort)
      .limit(EXPORT_LIMIT)
      .select(config.select)
      .cursor();
    for await (const doc of cursor) {
      worksheet.addRow(safeTransform(doc));
    }
  }
};

const writeExportWorkbook = async (res, { type, query }) => {
  const config = EXPORT_MODEL_CONFIG[type];
  const sheetName = EXPORT_SHEET_NAMES[type] || '数据导出';
  const filename = `${sheetName}_${new Date().toISOString().slice(0, 10)}.xlsx`;
  res.setHeader(
    'Content-Type',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
  );
  res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(filename)}"`);

  const workbook = new ExcelJS.Workbook();
  const worksheet = workbook.addWorksheet(sheetName);
  worksheet.properties.defaultColWidth = 15;
  worksheet.columns = EXPORT_COLUMN_DEFS[type];

  const safeTransform = createSafeTransform(EXPORT_ROW_TRANSFORMS[type]);
  await streamExportRows(worksheet, config, query, safeTransform);

  worksheet.getRow(1).eachCell((cell) => {
    cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF4472C4' } };
    cell.font = { bold: true, color: { argb: 'FFFFFFFF' } };
    cell.alignment = { vertical: 'middle', horizontal: 'center' };
    cell.border = { thin: true };
  });

  await workbook.xlsx.write(res);
};

module.exports = { streamExportRows, writeExportWorkbook };
