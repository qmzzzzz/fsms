/**
 * i18n 裸键清零迁移脚本（一次性，评价报告第三批 #19 收尾）
 *
 * 步骤：
 *  1. RAW_MAP：143 个中文裸键 → 规范点号键（显式映射，缺映射即失败）
 *  2. 替换 5 个历史文件中的 $t('中文') → $t('规范键')
 *  3. 词表重建：
 *     - zh-CN/en-US 删除全部顶层中文键条目（legacy 镜像 + 死条目）
 *     - 新增键值以 legacy-raw-zh/en 为翻译事实来源，注入对应命名空间
 *     - 新命名空间块（layout/auditLog/inspectionResult/inspectionReview）插到 export default { 之后
 *     - 已有命名空间（common/inspection）的新键插在其命名空间行之后
 *  4. 校验：替换后源码裸键数=0；词表可 import 且无顶层中文键
 */
const fs = require('fs');
const path = require('path');
const { pathToFileURL } = require('url');

const ROOT = path.resolve(__dirname, 'web-admin');
const read = (p) => fs.readFileSync(path.join(ROOT, p), 'utf8');
const write = (p, s) => fs.writeFileSync(path.join(ROOT, p), s);

// ============ 1. 映射表 ============
const RAW_MAP = {
  // layout
  全屏: 'layout.fullscreen',
  // 通用（复用已有 common 键）
  请选择: 'common.pleaseSelect',
  删除: 'common.delete',
  取消: 'common.cancel',
  '提交失败，请重试': 'common.submitFailedRetry',
  低: 'common.levelLow',
  中: 'common.levelMedium',
  高: 'common.levelHigh',
  紧急: 'common.urgent',
  // auditLog（AuditLogView）
  认证登录: 'auditLog.catAuthLogin',
  用户管理: 'auditLog.catUserManagement',
  角色管理: 'auditLog.catRoleManagement',
  权限管理: 'auditLog.catPermissionManagement',
  设备管理: 'auditLog.catDeviceManagement',
  报警处理: 'auditLog.catAlarmHandling',
  巡检管理: 'auditLog.catInspectionManagement',
  安全: 'auditLog.catSecurity',
  报表: 'auditLog.catReport',
  系统操作: 'auditLog.catSystemOps',
  认证: 'auditLog.shortAuth',
  用户: 'auditLog.shortUser',
  角色: 'auditLog.shortRole',
  权限: 'auditLog.shortPermission',
  设备: 'auditLog.shortDevice',
  报警: 'auditLog.shortAlarm',
  巡检: 'auditLog.shortInspection',
  系统: 'auditLog.shortSystem',
  日志等级: 'auditLog.logLevel',
  信息: 'auditLog.levelInfo',
  警告: 'auditLog.levelWarning',
  错误: 'auditLog.levelError',
  风险等级: 'auditLog.riskLevel',
  严重: 'auditLog.riskCritical',
  操作结果: 'auditLog.resultLabel',
  成功: 'auditLog.resultSuccess',
  失败: 'auditLog.resultFailure',
  严重告警: 'auditLog.severeAlert',
  高风险操作: 'auditLog.highRiskOps',
  登录失败: 'auditLog.loginFailed',
  总记录数: 'auditLog.totalRecords',
  操作时间: 'auditLog.opTime',
  操作用户: 'auditLog.opUser',
  '用户 ID': 'auditLog.userIdLabel',
  操作类型: 'auditLog.opType',
  分类: 'auditLog.categoryLabel',
  目标用户: 'auditLog.targetUser',
  操作原因: 'auditLog.opReason',
  请求方式: 'auditLog.reqMethod',
  请求路径: 'auditLog.reqPath',
  风险因素: 'auditLog.riskFactors',
  错误信息: 'auditLog.errorInfo',
  请求参数: 'auditLog.reqBody',
  执行时长: 'auditLog.duration',
  // inspection（复用已有 + 新增）
  巡检标题: 'inspection.inspectionTitle',
  巡检类型: 'inspection.inspectionType',
  日常巡检: 'inspection.typeDaily',
  每周巡检: 'inspection.typeWeekly',
  每月巡检: 'inspection.typeMonthly',
  季度巡检: 'inspection.typeQuarterly',
  年度巡检: 'inspection.typeAnnual',
  专项巡检: 'inspection.typeSpecial',
  检查项目: 'inspection.checkItems',
  负责人: 'inspection.ownerLabel',
  计划开始时间: 'inspection.planStartTime',
  计划结束时间: 'inspection.planEndTime',
  正常: 'inspection.normal',
  异常: 'inspection.abnormal',
  部分异常: 'inspection.partial',
  巡检结果: 'inspection.result',
  通过: 'inspection.approved',
  不通过: 'inspection.rejected',
  审核意见: 'inspection.reviewComment',
  审核结果: 'inspection.reviewResult',
  基本信息: 'inspection.basicInfo',
  请输入巡检标题: 'inspection.titlePlaceholder',
  巡检范围: 'inspection.scopeLabel',
  选择设备: 'inspection.selectDevices',
  请搜索并选择设备: 'inspection.deviceSearchPlaceholder',
  位置范围: 'inspection.locationScope',
  栋号: 'inspection.buildingLabel',
  楼层: 'inspection.floorLabel',
  区域: 'inspection.areaLabel',
  检查项目名称: 'inspection.checkItemNameLabel',
  检查标准: 'inspection.standardLabel',
  必检: 'inspection.checkRequired',
  选检: 'inspection.checkOptional',
  添加检查项目: 'inspection.addCheckItem',
  人员安排: 'inspection.staffing',
  请搜索并选择负责人: 'inspection.ownerSearchPlaceholder',
  时间计划: 'inspection.scheduleLabel',
  选择开始时间: 'inspection.startTimePlaceholder',
  选择结束时间: 'inspection.endTimePlaceholder',
  请合理设置巡检时间避免任务过载: 'inspection.scheduleHint',
  备注: 'inspection.remarkLabel',
  '巡检计划相关说明（可选）': 'inspection.remarkPlaceholder',
  编辑巡检计划: 'inspection.editPlanTitle',
  新建巡检计划: 'inspection.createPlanTitle',
  消防器材检查: 'inspection.sampleEquipmentCheck',
  '完好率100%': 'inspection.sampleEquipmentPass',
  消防通道检查: 'inspection.samplePassageCheck',
  畅通无阻: 'inspection.samplePassagePass',
  '标题长度在 2 到 200 个字符': 'inspection.titleLengthMsg',
  请选择巡检类型: 'inspection.typeRequiredMsg',
  请至少选择一个设备: 'inspection.devicesRequiredMsg',
  请选择计划开始时间: 'inspection.startTimeRequiredMsg',
  请选择计划结束时间: 'inspection.endTimeRequiredMsg',
  至少添加一个检查项目: 'inspection.checkItemsRequiredMsg',
  结束时间必须晚于开始时间: 'inspection.endAfterStartMsg',
  巡检计划更新成功: 'inspection.planUpdateSuccessMsg',
  巡检计划创建成功: 'inspection.planCreateSuccessMsg',
  发现问题: 'inspection.issuesFound',
  // inspectionResult（InspectionCompleteForm）
  提交巡检结果: 'inspectionResult.submitTitle',
  问题序号: 'inspectionResult.issueNo',
  选择问题设备: 'inspectionResult.issueDeviceLabel',
  请选择设备: 'inspectionResult.deviceRequiredMsg',
  问题描述: 'inspectionResult.issueDescLabel',
  请输入问题描述: 'inspectionResult.issueDescPlaceholder',
  严重程度: 'inspectionResult.severityLabel',
  请选择严重程度: 'inspectionResult.severityRequiredMsg',
  处理建议: 'inspectionResult.suggestionLabel',
  请输入处理建议: 'inspectionResult.suggestionPlaceholder',
  照片: 'inspectionResult.photosLabel',
  添加问题: 'inspectionResult.addIssue',
  完成地点: 'inspectionResult.locationLabel',
  '请输入巡检完成地点（可选）': 'inspectionResult.locationPlaceholder',
  提交结果: 'inspectionResult.submitBtn',
  请选择巡检结果: 'inspectionResult.resultRequiredMsg',
  异常情况至少需要记录一个问题: 'inspectionResult.issueRequiredMsg',
  请完整填写问题信息: 'inspectionResult.issueIncompleteMsg',
  请完整填写所有问题信息: 'inspectionResult.allIssuesIncompleteMsg',
  巡检结果提交成功: 'inspectionResult.submitSuccessMsg',
  // inspectionReview（InspectionReviewForm）
  审核巡检结果: 'inspectionReview.title',
  巡检信息: 'inspectionReview.infoLabel',
  请输入审核意见: 'inspection.reviewCommentPlaceholder',
  提交审核: 'inspection.submitReviewBtn',
  审核意见至少需要10个字符: 'inspection.reviewCommentMinMsg',
  未分配: 'inspectionReview.unassigned',
  未提交: 'inspectionReview.notSubmitted',
  未知: 'inspectionReview.unknown',
  加载巡检详情失败: 'inspectionReview.loadFailedMsg',
  审核提交成功: 'inspectionReview.submitSuccessMsg',
  '巡检备注（可选）': 'inspectionResult.remarkPlaceholder',
  // legacy 死条目（代码零引用）：迁移时直接弃用
  未登录: '__DEAD__',
};

// ============ 2. 读取 legacy 翻译事实来源 ============
async function loadLegacy() {
  const lz = await import(pathToFileURL(path.join(ROOT, 'src/i18n/locales/legacy-raw-zh.js')));
  const le = await import(pathToFileURL(path.join(ROOT, 'src/i18n/locales/legacy-raw-en.js')));
  return { lz: lz.default, le: le.default };
}

(async () => {
  const { lz, le } = await loadLegacy();
  const legacyKeys = new Set(Object.keys(lz));

  // 映射覆盖校验：legacy 的每个键都必须有映射
  const unmapped = [...legacyKeys].filter((k) => !RAW_MAP[k]);
  if (unmapped.length) {
    console.error('未映射的 legacy 键:', unmapped);
    process.exit(1);
  }
  const mapKeys = new Set(Object.keys(RAW_MAP));
  const overMapped = [...mapKeys].filter((k) => !legacyKeys.has(k));
  if (overMapped.length) {
    console.error('映射了 legacy 中不存在的键:', overMapped);
    process.exit(1);
  }
  // 规范键唯一性校验
  const targets = Object.values(RAW_MAP);
  const dup = targets.filter((v, i) => targets.indexOf(v) !== i);
  if (dup.length) {
    console.error('规范键重复:', dup);
    process.exit(1);
  }

  // ============ 3. 替换 5 个文件 ============
  const files = [
    'src/layout/index.vue',
    'src/views/AuditLogView.vue',
    'src/components/InspectionForm.vue',
    'src/components/InspectionCompleteForm.vue',
    'src/components/InspectionReviewForm.vue',
  ];
  let replaced = 0;
  for (const f of files) {
    let src = read(f);
    src = src.replace(/(\$t|\bt)\(\s*'([^']*[\u4e00-\u9fa5][^']*)'\s*\)/g, (m, fn, key) => {
      const mapped = RAW_MAP[key];
      if (!mapped || mapped === '__DEAD__') {
        console.error(`${f} 出现未映射裸键: ${key}`);
        process.exit(1);
      }
      replaced += 1;
      return `${fn}('${mapped}')`;
    });
    write(f, src);
  }
  console.log('源码替换完成，替换处数:', replaced);

  // 替换后自检：5 文件应无裸键
  const reScan = /(?:\$t|\bt)\(\s*'[^']*[\u4e00-\u9fa5][^']*'/;
  for (const f of files) {
    if (reScan.test(read(f))) {
      console.error(`${f} 仍有裸键残留`);
      process.exit(1);
    }
  }

  // ============ 4. 词表重建 ============
  // 4a. 按命名空间归集新键值（__DEAD__ 条目跳过）
  const entriesByNs = {}; // ns -> [{key, zh, en}]
  for (const [raw, target] of Object.entries(RAW_MAP)) {
    if (target === '__DEAD__') continue;
    const [ns, key] = target.split('.');
    (entriesByNs[ns] ||= []).push({ key, zh: lz[raw], en: le[raw] });
  }

  const NEW_NS_ORDER = ['layout', 'auditLog', 'inspectionResult', 'inspectionReview'];
  const EXISTING_NS = ['common', 'inspection'];

  const renderEntries = (entries, locale) =>
    entries
      .map(({ key, zh, en }) => `    ${key}: ${JSON.stringify(locale === 'zh' ? zh : en)},`)
      .join('\n');

  for (const [file, locale] of [
    ['src/i18n/locales/zh-CN.js', 'zh'],
    ['src/i18n/locales/en-US.js', 'en'],
  ]) {
    let src = read(file);
    const before = src.split('\n').length;

    // 删除顶层中文键行（缩进 2、键以中文开头、单行值）
    src = src.replace(/^ {2}[\u4e00-\u9fa5][^:\n]*: .*,\r?\n/gm, '');

    // 已有命名空间追加新键（插在 `  ns: {` 行后）
    for (const ns of EXISTING_NS) {
      const entries = entriesByNs[ns];
      if (!entries) continue;
      const re = new RegExp(`(^ {2}${ns}: \\{\\r?\\n)`, 'm');
      if (!re.test(src)) {
        console.error(`${file} 找不到命名空间 ${ns}`);
        process.exit(1);
      }
      src = src.replace(re, `$1${renderEntries(entries, locale)}\n`);
    }

    // 新命名空间块（插在 export default { 之后）
    const block = NEW_NS_ORDER.map((ns) => {
      const entries = entriesByNs[ns] || [];
      return `  ${ns}: {\n${renderEntries(entries, locale)}\n  },`;
    }).join('\n');
    src = src.replace(/(export default \{\r?\n)/, `$1${block}\n`);

    write(file, src);
    console.log(`${file}: ${before} -> ${src.split('\n').length} 行`);
  }

  // 4b. 自检：import 后无顶层中文键、新键可取值
  delete require.cache?.[path.join(ROOT, 'src/i18n/locales/zh-CN.js')];
  const zh = await import(
    pathToFileURL(path.join(ROOT, 'src/i18n/locales/zh-CN.js')) + `?t=${Date.now()}`
  );
  const en = await import(
    pathToFileURL(path.join(ROOT, 'src/i18n/locales/en-US.js')) + `?t=${Date.now()}`
  );
  const zhTopCn = Object.keys(zh.default).filter((k) => /[\u4e00-\u9fa5]/.test(k));
  const enTopCn = Object.keys(en.default).filter((k) => /[\u4e00-\u9fa5]/.test(k));
  console.log('zh 顶层中文键残留:', zhTopCn.length, '| en 顶层中文键残留:', enTopCn.length);
  // 抽查
  const pick = (obj, p) => p.split('.').reduce((o, k) => (o ? o[k] : undefined), obj);
  console.log('zh auditLog.opTime =', pick(zh.default, 'auditLog.opTime'));
  console.log('en auditLog.opTime =', pick(en.default, 'auditLog.opTime'));
  console.log('zh inspectionResult.issueNo =', pick(zh.default, 'inspectionResult.issueNo'));
  console.log('en inspectionResult.issueNo =', pick(en.default, 'inspectionResult.issueNo'));
  console.log('zh common.levelHigh =', pick(zh.default, 'common.levelHigh'));
  console.log('en layout.fullscreen =', pick(en.default, 'layout.fullscreen'));
  console.log('MIGRATION DONE');
})();
