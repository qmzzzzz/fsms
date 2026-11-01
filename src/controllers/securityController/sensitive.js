/**
 * 安全管理控制器 · 敏感面（PII 查看与安全举报）
 * （2026-10-19 批 3c-3 自 controllers/securityController.js 原样迁出，纯搬家不改语义）
 */

const { User, AuditLog } = require('./shared');
const { validationResult } = require('express-validator');
const { safeFieldErrors } = require('../../utils/validationRules');
const ApiResponse = require('../../utils/apiResponse');
const { getOperatorMaxLevel, maxRoleLevel } = require('../../utils/permissionHelper');
const {
  assertRecordInScope,
  buildRecordScopeFilter,
  getDataScope,
} = require('../../middleware/rbac');
// 举报目标核验的域字段取自同一份声明（constants/dataScopeFields.js）。
const { DATA_SCOPE_FIELDS } = require('../../constants/dataScopeFields');
const { DataMasking } = require('../../utils/encryption');
const logger = require('../../utils/logger');
const { asyncHandler } = require('../../middleware/errorHandler');
// 举报目标核验的数据访问（同 alarmController 的反查设备口径：controllers 不直连 model）
const userService = require('../../services/userService');
const deviceService = require('../../services/DeviceService');
const alarmService = require('../../services/AlarmService');
// 候选列举走独立服务：三个业务 service 已贴 max-lines 上限，且查询口径完全同构
const reportTargetService = require('../../services/reportTargetService');
const { onAuditWriteFailureRethrow } = require('../../utils/auditWriteFailure');
// 安全判定与 PII 查看留痕的客户端地址只有一个口径（utils/ipUtils.js）：
// `req.ip` 在开着 trust proxy 时取自请求方自己写的 X-Forwarded-For。
const { auditClientAddress } = require('../../utils/ipUtils');

/**
 * 查看敏感数据（需要二次验证）
 * POST /api/security/view-sensitive
 */
const viewSensitiveData = asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return ApiResponse.codeError(res, 'VALIDATION_FAILED', {
      fieldErrors: safeFieldErrors(errors),
    });
  }

  const { dataType, targetUserId } = req.body;
  // #9：本人查看（未指定 targetUserId 或指向自己）免鉴权——二次验证已由
  // requireReAuthentication 兜底；查看他人需 system:read（路由层 checkViewSensitivePermission
  // 已拦），且受数据范围约束（非超管不得越级查看层级高于自己的目标）。
  const isSelf = !targetUserId || String(targetUserId) === String(req.user.userId);

  // 数据范围保护：查看他人时，操作者层级须**严格高于**目标用户层级
  // （目标层级 >= 操作者层级即拒绝，含同级——与 userController/rolePermissionController/
  // authService 等其余 23 处「>= 即拒绝」口径一致，修复，2026-09-17）。
  // 理由：敏感数据（手机号/邮箱）的横向查看不因同级而合法，同级放行等于允许
  // 平级管理员互相读取 PII；越级（target > op）更应拒绝。超管 *:* 恒通过。
  if (!isSelf) {
    const opLevel = await getOperatorMaxLevel(req.user.userId);
    const targetUser = await User.findById(targetUserId)
      // 数据范围闸需要的属主/部门字段与层级字段同一次查出：少一列就会让
      // department/self 档把目标判成越权（假 deny），或在缺失字段上 fail-open。
      .select('roles department createdBy')
      .populate({ path: 'roles', select: 'level' })
      .lean();
    if (!targetUser) {
      return ApiResponse.codeError(res, 'TARGET_USER_NOT_FOUND');
    }
    const targetRoles = (targetUser.roles || []).filter(Boolean);
    const targetLevel = maxRoleLevel(targetRoles);
    // 目标层级必须取**全部**角色（含停用）：停用角色随时可能恢复，按 status:'active' 过滤
    // 会把 targetLevel 一路拉低；更危险的是空角色集时 maxRoleLevel 返回 -Infinity，
    // 于是 `opLevel <= targetLevel` 对任何持有者恒 false → 该账号 PII 对全体 system:read 者裸奔。
    // 故：无角色（无法确认其层级）从严拒绝；否则仍要求操作者严格高于目标。两处均 fail-closed。
    if (targetRoles.length === 0 || opLevel <= targetLevel) {
      return ApiResponse.codeError(res, 'SENSITIVE_VIEW_HIGHER_LEVEL_FORBIDDEN');
    }

    // 层级闸只回答"能不能管这一档人"，不回答"这个人归不归我管"：
    // 部门管理员持有 system:read 且层级高于外部门普通用户，原先仅凭层级比较即可
    // 跨部门读取手机号/邮箱。数据范围必须与列表/详情/写路径同一判据——字段取自
    // DATA_SCOPE_FIELDS 单一声明，闸门复用 rbac.assertRecordInScope，避免再抄一份。
    const { allowed } = await assertRecordInScope(
      req,
      targetUser,
      DATA_SCOPE_FIELDS.user.ownerField,
      DATA_SCOPE_FIELDS.user.departmentField
    );
    if (!allowed) {
      logger.warn('敏感信息查看被拒（超出数据范围）', {
        operator: req.user.username,
        targetUserId,
      });
      return ApiResponse.codeError(res, 'SENSITIVE_VIEW_OUT_OF_SCOPE');
    }
  }

  const user = isSelf ? await User.findById(req.user.userId) : await User.findById(targetUserId);
  if (!user) {
    return ApiResponse.codeError(res, 'USER_NOT_FOUND_OR_DELETED');
  }

  let sensitiveData = {};

  switch (dataType) {
    case 'phone':
      sensitiveData = {
        type: 'phone',
        masked: DataMasking.maskPhone(user.phone),
        full: user.phone, // 已是明文：schema 上 phone 的 get 即 decryptPii，不要再解一次
      };
      break;
    case 'email':
      sensitiveData = {
        type: 'email',
        masked: DataMasking.maskEmail(user.email),
        full: user.email,
      };
      break;
    default:
      return ApiResponse.codeError(res, 'UNSUPPORTED_DATA_TYPE');
  }

  // 记录审计日志
  // L-06 修复：原实现把 userId（操作者）与 username（被查看者）写进同一条记录，
  // 一条记录里两个主体字段指向不同的人。该处已设 skipGlobalAudit，故这是该操作
  // 的唯一留痕——按 username 检索时会把"谁查看了谁"记为被查看者本人。
  // 现改为：username 为操作者，被查看者另存 targetUserId/targetUsername。
  // 修复后"唯一留痕"才成立：skipGlobalAudit 由全局审计
  // 中间件在**响应时刻**读取（security.js 的 doLog），下方赋值与随后
  // res.json 之间的顺序因此生效；修复前该标志在中间件入口即被检查，
  // 此处赋值永远晚于检查，本次操作会被双写。
  res.locals.skipGlobalAudit = true;
  await AuditLog.create({
    action: 'view_sensitive_data',
    category: 'auth',
    userId: req.user.userId,
    username: req.user.username,
    targetUserId: user._id,
    targetUsername: user.username,
    dataType,
    // 这条记录是本操作唯一的留痕（上面设了 skipGlobalAudit），而留痕的意义在于归因。
    // 原实现取 `req.ip`：开着 trust proxy 时那就是请求方自己写的 X-Forwarded-For，
    // 读别人手机号的人可以顺手挑一个写进取证记录（auth.js 的 IP 范围拒绝审计早就
    // 用 clientIpForSecurityDecision 了，全仓唯一的 PII 查看留痕却漏了它 —— 同一件事
    // 两种口径，两边会互相"证明"对方没问题）。
    // auditClientAddress 在同一个安全裁决地址之上，另留 reportedIp/socketPeer
    // （clientInfo）供取证：只记裁决地址会丢掉"对方声称是谁"这个事实。
    ...auditClientAddress(req),
    userAgent: req.get('user-agent'),
    success: true,
    riskLevel: 'medium',
    // 用重抛档而不是吞错档（档位表见 utils/auditWriteFailure.js）：本操作已设
    // skipGlobalAudit，这条 create 是唯一留痕；吞掉错误会照样把明文手机号/邮箱
    // 发出去 ⇒「读了 PII 却毫无记录」，比失败更糟。
  }).catch(onAuditWriteFailureRethrow('view_sensitive_data', req));

  return ApiResponse.success(res, sensitiveData, '获取成功');
});

/**
 * 举报目标类型 → 「取哪个字段、越权/不存在各返什么码」的核验配置表。
 * 消费方是下面的 resolveReportTargetViolation；`system` 不在表内（它不指向记录）。
 */
const REPORT_TARGET_KINDS = {
  user: {
    pick: (id) => userService.findScopeFieldsByIds([id]),
    fields: DATA_SCOPE_FIELDS.user,
    notFound: 'USER_NOT_FOUND',
    notFoundStatusCode: 404, // 注册表里该码是 401（登录语义），本处是"对象不存在"
    outOfScope: 'USER_SCOPE_FORBIDDEN',
  },
  device: {
    pick: (id) => deviceService.findScopeFieldsByIds([id]),
    fields: DATA_SCOPE_FIELDS.device,
    notFound: 'DEVICE_NOT_FOUND',
    outOfScope: 'DEVICE_VIEW_FORBIDDEN',
  },
  alarm: {
    pick: (id) => alarmService.findScopeFieldsByIds([id]),
    fields: DATA_SCOPE_FIELDS.alarm,
    notFound: 'ALARM_NOT_FOUND',
    outOfScope: 'ALARM_VIEW_FORBIDDEN',
  },
};

/**
 * 举报目标的服务端事实核验（2026-10-01 拍板：校 ID + 存在性 + 数据范围）
 *
 * 原状态：本端点**不挂权限码**（刻意的：一线人员必须报得了警），而 targetId 是
 * 请求方自由填写的字符串，任何登录用户都能写一条 `riskLevel:'high'` 的审计记录
 * 指向**别人**的记录——路由注释却写着「本人资源…无越权面」。后果有两层：
 *   ① 安全概览的「高风险操作数」与告警取数都读这批行，定向刷写即制造告警疲劳；
 *   ② 结构化字段 `targetId` 可以是不存在的对象，事后核查者顺着 ID 找不到任何东西。
 *
 * 收口口径：`targetType` 决定 `targetId` 的语义。
 *  · user/device/alarm ⇒ 必须是**存在**且**在举报人数据范围内**的真实记录
 *    （范围判定复用 rbac.assertRecordInScope，字段取自 DATA_SCOPE_FIELDS 单一声明，
 *    与各自详情/写路径同判据；本人的记录恒在范围内，所以"举报自己"永远可行）；
 *  · system ⇒ 不指向记录，路由层已禁止携带 targetId（否则改一下类型就绕过整条核验）。
 * 自由文本 reason/description 不受影响：它们本来就不参与结构化判定，
 * 范围外的对象当然可以用文字描述——被约束的是"结构化字段必须是真记录"。
 *
 * 数据访问经 services 层的 `findScopeFieldsByIds`（同 alarmController 反查设备的口径），
 * 控制器不直连 model（架构棘轮 architecture/layeringRatchet）。这些 getter 返回**投影后的
 * lean 文档**而不是整条记录：投影必须覆盖 DATA_SCOPE_FIELDS 里该资源的每一条属主臂 +
 * 部门臂，少一列就会让 self/department 档把"本来在范围内"的记录判成越权（假 deny 比漏判
 * 更难发现——用户只是"报不了"，日志里却写着越权）。该同值关系有静态闸盯着，判据见
 * reportTargetScopeAndLimiter.test.js 的「投影完备性」。
 *
 * @returns {Promise<{code: string, statusCode?: number}|null>} null=通过；否则待发出的错误码
 */
async function resolveReportTargetViolation(req, targetType, targetId) {
  const kind = REPORT_TARGET_KINDS[targetType];
  if (!kind) return null; // system：没有可核验的记录，路由层已保证 targetId 缺席
  const [doc] = await kind.pick(targetId);
  if (!doc) {
    return { code: kind.notFound, statusCode: kind.notFoundStatusCode };
  }
  const { allowed } = await assertRecordInScope(
    req,
    doc,
    kind.fields.ownerField,
    kind.fields.departmentField
  );
  return allowed ? null : { code: kind.outOfScope };
}

/**
 * 举报对象候选的每类上限
 *
 * 20 是"够认出来"与"不给批量拖库留通道"的交点：远程搜索按输入停顿触发，
 * 用户通常在前几条里就能认出目标；再大就变成"一次请求取走一页人名/设备"。
 * 不导出——判据要能在上限被改动时变红（测试断言 items.length ≤ 20）。
 */
const REPORT_TARGET_CANDIDATE_LIMIT = 20;

/** 位置子字段拼成一行人话（设备与报警同形，缺哪段就少哪段） */
const formatLocationLabel = (location) => {
  if (!location || typeof location !== 'object') return '';
  return [location.building, location.floor, location.room]
    .filter((v) => typeof v === 'string' && v.trim() !== '')
    .join(' · ');
};

/**
 * 举报对象候选的三类取数配置
 *
 * 与 `REPORT_TARGET_KINDS` 刻意分成两张表：那张表服务于**提交时的事实核验**
 * （按 id 反查 + 越权码），这张服务于**候选列举**（按范围查 + 展示字段）。
 * 合并成一张会让"只改其中一侧"看起来无害，而两侧的字段集合本来就不该相同——
 * 核验需要属主/部门臂，列举需要的是用户认得出的名称。
 *
 * 两张表的 `fields` 都指向 `DATA_SCOPE_FIELDS` 的同一份声明：候选与核验
 * 必须同判据，否则会出现「下拉里选得到、提交却 403」。
 */
const REPORT_TARGET_CANDIDATE_KINDS = {
  user: {
    fields: DATA_SCOPE_FIELDS.user,
    toItem: (doc) => ({
      id: String(doc._id),
      kind: 'user',
      code: doc.username || '',
      name: doc.realName || '',
      detail: doc.department || '',
    }),
  },
  device: {
    fields: DATA_SCOPE_FIELDS.device,
    toItem: (doc) => ({
      id: String(doc._id),
      kind: 'device',
      code: doc.deviceCode || '',
      name: doc.deviceName || '',
      detail: formatLocationLabel(doc.location),
    }),
  },
  alarm: {
    fields: DATA_SCOPE_FIELDS.alarm,
    toItem: (doc) => ({
      id: String(doc._id),
      kind: 'alarm',
      code: doc.alarmCode || '',
      // name 放稳定码（alarmType），中文映射在前端：后端只出稳定码是本仓既有口径
      name: doc.alarmType || '',
      detail: formatLocationLabel(doc.location),
      occurredAt: doc.occurredAt || null,
    }),
  },
};

/**
 * 列出"我数据范围内的可举报对象"（GET /api/security/report-targets）
 *
 * 存在理由：举报对话框原先把「对象 ID」直接交给用户填 24 位 ObjectId，
 * 而一线人员拿不到这个值——功能上等价于不可用。本端点让前端把那个输入框
 * 换成"可搜索的对象选择器"。
 *
 * 安全边界（为什么这个端点敢不挂权限码）：
 *  · 它**不是**新的信息面，而是把已有信息收窄后复用——候选人只来自
 *    举报人自己的数据范围，判据与提交时的 `resolveReportTargetViolation`
 *    同源（`buildRecordScopeFilter` ↔ `isRecordInScope` 逐臂同值）；
 *  · 返回字段是"能认出是哪一条"的最小集：用户只给 username/realName/department，
 *    设备只给编号/名称/位置，报警只给编号/类型/位置/时间。phone/email、
 *    报警描述、上报人姓名一律不出现在候选里；
 *  · 账号级限流（`authenticate` 内的 `userLimiter`，普通用户 200/15min）压住
 *    枚举速率。这里**不另开专用桶**：候选集本身已被数据范围过滤，能枚举到的
 *    就是自己本来能看到的记录；再叠一个 60/15min 的桶只会让正常填写搜索
 *    （一次输入 3-8 次请求）更容易撞 429。
 *
 * 为什么仍然要单独开端点、而不是让前端调 /users、/devices、/alarms：
 * 那三个列表都要求 `user:read` / `device:read` / `alarm:read`，而举报入口
 * 刻意对全员开放。复用列表接口会让没有读权限的一线人员打开下拉就吃 403——
 * 比现在"填不出 ID"更糟：连提交入口都断了。
 */
const listReportTargets = asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return ApiResponse.codeError(res, 'VALIDATION_FAILED', {
      fieldErrors: safeFieldErrors(errors),
    });
  }

  const requestedType = req.query.type;
  // Object.hasOwn 而非裸下标：普通对象字面量 + 裸下标会取到原型链成员（constructor 等全 truthy）⇒ !kind 兜底失效
  const kind = Object.hasOwn(REPORT_TARGET_CANDIDATE_KINDS, requestedType)
    ? REPORT_TARGET_CANDIDATE_KINDS[requestedType]
    : null;
  if (!kind) {
    return ApiResponse.codeError(res, 'VALIDATION_FAILED', {
      fieldErrors: [{ field: 'type', message: '无效的目标类型' }],
    });
  }

  const dataScope = await getDataScope(req.user.userId);
  const filter = buildRecordScopeFilter(dataScope, {
    ownerField: kind.fields.ownerField,
    departmentField: kind.fields.departmentField,
    userId: req.user.userId,
  });

  const docs = await reportTargetService.search({
    type: requestedType,
    filter,
    keyword: req.query.keyword,
    limit: REPORT_TARGET_CANDIDATE_LIMIT,
  });

  return ApiResponse.success(res, { items: docs.map(kind.toItem) });
});

/**
 * 举报异常行为
 * POST /api/security/report
 */
const reportSuspiciousActivity = asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return ApiResponse.codeError(res, 'VALIDATION_FAILED', {
      fieldErrors: safeFieldErrors(errors),
    });
  }

  const { targetType, targetId, reason, description } = req.body;

  if (!targetType || !reason) {
    return ApiResponse.codeError(res, 'REPORT_TARGET_AND_REASON_REQUIRED');
  }

  const targetViolation = await resolveReportTargetViolation(req, targetType, targetId);
  if (targetViolation) {
    // 越权举报尝试本身是安全信号（有人试图往高危审计里投射他人记录）
    logger.warn('安全举报目标核验未通过', {
      reporter: req.user.username,
      targetType,
      targetId,
      errorCode: targetViolation.code,
    });
    return ApiResponse.codeError(res, targetViolation.code, {
      statusCode: targetViolation.statusCode,
    });
  }

  res.locals.skipGlobalAudit = true;
  const report = await AuditLog.create({
    action: 'suspicious_report',
    category: 'security',
    userId: req.user.userId,
    username: req.user.username,
    targetType,
    targetId,
    reason,
    description,
    ...auditClientAddress(req),
    userAgent: req.get('user-agent'),
    riskLevel: 'high',
    // 用重抛档而不是吞错档（档位表见 utils/auditWriteFailure.js）：`reportId` 取自
    // 这条 create 的文档，吞掉错误后它是 undefined 而响应仍写「举报已提交」。
  }).catch(onAuditWriteFailureRethrow('suspicious_report', req));

  logger.warn('安全举报', { reporter: req.user.username, targetType, targetId, reason });

  return ApiResponse.success(
    res,
    {
      reportId: report._id,
    },
    '举报已提交，安全团队将尽快处理'
  );
});

module.exports = {
  viewSensitiveData,
  listReportTargets,
  reportSuspiciousActivity,
};
