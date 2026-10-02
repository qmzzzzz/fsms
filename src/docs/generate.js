const fs = require('fs');
const path = require('path');
// E-05 整改：设备类型枚举此前在 deviceListParams（query）内联展开一份，与
// utils/constants.js、models/FireDevice.js、routes/deviceRoutes.js 合计 4 份副本。
// 现统一引用 constants 的单一事实来源（本文件的 deviceType 请求体只声明 string 类型，
// 枚举约束由模型层负责，故无需改）。
const { DEVICE_TYPE } = require('../utils/constants');
const DEVICE_TYPE_VALUES = Object.values(DEVICE_TYPE);
// 同一口径（E-05 的续集）：审计页两维枚举此前在本文件与产物里各抄一份，
// 与 constants/audit.js 没有任何连线——常量加一档时文档会继续宣称旧的四档，
// 调用方按文档传值换来一个 400。现在接上同一根线（openapiSync 有对账）。
const { AUDIT_RISK_LEVELS, AUDIT_DISPLAY_LEVELS } = require('../constants/audit');
const { PERMISSION_TYPES, PERMISSION_METHODS } = require('../constants/permission');
const { IP_LIST_TYPES } = require('../constants/ipList');
const { ALARM_LEVELS, ALARM_TYPES, ALARM_STATUSES, ALARM_CAUSES } = require('../constants/alarm');
const {
  INSPECTION_TYPES,
  INSPECTION_STATUSES,
  INSPECTION_RESULTS,
  INSPECTION_REVIEW_RESULTS,
} = require('../constants/inspection');
const { USER_STATUS } = require('../utils/constants');
// 设备状态：全集与「通用状态接口可写子集」都取自 constants/deviceStatus（它自身只是
// utils/constants 的 DEVICE_STATUS 的派生视图）。原先这两处各写一份字面量，与路由
// 校验器之间没有连线——加一档会让文档继续推荐旧五档，症状同 audit/alarm 那一族。
const { DEVICE_STATUS_VALUES, DEVICE_STATUS_WRITABLE } = require('../constants/deviceStatus');

const spec = {
  openapi: '3.0.3',
  info: {
    title: '消防巡检管理系统 API',
    description:
      '基于 Node.js + Express + MongoDB 的消防设备巡检、报警处理、安全管理系统 API 文档。\n\n## 认证方式\n所有私有接口需在请求头中携带 Authorization: Bearer <token>。\n\n## 数据范围\n部分接口受数据范围权限控制：all（全部）/ department（本部门）/ self（仅本人）/ none（无权限）。',
    version: '1.0.0',
  },
  servers: [
    { url: 'http://localhost:3000', description: '开发环境' },
    { url: '/', description: '当前服务器' },
  ],
  tags: [
    { name: 'Auth', description: '认证相关接口' },
    { name: 'Users', description: '用户管理接口' },
    { name: 'Roles', description: '角色管理接口' },
    { name: 'Permissions', description: '权限管理接口' },
    { name: 'Devices', description: '消防设备管理接口' },
    { name: 'Alarms', description: '火警报警管理接口' },
    { name: 'Inspections', description: '巡检计划与执行接口' },
    { name: 'Reports', description: '报表统计与数据导出' },
    { name: 'Security', description: '安全管理接口' },
    { name: 'System', description: '系统接口' },
  ],
  components: {
    securitySchemes: {
      bearerAuth: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' },
    },
  },
  paths: {},
};

const bearer = [{ bearerAuth: [] }];
const ok = (desc) => ({ 200: { description: desc } });
const created = (desc) => ({ 201: { description: desc } });
const notFound = { 404: { description: '资源不存在' } };
const forbidden = { 403: { description: '无权限' } };
const badRequest = { 400: { description: '参数错误' } };

function p(method, tags, summary, opts = {}) {
  const op = { tags, summary };
  if (opts.description) op.description = opts.description;
  if (opts.security !== false) op.security = bearer;
  if (opts.parameters) op.parameters = opts.parameters;
  if (opts.requestBody) op.requestBody = opts.requestBody;
  op.responses = opts.responses || ok('成功');
  return op;
}

function body(schema, required = true) {
  return { required, content: { 'application/json': { schema } } };
}

// ==================== Auth ====================
spec.paths['/api/auth/register'] = {
  post: p('post', ['Auth'], '用户注册', {
    security: false,
    description: '公开注册，受系统注册开关控制',
    requestBody: body({
      type: 'object',
      required: ['username', 'email', 'password'],
      properties: {
        username: { type: 'string', minLength: 3, maxLength: 30 },
        email: { type: 'string', format: 'email' },
        password: { type: 'string', description: '至少12位，含大小写字母、数字、特殊字符' },
        realName: { type: 'string' },
        phone: { type: 'string' },
        department: { type: 'string' },
        encPassword: { type: 'string', description: '口令密文（与 password 二选一）' },
      },
    }),
    responses: {
      ...created('注册成功'),
      400: { description: '参数验证失败' },
      403: { description: '系统已关闭公开注册' },
    },
  }),
};

spec.paths['/api/auth/login'] = {
  post: p('post', ['Auth'], '用户登录', {
    security: false,
    requestBody: body({
      type: 'object',
      required: ['username', 'password'],
      properties: {
        username: { type: 'string' },
        password: { type: 'string' },
        captchaId: { type: 'string' },
        encPassword: {
          type: 'string',
          description:
            '口令密文（ECDH+HKDF+AES-GCM 信封，经 GET /api/auth/login-public-key 公钥加密）；与 password 二选一',
        },
        captchaText: { type: 'string', description: '图形验证码答案（开启验证码时必填）' },
        mfaCode: { type: 'string', description: 'MFA 动态口令（6 位 TOTP 或 XXXX-XXXX 恢复码）' },
      },
    }),
    responses: {
      200: { description: '登录成功，返回 token 和 refreshToken' },
      401: { description: '用户名或密码错误' },
      429: { description: '请求过于频繁' },
    },
  }),
};

spec.paths['/api/auth/captcha'] = {
  get: p('get', ['Auth'], '获取图形验证码', {
    security: false,
    responses: ok('返回验证码图片和 captchaId'),
  }),
};
spec.paths['/api/auth/captcha-status'] = {
  get: p('get', ['Auth'], '查询登录验证码开关状态', { security: false }),
};

spec.paths['/api/auth/refresh'] = {
  post: p('post', ['Auth'], '刷新 Token', {
    security: false,
    description: 'refreshToken 一次性使用，旧 token 自动加入黑名单',
    requestBody: body({
      type: 'object',
      required: ['refreshToken'],
      properties: { refreshToken: { type: 'string' } },
    }),
    responses: { ...ok('刷新成功'), 401: { description: '刷新令牌无效' } },
  }),
};

spec.paths['/api/auth/me'] = {
  get: p('get', ['Auth'], '获取当前用户信息（含权限、菜单、数据范围）'),
};

spec.paths['/api/auth/password'] = {
  put: p('put', ['Auth'], '修改密码', {
    requestBody: body({
      type: 'object',
      required: ['currentPassword', 'newPassword'],
      properties: {
        currentPassword: { type: 'string' },
        newPassword: { type: 'string' },
        encCurrentPassword: {
          type: 'string',
          description: '当前口令密文（与 currentPassword 二选一）',
        },
        encNewPassword: { type: 'string', description: '新口令密文（与 newPassword 二选一）' },
      },
    }),
    responses: { ...ok('修改成功，需重新登录') },
  }),
};

spec.paths['/api/auth/profile'] = {
  put: p('put', ['Auth'], '更新个人资料', {
    requestBody: body(
      {
        type: 'object',
        properties: {
          realName: { type: 'string' },
          email: { type: 'string' },
          phone: { type: 'string' },
          department: { type: 'string' },
          avatar: { type: 'string' },
        },
      },
      false
    ),
  }),
};

spec.paths['/api/auth/logout'] = {
  post: p('post', ['Auth'], '用户登出', {
    requestBody: body({ type: 'object', properties: { refreshToken: { type: 'string' } } }, false),
  }),
};

// L-24：以下 14 个端点此前只存在于产物、生成器中缺失——重跑生成器会
// 把它们整体抹掉（实测 path 数 83 → 69），而产物却是线上 Swagger 的实际来源。
// 本块把它们补回生成器，使两者重新等价；openapiSync 测试新增对账守卫。
spec.paths['/api/auth/login-public-key'] = {
  get: p('get', ['Auth'], '获取登录口令加密公钥（ECDH P-256，供前端加密口令上行）', {
    security: false,
    responses: ok('返回 publicKey PEM / keyId / curve / 算法标识'),
  }),
};

spec.paths['/api/auth/session'] = {
  get: p('get', ['Auth'], '轻量会话探测（返回是否已登录；始终 200，不触发令牌刷新链）', {
    security: false,
    responses: ok('返回 { authenticated: boolean }'),
  }),
};

spec.paths['/api/auth/sessions'] = {
  get: p('get', ['Auth'], '获取当前用户的活跃会话列表（设备级会话管理）', {
    responses: ok('返回会话列表（sid/设备/时间），可远程吊销其他设备'),
  }),
};

spec.paths['/api/auth/sessions/others'] = {
  delete: p('delete', ['Auth'], '吊销除当前设备外的全部会话', {
    responses: ok('其余设备全部下线'),
  }),
};

spec.paths['/api/auth/sessions/{sid}'] = {
  delete: p('delete', ['Auth'], '吊销指定会话（踢除单台设备）', {
    parameters: [{ name: 'sid', in: 'path', required: true, schema: { type: 'string' } }],
    responses: { ...ok('该设备已下线'), 404: { description: '会话不存在' } },
  }),
};

spec.paths['/api/auth/mfa/status'] = {
  get: p('get', ['Auth'], '查询两步验证开启状态与剩余恢复码数量', {
    responses: ok('返回 { enabled, recoveryCodesRemaining }'),
  }),
};

spec.paths['/api/auth/mfa/enroll'] = {
  post: p('post', ['Auth'], '生成两步验证密钥（第一步，返回 Base32 密钥与 otpauth URI）', {
    responses: { ...ok('返回 secret 与 otpauthUri'), 400: { description: '已开启两步验证' } },
  }),
};

spec.paths['/api/auth/mfa/enable'] = {
  post: p('post', ['Auth'], '确认开启两步验证（校验一次动态口令，生成备用恢复码）', {
    requestBody: body({
      type: 'object',
      required: ['mfaCode'],
      properties: { mfaCode: { type: 'string', description: '6 位动态口令' } },
    }),
    responses: {
      ...ok('返回 { enabled: true, recoveryCodes }（明文仅此一次）'),
      400: { description: '验证码错误' },
    },
  }),
};

spec.paths['/api/auth/mfa/disable'] = {
  post: p('post', ['Auth'], '关闭两步验证（需动态口令或登录密码二次验证）', {
    requestBody: body(
      {
        type: 'object',
        properties: {
          mfaCode: { type: 'string', description: '6 位动态口令（与 currentPassword 二选一）' },
          encCurrentPassword: {
            type: 'string',
            description: '当前口令密文（与 currentPassword 二选一）',
          },
          currentPassword: { type: 'string' },
        },
      },
      // required=true：控制器在「既无动态码也无登录密码」时一律拒绝，
      // 空请求体必然失败，故此处按必填描述（字段级仍全部可选——两条路径二选一）。
      true
    ),
    responses: { ...ok('返回 { enabled: false }'), 403: { description: '验证失败' } },
  }),
};

spec.paths['/api/auth/mfa/recovery-codes'] = {
  post: p('post', ['Auth'], '重新生成备用恢复码（旧码全部作废；需当前动态口令）', {
    requestBody: body({
      type: 'object',
      required: ['mfaCode'],
      properties: { mfaCode: { type: 'string', description: '6 位动态口令' } },
    }),
    responses: { ...ok('返回新恢复码明文（仅此一次）'), 400: { description: '口令错误' } },
  }),
};

// ==================== Users ====================
const userListParams = [
  { name: 'page', in: 'query', schema: { type: 'integer', default: 1 } },
  { name: 'limit', in: 'query', schema: { type: 'integer', default: 10 } },
  { name: 'search', in: 'query', schema: { type: 'string' } },
  {
    name: 'status',
    in: 'query',
    schema: { type: 'string', enum: Object.values(USER_STATUS) },
  },
  { name: 'department', in: 'query', schema: { type: 'string' } },
];

spec.paths['/api/users'] = {
  get: p('get', ['Users'], '获取用户列表（分页）', { parameters: userListParams }),
  post: p('post', ['Users'], '创建用户', {
    requestBody: body({
      type: 'object',
      required: ['username', 'email', 'password'],
      properties: {
        username: { type: 'string' },
        email: { type: 'string' },
        password: { type: 'string' },
        realName: { type: 'string' },
        // 写入收明文、读出只给脱敏值：这个不对称是刻意的，理由见
        // services/userService.js 的 toMaskedAdminUser 注释。
        phone: {
          type: 'string',
          description:
            '仅接受写入（/^1[3-9]\\d{9}$/）；用户列表/详情/建号/改号/角色回显返回 phoneMasked，不含该字段',
        },
        department: { type: 'string' },
        roles: { type: 'array', items: { type: 'string' } },
      },
    }),
    responses: { ...created('创建成功'), ...badRequest },
  }),
};

spec.paths['/api/users/stats'] = {
  get: p('get', ['Users'], '获取用户统计信息', {
    responses: ok('返回总数、活跃/禁用数、按部门/角色统计'),
  }),
};

const idParam = [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }];

spec.paths['/api/users/{id}'] = {
  get: p('get', ['Users'], '获取用户详情', {
    parameters: idParam,
    responses: { ...ok('成功'), ...notFound },
  }),
  put: p('put', ['Users'], '更新用户信息', {
    parameters: idParam,
    responses: { ...ok('成功'), ...forbidden },
  }),
  delete: p('delete', ['Users'], '删除用户', {
    parameters: idParam,
    responses: { ...ok('删除成功'), 400: { description: '不能删除自己' } },
  }),
};

spec.paths['/api/users/{id}/roles'] = {
  put: p('put', ['Users'], '分配角色给用户', {
    parameters: idParam,
    requestBody: body({
      type: 'object',
      required: ['roles'],
      properties: { roles: { type: 'array', items: { type: 'string' }, minItems: 1 } },
    }),
  }),
};

spec.paths['/api/users/batch'] = {
  delete: p('delete', ['Users'], '批量删除用户', {
    requestBody: body({
      type: 'object',
      required: ['ids'],
      properties: { ids: { type: 'array', items: { type: 'string' }, maxItems: 100 } },
    }),
  }),
};

// ==================== Roles ====================
spec.paths['/api/roles'] = {
  get: p('get', ['Roles'], '获取角色列表（分页）'),
  post: p('post', ['Roles'], '创建角色', {
    requestBody: body({
      type: 'object',
      required: ['name', 'code'],
      properties: {
        name: { type: 'string' },
        code: { type: 'string', pattern: '^[A-Z_]+$' },
        description: { type: 'string' },
        level: { type: 'integer', minimum: 1, maximum: 10 },
        permissions: { type: 'array', items: { type: 'string' } },
      },
    }),
    responses: { ...created('创建成功') },
  }),
};

spec.paths['/api/roles/all'] = { get: p('get', ['Roles'], '获取所有可用角色（下拉选择）') };
spec.paths['/api/roles/permissions/tree'] = {
  get: p('get', ['Roles'], '获取权限树形结构', { responses: ok('返回按模块分组的权限树') }),
};

spec.paths['/api/roles/{id}'] = {
  get: p('get', ['Roles'], '获取角色详情', { parameters: idParam }),
  put: p('put', ['Roles'], '更新角色信息', { parameters: idParam }),
  delete: p('delete', ['Roles'], '删除角色', {
    parameters: idParam,
    responses: { ...ok('删除成功'), 400: { description: '有用户正在使用该角色' } },
  }),
};

spec.paths['/api/roles/{id}/permissions'] = {
  put: p('put', ['Roles'], '为角色分配权限', {
    parameters: idParam,
    description: '支持全局修改和单用户克隆两种模式',
    requestBody: body({
      type: 'object',
      required: ['permissions'],
      properties: {
        permissions: { type: 'array', items: { type: 'string' } },
        targetUserId: { type: 'string', description: '单用户克隆模式目标用户ID（可选）' },
      },
    }),
  }),
};

// ==================== Permissions ====================
spec.paths['/api/permissions'] = {
  get: p('get', ['Permissions'], '获取权限列表'),
  post: p('post', ['Permissions'], '创建权限', {
    requestBody: body({
      type: 'object',
      required: ['name', 'code', 'type', 'module'],
      properties: {
        name: { type: 'string' },
        code: { type: 'string', pattern: '^(\\*|[a-z]+):(\\*|[a-z_]+)$' },
        type: { type: 'string', enum: PERMISSION_TYPES },
        module: { type: 'string' },
        parent: { type: 'string' },
        path: { type: 'string' },
        method: { type: 'string', enum: PERMISSION_METHODS },
      },
    }),
    responses: { ...created('创建成功') },
  }),
};

spec.paths['/api/permissions/batch'] = {
  post: p('post', ['Permissions'], '批量创建权限（系统初始化）', {
    requestBody: body({
      type: 'object',
      required: ['permissions'],
      properties: { permissions: { type: 'array', items: { type: 'object' }, minItems: 1 } },
    }),
    responses: { ...created('创建成功') },
  }),
};

spec.paths['/api/permissions/{id}'] = {
  get: p('get', ['Permissions'], '获取权限详情', { parameters: idParam }),
  put: p('put', ['Permissions'], '更新权限', { parameters: idParam }),
  delete: p('delete', ['Permissions'], '删除权限', { parameters: idParam }),
};

// ==================== Devices ====================
const deviceListParams = [
  { name: 'page', in: 'query', schema: { type: 'integer', default: 1 } },
  { name: 'limit', in: 'query', schema: { type: 'integer', default: 10, maximum: 100 } },
  {
    name: 'deviceType',
    in: 'query',
    schema: {
      type: 'string',
      // E-05：引用共享枚举，避免与模型/路由校验漂移
      enum: DEVICE_TYPE_VALUES,
    },
  },
  {
    name: 'status',
    in: 'query',
    schema: {
      type: 'string',
      enum: DEVICE_STATUS_VALUES,
    },
  },
  { name: 'building', in: 'query', schema: { type: 'string' } },
  { name: 'floor', in: 'query', schema: { type: 'string' } },
  { name: 'search', in: 'query', schema: { type: 'string' } },
];

spec.paths['/api/devices'] = {
  get: p('get', ['Devices'], '获取设备列表（分页）', { parameters: deviceListParams }),
  post: p('post', ['Devices'], '创建设备', {
    description: '设备编号自动生成，格式为 类型前缀-年份-序号（如 FA-2026-0001）',
    requestBody: body({
      type: 'object',
      required: ['deviceName', 'deviceType'],
      properties: {
        deviceName: { type: 'string' },
        deviceType: { type: 'string' },
        model: { type: 'string' },
        manufacturer: { type: 'string' },
        location: { type: 'object' },
        installDate: { type: 'string', format: 'date' },
        expiryDate: { type: 'string', format: 'date' },
        checkCycle: { type: 'integer', description: '检查周期（天）' },
        remark: { type: 'string' },
        images: { type: 'array', items: { type: 'string' } },
      },
    }),
    responses: { ...created('创建成功') },
  }),
};

spec.paths['/api/devices/stats'] = {
  get: p('get', ['Devices'], '获取设备统计信息', {
    responses: ok('返回按类型/状态统计、待维护数、即将到期数、已过期数'),
  }),
};
spec.paths['/api/devices/expiring'] = {
  get: p('get', ['Devices'], '获取即将到期设备列表', {
    parameters: [
      {
        name: 'days',
        in: 'query',
        schema: { type: 'integer', default: 30, minimum: 1, maximum: 365 },
      },
    ],
  }),
};
spec.paths['/api/devices/reminders'] = {
  get: p('get', ['Devices'], '获取设备到期/维护提醒汇总', {
    parameters: [{ name: 'days', in: 'query', schema: { type: 'integer', default: 30 } }],
    responses: ok('返回到期、过期、待维护三类提醒'),
  }),
};

spec.paths['/api/devices/{id}'] = {
  get: p('get', ['Devices'], '获取设备详情', {
    parameters: idParam,
    responses: { ...ok('成功'), ...notFound },
  }),
  put: p('put', ['Devices'], '更新设备信息', { parameters: idParam }),
  delete: p('delete', ['Devices'], '删除设备', {
    parameters: idParam,
    description: '自动清理关联的报警和巡检记录中的设备引用',
  }),
};

spec.paths['/api/devices/{id}/status'] = {
  put: p('put', ['Devices'], '更新设备状态', {
    parameters: idParam,
    requestBody: body({
      type: 'object',
      required: ['status'],
      properties: {
        status: { type: 'string', enum: DEVICE_STATUS_WRITABLE },
      },
    }),
  }),
};

spec.paths['/api/devices/{id}/maintenance'] = {
  post: p('post', ['Devices'], '添加维护记录', {
    parameters: idParam,
    requestBody: body({
      type: 'object',
      required: ['content'],
      properties: {
        content: { type: 'string', minLength: 1, maxLength: 500 },
        // type 决定检查周期是否顺延（routine/inspection 顺延，repair/replacement 不顺延）；
        // 枚举须与 deviceRoutes.maintenanceValidation / FireDevice.maintenanceRecord.type 对齐。
        type: { type: 'string', enum: ['routine', 'repair', 'replacement', 'inspection'] },
      },
    }),
    responses: { ...ok('添加成功，自动更新下次检查日期') },
  }),
};

spec.paths['/api/devices/{id}/scrap'] = {
  put: p('put', ['Devices'], '设备报废', {
    parameters: idParam,
    requestBody: body(
      {
        type: 'object',
        // 字段名须与 deviceRoutes.scrapDeviceValidation / deviceController 的 scrapReason 一致；
        // 旧文档写成 reason，集成方按文档提交的报废原因会被静默丢弃（FireDevice.scrapReason 落默认值）。
        properties: {
          scrapReason: { type: 'string', maxLength: 200 },
          scrapDate: { type: 'string', format: 'date' },
        },
      },
      false
    ),
  }),
};

// ==================== Alarms ====================
const alarmListParams = [
  { name: 'page', in: 'query', schema: { type: 'integer', default: 1 } },
  { name: 'limit', in: 'query', schema: { type: 'integer', default: 10, maximum: 100 } },
  {
    name: 'status',
    in: 'query',
    schema: { type: 'string', enum: ALARM_STATUSES },
  },
  {
    name: 'level',
    in: 'query',
    schema: { type: 'string', enum: ALARM_LEVELS },
  },
  // 原先 alarmType 的 query 参数没有 enum，而路由校验器一直在 isIn(...) 上拒非法值：
  // 文档比运行时宽，调用方按文档传 'smoking' 会拿到 400。接同一根线后一并补齐。
  { name: 'alarmType', in: 'query', schema: { type: 'string', enum: ALARM_TYPES } },
  { name: 'startDate', in: 'query', schema: { type: 'string' } },
  { name: 'endDate', in: 'query', schema: { type: 'string' } },
  { name: 'search', in: 'query', schema: { type: 'string' } },
];

spec.paths['/api/alarms'] = {
  get: p('get', ['Alarms'], '获取报警列表（分页）', { parameters: alarmListParams }),
};
spec.paths['/api/alarms/stats'] = {
  get: p('get', ['Alarms'], '获取报警统计信息', {
    parameters: [
      { name: 'startDate', in: 'query', schema: { type: 'string' } },
      { name: 'endDate', in: 'query', schema: { type: 'string' } },
    ],
    responses: ok('返回按状态/级别/类型统计'),
  }),
};
spec.paths['/api/alarms/{id}'] = {
  get: p('get', ['Alarms'], '获取报警详情', { parameters: idParam }),
};

spec.paths['/api/alarms/report'] = {
  post: p('post', ['Alarms'], '上报火警（手动报警）', {
    description: '上报人身份强制使用当前登录用户，不可伪造',
    requestBody: body({
      type: 'object',
      required: ['alarmType', 'description'],
      properties: {
        alarmType: {
          type: 'string',
          enum: ALARM_TYPES,
        },
        level: { type: 'string', enum: ALARM_LEVELS },
        location: { type: 'object' },
        description: { type: 'string', maxLength: 500 },
        deviceId: { type: 'string' },
        reporter: {
          type: 'object',
          properties: {
            name: { type: 'string' },
            // 接受写入但任何读接口都不回传（投影见 services/AlarmService.js 的
            // ALARM_READ_SELECT）：明文手机号原样外发给全体 alarm:read 持有者会绕过
            // 仓里为手机号建立的 step-up 通道。
            phone: {
              type: 'string',
              description: '仅接受写入，报警列表/详情/处置响应均不返回该字段',
            },
          },
        },
      },
    }),
    responses: { ...created('报警接收成功') },
  }),
};

spec.paths['/api/alarms/{id}/dispatch'] = {
  put: p('put', ['Alarms'], '指派处理人', {
    parameters: idParam,
    requestBody: body(
      {
        type: 'object',
        properties: { handlerId: { type: 'string', description: '不填则指派给当前用户' } },
      },
      false
    ),
    responses: { ...ok('指派成功'), 409: { description: '报警已被处理' } },
  }),
};

spec.paths['/api/alarms/{id}/arrive'] = {
  put: p('put', ['Alarms'], '到达现场登记', {
    parameters: idParam,
    responses: { ...ok('登记成功'), 409: { description: '状态不允许此操作' } },
  }),
};

spec.paths['/api/alarms/{id}/resolve'] = {
  put: p('put', ['Alarms'], '处理完成', {
    parameters: idParam,
    requestBody: body({
      type: 'object',
      required: ['handleResult'],
      properties: {
        handleResult: { type: 'string', maxLength: 1000 },
        cause: {
          type: 'string',
          enum: ALARM_CAUSES,
        },
      },
    }),
  }),
};

spec.paths['/api/alarms/{id}/false-alarm'] = {
  put: p('put', ['Alarms'], '标记为误报', {
    parameters: idParam,
    requestBody: body({ type: 'object', properties: { reason: { type: 'string' } } }, false),
  }),
};

spec.paths['/api/alarms/{id}/cancel'] = {
  put: p('put', ['Alarms'], '取消报警', {
    parameters: idParam,
    requestBody: body({ type: 'object', properties: { reason: { type: 'string' } } }, false),
  }),
};

// ==================== Inspections ====================
const inspectionListParams = [
  { name: 'page', in: 'query', schema: { type: 'integer', default: 1 } },
  { name: 'limit', in: 'query', schema: { type: 'integer', default: 10, maximum: 100 } },
  {
    name: 'status',
    in: 'query',
    schema: { type: 'string', enum: INSPECTION_STATUSES },
  },
  { name: 'inspectionType', in: 'query', schema: { type: 'string', enum: INSPECTION_TYPES } },
  { name: 'assignedTo', in: 'query', schema: { type: 'string' } },
  { name: 'startDate', in: 'query', schema: { type: 'string' } },
  { name: 'endDate', in: 'query', schema: { type: 'string' } },
  { name: 'search', in: 'query', schema: { type: 'string' } },
];

spec.paths['/api/inspections'] = {
  get: p('get', ['Inspections'], '获取巡检列表（分页）', { parameters: inspectionListParams }),
  post: p('post', ['Inspections'], '创建巡检计划', {
    requestBody: body({
      type: 'object',
      required: ['title', 'inspectionType', 'planStartTime', 'planEndTime', 'checkItems'],
      properties: {
        title: { type: 'string' },
        inspectionType: {
          type: 'string',
          enum: INSPECTION_TYPES,
        },
        planStartTime: { type: 'string', format: 'date-time' },
        planEndTime: { type: 'string', format: 'date-time' },
        assignedTo: { type: 'array', items: { type: 'string', format: 'mongodb-id' } },
        devices: { type: 'array', items: { type: 'string' } },
        locations: { type: 'array', items: { type: 'object' } },
        checkItems: { type: 'array', items: { type: 'object' }, minItems: 1 },
        description: { type: 'string' },
        remark: { type: 'string' },
      },
    }),
    responses: { ...created('创建成功') },
  }),
};

spec.paths['/api/inspections/stats'] = {
  get: p('get', ['Inspections'], '获取巡检统计', {
    parameters: [
      { name: 'startDate', in: 'query', schema: { type: 'string' } },
      { name: 'endDate', in: 'query', schema: { type: 'string' } },
    ],
    responses: ok('返回按状态/类型/结果统计'),
  }),
};

spec.paths['/api/inspections/{id}'] = {
  get: p('get', ['Inspections'], '获取巡检详情', { parameters: idParam }),
  put: p('put', ['Inspections'], '更新巡检计划', {
    parameters: idParam,
    description: '仅 pending 状态可修改',
    responses: { ...ok('成功'), 400: { description: '已开始的巡检不能修改' } },
  }),
  delete: p('delete', ['Inspections'], '删除巡检', {
    parameters: idParam,
    responses: { ...ok('删除成功'), 400: { description: '正在执行的巡检不能删除' } },
  }),
};

spec.paths['/api/inspections/{id}/start'] = {
  put: p('put', ['Inspections'], '开始执行巡检', { parameters: idParam }),
};

spec.paths['/api/inspections/{id}/complete'] = {
  put: p('put', ['Inspections'], '提交巡检结果', {
    parameters: idParam,
    requestBody: body(
      {
        type: 'object',
        // result 必填：inspectionRoutes completeValidation 的 body('result').isIn([...]) 无 .optional()
        required: ['result'],
        properties: {
          result: { type: 'string', enum: INSPECTION_RESULTS },
          findings: { type: 'array', items: { type: 'object' } },
          location: { type: 'string' },
          remark: { type: 'string' },
        },
      },
      true
    ),
  }),
};

spec.paths['/api/inspections/{id}/review'] = {
  put: p('put', ['Inspections'], '审核巡检结果', {
    parameters: idParam,
    requestBody: body({
      type: 'object',
      required: ['reviewResult'],
      properties: {
        reviewResult: { type: 'string', enum: INSPECTION_REVIEW_RESULTS },
        reviewComment: { type: 'string' },
      },
    }),
  }),
};

spec.paths['/api/inspections/{id}/cancel'] = {
  put: p('put', ['Inspections'], '取消巡检', {
    parameters: idParam,
    requestBody: body({ type: 'object', properties: { reason: { type: 'string' } } }, false),
  }),
};

// ==================== Reports ====================
const dateRangeParams = [
  { name: 'startDate', in: 'query', schema: { type: 'string' } },
  { name: 'endDate', in: 'query', schema: { type: 'string' } },
];

spec.paths['/api/reports/dashboard'] = {
  get: p('get', ['Reports'], '获取综合仪表盘统计', {
    responses: ok('返回设备、报警、巡检综合统计'),
  }),
};
spec.paths['/api/reports/devices'] = {
  get: p('get', ['Reports'], '获取设备报表', { parameters: dateRangeParams }),
};
spec.paths['/api/reports/alarms'] = {
  get: p('get', ['Reports'], '获取报警报表', { parameters: dateRangeParams }),
};
spec.paths['/api/reports/inspections'] = {
  get: p('get', ['Reports'], '获取巡检报表', {
    parameters: dateRangeParams,
    responses: ok('返回按状态、结果、执行人统计'),
  }),
};

spec.paths['/api/reports/export'] = {
  get: p('get', ['Reports'], '导出报表数据（Excel）', {
    description: '支持 devices/alarms/inspections，受严格限流保护',
    parameters: [
      {
        name: 'type',
        in: 'query',
        required: true,
        schema: { type: 'string', enum: ['devices', 'alarms', 'inspections'] },
      },
      ...dateRangeParams,
    ],
    responses: { 200: { description: '返回 Excel 文件流' }, 429: { description: '请求过于频繁' } },
  }),
};

// ==================== Security ====================
spec.paths['/api/security/my-info'] = {
  get: p('get', ['Security'], '获取当前用户安全信息', {
    responses: ok('返回安全评分、近期登录记录、安全建议'),
  }),
};

spec.paths['/api/security/change-password'] = {
  put: p('put', ['Security'], '修改密码（强化版，需确认密码）', {
    requestBody: body({
      type: 'object',
      required: ['currentPassword', 'newPassword', 'confirmPassword'],
      properties: {
        currentPassword: { type: 'string' },
        newPassword: { type: 'string' },
        confirmPassword: { type: 'string' },
      },
    }),
    responses: { ...ok('修改成功，需重新登录') },
  }),
};

spec.paths['/api/security/bindings'] = {
  get: p('get', ['Security'], '获取账户绑定信息', {
    responses: ok('返回邮箱、手机、部门绑定状态（脱敏）'),
  }),
};

spec.paths['/api/security/view-sensitive'] = {
  post: p('post', ['Security'], '查看敏感数据（需二次验证）', {
    requestBody: body({
      type: 'object',
      required: ['dataType'],
      properties: { dataType: { type: 'string', enum: ['phone', 'email'] } },
    }),
    responses: { ...ok('返回脱敏和完整数据') },
  }),
};

spec.paths['/api/security/stats'] = {
  get: p('get', ['Security'], '获取系统安全统计（管理员）', {
    responses: ok('返回今日登录数、失败登录数、高风险操作数、异常行为'),
  }),
};

spec.paths['/api/security/report'] = {
  post: p('post', ['Security'], '举报异常行为', {
    requestBody: body({
      type: 'object',
      required: ['targetType', 'reason'],
      properties: {
        targetType: { type: 'string', enum: ['user', 'device', 'alarm', 'system'] },
        // 记录型（user/device/alarm）必填，且必须指向一条存在并在举报人数据范围内的记录；
        // system 型不得携带 targetId（服务端会拒绝）。核验位置见 securityRoutes.reportValidation
        // 与 securityController 的 resolveReportTargetViolation。
        targetId: { type: 'string', pattern: '^[a-f0-9]{24}$' },
        reason: { type: 'string', maxLength: 200 },
        description: { type: 'string' },
      },
    }),
    responses: {
      ...created('举报已提交'),
      403: { description: '被举报对象超出举报人的数据范围' },
      404: { description: '被举报对象不存在' },
    },
  }),
};

spec.paths['/api/security/my-logs'] = {
  get: p('get', ['Security'], '获取个人操作日志', {
    parameters: [
      { name: 'days', in: 'query', schema: { type: 'integer', default: 7 } },
      { name: 'limit', in: 'query', schema: { type: 'integer', default: 50 } },
      { name: 'category', in: 'query', schema: { type: 'string' } },
    ],
  }),
};

const userIdParam = [{ name: 'userId', in: 'path', required: true, schema: { type: 'string' } }];
spec.paths['/api/security/users/{userId}/lock'] = {
  put: p('put', ['Security'], '锁定/解锁用户账户（管理员）', {
    parameters: userIdParam,
    requestBody: body({
      type: 'object',
      required: ['locked'],
      properties: { locked: { type: 'boolean' }, reason: { type: 'string' } },
    }),
    responses: { ...ok('操作成功'), ...forbidden },
  }),
};

spec.paths['/api/security/overview'] = {
  get: p('get', ['Security'], '获取安全概览（管理员）', {
    responses: ok('返回严重/高危告警数、失败登录数、风险评分'),
  }),
};
spec.paths['/api/security/alerts'] = {
  get: p('get', ['Security'], '获取最近安全告警', { responses: ok('返回最近50条告警') }),
};

spec.paths['/api/security/audit-logs'] = {
  get: p('get', ['Security'], '查询审计日志（多维度筛选）', {
    parameters: [
      { name: 'page', in: 'query', schema: { type: 'integer', default: 1 } },
      { name: 'limit', in: 'query', schema: { type: 'integer', default: 20, maximum: 1000 } },
      { name: 'startDate', in: 'query', schema: { type: 'string' } },
      { name: 'endDate', in: 'query', schema: { type: 'string' } },
      { name: 'userId', in: 'query', schema: { type: 'string' } },
      { name: 'username', in: 'query', schema: { type: 'string' } },
      { name: 'action', in: 'query', schema: { type: 'string' } },
      { name: 'category', in: 'query', schema: { type: 'string' } },
      { name: 'ip', in: 'query', schema: { type: 'string' } },
      {
        name: 'riskLevel',
        in: 'query',
        schema: { type: 'string', enum: AUDIT_RISK_LEVELS },
      },
      { name: 'success', in: 'query', schema: { type: 'string', enum: ['true', 'false'] } },
      {
        name: 'level',
        in: 'query',
        schema: { type: 'string', enum: AUDIT_DISPLAY_LEVELS },
      },
    ],
  }),
};

spec.paths['/api/security/config/allowPublicRegistration'] = {
  get: p('get', ['Security'], '获取注册开关状态', {
    responses: ok('返回 allowPublicRegistration'),
  }),
  put: p('put', ['Security'], '设置注册开关', {
    requestBody: body({
      type: 'object',
      required: ['allowPublicRegistration'],
      properties: { allowPublicRegistration: { type: 'boolean' } },
    }),
  }),
};

spec.paths['/api/security/config/loginCaptchaEnabled'] = {
  get: p('get', ['Security'], '获取登录验证码开关状态', {
    responses: ok('返回 loginCaptchaEnabled'),
  }),
  put: p('put', ['Security'], '设置登录验证码开关', {
    requestBody: body({
      type: 'object',
      required: ['loginCaptchaEnabled'],
      properties: { loginCaptchaEnabled: { type: 'boolean' } },
    }),
  }),
};

spec.paths['/api/security/ip-list'] = {
  get: p('get', ['Security'], '获取 IP 黑白名单列表', {
    parameters: [{ name: 'type', in: 'query', schema: { type: 'string', enum: IP_LIST_TYPES } }],
  }),
  post: p('post', ['Security'], '添加 IP 到黑/白名单', {
    description: '白名单优先级高于黑名单；加入黑名单时若已在白名单则拒绝',
    requestBody: body({
      type: 'object',
      required: ['ip'],
      properties: {
        ip: { type: 'string', description: '支持 IPv4/IPv6/CIDR' },
        type: { type: 'string', enum: IP_LIST_TYPES, default: 'black' },
        reason: { type: 'string', maxLength: 200 },
        durationHours: { type: 'number', minimum: 0, maximum: 8760, description: '0=永久' },
      },
    }),
    responses: { ...created('添加成功'), 400: { description: 'IP 已在白名单中' } },
  }),
};

const ipIdParam = [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }];
spec.paths['/api/security/ip-list/{id}'] = {
  delete: p('delete', ['Security'], '从名单中移除 IP 记录', { parameters: ipIdParam }),
};

spec.paths['/api/security/ip-list/query'] = {
  get: p('get', ['Security'], '查询 IP 命中的黑/白名单记录', {
    description:
      '返回该 IP 命中的全部黑/白名单记录（含 CIDR 网段与等价地址形式）；各列表按覆盖面最宽优先排序（如 /16 与 /24 同时命中时 /16 在首位），并给出最终生效判定（白名单优先）',
    parameters: [
      {
        name: 'ip',
        in: 'query',
        required: true,
        schema: { type: 'string', description: 'IPv4/IPv6 单地址（不含 CIDR）' },
      },
    ],
    responses: ok('返回命中记录'),
  }),
};

// L-24：以下 4 个端点此前只存在于产物、生成器中缺失（同上方 Auth 块）。
spec.paths['/api/security/users/{userId}/mfa/reset'] = {
  put: p('put', ['Security'], '管理员重置用户两步验证（清除密钥/恢复码并强制下线）', {
    parameters: [{ name: 'userId', in: 'path', required: true, schema: { type: 'string' } }],
    responses: {
      ...ok('两步验证已重置'),
      400: { description: '未开启 MFA / 目标为自身' },
      403: { description: '同级或更高层级 / 内置超管' },
    },
  }),
};

spec.paths['/api/security/audit-logs/verify'] = {
  get: p('get', ['Security'], '校验审计日志哈希链完整性（hash 重算 + hmac + 链接性三层校验）', {
    parameters: [{ name: 'limit', in: 'query', schema: { type: 'integer' } }],
    responses: ok('返回校验报告（intact/breaks/byType）'),
  }),
};

spec.paths['/api/security/audit-logs/export'] = {
  get: p('get', ['Security'], '导出审计日志（CSV + sha256 签名 manifest，流式输出）', {
    parameters: [
      { name: 'limit', in: 'query', schema: { type: 'integer' } },
      { name: 'from', in: 'query', schema: { type: 'string' } },
    ],
    responses: ok('text/csv 流式响应'),
  }),
};

spec.paths['/api/security/config/registerCaptchaEnabled'] = {
  get: p('get', ['Security'], '获取注册验证码开关状态', {
    responses: ok('返回 { registerCaptchaEnabled: boolean }'),
  }),
  put: p('put', ['Security'], '切换注册验证码开关', {
    requestBody: body({
      type: 'object',
      required: ['registerCaptchaEnabled'],
      properties: { registerCaptchaEnabled: { type: 'boolean' } },
    }),
    responses: ok('开关已更新'),
  }),
};

// ==================== System ====================
spec.paths['/health'] = {
  get: p('get', ['System'], '健康检查', {
    security: false,
    // P2-46：原描述称「包含数据库连接状态」，与实现不符——app.js 的 /health
    // 只回 { status: 'ok' }（刻意最小化，不暴露版本/DB 状态等内部信息）；
    // 带 DB 连通性的是 /readyz（另有 M-1 固定枚举约束）。
    responses: ok("进程存活信号，固定返回 { status: 'ok' }"),
  }),
};
spec.paths['/api'] = {
  get: p('get', ['System'], 'API 根路径', {
    security: false,
    // P2-46：原描述称「返回 API 版本和可用端点列表」，与实现不符——
    // app.js 的 /api 只回 { success: true, message: '消防管理系统 API' }；
    // 返回端点清单是刻意的安全取舍（避免未认证的信息暴露），不会再恢复。
    responses: ok('固定返回 { success: true, message }，不含端点清单'),
  }),
};

// L-24：本文件此前只有「生成」一种用法——require 它就必然重写产物。
// 于是它无法被测试比对，产物与生成器之间的漂移长期无人发现
// （实测重跑会把 83 个 path 覆盖成 69 个，精确丢失 14 个端点）。
//
// 现在拆成两种用法：
//   - 直接执行（node src/docs/generate.js）→ 写盘，保持原有行为；
//   - 被 require → 只导出 spec，不产生任何副作用。
// 后者让 openapiSync 测试能对「生成器输出」与「已提交产物」做双向对账。
module.exports = spec;

if (require.main === module) {
  const outPath = path.join(__dirname, 'openapi.json');
  // 产物按仓库自己的 prettier 配置落盘。原先这里直接写 JSON.stringify 的结果：
  // 短数组会逐行展开，而已提交产物是 prettier 版（短数组并成一行）——
  // 于是「改完生成器重跑一次」必然把 500 多行格式噪声灌进 diff，
  // 并且让 CI 的 `npm run format:check` 红（openapiSync 的逐端点深比对按内容比，
  // 抓不到格式漂移；实测这次整改就是这么撞上的）。
  // prettier 只在 CLI 分支 require：被 app/tests require 时不走这里，
  // 生产安装（--omit=dev）因此不需要它。失败不做静默降级——
  // 退回未格式化写法等于把这个坑重新埋回去。
  (async () => {
    const prettier = require('prettier');
    const options = await prettier.resolveConfig(outPath);
    const raw = JSON.stringify(spec, null, 2);
    const formatted = await prettier.format(raw, { ...options, filepath: outPath });
    fs.writeFileSync(outPath, formatted, 'utf8');
    console.log('Generated:', outPath);
    console.log('Paths:', Object.keys(spec.paths).length);
    console.log(
      'Operations:',
      Object.values(spec.paths).reduce((n, p) => n + Object.keys(p).length, 0)
    );
  })().catch((err) => {
    console.error('生成 openapi.json 失败:', err.message);
    process.exitCode = 1;
  });
}
