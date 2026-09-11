const fs = require('fs');
const path = require('path');

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
        captchaCode: { type: 'string' },
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
      properties: { currentPassword: { type: 'string' }, newPassword: { type: 'string' } },
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

// ==================== Users ====================
const userListParams = [
  { name: 'page', in: 'query', schema: { type: 'integer', default: 1 } },
  { name: 'limit', in: 'query', schema: { type: 'integer', default: 10 } },
  { name: 'search', in: 'query', schema: { type: 'string' } },
  {
    name: 'status',
    in: 'query',
    schema: { type: 'string', enum: ['active', 'inactive', 'locked'] },
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
        phone: { type: 'string' },
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
        type: { type: 'string', enum: ['menu', 'button', 'api', 'data'] },
        module: { type: 'string' },
        parent: { type: 'string' },
        path: { type: 'string' },
        method: { type: 'string', enum: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', '*'] },
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
      enum: [
        'fire_alarm',
        'sprinkler',
        'hydrant',
        'extinguisher',
        'smoke_detector',
        'heat_detector',
        'emergency_light',
        'evacuation_sign',
        'fire_door',
        'other',
      ],
    },
  },
  {
    name: 'status',
    in: 'query',
    schema: {
      type: 'string',
      enum: ['normal', 'warning', 'fault', 'offline', 'maintenance', 'scrapped'],
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
        status: { type: 'string', enum: ['normal', 'warning', 'fault', 'offline', 'maintenance'] },
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
      properties: { content: { type: 'string', minLength: 1, maxLength: 500 } },
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
        properties: { reason: { type: 'string' }, scrapDate: { type: 'string', format: 'date' } },
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
    schema: {
      type: 'string',
      enum: ['pending', 'processing', 'resolved', 'false_alarm', 'cancelled'],
    },
  },
  {
    name: 'level',
    in: 'query',
    schema: { type: 'string', enum: ['info', 'warning', 'critical', 'emergency'] },
  },
  { name: 'alarmType', in: 'query', schema: { type: 'string' } },
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
          enum: ['smoke', 'temp_abnormal', 'manual_button', 'phone_report', 'patrol_find', 'other'],
        },
        level: { type: 'string', enum: ['info', 'warning', 'critical', 'emergency'] },
        location: { type: 'object' },
        description: { type: 'string', maxLength: 500 },
        deviceId: { type: 'string' },
        reporter: {
          type: 'object',
          properties: { name: { type: 'string' }, phone: { type: 'string' } },
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
          enum: ['fire', 'false_alarm', 'equipment_fault', 'test', 'unknown'],
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
    schema: { type: 'string', enum: ['pending', 'in_progress', 'completed', 'cancelled'] },
  },
  { name: 'inspectionType', in: 'query', schema: { type: 'string' } },
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
          enum: ['daily', 'weekly', 'monthly', 'quarterly', 'annual', 'special'],
        },
        planStartTime: { type: 'string', format: 'date-time' },
        planEndTime: { type: 'string', format: 'date-time' },
        assignedTo: { type: 'string' },
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
        properties: {
          result: { type: 'string', enum: ['normal', 'abnormal', 'partial'] },
          findings: { type: 'array', items: { type: 'object' } },
          location: { type: 'string' },
          remark: { type: 'string' },
        },
      },
      false
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
        reviewResult: { type: 'string', enum: ['approved', 'rejected'] },
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
        targetId: { type: 'string' },
        reason: { type: 'string', maxLength: 200 },
        description: { type: 'string' },
      },
    }),
    responses: { ...created('举报已提交') },
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
        schema: { type: 'string', enum: ['low', 'medium', 'high', 'critical'] },
      },
      { name: 'success', in: 'query', schema: { type: 'string', enum: ['true', 'false'] } },
      {
        name: 'level',
        in: 'query',
        schema: { type: 'string', enum: ['info', 'warning', 'error'] },
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
    parameters: [
      { name: 'type', in: 'query', schema: { type: 'string', enum: ['black', 'white'] } },
    ],
  }),
  post: p('post', ['Security'], '添加 IP 到黑/白名单', {
    description: '白名单优先级高于黑名单；加入黑名单时若已在白名单则拒绝',
    requestBody: body({
      type: 'object',
      required: ['ip'],
      properties: {
        ip: { type: 'string', description: '支持 IPv4/IPv6/CIDR' },
        type: { type: 'string', enum: ['black', 'white'], default: 'black' },
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
  }),
};

// ==================== System ====================
spec.paths['/health'] = {
  get: p('get', ['System'], '健康检查', {
    security: false,
    responses: ok('系统运行正常，包含数据库连接状态'),
  }),
};
spec.paths['/api'] = {
  get: p('get', ['System'], 'API 根路径', {
    security: false,
    responses: ok('返回 API 版本和可用端点列表'),
  }),
};

const outPath = path.join(__dirname, 'openapi.json');
fs.writeFileSync(outPath, JSON.stringify(spec, null, 2), 'utf8');
console.log('Generated:', outPath);
console.log('Paths:', Object.keys(spec.paths).length);
console.log(
  'Operations:',
  Object.values(spec.paths).reduce((n, p) => n + Object.keys(p).length, 0)
);
