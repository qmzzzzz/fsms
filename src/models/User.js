/**
 * 用户模型
 * 系统用户的基础数据结构
 */

const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const config = require('../config');

/**
 * 用户名比较口径（P3-30）
 *
 * strength: 2 = 大小写不敏感、重音敏感。用于 username 的唯一索引与所有
 * 「按用户名查找」的查询，使 Admin / admin / ADMIN 在系统中视为同一标识。
 *
 * 为何必须做：原先 username 唯一索引大小写敏感，`Admin` 与 `admin` 可并存。
 * 这不是重复数据问题而是仿冒面——审计日志、告警通知、审批记录里都以用户名
 * 呈现操作者，两个视觉上等同的账号足以让人把 A 的行为当成 B 的。
 *
 * 为何用 collation 而非新增 usernameLower 字段：collation 索引由数据库保证
 * 约束，不依赖应用层每次写入都记得同步冗余字段（漏一处约束即失效）。
 * 代价是查询必须显式带同一 collation 才能命中该索引，故所有按用户名的
 * 查找都要带 .collation(User.USERNAME_COLLATION)。
 */
const USERNAME_COLLATION = Object.freeze({ locale: 'en', strength: 2 });

const userSchema = new mongoose.Schema(
  {
    // 基本信息
    username: {
      type: String,
      required: [true, '用户名不能为空'],
      // P3-30：unique 不在字段上声明——字段级 unique 生成的是默认 collation
      // （二进制比较）的索引，Admin/admin 可并存。改为下方 schema.index()
      // 显式带 USERNAME_COLLATION 注册大小写不敏感唯一索引
      trim: true,
      minlength: [3, '用户名至少 3 个字符'],
      maxlength: [30, '用户名最多 30 个字符'],
    },
    email: {
      type: String,
      required: [true, '邮箱不能为空'],
      unique: true,
      lowercase: true,
      trim: true,
      maxlength: [254, '邮箱最多 254 个字符'],
      match: [/^\w+([-+.']\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*$/, '请输入有效的邮箱地址'],
    },
    password: {
      type: String,
      required: [true, '密码不能为空'],
      minlength: [12, '密码至少 12 个字符'],
      // P3-29：补长度上限。Mongoose 在 schema 构造时即注册 validate 为 pre('save')，
      // 因此校验先于下方的哈希钩子执行 —— 此处约束的是明文而非 60 字符的 bcrypt 哈希。
      // 上限取 bcrypt 的 72 字节硬边界：超出部分被 bcrypt 静默丢弃，
      // 意味着「合法口令 + 任意长后缀」可通过验证（等价口令），
      // 且纯 JS bcryptjs 对超长输入存在 CPU 放大。
      // 路由层 validatePasswordStrength 另有 64 字符 / 72 字节双重收口，
      // 此处是绕过路由直接操作模型（脚本、初始化数据）时的兜底。
      maxlength: [72, '密码最多 72 个字符'],
      select: false, // 默认不返回密码字段
    },

    // 个人信息
    realName: {
      type: String,
      trim: true,
      maxlength: [50, '姓名最多 50 个字符'],
    },
    phone: {
      type: String,
      trim: true,
      maxlength: [20, '手机号最多 20 个字符'],
      validate: {
        // 允许留空（清空手机号是合法操作），非空时才校验大陆手机号格式
        validator: (v) => v === '' || v === undefined || v === null || /^1[3-9]\d{9}$/.test(v),
        message: '请输入有效的手机号',
      },
    },
    department: {
      type: String,
      trim: true,
      maxlength: [100, '部门最多 100 个字符'],
    },
    avatar: {
      type: String,
      default: '',
      maxlength: [500, '头像地址最多 500 个字符'],
    },

    // 角色关联（RBAC 核心）
    roles: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Role',
      },
    ],

    // 账户状态
    status: {
      type: String,
      enum: ['active', 'inactive', 'locked'],
      default: 'active',
    },
    lastLoginAt: {
      type: Date,
    },
    lastLoginIp: {
      type: String,
    },
    passwordChangedAt: {
      type: Date,
    },

    // 允许登录/访问的 IP 范围规则文本（空 = 不限制）
    // 语法见 utils/ipRange：支持单地址、末段区间、CIDR、通配符、段区间，
    // 前缀 ! 表示排除（优先级高于允许项）；分隔符为 , ; 空格 换行
    allowedIPs: {
      type: String,
      default: '',
      maxlength: [8192, 'IP 范围规则文本过长'],
    },

    // Token 版本号：每次吊销全部会话时递增，所有 token 必须携带匹配的版本才有效
    // 用于 refresh token 重放检测后彻底使攻击者轮换出的新 token 失效
    tokenVersion: {
      type: Number,
      default: 0,
    },

    // MFA 两步验证（I-06，TOTP RFC 6238）
    // mfaSecret 与 password 同级敏感：select:false 默认不随查询返回，
    // 需要校验时显式 .select('+mfaSecret')
    mfaSecret: {
      type: String,
      select: false,
      default: '',
    },
    mfaEnabled: {
      type: Boolean,
      default: false,
    },
    // L5 重放防护：最近一次成功使用的 TOTP 时间窗序号，同窗/旧窗的码二次使用即拒绝
    mfaLastCounter: {
      type: Number,
      select: false,
      default: 0,
    },
    // 备用恢复码：仅存 SHA-256 摘要（明文只在生成时展示一次），使用即从数组移除。
    // 手机丢失/换机时凭恢复码仍可完成 MFA 登录，避免永久锁死
    mfaRecoveryCodes: {
      type: [String],
      select: false,
      default: [],
    },
    // MFA 验证码独立防爆破：与 failedLoginCount 分开的失败计数与锁定时间，
    // 覆盖登录 MFA 步骤、关闭 MFA、重新生成恢复码等所有验证码校验路径
    mfaFailCount: {
      type: Number,
      select: false,
      default: 0,
    },
    mfaLockUntil: {
      type: Date,
      select: false,
      default: null,
    },
    failedLoginCount: {
      type: Number,
      default: 0,
    },
    lockUntil: {
      type: Date,
      default: null,
    },

    // 审计字段
    createdBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
    },

    // 备注（管理员锁定/解锁等操作原因留存）
    remark: {
      type: String,
      default: '',
      maxlength: [500, '备注最多 500 个字符'],
    },
  },
  {
    timestamps: true, // 自动添加 createdAt 和 updatedAt
  }
);

// 索引优化
// P3-30：username 唯一索引显式带 collation（大小写不敏感），
// 名称固定为 username_ci 以便与旧的 username_1 区分、供启动期对账识别
userSchema.index(
  { username: 1 },
  { unique: true, background: true, collation: USERNAME_COLLATION, name: 'username_ci' }
);
userSchema.index({ status: 1 });
userSchema.index({ department: 1 });
userSchema.index({ roles: 1 });
userSchema.index({ createdAt: -1 });

/**
 * 对外响应的字段排除投影（G5：响应过度暴露）
 *
 * select:false 只覆盖了「凭证级」字段（password/mfaSecret/mfaRecoveryCodes/
 * mfaFailCount/mfaLockUntil/mfaLastCounter）；下列字段是「内部安全状态」，
 * schema 层必须默认可读（authenticate 每请求校验 tokenVersion/lockUntil，
 * 登录流程读写 failedLoginCount），因此不能设 select:false，
 * 只能在响应投影层显式排除。
 *
 * 排除理由：
 * - tokenVersion / lockUntil / failedLoginCount：会话吊销与锁定状态，
 *   暴露等于告知攻击者「该账号还剩几次尝试、是否已被锁定」
 * - passwordChangedAt / lastLoginIp：改密时间与上次登录 IP，属账户活动画像
 * - __v：Mongoose 内部版本号，无业务含义
 *
 * 保留 allowedIPs：用户管理界面编辑表单需回填该字段（UserView.handleEdit），
 * 且仅 user:read 权限者可见，属功能必需而非泄露。
 */
const USER_RESPONSE_EXCLUDE = [
  '-password',
  '-tokenVersion',
  '-lockUntil',
  '-failedLoginCount',
  '-passwordChangedAt',
  '-lastLoginIp',
  '-__v',
].join(' ');

userSchema.statics.RESPONSE_EXCLUDE = USER_RESPONSE_EXCLUDE;

// P3-30：用户名比较口径对外暴露，供控制器/脚本按同一 collation 查询
userSchema.statics.USERNAME_COLLATION = USERNAME_COLLATION;

/**
 * 按用户名查找（大小写不敏感，与唯一索引同一 collation）
 *
 * 必须走这个入口而非裸 findOne({ username })：后者用默认 collation 比较，
 * 既命中不了 username_ci 索引（退化为全表扫描），也会让 `Admin` 查不到
 * 已存在的 `admin`——判重放过、随后写入触发 E11000，表现为 500。
 * @param {string} username 用户名
 * @returns {import('mongoose').Query} 可继续链式 select/populate 的 Query
 */
userSchema.statics.findByUsername = function (username) {
  return this.findOne({ username }).collation(USERNAME_COLLATION);
};

// 密码加密中间件
userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();

  try {
    const salt = await bcrypt.genSalt(config.bcryptRounds);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

// ================= 权限查询与缓存（I-08 已拆出） =================
// 权限聚合查询、进程内 TTL 缓存与失效管理移至 services/userPermissionService，
// User 模型回归纯数据 schema（字段 + 密码哈希钩子 + 密码比对）；
// 下方保留薄代理转发以兼容既有调用方（将逐步迁移至直接引用 service）。
const userPermissionService = require('../services/userPermissionService');
userSchema.statics.getPermissions = function (userId) {
  return userPermissionService.getPermissions(userId);
};
userSchema.statics.invalidatePermissionCache = function (userId) {
  return userPermissionService.invalidatePermissionCache(userId);
};
userSchema.statics.hasPermission = function (userId, permissionCode) {
  return userPermissionService.hasPermission(userId, permissionCode);
};

// 实例方法：验证密码
// 纵深防御：bcrypt.compare 对非字符串入参抛 TypeError（异步拒绝），
// 会穿透控制器冒泡为 500。路由层校验器已挡住对象/数组类型，
// 但改密/登录/MFA 等多个调用点共用此方法，模型层再做一次类型收敛，
// 保证任何调用路径下「非字符串候选口令」都判为不匹配而非崩溃。
userSchema.methods.comparePassword = async function (candidatePassword) {
  if (typeof candidatePassword !== 'string' || typeof this.password !== 'string') {
    return false;
  }
  return await bcrypt.compare(candidatePassword, this.password);
};

// 实例方法：获取该用户完整权限列表（委托 service）
userSchema.methods.getPermissions = async function () {
  return userPermissionService.getPermissions(this._id);
};

module.exports = mongoose.model('User', userSchema);
