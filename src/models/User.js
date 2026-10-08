/**
 * 用户模型
 * 系统用户的基础数据结构
 */

const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const config = require('../config');
// 账户状态取值全集只有一份（utils/constants.js 的 USER_STATUS）。
// 此前这里是私抄 `['active','inactive','locked']`，而 userRoutes 的查询校验已经用的是
// Object.values(USER_STATUS) ⇒ 给 USER_STATUS 加一档时：查询侧放行、
// userService 的过滤白名单不认识它而**静默丢掉整个 status 条件**（返回全量而非 400），
// 保存侧则被本 enum 拒。三处同源后这类分叉不再可能。
const { USER_STATUS } = require('../utils/constants');
// P1-②：PII at-rest 加密（读侧解密 / 写侧加密 / 检索键），判据收口在 utils/piiCrypto.js
const { encryptPii, decryptPii, piiSearchKey } = require('../utils/piiCrypto');

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
      // 字符集约束必须落在模型层，与 userRoutes / authRoutes 的 `^[a-zA-Z0-9_]+$` 同源。
      // 原先模型只有长度约束：任何**非路由**写入（initData 走 raw collection、
      // 数据修复脚本、将来的批量导入）都能造出与既有账户视觉上等同的用户名。
      // USERNAME_COLLATION 只折大小写与重音，**不折西里尔 'а' 与拉丁 'a'**，
      // 于是 `аdmin` 能合法落库并与 `admin` 并存——而审计日志、告警通知、审批记录
      // 都以用户名呈现操作者（本文件上方对仿冒面的描述正是这件事）。
      match: [/^[a-zA-Z0-9_]+$/, '用户名只能包含字母、数字和下划线'],
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
      // 评价报告低危项：maxlength 是**字符**数，中文口令单字符 3 字节，
      // 72 个汉字可达 216 字节——补字节级校验器把边界对齐 bcrypt 实际截断点。
      maxlength: [72, '密码最多 72 个字符'],
      validate: {
        validator: (v) => Buffer.byteLength(v, 'utf8') <= 72,
        message: '密码过长（超过 bcrypt 72 字节硬边界，超出部分会被静默丢弃）',
      },
      select: false, // 默认不返回密码字段
    },

    // 个人信息（P1-②，2026-09-30 决策修订：仅 phone at-rest 加密）
    // realName 暂保持明文：姓名**片段模糊检索**是用户列表的日常能力，正则对
    // 密文不成立，加密它等于砍掉该能力；转入加密需先给姓名检索另立方案。
    // phone 加密判据收口在 utils/piiCrypto.js：读侧 getter 解密（存量明文
    // 透传），写侧 pre('validate') 钩子加密；长度/格式校验随钩子前移到明文
    // 阶段（validate 阶段看到的已是密文，schema 级校验会把每行都判非法）。
    realName: {
      type: String,
      trim: true,
      maxlength: [50, '姓名最多 50 个字符'],
    },
    phone: {
      type: String,
      trim: true,
      // v2 密文带 AAD 行绑定（pii:v2:<_id>:phone，见 utils/piiCrypto.js）：读侧必须把
      // 文档身份喂回解密——跨行复制的密文在这里以 GCM 认证失败暴露。Mongoose 8 以
      // 文档为 this 调用字段 getter（schematype.js applyGetters），_id 在文档创建期
      // 即由 ObjectId default 生成，save 前后两条读路径都拿得到。
      get: function (value) {
        const doc = this;
        const subjectId = doc && doc._id !== undefined && doc._id !== null ? String(doc._id) : null;
        return decryptPii(value, subjectId ? { subjectId, field: 'phone' } : null);
      },
    },
    // phone 的精确检索键（HMAC，select:false）：相等性只在这个键控字段上成立，
    // 密文列本身随机 IV、不可链接。空值落的是**空串键**（default:''，钩子里
    // 明文为空时也写 ''）——所有无手机号的行共享它，所以这一维只在非空明文上成立；
    // 判据与调用侧前提见 utils/piiCrypto.js 的 piiSearchKey 注释。
    phoneKey: {
      type: String,
      select: false,
      default: '',
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
      enum: Object.values(USER_STATUS),
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

    /**
     * 口令复用历史：最近 N 条**已退役**口令的 HMAC 摘要（最新在前）。
     *
     * select:false —— 与 password 同级的凭证材料：它是对口令明文的单向摘要，
     * 读到它等于拿到"判定某个口令是否曾被使用"的预言机，对外一律不返回。
     * 校验时需显式 .select('+password') .select('+passwordHistory')。
     *
     * 深度上限由 utils/passwordHistory 的 HISTORY_DEPTH 负责（写入侧截断 +
     * 读取侧再截一次）。schema 层**刻意不加长度 validator**：上限被调小后，
     * validator 会让库里既有的超长文档在**任何一次 save** 时校验失败——
     * 把一条运维配置变成全站不可写。脏数据由读取侧规整，不在 schema 拦。
     */
    passwordHistory: {
      type: [String],
      select: false,
      default: [],
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

// P1-②：PII 字段的明文只在 getter 里（存储侧是密文）。Mongoose 的 toObject/
// toJSON **默认不套字段 getter**——不开这两项，res.json / toObject 走到的地方
// （用户管理、资料、populate 出来的"经办人姓名"……）全都输出密文。
// 实测（zzz 探针）：doc.realName 是明文、toJSON 是密文——这是接线不变量，
// 迁移到哪条新序列化路径都要带着这两行走。
userSchema.set('toJSON', { getters: true });
userSchema.set('toObject', { getters: true });

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
// P1-② 检索键索引：按手机号找回用户走 phoneKey（realName 暂不加密、保持
// 正则模糊检索，无检索键）。非唯一：手机号本就没有唯一约束（保持现状）。
// 接线状态（2026-10-01 逐行复核，grep 实测）：**已供未接**——非测试代码里 phoneKey
// 只出现在 schema 声明、本索引、-phoneKey 响应投影、pre('validate') 写入与迁移脚本
// 的重算五处，没有任何 `find({ phoneKey })`；用户列表的搜索列表面向
// username/email/realName（userService.buildListQuery）。索引在 ≠ 能力在：
// 要按手机号联系人，得先加查询入口（并满足 piiCrypto.piiSearchKey 的非空前提）。
userSchema.index({ phoneKey: 1 }, { background: true, name: 'phoneKey_1' });

/**
 * 对外响应的字段排除投影（G5：响应过度暴露）
 *
 * select:false 只覆盖了「凭证级」字段（password/passwordHistory/mfaSecret/
 * mfaRecoveryCodes/mfaFailCount/mfaLockUntil/mfaLastCounter）；下列字段是
 * 「内部安全状态」，
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
 *
 * 清单是一张字段表而不是拼好的字符串：RESPONSE_EXCLUDE_PHONE_VISIBLE 要从同一张表
 * 派生（下面解释为什么要这个变体）。写成字符串手术（`base.replace(' -phone','')`）
 * 的话，将来清单里多一个空格、多个 `-phone` 别名，都会静默失效——而"静默失效"
 * 在这一项上等于把明文手机号放回去。
 */
const USER_RESPONSE_EXCLUDE_FIELDS = [
  '-password',
  // 凭证级材料的第二道：schema 已是 select:false，这里再排一次与 password 同规格。
  // 只排不减：少排一次的后果是历史摘要进到某个响应体里，而它是对明文的单向预言机。
  '-passwordHistory',
  '-tokenVersion',
  '-lockUntil',
  '-failedLoginCount',
  '-passwordChangedAt',
  '-lastLoginIp',
  // PII（2026-10-02）：phone 落库是密文，但本文件 phone 声明处的 getter **透明解密**，
  // 于是不写投影的用户读路径会把完整手机号放进响应体——持 user:read 的部门管理员
  // 一次 GET 就拿到整个部门的手机号，无二次验证、不写 view_sensitive_data 审计，
  // 而仓里专门为此建的合规通道（POST /api/security/view-sensitive：reauthLimiter +
  // requireReAuthentication + 严格更高级别 + 审计写失败即不发明文）被这个默认值架空。
  // 与 -phoneKey 同规格：排在这里是"默认不许外泄"，不是"某处正在用"。
  '-phone',
  // P1-② 检索键：相等性预言机（拿一个手机号问"系统里有没有人用"），
  // 对外响应与内部状态同规格排除。需要读它的一侧必须显式 select('+phoneKey')，
  // 而那样的读侧目前不存在（接线状态见本文件 phoneKey 索引处的注释）——
  // 排在这里是"默认不许外泄"，不是"某处正在用"。
  '-phoneKey',
  '-__v',
];

const USER_RESPONSE_EXCLUDE = USER_RESPONSE_EXCLUDE_FIELDS.join(' ');

/**
 * 唯一允许把**明文** phone 读进进程的对外投影：同一张字段表、只少 `-phone` 一项。
 *
 * 存在的理由是展示需求而非读取需求：用户管理表格要显示脱敏号码（`138****5678`），
 * 而脱敏必须在拿到明文的那一侧算——密文列随机 IV、逐行不同，对密文打码什么也读不出。
 * 代价是这条投影本身是个危险物：取到明文的每一行都必须立刻过
 * `services/userService.js` 的 `toMaskedAdminUser`，否则等于把明文重新装回响应。
 * 所以变体与主清单同源派生，并由 `tests/security/userPhoneMaskedEgress.test.js`
 * 的源码闸盯着"新增了用户读路径却没过脱敏"这一种漂移。
 */
const USER_RESPONSE_EXCLUDE_PHONE_VISIBLE = USER_RESPONSE_EXCLUDE_FIELDS.filter(
  (field) => field !== '-phone'
).join(' ');

userSchema.statics.RESPONSE_EXCLUDE = USER_RESPONSE_EXCLUDE;
userSchema.statics.RESPONSE_EXCLUDE_PHONE_VISIBLE = USER_RESPONSE_EXCLUDE_PHONE_VISIBLE;

// P3-30：用户名比较口径对外暴露，供控制器/脚本按同一 collation 查询
userSchema.statics.USERNAME_COLLATION = USERNAME_COLLATION;

/**
 * 读-改-save 的载入端必须带的排除投影（对象形态）。
 *
 * 它挡的是 HIGH 级"改头像顺手毁凭证"：`User.findById(id)` 不写任何投影时，mongod
 * 按 `_optionsForExec()`（schema 的 select:false 已并入其中）不返回下面这些路径，
 * 但文档构造拿到的却是 `_fieldsForExec()`——只含**调用方自己写的**投影，无用户投影时
 * 为 null。于是 Mongoose 8.24.1 的 applyDefaults 看不见那份排除，照样给未返回的路径
 * 填上 schema 默认值，而填出来的键会进 `save()` 的 `$set`（实测脏路径：
 * mfaSecret/mfaRecoveryCodes/mfaLastCounter/mfaFailCount/phoneKey/passwordHistory）。
 * 后果：一次 PUT /api/auth/profile 就关掉用户的 MFA（口令因子被写成 ""）、抹掉
 * TOTP 重放防护与恢复码、把爆破计数清零、让手机号精确检索键失联、清空口令历史。
 *
 * 三个已排除的替代修法，写下来是为了别让后人再走一遍：
 *  - 字符串形态 `.select('-mfaSecret')`：`_fields` 里保留 `-` 前缀，applyDefaults 的
 *    `curPath in fields` 判不出 ⇒ 与不写投影同样漏（实测仍清空）。
 *  - `findByIdAndUpdate`：绕开本文件 pre('validate')/pre('save')，而 phoneKey 同步与
 *    口令 bcrypt 正挂在那两个钩子上。
 *  - 载入时 `select('+全部凭证')` 再 save：把口令摘要与 MFA 密钥读进内存，
 *    与本文件"凭证级材料默认不出进程"的口径相反。
 *
 * 派生自 schema 而不是手写清单：日后新增 select:false 路径自动纳入。
 * 排除的是**读**，不是写：钩子或业务显式赋值这些路径时（改手机号 ⇒ pre('validate')
 * 写 phoneKey；解绑 ⇒ 写 mfaSecret）照常落库，由
 * tests/services/userSaveCredentialWipe.test.js 盯住这一条。
 *
 * @returns {Record<string, 0>} 可直接交给 Query#select 的对象形态排除投影
 */
userSchema.statics.unselectedCredentialProjection = function unselectedCredentialProjection() {
  const projection = {};
  for (const [path, schemaPath] of Object.entries(userSchema.paths)) {
    if (schemaPath && schemaPath.options && schemaPath.options.select === false) {
      projection[path] = 0;
    }
  }
  return projection;
};

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

// P1-②：PII 字段写入侧收口（加密 + 检索键同步 + 明文期格式校验）
// 只在字段被修改时动作：未修改的行重复 save 不重加密——随机 IV 下重加密会
// 无谓改写密文，让 updatedAt 漂移、审计上出现"没有变更的变更"。
// 手机号格式校验在这里（加密之前）而不是 schema validator：validate 阶段
// 看到的已是密文，正则会把每一行都判非法；错误文案与明文时代逐字一致。
const PII_ENCRYPTED_FIELDS = [
  {
    plain: 'phone',
    key: 'phoneKey',
    max: [20, '手机号最多 20 个字符'],
  },
];
userSchema.pre('validate', function (next) {
  try {
    for (const { plain, key, max } of PII_ENCRYPTED_FIELDS) {
      if (!this.isModified(plain)) continue;
      // this[plain] 经 getter：赋值期的明文与存量密文都解回明文（透传口径）
      const value = this[plain];
      if (value) {
        // 长度与格式判据都在加密前（明文阶段），文案与明文时代逐字一致
        if (value.length > max[0]) {
          this.invalidate(plain, max[1], value);
          continue; // 非法值不加密不落键：失败路径不留任何写入（与复用历史同纪律）
        }
        if (plain === 'phone' && !/^1[3-9]\d{9}$/.test(value)) {
          this.invalidate(plain, '请输入有效的手机号', value);
          continue;
        }
      }
      this[key] = value ? piiSearchKey(value) : '';
      // v2：加密必须绑定行身份（AAD = pii:v2:<_id>:<field>）。_id 缺失时拒绝加密
      // 而不是落到无绑定密文上——无绑定密文与 v1 同样可跨行搬运，等于白改。
      // （_id 由 ObjectId default 在文档创建期生成，走到这里必已存在；此守卫是给
      // 「未来某人改掉 _id 生成时机」的 fail-closed 兜底。）
      if (!this._id) {
        throw new Error(`PII v2 加密需要文档 _id 作 AAD 绑定（字段 ${plain}，_id 缺失即拒绝写入）`);
      }
      this[plain] = value
        ? encryptPii(value, { subjectId: String(this._id), field: plain })
        : value;
    }
    next();
  } catch (error) {
    next(error);
  }
});

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
