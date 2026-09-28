/**
 * 角色模型
 * RBAC 权限模型的核心实体
 */

const mongoose = require('mongoose');
const { RESOURCE_STATUSES } = require('../constants/permission');

const roleSchema = new mongoose.Schema(
  {
    // 角色基本信息
    name: {
      type: String,
      required: [true, '角色名称不能为空'],
      unique: true,
      trim: true,
      maxlength: [50, '角色名称最多 50 个字符'],
    },
    code: {
      type: String,
      required: [true, '角色编码不能为空'],
      unique: true,
      uppercase: true,
      trim: true,
      maxlength: [50, '角色编码最多 50 个字符'],
    },
    description: {
      type: String,
      trim: true,
      maxlength: [200, '描述最多 200 个字符'],
    },

    // 权限关联
    permissions: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Permission',
      },
    ],

    // 角色层级（用于数据权限）
    level: {
      type: Number,
      default: 1,
      min: 1,
      max: 10,
    },

    // 内置角色标识（内置角色不可删除）
    isBuiltIn: {
      type: Boolean,
      default: false,
    },

    // 状态
    status: {
      type: String,
      enum: RESOURCE_STATUSES,
      default: 'active',
    },
  },
  {
    timestamps: true,
  }
);

// 预保存钩子：确保内置角色标记
roleSchema.pre('save', function (next) {
  // 内置角色编码前缀
  const builtInCodes = ['SUPER_ADMIN', 'ADMIN', 'USER'];
  if (builtInCodes.includes(this.code)) {
    this.isBuiltIn = true;
  }
  next();
});

// 统一的内置角色删除保护：拦截所有删除操作
// 判据来自"这次删除会命中的那些角色"，因此两类入口要分两个上下文取过滤器：
//   - Query 类（deleteOne/deleteMany/findOneAndDelete）：this 是 Query，用 getFilter()
//   - bulkWrite：this 是 Model，没有 getFilter()，但 operations 是 pre 钩子的第二个实参
const assertNoBuiltInAmong = async function (Model, filter) {
  const roles = await Model.find(filter).select('isBuiltIn').lean();
  if (roles.some((r) => r.isBuiltIn)) {
    throw new Error('内置角色不可删除');
  }
};

const protectBuiltInRole = async function (next) {
  await assertNoBuiltInAmong(this.model, this.getFilter());
  next();
};

// bulkWrite 侧同一条判据：只挑出删除类操作的过滤器，没有删除类操作时原样放行
// （initData.js:721/742 的对账与授权批量写全是 updateOne，必须不受影响）
const deleteFiltersOf = (ops) =>
  (ops || [])
    .filter((o) => o && (o.deleteOne || o.deleteMany))
    .map((o) => (o.deleteOne ? o.deleteOne.filter : o.deleteMany.filter));

const protectBuiltInRoleBulk = async function (next, ops) {
  const filters = deleteFiltersOf(ops);
  if (filters.length === 0) return next();
  // 空过滤器＝"删全表"，必然覆盖内置角色；不交给 $or:[{}] 这种边界写法去猜，直接拒
  if (filters.some((f) => !f || Object.keys(f).length === 0)) {
    throw new Error('内置角色不可删除');
  }
  await assertNoBuiltInAmong(this, filters.length === 1 ? filters[0] : { $or: filters });
  next();
};

// 实测（src/tests/models/roleBuiltInDeleteGuard.test.js 逐条钉住）：
// mongoose 8 的 Model/Query/文档级删除写法都会经过上面三个钩子——包括 doc.deleteOne()
// （它内部仍构造 Query），而 Document#remove 在本版本已不存在。
// 仍不经过 ODM 护栏的只有两条：原生驱动 collection.deleteMany，以及 $graphql/聚合管道一类
// 不存在的写法——前者全仓仅 scripts/resign-audit-chain-v3.js 与 run-rollback-drill.js 使用，
// 且都不动 roles。所以"覆盖所有 ODM 删除入口"是本清单的准确边界，不是"覆盖所有删除可能"。
// （findOneAndRemove 是 findOneAndDelete 的废弃别名，同操作，只挂后者即可）
roleSchema.pre('findOneAndDelete', protectBuiltInRole);
roleSchema.pre('deleteOne', protectBuiltInRole);
roleSchema.pre('deleteMany', protectBuiltInRole);
roleSchema.pre('bulkWrite', protectBuiltInRoleBulk);

module.exports = mongoose.model('Role', roleSchema);
