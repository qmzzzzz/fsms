/**
 * 角色模型
 * RBAC 权限模型的核心实体
 */

const mongoose = require('mongoose');

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
      enum: ['active', 'inactive'],
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
const protectBuiltInRole = async function (next) {
  const filter = this.getFilter();
  const roles = await this.model.find(filter).select('isBuiltIn').lean();
  if (roles.some((r) => r.isBuiltIn)) {
    throw new Error('内置角色不可删除');
  }
  next();
};

// 覆盖所有删除入口，防止绕过
// （findOneAndRemove 是 findOneAndDelete 的废弃别名，二者同操作，只挂载后者即可）
roleSchema.pre('findOneAndDelete', protectBuiltInRole);
roleSchema.pre('deleteOne', protectBuiltInRole);
roleSchema.pre('deleteMany', protectBuiltInRole);

module.exports = mongoose.model('Role', roleSchema);
