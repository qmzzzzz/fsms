/**
 * 权限模型
 * 定义系统中所有的权限资源
 */

const mongoose = require('mongoose');
const {
  PERMISSION_TYPES,
  PERMISSION_METHODS,
  RESOURCE_STATUSES,
} = require('../constants/permission');

const permissionSchema = new mongoose.Schema(
  {
    // 权限基本信息
    name: {
      type: String,
      required: [true, '权限名称不能为空'],
      trim: true,
      maxlength: [50, '权限名称最多 50 个字符'],
    },
    code: {
      type: String,
      required: [true, '权限编码不能为空'],
      unique: true,
      lowercase: true,
      trim: true,
      match: [/^(\*|[a-z]+):(\*|[a-z_]+)$/, '权限编码格式应为 module:action，如 user:create'],
    },
    description: {
      type: String,
      trim: true,
    },

    // 权限类型
    type: {
      type: String,
      enum: PERMISSION_TYPES,
      default: 'api',
    },

    // 所属模块
    module: {
      type: String,
      required: [true, '所属模块不能为空'],
      trim: true,
    },

    // 父级权限（用于构建权限树）
    parent: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Permission',
      default: null,
    },

    // 关联的菜单/路由
    path: {
      type: String,
      trim: true,
    },
    method: {
      type: String,
      enum: PERMISSION_METHODS,
      default: '*',
    },

    // 状态
    status: {
      type: String,
      enum: RESOURCE_STATUSES,
      default: 'active',
    },

    // 排序
    sort: {
      type: Number,
      default: 0,
    },

    // 软删除标记：删除权限不再物理删除文档，避免「先删后复核」在恢复失败时
    // 丢权限并留下悬空的 Role.permissions。null = 正常；非 null = 已删除。
    // code 的唯一索引因此仍被占用（编码不复用），内置权限由启动播种自动恢复。
    deletedAt: {
      type: Date,
      default: null,
    },
  },
  {
    timestamps: true,
    // 与 Role 同口径：权限项的读-改-save 并发编辑以 VersionError 拒绝后提交者
    optimisticConcurrency: true,
  }
);

/**
 * 默认隐藏软删除文档；需要看到已删除记录时显式传 `includeDeleted: true`
 * （播种恢复与编码占用检查用）。覆盖 /^find/ 与 countDocuments：
 * 漏掉任何一条读路径，软删除的数据都会从"已删除"变成"时隐时现"。
 *
 * 过滤条件已显式写 deletedAt 时不再追加，避免覆盖调用方的查询意图。
 */
const excludeSoftDeleted = function () {
  if (this.getOptions().includeDeleted) return;
  const filter = this.getFilter();
  if (filter && filter.deletedAt !== undefined) return;
  this.where({ deletedAt: null });
};
permissionSchema.pre(/^find/, excludeSoftDeleted);
permissionSchema.pre('countDocuments', excludeSoftDeleted);

// 索引优化查询
permissionSchema.index({ module: 1, type: 1 });
permissionSchema.index({ parent: 1 });

module.exports = mongoose.model('Permission', permissionSchema);
