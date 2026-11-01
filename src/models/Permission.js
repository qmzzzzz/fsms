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
 * 默认隐藏软删除文档：显式 includeDeleted，或过滤条件/更新文档本身写了 deletedAt 时放行；
 * 判据只在 softDeleteExempt 一处（读路径与写钩子共用，/^find/ 已含 findOneAndUpdate/
 * findOneAndReplace）；estimatedDocumentCount 无 filter 形参、钩子改不到，不注册。详见测试头。
 */
const touchesDeletedAt = (update) => {
  if (!update || typeof update !== 'object') return false;
  return (
    (update.$set && update.$set.deletedAt !== undefined) ||
    (update.$unset && update.$unset.deletedAt !== undefined) ||
    update.deletedAt !== undefined
  );
};

/** 本次查询是否豁免软删除过滤（读路径与写路径共用这一个判据） */
const softDeleteExempt = (query) => {
  if (query.getOptions().includeDeleted) return true;
  const filter = query.getFilter();
  if (filter && filter.deletedAt !== undefined) return true;
  return touchesDeletedAt(query.getUpdate());
};

const excludeSoftDeleted = function () {
  if (softDeleteExempt(this)) return;
  this.where({ deletedAt: null });
};

// 写钩子只登记不被 /^find/ 覆盖的三个 op；findOneAndUpdate/findOneAndReplace 走 /^find/
for (const op of ['updateOne', 'updateMany', 'replaceOne']) {
  permissionSchema.pre(op, excludeSoftDeleted);
}
permissionSchema.pre(/^find/, excludeSoftDeleted);
permissionSchema.pre('countDocuments', excludeSoftDeleted);
permissionSchema.pre('distinct', excludeSoftDeleted);
permissionSchema.pre('aggregate', function () {
  if (this.options && this.options.includeDeleted) return;
  const first = this.pipeline()[0];
  if (first && first.$match && first.$match.deletedAt !== undefined) return;
  this.pipeline().unshift({ $match: { deletedAt: null } });
});

// 索引优化查询
permissionSchema.index({ module: 1, type: 1 });
permissionSchema.index({ parent: 1 });

module.exports = mongoose.model('Permission', permissionSchema);
