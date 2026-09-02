/**
 * 权限模型
 * 定义系统中所有的权限资源
 */

const mongoose = require('mongoose');

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
      enum: ['menu', 'button', 'api', 'data'],
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
      enum: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', '*'],
      default: '*',
    },

    // 状态
    status: {
      type: String,
      enum: ['active', 'inactive'],
      default: 'active',
    },

    // 排序
    sort: {
      type: Number,
      default: 0,
    },
  },
  {
    timestamps: true,
  }
);

// 索引优化查询
permissionSchema.index({ module: 1, type: 1 });
permissionSchema.index({ parent: 1 });

module.exports = mongoose.model('Permission', permissionSchema);
