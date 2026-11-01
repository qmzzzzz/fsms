// 用户头像（一人一图）：_id 与 userId 同值，data 为 PII 密文并 select:false。
// 不落磁盘：容器只读根文件系统，唯一可写卷是 /app/logs，且备份只 mongodump。
const mongoose = require('mongoose');

const userAvatarSchema = new mongoose.Schema(
  {
    _id: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    mime: { type: String, enum: ['image/jpeg', 'image/png'], required: true },
    data: { type: String, required: true, select: false }, // enc.v2 密文（明文是图片 Base64）
    hash: { type: String, required: true }, // sha256(原始二进制)：ETag 与 URL 版本号
    size: { type: Number, required: true }, // 原始二进制字节数
    width: { type: Number, required: true },
    height: { type: Number, required: true },
  },
  { timestamps: true, collection: 'useravatars' }
);

module.exports = mongoose.model('UserAvatar', userAvatarSchema);
