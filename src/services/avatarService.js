// 头像服务：上传 / 读取 / 删除 / 级联清理。UserAvatar 单文档（_id = userId），
// data 为 encryptPii v2 密文（明文是图片 Base64）；头像记录与 User.avatar 指针必须同事务变更，否则图与指针会不一致。
const crypto = require('crypto');
const User = require('../models/User');
const UserAvatar = require('../models/UserAvatar');
const { encryptPii, decryptPii, VERSION_PREFIX_V2 } = require('../utils/piiCrypto');
const { parseAvatarImage, sniffMime } = require('../utils/avatarImage');
const { buildAvatarUrl } = require('../utils/avatarUrl');
const { withTransaction } = require('../utils/transaction');
const logger = require('../utils/logger');

const avatarOpts = (session) => (session ? { session } : {});

function deleteAvatar(userId, session) {
  return UserAvatar.deleteOne({ _id: userId }, avatarOpts(session));
}

function deleteAvatars(userIds, session) {
  const ids = (userIds || []).filter(Boolean);
  if (ids.length === 0) return Promise.resolve({ deletedCount: 0 });
  return UserAvatar.deleteMany({ _id: { $in: ids } }, avatarOpts(session));
}

async function uploadAvatar(userId, image) {
  const parsed = parseAvatarImage(image);
  const userExists = await User.exists({ _id: userId });
  if (!userExists) return { outcome: 'USER_NOT_FOUND' };

  const avatarUrl = buildAvatarUrl(userId, parsed.hash);
  const current = await UserAvatar.findById(userId).select('hash').lean();
  if (current && current.hash === parsed.hash) {
    // 幂等捷径（图未变）：只可能是指针漂了（历史部分失败残留）。指针修正必须**读后重验**并进事务：
    // hash/pointer 两次读都在事务外，读与写之间并发的另一条上传事务可能已提交了不同的图——把
    // 那个新指针覆盖回本图的 URL 会造成图/指针分叉（User.avatar 指向已不存在的 hash 版本）。
    // 事务内重验 hash 与 pointer 均仍成立才写：副本集上与并发事务真冲突时 Mongo 判写冲突整体失败，
    // 调用方重试即收敛到一致；standalone 降级顺序写时，重验把竞态窗口压到两次顺序读之间（与该拓扑其余多集合写的既有口径一致）。
    await withTransaction(async (session) => {
      const opts = avatarOpts(session);
      const freshDoc = await UserAvatar.findById(userId)
        .select('hash')
        .session(session || undefined)
        .lean();
      if (!freshDoc || freshDoc.hash !== parsed.hash) return; // 图已被并发上传改写：本轮放弃修指针，以那条事务的最终状态为准
      const freshUser = await User.findById(userId)
        .select('avatar')
        .session(session || undefined)
        .lean();
      if (!freshUser || freshUser.avatar === avatarUrl) return;
      await User.updateOne({ _id: userId }, { avatar: avatarUrl }, opts);
    });
    return {
      outcome: 'OK',
      avatar: avatarUrl,
      width: parsed.width,
      height: parsed.height,
      size: parsed.size,
    };
  }

  const encrypted = encryptPii(parsed.buffer.toString('base64'), {
    subjectId: String(userId),
    field: 'data',
  });

  await withTransaction(async (session) => {
    const opts = avatarOpts(session);
    await UserAvatar.findOneAndUpdate(
      { _id: userId },
      {
        $set: {
          mime: parsed.mime,
          data: encrypted,
          hash: parsed.hash,
          size: parsed.size,
          width: parsed.width,
          height: parsed.height,
        },
      },
      { upsert: true, new: true, ...opts }
    );
    await User.updateOne({ _id: userId }, { avatar: avatarUrl }, opts);
  });

  logger.info('用户更新了头像', { userId: String(userId), size: parsed.size });
  return {
    outcome: 'OK',
    avatar: avatarUrl,
    width: parsed.width,
    height: parsed.height,
    size: parsed.size,
  };
}

async function removeAvatar(userId) {
  await withTransaction(async (session) => {
    const opts = avatarOpts(session);
    await deleteAvatar(userId, session);
    await User.updateOne({ _id: userId }, { avatar: '' }, opts);
  });
  return { outcome: 'OK' };
}

async function getAvatar(userId, ifNoneMatch) {
  const meta = await UserAvatar.findById(userId).select('mime hash').lean();
  if (!meta) return { outcome: 'NOT_FOUND' };

  const etag = '"' + meta.hash + '"';
  const candidates = String(ifNoneMatch || '')
    .split(',')
    .map((value) => value.trim());
  if (candidates.includes(etag)) return { outcome: 'NOT_MODIFIED', etag };

  const doc = await UserAvatar.findById(userId).select('+data').lean();
  if (!doc) return { outcome: 'NOT_FOUND' };
  if (typeof doc.data !== 'string' || !doc.data.startsWith(VERSION_PREFIX_V2)) {
    throw new Error('头像密文形态非法（缺少 enc.v2 前缀）'); // 新集合没有"存量明文"迁移期：非 v2 一律按损坏处理，绝不把明文当图片返回
  }
  const plain = decryptPii(doc.data, { subjectId: String(userId), field: 'data' });
  const buffer = Buffer.from(String(plain), 'base64');
  if (sniffMime(buffer) !== meta.mime) {
    throw new Error('头像内容与记录的 MIME 不一致');
  }
  const actualHash = crypto.createHash('sha256').update(buffer).digest('hex');
  if (actualHash !== meta.hash) {
    throw new Error('头像内容与记录的 hash 不一致（可能被篡改）');
  }
  return { outcome: 'OK', buffer, mime: meta.mime, etag, size: buffer.length };
}

async function loadScopeTarget(userId) {
  return User.findById(userId).select('createdBy department').lean();
}

module.exports = {
  uploadAvatar, // 上传/替换头像。幂等：同字节重复上传只修正指针，不重复加密写库。
  removeAvatar, // 删除头像（幂等：本来没有头像也返回 OK）
  getAvatar, // 读取头像。304 分支先只查 hash（data 为 select:false），不把密文拉进内存。
  deleteAvatar, // 删除单个用户的头像记录（调用方负责提供事务 session）
  deleteAvatars, // 批量删除头像记录（空数组不发写请求）
  loadScopeTarget, // 数据范围判定的目标用户投影：控制器不得直连 models（分层纪律 D-1a）
};
