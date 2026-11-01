// 头像 URL 唯一定义：/api/avatars/<目标用户 id>?v=<hash 前 16 位>。
// 绑定对象是目标用户而不是发起者（管理员改他人资料）；版本号承担缓存分桶。
const AVATAR_PATH_PREFIX = '/api/avatars/';

// 24 位 ObjectId + 16 位 hash 前缀，其余形态一律不认
const AVATAR_URL_RE = /^\/api\/avatars\/([0-9a-f]{24})\?v=([0-9a-f]{16})$/i;

const buildAvatarUrl = (userId, hash) =>
  `${AVATAR_PATH_PREFIX}${String(userId)}?v=${String(hash).slice(0, 16).toLowerCase()}`;

// 解析服务端生成的 URL；外部 URL / data URI / 相对路径一律 null
const parseAvatarUrl = (url) => {
  if (typeof url !== 'string') return null;
  const matched = AVATAR_URL_RE.exec(url);
  if (!matched) return null;
  return { userId: matched[1].toLowerCase(), version: matched[2].toLowerCase() };
};

// 非空头像只允许服务端为该用户生成的形态（profile 与管理员更新共用这道收口）
const isAvatarUrlForUser = (url, userId) => {
  const parsed = parseAvatarUrl(url);
  return Boolean(parsed && parsed.userId === String(userId).toLowerCase());
};

module.exports = { AVATAR_PATH_PREFIX, buildAvatarUrl, parseAvatarUrl, isAvatarUrlForUser };
