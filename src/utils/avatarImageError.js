class AvatarImageError extends Error {
  constructor(message, reason) {
    super(message);
    this.name = 'AvatarImageError';
    this.reason = reason || 'AVATAR_INVALID';
  }
}

module.exports = { AvatarImageError };
