'use strict';

/**
 * sharedCache 的 Redis Lua 脚本单例（从 index.js 抽出，为该文件的 max-lines 棘轮让路）。
 * 语义契约随消费方注释走：INCR_WITH_TTL_SCRIPT 见 index.js 的 incrWithTtl，
 * DECR_FLOOR_ZERO_SCRIPT 见 index.js 的 decrWithFloorZero（PTTL 先于 DECR 读）。
 */

/** 原子自增 + 首次/无 TTL 时补 PEXPIRE（计数器窗口语义） */
const INCR_WITH_TTL_SCRIPT = `
local v = redis.call('INCR', KEYS[1])
local ttl = tonumber(ARGV[1])
if ttl and ttl > 0 then
  if v == 1 or redis.call('PTTL', KEYS[1]) < 0 then
    redis.call('PEXPIRE', KEYS[1], ttl)
  end
end
return v
`;

/** 原子自减 + 下界 0；缺失/刚过期的残键删除归零，绝不复活成永久键 */
const DECR_FLOOR_ZERO_SCRIPT = `
local pttl = redis.call('PTTL', KEYS[1])
local v = redis.call('DECR', KEYS[1])
if v >= 0 then return v end
if pttl == -2 then
  redis.call('DEL', KEYS[1])
  return 0
end
redis.call('SET', KEYS[1], 0)
if pttl > 0 then redis.call('PEXPIRE', KEYS[1], pttl) end
return 0
`;

module.exports = { INCR_WITH_TTL_SCRIPT, DECR_FLOOR_ZERO_SCRIPT };
