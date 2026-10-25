/**
 * 文件级乱序 sequencer（仅顺序无关门禁用）
 *
 * Jest 的 `--randomize` 只打乱**单个文件内**的用例顺序（CLI 帮助原文：
 * "Shuffle the order of the tests within a file."）。CI 曾据此声称覆盖
 * 「文件/用例的执行次序」，实际文件顺序始终是默认值——文件 A 污染文件 B
 * 这类耦合不会被任何 seed 覆盖。
 *
 * 这里在默认 sequencer 给出的顺序上再做一次 Fisher-Yates：
 *   · 未设置 JEST_FILE_SEED ⇒ 完全沿用 Jest 默认顺序（本地 npm test 行为不变）；
 *   · 设置 seed ⇒ 同一 seed 可复现，不同 seed 给出不同排列。
 * 种子由环境变量传入而不是读 CLI 参数：sequencer 拿不到 Jest 的 --seed。
 */

const Sequencer = require('@jest/test-sequencer').default;

const FILE_SEED_ENV = 'JEST_FILE_SEED';

function hashSeed(seed) {
  // FNV-1a：把任意字符串稳定映射成 32 位整数
  let hash = 2166136261 >>> 0;
  for (let i = 0; i < seed.length; i += 1) {
    hash ^= seed.charCodeAt(i);
    hash = Math.imul(hash, 16777619) >>> 0;
  }
  return hash || 1;
}

function mulberry32(seed) {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function seededShuffle(items, seed) {
  const random = mulberry32(hashSeed(String(seed)));
  const shuffled = items.slice();
  for (let i = shuffled.length - 1; i > 0; i -= 1) {
    const j = Math.floor(random() * (i + 1));
    [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
  }
  return shuffled;
}

class SeededFileSequencer extends Sequencer {
  sort(tests) {
    const ordered = super.sort(tests);
    const seed = process.env[FILE_SEED_ENV];
    return seed ? seededShuffle(ordered, seed) : ordered;
  }
}

module.exports = SeededFileSequencer;
module.exports.FILE_SEED_ENV = FILE_SEED_ENV;
module.exports.seededShuffle = seededShuffle;
