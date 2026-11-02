'use strict';

/**
 * 画像的结论层：分类清单 → 评分 / 判定 / 风险等级 / 处置建议。
 *
 * 评分只回答"这组行为有多像攻击"，不替代人工判断；建议按判定分档，
 * 未封禁的攻击源才提"封禁"，已有处置状态的不重复建议。
 */

const {
  ATTACK_CATEGORIES: C,
  VERDICTS,
  SUGGESTIONS,
  CATEGORY_BASE_SCORE,
} = require('../constants/attackProfile');

const scoreOf = (categories, successAfterFailure, criticalRows) => {
  let score = 0;
  for (const category of categories) {
    score += CATEGORY_BASE_SCORE[category.code] || 0;
    score += Math.min(15, Math.floor(category.count / 5));
  }
  if (successAfterFailure) score += 20;
  if (criticalRows > 0) score += 5;
  return Math.min(100, score);
};

const verdictOf = ({ total, score, categories, successAfterFailure }) => {
  if (total === 0) return VERDICTS.NO_DATA;
  const hasCredentialAttack = categories.some(
    (c) => c.code === C.BRUTE_FORCE || c.code === C.CREDENTIAL_STUFFING
  );
  if (successAfterFailure && hasCredentialAttack) return VERDICTS.COMPROMISED;
  if (
    score >= 50 ||
    categories.some((c) => c.code === C.HONEYPOT || c.code === C.CREDENTIAL_STUFFING)
  ) {
    return VERDICTS.ATTACK;
  }
  if (score >= 25) return VERDICTS.SUSPICIOUS;
  if (score > 0) return VERDICTS.LOW;
  return VERDICTS.CLEAN;
};

const riskLevelOf = (verdict) =>
  ({
    [VERDICTS.COMPROMISED]: 'critical',
    [VERDICTS.ATTACK]: 'high',
    [VERDICTS.SUSPICIOUS]: 'medium',
    [VERDICTS.LOW]: 'low',
  })[verdict] || 'none';

const hasCategory = (categories, code) => categories.some((c) => c.code === code);

const attackSuggestionsOf = (verdict, categories) => {
  const codes = [SUGGESTIONS.MONITOR];
  const credential =
    hasCategory(categories, C.BRUTE_FORCE) || hasCategory(categories, C.CREDENTIAL_STUFFING);
  if (credential) codes.push(SUGGESTIONS.ENABLE_MFA);
  if (hasCategory(categories, C.DATA_EXFILTRATION)) codes.push(SUGGESTIONS.REVIEW_EXPORTS);
  if (hasCategory(categories, C.UNAUTHORIZED_ACCESS)) codes.push(SUGGESTIONS.REVIEW_ACCESS_CONTROL);
  if (hasCategory(categories, C.RATE_LIMIT_ABUSE)) codes.push(SUGGESTIONS.REVIEW_RATE_LIMITS);
  if (hasCategory(categories, C.HONEYPOT)) codes.push(SUGGESTIONS.REVIEW_HONEYPOT);
  if (hasCategory(categories, C.CREDENTIAL_STUFFING) || verdict === VERDICTS.COMPROMISED) {
    codes.push(SUGGESTIONS.REVIEW_ACCOUNTS);
  }
  return codes;
};

const baseSuggestionsOf = (verdict, categories) => {
  if (verdict === VERDICTS.COMPROMISED) {
    return [SUGGESTIONS.RESET_CREDENTIALS, SUGGESTIONS.REVIEW_ACCOUNTS, SUGGESTIONS.ENABLE_MFA];
  }
  if (verdict === VERDICTS.ATTACK || verdict === VERDICTS.SUSPICIOUS) {
    return attackSuggestionsOf(verdict, categories);
  }
  if (verdict === VERDICTS.LOW) return [SUGGESTIONS.MONITOR];
  if (verdict === VERDICTS.CLEAN) return [SUGGESTIONS.NO_ACTION];
  return [];
};

const suggestionsOf = ({ verdict, categories, containment, scopeLimited }) => {
  const codes = new Set(baseSuggestionsOf(verdict, categories));
  const attacking = verdict === VERDICTS.ATTACK || verdict === VERDICTS.COMPROMISED;
  if (attacking && !containment?.blacklisted) codes.add(SUGGESTIONS.BLOCK_IP);
  if (scopeLimited) codes.add(SUGGESTIONS.VERIFY_SCOPE);
  return [...codes];
};

module.exports = { scoreOf, verdictOf, riskLevelOf, suggestionsOf };
