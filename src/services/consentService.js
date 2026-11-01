/**
 * 隐私同意服务（审计一-7）：把「同意」从界面勾选变成可核对的记录。三个出口：scopesForPrivacyNotice()（范围清单取自 constants/dataClassification 的 CONSENT_SCOPES，不手抄第二份）、recordConsent()（幂等落库）、consentStatus()（现行版本是否已同意）。适用范围刻意只覆盖自助注册：管理员建号属组织法定基础，不以同意为前提（见 docs/data-classification.md）。
 */

const ConsentRecord = require('../models/ConsentRecord');
const { CONSENT_SCOPES } = require('../constants/dataClassification');
const logger = require('../utils/logger');

/** 现行隐私告知版本：改版必须改这里（升版后旧同意不会被当成对新版的同意） */
const PRIVACY_NOTICE_VERSION = '2026-11-01';

/** 本次告知覆盖的范围：只取 basis='notice' 的（组织法定基础项不写同意记录） */
const scopesForPrivacyNotice = () =>
  Object.entries(CONSENT_SCOPES)
    .filter(([, s]) => s.basis === 'notice')
    .map(([key]) => key);

/**
 * 落一条同意记录（幂等）。
 * @returns {Promise<{recorded:boolean, version:string, scopes:string[]}>}
 *   recorded=false 表示该账号在本版已同意过（重复提交），不产生第二条记录。
 */
async function recordConsent({ userId, username, req = null, source = 'self-register' }) {
  const version = PRIVACY_NOTICE_VERSION;
  const scopes = scopesForPrivacyNotice();
  const existing = await ConsentRecord.findOne({ userId, policy: 'privacy', version })
    .select('_id')
    .lean();
  if (existing) return { recorded: false, version, scopes };

  await ConsentRecord.create({
    userId,
    username,
    policy: 'privacy',
    version,
    scopes,
    acceptedAt: new Date(),
    ip: (req && req.ip) || '',
    userAgent: (req && req.get && req.get('user-agent')) || '',
    source,
  });
  logger.info('隐私同意已记录', { userId: String(userId), version });
  return { recorded: true, version, scopes };
}

/** 某账号是否已同意现行版本（fail-closed：查不到即视为未同意） */
async function consentStatus(userId) {
  const version = PRIVACY_NOTICE_VERSION;
  const doc = await ConsentRecord.findOne({ userId, policy: 'privacy', version })
    .select('acceptedAt version scopes')
    .lean();
  return {
    version,
    accepted: Boolean(doc),
    acceptedAt: doc ? doc.acceptedAt : null,
    scopes: doc ? doc.scopes : [],
    requiredScopes: scopesForPrivacyNotice(),
  };
}

module.exports = {
  PRIVACY_NOTICE_VERSION,
  scopesForPrivacyNotice,
  recordConsent,
  consentStatus,
};
