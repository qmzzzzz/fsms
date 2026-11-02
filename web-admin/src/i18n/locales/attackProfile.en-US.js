/**
 * IP behavior profile messages (English) — lazy-loaded with the profile page.
 *
 * Split out of en-US.js so the entry bundle does not carry this namespace.
 * Codes mirror src/constants/attackProfile.js; keep zh and en in sync.
 */
export default {
  pageTitle: 'IP Behavior Profile',
  pageSubtitle:
    'Enter one IP address. The system summarizes what it did in the selected period and tells you whether it attacked the system and what to do.',
  ipLabel: 'IP address',
  ipPlaceholder: 'e.g. 203.0.113.10',
  windowLabel: 'Look back',
  window24h: '24 hours',
  window7d: '7 days',
  window30d: '30 days',
  analyze: 'Analyze',
  analyzing: 'Analyzing…',
  reset: 'Clear',
  noIp: 'Please enter an IP address first',
  resultCard: 'Analysis result',
  loadError: 'Analysis failed. Please retry.',
  staleData: 'Refresh failed; the previous analysis is shown below',
  retry: 'Retry',
  truncated:
    'Too many records: only the latest {count} were analyzed. Narrow the time range for a fuller result.',
  scopeLimited:
    'Your data scope is limited, so the result may be incomplete. Ask a super administrator to verify if you need the full view.',
  privateIp:
    'This is a private or loopback address, usually from an internal device. Please check whether the IP is correct.',
  verdictCard: 'Bottom line',
  scoreLabel: 'Risk score',
  scoreUnit: 'pts',
  riskLabel: 'Risk level',
  windowRange: 'Period: {since} to {until}',
  windowHours: '{hours} hours',
  perHour: 'req/hour',
  perDay: 'req/day',
  recordCount: '{count} audit records',
  analyzedNote: '{count} analyzed',
  statsTitle: 'Key numbers',
  statTotal: 'Audit records',
  statBlocked: 'Blocked requests',
  statFailedLogins: 'Failed logins',
  statSuccessLogins: 'Successful logins',
  statAccounts: 'Accounts tried',
  statUserAgents: 'Distinct user agents',
  statPeakRequests: 'Peak requests',
  statHighRiskRows: 'High-risk records',
  statSuspiciousSuccess: 'Suspected breach at',
  statFirstSeen: 'First seen',
  statLastSeen: 'Last seen',
  suggestionsTitle: 'What to do',
  categoriesTitle: 'Behavior categories',
  categoriesEmpty:
    'No specific attack type was identified; access patterns and raw evidence are still listed below.',
  categoryCount: '{count} events',
  categoryBlocked: '{count} blocked',
  categorySuccess: '{count} passed',
  uncategorizedTitle: 'Uncategorized records ({count})',
  uncategorizedHint:
    'These records were not assigned a specific attack type (for example, blacklist blocks or ordinary business actions), but they are still part of this profile. Open each one for full forensics.',
  evidenceTitle: 'Evidence (excerpt)',
  evidenceHint:
    'Only the earliest and latest entries are shown. Select "View full forensics" to open the original record.',
  evidenceEmpty: 'No evidence to show',
  evidenceTime: 'Time',
  evidenceAction: 'Action',
  evidenceMethod: 'Method',
  evidencePath: 'Path',
  evidenceStatus: 'Status',
  evidenceAccount: 'Account',
  evidenceReason: 'Note',
  evidenceTrace: 'Record ID',
  viewForensics: 'View full forensics',
  timelineTitle: 'Activity timeline',
  timelineEmpty: 'No activity in the selected period',
  timelineTime: 'Time',
  timelineTotal: 'Requests',
  timelineBlocked: 'Blocked',
  timelineCategories: 'Categories',
  topTitle: 'Top patterns',
  topPaths: 'Most visited paths',
  topActions: 'Most frequent actions',
  topAccounts: 'Most targeted accounts',
  topUserAgents: 'Most common user agents',
  topEmpty: 'No records',
  countLabel: 'Count',
  containmentTitle: 'Current containment',
  containmentBlacklisted: 'This IP is blacklisted',
  containmentWhitelisted: 'This IP is whitelisted',
  containmentNone: 'This IP is not on any list',
  containmentDegraded: 'List status is temporarily unavailable; rely on the profile verdict.',
  containmentType: 'List',
  containmentIp: 'Address',
  containmentReason: 'Reason',
  containmentExpires: 'Expires',
  containmentTypeBlack: 'Blacklist',
  containmentTypeWhite: 'Whitelist',
  viewAuditLogs: 'View all audit records for this IP',
  reportAction: 'Generate report',
  reportTitle: 'IP Behavior Traceability Report',
  reportHint:
    'The report is generated in a readable format. Copy it into a ticket or download it as Markdown for archival.',
  reportCopy: 'Copy report',
  reportCopied: 'Report copied to clipboard',
  reportCopyFailed: 'Copy failed; please select the text and copy manually',
  reportDownload: 'Download Markdown',
  reportClose: 'Close',
  reportSectionConclusion: 'Conclusion',
  reportSectionStats: 'Key numbers',
  reportSectionCategories: 'Behavior categories and evidence',
  reportSectionUncategorized: 'Uncategorized records',
  reportNoUncategorized: 'No uncategorized records',
  reportSectionSuggestions: 'Recommended actions',
  reportSectionBoundary: 'Evidence boundary',
  reportGeneratedAt: 'Generated at',
  reportIp: 'Queried IP',
  reportWindow: 'Period',
  reportVerdict: 'Verdict',
  reportScore: 'Risk score',
  reportContainment: 'Containment',
  reportNoCategories: 'No specific attack type identified',
  reportNoSuggestions: 'No recommendation',
  reportBoundaryBody:
    'This report is generated from audit-log metadata and contains no request bodies. It supports judgment but must not be the sole basis for attributing an intrusion.',
  reportTraceHint:
    'Every evidence row carries an audit record ID. Open the matching record in Audit Logs to inspect request/response headers and bodies, client info, and hash-chain integrity.',
  verdict: {
    no_data: 'No records',
    clean: 'Normal behavior',
    low: 'Minor anomaly',
    suspicious: 'Suspicious behavior',
    attack: 'Attack detected',
    compromised: 'Possibly compromised',
  },
  verdictHint: {
    no_data:
      'No access records were found for this IP in the selected period. The IP may be wrong, or it has never accessed the system.',
    clean:
      'Access records were found, but no attack signs were detected. No action is needed for now.',
    low: 'A few anomalous requests appeared, but not enough to call it an attack. Keep watching.',
    suspicious:
      'Something worth watching happened. Keep monitoring and follow the recommendations if necessary.',
    attack:
      'This IP shows clear attack characteristics. Follow the recommendations below as soon as possible.',
    compromised:
      'A successful login followed repeated failures. An account may have been guessed; act immediately and investigate.',
  },
  risk: { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', none: 'None' },
  severity: { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' },
  category: {
    honeypot: {
      label: 'Honeypot trip',
      description:
        'The actor touched a fake account or fake entry point deliberately planted by the system, which usually means active probing.',
    },
    credential_stuffing: {
      label: 'Credential stuffing',
      description:
        'The actor tried many different accounts, as if testing a leaked username/password list.',
    },
    brute_force: {
      label: 'Password brute force',
      description: 'The actor repeatedly guessed passwords for a small number of accounts.',
    },
    account_enumeration: {
      label: 'Account enumeration',
      description: 'The actor probed which usernames really exist, preparing for a later attack.',
    },
    unauthorized_access: {
      label: 'Unauthorized access',
      description: 'The actor tried to reach features or data without permission.',
    },
    data_exfiltration: {
      label: 'Data export',
      description: 'The actor tried to export data in bulk; confirm whether it succeeded.',
    },
    injection_probe: {
      label: 'Injection probe',
      description: 'The actor tried special characters or path traversal against the system.',
    },
    path_scanning: {
      label: 'Path scanning',
      description:
        'The actor automatically scanned for system entry points, which is common in hacking tools.',
    },
    rate_limit_abuse: {
      label: 'High-frequency requests',
      description: 'The request rate was abnormally high and has been rate-limited by the system.',
    },
    suspicious_activity: {
      label: 'Other suspicious activity',
      description:
        'The system flagged these requests as suspicious but could not assign a more specific type.',
    },
  },
  suggestion: {
    block_ip: 'Block this IP now: add it to the blacklist to stop further access.',
    reset_credentials:
      'Reset the password of any account that may have been logged into successfully, and require it to sign in again.',
    enable_mfa:
      'Enable two-factor authentication (MFA) for related accounts so a leaked password is not enough.',
    review_accounts:
      'Check whether the targeted accounts still use weak passwords and rotate them if needed.',
    review_access_control:
      'Review the permissions of the related roles and confirm the attempts did not read or change sensitive data.',
    review_rate_limits:
      'Review rate-limit and blocking thresholds; keep the source contained if abuse persists.',
    review_exports:
      'Check whether this IP successfully exported data and confirm whether a leak occurred.',
    review_honeypot:
      'This IP tripped the honeypot and is probing the system; block it and review the entry points it tried.',
    monitor: 'No blocking is needed for now. Keep watching and escalate if the anomaly continues.',
    verify_scope:
      'Your account sees only part of the data, so the profile may be incomplete; verify with a super administrator account.',
    no_action: 'No action needed.',
  },
}
