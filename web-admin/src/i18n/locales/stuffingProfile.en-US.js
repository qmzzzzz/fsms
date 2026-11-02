/**
 * Credential-stuffing profile page dictionary (lazy-loaded with the page chunk).
 * Enum values come from the backend: lengthBucket ∈ LENGTH_BUCKETS in
 * constants/credentialShape.js; charsetClass is a concatenation of l/u/d/s flags.
 */
export default {
  pageTitle: 'Credential Stuffing Profile',
  pageSubtitle:
    'Aggregates honeypot-stage credential attempts by source network segment to surface dictionary hits and account coverage. Computed per business day, never persisted.',
  dayLabel: 'Business day',
  query: 'Generate profile',
  querying: 'Analyzing…',
  reset: 'Reset',
  resultCard: 'Profile Result',
  recordCount: '{count} source segment(s)',
  windowRange: 'Window {since} ~ {until}',
  sourceKey: 'Source segment',
  attempts: 'Attempts',
  successes: 'Successes',
  accounts: 'Accounts',
  stemHits: 'Dictionary hits',
  lengthBucket: 'Password length',
  charsetClass: 'Charset',
  scopeLabel: 'Data scope',
  scopeAll: 'All',
  scopeSelf: 'Self',
  scopeDepartment: 'Department',
  sourceHint:
    'Sources are grouped by /24 (IPv4) or /64 (IPv6); attempts count honeypot-stage rows only, successes count real account logins only.',
  thresholdHint: 'Sample threshold: a source segment needs at least {min} attempts to appear.',
  emptyTitle: 'No source segment reached the threshold for this business day',
  emptyGeneric:
    'No stuffing signs met the sample threshold in this window; this does not mean "no attack" — segments below the threshold were excluded.',
  emptyExpired:
    'This business day is beyond the audit retention period, so no evidence remains in the window — an empty table does not mean no attack.',
  emptyScope:
    'The current data scope is "{scope}". Honeypot audit rows carry no user ownership, so the profile is always empty under this scope. Use an account with global data scope.',
  droppedBelowMin: '{n} source segment(s) dropped for insufficient samples (threshold: {min}).',
  droppedUnparsable: '{n} record(s) had unparsable source addresses and were not aggregated.',
  loadError: 'Failed to load the profile. Please try again later.',
  staleData: 'Refresh failed; showing the previous result',
  retry: 'Retry',
  lengthBucketValue: {
    lt8: 'Under 8',
    '8-11': '8-11',
    '12-15': '12-15',
    '16-19': '16-19',
    '20plus': '20+',
  },
  charsetFlag: {
    l: 'lowercase',
    u: 'uppercase',
    d: 'digits',
    s: 'symbols',
  },
}
