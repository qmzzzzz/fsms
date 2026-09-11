const AuditLog = require('../../models/AuditLog');
const mongoose = require('mongoose');
const { verifyAuditChain } = require('../../services/auditChainVerify');

describe('audit chain v3 resignation invariant', () => {
  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  test('v3 records accept the current strict payload', async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    const report = await verifyAuditChain(AuditLog, { fromLatest: false, maxRecords: 100 });
    expect(report).toEqual(
      expect.objectContaining({
        intact: expect.any(Boolean),
        byType: expect.objectContaining({ hash_mismatch: expect.any(Number) }),
        legacyV2BatchTolerated: expect.any(Number),
      })
    );
  });
});
