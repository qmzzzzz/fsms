const jwt = require('jsonwebtoken');
const config = require('../../config');
const { generateToken, generateRefreshToken } = require('../../services/tokenService');

describe('tokenService claims', () => {
  test('access token keeps jti and sid separate', () => {
    const token = generateToken(
      'user-1',
      'alice',
      'alice@example.com',
      ['admin'],
      'Alice',
      2,
      'fixed-jti',
      'sid-1'
    );
    const decoded = jwt.verify(token, config.jwt.secret, { algorithms: ['HS256'] });

    expect(decoded).toMatchObject({
      userId: 'user-1',
      tokenVersion: 2,
      jti: 'fixed-jti',
      sid: 'sid-1',
    });
  });

  test('refresh token remains unique for same user and sid', () => {
    const first = generateRefreshToken('user-1', 3, 'sid-1');
    const second = generateRefreshToken('user-1', 3, 'sid-1');
    const firstClaims = jwt.verify(first, config.jwt.refreshSecret, { algorithms: ['HS256'] });
    const secondClaims = jwt.verify(second, config.jwt.refreshSecret, { algorithms: ['HS256'] });

    expect(first).not.toBe(second);
    expect(firstClaims.type).toBe('refresh');
    expect(secondClaims.type).toBe('refresh');
    expect(firstClaims.sid).toBe('sid-1');
    expect(secondClaims.sid).toBe('sid-1');
    expect(firstClaims.jti).not.toBe(secondClaims.jti);
  });
});
