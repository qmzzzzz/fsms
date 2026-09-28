/**
 * 令牌用途判据：一份实现，三个入口
 *
 * 覆盖三层（缺一不可）：
 *  1. 判据本体的真值表；
 *  2. 三个消费方（HTTP 中间件 / 令牌有效性探测 / WS 认证）确实引用同一份实现，
 *     且全仓不再出现第二份内联的 `decoded.type !== 'access'`；
 *  3. **行为**：拿一个 `type:'refresh'` 的载荷用 access 密钥签名（正是"两把密钥被配成
 *     同值"时攻击者能拿到的东西），WS 认证与探测都必须拒绝；
 *     反向对照是"没有 type 字段的历史 access 令牌"不得被这道闸拒掉。
 */
const path = require('path');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

const { violatesAccessTokenPurpose } = require('../../utils/tokenPurpose');

const ROOT = path.resolve(__dirname, '..', '..', '..');
const SRC = path.join(ROOT, 'src');

const listJs = (dir) => {
  const out = [];
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const abs = path.join(dir, e.name);
    if (e.isDirectory()) out.push(...listJs(abs));
    else if (e.name.endsWith('.js')) out.push(abs);
  }
  return out;
};
const stripComments = (s) => s.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');

describe('violatesAccessTokenPurpose 真值表', () => {
  test.each([
    ['type=access', { type: 'access' }, false],
    ['type=refresh', { type: 'refresh' }, true],
    ['无 type（历史 access 令牌）', {}, false],
    ['type=undefined 显式', { type: undefined }, false],
    ['type=null', { type: null }, true],
    ['decoded 为 null', null, false],
    ['decoded 为字符串', 'refresh', false],
  ])('%s ⇒ %s', (_label, input, expected) => {
    expect(violatesAccessTokenPurpose(input)).toBe(expected);
  });
});

describe('判据只有一处实现', () => {
  const CONSUMERS = [
    'src/middleware/auth.js',
    'src/services/tokenService.js',
    'src/services/websocketService.js',
  ];

  test('三个入口都引用 utils/tokenPurpose', () => {
    for (const rel of CONSUMERS) {
      const code = stripComments(fs.readFileSync(path.join(ROOT, rel), 'utf8'));
      expect({ rel, refs: /utils\/tokenPurpose/.test(code) }).toEqual({ rel, refs: true });
    }
  });

  test('全仓（判据自身之外）不得再内联写一份 type 比较', () => {
    const self = path.join(SRC, 'utils', 'tokenPurpose.js');
    const offenders = [];
    for (const abs of listJs(SRC)) {
      if (path.resolve(abs) === self) continue;
      if (abs.includes(`${path.sep}tests${path.sep}`)) continue;
      const code = stripComments(fs.readFileSync(abs, 'utf8'));
      if (/\.type\s*!==\s*'access'/.test(code)) offenders.push(path.relative(ROOT, abs));
    }
    expect(offenders).toEqual([]);
  });

  test('反向前提：内联一份的写法确实会被上面那条扫描抓出（防空集假绿）', () => {
    const dirty = stripComments(
      "const f = (d) => d.type !== 'access';\n// d.type !== 'access' 在注释里，不该被抓\n"
    );
    expect(/\.type\s*!==\s*'access'/.test(dirty)).toBe(true);
    const clean = stripComments("const f = (d) => violates(d);\n// d.type !== 'access' 只是注释\n");
    expect(/\.type\s*!==\s*'access'/.test(clean)).toBe(false);
  });
});

describe('行为：refresh 载荷不得建立推送通道 / 不得被探测当成有效 access', () => {
  const userId = String(new mongoose.Types.ObjectId());
  const sign = (payload) => jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });

  const mockActiveUser = (modPath) => {
    jest.doMock(modPath, () => ({
      findById: jest.fn(() => ({
        select: () => ({
          populate: () =>
            Promise.resolve({
              username: 'purpose-target',
              status: 'active',
              tokenVersion: 0,
              passwordChangedAt: null,
              allowedIPs: [],
              roles: [{ code: 'GUEST' }],
            }),
          lean: async () => ({ status: 'active', tokenVersion: 0 }),
        }),
      })),
    }));
  };

  beforeEach(() => {
    jest.resetModules();
    const bl = path.join(__dirname, '../../middleware/tokenBlacklist');
    mockActiveUser(path.join(__dirname, '../../models/User'));
    jest.doMock(bl, () => ({ isTokenBlacklisted: async () => false }));
  });

  afterEach(() => {
    jest.dontMock(path.join(__dirname, '../../models/User'));
    jest.dontMock(path.join(__dirname, '../../middleware/tokenBlacklist'));
    jest.resetModules();
  });

  const makeSocket = () => {
    const socket = {
      id: 'sock-purpose',
      authenticated: false,
      emitted: [],
      connected: true,
      emit: (ev, data) => socket.emitted.push({ ev, data }),
      disconnect: () => {
        socket.connected = false;
      },
      join: () => {},
    };
    return socket;
  };

  const authenticate = async (token) => {
    const WebSocketService = require('../../services/websocketService');
    const svc = Object.create(WebSocketService.prototype);
    svc.clients = new Map();
    svc.userConnections = new Map();
    svc.io = { sockets: { sockets: new Map() } };
    const socket = makeSocket();
    const result = await svc.authenticateSocket(socket, token, null);
    return { result, socket };
  };

  test('WS：type=refresh 的令牌被拒（emit auth-error + 断开 + false）', async () => {
    const { result, socket } = await authenticate(
      sign({ userId, tokenVersion: 0, type: 'refresh', sid: 's1' })
    );
    expect(result).toBe(false);
    expect(socket.connected).toBe(false);
    expect(socket.emitted.map((e) => e.ev)).toContain('auth-error');
    expect(socket.emitted[0].data.message).toBe('认证令牌类型不合法');
  });

  test('反向对照：没有 type 字段的历史 access 令牌不被这道闸拒绝', async () => {
    const { socket } = await authenticate(sign({ userId, tokenVersion: 0 }));
    const messages = socket.emitted.map((e) => e.data && e.data.message);
    expect(messages).not.toContain('认证令牌类型不合法');
  });

  test('反向对照：type=access 正常通过用途闸（不得把校验收紧成只认无 type）', async () => {
    const { socket } = await authenticate(sign({ userId, tokenVersion: 0, type: 'access' }));
    const messages = socket.emitted.map((e) => e.data && e.data.message);
    expect(messages).not.toContain('认证令牌类型不合法');
  });

  test('探测：isAccessTokenValid 对同形态的 refresh 载荷返回 false', async () => {
    const tokenService = require('../../services/tokenService');
    expect(
      await tokenService.isAccessTokenValid(sign({ userId, tokenVersion: 0, type: 'refresh' }))
    ).toBe(false);
    expect(await tokenService.isAccessTokenValid(sign({ userId, tokenVersion: 0 }))).toBe(true);
  });
});
