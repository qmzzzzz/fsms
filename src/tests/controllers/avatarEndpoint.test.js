/**
 * 头像端点端到端：上传 / 读取（本人 + 他人 + 越权）/ 304 / 移除 / 资料页清空级联
 *
 * 授权口径是本文件的主判据：
 *   - 本人读自己的头像不需要 user:read；
 *   - 他人读需要 user:read **且**通过用户数据范围（与 GET /api/users/:id 同一把尺）；
 *   - 有 user:read 但范围外 → 403 USER_VIEW_FORBIDDEN，不是 404（不伪装存在性）。
 * 另外锁定审计体不得记录头像 data URI（P0-5：窄键规则，不污染全局敏感键名单）。
 */

const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { randomPassword } = require('../helpers/buildLoginEnvelope');
const auditBuffer = require('../../services/auditBuffer');
const { buildAvatarUrl, parseAvatarUrl } = require('../../utils/avatarUrl');

const zlib = require('zlib');

const PNG_SIG = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

// chunk 必须带真实 CRC：校验器会逐 chunk 核对（CRC 为零等于给自己伪造一张坏图）
function pngChunk(type, data) {
  const chunk = Buffer.alloc(12 + data.length);
  chunk.writeUInt32BE(data.length, 0);
  chunk.write(type, 4, 'latin1');
  data.copy(chunk, 8);
  const body = Buffer.concat([Buffer.from(type, 'latin1'), data]);
  chunk.writeUInt32BE(zlib.crc32(body), 8 + data.length);
  return chunk;
}

// IDAT 必须是真能解压、且解压字节数与声明尺寸相符的 zlib 流（假数据会被 PNG_MALFORMED 拦掉）
function pngBuffer(width, height) {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8;
  ihdr[9] = 6;
  const raw = Buffer.alloc((1 + width * 4) * height, 0);
  return Buffer.concat([
    PNG_SIG,
    pngChunk('IHDR', ihdr),
    pngChunk('IDAT', zlib.deflateSync(raw)),
    pngChunk('IEND', Buffer.alloc(0)),
  ]);
}

const PNG_URI = 'data:image/png;base64,' + pngBuffer(32, 32).toString('base64');

describe('头像端点', () => {
  let app;
  let User;
  let Role;
  let Permission;
  let owner;
  let admin;
  let reader;
  let outsider;
  let nobody;
  const stamp = `avt${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);
  const PASSWORD = randomPassword();
  const tokens = {};

  const tokenFor = (user) => {
    tokens[user.username] = jwt.sign(
      { userId: String(user._id), username: user.username, tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );
    return tokens[user.username];
  };
  const as = (user) => ({
    get: (url) =>
      request(app)
        .get(url)
        .set('Authorization', `Bearer ${tokenFor(user)}`),
    put: (url, body) =>
      request(app)
        .put(url)
        .set('Authorization', `Bearer ${tokenFor(user)}`)
        .send(body),
    delete: (url) =>
      request(app)
        .delete(url)
        .set('Authorization', `Bearer ${tokenFor(user)}`),
  });

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    Role = require('../../models/Role');
    Permission = require('../../models/Permission');

    const readPerm = await Permission.findOneAndUpdate(
      { code: 'user:read' },
      { $setOnInsert: { name: '用户读取', code: 'user:read', type: 'api', module: 'system' } },
      { upsert: true, new: true }
    );
    const mkRole = (tag) =>
      Role.create({
        name: `头像测试_${tag}_${stamp}`,
        code: `AVT_${tag}_${stamp}`,
        level: 5,
        permissions: [readPerm._id],
      });
    const readerRole = await mkRole('READ');
    const outsiderRole = await mkRole('OUT');

    // 超管通配：验证 *:* 也能读他人头像（若控制器只做 includes('user:read') 会 403）
    const wildcardPerm = await Permission.findOneAndUpdate(
      { code: '*:*' },
      { $setOnInsert: { name: '全部权限', code: '*:*', type: 'api', module: 'system' } },
      { upsert: true, new: true }
    );
    const adminRole = await Role.create({
      name: `头像测试_ADMIN_${stamp}`,
      code: `AVT_ADMIN_${stamp}`,
      level: 10,
      permissions: [wildcardPerm._id],
    });

    const mkUser = (tag, department) =>
      User.create({
        username: `avt${tag}${stamp}`,
        email: `avt${tag}${stamp}@example.com`,
        password: PASSWORD,
        department,
      });

    admin = await mkUser('admin', 'OTHERDEPT2');
    reader = await mkUser('reader', 'AVTDEPT');
    outsider = await mkUser('outsider', 'OTHERDEPT');
    nobody = await mkUser('nobody', 'AVTDEPT');
    owner = await mkUser('owner', 'AVTDEPT');

    await User.updateOne({ _id: admin._id }, { roles: [adminRole._id] });
    await User.updateOne({ _id: reader._id }, { roles: [readerRole._id] });
    await User.updateOne({ _id: outsider._id }, { roles: [outsiderRole._id] });
    // 数据范围 self 档：把目标挂到读取者名下，范围闸才放行
    await User.updateOne({ _id: owner._id }, { createdBy: reader._id });

    const { createApp } = require('../../app');
    app = createApp();
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      const rx = new RegExp(`^avt(admin|reader|outsider|nobody|owner)${stamp}$`);
      await User.deleteMany({ username: rx }).catch(() => {});
      await require('../../models/UserAvatar')
        .deleteMany({})
        .catch(() => {});
      await Role.deleteMany({ code: new RegExp(`^AVT_(READ|OUT|ADMIN)_${stamp}$`) }).catch(
        () => {}
      );
      await mongoose.connection.close();
    }
  });

  describe('上传', () => {
    test('本人上传合法 PNG → 200，返回服务端 URL，User.avatar 与记录同步', async () => {
      const spy = jest.spyOn(auditBuffer, 'push');
      const res = await as(owner).put('/api/auth/avatar', { image: PNG_URI });
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      const { avatar, width, height } = res.body.data;
      expect(width).toBe(32);
      expect(height).toBe(32);
      const parsed = parseAvatarUrl(avatar);
      expect(parsed.userId).toBe(String(owner._id));
      expect(avatar).toBe(buildAvatarUrl(owner._id, parsed.version));

      const fresh = await User.findById(owner._id).lean();
      expect(fresh.avatar).toBe(avatar);
      const record = await require('../../models/UserAvatar')
        .findById(owner._id)
        .select('+data')
        .lean();
      expect(record.hash.slice(0, 16)).toBe(parseAvatarUrl(avatar).version);
      // 密文落库，明文 Base64 不得出现（即使 select:false 被绕过也不该是明文）
      expect(record.data.startsWith('enc.v2.')).toBe(true);

      await new Promise((resolve) => setImmediate(resolve));
      const doc = spy.mock.calls.map(([d]) => d).find((d) => d && d.path === '/api/auth/avatar');
      expect(doc).toBeDefined();
      expect(doc.body.image).toBe('***');
      expect(JSON.stringify(doc.body)).not.toContain('data:image');
      spy.mockRestore();
    });

    test('重复上传同一图片：幂等，只修指针', async () => {
      const first = await as(owner).put('/api/auth/avatar', { image: PNG_URI });
      const second = await as(owner).put('/api/auth/avatar', { image: PNG_URI });
      expect(second.status).toBe(200);
      expect(second.body.data.avatar).toBe(first.body.data.avatar);
    });

    test('非 data URI → 400 AVATAR_INVALID', async () => {
      const res = await as(owner).put('/api/auth/avatar', { image: 'https://x/y.png' });
      expect(res.status).toBe(400);
      expect(res.body.errors.errorCode).toBe('AVATAR_INVALID');
    });

    test('MIME 与内容不一致 → 400', async () => {
      const res = await as(owner).put('/api/auth/avatar', {
        image: PNG_URI.replace('data:image/png', 'data:image/jpeg'),
      });
      expect(res.status).toBe(400);
      expect(res.body.errors.errorCode).toBe('AVATAR_INVALID');
    });
  });

  // 读取类用例的自足前提：owner 名下必须有一条头像记录。默认顺序靠「上传」用例先跑，
  // 但「移除与清空级联」的 DELETE /auth/avatar 会清掉它，--randomize 下顺序不定。
  // 上传是幂等的：同一张图重复上传只修指针，不改变版本。
  const ensureOwnerAvatar = async () => {
    const res = await as(owner).put('/api/auth/avatar', { image: PNG_URI });
    expect(res.status).toBe(200);
  };

  describe('读取', () => {
    test('本人读取无需 user:read → 200 + ETag + private,no-cache', async () => {
      const res = await as(nobody).get('/api/avatars/' + nobody._id);
      // nobody 还没上传：404 才说明"本人直通授权"确实先于记录存在性
      expect(res.status).toBe(404);
      expect(res.body.errors.errorCode).toBe('AVATAR_NOT_FOUND');

      await as(nobody).put('/api/auth/avatar', { image: PNG_URI });
      const ok = await as(nobody).get('/api/avatars/' + nobody._id);
      expect(ok.status).toBe(200);
      expect(ok.headers['content-type']).toBe('image/png');
      expect(ok.headers.etag).toMatch(/^"[0-9a-f]{64}"$/);
      expect(ok.headers['cache-control']).toBe('private, no-cache');
      expect(ok.headers.vary).toBe('Cookie');
      expect(ok.headers['x-content-type-options']).toBe('nosniff');
      expect(ok.headers['content-security-policy']).toContain("default-src 'none'");
      expect(ok.headers['content-security-policy']).toContain('sandbox');
      expect(ok.body.length).toBe(pngBuffer(32, 32).length);
    });

    test('If-None-Match 命中 → 304，且仍带 ETag/Cache-Control', async () => {
      await ensureOwnerAvatar();
      const first = await as(owner).get('/api/avatars/' + owner._id);
      const res = await as(owner)
        .get('/api/avatars/' + owner._id)
        .set('If-None-Match', first.headers.etag);
      expect(res.status).toBe(304);
      expect(res.headers.etag).toBe(first.headers.etag);
      expect(res.headers['cache-control']).toBe('private, no-cache');
      expect(res.headers['x-content-type-options']).toBe('nosniff');
      expect(res.headers['content-security-policy']).toContain('sandbox');
      expect(res.text).toBe('');
    });

    test('他人 + user:read + 数据范围内 → 200', async () => {
      await ensureOwnerAvatar();
      const res = await as(reader).get('/api/avatars/' + owner._id);
      expect(res.status).toBe(200);
      expect(res.headers['content-type']).toBe('image/png');
    });

    test('超管通配 *:* + 数据范围全部 → 200（不被窄接口挡住）', async () => {
      await ensureOwnerAvatar();
      const res = await as(admin).get('/api/avatars/' + owner._id);
      expect(res.status).toBe(200);
      expect(res.headers['content-type']).toBe('image/png');
    });

    test('他人无 user:read → 403 PERMISSION_DENIED（不是 404）', async () => {
      const res = await as(nobody).get('/api/avatars/' + owner._id);
      expect(res.status).toBe(403);
      expect(res.body.errors.errorCode).toBe('PERMISSION_DENIED');
    });

    test('他人有 user:read 但数据范围外 → 403 USER_VIEW_FORBIDDEN', async () => {
      const res = await as(outsider).get('/api/avatars/' + owner._id);
      expect(res.status).toBe(403);
      expect(res.body.errors.errorCode).toBe('USER_VIEW_FORBIDDEN');
    });

    test('非法 userId → 400（路由层 isMongoId）', async () => {
      const res = await as(owner).get('/api/avatars/not-an-id');
      expect(res.status).toBe(400);
    });
  });

  describe('管理员改他人头像（P0-1：URL 绑定目标用户而不是发起者）', () => {
    test('管理员保存他人的服务端头像 URL → 200', async () => {
      const url = buildAvatarUrl(nobody._id, 'e'.repeat(64));
      const res = await as(admin).put('/api/users/' + nobody._id, { avatar: url });
      expect(res.status).toBe(200);
      const fresh = await User.findById(nobody._id).lean();
      expect(fresh.avatar).toBe(url);
    });

    test('管理员提交外部 URL → 400 AVATAR_INVALID（不是"绑定发起者"漏放）', async () => {
      const res = await as(admin).put('/api/users/' + nobody._id, {
        avatar: 'https://evil.example/x.png',
      });
      expect(res.status).toBe(400);
      expect(res.body.errors.errorCode).toBe('AVATAR_INVALID');
    });
  });

  describe('移除与清空级联', () => {
    test('DELETE /auth/avatar → 记录与指针同时清空', async () => {
      await as(owner).put('/api/auth/avatar', { image: PNG_URI });
      const del = await as(owner).delete('/api/auth/avatar');
      expect(del.status).toBe(200);
      expect(await require('../../models/UserAvatar').findById(owner._id).lean()).toBeNull();
      const fresh = await User.findById(owner._id).lean();
      expect(fresh.avatar).toBe('');
    });

    test('PUT /auth/profile 的 avatar:"" 也删记录（只清指针不算清）', async () => {
      await as(owner).put('/api/auth/avatar', { image: PNG_URI });
      const res = await as(owner).put('/api/auth/profile', { avatar: '' });
      expect(res.status).toBe(200);
      expect(await require('../../models/UserAvatar').findById(owner._id).lean()).toBeNull();
      const get = await as(owner).get('/api/avatars/' + owner._id);
      expect(get.status).toBe(404);
    });

    test('删除用户时级联删除头像记录', async () => {
      const temp = await User.create({
        username: `avttemp${stamp}`,
        email: `avttemp${stamp}@example.com`,
        password: PASSWORD,
        department: 'AVTDEPT',
        createdBy: reader._id,
      });
      const avatarService = require('../../services/avatarService');
      await avatarService.uploadAvatar(temp._id, PNG_URI);
      // 直接走 service 删除，避开 DELETE /users 对超管/自身的额外约束
      const userService = require('../../services/userService');
      await userService.deleteById(String(temp._id));
      expect(await require('../../models/UserAvatar').findById(temp._id).lean()).toBeNull();
    });
  });
});
