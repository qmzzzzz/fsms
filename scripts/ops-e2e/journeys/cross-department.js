'use strict';

const crypto = require('crypto');
const http = require('http');
const net = require('net');
const path = require('path');
const mongoose = require('mongoose');
const { assert, createJourney, waitFor } = require('../lib');
const { isolateDisposableSecrets } = require('../../devSecretIsolation');

const REQUIRED_MARKERS = [
  '管理员可见两台设备',
  '部门账号列表只含本部门设备',
  '越界详情返回 403 DEVICE_VIEW_FORBIDDEN',
];

function request(base, method, urlPath, { cookie, token, body } = {}) {
  return new Promise((resolve, reject) => {
    const payload = body ? JSON.stringify(body) : null;
    const req = http.request(
      base + urlPath,
      {
        method,
        headers: Object.assign(
          {},
          payload
            ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) }
            : {},
          token ? { Authorization: 'Bearer ' + token } : {},
          cookie ? { Cookie: cookie } : {}
        ),
        timeout: 10000,
      },
      (res) => {
        const chunks = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          try {
            resolve({ status: res.statusCode, body: JSON.parse(text), headers: res.headers });
          } catch (_) {
            resolve({ status: res.statusCode, body: text, headers: res.headers });
          }
        });
      }
    );
    req.on('error', reject);
    req.on('timeout', () => req.destroy(new Error(`请求超时 ${urlPath}`)));
    if (payload) req.write(payload);
    req.end();
  });
}

function getFreePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.unref();
    server.on('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
}

function setupEnv({ port, uri, tmpDir, base, password }) {
  process.env.NODE_ENV = 'development';
  process.env.PORT = String(port);
  process.env.MONGODB_URI = uri;
  process.env.JWT_SECRET = crypto.randomBytes(32).toString('hex');
  process.env.JWT_REFRESH_SECRET = crypto.randomBytes(32).toString('hex');
  process.env.AES_SECRET_KEY = crypto.randomBytes(32).toString('hex');
  process.env.HMAC_SECRET = crypto.randomBytes(16).toString('hex');
  process.env.ADMIN_INITIAL_PASSWORD = password;
  process.env.CORS_ORIGIN = base;
  process.env.ALLOWED_HOSTS = `127.0.0.1:${port}`;
  process.env.ENABLE_API_DOCS = 'false';
  process.env.ALLOW_PUBLIC_REGISTRATION = 'false';
  process.env.AUDIT_WAL_PATH = path.join(tmpDir, 'audit.wal');
  process.env.LOG_LEVEL = 'error';
}

async function login(base, username, password) {
  const result = await request(base, 'POST', '/api/auth/login', { body: { username, password } });
  assert.equal(
    result.status,
    200,
    `登录 ${username} 失败：status=${result.status} ${JSON.stringify(result.body).slice(0, 200)}`
  );
  // I-01 起令牌只经 httpOnly cookie 下发（响应体刻意不回传，防 XSS 窃取）。
  const cookie = (result.headers['set-cookie'] || []).map((line) => line.split(';')[0]).join('; ');
  assert.match(cookie, /(^|; )access_token=/, '登录未下发 access_token cookie');
  return cookie;
}

async function listDevices(base, cookie) {
  const result = await request(base, 'GET', '/api/devices?limit=100', { cookie });
  assert.equal(
    result.status,
    200,
    `设备列表失败：status=${result.status} ${JSON.stringify(result.body).slice(0, 200)}`
  );
  return result.body.data;
}

async function createDepartmentFixture(base, adminCookie, roleId, ctx, suffix) {
  const createUser = async (label, department) => {
    const username = `ops_${label}_${suffix}`;
    const result = await request(base, 'POST', '/api/users', {
      cookie: adminCookie,
      body: {
        username,
        email: `${username}@example.com`,
        password: ctx.password,
        realName: `范围测试-${label}`,
        department,
        roles: [roleId],
      },
    });
    assert.equal(
      result.status,
      201,
      `创建用户 ${username} 失败：status=${result.status} ${JSON.stringify(result.body).slice(0, 200)}`
    );
    return String(result.body.data._id);
  };

  const createDevice = async (label, building) => {
    const result = await request(base, 'POST', '/api/devices', {
      cookie: adminCookie,
      body: {
        deviceCode: `OPS-SCOPE-${label}-${suffix}`,
        deviceName: `范围测试设备-${label}`,
        deviceType: 'hydrant',
        installDate: '2026-01-01T00:00:00.000Z',
        location: { building },
      },
    });
    assert.equal(
      result.status,
      201,
      `创建设备 ${label} 失败：status=${result.status} ${JSON.stringify(result.body).slice(0, 200)}`
    );
    return String(result.body.data._id);
  };

  ctx.departments.A = `A部门-${suffix}`;
  ctx.departments.B = `B部门-${suffix}`;
  ctx.users.A = await createUser('a', ctx.departments.A);
  ctx.users.B = await createUser('b', ctx.departments.B);
  ctx.devices.A = await createDevice('A', ctx.departments.A);
  ctx.devices.B = await createDevice('B', ctx.departments.B);
}

async function assertDepartmentIsolation(base, cookie, ownDeviceId, ownDepartment, otherDeviceId) {
  const devices = await listDevices(base, cookie);
  assert.deepEqual(
    devices.map((d) => String(d._id)),
    [ownDeviceId],
    '部门账号的设备列表必须恰好是本部门的设备'
  );
  for (const device of devices) {
    assert.equal(device.location.building, ownDepartment);
  }
  assert.ok(
    !devices.some((d) => String(d._id) === otherDeviceId),
    '部门账号列表里出现了其他部门的设备'
  );
}

async function main(config) {
  const { root, tmpDir } = config;
  const journey = createJourney('cross-department', REQUIRED_MARKERS);

  // 必须早于 require src/index.js：宿主残留的 *_FILE / 明文密钥会在启动期
  // 覆盖这里的一次性密钥与内存库连接串。
  isolateDisposableSecrets({ scriptName: 'ops-e2e-cross-department' });

  const { MongoMemoryServer } = require('mongodb-memory-server');
  const mongo = await MongoMemoryServer.create();
  const port = await getFreePort();
  const base = `http://127.0.0.1:${port}`;
  const password = `Ops!${crypto.randomBytes(6).toString('hex')}Aa1`;
  setupEnv({ port, uri: mongo.getUri('fsms_ops_e2e_scope'), tmpDir, base, password });

  require(path.join(root, 'src', 'index.js'));

  const ctx = {
    password,
    adminCookie: null,
    departments: {},
    users: {},
    devices: {},
    cookies: {},
  };

  try {
    await journey.step('启动完整应用并等待 /readyz 通过', async () => {
      await waitFor(
        async () => {
          const result = await request(base, 'GET', '/readyz');
          return result.status === 200;
        },
        { timeoutMs: 60000, intervalMs: 200, label: '/readyz' }
      );
    });

    await journey.step(
      '管理员创建两个部门账号与两台设备（正对照：管理员可见两台设备）',
      async () => {
        ctx.adminCookie = await login(base, 'admin', password);
        const roles = await request(base, 'GET', '/api/roles?limit=100', {
          cookie: ctx.adminCookie,
        });
        assert.equal(roles.status, 200, `角色列表失败：status=${roles.status}`);
        const role = (roles.body.data || []).find((item) => item.code === 'SECURITY_ADMIN');
        assert.ok(role, '未找到 SECURITY_ADMIN 角色');

        const suffix = String(process.pid);
        await createDepartmentFixture(base, ctx.adminCookie, role._id, ctx, suffix);

        const adminDevices = await listDevices(base, ctx.adminCookie);
        const ids = adminDevices.map((d) => String(d._id));
        assert.ok(ids.includes(ctx.devices.A), '管理员看不到 A 部门设备（数据未就绪）');
        assert.ok(ids.includes(ctx.devices.B), '管理员看不到 B 部门设备（数据未就绪）');
      }
    );

    await journey.step('部门账号列表只含本部门设备', async () => {
      const cookieA = await login(base, `ops_a_${process.pid}`, password);
      const cookieB = await login(base, `ops_b_${process.pid}`, password);
      await assertDepartmentIsolation(
        base,
        cookieA,
        ctx.devices.A,
        ctx.departments.A,
        ctx.devices.B
      );
      await assertDepartmentIsolation(
        base,
        cookieB,
        ctx.devices.B,
        ctx.departments.B,
        ctx.devices.A
      );
      ctx.cookies = { A: cookieA, B: cookieB };
    });

    await journey.step('越界详情返回 403 DEVICE_VIEW_FORBIDDEN（本部门详情仍 200）', async () => {
      assert.ok(ctx.cookies.A, '前置步骤未完成');
      const cross = await request(base, 'GET', `/api/devices/${ctx.devices.B}`, {
        cookie: ctx.cookies.A,
      });
      assert.equal(cross.status, 403, '跨部门读取详情必须被拒绝');
      assert.equal(cross.body.errors && cross.body.errors.errorCode, 'DEVICE_VIEW_FORBIDDEN');

      const reverse = await request(base, 'GET', `/api/devices/${ctx.devices.A}`, {
        cookie: ctx.cookies.B,
      });
      assert.equal(reverse.status, 403);
      assert.equal(reverse.body.errors && reverse.body.errors.errorCode, 'DEVICE_VIEW_FORBIDDEN');

      const own = await request(base, 'GET', `/api/devices/${ctx.devices.A}`, {
        cookie: ctx.cookies.A,
      });
      assert.equal(own.status, 200, '本部门详情不应被误拦');
    });
  } finally {
    if (mongoose.connection.readyState !== 0) await mongoose.disconnect().catch(() => {});
    await mongo.stop().catch(() => {});
  }

  return journey.finish();
}

module.exports = { main, REQUIRED_MARKERS };
