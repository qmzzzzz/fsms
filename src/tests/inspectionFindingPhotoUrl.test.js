/**
 * P2-25：findings[].photo 的 URL 形态闸必须在后端执行
 *
 * 此前后端只限长度 ≤500，`javascript:` / `data:` / 任意文本都能落库；
 * 前端 InspectionCompleteForm.photoRule 的形态判据（http(s) 绝对地址或
 * 以 / 开头的站内绝对路径）现已镜像到 completeValidation。本套件绕过 UI
 * 直调 API，断言伪 URL 一律 400 且不落库，合法两形态放行。
 */
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const request = require('supertest');

const { randomPassword } = require('./helpers/buildLoginEnvelope');
const { INSPECTION_RESULTS, INSPECTION_FINDING_SEVERITIES } = require('../constants/inspection');

const DEPT = 'ZZPU-A';
const stamp = `zzpu${Date.now()}`.replace(/[^a-z0-9]/g, '').slice(0, 8);

describe('complete：findings[].photo 的 URL 形态校验（后端镜像前端规则）', () => {
  let app;
  let Inspection;
  let User;
  let Role;
  let Permission;
  let token;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) await mongoose.connect(process.env.MONGODB_URI);
    User = require('../models/User');
    Role = require('../models/Role');
    Permission = require('../models/Permission');
    Inspection = require('../models/Inspection');
    require('../models/AuditLog');
    require('../models/TokenBlacklist');

    const wildcard = await Permission.findOneAndUpdate(
      { code: '*:*' },
      { $setOnInsert: { name: '全部权限', code: '*:*', type: 'api', module: 'system' } },
      { upsert: true, new: true }
    );
    const role = await Role.create({
      name: `${stamp} 照片`,
      code: `${stamp}_photo`,
      level: 7,
      permissions: [wildcard._id],
    });
    const operator = await User.create({
      username: `${stamp}_op`,
      email: `${stamp}_op@example.com`,
      password: randomPassword(),
      department: DEPT,
      roles: [role._id],
    });
    token = jwt.sign(
      {
        userId: String(operator._id),
        username: operator.username,
        tokenVersion: operator.tokenVersion ?? 0,
      },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    const { createApp } = require('../app');
    app = createApp();
  });

  afterAll(async () => {
    await Inspection.deleteMany({ title: new RegExp(stamp) }).catch(() => {});
    await User.deleteMany({ username: new RegExp(`^${stamp}`) }).catch(() => {});
    await Role.deleteMany({ name: new RegExp(`^${stamp} `) }).catch(() => {});
    if (mongoose.connection.readyState !== 0) await mongoose.connection.close();
  });

  const mkStarted = async (tag) => {
    const created = await request(app)
      .post('/api/inspections')
      .set('Authorization', `Bearer ${token}`)
      .send({
        title: `${stamp}-${tag}`,
        inspectionType: 'daily',
        planStartTime: '2026-09-20T08:00:00.000Z',
        planEndTime: '2026-09-20T10:00:00.000Z',
        checkItems: [{ name: `${stamp} 检查项` }],
        locations: [{ building: DEPT }],
      });
    expect(created.status).toBe(201);
    const id = created.body.data._id;
    const start = await request(app)
      .put(`/api/inspections/${id}/start`)
      .set('Authorization', `Bearer ${token}`)
      .send({});
    expect(start.status).toBe(200);
    return id;
  };

  const completeWithPhoto = (id, photo) =>
    request(app)
      .put(`/api/inspections/${id}/complete`)
      .set('Authorization', `Bearer ${token}`)
      .send({
        result: INSPECTION_RESULTS[0],
        findings: [
          { issue: `${stamp} 灭火器失压`, severity: INSPECTION_FINDING_SEVERITIES[1], photo },
        ],
      });

  test.each([
    ['javascript:alert(1)', 'javascript: 伪 URL'],
    ['JaVaScRiPt:alert(1)', '大小写混淆的 javascript: 伪 URL'],
    ['data:text/html;base64,PHNjcmlwdD4=', 'data: 伪 URL'],
    ['DATA:text/plain,xxx', '大写 data: 伪 URL'],
    ['手机拍了', '非 URL 自由文本'],
    ['//evil.com/x.jpg', '协议相对地址'],
    ['ftp://example.com/x.jpg', '非 http(s) 协议'],
    ['https://', '残缺 URL'],
  ])('photo=%s（%s）→ 400 且不落库', async (photo) => {
    const id = await mkStarted(photo.replace(/[^a-z0-9]/gi, '').slice(0, 6) || 'bad');
    const res = await completeWithPhoto(id, photo);
    expect(res.status).toBe(400);
    expect(res.body.errors.errorCode).toBe('VALIDATION_FAILED');
    const after = await Inspection.findById(id).lean();
    expect(after.findings ?? []).toHaveLength(0);
    expect(after.status).toBe('in_progress');
  });

  test.each([
    ['https://example.com/uploads/x.jpg', 'http(s) 绝对地址'],
    ['http://example.com/uploads/x.jpg', 'http 绝对地址'],
    ['/uploads/2026/11/x.jpg', '站内绝对路径'],
  ])('photo=%s（%s）→ 200 且原样落库', async (photo) => {
    const id = await mkStarted(`ok${photo.replace(/[^a-z0-9]/gi, '').slice(0, 6)}`);
    const res = await completeWithPhoto(id, photo);
    expect(res.status).toBe(200);
    const after = await Inspection.findById(id).lean();
    expect(after.findings).toHaveLength(1);
    expect(after.findings[0].photo).toBe(photo);
  });

  test('photo 为空串 → 放行（照片可选项，与前端空值放行一致）', async () => {
    const id = await mkStarted('empty');
    const res = await completeWithPhoto(id, '');
    expect(res.status).toBe(200);
    const after = await Inspection.findById(id).lean();
    expect(after.findings[0].photo ?? '').toBe('');
  });

  test('photo 恰好 500 字符的合法 URL → 放行；501 字符 → 400', async () => {
    const okId = await mkStarted('len500');
    const okRes = await completeWithPhoto(okId, `https://example.com/${'a'.repeat(480)}`);
    expect(okRes.status).toBe(200);

    const badId = await mkStarted('len501');
    const badRes = await completeWithPhoto(badId, `https://example.com/${'a'.repeat(481)}`);
    expect(badRes.status).toBe(400);
  });
});
