/**
 * 未脱敏 PII 导出的访问控制（L-17）
 *
 * 缺口：GET /reports/export 只要求 report:export，真实姓名是否输出由 system:read 决定，
 * 且有审计留痕——但拿到口令/会话的人可以直接批量下载全文，没有任何"此刻是本人操作"
 * 的证明，也没有一条比 report:export 更窄的权限。
 *
 * 修复后的契约（本文件逐条钉住）：
 *   ① GET 恒掩码：即使持有 pii:export，也只能拿到「张*明」；
 *   ② 未脱敏只走 POST /export/pii，需 pii:export + 二次验证（当前口令或 MFA）；
 *   ③ 缺权限时口令再对也拿不到文件，且不得产生凭据侧副作用（不计失败次数）；
 *   ④ 非 PII 类型在凭据校验前被拒（注定 400 的请求不消耗二次验证配额）；
 *   ⑤ 未掩码导出必须落 view_sensitive_data 审计。
 */

const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const request = require('supertest');
const { randomPassword } = require('../helpers/buildLoginEnvelope');
const { waitFor } = require('../helpers/waitFor');

describe('未脱敏 PII 导出：pii:export + 二次验证（L-17）', () => {
  const stamp = String(Date.now())
    .replace(/\d/g, (d) => 'abcdefghij'[Number(d)])
    .slice(-8);
  const PASSWORD = randomPassword();
  const REAL_NAME = '张伟明';
  const MASKED_NAME = '张*明';

  let app;
  let User;
  let Role;
  let Permission;
  let FireAlarm;
  let AuditLog;
  let piiUser;
  let maskUser;
  let piiRole;
  let maskRole;
  let piiToken;
  let maskToken;
  let alarmDescription;

  const signToken = (user) =>
    jwt.sign(
      { userId: String(user._id), username: user.username, tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

  /** xlsx 响应体 → 「表头 → 该列全部单元格文本」 */
  const columnsFromWorkbook = async (body) => {
    const ExcelJS = require('exceljs');
    const wb = new ExcelJS.Workbook();
    await wb.xlsx.load(body);
    const ws = wb.worksheets[0];
    const header = [];
    ws.getRow(1).eachCell({ includeEmpty: true }, (cell, idx) => {
      header[idx - 1] = String(cell.value ?? '');
    });
    const out = {};
    header.forEach((name, idx) => {
      out[name] = [];
      ws.eachRow((row, rowNumber) => {
        if (rowNumber === 1) return;
        out[name].push(String(row.getCell(idx + 1).value ?? ''));
      });
    });
    return out;
  };

  /** 最后一行的第一格文本（A-8 的水印行；掩码档没有这一行） */
  /** 工作簿属性（A-8 水印的另两路：creator/lastModifiedBy/description/keywords） */
  const workbookPropsOf = async (body) => {
    const ExcelJS = require('exceljs');
    const wb = new ExcelJS.Workbook();
    await wb.xlsx.load(body);
    return {
      creator: wb.creator,
      lastModifiedBy: wb.lastModifiedBy,
      description: wb.description,
      keywords: wb.keywords,
    };
  };

  const lastRowFirstCell = async (body) => {
    const ExcelJS = require('exceljs');
    const wb = new ExcelJS.Workbook();
    await wb.xlsx.load(body);
    return String(wb.worksheets[0].lastRow.getCell(1).value ?? '');
  };

  const binaryParser = (res, cb) => {
    const chunks = [];
    res.on('data', (chunk) => chunks.push(chunk));
    res.on('end', () => cb(null, Buffer.concat(chunks)));
  };

  const bufferResponse = (reqBuilder) =>
    reqBuilder
      .buffer()
      .parse(binaryParser)
      .then((res) => ({
        ...res,
        buffer: res.body,
      }));

  const exportGet = (token, query = 'type=alarms&format=xlsx') =>
    bufferResponse(
      request(app).get(`/api/reports/export?${query}`).set('Authorization', `Bearer ${token}`)
    );

  const exportPost = (token, body, query = 'type=alarms&format=xlsx') =>
    bufferResponse(
      request(app)
        .post(`/api/reports/export/pii?${query}`)
        .set('Authorization', `Bearer ${token}`)
        .send(body)
    );

  const jsonOf = (res) => {
    try {
      return JSON.parse(res.buffer.toString('utf8'));
    } catch {
      return null;
    }
  };

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    Role = require('../../models/Role');
    Permission = require('../../models/Permission');
    FireAlarm = require('../../models/FireAlarm');
    AuditLog = require('../../models/AuditLog');

    const perms = {};
    for (const code of ['report:read', 'report:export', 'pii:export']) {
      perms[code] = await Permission.findOneAndUpdate(
        { code },
        {
          $setOnInsert: {
            name: `pii_${code}_${stamp}`,
            code,
            type: 'api',
            module: 'report',
          },
        },
        { upsert: true, new: true }
      );
    }

    piiRole = await Role.create({
      name: `PII导出角色_${stamp}`,
      code: `PII_EXPORT_${stamp.toUpperCase()}`,
      level: 9, // 数据范围 all：确保夹具报警在导出集合里
      permissions: [perms['report:read']._id, perms['report:export']._id, perms['pii:export']._id],
    });
    maskRole = await Role.create({
      name: `掩码导出角色_${stamp}`,
      code: `MASK_EXPORT_${stamp.toUpperCase()}`,
      level: 9,
      permissions: [perms['report:read']._id, perms['report:export']._id],
    });

    piiUser = await User.create({
      username: `piiexp${stamp}`,
      email: `piiexp${stamp}@example.com`,
      password: PASSWORD,
      realName: REAL_NAME,
      roles: [piiRole._id],
    });
    maskUser = await User.create({
      username: `maskexp${stamp}`,
      email: `maskexp${stamp}@example.com`,
      password: PASSWORD,
      realName: '李四海',
      roles: [maskRole._id],
    });
    piiToken = signToken(piiUser);
    maskToken = signToken(maskUser);

    alarmDescription = `PII导出夹具_${stamp}`;
    await FireAlarm.create({
      alarmType: 'other',
      level: 'warning',
      description: alarmDescription,
      status: 'resolved',
      handler: piiUser._id,
      occurredAt: new Date(),
    });

    const { createApp } = require('../../app');
    app = createApp();
  });

  afterAll(async () => {
    await FireAlarm.deleteMany({ description: alarmDescription }).catch(() => {});
    await AuditLog.deleteMany(
      { username: { $in: [piiUser?.username, maskUser?.username] } },
      { bypassAppendOnly: true }
    ).catch(() => {});
    await User.deleteMany({ username: { $in: [piiUser?.username, maskUser?.username] } }).catch(
      () => {}
    );
    await Role.deleteMany({ _id: { $in: [piiRole?._id, maskRole?._id].filter(Boolean) } }).catch(
      () => {}
    );
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  test('① GET 恒掩码：持 pii:export 也只能拿到「张*明」', async () => {
    const res = await exportGet(piiToken);
    expect(res.status).toBe(200);
    const columns = await columnsFromWorkbook(res.buffer);
    expect(columns['描述']).toContain(alarmDescription);
    expect(columns['处理人']).toEqual([MASKED_NAME]);
    expect(columns['处理人']).not.toContain(REAL_NAME);
    // 反向对照（A-8）：掩码档既没有追溯号响应头，也没有表尾水印行
    expect(res.headers['x-export-trace-id']).toBeUndefined();
    expect(await lastRowFirstCell(res.buffer)).not.toContain('未脱敏导出');
  });

  test('② 未脱敏只经 POST：口令正确且持 pii:export 时输出「张伟明」并留痕', async () => {
    const res = await exportPost(piiToken, { currentPassword: PASSWORD });
    expect(res.status).toBe(200);
    const columns = await columnsFromWorkbook(res.buffer);
    // A-8：表尾多一行可见水印，故「处理人」列有两条——数据行 + 空（水印那行）
    expect(columns['处理人']).toEqual([REAL_NAME, '']);

    // A-8：水印多路同号（响应头 / 表尾行 / 文件名 / 审计），外流件能反查到导出人
    const traceId = res.headers['x-export-trace-id'];
    expect(traceId).toMatch(/^[0-9a-f]{16}$/);
    const lastCell = await lastRowFirstCell(res.buffer);
    expect(lastCell).toContain('未脱敏导出');
    expect(lastCell).toContain(piiUser.username);
    expect(lastCell).toContain(traceId);
    expect(decodeURIComponent(res.headers['content-disposition'])).toContain(traceId);
    const props = await workbookPropsOf(res.buffer);
    expect(props.creator).toBe(piiUser.username);
    expect(props.description).toBe(lastCell);
    expect(props.keywords).toContain(traceId);
    expect(props.lastModifiedBy).toContain(traceId);

    // 提权路径必须可回答"谁在什么时候导出了全文"。
    // 审计经 auditBuffer 异步落库：响应先回，行在并行 worker 下可能尚未可见，
    // 轮询到真实条件成立，而不是靠固定睡眠赌时延。
    let audit = null;
    await waitFor(
      async () => {
        audit = await AuditLog.findOne({
          action: 'view_sensitive_data',
          username: piiUser.username,
          'body.masked': false,
        }).lean();
        return Boolean(audit);
      },
      { label: 'view_sensitive_data 审计落库' }
    );
    expect(audit).toBeTruthy();
    expect(audit.body).toMatchObject({ type: 'alarms', masked: false, traceId });
    expect(audit.dataType).toBe('export_realname');
  });

  test('③ 缺 pii:export 时口令正确也 403，且不产生凭据侧副作用', async () => {
    const before = await User.findById(maskUser._id).select('mfaFailCount').lean();
    const res = await exportPost(maskToken, { currentPassword: PASSWORD });
    expect(res.status).toBe(403);
    expect(res.body?.errors?.errorCode ?? jsonOf(res)?.errors?.errorCode).toBe('PERMISSION_DENIED');

    const after = await User.findById(maskUser._id).select('mfaFailCount').lean();
    expect(after.mfaFailCount).toBe(before.mfaFailCount ?? 0);
  });

  test('② 持 pii:export 但未带任何凭据 → REAUTH_REQUIRED', async () => {
    const res = await exportPost(piiToken, {});
    expect(res.status).toBe(403);
    expect(res.body?.errors?.errorCode ?? jsonOf(res)?.errors?.errorCode).toBe('REAUTH_REQUIRED');
  });

  test('② 口令错误 → REAUTH_PASSWORD_INCORRECT，且不产出文件', async () => {
    const res = await exportPost(piiToken, { currentPassword: `${PASSWORD}_wrong` });
    expect(res.status).toBe(403);
    expect(res.body?.errors?.errorCode ?? jsonOf(res)?.errors?.errorCode).toBe(
      'REAUTH_PASSWORD_INCORRECT'
    );
    expect(res.headers['content-type']).not.toContain('spreadsheetml');
  });

  test('④ 非 PII 类型在凭据校验前被拒：400 且不计失败次数', async () => {
    await User.updateOne({ _id: piiUser._id }, { $set: { mfaFailCount: 0 } });
    const res = await exportPost(
      piiToken,
      { currentPassword: 'definitely-wrong' },
      'type=devices&format=xlsx'
    );
    expect(res.status).toBe(400);
    expect(jsonOf(res)?.errors?.errorCode).toBe('REPORT_TYPE_UNSUPPORTED');

    const fresh = await User.findById(piiUser._id).select('mfaFailCount').lean();
    expect(fresh.mfaFailCount ?? 0).toBe(0);
  });

  test('A-8：配额用尽（滚动 24h）时在二次验证之前拒绝，并给出 Retry-After', async () => {
    const now = new Date();
    await AuditLog.insertMany(
      Array.from({ length: 5 }, () => ({
        action: 'view_sensitive_data',
        category: 'report',
        userId: piiUser._id,
        username: piiUser.username,
        dataType: 'export_realname',
        success: true,
        riskLevel: 'medium',
        timestamp: now,
      }))
    );
    const res = await exportPost(piiToken, { currentPassword: PASSWORD });
    expect(res.status).toBe(429);
    expect(jsonOf(res)?.errors?.errorCode).toBe('PII_EXPORT_QUOTA_EXCEEDED');
    expect(Number(res.headers['retry-after'])).toBeGreaterThan(0);
    expect(res.headers['content-type']).not.toContain('spreadsheetml');
  });
});
