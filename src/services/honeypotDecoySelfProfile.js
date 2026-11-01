'use strict';

const config = require('../config');
const { DataMasking } = require('../utils/encryption');
const { sessionClientIp } = require('../utils/ipUtils');
const { durationToMs } = require('../utils/cookie');
const ipLocationService = require('./ipLocationService');
const { parseUserAgent } = require('./sessionService');
const {
  DECOY_PERMISSION_CATALOG,
  DECOY_SELF_EMAIL_DOMAIN,
  DECOY_SELF_PROFILE,
} = require('../constants/honeypotDecoySelf');
const { DECOY_ROLES, DECOY_ROLE_CODES } = require('../constants/honeypotDecoyData');

const MINUTE_MS = 60 * 1000;
const DAY_MS = 24 * 60 * MINUTE_MS;
const TTL_FALLBACK_MS = 7 * DAY_MS;

const sessionContextOf = (req) => {
  // 会话身份：只摘 req 上已有的东西，不做任何判定
  const source = req || {};
  const user = source.user || {};
  const headers = source.headers || {};
  return {
    sid: typeof user.sid === 'string' ? user.sid : null,
    userId: user.userId ? String(user.userId) : null,
    username: typeof user.username === 'string' ? user.username : '',
    realName: typeof user.realName === 'string' ? user.realName : '',
    mustChangePassword: user.mustChangePassword === true,
    ua: typeof headers['user-agent'] === 'string' ? headers['user-agent'] : '',
    ip: sessionClientIp(source),
    iatMs: Number.isFinite(user.iat) ? user.iat * 1000 : null,
    now: Date.now(),
  };
};

const contextOf = (session) => {
  const source = session || {};
  const now = Number.isFinite(source.now) ? source.now : Date.now();
  const username = typeof source.username === 'string' ? source.username : '';
  const lastLoginMs = Number.isFinite(source.iatMs) ? source.iatMs : now;
  return {
    now,
    sid: typeof source.sid === 'string' ? source.sid : null,
    userId: source.userId ? String(source.userId) : null,
    username,
    realName: typeof source.realName === 'string' ? source.realName : '',
    email: username ? username + '@' + DECOY_SELF_EMAIL_DOMAIN : '',
    phone: DECOY_SELF_PROFILE.phone,
    department: DECOY_SELF_PROFILE.department,
    avatar: DECOY_SELF_PROFILE.avatar,
    ua: typeof source.ua === 'string' ? source.ua : '',
    ip: typeof source.ip === 'string' && source.ip ? source.ip : null,
    mustChangePassword: source.mustChangePassword === true,
    lastLoginMs,
    lastLoginAt: new Date(lastLoginMs).toISOString(),
    createdAt: new Date(now - DECOY_SELF_PROFILE.createdAtOffsetMin * MINUTE_MS).toISOString(),
  };
};

const atOf = (ctx, offsetMin) => ctx.now - offsetMin * MINUTE_MS;
const isoOf = (ms) => new Date(ms).toISOString();
const locateOf = (ip) => (ip ? ipLocationService.locate(ip) : null);

const roleViewOf = () =>
  DECOY_ROLE_CODES.map((code) => DECOY_ROLES.find((role) => role.code === code))
    .filter((role) => role)
    .map((role) => ({ name: role.name, code: role.code }));

const menuTreeOf = () => {
  const menus = DECOY_PERMISSION_CATALOG.filter((row) => row.type === 'menu');
  const modules = [];
  for (const menu of menus) {
    let node = modules.find((item) => item.id === menu.module);
    if (!node) {
      const owner = menus.find((item) => item.code === menu.module + ':*');
      node = { id: menu.module, name: owner ? owner.name : menu.module, children: [] };
      modules.push(node);
    }
    node.children.push({ id: menu.code, name: menu.name, path: menu.path, code: menu.code });
  }
  return modules;
};

const viewOf = (type) => DECOY_PERMISSION_CATALOG.filter((row) => row.type === type);

const mePayload = (ctx) => {
  const buttonPermissions = viewOf('button').map((row) => ({
    code: row.code,
    name: row.name,
    path: row.path,
  }));
  return {
    user: {
      id: ctx.userId,
      username: ctx.username,
      realName: ctx.realName,
      email: ctx.email,
      phone: ctx.phone,
      department: ctx.department,
      avatar: ctx.avatar,
      lastLoginAt: ctx.lastLoginAt,
      createdAt: ctx.createdAt,
      roles: roleViewOf(),
      mustChangePassword: ctx.mustChangePassword,
    },
    permissions: DECOY_PERMISSION_CATALOG.map((row) => row.code),
    menuPermissions: viewOf('menu').map((row) => ({
      code: row.code,
      name: row.name,
      path: row.path,
      module: row.module,
    })),
    buttonPermissions,
    apiPermissions: viewOf('api').map((row) => ({
      code: row.code,
      name: row.name,
      path: row.path,
      method: row.method,
    })),
    menus: menuTreeOf(),
    buttons: buttonPermissions.map((row) => row.code),
    dataScope: { type: 'all' },
  };
};

const sessionRowOf = (ctx) => {
  const ua = ctx.ua.slice(0, 512);
  const info = parseUserAgent(ua);
  const ttlMs = durationToMs(config.jwt.refreshExpire, TTL_FALLBACK_MS);
  return {
    sid: ctx.sid,
    current: true,
    deviceType: info.deviceType,
    browser: info.browser,
    browserVersion: info.browserVersion,
    os: info.os,
    osVersion: info.osVersion,
    deviceVendor: info.deviceVendor,
    deviceModel: info.deviceModel,
    engine: info.engine,
    cpu: info.cpu,
    userAgent: ua,
    ip: ctx.ip,
    lastIp: ctx.ip,
    createdAt: ctx.lastLoginAt,
    lastSeenAt: isoOf(ctx.now),
    expiresAt: isoOf(ctx.lastLoginMs + ttlMs),
    location: locateOf(ctx.ip),
    loginLocation: locateOf(ctx.ip),
  };
};

const sessionsPayload = (ctx) =>
  ctx.sid
    ? { sessions: [sessionRowOf(ctx)], total: 1, currentSidPresent: true }
    : { sessions: [], total: 0, currentSidPresent: false };

const bindingsPayload = (ctx) => ({
  bindings: [
    {
      type: 'email',
      value: DataMasking.maskEmail(ctx.email),
      verified: ctx.email !== '',
      required: true,
    },
    {
      type: 'phone',
      value: DataMasking.maskPhone(ctx.phone),
      verified: ctx.phone !== '',
      required: false,
    },
    {
      type: 'department',
      value: ctx.department,
      verified: ctx.department !== '',
      required: false,
    },
  ],
});

const mfaStatusPayload = () => ({ enabled: false, recoveryCodesRemaining: 0 }); // 诱饵账户恒未开 MFA（isLureLogin 要求 mfaEnabled !== true），故形态恒定

module.exports = {
  atOf,
  bindingsPayload,
  contextOf,
  DAY_MS,
  isoOf,
  mePayload,
  MINUTE_MS,
  mfaStatusPayload,
  sessionContextOf,
  sessionsPayload,
};
