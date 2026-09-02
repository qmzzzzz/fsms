/**
 * 路由统一导出
 */

const authRoutes = require('./authRoutes');
const userRoutes = require('./userRoutes');
const roleRoutes = require('./roleRoutes');
const permissionRoutes = require('./permissionRoutes');
const deviceRoutes = require('./deviceRoutes');
const alarmRoutes = require('./alarmRoutes');
const inspectionRoutes = require('./inspectionRoutes');
const reportRoutes = require('./reportRoutes');
const securityRoutes = require('./securityRoutes');
const wellKnownRoutes = require('./wellKnownRoutes');

module.exports = {
  authRoutes,
  userRoutes,
  roleRoutes,
  permissionRoutes,
  deviceRoutes,
  alarmRoutes,
  inspectionRoutes,
  reportRoutes,
  securityRoutes,
  wellKnownRoutes,
};
