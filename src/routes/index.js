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
const forensicRoutes = require('./forensicRoutes'); // 取证溯源（T5/T6）：单独成文件，避免继续堆大 securityRoutes（其有效行已超棘轮阈值）
const versionRoutes = require('./versionRoutes');
const wellKnownRoutes = require('./wellKnownRoutes');
const avatarRoutes = require('./avatarRoutes');

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
  forensicRoutes,
  versionRoutes,
  wellKnownRoutes,
  avatarRoutes,
};
