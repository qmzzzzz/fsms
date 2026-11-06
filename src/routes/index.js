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
const stuffingProfileRoutes = require('./stuffingProfileRoutes'); // 撞库画像（P2 情报）：securityRoutes 有效行已顶到棘轮地板，同 forensicRoutes 拆出
const attackProfileRoutes = require('./attackProfileRoutes'); // IP 攻击行为画像：同因独立成文件，挂 /api/security 同前缀
const attackEventRoutes = require('./attackEventRoutes'); // 攻击告警查询（专家分析）：同因独立成文件，挂 /api/security 同前缀
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
  stuffingProfileRoutes,
  attackProfileRoutes,
  attackEventRoutes,
  forensicRoutes,
  versionRoutes,
  wellKnownRoutes,
  avatarRoutes,
};
